#!/usr/bin/env python3
"""
METATRON - dispatch.py
Tag parsing, URL canonicalization, wave ordering, log sanitization,
resource throttle, and safety gates. No subprocess / Ollama imports.
"""

from __future__ import annotations

import os
import re
import time
from urllib.parse import parse_qsl, urlparse


INJECTION_TOOLS = ("sqlmap", "dalfox", "commix")
SERIAL_TOOLS = {"playwright", "zaproxy"}
WEAK_QUERY_KEYS = {
    "unique", "v", "ver", "version", "cb", "cache", "nocache", "_",
}
KEY_TOKEN_RE = re.compile(
    r"^(TARGET|PROFILE|SCENARIO|WORDLIST):(.+)$",
    re.IGNORECASE,
)
PROGRESS_LINE_RE = re.compile(
    r"^\s*\[[=\s]*\]\s*\d+\s*%|"
    r"^\s*\d{1,3}\s*%\s*[|\\/-]?\s*$|"
    r"Progress:\s*\d+|"
    r"\[INF\]\s+Using.*templates|"
    r"^\[\*\]\s+elapsed:",
    re.IGNORECASE,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

DEFAULT_WAVES = [
    {"name": "passive", "tools": ["whois", "dig", "curl", "whatweb"], "max_workers": 4, "depends_on": []},
    {"name": "ports", "tools": ["nmap", "arp-scan", "masscan"], "max_workers": 1, "depends_on": ["passive"]},
    {"name": "tls", "tools": ["sslscan", "testssl.sh"], "max_workers": 2, "depends_on": ["ports"]},
    {"name": "http_probe", "tools": ["httpx"], "max_workers": 1, "depends_on": ["ports"]},
    {"name": "crawl", "tools": ["katana", "gobuster", "ffuf", "gau", "subfinder"], "max_workers": 1, "depends_on": ["http_probe"]},
    {"name": "browser", "tools": ["playwright"], "max_workers": 1, "depends_on": ["http_probe"]},
    {"name": "vuln_scan", "tools": ["nuclei", "nikto", "wpscan"], "max_workers": 2, "depends_on": ["crawl"]},
    {"name": "heavy_scan", "tools": ["wapiti", "zaproxy"], "max_workers": 1, "depends_on": ["crawl"]},
    {"name": "inject", "tools": ["sqlmap", "dalfox", "commix"], "max_workers": 1, "depends_on": ["crawl"]},
    {"name": "lookup", "tools": ["searchsploit"], "max_workers": 2, "depends_on": []},
]


def extract_tool_calls(response: str) -> list:
    """Extract [TOOL: ...] and [SEARCH: ...] tags. Returns list of (type, content)."""
    calls = []
    for match in re.findall(r"\[TOOL:\s*(.+?)\]", response or ""):
        calls.append(("TOOL", match.strip()))
    for match in re.findall(r"\[SEARCH:\s*(.+?)\]", response or ""):
        calls.append(("SEARCH", match.strip()))
    return calls


def parse_tool_tag(content: str) -> dict:
    """Parse `name TARGET:url PROFILE:x SCENARIO:y` or legacy positional TARGET."""
    parts = (content or "").strip().split()
    if not parts:
        return {
            "tool": "", "target": "", "profile": "", "scenario": "",
            "invented_flags": [], "raw": content or "",
        }
    tool = parts[0].lower().split("/")[-1]
    if tool == "httpx-toolkit":
        tool = "httpx"
    keyed = {}
    positional = []
    invented = []
    for token in parts[1:]:
        if token.startswith("-"):
            invented.append(token)
            continue
        match = KEY_TOKEN_RE.match(token)
        if match:
            keyed[match.group(1).lower()] = match.group(2)
            continue
        positional.append(token)
    target = (keyed.get("target") or "").strip()
    if not target:
        if tool == "searchsploit":
            target = " ".join(positional).strip()
        elif positional:
            target = positional[-1]
    profile = (keyed.get("profile") or "").strip().lower()
    scenario = (keyed.get("scenario") or keyed.get("wordlist") or "").strip().lower()
    if "/" in scenario or "\\" in scenario or ".." in scenario or scenario.startswith("."):
        scenario = ""
    return {
        "tool": tool,
        "target": target,
        "profile": profile,
        "scenario": scenario,
        "invented_flags": invented,
        "raw": content or "",
    }


def format_tool_call(tool: str, target: str, profile: str = "", scenario: str = "") -> str:
    parts = [tool, f"TARGET:{target}"]
    if profile:
        parts.append(f"PROFILE:{profile}")
    if scenario:
        parts.append(f"SCENARIO:{scenario}")
    return " ".join(parts)


def canonical_endpoint(url: str, include_params: bool = False) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = (parsed.hostname or "").lower()
    if not host:
        host = (parsed.path or "").split("/")[0].lower()
    port = parsed.port
    scheme = (parsed.scheme or "https").lower()
    if port in (80, 443, None):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    key = f"{scheme}://{netloc}{path}"
    if not include_params:
        return key
    names = []
    for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
        lower = name.lower()
        if not name or lower in WEAK_QUERY_KEYS or lower.startswith("utm_"):
            continue
        if name not in names:
            names.append(name)
    if names:
        key += "?" + "&".join(sorted(names))
    return key


def run_key(tool: str, target: str, profile: str = "", scenario: str = "") -> tuple:
    tool = (tool or "").lower()
    profile = (profile or "default").strip().lower() or "default"
    scenario = (scenario or "").strip().lower()
    if tool == "searchsploit":
        return (tool, (target or "").strip().lower(), profile, scenario)
    include = tool in INJECTION_TOOLS
    return (tool, canonical_endpoint(target, include), profile, scenario)


def format_run_key(key: tuple) -> str:
    tool, endpoint, profile, scenario = key
    extra = f" SCENARIO:{scenario}" if scenario else ""
    return f"{tool} {profile} @ {endpoint}{extra}"


def tools_by_wave(selected: list, waves: list = None) -> list:
    """Return [(wave_name, tool_names, max_workers), ...] for selected logical names."""
    waves = waves if waves is not None else DEFAULT_WAVES
    selected_set = list(dict.fromkeys(selected or []))
    remaining = set(selected_set)
    done = set()
    ordered = []
    progress = True
    while progress:
        progress = False
        for wave in waves:
            if not isinstance(wave, dict):
                continue
            name = str(wave.get("name") or "").strip() or "wave"
            if name in done:
                continue
            deps = {str(d) for d in (wave.get("depends_on") or [])}
            if deps - done:
                continue
            names = [t for t in (wave.get("tools") or []) if t in remaining]
            workers = int(wave.get("max_workers") or 1) or 1
            if names:
                ordered.append((name, names, workers))
                remaining -= set(names)
            done.add(name)
            progress = True
    if remaining:
        leftover = [t for t in selected_set if t in remaining]
        ordered.append(("other", leftover, 1))
    return ordered


def group_jobs_by_wave(jobs: list, waves: list = None) -> list:
    """jobs are dicts with at least 'tool'. Preserve job order within each wave."""
    names = [j.get("tool") for j in jobs if j.get("tool")]
    grouped = []
    placed = set()
    for wave_name, tools, workers in tools_by_wave(names, waves):
        wave_jobs = []
        for job in jobs:
            tool = job.get("tool")
            if tool in tools and id(job) not in placed:
                wave_jobs.append(job)
                placed.add(id(job))
        if wave_jobs:
            force_serial = any(
                j.get("tool") in SERIAL_TOOLS or (j.get("profile") or "") == "exploit"
                for j in wave_jobs
            )
            grouped.append((wave_name, wave_jobs, 1 if force_serial else workers))
    leftovers = [j for j in jobs if id(j) not in placed]
    if leftovers:
        grouped.append(("other", leftovers, 1))
    return grouped


def sanitize_tool_chunk(text: str, tool_name: str = "") -> str:
    text = (text or "").replace("\r", "\n")
    text = ANSI_RE.sub("", text)
    keep = []
    xml = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped:
            continue
        if tool_name == "zaproxy" and (
            stripped.startswith("<?xml") or "<OWASPZAPReport" in stripped
        ):
            xml = True
            continue
        if xml and tool_name == "zaproxy":
            continue
        if PROGRESS_LINE_RE.search(stripped):
            continue
        keep.append(line)
    return "".join(keep)


def throttle_resources(cfg: dict = None) -> None:
    cfg = cfg or {}
    ram_lim = float(cfg.get("ram_percent_limit") or 0)
    load_lim = float(cfg.get("load_per_cpu_limit") or 0)
    if not ram_lim and not load_lim:
        return
    while True:
        wait = False
        try:
            import psutil
            if ram_lim and psutil.virtual_memory().percent >= ram_lim:
                wait = True
            if load_lim:
                try:
                    cpus = psutil.cpu_count() or 1
                    if psutil.getloadavg()[0] / cpus >= load_lim:
                        wait = True
                except (AttributeError, OSError):
                    pass
        except Exception:
            return
        if not wait:
            return
        time.sleep(2)


def apply_safety_gates(
    job: dict,
    ran_keys: set,
    origin: str = "",
    is_wp: bool = False,
    is_lan: bool = False,
    global_cfg: dict = None,
) -> tuple:
    """
    Return (ok, job, reason). On failure ok is False and reason is a skip line.
    May rewrite job target (junk/off-origin).
    """
    global_cfg = global_cfg or {}
    tool = (job.get("tool") or "").lower()
    target = job.get("target") or ""
    profile = (job.get("profile") or "default").strip().lower() or "default"
    scenario = job.get("scenario") or ""
    job = dict(job)
    job["profile"] = profile

    if tool == "wpscan" and not is_wp:
        return False, job, "[!] Skipping wpscan — target does not look like WordPress."
    if tool == "masscan" and not is_lan:
        return False, job, "[!] Skipping masscan — target is not on the local network."

    if profile == "exploit":
        max_exploit = int(global_cfg.get("max_exploit_runs") or 1)
        exploit_count = sum(1 for k in ran_keys if len(k) > 2 and k[2] == "exploit")
        if exploit_count >= max_exploit:
            return False, job, f"[!] Skipping {tool} PROFILE:exploit — max_exploit_runs={max_exploit}."
        if global_cfg.get("exploit_requires_detect", True):
            endpoint = run_key(tool, target, "default", scenario)[1]
            prior = any(
                k[0] == tool and k[1] == endpoint and k[2] in ("default", "aggressive")
                for k in ran_keys
            )
            if not prior:
                return False, job, (
                    f"[!] Skipping {tool} PROFILE:exploit — run default/aggressive on this "
                    "endpoint first."
                )

    if tool in INJECTION_TOOLS:
        cap = int(global_cfg.get("max_injection_endpoints") or 3)
        count = sum(1 for k in ran_keys if k[0] == tool)
        key = run_key(tool, target, profile, scenario)
        if key not in ran_keys and count >= cap:
            return False, job, (
                f"[!] Skipping {tool} — max_injection_endpoints={cap} already reached."
            )

    key = run_key(tool, target, profile, scenario)
    if key in ran_keys:
        return False, job, f"[!] Skipping duplicate {format_run_key(key)}"

    job["_run_key"] = key
    return True, job, ""


def already_ran_text(ran_keys: set) -> str:
    if not ran_keys:
        return "ALREADY_RAN:\n(none)"
    lines = ["ALREADY_RAN:"]
    for key in sorted(ran_keys, key=lambda k: (k[0], k[2], k[1], k[3])):
        lines.append(format_run_key(key))
    return "\n".join(lines)


def dry_run_enabled() -> bool:
    return os.environ.get("METATRON_DRY_RUN", "").strip() in ("1", "true", "yes")
