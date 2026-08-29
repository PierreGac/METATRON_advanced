#!/usr/bin/env python3
"""
METATRON - llm.py
Ollama interface for metatron-qwen model.
Builds prompts, handles AI responses, runs tool dispatch loop.
Model: metatron-qwen (fine-tuned from huihui_ai/qwen3.5-abliterated:9b)
"""

import re
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from report_md import render_markdown_report, reports_dir, write_markdown_file
from search import handle_search_dispatch
from harvest import (
    already_reported_text,
    canned_summary,
    derive_risk,
    filter_gap_vulns,
    findings_to_exploits,
    findings_to_vulns,
    format_digest,
    harvest_findings,
    leftover_interesting_lines,
    looks_like_schema as _looks_like_schema,
    merge_exploits,
    merge_vulns,
    pick_schema_text,
    schema_text_from_harvest,
    strip_ansi,
)
from dispatch import (
    already_ran_text,
    extract_tool_calls,
    format_tool_call,
    parse_tool_tag,
    run_key,
)
from tools import (
    _http_url,
    current_results_dir,
    lan_ips_for_target,
    list_wordlist_scenarios,
    run_dispatch_jobs,
)

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "metatron-qwen"
MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 6
OLLAMA_TIMEOUT = 800
ANALYSIS_TEMPERATURE = 0.2

WEB_OPTIONAL = ("wapiti", "zaproxy")
INJECTION_TOOLS = ("sqlmap", "dalfox", "commix")
MAX_TOOLS_PER_ROUND = 8

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
NUCLEI_LINE_RE = re.compile(
    r"^\s*\[?([^\]]+)\]\s*\[(?:http|dns|ssl|tcp|javascript)\]\s*"
    r"\[(info|low|medium|high|critical|unknown)\]",
    re.IGNORECASE,
)
STATIC_EXT_RE = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4)(?:\?|$)",
    re.IGNORECASE,
)
OUTPUT_HEADER_RE = re.compile(r"\[\s*([A-Z0-9._-]+)\s+OUTPUT\s*\]")
RUNNING_RE = re.compile(r"\[\*\]\s+Running\s+(\S+)", re.IGNORECASE)
GOBUSTER_PATH_RE = re.compile(
    r"^\s*(/[^\s]*?)\s+\(Status:\s*\d+",
    re.IGNORECASE | re.MULTILINE,
)
FFUF_STATUS_PATH_RE = re.compile(
    r"\[Status:\s*\d+[^\]]*\]\s+(/\S+)",
    re.IGNORECASE,
)
BARE_PATH_RE = re.compile(r"^(/[A-Za-z0-9._~/-]+)$", re.MULTILINE)
FS_PATH_PREFIXES = (
    "/usr/", "/home/", "/opt/", "/etc/", "/var/", "/tmp/", "/proc/", "/root/",
)

MAX_DISCOVERED_URLS = 40
MAX_EVIDENCE_CHARS = 12000
SHORT_OUTPUT = 800
TAIL_LINES = 20
JUNK_PATH_SEGMENTS = {
    "fullpath", "fuzz", "fu", "path", "url", "target", "endpoint", "endpoints",
}
WEAK_QUERY_KEYS = {
    "unique", "v", "ver", "version", "cb", "cache", "nocache", "_", "utm_source",
    "utm_medium", "utm_campaign", "utm_content", "utm_term",
}
CATCHALL_SIZE_HITS = 8
ERROR_REPLY_PREFIXES = (
    "[!] Model returned empty response.",
    "[!] Cannot connect to Ollama",
    "[!] Ollama timed out",
    "[!] Ollama HTTP error",
    "[!] Unexpected error:",
)

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are METATRON, a penetration testing assistant.
Plain text only. No markdown. No YAML. No flags.

You propose an action plan, then drive tools with tags.
Argv always comes from tools_config.json profiles. You never invent -flags.

Tag format (all keys optional except name and TARGET):
  [TOOL: <name> TARGET:<url-or-query> PROFILE:<default|aggressive|exploit> SCENARIO:<wordlist-key>]
  [SEARCH: CVE-YYYY-NNNN]

Examples:
  [TOOL: gobuster TARGET:https://example.com PROFILE:default SCENARIO:api]
  [TOOL: sqlmap TARGET:https://example.com/search?q=test PROFILE:aggressive]
  [TOOL: searchsploit TARGET:CVE-2024-1234 PROFILE:default]
  [SEARCH: CVE-2024-1234]

Output this round:
1. PLAN: 3-8 short lines. Why these tools, which PROFILE, which URLs. No vuln table yet.
2. Zero or more [TOOL: ...] and [SEARCH: ...] tags.
3. If no further tools are needed, write PLAN: done and no TOOL tags.

Rules:
- SEARCH must be a real CVE id.
- TARGET for searchsploit is a CVE or "product version", never a URL.
- TARGET for other tools is the session host or a same-host discovered URL.
- Do not invent paths like /fullpath.
- Do not request PROFILE:exploit unless a prior detect/aggressive run on that endpoint showed a confirmed injection and SEARCH supports it.
- At most one PROFILE:exploit tag per round. Prefer none.
- Do not re-request a tool+endpoint+profile listed under ALREADY_RAN.
- wpscan only if the target looks like WordPress.
- masscan only if the digest says LAN.
- playwright: cookie banners are not vulnerabilities.
- Skip SPA catch-all paths that share the same homepage size.

Accuracy:
- nmap filtered / no-response is INCONCLUSIVE.
- Never invent CVEs or versions.
- curl HTTP_CODE=000 means unreachable.
"""

FINALIZE_PROMPT = """You are METATRON writing the saved pentest record.
Output ONLY the schema below. No markdown, no backticks, no YAML, no headings, no emoji.

VULN: <name> | SEVERITY: <critical|high|medium|low> | PORT: <port or blank> | SERVICE: <service>
DESC: <one line>
FIX: <one line>

EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected or observed result>
NOTES: <notes>

RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentences>

Rules:
- CRITICAL only if SEARCH results and endpoint evidence support exploitability.
- Cookie consent overlays and WebGL/console warnings are not vulnerabilities.
- For Nuclei CVE hits, name the product from the template. If the target app
  does not match that product, SEVERITY: low and DESC must say unconfirmed false positive.
- Missing security headers are medium or low, not critical.
- If evidence is weak, say unconfirmed.
"""

GAP_PROMPT = """You are METATRON reviewing leftover scanner lines that may be missing from the draft report.
Output ONLY new schema rows. No markdown, no backticks, no YAML, no headings, no emoji.

VULN: <name> | SEVERITY: <critical|high|medium|low> | PORT: <port or blank> | SERVICE: <service>
DESC: <one line>
FIX: <one line>

EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected or observed result>
NOTES: <notes>

Rules:
- ALREADY_REPORTED lists findings already kept. Do not repeat them.
- Copy evidence from LOG_LEFTOVERS. Do not invent CVEs, URLs, or products.
- A CVE is allowed only if that exact id appears in LOG_LEFTOVERS.
- If nothing new is evidenced, output exactly: NO_NEW_FINDINGS
"""


# ─────────────────────────────────────────────
# OLLAMA API CALL
# ─────────────────────────────────────────────

def ask_ollama(messages: list, temperature: float = ANALYSIS_TEMPERATURE, retries: int = 1) -> str:
    last = "[!] Model returned empty response."
    for attempt in range(max(retries, 0) + 1):
        try:
            payload = {
                "model": MODEL_NAME,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict": MAX_TOKENS,
                    "temperature": temperature,
                    "top_p": 0.9,
                },
            }
            print(f"\n[*] Sending to {MODEL_NAME}...")
            resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            response = data.get("message", {}).get("content", "").strip()
            if response:
                return response
            last = "[!] Model returned empty response."
        except requests.exceptions.ConnectionError:
            return "[!] Cannot connect to Ollama. Is it running? Try: ollama serve"
        except requests.exceptions.Timeout:
            last = "[!] Ollama timed out. Model may be loading, try again."
        except requests.exceptions.HTTPError as e:
            last = f"[!] Ollama HTTP error: {e}"
        except Exception as e:
            last = f"[!] Unexpected error: {e}"
        if attempt < retries:
            print("[*] Empty or failed model reply — retrying...")
    return last


# ─────────────────────────────────────────────
# EVIDENCE / URL / CVE HARVEST
# ─────────────────────────────────────────────

def _canonical_tool(name: str) -> str:
    n = (name or "").lower().split("/")[-1].strip(".:")
    if n in ("httpx-toolkit", "httpx_pd", "httpx-pd"):
        return "httpx"
    if n in ("curl_headers", "curl"):
        return "curl"
    if n in ("zap.sh", "owasp-zap", "zaproxy"):
        return "zaproxy"
    return n


def extract_cves(text: str) -> list:
    seen = []
    for match in CVE_RE.findall(strip_ansi(text or "")):
        key = match.upper()
        if key not in seen:
            seen.append(key)
    return seen


def _strip_url(url: str) -> str:
    return url.rstrip(".,;:)'\"\\]>")


def _parse_url(url: str):
    """urlparse that never raises on junk scanner output."""
    if not url:
        return None
    try:
        return urlparse(_strip_url(url))
    except (ValueError, TypeError):
        return None


def _is_truncated_bracket_url(url: str, parsed) -> bool:
    """Drop placeholders like https://host/[... where ] was stripped by URL_RE."""
    if parsed is None:
        return True
    stripped = _strip_url(url)
    if stripped.count("[") > stripped.count("]"):
        return True
    path = parsed.path or ""
    netloc = parsed.netloc or ""
    if path.startswith("[") and "]" not in path:
        return True
    if netloc.startswith("[") and "]" not in netloc:
        return True
    return False


def _session_host(target: str) -> str:
    raw = target if "://" in target else f"http://{target}"
    parsed = _parse_url(raw)
    if parsed is None:
        return ""
    return (parsed.hostname or "").lower()


def _same_host(url: str, host: str) -> bool:
    if not host:
        return False
    parsed = _parse_url(url)
    if parsed is None:
        return False
    h = (parsed.hostname or "").lower()
    return h == host


def _is_static_asset(url: str) -> bool:
    parsed = _parse_url(url)
    if parsed is None:
        return False
    path = parsed.path or ""
    return bool(STATIC_EXT_RE.search(path))


def _path_last_segment(url: str) -> str:
    parsed = _parse_url(url) or _parse_url(_http_url(url))
    if parsed is None:
        return (url or "").rstrip("/").split("/")[-1].lower()
    return (parsed.path or "").rstrip("/").split("/")[-1].lower()


def _is_junk_target(target: str) -> bool:
    seg = _path_last_segment(target)
    return seg in JUNK_PATH_SEGMENTS


def _query_keys(url: str) -> list:
    parsed = _parse_url(url)
    if parsed is None or not parsed.query:
        return []
    keys = []
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in keys:
            keys.append(key)
    return keys


def _is_weak_injection_url(url: str) -> bool:
    parsed = _parse_url(url) or _parse_url(_http_url(url))
    if parsed is None:
        return True
    if _is_static_asset(url) or STATIC_EXT_RE.search(parsed.path or ""):
        return True
    if _is_junk_target(url):
        return True
    keys = _query_keys(url)
    if keys and all(k.lower() in WEAK_QUERY_KEYS or k.lower().startswith("utm_") for k in keys):
        return True
    path = parsed.path or ""
    if re.match(r"^/_[A-Za-z0-9._-]+/?$", path) and not parsed.query:
        return True
    return False


def _catchall_sizes(text: str, min_hits: int = CATCHALL_SIZE_HITS) -> set:
    sizes = re.findall(r"\[Size:\s*(\d+)\]", text or "", re.IGNORECASE)
    if len(sizes) < min_hits:
        return set()
    counts = {}
    for size in sizes:
        counts[size] = counts.get(size, 0) + 1
    dominant = max(counts.values()) if counts else 0
    if dominant < min_hits:
        return set()
    return {size for size, n in counts.items() if n >= min_hits and n / len(sizes) >= 0.5}


def _usable_model_text(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    return not any(t.startswith(p) for p in ERROR_REPLY_PREFIXES)


def _url_has_query(url: str) -> bool:
    parsed = _parse_url(url)
    return bool(parsed and parsed.query)


def _canonical_scan_url(url: str) -> str:
    parsed = _parse_url(url)
    if parsed is None:
        return _strip_url(url)
    return parsed._replace(fragment="").geturl()


def _looks_like_fs_path(path: str) -> bool:
    lower = (path or "").lower()
    return any(lower.startswith(p) for p in FS_PATH_PREFIXES)


def _join_origin_path(origin: str, path: str) -> str:
    if not origin or not path or path.startswith("//"):
        return ""
    if _looks_like_fs_path(path):
        return ""
    base = origin if origin.endswith("/") else origin + "/"
    return urljoin(base, path)


def _add_harvested(url: str, host: str, seen: set, found: list, cap: int, skip_catchall: bool = False) -> bool:
    parsed = _parse_url(url)
    if parsed is None or _is_truncated_bracket_url(url, parsed):
        return False
    if url in seen or not _same_host(url, host):
        return False
    if _is_static_asset(url) or _is_junk_target(url):
        return False
    if skip_catchall and re.match(r"^/_[A-Za-z0-9._-]+/?$", parsed.path or ""):
        return False
    seen.add(url)
    found.append(url)
    return len(found) >= cap


def harvest_urls(text: str, host: str, cap: int = MAX_DISCOVERED_URLS, origin: str = "") -> list:
    found = []
    seen = set()
    blob = text or ""
    base = origin or (_http_url(host) if host else "")
    skip_catchall = bool(_catchall_sizes(blob))

    for raw in URL_RE.findall(blob):
        url = _strip_url(raw)
        if _add_harvested(url, host, seen, found, cap, skip_catchall=skip_catchall):
            return found

    if base:
        paths = []
        for match in GOBUSTER_PATH_RE.finditer(blob):
            paths.append(match.group(1))
        for match in FFUF_STATUS_PATH_RE.finditer(blob):
            paths.append(match.group(1).rstrip(",;"))
        for match in BARE_PATH_RE.finditer(blob):
            paths.append(match.group(1))
        for path in paths:
            url = _join_origin_path(base, path)
            if not url:
                continue
            if _add_harvested(url, host, seen, found, cap, skip_catchall=skip_catchall):
                return found
    return found


def harvest_cve_urls(text: str, host: str = "") -> dict:
    mapping = {}
    for line in strip_ansi(text or "").splitlines():
        if "CVE-" not in line.upper():
            continue
        match = re.search(
            r"(CVE-\d{4}-\d+)\S*.*?(https?://[^\s<>\"']+)",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        url = _strip_url(match.group(2))
        if _parse_url(url) is None:
            continue
        if host and not _same_host(url, host):
            continue
        mapping[match.group(1).upper()] = url
    return mapping


def _xml_tag(block: str, name: str) -> str:
    match = re.search(rf"<{name}>([^<]*)</{name}>", block, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _zap_facts(text: str) -> list:
    if "<alertitem>" not in text.lower() and "<OWASPZAPReport" not in text:
        return []
    lines = []
    for block in re.findall(r"<alertitem>(.*?)</alertitem>", text, re.S | re.I):
        alert = _xml_tag(block, "alert") or _xml_tag(block, "name")
        risk = _xml_tag(block, "riskdesc")
        uris = re.findall(r"<uri>([^<]+)</uri>", block, re.I)
        uri = uris[0] if uris else ""
        if alert:
            lines.append(f"ZAP: {alert} | {risk} | {uri}")
        if len(lines) >= 30:
            break
    return lines


def _nuclei_facts(text: str) -> list:
    lines = []
    for line in strip_ansi(text or "").splitlines():
        if NUCLEI_LINE_RE.search(line) or (line.strip().startswith("[") and "CVE-" in line.upper()):
            lines.append(line.strip())
        if len(lines) >= 40:
            break
    return lines


def _rank_url(url: str) -> int:
    parsed = _parse_url(url)
    if parsed is None:
        return 4
    if parsed.query:
        return 0
    if _is_static_asset(url):
        return 3
    path = parsed.path or ""
    if path not in ("", "/"):
        return 1
    return 2


def ranked_urls(urls: list) -> list:
    return sorted(urls, key=_rank_url)


def injection_target(origin: str, urls: list) -> str:
    for url in ranked_urls(urls):
        parsed = _parse_url(url)
        if parsed is None or _is_truncated_bracket_url(url, parsed):
            continue
        if parsed.query and not _is_weak_injection_url(url):
            return url
    for url in ranked_urls(urls):
        parsed = _parse_url(url)
        if parsed is None or _is_truncated_bracket_url(url, parsed):
            continue
        if parsed.path not in ("", "/") and not _is_static_asset(url) and not _is_weak_injection_url(url):
            return url
    return origin


def summarize_tool_output(raw_output: str, session_host: str = "") -> str:
    """
    Deterministic extract: CVE/template lines, ZAP alerts, URLs, plus a short tail.
    No second Ollama call.
    """
    text = strip_ansi((raw_output or "").strip())
    if not text:
        return ""

    facts = _nuclei_facts(text) + _zap_facts(text)
    urls = harvest_urls(text, session_host, origin=_http_url(session_host)) if session_host else []

    if len(text) < SHORT_OUTPUT and "<alertitem>" not in text.lower():
        body = text
    else:
        parts = []
        if facts:
            parts.append("EXTRACTED FINDINGS:")
            parts.extend(facts)
        if urls:
            parts.append("URLS:")
            parts.extend(ranked_urls(urls)[:25])
        tail_source = text
        if "<OWASPZAPReport" in text or "<alertitem>" in text.lower():
            tail_source = ""
        if tail_source:
            tail = "\n".join(tail_source.splitlines()[-TAIL_LINES:])
            parts.append("LOG TAIL:")
            parts.append(tail)
        body = "\n".join(parts) if parts else text[:SHORT_OUTPUT]

    if urls:
        body += "\nDISCOVERED_URLS:\n" + "\n".join(ranked_urls(urls)[:MAX_DISCOVERED_URLS])

    if len(body) > MAX_EVIDENCE_CHARS:
        body = body[:MAX_EVIDENCE_CHARS] + "\n[truncated]"
    return body


def tools_from_text(text: str) -> set:
    found = set()
    for match in OUTPUT_HEADER_RE.finditer(text or ""):
        found.add(_canonical_tool(match.group(1)))
    for match in RUNNING_RE.finditer(text or ""):
        found.add(_canonical_tool(match.group(1)))
    return found


def looks_like_http(target: str, recon: str) -> bool:
    blob = f"{target}\n{recon}".lower()
    if target.lower().startswith(("http://", "https://")):
        return True
    markers = (
        "80/tcp", "443/tcp", "http", "nginx", "apache", "ssl/http",
        "whatweb", "httpx", "text/html",
    )
    return any(m in blob for m in markers)


def looks_like_wordpress(recon: str) -> bool:
    blob = (recon or "").lower()
    return any(x in blob for x in ("wordpress", "wp-content", "wp-login", "wp-json"))


def preferred_origin(target: str, recon: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    blob = (recon or "").lower()
    if "https://" in blob or "443/tcp" in blob:
        return f"https://{target}"
    return _http_url(target)


def missing_web_tools(*_args, **_kwargs) -> list:
    """Mandatory scanner checklist removed — AI plans follow-up tools."""
    return []


def injection_covered(
    name: str,
    ran: set,
    discovered: list,
    ran_injection_urls: dict,
    retargeted: set,
) -> bool:
    if name not in ran:
        return False
    urls = (ran_injection_urls or {}).get(name, set())
    if any(_url_has_query(u) and not _is_weak_injection_url(u) for u in urls):
        return True
    if not any(_url_has_query(u) and not _is_weak_injection_url(u) for u in (discovered or [])):
        return True
    if name in (retargeted or set()):
        return True
    return False


def pending_curl_urls(cve_urls: dict, curled_urls: set) -> list:
    pending = []
    seen = set()
    for url in cve_urls.values():
        if url and url not in curled_urls and url not in seen:
            seen.add(url)
            pending.append(url)
    return pending


def build_auto_dispatch(
    unverified_cves: list,
    cve_urls: dict,
    curled_urls: set,
) -> list:
    """Gap-only: SEARCH unverified CVEs and curl their hit URLs."""
    calls = []
    for cve in unverified_cves[:3]:
        calls.append(("SEARCH", cve))
        url = cve_urls.get(cve.upper())
        if url and url not in curled_urls:
            calls.append(("TOOL", format_tool_call("curl", url, "default")))
    if calls:
        return calls
    for url in pending_curl_urls(cve_urls, curled_urls)[:2]:
        calls.append(("TOOL", format_tool_call("curl", url, "default")))
    return calls


def checklist_message(
    unverified_cves: list,
    discovered: list,
    loops_left: int,
    curl_pending: list = None,
    ran_keys: set = None,
) -> str:
    lines = []
    lines.append(already_ran_text(ran_keys or set()))
    if unverified_cves:
        lines.append("UNVERIFIED CVEs — emit [SEARCH: CVE-…] and [TOOL: curl TARGET:<hit-url>] before calling them findings:")
        lines.append(", ".join(unverified_cves))
    if curl_pending:
        lines.append("CVE EVIDENCE URLS still need [TOOL: curl TARGET:<url>]:")
        lines.extend(curl_pending[:5])
    ranked = ranked_urls(discovered)[:20]
    if ranked:
        lines.append("DISCOVERED_URLS:")
        lines.extend(ranked)
    scenarios = list_wordlist_scenarios()
    if scenarios:
        lines.append("WORDLIST SCENARIOS (optional SCENARIO:name on gobuster/ffuf):")
        lines.append(", ".join(scenarios))
    lines.append("Emit PLAN: plus [TOOL: name TARGET:... PROFILE:...] tags, or PLAN: done if finished.")
    lines.append("Do not write RISK_LEVEL yet.")
    lines.append(f"Loops left: {loops_left}")
    return "\n".join(lines)


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def _search_is_cve(query: str) -> bool:
    return bool(CVE_RE.search(query or ""))


def _search_looks_like_fake_cve(query: str) -> bool:
    q = (query or "").strip()
    if not q:
        return True
    if re.match(r"CVE[\s:=_-]", q, re.IGNORECASE) and not _search_is_cve(q):
        return True
    if q.lower().startswith("cve") and not _search_is_cve(q):
        return True
    return False


def sanitize_calls(calls: list, origin: str = "", is_wp: bool = False) -> list:
    """Drop junk SEARCH/TARGET tags the model invents."""
    cleaned = []
    origin_host = _session_host(origin)
    for call_type, content in calls or []:
        if call_type == "SEARCH":
            if _search_looks_like_fake_cve(content) and not _search_is_cve(content):
                print(f"  [!] Ignoring SEARCH (not a CVE id): {content}")
                continue
            cleaned.append((call_type, content))
            continue
        if call_type != "TOOL":
            cleaned.append((call_type, content))
            continue
        parsed = parse_tool_tag(content)
        tool = _canonical_tool(parsed.get("tool") or "")
        target = parsed.get("target") or ""
        scenario = parsed.get("scenario") or ""
        profile = parsed.get("profile") or ""
        if tool == "wpscan" and not is_wp:
            print("  [!] Ignoring wpscan — target does not look like WordPress.")
            continue
        if tool != "searchsploit" and target and _is_junk_target(target):
            if origin:
                print(f"  [!] Replacing junk TARGET {target} with origin")
                target = origin
            else:
                print(f"  [!] Ignoring TOOL {tool} with junk TARGET {target}")
                continue
        if tool != "searchsploit" and target and origin_host:
            th = _session_host(target)
            if th and th != origin_host and not th.endswith("." + origin_host):
                print(f"  [!] Skipping {tool} — off-origin TARGET {target}")
                continue
        if tool in INJECTION_TOOLS and target and _is_weak_injection_url(target):
            print(f"  [!] Ignoring {tool} on weak/static URL: {target}")
            continue
        if parsed.get("invented_flags"):
            print(f"  [*] Ignoring model flags on {tool}")
        content = format_tool_call(tool, target, profile, scenario)
        cleaned.append(("TOOL", content))
    return cleaned


def _call_key(call: tuple) -> tuple:
    call_type, content = call
    if call_type == "SEARCH":
        return ("SEARCH", (content or "").strip().upper())
    parsed = parse_tool_tag(content)
    return ("TOOL",) + run_key(
        _canonical_tool(parsed.get("tool") or ""),
        parsed.get("target") or "",
        parsed.get("profile") or "default",
        parsed.get("scenario") or "",
    )


def merge_calls(model_calls: list, auto_calls: list, max_tools: int = MAX_TOOLS_PER_ROUND) -> list:
    """Keep model tags, then fill remaining gaps. SEARCH first; cap TOOL count."""
    model_calls = list(model_calls or [])
    auto_calls = list(auto_calls or [])
    merged = []
    seen = set()

    def _add(call, count_tool: bool, skip_dup_tool: bool = False) -> bool:
        key = _call_key(call)
        if key in seen:
            return False
        if call[0] == "TOOL" and count_tool:
            if sum(1 for t, _ in merged if t == "TOOL") >= max_tools:
                return False
            tool = key[1]
            if skip_dup_tool and any(
                _canonical_tool((c.split() or [""])[0]) == tool
                for t, c in merged
                if t == "TOOL"
            ):
                return False
        seen.add(key)
        merged.append(call)
        return True

    for call in model_calls:
        if call[0] == "SEARCH":
            _add(call, count_tool=False)
    for call in auto_calls:
        if call[0] == "SEARCH":
            _add(call, count_tool=False)
    for call in model_calls:
        if call[0] == "TOOL":
            _add(call, count_tool=True, skip_dup_tool=False)
    for call in auto_calls:
        if call[0] != "TOOL":
            continue
        _add(call, count_tool=True, skip_dup_tool=True)
    return merged


def record_calls(
    calls: list,
    ran_tools: set,
    searched_cves: set,
    curled_urls: set,
    ran_injection_urls: dict = None,
    ran_scenarios: set = None,
    ran_keys: set = None,
) -> None:
    for call_type, content in calls:
        if call_type == "SEARCH":
            for cve in extract_cves(content):
                searched_cves.add(cve)
            continue
        if call_type != "TOOL":
            continue
        parsed = parse_tool_tag(content)
        tool = _canonical_tool(parsed.get("tool") or "")
        target = parsed.get("target") or ""
        scenario = parsed.get("scenario") or ""
        profile = parsed.get("profile") or "default"
        ran_tools.add(tool)
        if scenario and ran_scenarios is not None:
            ran_scenarios.add(f"{tool}:{scenario}")
        if tool == "curl" and target:
            curled_urls.add(_strip_url(target))
        if tool in INJECTION_TOOLS and target and ran_injection_urls is not None:
            ran_injection_urls.setdefault(tool, set()).add(_canonical_scan_url(target))
        if ran_keys is not None:
            ran_keys.add(run_key(tool, target, profile, scenario))


def run_tool_calls(
    calls: list,
    session_host: str = "",
    is_wp: bool = False,
    origin: str = "",
    ran_keys: set = None,
    is_lan: bool = False,
) -> tuple:
    """
    Execute SEARCH sequentially and TOOL jobs in waves.
    Returns (evidence_string, ran_keys).
    """
    if not calls:
        return "", ran_keys or set()

    ran_keys = set(ran_keys or [])
    results = ""
    jobs = []

    for call_type, call_content in calls:
        if call_type == "SEARCH":
            print(f"\n  [DISPATCH] SEARCH: {call_content}")
            if _search_looks_like_fake_cve(call_content) and not _search_is_cve(call_content):
                output = f"[!] Skipping SEARCH — not a CVE id: {call_content}"
                print(f"  {output}")
            else:
                output = handle_search_dispatch(call_content)
            compressed = summarize_tool_output(output.strip(), session_host)
            results += f"\n[SEARCH RESULT: {call_content}]\n"
            results += "─" * 40 + "\n"
            results += compressed + "\n"
            continue
        if call_type != "TOOL":
            continue
        parsed = parse_tool_tag(call_content)
        parsed["tool"] = _canonical_tool(parsed.get("tool") or "")
        jobs.append(parsed)

    if jobs:
        print(f"\n  [DISPATCH] {len(jobs)} tool job(s)")
        job_results, notes, ran_keys = run_dispatch_jobs(
            jobs,
            ran_keys=ran_keys,
            origin=origin or session_host,
            is_wp=is_wp,
            is_lan=is_lan,
        )
        for note in notes:
            results += f"\n{note}\n"
        for label, output in job_results.items():
            compressed = summarize_tool_output((output or "").strip(), session_host)
            results += f"\n[TOOL RESULT: {label}]\n"
            results += "─" * 40 + "\n"
            results += compressed + "\n"

    return results, ran_keys


# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────

def _clean(line: str) -> str:
    line = re.sub(r"\*+", "", line)
    return line.replace("`", "").strip()


def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         "",
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_exploits(response: str) -> list:
    """
    Parse EXPLOIT: lines from AI response into dicts.
    Returns list of exploit dicts ready for db.save_exploit()
    """
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        "",
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response (tolerate markdown/backticks/headings)."""
    cleaned = re.sub(r"[`*_#]", "", response or "")
    match = re.search(
        r"RISK[_ ]?LEVEL\s*:?\s*(CRITICAL|HIGH|MEDIUM|LOW)",
        cleaned,
        re.IGNORECASE,
    )
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(
        r"SUMMARY:\s*(.+?)(?=\n\s*(?:VULN:|EXPLOIT:|RISK_LEVEL:|IMPORTANT:)|\Z)",
        response or "",
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    text = re.sub(r"\s+", " ", match.group(1)).strip()
    return text[:800]


def _pick_schema_text(finalize: str, transcript: list) -> str:
    """Prefer finalize schema. Never save a [TOOL:]/[SEARCH:] round as the record."""
    return pick_schema_text(finalize, transcript, usable=_usable_model_text)


def _cap_evidence(chunks: list) -> str:
    blob = "\n".join(chunks)
    if len(blob) <= MAX_EVIDENCE_CHARS:
        return blob
    return blob[-MAX_EVIDENCE_CHARS:]


def _run_gap_pass(target: str, vulns: list, exploits: list, leftovers: str) -> tuple:
    """Bounded leftover review. Empty/unparsed reply must not wipe harvested rows."""
    if not (leftovers or "").strip():
        return [], []
    print(f"\n{'─'*60}")
    print("[METATRON - Gap pass]")
    print(f"{'─'*60}")
    user = (
        f"TARGET: {target}\n\n"
        f"ALREADY_REPORTED:\n{already_reported_text(vulns, exploits)}\n\n"
        f"LOG_LEFTOVERS:\n{leftovers}\n"
    )
    reply = ask_ollama(
        [
            {"role": "system", "content": GAP_PROMPT},
            {"role": "user", "content": user},
        ],
        retries=1,
    )
    print(reply)
    if not _usable_model_text(reply):
        print("[*] Gap pass empty — keeping harvested report.")
        return [], []
    if re.search(r"NO_NEW_FINDINGS", reply, re.IGNORECASE):
        print("[*] Gap pass: no new findings.")
        return [], []
    new_v = filter_gap_vulns(parse_vulnerabilities(reply), leftovers)
    new_e = parse_exploits(reply)
    print(f"[*] Gap pass proposed: {len(new_v)} vulns, {len(new_e)} exploits")
    return new_v, new_e


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    host = _session_host(target)
    origin = preferred_origin(target, raw_scan)
    is_wp = looks_like_wordpress(raw_scan)
    is_lan = bool(lan_ips_for_target(target)[0])

    ran_tools = tools_from_text(raw_scan)
    searched_cves = set()
    curled_urls = set()
    ran_injection_urls = {}
    ran_scenarios = set()
    retargeted = set()
    ran_keys = set()
    for name in ran_tools:
        ran_keys.add(run_key(name, origin, "default", ""))
    discovered = harvest_urls(raw_scan, host, origin=origin)
    all_cves = extract_cves(raw_scan)
    cve_urls = harvest_cve_urls(raw_scan, host)
    evidence_chunks = []
    transcript = []
    scan_parts = [raw_scan or ""]
    harvested = harvest_findings(raw_scan, host=host)
    digest = format_digest(harvested)
    recon_highlights = summarize_tool_output(raw_scan or "", host)
    if len(recon_highlights) > 8000:
        recon_highlights = recon_highlights[:8000] + "\n[truncated]"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"TARGET: {target}\nORIGIN: {origin}\n"
                f"LAN: {'yes' if is_lan else 'no'}\n\n"
                f"{digest}\n\n"
                f"{already_ran_text(ran_keys)}\n\n"
                f"RECON HIGHLIGHTS:\n{recon_highlights}\n\n"
                "Write PLAN: then [TOOL: name TARGET:... PROFILE:...] and [SEARCH: CVE] tags.\n"
                "Do not invent flags. Do not write RISK_LEVEL yet.\n"
                "If recon is enough, write PLAN: done with no TOOL tags."
            ),
        },
    ]

    for loop in range(MAX_TOOL_LOOPS):
        unverified = [c for c in all_cves if c not in searched_cves]
        curl_pending = pending_curl_urls(cve_urls, curled_urls)
        loops_left = MAX_TOOL_LOOPS - loop

        response = ask_ollama(messages)
        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)
        if not _usable_model_text(response):
            print("[!] Skipping empty/error model round.")
            continue
        transcript.append(response)

        model_calls = sanitize_calls(extract_tool_calls(response), origin, is_wp)
        auto_calls = []
        if unverified or curl_pending:
            auto_calls = build_auto_dispatch(unverified, cve_urls, curled_urls)
        auto_calls = sanitize_calls(auto_calls, origin, is_wp)
        calls = merge_calls(model_calls, auto_calls)
        auto = bool(auto_calls) and any(c not in model_calls for c in calls)
        if auto and auto_calls:
            print(f"\n[*] Auto-dispatch fill ({len(auto_calls)} candidates): "
                  + ", ".join(f"{t} {c}" for t, c in auto_calls[:6]))

        plan_done = bool(re.search(r"PLAN:\s*done\b", response or "", re.I))
        if not calls:
            if plan_done or loop > 0:
                print("\n[*] No further tools. Moving to finalize.")
                break
            print("\n[*] No tool tags this round.")
            messages.append({"role": "assistant", "content": response})
            messages.append({
                "role": "user",
                "content": checklist_message(
                    unverified, discovered, loops_left - 1, curl_pending, ran_keys,
                ),
            })
            continue

        record_calls(
            calls, ran_tools, searched_cves, curled_urls, ran_injection_urls,
            ran_scenarios=ran_scenarios, ran_keys=None,
        )
        tool_results, ran_keys = run_tool_calls(
            calls, session_host=host, is_wp=is_wp, origin=origin,
            ran_keys=ran_keys, is_lan=is_lan,
        )
        evidence_chunks.append(tool_results)
        scan_parts.append(tool_results)
        harvested = harvest_findings("\n".join(scan_parts), host=host)
        digest = format_digest(harvested)

        all_cves = list(dict.fromkeys(all_cves + extract_cves(tool_results)))
        cve_urls.update(harvest_cve_urls(tool_results, host))
        for url in harvest_urls(tool_results, host, origin=origin):
            if url not in discovered:
                discovered.append(url)

        messages.append({"role": "assistant", "content": response})
        unverified = [c for c in all_cves if c not in searched_cves]
        curl_pending = pending_curl_urls(cve_urls, curled_urls)
        nudge = checklist_message(
            unverified, discovered, loops_left - 1, curl_pending, ran_keys,
        )
        prefix = "[AUTO-DISPATCH RESULTS]\n" if auto else "[TOOL RESULTS]\n"
        messages.append({
            "role": "user",
            "content": f"{prefix}{tool_results}\n\n{digest}\n\n{nudge}",
        })

        if plan_done and not unverified and not curl_pending:
            print("\n[*] PLAN: done and CVE SEARCH complete.")
            break

    harvested = harvest_findings("\n".join(scan_parts), host=host)
    digest = format_digest(harvested)
    finalize_user = (
        f"TARGET: {target}\nORIGIN: {origin}\n\n"
        f"{digest}\n\n"
        f"SEARCHED CVEs: {', '.join(sorted(searched_cves)) or 'none'}\n"
        f"DISCOVERED_URLS:\n" + "\n".join(ranked_urls(discovered)[:20]) + "\n\n"
        "Write the schema-only report now. Include every EXTRACTED FINDING that is a real issue."
    )
    print(f"\n{'─'*60}")
    print("[METATRON - Finalize]")
    print(f"{'─'*60}")
    finalize_response = ask_ollama(
        [
            {"role": "system", "content": FINALIZE_PROMPT},
            {"role": "user", "content": finalize_user},
        ],
        retries=2,
    )
    print(finalize_response)
    if _usable_model_text(finalize_response) and _looks_like_schema(finalize_response):
        transcript.append(finalize_response)

    record_text = _pick_schema_text(finalize_response, transcript)
    if record_text and record_text != finalize_response:
        print("[*] Finalize empty or unparsed — using last schema reply.")
        print(record_text)
    elif not record_text:
        print("[*] Finalize empty or unparsed — using harvested findings.")

    harvested_vulns = findings_to_vulns(harvested)
    harvested_exploits = findings_to_exploits(harvested)
    vulnerabilities = merge_vulns(parse_vulnerabilities(record_text), harvested_vulns)
    exploits = merge_exploits(parse_exploits(record_text), harvested_exploits)
    risk_level = parse_risk_level(record_text)
    if risk_level == "UNKNOWN":
        risk_level = derive_risk(harvested, vulnerabilities)
    summary = parse_summary(record_text)
    if not summary:
        summary = canned_summary(target, harvested, risk_level)

    leftovers = leftover_interesting_lines(
        "\n".join(scan_parts),
        reported=harvested + vulnerabilities + exploits,
    )
    gap_v, gap_e = _run_gap_pass(target, vulnerabilities, exploits, leftovers)
    if gap_v or gap_e:
        vulnerabilities = merge_vulns(vulnerabilities, gap_v)
        exploits = merge_exploits(exploits, gap_e)
        if parse_risk_level(record_text) == "UNKNOWN":
            risk_level = derive_risk(harvested, vulnerabilities)

    if not record_text or not _looks_like_schema(record_text):
        record_text = schema_text_from_harvest(
            vulnerabilities, exploits, risk_level, summary,
        )

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    tools_run = [already_ran_text(ran_keys).replace("ALREADY_RAN:\n", "").replace("(none)", "")]
    tools_run = [ln for ln in already_ran_text(ran_keys).splitlines()[1:] if ln and ln != "(none)"]
    md_text = render_markdown_report(
        target,
        risk=risk_level,
        summary=summary,
        vulns=vulnerabilities,
        exploits=exploits,
        tools_run=tools_run,
    )
    md_path = ""
    dest_dir = current_results_dir()
    if dest_dir is not None:
        md_path = write_markdown_file(md_text, Path(dest_dir) / "report.md")
        print(f"[+] Markdown report: {md_path}")
    try:
        md_copy = write_markdown_file(
            md_text,
            Path(reports_dir()) / "metatron_last.md",
        )
        if not md_path:
            md_path = md_copy
    except OSError:
        pass

    return {
        "full_response": record_text,
        "vulnerabilities": vulnerabilities,
        "exploits": exploits,
        "risk_level": risk_level,
        "summary": summary,
        "raw_scan": raw_scan,
        "ran_keys": tools_run,
        "markdown": md_text,
        "markdown_path": md_path,
    }


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    try:
        r = requests.get("http://localhost:11434", timeout=5)
        print("[+] Ollama is running.")
    except Exception:
        print("[!] Ollama not reachable. Run: ollama serve")
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
