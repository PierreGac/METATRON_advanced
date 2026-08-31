#!/usr/bin/env python3
"""
METATRON - tools.py
Recon and web-testing tool runners — output is streamed live, saved to disk,
and returned as strings to feed into the LLM.
OS: Parrot OS (tools pre-installed or easily available)
"""

import copy
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dispatch import (
    DEFAULT_WAVES,
    apply_safety_gates,
    dry_run_enabled,
    format_tool_call,
    group_jobs_by_wave,
    parse_tool_tag,
    run_key,
    sanitize_tool_chunk,
    throttle_resources,
    tools_by_wave,
)


PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "tools_config.json"

TOOL_INSTALL_HINTS = {
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "httpx": "sudo apt install httpx-toolkit  # or: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && export PATH=\"$(go env GOPATH)/bin:$PATH\"",
    "httpx-toolkit": "sudo apt install httpx-toolkit",
    "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest  # then: export PATH=\"$(go env GOPATH)/bin:$PATH\"",
    "ffuf": "sudo apt install ffuf || go install github.com/ffuf/ffuf/v2@latest",
    "sqlmap": "git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap  # apt 1.9.x is flagged outdated",
    "wapiti": "pip install -U wapiti3  # apt 3.0.x has a broken wapp database",
    "commix": "git clone https://github.com/commixproject/commix.git /opt/commix  # apt is often stale",
    "wpscan": "sudo apt install wpscan || sudo gem install wpscan",
    "playwright": "pip install playwright && playwright install chromium",
    "testssl.sh": "sudo apt install testssl.sh",
    "zaproxy": "sudo apt install zaproxy  # binary may be zap.sh",
    "arp-scan": "sudo apt install arp-scan",
    "seclists": "sudo apt install seclists",
    "searchsploit": "sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && sudo chmod +x /opt/exploitdb/searchsploit && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && sudo git clone https://gitlab.com/exploit-database/exploitdb-papers.git /opt/exploitdb-papers",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest  # then: export PATH=\"$(go env GOPATH)/bin:$PATH\"",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "masscan": "sudo apt install masscan",
}


def tool_install_hint(name: str) -> str:
    """Install hint for a missing tool. searchsploit adapts if /opt/exploitdb already exists."""
    if name == "searchsploit":
        script = Path("/opt/exploitdb/searchsploit")
        if script.is_file():
            return (
                "sudo chmod +x /opt/exploitdb/searchsploit && "
                "sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit"
            )
        if Path("/opt/exploitdb").exists():
            return (
                "sudo rm -rf /opt/exploitdb && "
                "sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && "
                "sudo chmod +x /opt/exploitdb/searchsploit && "
                "sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit"
            )
    return TOOL_INSTALL_HINTS.get(name, f"sudo apt install {name}")


DEFAULT_WORDLIST = "Discovery/Web-Content/common.txt"
DIRB_FALLBACKS = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
)
SECLISTS_ROOT_CANDIDATES = (
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
)
WORDLIST_ABS_PREFIXES = (
    "/usr/share/seclists/",
    "/usr/share/wordlists/seclists/",
    "/usr/share/wordlists/",
)
DIR_FILE_PREFS = (
    "common.txt",
    "wordpress.fuzz.txt",
    "api-endpoints.txt",
    "Generic-SQLi.txt",
    "XSS-Jhaddix.txt",
    "burp-parameter-names.txt",
    "big.txt",
    "directory-list-2.3-medium.txt",
    "Common-DB-Backups.txt",
)
WORDLIST_TAG_RE = re.compile(r"^(?:SCENARIO|WORDLIST):(.+)$", re.IGNORECASE)

DEFAULT_WORDLISTS = {
    "wordpress": {
        "path": "Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "tools": ["gobuster", "ffuf"],
        "mode": "path",
    },
    "api": {
        "path": "Discovery/Web-Content/api/api-endpoints.txt",
        "tools": ["gobuster", "ffuf"],
        "mode": "path",
    },
    "backups": {
        "path": "Discovery/Web-Content/Common-DB-Backups.txt",
        "tools": ["gobuster", "ffuf"],
        "mode": "path",
    },
    "sqli": {
        "path": "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        "fallbacks": ["Fuzzing/SQLi/Generic-SQLi.txt"],
        "tools": ["ffuf"],
        "mode": "value",
    },
    "xss": {
        "path": "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
        "tools": ["ffuf", "dalfox"],
        "mode": "value",
    },
    "parameters": {
        "path": "Discovery/Web-Content/burp-parameter-names.txt",
        "tools": ["ffuf"],
        "mode": "param",
    },
}

DEFAULT_CONFIG = {
    "_global": {
        "max_log_lines": 2000,
        "timeout_retry_multiplier": 2,
        "results_dir": "scan_results",
        "wordlists_root": "",
        "max_workers": 4,
        "ram_percent_limit": 85,
        "load_per_cpu_limit": 2.0,
        "max_injection_endpoints": 3,
        "max_exploit_runs": 1,
        "exploit_requires_detect": True,
        "write_raw_logs": False,
        "idle_reset": True,
    },
    "waves": DEFAULT_WAVES,
    "wordlists": DEFAULT_WORDLISTS,
    "nmap": {"timeout": 180, "args": ["-sV", "-sC", "-T4", "--open", "{host}"], "extra_args": []},
    "whois": {"timeout": 30, "args": ["{host}"], "extra_args": []},
    "whatweb": {"timeout": 60, "args": ["-a", "3", "{target}"], "extra_args": []},
    "curl": {"timeout": 20, "args": ["-I", "--max-time", "10"], "extra_args": []},
    "dig": {"timeout": 15, "args": ["+short"], "extra_args": []},
    "nikto": {"timeout": 300, "args": ["-h", "{url}", "-ssl", "-nointeractive"], "extra_args": []},
    "gobuster": {
        "timeout": 300,
        "wordlist": "Discovery/Web-Content/big.txt",
        "args": ["dir", "-u", "{url}", "-w", "{wordlist}", "-r", "-e"],
        "extra_args": [],
    },
    "arp-scan": {"timeout": 60, "args": ["--ignoredups", "{target}"], "extra_args": []},
    "sslscan": {"timeout": 240, "args": ["--no-colour", "{host}"], "extra_args": []},
    "testssl.sh": {"timeout": 300, "args": ["{host}"], "extra_args": []},
    "katana": {"timeout": 180, "depth": 2, "args": ["-u", "{url}", "-d", "{depth}", "-jc"], "extra_args": []},
    "nuclei": {"timeout": 300, "args": ["-u", "{url}"], "extra_args": []},
    "httpx": {
        "timeout": 60,
        "args": ["-u", "{url}", "-title", "-tech-detect", "-status-code"],
        "extra_args": [],
    },
    "ffuf": {
        "timeout": 300,
        "wordlist": "Discovery/Web-Content/directory-list-2.3-big.txt",
        "args": ["-u", "{url}/FUZZ", "-w", "{wordlist}"],
        "extra_args": [],
    },
    "sqlmap": {
        "timeout": 420,
        "crawl": 1,
        "args": ["-u", "{url}", "--batch", "--crawl={crawl}"],
        "extra_args": [],
    },
    "wapiti": {
        "timeout": 120,
        "idle_reset": True,
        "max_timeout": 3600,
        "args": ["-u", "{url}", "-v", "2"],
        "extra_args": [],
    },
    "dalfox": {
        "timeout": 300,
        "wordlist": "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
        "args": ["url", "{url}", "--custom-payload", "{wordlist}"],
        "extra_args": [],
    },
    "commix": {
        "timeout": 600,
        "crawl": 2,
        "args": ["--url", "{url}", "--batch", "--crawl={crawl}"],
        "extra_args": [],
    },
    "wpscan": {"timeout": 300, "args": ["--url", "{url}"], "extra_args": []},
    "zaproxy": {
        "timeout": 120,
        "idle_reset": True,
        "max_timeout": 3600,
        "args": [
            "-cmd", "-quickurl", "{url}",
            "-config", "spider.maxChildren=10",
            "-config", "spider.maxDepth=2",
            "-config", "spider.maxDuration=5",
            "-config", "scanner.threadPerHost=2",
        ],
        "extra_args": [],
    },
    "playwright": {
        "timeout": 180,
        "max_clicks": 15,
        "click_timeout_ms": 5000,
        "headless": True,
        "allowed_hosts": [],
        "allow_subdomains": False,
    },
    "searchsploit": {
        "timeout": 30,
        "args": ["--colour", "disable", "--www"],
        "extra_args": [],
    },
    "gau": {
        "timeout": 180,
        "args": ["{host}", "--subs"],
        "extra_args": ["--blacklist", "png,jpg,gif,svg,woff,woff2,css,ico"],
    },
    "subfinder": {
        "timeout": 120,
        "args": ["-d", "{host}", "-silent"],
        "extra_args": [],
    },
    "masscan": {
        "timeout": 180,
        "args": ["{target}", "-p1-65535", "--rate", "1000", "--wait", "3"],
        "extra_args": [],
    },
}

_config = None
_version_cache = {}
_current_results_dir = None
_log_lock = threading.Lock()
_print_lock = threading.Lock()


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

def _http_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _scheme_urls(target: str) -> tuple:
    """Return (http_url, https_url) so curl can probe both schemes."""
    raw = (target or "").strip()
    if raw.startswith("https://"):
        https_url = raw
        http_url = "http://" + raw[len("https://"):]
    elif raw.startswith("http://"):
        http_url = raw
        https_url = "https://" + raw[len("http://"):]
    else:
        http_url = f"http://{raw}"
        https_url = f"https://{raw}"
    return http_url, https_url


def _hostname(target: str) -> str:
    """Hostname or IP from a URL, host:port, or bare host — no scheme or path."""
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        return host.strip("[]")
    host = raw.split("/")[0]
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            return left
    return host


def _is_ip(host: str) -> bool:
    raw = (host or "").strip("[]")
    if not raw:
        return False
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


def _apex_host(target: str) -> str:
    host = (_hostname(target) or "").lower().rstrip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def is_domain_name(target: str) -> bool:
    """True when the target is a DNS name (not an IP), suitable for subfinder/gau."""
    host = _hostname(target)
    if not host or _is_ip(host):
        return False
    if host.lower() in ("localhost",):
        return False
    return "." in host


def _is_lan_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address((ip_str or "").strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def lan_ips_for_target(target: str) -> tuple:
    """
    Resolve the target and return (ok, ips, reason).
    ok is True only if every resolved address is RFC1918, loopback, or link-local.
    Fails closed on DNS errors or any public address.
    """
    host = _hostname(target)
    if not host:
        return False, [], "empty host"
    if _is_ip(host):
        if _is_lan_ip(host):
            return True, [host], ""
        return False, [], f"{host} is not a LAN address"
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        return False, [], f"DNS failed: {exc}"
    addrs = []
    seen = set()
    for info in infos:
        addr = info[4][0]
        if "%" in addr:
            addr = addr.split("%", 1)[0]
        if addr in seen:
            continue
        seen.add(addr)
        if not _is_lan_ip(addr):
            return False, [], f"{host} resolves to public address {addr}"
        addrs.append(addr)
    if not addrs:
        return False, [], f"no addresses for {host}"
    return True, addrs, ""


def load_tools_config(force: bool = False) -> dict:
    """Load tools_config.json, merged over in-code defaults."""
    global _config
    if _config is not None and not force:
        return _config

    merged = copy.deepcopy(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            print(f"[!] {CONFIG_PATH.name} is not a JSON object — using defaults.")
            _config = merged
            return _config
        for key, value in data.items():
            if key == "_global" and isinstance(value, dict):
                merged["_global"].update(value)
            elif key == "wordlists" and isinstance(value, dict):
                bucket = merged.setdefault("wordlists", {})
                for name, spec in value.items():
                    if isinstance(spec, dict) and isinstance(bucket.get(name), dict):
                        bucket[name].update(spec)
                    else:
                        bucket[name] = spec
            elif isinstance(value, dict):
                merged.setdefault(key, {}).update(value)
            else:
                merged[key] = value
        _config = merged
    except FileNotFoundError:
        print(f"[!] Config not found: {CONFIG_PATH} — using built-in defaults.")
        _config = merged
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON in {CONFIG_PATH}: {exc} — using built-in defaults.")
        _config = merged
    return _config


def get_tool_config(name: str) -> dict:
    cfg = load_tools_config()
    tool_cfg = cfg.get(name, {})
    if not isinstance(tool_cfg, dict):
        return {}
    return tool_cfg


def get_waves_config() -> list:
    cfg = load_tools_config()
    waves = cfg.get("waves")
    if isinstance(waves, list) and waves:
        return waves
    return list(DEFAULT_WAVES)


def resolve_profile(cfg: dict, name: str = None) -> dict:
    """
    Merge PROFILE inheritance. Child args replace if present; extra_args append.
    Unknown profile names fall back to default_profile then top-level args.
    """
    cfg = cfg if isinstance(cfg, dict) else {}
    result = dict(cfg)
    profiles = cfg.get("profiles") if isinstance(cfg.get("profiles"), dict) else {}
    default_name = str(cfg.get("default_profile") or "default").strip().lower() or "default"
    wanted = (name or default_name).strip().lower() or default_name

    def _base_from_top():
        return {
            "timeout": cfg.get("timeout"),
            "crawl": cfg.get("crawl"),
            "depth": cfg.get("depth"),
            "idle_reset": cfg.get("idle_reset"),
            "max_timeout": cfg.get("max_timeout"),
            "wordlist": cfg.get("wordlist"),
            "args": list(cfg.get("args") or []),
            "extra_args": list(cfg.get("extra_args") or []),
        }

    if wanted not in profiles:
        if name and wanted != default_name:
            print(f"  [!] Unknown PROFILE:{wanted} — using {default_name}")
            wanted = default_name
        if wanted not in profiles:
            merged = _base_from_top()
            result.update({k: v for k, v in merged.items() if v is not None or k in ("args", "extra_args")})
            result["_profile"] = wanted
            return result

    def _merge(profile_name, seen):
        if profile_name in seen:
            print(f"  [!] PROFILE cycle involving {profile_name} — using default")
            return _base_from_top()
        seen = seen | {profile_name}
        spec = profiles.get(profile_name)
        if not isinstance(spec, dict):
            return _base_from_top()
        parent_name = str(spec.get("extends") or "").strip().lower()
        if parent_name:
            base = _merge(parent_name, seen)
        else:
            base = _base_from_top()
        out = dict(base)
        for key in ("timeout", "crawl", "depth", "idle_reset", "max_timeout", "wordlist"):
            if key in spec and spec[key] is not None:
                out[key] = spec[key]
        if spec.get("args") is not None:
            out["args"] = list(spec.get("args") or [])
        inherited = list(out.get("extra_args") or [])
        for item in list(spec.get("extra_args") or []):
            if item not in inherited:
                inherited.append(item)
        out["extra_args"] = inherited
        return out

    merged = _merge(wanted, set())
    result.update({k: v for k, v in merged.items() if v is not None or k in ("args", "extra_args")})
    result["_profile"] = wanted
    return result


def get_global_config() -> dict:
    cfg = load_tools_config()
    global_cfg = cfg.get("_global", {})
    return global_cfg if isinstance(global_cfg, dict) else {}


def _timeout_policy(cfg: dict = None) -> tuple:
    """
    timeout is silence seconds by default: any tool output resets the timer.
    Set idle_reset false on a tool (or _global) for wall-clock timeout.
    max_timeout is an optional hard cap from process start (0 = none).
    """
    global_cfg = get_global_config()
    cfg = cfg if isinstance(cfg, dict) else {}
    if cfg.get("idle_reset") is not None:
        idle = bool(cfg.get("idle_reset"))
    elif global_cfg.get("idle_reset") is not None:
        idle = bool(global_cfg.get("idle_reset"))
    else:
        idle = True
    try:
        max_timeout = int(cfg.get("max_timeout") or global_cfg.get("max_timeout") or 0)
    except (TypeError, ValueError):
        max_timeout = 0
    return idle, max_timeout


def _run_tool_timeout_kwargs(tool: str = "", cfg: dict = None) -> dict:
    idle, max_timeout = _timeout_policy(cfg if cfg is not None else get_tool_config(tool))
    return {"idle_reset": idle, "max_timeout": max_timeout}


def _looks_like_seclists_root(path: str) -> bool:
    root = Path(path)
    return root.is_dir() and (root / "Discovery").is_dir()


def detect_wordlists_root() -> str:
    """Return the SecLists root, or '' if none is present."""
    configured = str(get_global_config().get("wordlists_root") or "").strip()
    if configured:
        if _looks_like_seclists_root(configured):
            return configured
        if Path(configured).is_dir():
            return configured
    for candidate in SECLISTS_ROOT_CANDIDATES:
        if _looks_like_seclists_root(candidate):
            return candidate
    return ""


def get_wordlist_scenarios() -> dict:
    cfg = load_tools_config()
    scenarios = cfg.get("wordlists") or {}
    return scenarios if isinstance(scenarios, dict) else {}


def list_wordlist_scenarios(tool: str = None) -> list:
    names = []
    for name, spec in get_wordlist_scenarios().items():
        if not isinstance(spec, dict):
            continue
        allowed = spec.get("tools") or []
        if tool and allowed and tool not in allowed:
            continue
        names.append(str(name).lower())
    return names


def get_scenario(name: str, tool: str = None):
    """Return scenario spec if it exists and is allowed for this tool."""
    key = (name or "").strip().lower()
    if not key:
        return None
    spec = get_wordlist_scenarios().get(key)
    if not isinstance(spec, dict):
        return None
    allowed = spec.get("tools") or []
    if tool and allowed and tool not in allowed:
        return None
    return spec


def _to_relative_wordlist(path: str) -> str:
    raw = (path or "").replace("\\", "/").strip()
    for prefix in WORDLIST_ABS_PREFIXES:
        if raw.startswith(prefix):
            rest = raw[len(prefix):]
            if rest.startswith("Discovery/") or rest.startswith("Fuzzing/"):
                return rest
    return raw


def _pick_txt_from_dir(directory: Path) -> str:
    files = [
        f for f in directory.iterdir()
        if f.is_file()
        and f.suffix.lower() == ".txt"
        and f.name.lower() not in ("readme.txt", "license.txt")
    ]
    if not files:
        return ""
    lower = {f.name.lower(): f for f in files}
    for pref in DIR_FILE_PREFS:
        if pref.lower() in lower:
            return str(lower[pref.lower()])
    fuzz = sorted(f for f in files if f.name.lower().endswith(".fuzz.txt"))
    if fuzz:
        return str(fuzz[0])
    return str(sorted(files, key=lambda f: f.name.lower())[0])


def _file_from_candidate(path: str) -> str:
    if not path:
        return ""
    p = Path(path)
    if p.is_file():
        return str(p)
    if p.is_dir():
        return _pick_txt_from_dir(p)
    return ""


def _expand_wordlist_path(path: str, root: str) -> list:
    """Absolute path plus root-relative variants to try."""
    raw = (path or "").strip()
    if not raw:
        return []
    out = []
    if Path(raw).is_absolute():
        out.append(raw)
        rel = _to_relative_wordlist(raw)
        if rel != raw and root:
            out.append(str(Path(root) / rel))
    elif root:
        out.append(str(Path(root) / raw))
        out.append(raw)
    else:
        out.append(raw)
    seen = set()
    unique = []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def resolve_wordlist(cfg: dict, scenario: str = None, tool: str = None) -> str:
    """
    Resolve a wordlist file. Relative paths are joined to the detected
    SecLists root. Named scenarios are allowlisted in tools_config.json.
    """
    cfg = cfg if isinstance(cfg, dict) else {}
    root = detect_wordlists_root()
    candidates = []
    key = (scenario or "").strip().lower()
    if key:
        spec = get_scenario(key, tool=tool)
        if spec is None:
            if get_wordlist_scenarios().get(key) is not None:
                print(f"  [!] SCENARIO:{key} is not valid for {tool or 'this tool'} — using default wordlist")
            else:
                print(f"  [!] Unknown SCENARIO:{key} — using default wordlist")
            key = ""
        else:
            for item in [spec.get("path"), *(spec.get("fallbacks") or [])]:
                if item:
                    candidates.extend(_expand_wordlist_path(str(item), root))
    if not candidates:
        configured = str(cfg.get("wordlist") or DEFAULT_WORDLIST)
        candidates.extend(_expand_wordlist_path(configured, root))
        if root:
            candidates.extend(_expand_wordlist_path(DEFAULT_WORDLIST, root))
        candidates.extend(DIRB_FALLBACKS)

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        found = _file_from_candidate(candidate)
        if found:
            configured = str(cfg.get("wordlist") or "")
            if key:
                print(f"  [*] wordlist scenario {key}: {found}")
            elif configured and found != configured and not Path(configured).is_file():
                print(f"  [*] wordlist {configured} missing — using {found}")
            return found

    fallback = candidates[0] if candidates else (cfg.get("wordlist") or DEFAULT_WORDLIST)
    return str(fallback)


def _ffuf_url_for_mode(target: str, mode: str) -> str:
    url = _http_url(target)
    parsed = urlparse(url)
    mode = (mode or "path").lower()
    if mode == "value":
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if pairs:
            last_key, _ = pairs[-1]
            pairs = list(pairs[:-1]) + [(last_key, "FUZZ")]
            return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))
        return urlunparse(parsed._replace(query="q=FUZZ"))
    if mode == "param":
        return urlunparse(parsed._replace(query="FUZZ=1"))
    return url


def _strip_flag_and_value(command: list, flag: str) -> list:
    out = []
    skip = False
    for arg in command:
        if skip:
            skip = False
            continue
        if arg == flag:
            skip = True
            continue
        out.append(arg)
    return out


def _apply_ffuf_scenario(command: list, target: str, mode: str) -> list:
    mode = (mode or "path").lower()
    if mode == "path":
        return command
    out = list(command)
    new_url = _ffuf_url_for_mode(target, mode)
    try:
        idx = out.index("-u")
        out[idx + 1] = new_url
    except (ValueError, IndexError):
        pass
    return _strip_flag_and_value(out, "-e")


def substitute_args(args: list, target: str, cfg: dict, wordlist: str = None) -> list:
    url = _http_url(target)
    host = _hostname(target)
    if wordlist is None:
        wordlist = resolve_wordlist(cfg)
    try:
        crawl_n = int(cfg.get("crawl", 1) or 1)
    except (TypeError, ValueError):
        crawl_n = 1
    crawl = str(max(1, min(3, crawl_n)))
    depth = str(cfg.get("depth", 2))
    mapping = {
        "{target}": target,
        "{url}": url,
        "{host}": host,
        "{wordlist}": wordlist,
        "{crawl}": crawl,
        "{depth}": depth,
    }
    out = []
    for arg in args:
        arg = str(arg)
        for placeholder, value in mapping.items():
            arg = arg.replace(placeholder, value)
        out.append(arg)
    return out


def build_command(binary: str, target: str, cfg: dict, scenario: str = None, tool: str = None, profile: str = None) -> list:
    """Build argv. Binary (argv[0]) is never taken from JSON args/extra_args."""
    logical = tool or Path(str(binary)).name
    cfg = resolve_profile(cfg, profile)
    wordlist = resolve_wordlist(cfg, scenario=scenario, tool=logical)
    args = substitute_args(list(cfg.get("args") or []), target, cfg, wordlist=wordlist)
    extra = substitute_args(list(cfg.get("extra_args") or []), target, cfg, wordlist=wordlist)
    prefix = [sys.executable, binary] if str(binary).endswith(".py") else [binary]
    command = prefix + args + extra
    if logical == "ffuf" and scenario:
        spec = get_scenario(scenario, tool="ffuf")
        if spec:
            command = _apply_ffuf_scenario(command, target, spec.get("mode") or "path")
    return command


def _help_blob(binary: str) -> str:
    try:
        result = subprocess.run(
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=8,
            encoding="utf-8",
            errors="replace",
        )
        return ((result.stdout or "") + (result.stderr or "")).lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _is_projectdiscovery_httpx(binary: str) -> bool:
    blob = _help_blob(binary)
    if not blob:
        return False
    if "projectdiscovery" in blob or "-tech-detect" in blob or "-status-code" in blob:
        return True
    if "-u string" in blob or "-u, -list" in blob:
        return True
    return "-title" in blob and " -u" in blob


def _go_bin(name: str) -> str:
    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    path = Path(gopath) / "bin" / name
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return ""


def _project_venv_bin(name: str) -> str:
    path = Path(__file__).parent / "venv" / "bin" / name
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return ""


def resolve_tool_binary(logical_name: str) -> str:
    """
    Map a config/allowlist name to an executable on PATH.
    httpx: prefer httpx-toolkit / Go install over the Python httpx CLI.
    sqlmap: prefer GitHub /opt/sqlmap or venv over outdated apt.
    commix: prefer GitHub /opt/commix over outdated apt.
    searchsploit: prefer GitLab /opt/exploitdb over apt exploitdb.
    wapiti: prefer venv wapiti3 over apt 3.0.x.
    zaproxy: also try zap.sh / owasp-zap.
    Optional tools_config.json field "binary" overrides.
    """
    cfg = get_tool_config(logical_name)
    override = str(cfg.get("binary") or "").strip()
    if override:
        return override

    if logical_name in ("httpx", "httpx-toolkit"):
        found = shutil.which("httpx-toolkit")
        if found:
            return found
        go_httpx = _go_bin("httpx")
        if go_httpx and _is_projectdiscovery_httpx(go_httpx):
            return go_httpx
        path_httpx = shutil.which("httpx")
        if path_httpx and _is_projectdiscovery_httpx(path_httpx):
            return path_httpx
        if go_httpx:
            return go_httpx
        return path_httpx or "httpx-toolkit"

    if logical_name == "searchsploit":
        for candidate in (Path("/usr/local/bin/searchsploit"), Path("/opt/exploitdb/searchsploit")):
            # A complete clone is enough; +x / PATH symlink may still be missing.
            if candidate.is_file():
                return str(candidate)
        return shutil.which("searchsploit") or "searchsploit"

    if logical_name == "sqlmap":
        for candidate in (Path("/usr/local/bin/sqlmap"), Path("/opt/sqlmap/sqlmap.py")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        venv_sqlmap = _project_venv_bin("sqlmap")
        if venv_sqlmap:
            return venv_sqlmap
        return shutil.which("sqlmap") or "sqlmap"

    if logical_name == "commix":
        for candidate in (Path("/usr/local/bin/commix"), Path("/opt/commix/commix.py")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        opt_py = Path("/opt/commix/commix.py")
        if opt_py.is_file():
            return str(opt_py)
        return shutil.which("commix") or "commix"

    if logical_name == "wapiti":
        venv_wapiti = _project_venv_bin("wapiti")
        if venv_wapiti:
            return venv_wapiti
        local = Path("/usr/local/bin/wapiti")
        if local.is_file() and os.access(local, os.X_OK):
            return str(local)
        return shutil.which("wapiti") or "wapiti"

    if logical_name == "zaproxy":
        for candidate in ("zaproxy", "owasp-zap", "zap.sh"):
            found = shutil.which(candidate)
            if found:
                return found
        zap_sh = Path("/usr/share/zaproxy/zap.sh")
        if zap_sh.is_file():
            return str(zap_sh)
        return "zaproxy"

    found = shutil.which(logical_name)
    if found:
        return found
    go = _go_bin(logical_name)
    if go:
        return go
    return logical_name


def _editor_cmd() -> str:
    if os.environ.get("EDITOR"):
        return os.environ["EDITOR"]
    if os.name == "nt":
        return "notepad"
    return "nano"


def open_config_editor() -> None:
    cmd = _editor_cmd()
    print(f"[*] Opening {CONFIG_PATH} with {cmd}...")
    try:
        subprocess.call([cmd, str(CONFIG_PATH)])
    except FileNotFoundError:
        print(f"[!] Editor '{cmd}' not found. Set $EDITOR or edit {CONFIG_PATH} manually.")
        input("Press Enter when done editing...")


def print_config_preview(selected_names: list) -> None:
    cfg = load_tools_config()
    print("\n[ TOOL CONFIGURATION ]")
    global_cfg = cfg.get("_global", {})
    print("=== _global ===")
    print(json.dumps(global_cfg, indent=2))
    print()
    for name in selected_names:
        tool_cfg = cfg.get(name, {})
        print(f"=== {name} ===")
        print(json.dumps(tool_cfg, indent=2))
        print()


def prompt_edit_config(selected_names: list) -> None:
    """Show per-tool JSON and optionally open the editor before running."""
    while True:
        load_tools_config(force=True)
        print_config_preview(selected_names)
        choice = input("[Enter] Run with this configuration  [e] Edit tools_config.json: ").strip().lower()
        if choice != "e":
            return
        open_config_editor()
        try:
            with open(CONFIG_PATH, encoding="utf-8") as fh:
                json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] Config is invalid after edit: {exc}")
            print("    Enter uses built-in defaults if the file still fails to load.")
            continue
        load_tools_config(force=True)


# ─────────────────────────────────────────────
# RESULTS DIR / LOG HELPERS
# ─────────────────────────────────────────────

def sanitize_target(target: str) -> str:
    text = target.strip()
    text = re.sub(r"^https?://", "", text, flags=re.IGNORECASE)
    text = re.sub(r"[^\w.\-]+", "_", text)
    return (text[:80] or "target").strip("._") or "target"


def resolve_results_root() -> Path:
    """Resolve scan_results against the project directory, not process CWD."""
    root = str(get_global_config().get("results_dir", "scan_results") or "scan_results")
    path = Path(root).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def reports_dir() -> Path:
    path = PROJECT_ROOT / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def start_results_dir(target: str) -> Path:
    global _current_results_dir
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = resolve_results_root() / sanitize_target(target) / stamp
    path.mkdir(parents=True, exist_ok=True)
    _current_results_dir = path
    print(f"[+] Saving full tool logs to: {path}")
    return path


def current_results_dir():
    """Active scan_results/<target>/<stamp> directory, or None."""
    return _current_results_dir


def _truncate_log(text: str, max_lines: int) -> str:
    if max_lines <= 0:
        return text
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    head = max(1, int(max_lines * 0.2))
    tail = max(max_lines - head, 1)
    omitted = len(lines) - head - tail
    if omitted <= 0:
        return text
    return "\n".join(lines[:head] + [f"--- truncated {omitted} lines ---"] + lines[-tail:])


def _probe_version(binary: str) -> str:
    if binary in _version_cache:
        return _version_cache[binary]
    if binary in (sys.executable, "python", "python3"):
        _version_cache[binary] = ""
        return ""
    attempts = (("version",), ("--version",), ("-V",))
    for argv in attempts:
        try:
            result = subprocess.run(
                [binary, *argv],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                continue
            blob = (result.stdout or "") + (result.stderr or "")
            lower = blob.lower()
            if "unknown flag" in lower or "unknown option" in lower:
                continue
            summary = _version_summary(blob)
            if summary:
                _version_cache[binary] = summary
                print(f"  [version] {binary}: {summary}")
                return summary
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    _version_cache[binary] = ""
    return ""


def _version_summary(blob: str) -> str:
    """Pick a short version line; skip ASCII-art banners."""
    art = re.compile(r"[█░▓▒▄▀━_/\\\\|`]{8,}")
    candidates = []
    for ln in (blob or "").splitlines():
        text = ln.strip()
        if not text or len(text) > 160:
            continue
        if text.lower().startswith("error:"):
            continue
        if art.search(text) or text.count("_") > 12:
            continue
        if re.search(r"\d+\.\d+", text):
            candidates.append(text)
    if candidates:
        return " | ".join(candidates[:2])
    return ""


def _append_log_file(tool_name: str, text: str) -> None:
    if not _current_results_dir or not tool_name:
        return
    log_path = _current_results_dir / f"{tool_name}.log"
    with _log_lock:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")


def _append_raw_log(tool_name: str, text: str) -> None:
    if not _current_results_dir or not tool_name:
        return
    if not get_global_config().get("write_raw_logs"):
        return
    log_path = _current_results_dir / f"{tool_name}.raw.log"
    with _log_lock:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")


ZAP_PROGRESS_RE = re.compile(r"^\s*\[[=\s]*\]\s*\d+%")


def _zap_alert_summary(text: str) -> str:
    if "<alertitem>" not in (text or "").lower() and "<OWASPZAPReport" not in (text or ""):
        return ""
    lines = []
    for block in re.findall(r"<alertitem>(.*?)</alertitem>", text or "", re.S | re.I):
        alert = ""
        risk = ""
        uri = ""
        am = re.search(r"<alert>([^<]*)</alert>", block, re.I)
        nm = re.search(r"<name>([^<]*)</name>", block, re.I)
        rm = re.search(r"<riskdesc>([^<]*)</riskdesc>", block, re.I)
        um = re.search(r"<uri>([^<]+)</uri>", block, re.I)
        if am:
            alert = am.group(1).strip()
        elif nm:
            alert = nm.group(1).strip()
        if rm:
            risk = rm.group(1).strip()
        if um:
            uri = um.group(1).strip()
        if alert:
            lines.append(f"ZAP: {alert} | {risk} | {uri}")
        if len(lines) >= 30:
            break
    if not lines:
        return ""
    return "ZAP ALERTS:\n" + "\n".join(lines)


def zap_report_path():
    if _current_results_dir is None:
        return None
    path = _current_results_dir / "zaproxy_report.xml"
    return path if path.is_file() else None


def read_zap_report_xml() -> str:
    path = zap_report_path()
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _attach_zap_report(body: str) -> str:
    """Prefer on-disk quickout XML over stdout (progress bars / idle timeout)."""
    xml = read_zap_report_xml()
    source = xml or (body or "")
    summary = _zap_alert_summary(source)
    notices = []
    for line in (body or "").splitlines():
        if line.startswith("[!]"):
            notices.append(line)
    if summary:
        print(summary)
        prefix = ("\n".join(notices) + "\n") if notices else ""
        return (prefix + summary).strip()
    if xml:
        return ((("\n".join(notices) + "\n") if notices else "") + xml).strip()
    return body


def _filter_live_output(tool_name: str, text: str, state: dict) -> str:
    """Collapse CR progress updates; hide ZAP XML and percentage bars from the console."""
    text = (text or "").replace("\r", "\n")
    if tool_name != "zaproxy":
        return text
    if state.get("xml"):
        return ""
    out = []
    for line in text.splitlines(keepends=True):
        if "<?xml" in line or "<OWASPZAPReport" in line:
            state["xml"] = True
            continue
        if state.get("xml"):
            continue
        if ZAP_PROGRESS_RE.search(line):
            continue
        out.append(line)
    return "".join(out)

def _wait_process(proc, timeout: int, idle_reset: bool, max_timeout: int, activity: dict) -> bool:
    """
    Wait until the process exits. Return True if we killed it for timeout.
    idle_reset (default): `timeout` is seconds of silence; any stdout/stderr
    chunk resets the timer. max_timeout is an optional wall-clock cap (0 = none).
    idle_reset false: `timeout` is wall-clock from process start.
    """
    start = time.monotonic()
    if not idle_reset:
        try:
            proc.wait(timeout=timeout)
            return False
        except subprocess.TimeoutExpired:
            return True

    idle_limit = max(int(timeout or 0), 1)
    hard_limit = int(max_timeout or 0)
    while proc.poll() is None:
        now = time.monotonic()
        elapsed = now - start
        if hard_limit and elapsed >= hard_limit:
            return True
        idle = now - activity["t"]
        if idle >= idle_limit:
            return True
        slice_t = min(0.5, idle_limit - idle)
        if hard_limit:
            slice_t = min(slice_t, hard_limit - elapsed)
        if slice_t <= 0:
            return True
        try:
            proc.wait(timeout=slice_t)
        except subprocess.TimeoutExpired:
            continue
    return False


def run_tool(
    command: list,
    timeout: int = 120,
    tool_name: str = "",
    allow_retry: bool = False,
    _retried: bool = False,
    idle_reset: bool = True,
    max_timeout: int = 0,
    quiet: bool = False,
) -> str:
    """
    Execute a command, stream stdout+stderr live, save full log to disk,
    return a (possibly truncated) string for the LLM.
    timeout is silence seconds by default (any output resets the timer).
    """
    if not command:
        return "[!] Empty command."

    binary = str(command[0])
    display = " ".join(str(c) for c in command)
    name = tool_name or Path(binary).name
    global_cfg = get_global_config()
    max_lines = int(global_cfg.get("max_log_lines", 2000) or 2000)

    if dry_run_enabled():
        msg = f"[dry-run] {display}"
        if not quiet:
            print(msg)
        _append_log_file(name, msg + "\n")
        return msg

    version = _probe_version(binary)
    if version:
        _append_log_file(name, f"[version] {binary}: {version}\n")

    captured = []
    timed_out = False
    proc = None
    activity = {"t": time.monotonic()}
    started = time.monotonic()

    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

        def _reader():
            raw = proc.stdout
            if raw is None:
                return
            while True:
                chunk = raw.read(4096)
                if not chunk:
                    break
                activity["t"] = time.monotonic()
                text = chunk.decode("utf-8", errors="replace")
                _append_raw_log(name, text)
                cleaned = sanitize_tool_chunk(text, name)
                if cleaned:
                    if not quiet:
                        with _print_lock:
                            print(cleaned, end="", flush=True)
                    captured.append(cleaned)
                    _append_log_file(name, cleaned)

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        timed_out = _wait_process(proc, timeout, idle_reset, max_timeout, activity)
        if timed_out:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
        reader.join(timeout=5)

    except FileNotFoundError:
        hint_key = name or Path(binary).name
        if hint_key not in TOOL_INSTALL_HINTS:
            hint_key = Path(binary).name
        hint = tool_install_hint(hint_key)
        msg = f"[!] Tool not found: {binary} — install it with: {hint}"
        print(msg)
        _append_log_file(name, msg + "\n")
        return msg
    except Exception as exc:
        msg = f"[!] Unexpected error running {binary}: {exc}"
        print(msg)
        _append_log_file(name, msg + "\n")
        return msg
    finally:
        if proc is not None and proc.stdout:
            try:
                proc.stdout.close()
            except OSError:
                pass

    body = "".join(captured).rstrip()
    if timed_out:
        elapsed = int(time.monotonic() - started)
        if idle_reset:
            notice = (
                f"[!] Idle timeout after {timeout}s with no output "
                f"(ran {elapsed}s): {display}"
            )
        else:
            notice = f"[!] Timed out after {timeout}s: {display}"
        print(notice)
        _append_log_file(name, notice + "\n")
        partial = body + ("\n" if body else "") + notice

        if allow_retry and not _retried and not quiet:
            multiplier = float(global_cfg.get("timeout_retry_multiplier", 2) or 2)
            bumped = max(int(timeout * multiplier), timeout + 1)
            bumped_max = int(max_timeout * multiplier) if max_timeout else 0
            choice = input(
                f"Timed out after {timeout}s. Retry with timeout={bumped}? [y/N/e]: "
            ).strip().lower()
            if choice == "y":
                print(f"[*] Retrying with timeout={bumped}s...")
                return run_tool(
                    command,
                    timeout=bumped,
                    tool_name=name,
                    allow_retry=False,
                    _retried=True,
                    idle_reset=idle_reset,
                    max_timeout=bumped_max or max_timeout,
                    quiet=quiet,
                )
            if choice == "e":
                prompt_edit_config([name])
                new_cfg = get_tool_config(name)
                new_timeout = int(new_cfg.get("timeout", bumped) or bumped)
                new_idle, new_max = _timeout_policy(new_cfg)
                print(f"[*] Retrying with timeout={new_timeout}s from config...")
                return run_tool(
                    command,
                    timeout=new_timeout,
                    tool_name=name,
                    allow_retry=False,
                    _retried=True,
                    idle_reset=new_idle,
                    max_timeout=new_max,
                    quiet=quiet,
                )
        if name == "zaproxy":
            partial = _attach_zap_report(partial)
        return _truncate_log(partial, max_lines)

    if not body:
        body = "[!] Tool returned no output."
    if name == "zaproxy":
        body = _attach_zap_report(body)
    return _truncate_log(body, max_lines)


GOBUSTER_WILDCARD_RE = re.compile(
    r"exclude the status code or the length",
    re.IGNORECASE,
)
GOBUSTER_LENGTH_RE = re.compile(r"\(Length:\s*(\d+)\)", re.IGNORECASE)
RESPONSE_SIZE_RE = re.compile(r"\[Size:\s*(\d+)\]", re.IGNORECASE)


def _dominant_response_size(output: str, min_hits: int = 8) -> str:
    sizes = RESPONSE_SIZE_RE.findall(output or "")
    if len(sizes) < min_hits:
        return ""
    counts = {}
    for size in sizes:
        counts[size] = counts.get(size, 0) + 1
    size, n = max(counts.items(), key=lambda kv: kv[1])
    if n >= min_hits and n / len(sizes) >= 0.5:
        return size
    return ""


def _retry_gobuster_wildcard(output: str, command: list, timeout: int) -> str:
    if "--exclude-length" in command:
        return output
    length = ""
    if GOBUSTER_WILDCARD_RE.search(output or ""):
        match = GOBUSTER_LENGTH_RE.search(output or "")
        if match:
            length = match.group(1)
    if not length:
        length = _dominant_response_size(output)
    if not length:
        return output
    retry_cmd = list(command) + ["--exclude-length", length]
    print(f"  [*] gobuster catch-all size {length} — retrying with --exclude-length {length}")
    print(f"  [*] {' '.join(str(c) for c in retry_cmd)}")
    retry_out = run_tool(
        retry_cmd,
        timeout=timeout,
        tool_name="gobuster",
        allow_retry=False,
        **_run_tool_timeout_kwargs("gobuster"),
    )
    return (output or "") + f"\n\n[retry --exclude-length {length}]\n" + retry_out


def _retry_ffuf_filter(output: str, command: list, timeout: int) -> str:
    if "-fs" in command:
        return output
    size = _dominant_response_size(output)
    if not size:
        return output
    retry_cmd = list(command) + ["-fs", size]
    print(f"  [*] ffuf catch-all size {size} — retrying with -fs {size}")
    print(f"  [*] {' '.join(str(c) for c in retry_cmd)}")
    retry_out = run_tool(
        retry_cmd,
        timeout=timeout,
        tool_name="ffuf",
        allow_retry=False,
        **_run_tool_timeout_kwargs("ffuf"),
    )
    return (output or "") + f"\n\n[retry -fs {size}]\n" + retry_out


def _finalize_command(logical_name: str, command: list, target: str) -> list:
    command = list(command)
    if logical_name == "nikto":
        url = _http_url(target)
        if url.startswith("https://") and "-ssl" not in command:
            command.append("-ssl")
    if logical_name == "zaproxy" and _current_results_dir is not None:
        out = str(_current_results_dir / "zaproxy_report.xml")
        if "-quickout" not in command:
            command.extend(["-quickout", out])
    if logical_name == "commix":
        url = _http_url(target)
        if url.startswith("https://") and "--force-ssl" not in command:
            command.append("--force-ssl")
        raw = target if target.startswith(("http://", "https://")) else url
        parsed = urlparse(raw)
        has_query = bool(parse_qsl(parsed.query, keep_blank_values=True))
        if not has_query and not any(str(a).startswith("--crawl") for a in command):
            command.append("--crawl=2")
    if logical_name == "sqlmap":
        raw = target if target.startswith(("http://", "https://")) else _http_url(target)
        parsed = urlparse(raw)
        weak = {
            "unique", "v", "ver", "version", "cb", "cache", "nocache", "_",
        }
        keys = []
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if not key or key.lower() in weak or key.lower().startswith("utm_"):
                continue
            if key not in keys:
                keys.append(key)
        if keys:
            if "-p" not in command:
                command.extend(["-p", ",".join(keys)])
        elif "--forms" not in command:
            command.append("--forms")
    return command


def _run_configured(
    binary: str,
    target: str,
    allow_retry: bool = True,
    profile: str = None,
    scenario: str = None,
    quiet: bool = False,
) -> str:
    cfg = resolve_profile(get_tool_config(binary), profile)
    timeout = int(cfg.get("timeout", 120) or 120)
    idle_reset, max_timeout = _timeout_policy(cfg)
    argv0 = resolve_tool_binary(binary)
    command = _finalize_command(
        binary,
        build_command(argv0, target, cfg, scenario=scenario, tool=binary, profile=profile),
        target,
    )
    print(f"  [*] {' '.join(str(c) for c in command)}")
    output = run_tool(
        command,
        timeout=timeout,
        tool_name=binary,
        allow_retry=allow_retry and not quiet,
        idle_reset=idle_reset,
        max_timeout=max_timeout,
        quiet=quiet,
    )
    if binary == "gobuster":
        output = _retry_gobuster_wildcard(output, command, timeout)
    if binary == "ffuf":
        output = _retry_ffuf_filter(output, command, timeout)
    return output


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    return _run_configured("nmap", target)


def run_whois(target: str) -> str:
    return _run_configured("whois", target)


def run_whatweb(target: str) -> str:
    return _run_configured("whatweb", target)


def run_curl_headers(target: str) -> str:
    """Fetch HTTP and HTTPS headers using configured curl flags."""
    cfg = get_tool_config("curl")
    timeout = int(cfg.get("timeout", 20) or 20)
    wordlist = resolve_wordlist(cfg)
    base_args = substitute_args(
        list(cfg.get("args") or ["-I", "--max-time", "10"]),
        target,
        cfg,
        wordlist=wordlist,
    )
    extra = substitute_args(list(cfg.get("extra_args") or []), target, cfg, wordlist=wordlist)
    http_url, https_url = _scheme_urls(target)

    idle_kw = _run_tool_timeout_kwargs("curl", cfg)
    print(f"  [*] curl {' '.join(base_args + extra)} {http_url}")
    http_out = run_tool(
        ["curl"] + base_args + extra + [http_url],
        timeout=timeout,
        tool_name="curl",
        allow_retry=True,
        **idle_kw,
    )

    https_cmd = ["curl"] + base_args + extra
    if "-k" not in https_cmd:
        https_cmd.append("-k")
    https_cmd.append(https_url)
    print(f"  [*] curl {' '.join(base_args + extra)} -k {https_url}")
    https_out = run_tool(https_cmd, timeout=timeout, tool_name="curl", allow_retry=True, **idle_kw)

    return f"[HTTP Headers]\n{http_out}\n\n[HTTPS Headers]\n{https_out}"


def run_dig(target: str) -> str:
    cfg = get_tool_config("dig")
    timeout = int(cfg.get("timeout", 15) or 15)
    wordlist = resolve_wordlist(cfg)
    extra = substitute_args(list(cfg.get("extra_args") or []), target, cfg, wordlist=wordlist)
    prefix = substitute_args(list(cfg.get("args") or ["+short"]), target, cfg, wordlist=wordlist)
    host = _hostname(target) or target
    print(f"  [*] dig {host} A/MX/NS/TXT")
    records = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        records[rtype] = run_tool(
            ["dig"] + prefix + extra + [rtype, host],
            timeout=timeout,
            tool_name="dig",
            allow_retry=True,
            **_run_tool_timeout_kwargs("dig", cfg),
        )
    return (
        f"[A Records]\n{records['A']}\n\n"
        f"[MX Records]\n{records['MX']}\n\n"
        f"[NS Records]\n{records['NS']}\n\n"
        f"[TXT Records]\n{records['TXT']}"
    )


def run_nikto(target: str) -> str:
    return _run_configured("nikto", target)


def run_gobuster(target: str) -> str:
    return _run_configured("gobuster", target)


def run_arp_scan(target: str) -> str:
    output = _run_configured("arp-scan", target)
    if "Operation not permitted" in output or "You don't have permission" in output:
        notice = "[!] arp-scan needs CAP_NET_RAW/root — treating as non-fatal."
        print(notice)
        return output + "\n" + notice
    return output


def run_sslscan(target: str) -> str:
    return _run_configured("sslscan", target)


def run_testssl(target: str) -> str:
    return _run_configured("testssl.sh", target)


def run_katana(target: str) -> str:
    return _run_configured("katana", target)


def run_nuclei(target: str) -> str:
    return _run_configured("nuclei", target)


def run_httpx_probe(target: str) -> str:
    return _run_configured("httpx", target)


def run_ffuf(target: str) -> str:
    return _run_configured("ffuf", target)


def run_sqlmap(target: str) -> str:
    return _run_configured("sqlmap", target)


def run_wapiti(target: str) -> str:
    return _run_configured("wapiti", target)


def run_dalfox(target: str) -> str:
    return _run_configured("dalfox", target)


def run_commix(target: str) -> str:
    return _run_configured("commix", target)


def run_wpscan(target: str) -> str:
    return _run_configured("wpscan", target)


def run_zap(target: str) -> str:
    return _run_configured("zaproxy", target)


def run_playwright(target: str, allow_retry: bool = True) -> str:
    """Origin-locked browser click probe (virtual tool)."""
    cfg = get_tool_config("playwright")
    timeout = int(cfg.get("timeout", 180) or 180)
    script = Path(__file__).parent / "browser_probe.py"
    url = _http_url(target)
    cmd = [
        sys.executable,
        str(script),
        "--url", url,
        "--max-clicks", str(cfg.get("max_clicks", 15)),
        "--click-timeout-ms", str(cfg.get("click_timeout_ms", 5000)),
    ]
    if cfg.get("headless", True):
        cmd.append("--headless")
    else:
        cmd.append("--headed")
    hosts = cfg.get("allowed_hosts") or []
    if hosts:
        cmd.extend(["--allowed-hosts", ",".join(str(h) for h in hosts)])
    if cfg.get("allow_subdomains"):
        cmd.append("--allow-subdomains")
    print(f"  [*] playwright probe {url}")
    return run_tool(
        cmd,
        timeout=timeout,
        tool_name="playwright",
        allow_retry=allow_retry,
        **_run_tool_timeout_kwargs("playwright", cfg),
    )


def run_searchsploit(target: str) -> str:
    """Exploit-DB search. TARGET is a product/version query, not a URL."""
    query = (target or "").strip()
    if not query:
        return "[!] searchsploit needs a product/version query, not a URL."
    if "://" in query:
        msg = "[!] searchsploit skipped — TARGET must be a product/version query, not a URL."
        print(msg)
        return msg
    terms = [t for t in query.split() if t]
    if not terms:
        return "[!] searchsploit needs a product/version query, not a URL."
    cfg = get_tool_config("searchsploit")
    timeout = int(cfg.get("timeout", 30) or 30)
    argv0 = resolve_tool_binary("searchsploit")
    wordlist = resolve_wordlist(cfg)
    prefix = substitute_args(
        list(cfg.get("args") or ["--colour", "disable", "--www"]),
        query,
        cfg,
        wordlist=wordlist,
    )
    extra = substitute_args(list(cfg.get("extra_args") or []), query, cfg, wordlist=wordlist)
    if Path(argv0).is_file() and not os.access(argv0, os.X_OK):
        command = ["bash", argv0] + prefix + extra + terms
    else:
        command = [argv0] + prefix + extra + terms
    print(f"  [*] {' '.join(str(c) for c in command)}")
    return run_tool(
        command,
        timeout=timeout,
        tool_name="searchsploit",
        allow_retry=True,
        **_run_tool_timeout_kwargs("searchsploit", cfg),
    )


def run_gau(target: str) -> str:
    host = _apex_host(target)
    if not host or _is_ip(host):
        msg = "[!] gau skipped — target is an IP, not a domain."
        print(msg)
        return msg
    return _run_configured("gau", host)


def run_subfinder(target: str) -> str:
    host = _apex_host(target)
    if not host or _is_ip(host):
        msg = "[!] subfinder skipped — target is an IP, not a domain."
        print(msg)
        return msg
    return _run_configured("subfinder", host)


def run_masscan(target: str) -> str:
    ok, ips, reason = lan_ips_for_target(target)
    if not ok:
        msg = f"[!] masscan skipped — target is not on the local network ({reason})"
        print(msg)
        return msg
    cfg = get_tool_config("masscan")
    timeout = int(cfg.get("timeout", 180) or 180)
    argv0 = resolve_tool_binary("masscan")
    chunks = []
    for ip in ips:
        command = _finalize_command("masscan", build_command(argv0, ip, cfg), ip)
        print(f"  [*] {' '.join(str(c) for c in command)}")
        output = run_tool(
            command,
            timeout=timeout,
            tool_name="masscan",
            allow_retry=True,
            **_run_tool_timeout_kwargs("masscan", cfg),
        )
        blob = output or ""
        if (
            "Operation not permitted" in blob
            or "You don't have permission" in blob
            or "need to be root" in blob.lower()
        ):
            notice = "[!] masscan needs CAP_NET_RAW/root — treating as non-fatal."
            print(notice)
            blob = blob + "\n" + notice
        if len(ips) == 1:
            chunks.append(blob)
        else:
            chunks.append(f"[masscan {ip}]\n{blob}")
    return "\n\n".join(chunks)


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1":  ("nmap",          run_nmap),
    "2":  ("whois",         run_whois),
    "3":  ("whatweb",       run_whatweb),
    "4":  ("curl headers",  run_curl_headers),
    "5":  ("dig DNS",       run_dig),
    "6":  ("nikto",         run_nikto),
    "7":  ("gobuster",      run_gobuster),
    "8":  ("arp-scan",      run_arp_scan),
    "9":  ("sslscan",       run_sslscan),
    "10": ("testssl.sh",    run_testssl),
    "11": ("katana",        run_katana),
    "12": ("nuclei",        run_nuclei),
    "13": ("httpx",         run_httpx_probe),
    "14": ("ffuf",          run_ffuf),
    "15": ("sqlmap",        run_sqlmap),
    "16": ("wapiti",        run_wapiti),
    "17": ("dalfox",        run_dalfox),
    "18": ("commix",        run_commix),
    "19": ("wpscan",        run_wpscan),
    "20": ("zaproxy",       run_zap),
    "21": ("playwright",    run_playwright),
    "22": ("searchsploit",  run_searchsploit),
    "23": ("gau",           run_gau),
    "24": ("subfinder",     run_subfinder),
    "25": ("masscan",       run_masscan),
}

# Config / log file keys for menu entries (curl headers → curl, dig DNS → dig)
MENU_CONFIG_KEYS = {
    "1": "nmap",
    "2": "whois",
    "3": "whatweb",
    "4": "curl",
    "5": "dig",
    "6": "nikto",
    "7": "gobuster",
    "8": "arp-scan",
    "9": "sslscan",
    "10": "testssl.sh",
    "11": "katana",
    "12": "nuclei",
    "13": "httpx",
    "14": "ffuf",
    "15": "sqlmap",
    "16": "wapiti",
    "17": "dalfox",
    "18": "commix",
    "19": "wpscan",
    "20": "zaproxy",
    "21": "playwright",
    "22": "searchsploit",
    "23": "gau",
    "24": "subfinder",
    "25": "masscan",
}

DEFAULT_RECON_KEYS = ["1", "2", "3", "4", "5"]
ALL_TOOL_KEYS = list(TOOLS_MENU.keys())


def _job_label(job: dict) -> str:
    return format_tool_call(
        job.get("tool") or "",
        job.get("target") or "",
        job.get("profile") or "",
        job.get("scenario") or "",
    )


def run_dispatch_jobs(
    jobs: list,
    ran_keys: set = None,
    origin: str = "",
    is_wp: bool = False,
    is_lan=None,
) -> tuple:
    """
    Run dispatch jobs in JSON waves. Partial failures are recorded and the
    rest of the wave continues. Returns (results_dict, skip_notes, ran_keys).
    """
    ran_keys = set(ran_keys or [])
    global_cfg = get_global_config()
    origin = origin or ((jobs[0].get("target") if jobs else "") or "")
    if is_lan is None:
        is_lan = bool(lan_ips_for_target(origin)[0])

    accepted = []
    notes = []
    for job in jobs or []:
        if not isinstance(job, dict) or not job.get("tool"):
            continue
        ok, job, reason = apply_safety_gates(
            job, ran_keys, origin, is_wp, is_lan, global_cfg,
        )
        if not ok:
            notes.append(reason)
            print(f"  {reason}")
            continue
        accepted.append(job)
        ran_keys.add(job["_run_key"])

    results = {}
    max_global = int(global_cfg.get("max_workers") or 4) or 4
    grouped = group_jobs_by_wave(accepted, get_waves_config())

    for wave_name, wave_jobs, workers in grouped:
        workers = min(max(int(workers) or 1, 1), max_global, len(wave_jobs))
        print(f"\n[*] Wave {wave_name} ({len(wave_jobs)} tool(s), workers={workers})")
        if workers == 1:
            for job in wave_jobs:
                label = _job_label(job)
                started = time.monotonic()
                try:
                    out = run_tool_by_command(
                        format_tool_call(
                            job["tool"], job["target"],
                            job.get("profile") or "", job.get("scenario") or "",
                        ),
                        quiet=False,
                    )
                except Exception as exc:
                    out = f"[!] {job['tool']} failed: {exc}"
                elapsed = int(time.monotonic() - started)
                failed = (out or "").lstrip().startswith("[!]")
                print(f"  [{'!' if failed else '+'}] {job['tool']} "
                      f"{'failed' if failed else 'done'} {elapsed}s")
                results[label] = out
            continue

        status = {_job_label(j): "queued" for j in wave_jobs}
        stop = threading.Event()

        def _heartbeat():
            while not stop.wait(2):
                running = [n for n, s in status.items() if s == "running"]
                queued = [n for n, s in status.items() if s == "queued"]
                with _print_lock:
                    print(
                        f"\r[wave {wave_name}] {len(running)} running "
                        f"{','.join(running) or '-'} | queued {len(queued)}   ",
                        end="",
                        flush=True,
                    )

        hb = threading.Thread(target=_heartbeat, daemon=True)
        hb.start()

        def _one(job):
            throttle_resources(global_cfg)
            label = _job_label(job)
            status[label] = "running"
            started = time.monotonic()
            try:
                out = run_tool_by_command(
                    format_tool_call(
                        job["tool"], job["target"],
                        job.get("profile") or "", job.get("scenario") or "",
                    ),
                    quiet=True,
                )
            except Exception as exc:
                out = f"[!] {job['tool']} failed: {exc}"
            status[label] = "done"
            return label, out, int(time.monotonic() - started)

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = [pool.submit(_one, j) for j in wave_jobs]
                for fut in as_completed(futs):
                    try:
                        label, out, elapsed = fut.result()
                    except Exception as exc:
                        label, out, elapsed = "unknown", f"[!] failed: {exc}", 0
                    results[label] = out
                    failed = (out or "").lstrip().startswith("[!]")
                    with _print_lock:
                        print()
                        print(
                            f"  [{'!' if failed else '+'}] {label} "
                            f"{'failed' if failed else 'done'} {elapsed}s"
                        )
        finally:
            stop.set()
            hb.join(timeout=1)
            print()

    return results, notes, ran_keys


def run_named_tools(target: str, names: list) -> dict:
    jobs = [
        {"tool": name, "target": target, "profile": "", "scenario": ""}
        for name in names
    ]
    results, notes, _ = run_dispatch_jobs(jobs, origin=target)
    by_tool = {}
    for label, out in results.items():
        tool = (label.split() or [""])[0]
        prev = by_tool.get(tool, "")
        by_tool[tool] = (prev + "\n" + (out or "")).strip() if prev else (out or "")
    if notes:
        by_tool["skipped"] = "\n".join(notes)
    return by_tool


def run_default_recon(target: str) -> dict:
    """
    Run the standard recon pipeline (everything except nikto).
    Returns a dict of {tool_name: output_string}.
    """
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)
    results = run_named_tools(target, ["whois", "dig", "curl", "whatweb", "nmap"])
    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


INSTALL_CHECK_TOOLS = (
    "nmap", "whois", "whatweb", "curl", "dig", "nikto", "gobuster",
    "arp-scan", "sslscan", "testssl.sh", "katana", "nuclei", "httpx",
    "ffuf", "sqlmap", "wapiti", "dalfox", "commix", "wpscan", "zaproxy",
    "searchsploit", "gau", "subfinder", "masscan",
)


def _binary_available(path_or_name: str) -> str:
    if not path_or_name:
        return ""
    path = Path(path_or_name)
    if path.is_file() and os.access(path_or_name, os.X_OK):
        return str(path)
    # searchsploit is a bash script; a clone without +x is still usable via bash.
    if path.is_file() and path.name == "searchsploit":
        return str(path)
    found = shutil.which(path_or_name)
    return found or ""


def tool_binary_status(logical_name: str) -> tuple:
    """Return (ok, resolved_path_or_name)."""
    if logical_name in ("curl", "whois", "dig"):
        aliases = {
            "curl": ("curl",),
            "whois": ("whois",),
            "dig": ("dig",),
        }
        for name in aliases[logical_name]:
            found = shutil.which(name)
            if found:
                return True, found
        return False, logical_name

    if logical_name in ("httpx", "httpx-toolkit"):
        resolved = resolve_tool_binary(logical_name)
        found = _binary_available(resolved)
        if found and (
            Path(found).name in ("httpx-toolkit", "httpx-pd")
            or _is_projectdiscovery_httpx(found)
        ):
            return True, found
        return False, "ProjectDiscovery httpx not found (not the Python httpx CLI)"

    resolved = resolve_tool_binary(logical_name)
    found = _binary_available(resolved)
    if found:
        return True, found
    fallback = _binary_available(logical_name)
    if fallback:
        return True, fallback
    return False, resolved or logical_name


def playwright_status() -> tuple:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "python package missing (pip install playwright && playwright install chromium)"
    try:
        with sync_playwright() as p:
            exe = p.chromium.executable_path
        if exe and Path(exe).is_file():
            return True, exe
        return False, "Chromium missing (playwright install chromium)"
    except Exception as exc:
        return False, str(exc)


def wordlist_status() -> tuple:
    root = detect_wordlists_root()
    if root:
        common = Path(root) / "Discovery" / "Web-Content" / "common.txt"
        if common.is_file():
            return True, root
        return True, f"{root} (Discovery/Web-Content/common.txt missing)"
    path = resolve_wordlist({})
    if path and Path(path).is_file():
        return True, path
    return False, "SecLists not found"


def _wordlist_file_status(tool: str) -> tuple:
    cfg = get_tool_config(tool)
    path = resolve_wordlist(cfg, tool=tool)
    if path and Path(path).is_file():
        return True, path
    return False, path or cfg.get("wordlist") or DEFAULT_WORDLIST


def collect_install_status() -> list:
    """
    Presence checks for scanners, Playwright, and SecLists wordlists.
    Each item: {group, name, ok, detail, hint}
    """
    rows = []
    for name in INSTALL_CHECK_TOOLS:
        ok, detail = tool_binary_status(name)
        rows.append({
            "group": "tools",
            "name": name,
            "ok": ok,
            "detail": detail,
            "hint": tool_install_hint(name),
        })
    ok, detail = playwright_status()
    rows.append({
        "group": "tools",
        "name": "playwright",
        "ok": ok,
        "detail": detail,
        "hint": TOOL_INSTALL_HINTS["playwright"],
    })
    ok, detail = wordlist_status()
    rows.append({
        "group": "wordlist",
        "name": "SecLists",
        "ok": ok,
        "detail": detail,
        "hint": TOOL_INSTALL_HINTS["seclists"],
    })
    ok, detail = _wordlist_file_status("gobuster")
    rows.append({
        "group": "wordlist",
        "name": "gobuster wordlist",
        "ok": ok,
        "detail": detail,
        "hint": TOOL_INSTALL_HINTS["seclists"],
    })
    ok, detail = _wordlist_file_status("ffuf")
    rows.append({
        "group": "wordlist",
        "name": "ffuf wordlist",
        "ok": ok,
        "detail": detail,
        "hint": TOOL_INSTALL_HINTS["seclists"],
    })
    java = shutil.which("java")
    rows.append({
        "group": "runtime",
        "name": "java (ZAP)",
        "ok": bool(java),
        "detail": java or "not on PATH",
        "hint": "sudo apt install default-jre",
    })
    go = shutil.which("go")
    rows.append({
        "group": "runtime",
        "name": "go",
        "ok": bool(go),
        "detail": go or "not on PATH (needed to install nuclei/katana/httpx/dalfox/ffuf/gau/subfinder)",
        "hint": "sudo apt install golang-go",
    })
    return rows


ALLOWED_TOOLS = {
    "nmap", "whois", "whatweb", "curl", "dig", "nikto",
    "gobuster", "arp-scan", "sslscan", "testssl.sh",
    "katana", "nuclei", "httpx", "httpx-toolkit", "ffuf", "sqlmap", "wapiti",
    "dalfox", "commix", "wpscan", "zaproxy",
    "playwright",
    "searchsploit", "gau", "subfinder", "masscan",
}


def _is_wordlist_tag(token: str) -> bool:
    t = (token or "").strip()
    return t.upper().startswith("SCENARIO:") or t.upper().startswith("WORDLIST:")


def _sanitize_scenario_name(raw: str) -> str:
    name = (raw or "").strip().lower()
    if not name:
        return ""
    if "/" in name or "\\" in name or ".." in name or name.startswith("."):
        print(f"  [!] Ignoring filesystem path in SCENARIO — using default wordlist")
        return ""
    return name


def _extract_dispatch_scenario(parts: list) -> str:
    """Allowlisted SCENARIO:name / WORDLIST:name token from an AI TOOL tag."""
    parsed = parse_tool_tag(" ".join(parts))
    return parsed.get("scenario") or ""


def _extract_dispatch_profile(parts: list) -> str:
    parsed = parse_tool_tag(" ".join(parts))
    return parsed.get("profile") or ""


def _extract_dispatch_target(parts: list) -> str:
    """TARGET: value, or last non-flag, non-key token after the binary."""
    parsed = parse_tool_tag(" ".join(parts))
    return parsed.get("target") or ""


def _extract_searchsploit_query(parts: list) -> str:
    parsed = parse_tool_tag(" ".join(parts))
    if parsed.get("tool") != "searchsploit":
        parsed = parse_tool_tag("searchsploit " + " ".join(parts[1:]))
    return parsed.get("target") or ""


_JUNK_PATH_SEGMENTS = {
    "fullpath", "fuzz", "fu", "path", "url", "target", "endpoint", "endpoints",
}


def _sanitize_dispatch_target(target: str) -> str:
    """Drop invented path tokens like /fullpath so ffuf/gobuster stay on origin."""
    raw = (target or "").strip()
    if not raw:
        return raw
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    last = (parsed.path or "").rstrip("/").split("/")[-1].lower()
    if last in _JUNK_PATH_SEGMENTS:
        host = parsed.netloc or parsed.path.split("/")[0]
        if parsed.scheme and host:
            return f"{parsed.scheme}://{host}"
        return host
    return raw


def run_tool_by_command(command_str: str, quiet: bool = False) -> str:
    """
    AI dispatch: binary name is allowlisted; flags always come from
    tools_config.json profiles. Extra flags the model invents are ignored.
    Optional TARGET: / PROFILE: / SCENARIO: tokens.
    """
    parsed = parse_tool_tag(command_str)
    tool = parsed.get("tool") or ""
    if not tool:
        return "[!] Empty command."
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{tool}' is not permitted. Allowed: {ALLOWED_TOOLS}"

    scenario = parsed.get("scenario") or ""
    profile = parsed.get("profile") or ""
    target = parsed.get("target") or ""
    if not target:
        return f"[!] No target in command. Use: [TOOL: {tool} TARGET:<url>]"
    if tool != "searchsploit":
        cleaned = _sanitize_dispatch_target(target)
        if cleaned != target:
            print(f"  [!] Stripped junk path from TARGET: {target} → {cleaned}")
            target = cleaned

    if parsed.get("invented_flags"):
        print(f"  [*] Ignoring model flags; using {CONFIG_PATH.name} PROFILE for {tool}")

    try:
        if tool == "playwright":
            return run_playwright(target, allow_retry=False)
        if tool == "curl":
            return run_curl_headers(target)
        if tool == "dig":
            return run_dig(target)
        if tool == "searchsploit":
            return run_searchsploit(target)
        if tool == "gau":
            return run_gau(target)
        if tool == "subfinder":
            return run_subfinder(target)
        if tool == "masscan":
            return run_masscan(target)

        config_key = "httpx" if tool == "httpx-toolkit" else tool
        return _run_configured(
            config_key,
            target,
            allow_retry=False,
            profile=profile,
            scenario=scenario,
            quiet=quiet,
        )
    except Exception as exc:
        return f"[!] {tool} failed: {exc}"


# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def _run_selected(target: str, keys: list) -> dict:
    names = []
    for key in keys:
        if key not in TOOLS_MENU:
            print(f"[!] Unknown option: {key}")
            continue
        names.append(MENU_CONFIG_KEYS.get(key) or TOOLS_MENU[key][0])
    if not names:
        return {}
    return run_named_tools(target, names)


def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run, optionally edit JSON config,
    then execute. Returns combined output string.
    """
    load_tools_config(force=True)

    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Legacy: nmap, whois, whatweb, curl, dig")
    print("  [n] Legacy: same as [a] plus nikto")
    print("  [m] Run all tools")

    choice = input("\nChoice(s) e.g. 1 2 4 or m: ").strip().lower()

    if choice == "a":
        keys = list(DEFAULT_RECON_KEYS)
    elif choice == "n":
        keys = list(DEFAULT_RECON_KEYS) + ["6"]
    elif choice == "m":
        keys = list(ALL_TOOL_KEYS)
    else:
        keys = choice.split()

    selected_config_names = []
    for key in keys:
        if key in MENU_CONFIG_KEYS:
            selected_config_names.append(MENU_CONFIG_KEYS[key])
        elif key not in ("a", "n", "m") and key not in TOOLS_MENU:
            print(f"[!] Unknown option: {key}")

    if not selected_config_names:
        return ""

    prompt_edit_config(selected_config_names)
    start_results_dir(target)

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)

    combined = _run_selected(target, keys)
    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    start_results_dir(target)
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
