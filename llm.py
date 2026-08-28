#!/usr/bin/env python3
"""
METATRON - llm.py
Ollama interface for metatron-qwen model.
Builds prompts, handles AI responses, runs tool dispatch loop.
Model: metatron-qwen (fine-tuned from huihui_ai/qwen3.5-abliterated:9b)
"""

import re
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from search import handle_search_dispatch
from tools import _extract_dispatch_target, _http_url, run_tool_by_command

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "metatron-qwen"
MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 9
OLLAMA_TIMEOUT = 600
ANALYSIS_TEMPERATURE = 0.2

WEB_MANDATORY = (
    "nuclei", "sqlmap", "dalfox", "commix", "katana", "gobuster", "playwright",
)
WEB_OPTIONAL = ("wapiti", "zaproxy")
SCANNER_ORDER = (
    "katana", "gobuster", "nuclei", "playwright", "zaproxy", "wapiti", "wpscan",
)
DISCOVERY_ORDER = ("katana", "gobuster", "nuclei", "playwright")
OPTIONAL_SCANNERS = ("zaproxy", "wapiti")
INJECTION_TOOLS = ("sqlmap", "dalfox", "commix")
MAX_TOOLS_PER_ROUND = 2

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
NUCLEI_LINE_RE = re.compile(
    r"^\s*\[[^\]]+\]\s*\[(?:http|dns|ssl|tcp|javascript)\]\s*"
    r"\[(?:info|low|medium|high|critical)\]",
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
Be precise and technical. No fluff. No markdown. No YAML.

You drive real tools with tags. Flags always come from tools_config.json.

  [TOOL: nuclei https://host/path]   → runs that tool against TARGET
  [SEARCH: CVE-2026-33017]           → DuckDuckGo lookup

Rules for tags:
- Write ONLY [TOOL: <name> <TARGET>] or [SEARCH: CVE-YYYY-NNNN].
- SEARCH must be a real CVE id (CVE-2024-1234), never a site path.
- TARGET may be the session host OR any discovered same-host URL
  (example: [TOOL: dalfox https://example.com/search?q=test]).
- Do not invent flags (-sV, -u, --batch, -silent, YAML, nuclei templates).
- Do not invent paths like /fullpath. Extra flags are ignored.
- To change paths, change TARGET only.

Allowed tool names:
  nmap, whois, whatweb, curl, dig, nikto, gobuster, arp-scan, sslscan, testssl.sh,
  katana, nuclei, httpx, ffuf, sqlmap, wapiti, dalfox, commix, wpscan, zaproxy, playwright

How to use them:
- katana/gobuster first on a web target to collect paths.
- Then retarget sqlmap, dalfox, and commix at URLs with query strings or API paths
  from DISCOVERED_URLS. Do not keep scanning only the origin homepage.
- Skip catch-all SPA paths that all return the same homepage size.
- nuclei/wapiti/zaproxy: origin or interesting paths.
- curl: fetch a specific evidence URL (headers). Use this for Nuclei hit URLs.
- [SEARCH: CVE-…] for every CVE that appears in tool output BEFORE you treat it as a finding.
- playwright: browser clicks. Cookie banners are probe blockers, not vulnerabilities.
- wpscan only if the target is WordPress.

During tool rounds write tags only. When the checklist is complete, write the
VULN:/EXPLOIT:/RISK_LEVEL schema in plain text (same format as original METATRON).

Accuracy:
- nmap filtered or no-response is INCONCLUSIVE, not vulnerable.
- Never assert a version that is not in scan output.
- Never invent CVEs. Repeat a Nuclei CVE only after SEARCH, and name the product
  in the template (e.g. Langflow). If the app does not match, it is unconfirmed.
- Only CRITICAL with SEARCH plus endpoint evidence of exploitability.
- Cookie overlays and WebGL/console deprecation noise are not vulns.
- curl HTTP_CODE=000 means unreachable, not exploitable.
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
    for match in CVE_RE.findall(text or ""):
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


def _looks_like_schema(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"^\s*VULN:", text, re.MULTILINE) or re.search(
        r"RISK_LEVEL", text, re.IGNORECASE
    ))


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
    for line in (text or "").splitlines():
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
    for line in (text or "").splitlines():
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
    text = (raw_output or "").strip()
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


def missing_web_tools(
    ran: set,
    is_http: bool,
    is_wp: bool,
    discovered: list = None,
    ran_injection_urls: dict = None,
    retargeted: set = None,
) -> list:
    if not is_http:
        return []
    needed = list(WEB_MANDATORY)
    needed.extend(WEB_OPTIONAL)
    if is_wp:
        needed.append("wpscan")
    missing = []
    for name in needed:
        if name in INJECTION_TOOLS:
            if not injection_covered(name, ran, discovered, ran_injection_urls, retargeted):
                missing.append(name)
            continue
        if name not in ran and name not in missing:
            missing.append(name)
    return missing


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
    missing: list,
    unverified_cves: list,
    cve_urls: dict,
    discovered: list,
    origin: str,
    curled_urls: set,
    ran_tools: set = None,
    ran_injection_urls: dict = None,
    retargeted: set = None,
) -> list:
    ran_tools = ran_tools or set()
    ran_injection_urls = ran_injection_urls or {}
    retargeted = retargeted if retargeted is not None else set()
    calls = []
    for cve in unverified_cves[:3]:
        calls.append(("SEARCH", cve))
        url = cve_urls.get(cve.upper())
        if url and url not in curled_urls:
            calls.append(("TOOL", f"curl {url}"))
    if calls:
        return calls

    for url in pending_curl_urls(cve_urls, curled_urls)[:2]:
        calls.append(("TOOL", f"curl {url}"))
    if calls:
        return calls

    picked = []
    for name in DISCOVERY_ORDER:
        if name in missing:
            picked.append(("TOOL", f"{name} {origin}"))
            if len(picked) >= MAX_TOOLS_PER_ROUND:
                return picked

    inj = injection_target(origin, discovered)
    for name in INJECTION_TOOLS:
        if name not in missing:
            continue
        canon = _canonical_scan_url(inj)
        already = ran_injection_urls.get(name, set())
        if canon and canon in already:
            continue
        if name in ran_tools:
            retargeted.add(name)
        picked.append(("TOOL", f"{name} {inj}"))
        if len(picked) >= MAX_TOOLS_PER_ROUND:
            return picked

    for name in OPTIONAL_SCANNERS:
        if name in missing:
            picked.append(("TOOL", f"{name} {origin}"))
            if len(picked) >= MAX_TOOLS_PER_ROUND:
                break
    return picked


def checklist_message(
    missing: list,
    unverified_cves: list,
    discovered: list,
    loops_left: int,
    curl_pending: list = None,
) -> str:
    lines = []
    if missing:
        lines.append("MISSING TOOLS (emit [TOOL: name TARGET] or they will be auto-run):")
        lines.append(", ".join(missing))
    if unverified_cves:
        lines.append("UNVERIFIED CVEs — emit [SEARCH: CVE-…] and [TOOL: curl <hit-url>] before calling them findings:")
        lines.append(", ".join(unverified_cves))
    if curl_pending:
        lines.append("CVE EVIDENCE URLS still need [TOOL: curl URL]:")
        lines.extend(curl_pending[:5])
    ranked = ranked_urls(discovered)[:20]
    if ranked:
        lines.append("DISCOVERED_URLS (use these as TARGET for sqlmap/dalfox/commix when they have parameters):")
        lines.extend(ranked)
    if missing or unverified_cves or curl_pending:
        lines.append("Do not write RISK_LEVEL yet. Emit tags only for the gaps above.")
        lines.append(f"Loops left: {loops_left}")
    else:
        lines.append("Checklist complete. If you still need a tool, emit tags.")
        lines.append("Otherwise write the VULN:/EXPLOIT:/RISK_LEVEL schema now (plain text, no markdown).")
    return "\n".join(lines)


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches = re.findall(r"\[TOOL:\s*(.+?)\]", response)
    search_matches = re.findall(r"\[SEARCH:\s*(.+?)\]", response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls


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
        parts = (content or "").split()
        if not parts:
            continue
        tool = _canonical_tool(parts[0])
        target = _extract_dispatch_target(parts)
        if tool == "wpscan" and not is_wp:
            print("  [!] Ignoring wpscan — target does not look like WordPress.")
            continue
        if target and _is_junk_target(target):
            if origin:
                print(f"  [!] Replacing junk TARGET {target} with origin")
                content = f"{tool} {origin}"
                target = origin
            else:
                print(f"  [!] Ignoring TOOL {tool} with junk TARGET {target}")
                continue
        if tool in INJECTION_TOOLS and target and _is_weak_injection_url(target):
            print(f"  [!] Ignoring {tool} on weak/static URL: {target}")
            continue
        cleaned.append(("TOOL", content))
    return cleaned


def _call_key(call: tuple) -> tuple:
    call_type, content = call
    if call_type == "SEARCH":
        return ("SEARCH", (content or "").strip().upper())
    parts = (content or "").split()
    tool = _canonical_tool(parts[0]) if parts else ""
    target = _extract_dispatch_target(parts) if parts else ""
    return ("TOOL", tool, target)


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
) -> None:
    for call_type, content in calls:
        if call_type == "SEARCH":
            for cve in extract_cves(content):
                searched_cves.add(cve)
            continue
        if call_type != "TOOL":
            continue
        parts = content.split()
        if not parts:
            continue
        tool = _canonical_tool(parts[0])
        ran_tools.add(tool)
        target = _extract_dispatch_target(parts)
        if tool == "curl" and target:
            curled_urls.add(_strip_url(target))
        if tool in INJECTION_TOOLS and target and ran_injection_urls is not None:
            ran_injection_urls.setdefault(tool, set()).add(_canonical_scan_url(target))


def run_tool_calls(calls: list, session_host: str = "", is_wp: bool = False) -> str:
    """
    Execute all tool/search calls and return combined evidence string.
    """
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            parts = call_content.split()
            tool = _canonical_tool(parts[0]) if parts else ""
            target = _extract_dispatch_target(parts) if parts else ""
            if tool == "wpscan" and not is_wp:
                output = "[!] Skipping wpscan — target does not look like WordPress."
                print(f"  {output}")
            elif tool in INJECTION_TOOLS and target and _is_weak_injection_url(target):
                output = f"[!] Skipping {tool} on weak/static URL: {target}"
                print(f"  {output}")
            elif target and _is_junk_target(target):
                output = f"[!] Skipping {tool} — junk TARGET {target}"
                print(f"  {output}")
            else:
                output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            if _search_looks_like_fake_cve(call_content) and not _search_is_cve(call_content):
                output = f"[!] Skipping SEARCH — not a CVE id: {call_content}"
                print(f"  {output}")
            else:
                output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        compressed = summarize_tool_output(output.strip(), session_host)
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"

    return results


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
    """Prefer finalize schema; fall back to last usable round like original METATRON."""
    if _usable_model_text(finalize) and (
        _looks_like_schema(finalize) or parse_risk_level(finalize) != "UNKNOWN"
    ):
        return finalize
    for text in reversed(transcript or []):
        if _usable_model_text(text) and _looks_like_schema(text):
            return text
    if _usable_model_text(finalize):
        return finalize
    for text in reversed(transcript or []):
        if _usable_model_text(text):
            return text
    return (finalize or "").strip()


def _cap_evidence(chunks: list) -> str:
    blob = "\n".join(chunks)
    if len(blob) <= MAX_EVIDENCE_CHARS:
        return blob
    return blob[-MAX_EVIDENCE_CHARS:]


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    host = _session_host(target)
    origin = preferred_origin(target, raw_scan)
    is_http = looks_like_http(target, raw_scan)
    is_wp = looks_like_wordpress(raw_scan)

    ran_tools = tools_from_text(raw_scan)
    searched_cves = set()
    curled_urls = set()
    ran_injection_urls = {}
    retargeted = set()
    discovered = harvest_urls(raw_scan, host, origin=origin)
    all_cves = extract_cves(raw_scan)
    cve_urls = harvest_cve_urls(raw_scan, host)
    evidence_chunks = []
    transcript = []

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"TARGET: {target}\nORIGIN: {origin}\n\n"
                f"RECON DATA:\n{raw_scan}\n\n"
                "This is a tool round. Emit [TOOL: name TARGET] and [SEARCH: CVE] tags.\n"
                "TARGET may be a discovered URL, not only the origin.\n"
                "Do not invent flags. Do not write RISK_LEVEL yet."
            ),
        },
    ]

    for loop in range(MAX_TOOL_LOOPS):
        missing = missing_web_tools(
            ran_tools, is_http, is_wp, discovered, ran_injection_urls, retargeted,
        )
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
        if missing or unverified or curl_pending:
            auto_calls = build_auto_dispatch(
                missing, unverified, cve_urls, discovered, origin, curled_urls,
                ran_tools, ran_injection_urls, retargeted,
            )
        auto_calls = sanitize_calls(auto_calls, origin, is_wp)
        calls = merge_calls(model_calls, auto_calls)
        auto = bool(auto_calls) and any(c not in model_calls for c in calls)
        if auto and auto_calls:
            print(f"\n[*] Auto-dispatch fill ({len(auto_calls)} candidates): "
                  + ", ".join(f"{t} {c}" for t, c in auto_calls[:6]))
        if not calls:
            print("\n[*] Checklist complete or no further tools. Moving to finalize.")
            break

        record_calls(calls, ran_tools, searched_cves, curled_urls, ran_injection_urls)
        tool_results = run_tool_calls(calls, session_host=host, is_wp=is_wp)
        evidence_chunks.append(tool_results)

        all_cves = list(dict.fromkeys(all_cves + extract_cves(tool_results)))
        cve_urls.update(harvest_cve_urls(tool_results, host))
        for url in harvest_urls(tool_results, host, origin=origin):
            if url not in discovered:
                discovered.append(url)

        messages.append({"role": "assistant", "content": response})
        missing = missing_web_tools(
            ran_tools, is_http, is_wp, discovered, ran_injection_urls, retargeted,
        )
        unverified = [c for c in all_cves if c not in searched_cves]
        curl_pending = pending_curl_urls(cve_urls, curled_urls)
        nudge = checklist_message(
            missing, unverified, discovered, loops_left - 1, curl_pending,
        )
        prefix = "[AUTO-DISPATCH RESULTS]\n" if auto else "[TOOL RESULTS]\n"
        messages.append({
            "role": "user",
            "content": f"{prefix}{tool_results}\n\n{nudge}",
        })

        if not missing and not unverified and not curl_pending:
            print("\n[*] Tool checklist and CVE SEARCH complete.")
            break

    evidence = _cap_evidence(evidence_chunks)
    recon_clip = (raw_scan or "")[:4000]
    finalize_user = (
        f"TARGET: {target}\nORIGIN: {origin}\n\n"
        f"RECON HIGHLIGHTS:\n{recon_clip}\n\n"
        f"TOOL EVIDENCE:\n{evidence}\n\n"
        f"SEARCHED CVEs: {', '.join(sorted(searched_cves)) or 'none'}\n"
        f"DISCOVERED_URLS:\n" + "\n".join(ranked_urls(discovered)[:20]) + "\n\n"
        "Write the schema-only report now."
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
    if _usable_model_text(finalize_response):
        transcript.append(finalize_response)

    record_text = _pick_schema_text(finalize_response, transcript)
    if record_text != finalize_response:
        print("[*] Finalize empty or unparsed — using last schema reply (original METATRON behavior).")
        print(record_text)

    vulnerabilities = parse_vulnerabilities(record_text)
    exploits = parse_exploits(record_text)
    risk_level = parse_risk_level(record_text)
    summary = parse_summary(record_text)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response": record_text,
        "vulnerabilities": vulnerabilities,
        "exploits": exploits,
        "risk_level": risk_level,
        "summary": summary,
        "raw_scan": raw_scan,
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
