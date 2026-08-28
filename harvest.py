#!/usr/bin/env python3
"""
Deterministic finding extraction from scanner logs.
Does not call Ollama. Used as the safety net when the model fails to emit schema.
"""

from __future__ import annotations

import html as html_lib
import re
from pathlib import Path
from urllib.parse import urlparse

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)

NUCLEI_LINE_RE = re.compile(
    r"^\s*\[?([^\]]+)\]\s*\[(?:http|dns|ssl|tcp|javascript)\]\s*"
    r"\[(info|low|medium|high|critical|unknown)\]\s*(\S+)?",
    re.IGNORECASE,
)

NIKTO_PLUS_RE = re.compile(r"^\+\s+(.+)$")
NIKTO_SKIP_RE = re.compile(r"OSVDB-\d+|ans\.pl|cgi-bin/ans|/cgi\.cgi/", re.IGNORECASE)

WAPITI_HEADER_RE = re.compile(
    r"^(CSP is not set|.+ is not set|Secure flag is not set.+|HttpOnly flag is not set.+)$",
    re.IGNORECASE,
)

LOCATION_RE = re.compile(r"^\s*location:\s*(\S+)", re.IGNORECASE)
CURL_URL_RE = re.compile(r"curl\s+[^\n]*?(https?://\S+)", re.IGNORECASE)
HTTP_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})", re.IGNORECASE)

DISPATCH_HEADER_RE = re.compile(
    r"^\[(?:TOOL|SEARCH) RESULT:\s*(.+)\]\s*$",
    re.IGNORECASE | re.MULTILINE,
)
ZAP_SUMMARY_LINE_RE = re.compile(
    r"^ZAP:\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.*)$",
    re.IGNORECASE,
)

INTERESTING_RE = re.compile(
    r"timeout|timed out|idle timeout|"
    r"HTTP/[12][.\d]*\s+[45]\d\d|"
    r"\b(?:50[0-9]|401|403)\b|"
    r"location:\s*https?://|"
    r"injectable|reflected|"
    r"CVE-\d{4}-\d+|"
    r"vulnerab|High \(|Medium \(|"
    r"not set|HttpOnly|Secure flag|"
    r"issues:\s*[1-9]|"
    r"credentials-disclosure|nginx_status|database/manager|"
    r"open.?redirect|SQL Injection|"
    r"cookie .+ without",
    re.IGNORECASE,
)
BORING_LEFTOVER_RE = re.compile(
    r"please wait|testing the |testing '|boolean-based|"
    r"time-based blind|UNION query|heuristic \(|"
    r"^\s*\[[=\s]*\]\s*\d+%|"
    r"worker /|Started at|FollowRedirect|"
    r"Templates loaded|HTTP connections:|"
    r"do you want to |legal disclaimer",
    re.IGNORECASE,
)

NUCLEI_SKIP_INFO = {
    "wildcard-dns-detect", "azure-domain-tenant", "tls-version", "robots-txt",
    "robots-txt-endpoint", "metatag-cms", "tech-detect", "rdap-whois",
    "email-extractor", "mx-fingerprint", "dkim-record-detect",
    "nameserver-fingerprint", "srv-service-detect", "dmarc-detect",
    "spf-record-detect", "txt-fingerprint", "dnssec-detection",
    "ssl-issuer", "ssl-dns-names", "wildcard-tls", "waf-detect",
    "odoo-detection",
}
NUCLEI_KEEP_INFO_SUBSTR = (
    "missing-security-headers", "cookies-without", "credentials-disclosure",
    "nginx-status", "database-manager", "database/selector", "openerp-database",
)

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
    "unknown": 0,
}

MAX_DIGEST_LINES = 80
MAX_NIKTO = 20
MAX_ZAP = 30
MAX_NUCLEI = 40
MAX_LEFTOVER_CHARS = 12000


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def _parse_url(url: str):
    raw = (url or "").rstrip(".,;:)'\"\\]>")
    if not raw:
        return None
    try:
        return urlparse(raw)
    except (ValueError, TypeError):
        return None


def _hostname(url_or_host: str) -> str:
    parsed = _parse_url(url_or_host if "://" in (url_or_host or "") else f"https://{url_or_host}")
    if parsed is None:
        return (url_or_host or "").lower()
    return (parsed.hostname or "").lower()


def _same_host(url: str, host: str) -> bool:
    if not host:
        return True
    h = _hostname(url)
    return bool(h) and h == host.lower()


def extract_cves(text: str) -> list:
    seen = []
    for match in CVE_RE.findall(text or ""):
        key = match.upper()
        if key not in seen:
            seen.append(key)
    return seen


def _finding(
    source: str,
    name: str,
    severity: str = "medium",
    description: str = "",
    url: str = "",
    service: str = "",
    port: str = "",
    fix: str = "",
    kind: str = "vuln",
    tool_used: str = "",
    payload: str = "",
    result: str = "",
    notes: str = "",
    evidence: str = "",
) -> dict:
    cves = extract_cves(f"{name} {description} {evidence}")
    return {
        "source": source,
        "kind": kind,
        "name": (name or "").strip(),
        "severity": (severity or "medium").lower(),
        "port": port,
        "service": service,
        "description": (description or "").strip(),
        "fix": fix,
        "url": url,
        "cve": cves[0] if cves else "",
        "evidence": (evidence or description or "").strip()[:500],
        "tool_used": tool_used or source,
        "payload": payload,
        "result": result,
        "notes": notes,
    }


def _xml_tag(block: str, name: str) -> str:
    match = re.search(rf"<{name}>([^<]*)</{name}>", block, re.IGNORECASE)
    if not match:
        return ""
    return html_lib.unescape(match.group(1)).strip()


def zap_facts_from_xml(text: str) -> list:
    if "<alertitem>" not in (text or "").lower() and "<OWASPZAPReport" not in (text or ""):
        return []
    lines = []
    for block in re.findall(r"<alertitem>(.*?)</alertitem>", text or "", re.S | re.I):
        alert = _xml_tag(block, "alert") or _xml_tag(block, "name")
        risk = _xml_tag(block, "riskdesc")
        uris = re.findall(r"<uri>([^<]+)</uri>", block, re.I)
        uri = html_lib.unescape(uris[0]).strip() if uris else ""
        if alert:
            lines.append(f"ZAP: {alert} | {risk} | {uri}")
        if len(lines) >= MAX_ZAP:
            break
    return lines


def read_zap_report_xml(results_dir=None) -> str:
    path = None
    if results_dir:
        path = Path(results_dir) / "zaproxy_report.xml"
    else:
        try:
            from tools import current_results_dir
            cur = current_results_dir()
            if cur:
                path = Path(cur) / "zaproxy_report.xml"
        except Exception:
            path = None
    if path is None or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _nuclei_template_base(raw: str) -> str:
    name = (raw or "").strip()
    if ":" in name:
        name = name.split(":", 1)[0]
    return name.strip()


def _keep_nuclei(template: str, severity: str) -> bool:
    sev = (severity or "").lower()
    base = _nuclei_template_base(template).lower()
    if sev in ("low", "medium", "high", "critical"):
        return True
    if "CVE-" in template.upper():
        return True
    if any(s in base for s in NUCLEI_KEEP_INFO_SUBSTR):
        return True
    if base in NUCLEI_SKIP_INFO or any(base.startswith(s) for s in NUCLEI_SKIP_INFO):
        return False
    return False


def harvest_nuclei(text: str) -> list:
    findings = []
    clean = strip_ansi(text)
    for line in clean.splitlines():
        match = NUCLEI_LINE_RE.search(line)
        if not match:
            if "CVE-" in line.upper() and "] [" in line:
                cves = extract_cves(line)
                urls = URL_RE.findall(line)
                if cves:
                    findings.append(_finding(
                        "nuclei", cves[0], "medium",
                        description=line.strip()[:300],
                        url=urls[0] if urls else "",
                        evidence=line.strip(),
                    ))
            continue
        template, severity, url = match.group(1), match.group(2).lower(), (match.group(3) or "")
        if not _keep_nuclei(template, severity):
            continue
        cves = extract_cves(template) or extract_cves(line)
        name = cves[0] if cves else _nuclei_template_base(template)
        desc = line.strip()[:400]
        findings.append(_finding(
            "nuclei", name, severity if severity != "unknown" else "medium",
            description=desc, url=url, evidence=line.strip(),
            service="http" if url.startswith("http") else "",
        ))
        if len(findings) >= MAX_NUCLEI:
            break
    return findings


def harvest_zap(text: str, xml_text: str = "") -> list:
    findings = []
    blob = xml_text or text or ""
    if "<alertitem>" in blob.lower() or "<OWASPZAPReport" in blob:
        source = blob
        for block in re.findall(r"<alertitem>(.*?)</alertitem>", source, re.S | re.I):
            alert = _xml_tag(block, "alert") or _xml_tag(block, "name")
            riskdesc = _xml_tag(block, "riskdesc")
            uris = re.findall(r"<uri>([^<]+)</uri>", block, re.I)
            uri = html_lib.unescape(uris[0]).strip() if uris else ""
            risk_word = (riskdesc.split("(")[0] if riskdesc else "medium").strip().lower()
            if risk_word in ("informational", "info"):
                continue
            if not alert:
                continue
            findings.append(_finding(
                "zap", alert,
                severity=risk_word if risk_word in SEVERITY_RANK else "medium",
                description=f"{alert} ({riskdesc}) {uri}".strip(),
                url=uri, evidence=f"ZAP: {alert} | {riskdesc} | {uri}",
                service="http",
            ))
            if len(findings) >= MAX_ZAP:
                break
        return findings

    for line in strip_ansi(text or "").splitlines():
        match = ZAP_SUMMARY_LINE_RE.match(line.strip())
        if not match:
            continue
        alert, riskdesc, uri = match.group(1).strip(), match.group(2).strip(), match.group(3).strip()
        risk_word = (riskdesc.split("(")[0] if riskdesc else "medium").strip().lower()
        if risk_word in ("informational", "info"):
            continue
        findings.append(_finding(
            "zap", alert,
            severity=risk_word if risk_word in SEVERITY_RANK else "medium",
            description=f"{alert} ({riskdesc}) {uri}".strip(),
            url=uri, evidence=line.strip(), service="http",
        ))
        if len(findings) >= MAX_ZAP:
            break
    return findings


def harvest_nikto(text: str) -> list:
    findings = []
    for line in strip_ansi(text or "").splitlines():
        match = NIKTO_PLUS_RE.match(line.strip())
        if not match:
            continue
        body = match.group(1).strip()
        if NIKTO_SKIP_RE.search(body):
            continue
        if "retrieved but it does not contain" in body.lower():
            continue
        sev = "low"
        lower = body.lower()
        if "x-frame-options" in lower or "clickjack" in lower:
            sev = "medium"
        findings.append(_finding(
            "nikto", body[:120], sev,
            description=body[:400], evidence=line.strip(), service="http",
        ))
        if len(findings) >= MAX_NIKTO:
            break
    return findings


def harvest_wapiti(text: str) -> list:
    findings = []
    seen = set()
    for line in strip_ansi(text or "").splitlines():
        stripped = line.strip()
        if not WAPITI_HEADER_RE.match(stripped):
            continue
        key = stripped.lower()
        if key in seen:
            continue
        seen.add(key)
        sev = "medium" if "csp" in key or "x-frame" in key or "strict-transport" in key else "low"
        findings.append(_finding(
            "wapiti", stripped[:120], sev,
            description=stripped, evidence=stripped, service="http",
        ))
    return findings


def harvest_curl_redirects(text: str, host: str = "") -> list:
    findings = []
    current_url = ""
    last_status = ""
    for line in strip_ansi(text or "").splitlines():
        curl_m = CURL_URL_RE.search(line)
        if curl_m:
            current_url = curl_m.group(1).rstrip("\"'")
        status_m = HTTP_STATUS_RE.match(line.strip())
        if status_m:
            last_status = status_m.group(1)
        loc_m = LOCATION_RE.match(line)
        if not loc_m:
            continue
        dest = loc_m.group(1).strip().rstrip(".,;")
        dest_host = _hostname(dest)
        if not dest_host:
            continue
        if host and dest_host == host.lower():
            continue
        name = "Open redirect"
        cves = extract_cves(text)
        if "logout" in (current_url or "").lower() or "redirect=" in (current_url or "").lower():
            if any(c == "CVE-2017-5871" for c in cves) or "oast." in dest.lower() or "burpcollaborator" in dest.lower():
                name = "CVE-2017-5871"
        findings.append(_finding(
            "curl", name, "medium",
            description=f"{current_url or 'request'} -> {dest} (HTTP {last_status or '?'})",
            url=current_url, evidence=line.strip(),
            result=f"{last_status} Location: {dest}",
            kind="vuln",
            service="http",
        ))
    return findings


def harvest_dispatch_attempts(text: str) -> list:
    """One exploit-attempt row per TOOL RESULT block for injection/curl tools."""
    findings = []
    clean = strip_ansi(text or "")
    blocks = re.split(r"(?=^\[(?:TOOL|SEARCH) RESULT:)", clean, flags=re.M)
    for block in blocks:
        header = DISPATCH_HEADER_RE.search(block)
        if not header:
            continue
        content = header.group(1).strip()
        parts = content.split()
        if not parts:
            continue
        tool = parts[0].lower()
        if tool in ("search",):
            continue
        target = " ".join(parts[1:]) if len(parts) > 1 else ""
        if tool not in ("sqlmap", "dalfox", "commix", "curl", "nuclei"):
            continue
        lower = block.lower()
        result = "unknown"
        if "does not appear to be injectable" in lower or "do not appear to be injectable" in lower:
            result = "not injectable"
        elif re.search(r"\[issues:\s*0\]", lower):
            result = "issues: 0"
        else:
            issues = re.search(r"\[issues:\s*([1-9]\d*)\]", lower)
            if issues:
                result = f"issues: {issues.group(1)}"
        loc = LOCATION_RE.search(block)
        if loc:
            result = f"redirect to {loc.group(1).strip()}"
        status = HTTP_STATUS_RE.search(block)
        if status and tool == "curl":
            result = (result + f" HTTP {status.group(1)}").strip()
        if "timed out" in lower:
            result = "timed out"
        findings.append(_finding(
            "dispatch", f"{tool} {target}".strip()[:160],
            severity="info",
            description=f"{tool} against {target}".strip(),
            url=target if target.startswith("http") else "",
            kind="exploit",
            tool_used=tool,
            payload=target,
            result=result,
            notes=block[:400],
            evidence=content,
        ))
    return findings


def harvest_findings(text: str, host: str = "", xml_text: str = "", results_dir=None) -> list:
    blob = text or ""
    zap_xml = xml_text or read_zap_report_xml(results_dir)
    findings = []
    findings.extend(harvest_nuclei(blob))
    findings.extend(harvest_zap(blob, zap_xml))
    findings.extend(harvest_nikto(blob))
    findings.extend(harvest_wapiti(blob))
    findings.extend(harvest_curl_redirects(blob, host=host))
    findings.extend(harvest_dispatch_attempts(blob))
    return _dedupe_findings(findings)


def _finding_key(item: dict) -> tuple:
    cve = (item.get("cve") or "").upper()
    if cve:
        return ("cve", cve)
    name = re.sub(r"\s+", " ", (item.get("name") or "").lower())[:80]
    url = (item.get("url") or "")[:120]
    kind = item.get("kind") or "vuln"
    return ("name", kind, name, url)


def _dedupe_findings(items: list) -> list:
    out = []
    seen = set()
    for item in items:
        if not item.get("name"):
            continue
        key = _finding_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def format_digest(findings: list, max_lines: int = MAX_DIGEST_LINES) -> str:
    lines = ["EXTRACTED FINDINGS:"]
    if not findings:
        lines.append("(none)")
        return "\n".join(lines)
    for item in findings[:max_lines]:
        if item.get("kind") == "exploit":
            lines.append(
                f"ATTEMPT: {item['name']} | TOOL: {item.get('tool_used','')} | "
                f"RESULT: {item.get('result','unknown')}"
            )
        else:
            extra = f" | {item['url']}" if item.get("url") else ""
            lines.append(
                f"{item.get('source','?').upper()}: {item['name']} | "
                f"{item.get('severity','medium')}{extra}"
            )
            if item.get("description") and item["description"] != item["name"]:
                lines.append(f"  {item['description'][:240]}")
    if len(findings) > max_lines:
        lines.append(f"[+{len(findings) - max_lines} more]")
    return "\n".join(lines)


def findings_to_vulns(findings: list) -> list:
    vulns = []
    for item in findings:
        if item.get("kind") == "exploit":
            continue
        sev = item.get("severity") or "medium"
        if sev in ("info", "informational"):
            sev = "low"
        vulns.append({
            "vuln_name": item.get("name") or "finding",
            "severity": sev,
            "port": item.get("port") or "",
            "service": item.get("service") or "",
            "description": item.get("description") or item.get("evidence") or "",
            "fix": item.get("fix") or "",
        })
    return vulns


def findings_to_exploits(findings: list) -> list:
    exploits = []
    for item in findings:
        if item.get("kind") != "exploit":
            continue
        exploits.append({
            "exploit_name": item.get("name") or "attempt",
            "tool_used": item.get("tool_used") or item.get("source") or "",
            "payload": item.get("payload") or item.get("url") or "",
            "result": item.get("result") or "unknown",
            "notes": item.get("notes") or item.get("description") or "",
        })
    return exploits


def derive_risk(findings: list, vulns: list = None) -> str:
    best = 0
    rows = list(findings or [])
    for v in vulns or []:
        rows.append({"severity": v.get("severity") or "medium", "kind": "vuln"})
    for item in rows:
        if item.get("kind") == "exploit":
            continue
        best = max(best, SEVERITY_RANK.get((item.get("severity") or "").lower(), 0))
    if best >= 4:
        return "CRITICAL"
    if best >= 3:
        return "HIGH"
    if best >= 2:
        return "MEDIUM"
    if best >= 1 or any(item.get("kind") != "exploit" for item in rows):
        return "LOW"
    return "UNKNOWN"


def canned_summary(target: str, findings: list, risk: str) -> str:
    vulns = [f for f in findings if f.get("kind") != "exploit"]
    attempts = [f for f in findings if f.get("kind") == "exploit"]
    names = ", ".join(f.get("name", "") for f in vulns[:8] if f.get("name"))
    return (
        f"Scanner harvest for {target}: {len(vulns)} finding(s), "
        f"{len(attempts)} exploit attempt(s). Risk {risk}. "
        f"{('Notable: ' + names + '.') if names else 'No structured findings extracted.'}"
    )[:800]


def schema_text_from_harvest(vulns: list, exploits: list, risk: str, summary: str) -> str:
    lines = []
    for v in vulns:
        lines.append(
            f"VULN: {v.get('vuln_name','')} | SEVERITY: {v.get('severity','medium')} | "
            f"PORT: {v.get('port','')} | SERVICE: {v.get('service','')}"
        )
        if v.get("description"):
            lines.append(f"DESC: {v['description'][:300]}")
        if v.get("fix"):
            lines.append(f"FIX: {v['fix']}")
        lines.append("")
    for e in exploits:
        lines.append(
            f"EXPLOIT: {e.get('exploit_name','')} | TOOL: {e.get('tool_used','')} | "
            f"PAYLOAD: {e.get('payload','')}"
        )
        lines.append(f"RESULT: {e.get('result','unknown')}")
        if e.get("notes"):
            lines.append(f"NOTES: {str(e['notes'])[:300]}")
        lines.append("")
    lines.append(f"RISK_LEVEL: {risk}")
    lines.append(f"SUMMARY: {summary}")
    return "\n".join(lines).strip()


def vuln_key(vuln: dict) -> tuple:
    blob = f"{vuln.get('vuln_name','')} {vuln.get('description','')}"
    cves = extract_cves(blob)
    if cves:
        return ("cve", cves[0])
    name = re.sub(r"\s+", " ", (vuln.get("vuln_name") or "").lower())[:80]
    return ("name", name)


def exploit_key(exp: dict) -> tuple:
    return (
        (exp.get("tool_used") or "").lower(),
        re.sub(r"\s+", " ", (exp.get("exploit_name") or "").lower())[:80],
        (exp.get("payload") or "")[:120],
    )


def merge_vulns(base: list, extra: list) -> list:
    """Keep base; add extra rows whose key is new. Extra may refine empty descriptions."""
    out = list(base or [])
    seen = {vuln_key(v) for v in out if v.get("vuln_name")}
    for v in extra or []:
        if not v.get("vuln_name"):
            continue
        key = vuln_key(v)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def merge_exploits(base: list, extra: list) -> list:
    out = list(base or [])
    seen = {exploit_key(e) for e in out if e.get("exploit_name")}
    for e in extra or []:
        if not e.get("exploit_name"):
            continue
        key = exploit_key(e)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def leftover_interesting_lines(
    text: str,
    reported: list = None,
    max_chars: int = MAX_LEFTOVER_CHARS,
) -> str:
    """Lines that look like signal and are not already represented in reported findings."""
    reported = reported or []
    skip_needles = set()
    for item in reported:
        if isinstance(item, dict):
            for field in ("name", "vuln_name", "cve", "exploit_name", "description"):
                val = (item.get(field) or "").strip()
                if len(val) >= 6:
                    skip_needles.add(val.lower())
            for cve in extract_cves(str(item)):
                skip_needles.add(cve.lower())
        elif isinstance(item, str) and len(item) >= 6:
            skip_needles.add(item.lower())

    kept = []
    used = 0
    for line in strip_ansi(text or "").splitlines():
        stripped = line.strip()
        if len(stripped) < 8 or len(stripped) > 400:
            continue
        if BORING_LEFTOVER_RE.search(stripped):
            continue
        if not INTERESTING_RE.search(stripped):
            continue
        low = stripped.lower()
        if any(n in low for n in skip_needles if len(n) >= 6):
            continue
        if used + len(stripped) + 1 > max_chars:
            break
        kept.append(stripped)
        used += len(stripped) + 1
    return "\n".join(kept)


def filter_gap_vulns(new_vulns: list, leftovers: str) -> list:
    """Drop gap-pass rows whose CVEs were not in leftover text (hallucinations)."""
    blob = (leftovers or "").upper()
    out = []
    for v in new_vulns or []:
        cves = extract_cves(f"{v.get('vuln_name','')} {v.get('description','')}")
        if cves and not all(c in blob for c in cves):
            continue
        out.append(v)
    return out


def already_reported_text(vulns: list, exploits: list) -> str:
    lines = []
    for v in vulns or []:
        lines.append(f"VULN: {v.get('vuln_name','')} | SEVERITY: {v.get('severity','')}")
    for e in exploits or []:
        lines.append(f"EXPLOIT: {e.get('exploit_name','')} | TOOL: {e.get('tool_used','')}")
    return "\n".join(lines) if lines else "(none)"


def looks_like_schema(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"^\s*VULN:", text, re.MULTILINE) or re.search(
        r"RISK_LEVEL", text, re.IGNORECASE
    ))


def looks_like_tool_tags_only(text: str) -> bool:
    if not text or looks_like_schema(text):
        return False
    return bool(re.search(r"\[(?:TOOL|SEARCH):", text))


def _default_usable(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    return not t.startswith("[!]")


def pick_schema_text(finalize: str, transcript: list, usable=None) -> str:
    """Prefer finalize schema. Never save a [TOOL:]/[SEARCH:] round as the record."""
    ok = usable or _default_usable
    if ok(finalize) and looks_like_schema(finalize):
        return finalize
    for text in reversed(transcript or []):
        if not ok(text):
            continue
        if looks_like_schema(text) and not looks_like_tool_tags_only(text):
            return text
    return ""
