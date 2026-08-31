#!/usr/bin/env python3
"""Markdown pentest report helpers (no database imports)."""

from __future__ import annotations

import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def reports_dir() -> str:
    path = PROJECT_ROOT / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _attack_fields(attack) -> dict:
    if isinstance(attack, dict):
        return {
            "name": attack.get("attack_name") or "attack",
            "severity": attack.get("severity") or "medium",
            "target": attack.get("target") or "",
            "danger": attack.get("danger") or "",
            "vulns": attack.get("vulns_used") or "",
            "fix": attack.get("fix") or "",
        }
    return {
        "name": attack[2] if len(attack) > 2 else "attack",
        "severity": attack[3] if len(attack) > 3 else "medium",
        "target": attack[4] if len(attack) > 4 else "",
        "danger": attack[5] if len(attack) > 5 else "",
        "vulns": attack[6] if len(attack) > 6 else "",
        "fix": attack[7] if len(attack) > 7 else "",
    }


def render_markdown_report(
    target: str,
    sl_no="",
    risk="UNKNOWN",
    summary="",
    vulns=None,
    exploits=None,
    attacks=None,
    tools_run=None,
    notes="",
    date="",
) -> str:
    vulns = vulns or []
    exploits = exploits or []
    attacks = attacks or []
    tools_run = tools_run or []
    date = date or datetime.datetime.now().isoformat(timespec="seconds")
    tools_line = ", ".join(str(t) for t in tools_run) if tools_run else "(none recorded)"
    session = f"SL#{sl_no}" if sl_no not in (None, "") else "(unsaved)"
    lines = [
        f"# METATRON report — {target}",
        "",
        f"- Session: {session}",
        f"- Date: {date}",
        f"- Risk: **{risk}**",
        f"- Tools run: {tools_line}",
        "",
        "## Summary",
        (summary or "").strip() or "(none)",
        "",
        "## Findings",
        "",
    ]
    if not vulns:
        lines.append("(none)")
        lines.append("")
    for i, vuln in enumerate(vulns, 1):
        if isinstance(vuln, dict):
            name = vuln.get("vuln_name") or "finding"
            sev = vuln.get("severity") or "medium"
            port = vuln.get("port") or ""
            service = vuln.get("service") or ""
            desc = vuln.get("description") or ""
            fix = vuln.get("fix") or ""
        else:
            name = vuln[2] if len(vuln) > 2 else "finding"
            sev = vuln[3] if len(vuln) > 3 else "medium"
            port = vuln[4] if len(vuln) > 4 else ""
            service = vuln[5] if len(vuln) > 5 else ""
            desc = vuln[6] if len(vuln) > 6 else ""
            fix = ""
        lines.append(f"### {i}. {name} — {sev}")
        lines.append(f"- Port / service: {port} / {service}")
        lines.append(f"- Evidence: {desc}")
        lines.append(f"- Remediation: {fix or '(none)'}")
        lines.append("")
    lines.append("## Attempts")
    lines.append("")
    lines.append("| Tool | Target | Result |")
    lines.append("| --- | --- | --- |")
    if not exploits:
        lines.append("| — | — | none recorded |")
    for exp in exploits:
        if isinstance(exp, dict):
            tool = exp.get("tool_used") or ""
            name = exp.get("exploit_name") or ""
            result = exp.get("result") or ""
            payload = exp.get("payload") or ""
        else:
            name = exp[2] if len(exp) > 2 else ""
            tool = exp[3] if len(exp) > 3 else ""
            payload = exp[4] if len(exp) > 4 else ""
            result = exp[5] if len(exp) > 5 else ""
        lines.append(f"| {tool or name} | {payload} | {result} |")
    lines.append("")
    lines.append("## Possible attacks")
    lines.append("")
    if not attacks:
        lines.append("(none)")
        lines.append("")
    for i, attack in enumerate(attacks, 1):
        a = _attack_fields(attack)
        lines.append(f"### {i}. {a['name']} — {a['severity']}")
        lines.append(f"- Target: {a['target'] or '(unspecified)'}")
        lines.append(f"- Why this is dangerous: {a['danger'] or '(none)'}")
        lines.append(f"- Vulnerabilities used: {a['vulns'] or '(none)'}")
        lines.append(f"- How to fix: {a['fix'] or '(none)'}")
        lines.append("")
    lines.append("## Notes")
    lines.append(
        (notes or "").strip()
        or "Unconfirmed findings, skipped duplicates, and failed tools are listed in tool logs."
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown_file(text: str, dest: Path) -> str:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return str(dest)
