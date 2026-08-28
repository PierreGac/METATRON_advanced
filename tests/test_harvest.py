#!/usr/bin/env python3
"""Unit tests for harvest + schema fallback (no live scan, no Ollama)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harvest import (
    canned_summary,
    derive_risk,
    filter_gap_vulns,
    findings_to_exploits,
    findings_to_vulns,
    format_digest,
    harvest_curl_redirects,
    harvest_findings,
    harvest_nuclei,
    harvest_zap,
    leftover_interesting_lines,
    looks_like_schema,
    looks_like_tool_tags_only,
    merge_exploits,
    merge_vulns,
    pick_schema_text,
    schema_text_from_harvest,
    strip_ansi,
)


NUCLEI_ANSI = (
    "\x1b[92mCVE-2017-5871\x1b[0m] [\x1b[94mhttp\x1b[0m] "
    "[\x1b[33mmedium\x1b[0m] "
    "https://decgroupe.com/web/session/logout?redirect=https://oast.me"
)

ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.17.0">
  <site name="https://decgroupe.com" host="decgroupe.com" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>40018</pluginid>
        <alert>SQL Injection</alert>
        <name>SQL Injection</name>
        <riskcode>3</riskcode>
        <riskdesc>High (Medium)</riskdesc>
        <uri>https://decgroupe.com/shop/category/x?search=ZAP</uri>
      </alertitem>
      <alertitem>
        <alert>Modern Web Application</alert>
        <name>Modern Web Application</name>
        <riskdesc>Informational (Medium)</riskdesc>
        <uri>https://decgroupe.com/</uri>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""

CURL_303 = """
  [*] curl -I --max-time 10 -k https://decgroupe.com/web/session/logout?redirect=https://oast.me
HTTP/2 303
server: nginx
location: https://oast.me
"""

TOOL_TAGS = """[TOOL: commix https://decgroupe.com/shop?category=3]
[TOOL: dalfox https://decgroupe.com/shop?category=3]
[SEARCH: CVE-2017-5871]
"""

DISPATCH_SQLMAP = """
[TOOL RESULT: sqlmap https://decgroupe.com/shop?category=3]
all tested parameters do not appear to be injectable.
"""


class HarvestTests(unittest.TestCase):
    def test_nuclei_ansi_cve(self):
        findings = harvest_nuclei(NUCLEI_ANSI)
        self.assertTrue(any(f.get("cve") == "CVE-2017-5871" for f in findings), findings)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("logout", findings[0].get("url", ""))

    def test_strip_ansi_leaves_template(self):
        clean = strip_ansi(NUCLEI_ANSI)
        self.assertNotIn("\x1b", clean)
        self.assertIn("CVE-2017-5871", clean)
        self.assertIn("[http]", clean)

    def test_zap_xml_sqli_skips_info(self):
        findings = harvest_zap("", xml_text=ZAP_XML)
        names = [f["name"] for f in findings]
        self.assertIn("SQL Injection", names)
        self.assertNotIn("Modern Web Application", names)
        sqli = next(f for f in findings if f["name"] == "SQL Injection")
        self.assertEqual(sqli["severity"], "high")

    def test_zap_from_results_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zaproxy_report.xml"
            path.write_text(ZAP_XML, encoding="utf-8")
            findings = harvest_findings("no alerts in stdout", host="decgroupe.com", results_dir=tmp)
            self.assertTrue(any(f["name"] == "SQL Injection" for f in findings), findings)

    def test_curl_303_off_origin(self):
        findings = harvest_curl_redirects(CURL_303, host="decgroupe.com")
        self.assertTrue(findings, "expected open-redirect finding")
        self.assertIn("oast.me", findings[0]["description"])
        self.assertIn(findings[0]["name"], ("Open redirect", "CVE-2017-5871"))

    def test_same_host_redirect_skipped(self):
        text = (
            "curl -I http://decgroupe.com\n"
            "HTTP/1.1 301 Moved Permanently\n"
            "location: https://decgroupe.com/\n"
        )
        self.assertEqual(harvest_curl_redirects(text, host="decgroupe.com"), [])

    def test_combined_scan_not_unknown(self):
        blob = NUCLEI_ANSI + "\n" + CURL_303 + "\n" + DISPATCH_SQLMAP
        findings = harvest_findings(blob, host="decgroupe.com", xml_text=ZAP_XML)
        vulns = findings_to_vulns(findings)
        exploits = findings_to_exploits(findings)
        risk = derive_risk(findings, vulns)
        self.assertGreaterEqual(len(vulns), 1)
        self.assertNotEqual(risk, "UNKNOWN")
        self.assertEqual(risk, "HIGH")
        self.assertTrue(any("sqlmap" in (e.get("tool_used") or "") for e in exploits))

    def test_tool_tag_transcript_not_schema(self):
        self.assertFalse(looks_like_schema(TOOL_TAGS))
        self.assertTrue(looks_like_tool_tags_only(TOOL_TAGS))
        picked = pick_schema_text("[!] Model returned empty response.", [TOOL_TAGS])
        self.assertEqual(picked, "")
        findings = harvest_findings(NUCLEI_ANSI + "\n" + ZAP_XML, host="decgroupe.com")
        vulns = findings_to_vulns(findings)
        risk = derive_risk(findings, vulns)
        self.assertGreaterEqual(len(vulns), 1)
        self.assertNotEqual(risk, "UNKNOWN")
        text = schema_text_from_harvest(
            vulns, [], risk, canned_summary("decgroupe.com", findings, risk),
        )
        self.assertIn("VULN:", text)
        self.assertIn("RISK_LEVEL:", text)

    def test_leftover_new_line_kept_duplicate_cve_dropped(self):
        reported = harvest_findings(NUCLEI_ANSI, host="decgroupe.com")
        leftover_src = (
            NUCLEI_ANSI + "\n"
            "[credentials-disclosure] [http] [unknown] https://decgroupe.com "
            "[\"access_token=abc\"]\n"
        )
        leftovers = leftover_interesting_lines(leftover_src, reported=reported)
        self.assertNotIn("CVE-2017-5871", leftovers)
        self.assertIn("credentials-disclosure", leftovers)

    def test_gap_invented_cve_dropped(self):
        leftovers = "nginx_status exposed on https://decgroupe.com/nginx_status"
        invented = [{
            "vuln_name": "CVE-2026-33017",
            "severity": "critical",
            "port": "",
            "service": "http",
            "description": "version disclosure",
            "fix": "",
        }]
        kept = filter_gap_vulns(invented, leftovers)
        self.assertEqual(kept, [])
        real = [{
            "vuln_name": "nginx_status exposed",
            "severity": "low",
            "port": "",
            "service": "http",
            "description": leftovers,
            "fix": "",
        }]
        self.assertEqual(len(filter_gap_vulns(real, leftovers)), 1)

    def test_empty_gap_leaves_harvest_unchanged(self):
        base = findings_to_vulns(harvest_nuclei(NUCLEI_ANSI))
        merged = merge_vulns(base, [])
        self.assertEqual(len(merged), len(base))
        self.assertEqual(merged[0]["vuln_name"], base[0]["vuln_name"])

    def test_merge_drops_duplicate_cve(self):
        a = findings_to_vulns(harvest_nuclei(NUCLEI_ANSI))
        extra = [{
            "vuln_name": "CVE-2017-5871",
            "severity": "high",
            "port": "",
            "service": "http",
            "description": "duplicate",
            "fix": "",
        }]
        merged = merge_vulns(a, extra)
        self.assertEqual(len(merged), len(a))

    def test_digest_mentions_extracted(self):
        findings = harvest_findings(NUCLEI_ANSI, host="decgroupe.com")
        digest = format_digest(findings)
        self.assertIn("EXTRACTED FINDINGS:", digest)
        self.assertIn("CVE-2017-5871", digest)

    def test_nikto_skips_osvdb_flood(self):
        text = (
            "+ The anti-clickjacking X-Frame-Options header is not present.\n"
            "+ OSVDB-724: /cgi-bin/ans.pl?p=../../../../../usr/bin/id|&blah: remote.\n"
        )
        findings = harvest_findings(text, host="decgroupe.com")
        names = " ".join(f["name"] for f in findings)
        self.assertIn("X-Frame-Options", names)
        self.assertNotIn("ans.pl", names)

    def test_wapiti_headers(self):
        text = "CSP is not set\nX-Frame-Options is not set\nSecure flag is not set in the cookie : session_id\n"
        findings = harvest_findings(text, host="decgroupe.com")
        self.assertTrue(any("CSP" in f["name"] for f in findings))
        self.assertTrue(any("session_id" in f["name"] for f in findings))

    def test_merge_exploits_empty_extra(self):
        ex = findings_to_exploits(harvest_findings(DISPATCH_SQLMAP, host="decgroupe.com"))
        self.assertEqual(merge_exploits(ex, []), ex)


if __name__ == "__main__":
    unittest.main()
