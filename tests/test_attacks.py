#!/usr/bin/env python3
"""Unit tests for the final attack-analysis parser and markdown section."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harvest import format_attacks_schema, parse_attacks
from report_md import render_markdown_report


SAMPLE = """
ATTACK: Open redirect session theft | SEVERITY: high
TARGET: https://decgroupe.com/web/session/logout?redirect=
DANGER: An attacker can bounce a logged-in user to a lookalike host and steal the session.
VULNS: CVE-2017-5871, cookies without Secure flag
FIX: Reject off-origin redirect targets in logout and set Secure, HttpOnly, and SameSite=Strict on session cookies.

ATTACK: Clickjacking | SEVERITY: medium
TARGET: https://decgroupe.com/ (missing X-Frame-Options)
IMPACT: The shop UI can be framed so a victim clicks a purchase they did not intend.
VULNS: X-Frame-Options is not set
REMEDIATION: Send Content-Security-Policy frame-ancestors 'self' and X-Frame-Options: DENY.
Extra: disable framing in the reverse proxy as well.
"""


class AttackParseTests(unittest.TestCase):
    def test_parses_two_attacks_with_aliases(self):
        attacks = parse_attacks(SAMPLE)
        self.assertEqual(len(attacks), 2)
        first = attacks[0]
        self.assertEqual(first["attack_name"], "Open redirect session theft")
        self.assertEqual(first["severity"], "high")
        self.assertIn("logout", first["target"])
        self.assertIn("session", first["danger"])
        self.assertIn("CVE-2017-5871", first["vulns_used"])
        self.assertIn("SameSite", first["fix"])

        second = attacks[1]
        self.assertEqual(second["attack_name"], "Clickjacking")
        self.assertIn("framed", second["danger"])
        self.assertIn("X-Frame-Options", second["vulns_used"])
        self.assertIn("frame-ancestors", second["fix"])
        self.assertIn("reverse proxy", second["fix"])

    def test_no_attacks_token(self):
        self.assertEqual(parse_attacks("NO_ATTACKS"), [])

    def test_empty_and_unrelated(self):
        self.assertEqual(parse_attacks(""), [])
        self.assertEqual(parse_attacks("VULN: missing header | SEVERITY: low\nDESC: x"), [])

    def test_format_roundtrip(self):
        attacks = parse_attacks(SAMPLE)
        text = format_attacks_schema(attacks)
        self.assertIn("ATTACK: Open redirect session theft", text)
        self.assertIn("FIX:", text)
        again = parse_attacks(text)
        self.assertEqual(len(again), 2)
        self.assertEqual(again[0]["attack_name"], attacks[0]["attack_name"])

    def test_markdown_lists_fix_and_danger(self):
        md = render_markdown_report(
            "decgroupe.com",
            risk="HIGH",
            summary="test",
            vulns=[{"vuln_name": "Open redirect", "severity": "high",
                    "port": "443", "service": "https", "description": "logout",
                    "fix": "validate redirect"}],
            attacks=parse_attacks(SAMPLE),
        )
        self.assertIn("## Possible attacks", md)
        self.assertIn("Why this is dangerous:", md)
        self.assertIn("Vulnerabilities used:", md)
        self.assertIn("How to fix:", md)
        self.assertIn("Open redirect session theft", md)


if __name__ == "__main__":
    unittest.main()
