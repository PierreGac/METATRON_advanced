#!/usr/bin/env python3
"""Unit tests for dispatch tags, sanitizer, waves, profiles, dedup (no Ollama, no live tools)."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dispatch import (
    apply_safety_gates,
    canonical_endpoint,
    extract_tool_calls,
    parse_tool_tag,
    run_key,
    sanitize_tool_chunk,
    tools_by_wave,
)
from tools import resolve_profile, _timeout_policy


class ParseToolTagTests(unittest.TestCase):
    def test_keyed_tokens(self):
        p = parse_tool_tag(
            "sqlmap TARGET:https://example.com/search?q=test PROFILE:aggressive SCENARIO:sqli"
        )
        self.assertEqual(p["tool"], "sqlmap")
        self.assertEqual(p["target"], "https://example.com/search?q=test")
        self.assertEqual(p["profile"], "aggressive")
        self.assertEqual(p["scenario"], "sqli")

    def test_legacy_positional(self):
        p = parse_tool_tag("gobuster https://example.com SCENARIO:api")
        self.assertEqual(p["tool"], "gobuster")
        self.assertEqual(p["target"], "https://example.com")
        self.assertEqual(p["scenario"], "api")

    def test_searchsploit_cve(self):
        p = parse_tool_tag("searchsploit TARGET:CVE-2024-1234 PROFILE:default")
        self.assertEqual(p["target"], "CVE-2024-1234")

    def test_invented_flags_collected(self):
        p = parse_tool_tag("sqlmap TARGET:https://h/ --os-shell -u https://h/")
        self.assertTrue(p["invented_flags"])

    def test_extract_tool_calls_from_plan(self):
        text = (
            "PLAN: crawl then inject\n"
            "[TOOL: gobuster TARGET:https://example.com PROFILE:default SCENARIO:api]\n"
            "[SEARCH: CVE-2024-1234]\n"
        )
        calls = extract_tool_calls(text)
        self.assertEqual(calls[0][0], "TOOL")
        self.assertIn("gobuster", calls[0][1])
        self.assertEqual(calls[1], ("SEARCH", "CVE-2024-1234"))


class CanonicalTests(unittest.TestCase):
    def test_query_values_ignored(self):
        a = canonical_endpoint("https://site.com/page?id=1", include_params=True)
        b = canonical_endpoint("https://site.com/page?id=2", include_params=True)
        self.assertEqual(a, b)

    def test_new_param_is_different(self):
        a = canonical_endpoint("https://site.com/page?id=1", include_params=True)
        b = canonical_endpoint("https://site.com/page?id=1&q=x", include_params=True)
        self.assertNotEqual(a, b)

    def test_paths_differ(self):
        a = canonical_endpoint("https://site.com/search", include_params=False)
        b = canonical_endpoint("https://site.com/login", include_params=False)
        self.assertNotEqual(a, b)

    def test_utm_stripped(self):
        a = canonical_endpoint("https://site.com/p?id=1", include_params=True)
        b = canonical_endpoint("https://site.com/p?id=1&utm_source=x", include_params=True)
        self.assertEqual(a, b)

    def test_injection_run_key_same_param(self):
        k1 = run_key("sqlmap", "https://h/s?id=1", "default")
        k2 = run_key("sqlmap", "https://h/s?id=2", "default")
        self.assertEqual(k1, k2)

    def test_discovery_ignores_query(self):
        k1 = run_key("nuclei", "https://h/?id=1", "default")
        k2 = run_key("nuclei", "https://h/?id=2", "default")
        self.assertEqual(k1, k2)


class SanitizeTests(unittest.TestCase):
    def test_strips_zap_progress(self):
        raw = "[                    ] 3% |\n[=                   ] 9% \\\nReal alert line\n"
        out = sanitize_tool_chunk(raw, "zaproxy")
        self.assertNotIn("3%", out)
        self.assertIn("Real alert line", out)

    def test_strips_cr_and_ansi(self):
        raw = "\x1b[92mhit\x1b[0m\r[====] 42%\nkeep me\n"
        out = sanitize_tool_chunk(raw, "nuclei")
        self.assertIn("hit", out)
        self.assertIn("keep me", out)
        self.assertNotIn("42%", out)

    def test_drops_zap_xml(self):
        raw = "<?xml version='1.0'?>\n<OWASPZAPReport>\n<alert>x</alert>\n"
        out = sanitize_tool_chunk(raw, "zaproxy")
        self.assertNotIn("OWASPZAPReport", out)


class WaveTests(unittest.TestCase):
    def test_orders_and_skips_empty(self):
        waves = [
            {"name": "passive", "tools": ["whois", "dig"], "max_workers": 4, "depends_on": []},
            {"name": "ports", "tools": ["nmap"], "max_workers": 1, "depends_on": ["passive"]},
        ]
        ordered = tools_by_wave(["nmap", "whois"], waves)
        names = [w[0] for w in ordered]
        self.assertEqual(names[0], "passive")
        self.assertEqual(ordered[0][1], ["whois"])
        self.assertEqual(ordered[1][1], ["nmap"])

    def test_unknown_tools_go_other(self):
        ordered = tools_by_wave(["custom-tool"], [])
        self.assertEqual(ordered[0][0], "other")


class ProfileTests(unittest.TestCase):
    def test_unknown_falls_back(self):
        cfg = {
            "timeout": 10,
            "args": ["-u", "{url}"],
            "extra_args": [],
            "default_profile": "default",
            "profiles": {"default": {}, "aggressive": {"extends": "default", "timeout": 20}},
        }
        merged = resolve_profile(cfg, "nope")
        self.assertEqual(merged["_profile"], "default")
        self.assertEqual(merged["args"], ["-u", "{url}"])

    def test_exploit_appends_extra(self):
        cfg = {
            "args": ["-u", "{url}", "--batch"],
            "extra_args": [],
            "profiles": {
                "default": {},
                "aggressive": {"extends": "default", "args": ["-u", "{url}", "--level=3"]},
                "exploit": {"extends": "aggressive", "extra_args": ["--os-shell"]},
            },
        }
        merged = resolve_profile(cfg, "exploit")
        self.assertIn("--os-shell", merged["extra_args"])
        self.assertEqual(merged["args"], ["-u", "{url}", "--level=3"])


class GateTests(unittest.TestCase):
    def test_duplicate_skipped(self):
        key = run_key("sqlmap", "https://h/s?id=1", "default")
        ok, _, reason = apply_safety_gates(
            {"tool": "sqlmap", "target": "https://h/s?id=2", "profile": "default"},
            {key},
        )
        self.assertFalse(ok)
        self.assertIn("duplicate", reason.lower())

    def test_exploit_requires_detect(self):
        ok, _, reason = apply_safety_gates(
            {"tool": "sqlmap", "target": "https://h/s?id=1", "profile": "exploit"},
            set(),
            global_cfg={"max_exploit_runs": 1, "exploit_requires_detect": True},
        )
        self.assertFalse(ok)
        self.assertIn("default/aggressive", reason)


class TimeoutPolicyTests(unittest.TestCase):
    def test_missing_idle_reset_defaults_true(self):
        with patch("tools.get_global_config", return_value={}):
            idle, max_t = _timeout_policy({})
            self.assertTrue(idle)
            self.assertEqual(max_t, 0)

    def test_gobuster_style_cfg_inherits_global(self):
        with patch("tools.get_global_config", return_value={"idle_reset": True}):
            idle, _ = _timeout_policy({"timeout": 600})
            self.assertTrue(idle)

    def test_tool_can_force_wall_clock(self):
        with patch("tools.get_global_config", return_value={"idle_reset": True}):
            idle, _ = _timeout_policy({"idle_reset": False})
            self.assertFalse(idle)

    def test_max_timeout_from_tool(self):
        with patch("tools.get_global_config", return_value={}):
            idle, max_t = _timeout_policy({"max_timeout": 3600})
            self.assertTrue(idle)
            self.assertEqual(max_t, 3600)


class DryRunTests(unittest.TestCase):
    def test_env_flag(self):
        from dispatch import dry_run_enabled
        with patch.dict(os.environ, {"METATRON_DRY_RUN": "1"}):
            self.assertTrue(dry_run_enabled())


if __name__ == "__main__":
    unittest.main()
