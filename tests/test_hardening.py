"""Hardening tests: bad input, edge cases, and error paths for EGRESSWATCH."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from egresswatch.core import (  # noqa: E402
    Policy,
    evaluate,
    audit,
    parse_events,
    parse_proc_net,
    Connection,
    DEFAULT_POLICY,
)
from egresswatch.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# Policy.from_dict validation
# ---------------------------------------------------------------------------

class TestPolicyFromDictValidation(unittest.TestCase):
    def test_non_dict_raises(self):
        with self.assertRaises((ValueError, TypeError)):
            Policy.from_dict([{"name": "r"}])  # type: ignore[arg-type]

    def test_rules_not_list_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": "not-a-list"})

    def test_rule_missing_name_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": [{"action": "allow", "ports": [443]}]})

    def test_rule_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": [{"name": "r", "action": "block"}]})

    def test_rule_invalid_severity_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": [{"name": "r", "severity": "fatal"}]})

    def test_rule_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": [{"name": "r", "ports": [99999]}]})

    def test_rule_port_negative_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": [{"name": "r", "ports": [-1]}]})

    def test_rule_invalid_cidr_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"rules": [{"name": "r", "cidrs": ["not-a-cidr"]}]})

    def test_empty_rules_ok(self):
        p = Policy.from_dict({"name": "empty", "rules": []})
        self.assertEqual(p.rules, [])

    def test_valid_policy_parses(self):
        p = Policy.from_dict({
            "name": "test",
            "rules": [{"name": "allow-tls", "action": "allow", "ports": [443]}],
        })
        self.assertEqual(len(p.rules), 1)
        self.assertEqual(p.rules[0].action, "allow")


# ---------------------------------------------------------------------------
# audit() source validation
# ---------------------------------------------------------------------------

class TestAuditSourceValidation(unittest.TestCase):
    def test_unknown_source_raises(self):
        with self.assertRaises(ValueError) as ctx:
            audit("{}", source="falco-raw")
        self.assertIn("unknown source", str(ctx.exception))

    def test_valid_sources_accepted(self):
        # Should not raise, just returns an AuditResult.
        r = audit("[]", source="events")
        self.assertEqual(r.total_connections, 0)
        # proc source with minimal valid content
        r2 = audit("  sl  local_address rem_address\n", source="proc")
        self.assertEqual(r2.total_connections, 0)


# ---------------------------------------------------------------------------
# Malformed CIDR in rule — should not crash at match time
# ---------------------------------------------------------------------------

class TestMalformedCidrDoesNotCrash(unittest.TestCase):
    def test_bad_cidr_rule_does_not_crash(self):
        """A rule with a bad CIDR loaded outside from_dict should not crash evaluate()."""
        from egresswatch.core import Rule
        rule = Rule(name="bad-cidr", action="deny", cidrs=["999.999.999.999/24"])
        policy = Policy(name="t", rules=[rule], flag_plaintext_public=False)
        conn = Connection(proc="test", dest_ip="1.2.3.4", dest_port=80)
        # Should not raise; rule simply won't match.
        result = evaluate([conn], policy)
        # Connection matches no rule → no-policy-match finding.
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule, "no-policy-match")


# ---------------------------------------------------------------------------
# Edge cases: empty / whitespace input
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    def test_parse_events_whitespace_only(self):
        self.assertEqual(parse_events("   \n\t  "), [])

    def test_parse_events_all_bad_lines(self):
        self.assertEqual(parse_events("not json\nalso not json\n"), [])

    def test_parse_events_missing_dest_ip_skipped(self):
        text = json.dumps([{"proc": "curl", "dest_port": 443}])
        conns = parse_events(text)
        self.assertEqual(conns, [])

    def test_evaluate_empty_connections(self):
        result = evaluate([], DEFAULT_POLICY)
        self.assertEqual(result.total_connections, 0)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.max_severity, "info")

    def test_parse_proc_net_empty(self):
        self.assertEqual(parse_proc_net(""), [])

    def test_parse_proc_net_header_only(self):
        self.assertEqual(parse_proc_net("  sl  local_address rem_address   st\n"), [])

    def test_connection_empty_dest_ip_not_public(self):
        conn = Connection(dest_ip="")
        self.assertFalse(conn.is_public_dest())
        self.assertFalse(conn.is_private_dest())


# ---------------------------------------------------------------------------
# CLI error paths
# ---------------------------------------------------------------------------

class TestCliErrorPaths(unittest.TestCase):
    def test_missing_input_file_returns_2(self):
        rc = main(["audit", "/tmp/does-not-exist-xyz.jsonl"])
        self.assertEqual(rc, 2)

    def test_malformed_policy_file_returns_2(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False, encoding="utf-8") as f:
            f.write('{"rules": "not-a-list"}')
            fpath = f.name
        try:
            rc = main(["audit", "--policy", fpath, "-"])
        finally:
            os.unlink(fpath)
        self.assertEqual(rc, 2)

    def test_bad_json_policy_file_returns_2(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False, encoding="utf-8") as f:
            f.write("{bad json}")
            fpath = f.name
        try:
            rc = main(["audit", "--policy", fpath, "-"])
        finally:
            os.unlink(fpath)
        self.assertEqual(rc, 2)

    def test_empty_input_file_exits_cleanly(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl",
                                        delete=False, encoding="utf-8") as f:
            f.write("")
            fpath = f.name
        try:
            rc = main(["audit", fpath])
        finally:
            os.unlink(fpath)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
