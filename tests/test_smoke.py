"""Smoke tests for EGRESSWATCH. No network. Stdlib unittest only."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from egresswatch import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Connection,
    Policy,
    DEFAULT_POLICY,
    parse_events,
    parse_proc_net,
    evaluate,
    audit,
)
from egresswatch.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic", "egress_events.jsonl")


class TestMeta(unittest.TestCase):
    def test_tool_identity(self):
        self.assertEqual(TOOL_NAME, "egresswatch")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestParsing(unittest.TestCase):
    def test_parse_jsonl_events(self):
        text = ('{"proc":"curl","dest_ip":"1.2.3.4","dest_port":443}\n'
                '{"proc":"sh","fd.rip":"5.6.7.8","fd.rport":23}')
        conns = parse_events(text)
        self.assertEqual(len(conns), 2)
        self.assertEqual(conns[0].dest_port, 443)
        self.assertEqual(conns[1].dest_ip, "5.6.7.8")  # alias fields resolved

    def test_parse_json_array_and_falco_nesting(self):
        text = json.dumps([{"output_fields": {"proc.name": "x", "fd.rip": "9.9.9.9",
                                               "fd.rport": 80, "fd.l4proto": "tcp"}}])
        conns = parse_events(text)
        self.assertEqual(conns[0].proc, "x")
        self.assertEqual(conns[0].dest_port, 80)

    def test_parse_empty(self):
        self.assertEqual(parse_events(""), [])

    def test_parse_proc_net(self):
        snap = (
            "  sl  local_address rem_address   st\n"
            "   0: 0100007F:0035 04030201:01BB 01\n"  # rem 1.2.3.4:443
            "   1: 0100007F:1234 00000000:0000 0A\n"  # listening -> skipped
        )
        conns = parse_proc_net(snap)
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].dest_ip, "1.2.3.4")
        self.assertEqual(conns[0].dest_port, 443)


class TestConnection(unittest.TestCase):
    def test_private_vs_public(self):
        self.assertTrue(Connection(dest_ip="10.0.0.5").is_private_dest())
        self.assertTrue(Connection(dest_ip="8.8.8.8").is_public_dest())
        self.assertFalse(Connection(dest_ip="8.8.8.8").is_private_dest())


class TestEvaluate(unittest.TestCase):
    def test_demo_findings(self):
        with open(DEMO, encoding="utf-8") as fh:
            result = audit(fh.read(), policy=DEFAULT_POLICY, source="events")
        self.assertEqual(result.total_connections, 7)
        # Three offending public/plaintext callouts -> at least 3 high findings.
        highs = [f for f in result.findings if f.severity == "high"]
        self.assertGreaterEqual(len(highs), 3)
        self.assertEqual(result.max_severity, "high")
        # Allowed traffic produces no finding for the DNS connection.
        rules_hit = {f.rule for f in result.findings}
        self.assertIn("plaintext-egress-public", rules_hit)

    def test_allow_short_circuits(self):
        policy = Policy(name="t", rules=[
            Policy.from_dict({"rules": [{"name": "ok", "action": "allow",
                                         "ports": [443]}]}).rules[0]
        ], flag_plaintext_public=False)
        res = evaluate([Connection(proc="curl", dest_ip="1.1.1.1", dest_port=443)], policy)
        self.assertEqual(res.findings, [])

    def test_no_match_is_flagged(self):
        policy = Policy(name="empty", rules=[], flag_plaintext_public=False)
        res = evaluate([Connection(proc="x", dest_ip="9.9.9.9", dest_port=9999)], policy)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].rule, "no-policy-match")


class TestCli(unittest.TestCase):
    def test_audit_json_exit_nonzero(self):
        rc = main(["--format", "json", "audit", DEMO, "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_audit_table_exit_clean_when_threshold_high(self):
        rc = main(["audit", DEMO, "--fail-on", "critical"])
        self.assertEqual(rc, 0)  # no critical findings in demo

    def test_missing_file_returns_2(self):
        rc = main(["audit", "/no/such/file.jsonl"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
