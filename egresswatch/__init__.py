"""EGRESSWATCH — server-side outbound connection auditor.

A stdlib-only eBPF/Falco-spirit wrapper that parses kernel/socket event
streams (or live /proc data) into a normalized egress audit, then evaluates
each outbound connection against a policy of allow/deny rules — flagging
unexpected destinations, plaintext ports, private-to-public crossings, and
known-bad endpoints.
"""

from .core import (
    Connection,
    Rule,
    Policy,
    Finding,
    AuditResult,
    parse_events,
    parse_proc_net,
    evaluate,
    audit,
    DEFAULT_POLICY,
)

TOOL_NAME = "egresswatch"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Connection",
    "Rule",
    "Policy",
    "Finding",
    "AuditResult",
    "parse_events",
    "parse_proc_net",
    "evaluate",
    "audit",
    "DEFAULT_POLICY",
    "TOOL_NAME",
    "TOOL_VERSION",
]
