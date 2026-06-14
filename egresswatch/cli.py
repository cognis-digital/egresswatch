"""Command-line interface for EGRESSWATCH."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Policy, DEFAULT_POLICY, SEVERITY_ORDER, AuditResult, audit


def _read_input(path: Optional[str]) -> str:
    if path in (None, "-"):
        try:
            return sys.stdin.read()
        except UnicodeDecodeError as exc:
            raise UnicodeDecodeError(
                exc.encoding, exc.object, exc.start, exc.end,
                "stdin is not valid UTF-8; pass a file path instead"
            ) from None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _load_policy(path: Optional[str]) -> Policy:
    if not path:
        return DEFAULT_POLICY
    with open(path, "r", encoding="utf-8") as fh:
        return Policy.from_dict(json.load(fh))


def _render_table(result: AuditResult) -> str:
    lines = []
    lines.append(f"EGRESSWATCH audit — policy: {result.policy}")
    lines.append(f"connections: {result.total_connections}   "
                 f"findings: {len(result.findings)}   "
                 f"max-severity: {result.max_severity}")
    counts = result.counts()
    if counts:
        lines.append("  " + "  ".join(f"{k}={v}" for k, v in sorted(
            counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))))
    lines.append("-" * 72)
    if not result.findings:
        lines.append("no findings — all egress within policy")
    else:
        lines.append(f"{'SEVERITY':<9} {'RULE':<26} MESSAGE")
        for f in sorted(result.findings,
                        key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
            lines.append(f"{f.severity:<9} {f.rule:<26} {f.message}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Server-side outbound connection auditor (eBPF/Falco-spirit).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")

    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="audit an egress event stream or /proc/net snapshot")
    a.add_argument("input", nargs="?", default="-",
                   help="input file ('-' or omit for stdin)")
    a.add_argument("--source", choices=["events", "proc"], default="events",
                   help="input type: Falco/eBPF JSON events or /proc/net/tcp snapshot")
    a.add_argument("--policy", help="path to a JSON policy file (else built-in baseline)")
    a.add_argument("--fail-on", default="high",
                   choices=list(SEVERITY_ORDER.keys()),
                   help="min severity that yields a non-zero exit (default: high)")

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        try:
            text = _read_input(args.input)
            policy = _load_policy(args.policy)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"egresswatch: error: {exc}", file=sys.stderr)
            return 2

        try:
            result = audit(text, policy=policy, source=args.source)
        except ValueError as exc:
            print(f"egresswatch: error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(_render_table(result))

        threshold = SEVERITY_ORDER[args.fail_on]
        triggered = any(SEVERITY_ORDER.get(f.severity, 0) >= threshold
                        for f in result.findings)
        return 1 if triggered else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
