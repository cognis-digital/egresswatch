"""Core engine for EGRESSWATCH.

Pure stdlib. The engine ingests outbound (egress) connection events from two
real sources:

  1. A JSON/JSONL event stream in the shape Falco/eBPF outbound probes emit
     (proc, pid, user, dest ip/port, l4proto, container, timestamp).
  2. A live Linux ``/proc/net/tcp`` snapshot (so the tool works zero-install
     on any server with no agent running).

Each connection is normalized into a ``Connection`` then evaluated against an
ordered ``Policy``. Findings carry a severity so the CLI can return a non-zero
exit when anything at or above a threshold is seen — the classic "fail the
build / fail the audit" behavior.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Ports that move data in the clear — egress on these to a public host is a
# data-exfil / credential-leak smell.
PLAINTEXT_PORTS = {
    21: "ftp",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    11211: "memcached",
    27017: "mongodb",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Connection:
    """A single normalized outbound connection."""

    proc: str = "?"
    pid: int = 0
    user: str = "?"
    dest_ip: str = ""
    dest_port: int = 0
    proto: str = "tcp"
    container: Optional[str] = None
    ts: Optional[str] = None

    def is_private_dest(self) -> bool:
        try:
            ip = ipaddress.ip_address(self.dest_ip)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local

    def is_public_dest(self) -> bool:
        try:
            ip = ipaddress.ip_address(self.dest_ip)
        except ValueError:
            return False
        return ip.is_global

    def key(self) -> str:
        return f"{self.proc}:{self.dest_ip}:{self.dest_port}/{self.proto}"


@dataclass
class Rule:
    """An ordered policy rule. First matching rule wins (allow short-circuits)."""

    name: str
    action: str = "deny"  # "allow" | "deny" | "flag"
    severity: str = "medium"
    cidrs: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    procs: list[str] = field(default_factory=list)
    note: str = ""

    def matches(self, conn: Connection) -> bool:
        if self.ports and conn.dest_port not in self.ports:
            return False
        if self.procs and conn.proc not in self.procs:
            return False
        if self.cidrs:
            try:
                ip = ipaddress.ip_address(conn.dest_ip)
            except ValueError:
                return False
            if not any(ip in ipaddress.ip_network(c, strict=False) for c in self.cidrs):
                return False
        # An empty rule (no selectors) matches everything — used as catch-all.
        return True


@dataclass
class Policy:
    name: str = "default"
    rules: list[Rule] = field(default_factory=list)
    # When True, public-destination plaintext ports are flagged automatically
    # even if no explicit rule covers them.
    flag_plaintext_public: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = [Rule(**r) for r in data.get("rules", [])]
        return cls(
            name=data.get("name", "custom"),
            rules=rules,
            flag_plaintext_public=data.get("flag_plaintext_public", True),
        )


@dataclass
class Finding:
    severity: str
    rule: str
    message: str
    connection: dict


@dataclass
class AuditResult:
    policy: str
    total_connections: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "policy": self.policy,
            "total_connections": self.total_connections,
            "max_severity": self.max_severity,
            "counts": self.counts(),
            "findings": [asdict(f) for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Default policy: a sane server baseline.
# ---------------------------------------------------------------------------

DEFAULT_POLICY = Policy(
    name="server-baseline",
    rules=[
        Rule("allow-dns", action="allow", ports=[53], severity="info",
             note="DNS resolution"),
        Rule("allow-https", action="allow", ports=[443], severity="info",
             note="TLS egress"),
        Rule("allow-ssh-out", action="allow", ports=[22], severity="info",
             note="outbound ssh/git"),
        Rule("allow-private", action="allow", severity="info",
             cidrs=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
             note="intra-VPC / loopback traffic"),
        # Anything else reaching a public host is suspicious by default.
        Rule("deny-unexpected-public", action="flag", severity="high",
             cidrs=["0.0.0.0/0", "::/0"],
             note="unexpected outbound to public internet"),
    ],
    flag_plaintext_public=True,
)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_events(text: str) -> list[Connection]:
    """Parse a Falco/eBPF-style event stream.

    Accepts either a JSON array of objects or newline-delimited JSON (JSONL).
    Tolerates several common field aliases.
    """
    text = text.strip()
    if not text:
        return []

    objs: list[dict] = []
    try:
        loaded = json.loads(text)
        if isinstance(loaded, list):
            objs = [o for o in loaded if isinstance(o, dict)]
        elif isinstance(loaded, dict):
            objs = [loaded]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(o, dict):
                objs.append(o)

    conns: list[Connection] = []
    for o in objs:
        out = o.get("output_fields", o)  # Falco nests fields under output_fields
        dest_ip = _first(out, "dest_ip", "fd.rip", "dip", "remote_ip", "raddr")
        if not dest_ip:
            continue
        conns.append(
            Connection(
                proc=str(_first(out, "proc", "proc.name", "comm", "process") or "?"),
                pid=_int(_first(out, "pid", "proc.pid")),
                user=str(_first(out, "user", "user.name", "username") or "?"),
                dest_ip=str(dest_ip),
                dest_port=_int(_first(out, "dest_port", "fd.rport", "dport", "remote_port")),
                proto=str(_first(out, "proto", "fd.l4proto", "l4proto") or "tcp").lower(),
                container=_first(out, "container", "container.id", "container.name"),
                ts=_first(out, "ts", "time", "evt.time"),
            )
        )
    return conns


def parse_proc_net(text: str, proto: str = "tcp") -> list[Connection]:
    """Parse a Linux ``/proc/net/tcp`` (or udp) snapshot into Connections.

    The remote address column is little-endian hex ``IP:PORT``. We surface
    only established / connecting sockets (non-zero remote addr).
    """
    conns: list[Connection] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[2]:
            continue
        if parts[0].rstrip(":").isalpha():  # header row ("sl local_address ...")
            continue
        rem = parts[2]
        ip, port = _decode_hex_addr(rem)
        if ip is None or port == 0 or ip in ("0.0.0.0", "::"):
            continue
        conns.append(Connection(dest_ip=ip, dest_port=port, proto=proto, proc="kernel-socket"))
    return conns


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(conns: Iterable[Connection], policy: Policy) -> AuditResult:
    conns = list(conns)
    result = AuditResult(policy=policy.name, total_connections=len(conns))

    for conn in conns:
        matched = False
        for rule in policy.rules:
            if not rule.matches(conn):
                continue
            matched = True
            if rule.action == "allow":
                break  # allowed → no finding, stop evaluating
            sev = rule.severity
            verb = "DENIED" if rule.action == "deny" else "FLAGGED"
            result.findings.append(
                Finding(
                    severity=sev,
                    rule=rule.name,
                    message=f"{verb} {conn.proc} -> {conn.dest_ip}:{conn.dest_port}/"
                            f"{conn.proto} ({rule.note or rule.name})",
                    connection=asdict(conn),
                )
            )
            break

        # Independent plaintext-to-public heuristic (Falco-style built-in rule).
        if policy.flag_plaintext_public and conn.is_public_dest() \
                and conn.dest_port in PLAINTEXT_PORTS:
            result.findings.append(
                Finding(
                    severity="high",
                    rule="plaintext-egress-public",
                    message=f"plaintext {PLAINTEXT_PORTS[conn.dest_port]} egress to "
                            f"public host {conn.dest_ip}:{conn.dest_port}",
                    connection=asdict(conn),
                )
            )

        if not matched:
            result.findings.append(
                Finding(
                    severity="medium",
                    rule="no-policy-match",
                    message=f"{conn.proc} -> {conn.dest_ip}:{conn.dest_port}/"
                            f"{conn.proto} matched no policy rule",
                    connection=asdict(conn),
                )
            )

    return result


def audit(text: str, policy: Optional[Policy] = None, source: str = "events") -> AuditResult:
    """End-to-end: parse ``text`` from ``source`` then evaluate against policy."""
    policy = policy or DEFAULT_POLICY
    if source == "proc":
        conns = parse_proc_net(text)
    else:
        conns = parse_events(text)
    return evaluate(conns, policy)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first(d: dict, *keys: str):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _decode_hex_addr(token: str):
    """Decode ``/proc/net`` little-endian hex ``ADDR:PORT`` (IPv4 only)."""
    try:
        hex_ip, hex_port = token.split(":")
        port = int(hex_port, 16)
        if len(hex_ip) == 8:  # IPv4, little-endian
            b = bytes.fromhex(hex_ip)
            ip = ".".join(str(x) for x in reversed(b))
            return ip, port
        return None, 0  # skip IPv6 for this stdlib parser
    except (ValueError, AttributeError):
        return None, 0
