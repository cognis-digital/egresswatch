# Demo 01 — Basic egress audit

A CI/app server is emitting outbound-connection events from an eBPF/Falco
probe. We want to confirm every egress destination is expected, and to catch
anything reaching the public internet on an unexpected or plaintext port —
the classic data-exfiltration / reverse-shell smell.

## Input

`egress_events.jsonl` — newline-delimited Falco-style events (one outbound
connection per line). It mixes legitimate traffic with three problems:

- `python3 -> 185.220.101.7:4444` — a reverse-shell-style callout to a public
  host on a non-standard port (matches no allow rule → flagged as public).
- `sh -> 45.83.220.18:23` — root running plaintext **telnet** to the internet.
- `backup-agent -> 91.198.174.192:21` — plaintext **FTP** egress to a public host.

Legitimate traffic that must NOT be flagged: DNS (53), HTTPS (443),
outbound SSH/git (22), and intra-VPC Postgres (10.0.3.18:5432).

## Run

```bash
# Human-readable table
python -m egresswatch audit demos/01-basic/egress_events.jsonl

# Machine-readable JSON, fail the pipeline on any high+ finding
python -m egresswatch --format json audit demos/01-basic/egress_events.jsonl --fail-on high
echo "exit=$?"   # -> non-zero because high-severity findings exist
```

## Expected

The DNS, HTTPS, SSH, and private Postgres connections are allowed silently.
The three public/plaintext callouts surface as `high` findings (the telnet and
FTP ones also trip the built-in `plaintext-egress-public` rule), so the audit
exits non-zero — exactly what you want gating a deploy.
