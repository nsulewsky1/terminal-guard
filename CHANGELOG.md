# Changelog

## 0.2.0 (experimental, unaudited)

Added:

- `Guard::decide_with_approval` and `ActionApproval` / `SignedActionApproval`:
  a one-time signed approval for a named action. It turns one
  `NeedsApproval` into `Allow`. `Deny` and `Allow` are returned unchanged and
  the approval isn't used up. Approvals are bound to the engine id and the
  action name, carry a unique id, use their own signed format (separate from
  contact messages), are checked with strict Ed25519 verification, and
  expire with the policy's contact freshness window. Used ids are written to
  the audit log (`approved_decision` entries) and recovered by
  `AuditLog::open`, so a reopened log refuses them. Rejections are logged
  (`approval_rejected`). Approvals don't cover arguments.
- An exclusive, non-blocking, advisory lock on the audit log, held for the
  life of `AuditLog` (via the `fs4` crate). A second open gets
  `AuditError::Locked`. `AuditLog::open` takes the lock before it reads and
  verifies the log. Before each append the guard also checks that the log
  path still points at the locked file.
- `terminal-guard mcp-proxy`: a stdio proxy in front of one MCP server. See
  the README for exactly what it forwards and blocks.
- `terminal-guard hold-lock`, a small command the lock test uses to hold a
  log open from a second process.
- `keys::signing_key_hex` and `keys::parse_signing_key_hex` for the
  proxy's audit key file.

Changed:

- Version 0.2.0. `verify_log` reports used approval ids and rejects a log
  that uses the same approval id twice.

Not included: key ratcheting, log-head countersignatures, numeric limits,
hardware control.

## 0.1.0

First public version: contact levels that only step down, signed contact
renewal with a replay floor, a signed hash-chained audit log with
checkpoints, the `verify` and `check-policy` commands, and the demo.
