# Roadmap

## What 0.2.0 adds

Three things, and only these:

1. One-time signed approvals for a named action. They can satisfy a
   single `NeedsApproval`. They can't override `Deny`. They don't cover
   arguments.
2. An exclusive file lock on the audit log, held by `AuditLog`.
3. `terminal-guard mcp-proxy`, which forwards a `tools/call` only when the
   guard allows it, passes the read-only MCP session messages, and blocks
   everything else.

Not built, and not claimed: audit-key ratcheting, operator
countersignatures of the log head, numeric limits, or any hardware
control. Hardware control isn't planned for this repository.

Candidates for later, if review supports them: a live contact renewal
channel for the proxy, approvals bound to a hash of the arguments, a
separate approval key role, and filtering `tools/list` by policy.

## What 0.1.0 has

Permissions step down in stages when human contact is lost, and only a new
signed renewal restores them. Decisions fail closed, and a signed local
hash-chained log records the contact level in every entry. This core stays
free and open source under Apache 2.0.

## Planned, roughly in order

These are plans. Nothing below exists yet, and there are no dates.

1. Easier embedding: optional checkpointing, an in-memory or custom log
   sink, and fewer filesystem assumptions in the core.
2. Resource and capability bounds, such as counts, sizes or scopes per
   action, that also shrink as contact degrades.
3. Attenuation-only permissions, which can be narrowed but never widened.
   These would use existing standard crypto or Biscuit tokens, with no new
   cryptography.
4. A fail-closed monitor that moves the guard to `hold` if the agent stops
   checking in.
5. Simple policy-as-code: small, testable policy definitions beyond the
   current TOML table.
6. Optional thin bindings for Python and C.

Extensions would sit behind Cargo feature flags so the core stays small.

## How the project plans to pay for itself

The crate won't be sold or relicensed. The plan is to offer paid help
around it: integration and setup, policy and audit-log review, support
retainers and example policy packs, and possibly an optional multi-device
log dashboard. None of these are offered yet.
