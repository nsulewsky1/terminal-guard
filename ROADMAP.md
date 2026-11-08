# Roadmap

These are plans. Nothing below exists in the crate yet, and there are no
dates.

## What 0.1.0 has

Permissions step down in stages when human contact is lost, and only a new
signed renewal restores them. Decisions fail closed, and a signed local
hash-chained log records the contact level in every entry. This core stays
free and open source under Apache 2.0.

## Planned, roughly in order

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
