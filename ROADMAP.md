# Roadmap

Plans only. Nothing below exists in the crate yet, and there are no dates.

## Core (what 0.1.0 has)

Staged step-down on lost human contact, restore only on a new signed
renewal, fail-closed decisions, and a signed local hash-chained log that
records the contact level in every entry. This core stays free and open
source under Apache 2.0.

## Next, in rough order

1. **Embedding polish.** Optional checkpointing, an in-memory or custom
   log sink, and fewer filesystem assumptions in the core.
2. **Resource and capability bounds.** Limits such as counts, sizes or
   scopes per action, also shrinking as contact degrades.
3. **Attenuation-only permissions.** Permissions that can be narrowed but
   never widened, using existing standard crypto or Biscuit tokens rather
   than new cryptography.
4. **Fail-closed monitor.** A small helper that moves the guard to `hold`
   if the agent stops checking in.
5. **Simple policy-as-code.** Small, testable policy definitions beyond the
   current TOML table.
6. **Optional thin bindings** for Python and C.

Extensions would sit behind Cargo feature flags so the core stays small.

## How the project intends to sustain itself

The crate itself will not be sold or relicensed. The intent is to offer
paid help around it: integration and setup, policy and audit-log review,
support retainers, example policy packs, and possibly an optional
multi-device log dashboard. None of these are offered yet.
