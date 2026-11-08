# How terminal-guard relates to existing work

None of the building blocks here are new. Leases that expire unless renewed,
dead-man switches, tokens that can only lose rights, policy engines that
return allow or deny, and signed append-only logs all exist and are well
understood. What terminal-guard does is combine a few of them into one small
embedded library for a specific situation: an AI agent that loses contact
with the people supervising it.

This page describes what each project below documents about itself, based on
the pages linked. It doesn't claim that any of them can't do something, only
what their own docs say.

## Closest ideas

**Leases.** HashiCorp Vault attaches a lease with a time to live to dynamic
secrets and service tokens. Consumers have to check in to renew, and expired
leases are revoked
([Vault: Lease, renew, and revoke](https://developer.hashicorp.com/vault/docs/concepts/lease)).
terminal-guard uses the same idea of "keep checking in or lose access", but
instead of one expiry it steps through several levels, and the renewal has
to be a signed message from a pinned human key.

**Attenuation.** Biscuit tokens are signed with public-key cryptography and
support offline attenuation: a holder can add restrictions, and the token
"can only be restricted, it will never gain more rights"
([Biscuit introduction](https://www.biscuitsec.org/docs/getting-started/introduction/)).
terminal-guard's policy check has the same shape of guarantee in a narrower
form: the policy file won't load unless every action's permission stays the
same or shrinks as contact degrades. It doesn't use Biscuit today; the
roadmap lists Biscuit or standard crypto as options for richer attenuation.

**Policy engines.** Open Policy Agent decouples decisions from enforcement:
software queries OPA with structured input and gets a decision back, and OPA
can be embedded as a Go library
([OPA docs](https://www.openpolicyagent.org/docs)). Cedar is a policy
language and Rust engine for fine-grained authorization that applications
call to authorize requests
([cedar-policy/cedar](https://github.com/cedar-policy/cedar)). Both are far
more expressive than terminal-guard's four-level table. terminal-guard has
no policy language. It's closer to a fixed state machine with a small table,
and it could sit next to either engine, for example by passing the current
contact level in as an input.

**Tamper-evident logs.** Certificate Transparency keeps append-only logs
built on Merkle trees, signs tree heads, and relies on monitors and gossip
to catch a log that shows different views to different parties
([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)). terminal-guard's log
is much simpler: a linear SHA-256 chain with a signed checkpoint, kept on
one machine. It has no consistency proofs and no gossip, which is why a
joint rollback of the log and checkpoint can only be caught with a
checkpoint kept somewhere else.

## Agent-specific projects

Several open-source projects already target AI agents with similar
controls. A few found during this review:

- [Technika11y/cyberdyne](https://github.com/Technika11y/cyberdyne)
  (Python, Apache-2.0) describes a fail-closed decision engine with step and
  time budgets, a heartbeat dead-man's switch and human-approval gates, and
  says wiring the actual stop is left to the integrator.
- [flowdot-llc/guardian-agent](https://github.com/flowdot-llc/guardian-agent)
  (Python and TypeScript, pre-alpha) describes a hash-chained audit log with
  optional ed25519 signatures, tool-permission scoping, human-in-the-loop
  approval gates, an emergency stop, and a dead-man's heartbeat in its
  TypeScript reference.
- [TomCruiseTorpedo/leasebroker](https://github.com/TomCruiseTorpedo/leasebroker)
  (TypeScript, Apache-2.0) describes signed, scoped, expiring capability
  leases for agents and MCP servers, enforced in an MCP proxy, with a
  hash-chained audit log, revocation and human veto on risky grants.

So a heartbeat or lease for agents, a hash-chained audit log and approval
gates are all covered elsewhere.

## What terminal-guard does differently

The narrower combination, as far as this review found, is:

- graded step-down through several contact levels, rather than a single
  expiry or halt, with a load-time check that no action gains permission as
  contact gets worse;
- restore only through a fresh renewal signed by a pinned human key and
  bound to this engine, a domain string and an increasing sequence number,
  so reconnecting alone does nothing and replays are refused;
- the contact level recorded in every log entry, and a replay floor that is
  recovered from the verified log when the guard restarts;
- an embedded Rust library with no daemon or network service.

That's an integration of known pieces for one failure mode, not a new
security primitive. It hasn't been independently reviewed, and the other
projects above may cover more ground in other directions.

## Open work that needs outside review

- An independent review of the state machine, the renewal checks and the
  restart path.
- Persistence that survives a lost or replaced log, such as sending
  checkpoints to a separate witness the agent host can't rewrite.
- Measurements of decision latency and log overhead on real hardware. No
  benchmarks have been run yet.
- Trying it inside at least one real agent framework, with the caller's
  enforcement code reviewed too.
