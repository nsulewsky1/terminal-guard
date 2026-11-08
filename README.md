# terminal-guard

A small, fail-closed policy engine for AI agents that can lose contact with
the people supervising them.

As time since the last verified human contact grows, the agent's permissions
shrink on a fixed schedule. Only a fresh message signed by a trusted person
moves them back up. Every decision goes into a signed, hash-chained audit log
that anyone holding the audit public key can check.

Status: early first version (0.1.0). Intended to be open source; the license
has not been chosen yet, so no license is granted until one is added.

## What it does

1. **Check.** `guard.check("action")` returns `Allow`, `NeedsApproval` or
   `Deny`. Unknown actions, malformed names, internal errors and failed audit
   writes all return `Deny`.
2. **Policy file.** Four contact levels, best to worst:
   `connected -> degraded -> lost -> hold`. Each action lists a decision per
   level. Loading fails unless every action satisfies
   `connected >= degraded >= lost >= hold` (with `deny < needs_approval < allow`),
   so losing contact can never add a permission. (A policy may still allow
   an action at every level, including `hold`; that is the author's choice.)
3. **Contact timer.** Uses monotonic time, so wall-clock changes cannot make
   the agent look more connected. Steps down on the schedule and never steps
   up on its own, even if the clock goes backwards. The engine **starts in
   `hold`** on every start and restart until it gets fresh verified contact.
4. **Signed human contact.** The only way up. A contact message must be
   signed (Ed25519, strict verification) by a pinned human key, carry the
   `terminal-guard/contact/v1` domain and this engine's ID, have a sequence
   number higher than any accepted before, and have a timestamp inside the
   policy's freshness window. Old messages are backdated by their age.
   Replays, stale or future-dated messages, wrong engine, wrong domain and
   wrong key are rejected and logged.
5. **Audit log.** One JSON line per entry, each holding the contact level at
   that moment, a SHA-256 link to the previous entry, and an Ed25519
   signature from a separate audit key. Hashes and signatures cover a
   canonical, versioned, length-prefixed binary encoding, not the JSON text.
6. **Checkpoint + verify.** A small signed checkpoint (`log_id`, `count`,
   `head`) is rewritten after each append. `terminal-guard verify` checks the
   genesis link, sequence numbers, every signature and link, and that the log
   ends exactly at the checkpoint's count and head. A missing checkpoint
   fails.

## Quick start

```sh
cargo test
cargo run --example demo
cargo run --bin terminal-guard -- verify \
  --log demo-out/audit.log \
  --checkpoint demo-out/audit.checkpoint \
  --audit-pubkey demo-out/audit.pub \
  --log-id demo-agent-01
cargo run --bin terminal-guard -- check-policy policies/example.toml
```

`verify` exits 0 when the log checks out, 1 when it does not, 2 on bad usage.
Add `--prefix` to verify against an older checkpoint you kept elsewhere; the
log may have grown since, but it must still contain that checkpoint.

## Demo

`cargo run --example demo` runs a mock agent through a **simulated** lost link
using a mock clock. It is a test of the policy logic, not evidence from
unplugging a real network. Actions are harmless local stand-ins (read a local
fixture, draft a local note, send an external message, delete a local file).
Keys are generated fresh in memory on each run; private keys are never
written. Output goes to `demo-out/` (git-ignored). Example output:

```text
t+0      engine start, no contact yet  level=hold      read_local_fixture=deny  draft_local_note=deny  send_external_message=deny  delete_local_file=deny  unlisted_action=deny
  -> fresh signed human contact (seq 1): Ok(())
t+0      after verified contact        level=connected read_local_fixture=ALLOW  draft_local_note=ALLOW  send_external_message=APPROVAL  delete_local_file=APPROVAL  unlisted_action=deny
t+15m    no contact for 15 min         level=degraded  read_local_fixture=ALLOW  draft_local_note=ALLOW  send_external_message=APPROVAL  delete_local_file=deny  unlisted_action=deny
t+1h15m  no contact for 75 min         level=lost      read_local_fixture=ALLOW  draft_local_note=APPROVAL  send_external_message=deny  delete_local_file=deny  unlisted_action=deny
  -> replay of old contact (seq 1): Err(Replay)
  -> contact signed by unknown key: Err(BadSignature)
t+4h15m  no contact for over 4 h       level=hold      read_local_fixture=deny  draft_local_note=deny  send_external_message=deny  delete_local_file=deny  unlisted_action=deny
```

## Using it

```rust
use terminal_guard::{AuditLog, Decision, Guard, Policy, SystemClock};

let policy = Policy::from_toml(&std::fs::read_to_string("policies/example.toml")?)?;
let audit = AuditLog::create("agent.log".as_ref(), "agent.checkpoint".as_ref(), "agent-01", audit_signing_key)?;
let mut guard = Guard::new(policy, "agent-01", vec![operator_public_key], next_sequence, audit, SystemClock::new())?;

// Feed operator contact messages (JSON) as they arrive:
let _ = guard.accept_contact_json(&incoming);

match guard.check("send_external_message") {
    Decision::Allow => { /* the caller performs the action */ }
    Decision::NeedsApproval => { /* the caller must get a human approval first */ }
    Decision::Deny => { /* do not act */ }
}
```

Operators sign contact with `ContactAuth::new(engine_id, sequence, unix_ms).sign(&key)`.
Key storage and transport of contact messages are up to you.

## Security boundary (read this)

- **Decision only.** This crate decides; it does not enforce. The calling
  code must actually refuse denied actions. It does not intercept network
  traffic, system calls or tools.
- **`NeedsApproval` is not permission.** There is no approval API and no
  bypass path in this crate. The caller must get and check a human approval
  through its own channel before acting.
- **Key roles.** Human contact keys and the audit key are separate. The guard
  refuses to start if the audit key is also a trusted human key. The verifier
  must pin the audit public key from a trusted source, never from the log or
  checkpoint.
- **Deleted newest entry.** Detected only when you verify against the
  trusted latest checkpoint. If someone rolls back the log **and** the
  checkpoint together to an earlier matching pair, file-only verification
  cannot detect it. Copy checkpoints somewhere the agent host cannot rewrite
  and verify with `--prefix` against that copy.
- **Crash between writes.** If the process dies after appending an entry but
  before rewriting the checkpoint, verification fails (one extra entry).
  That is fail-closed; an operator has to inspect it.
- **Anti-replay across restarts.** The last accepted contact sequence lives in
  memory. After a restart, pass `last accepted + 1` to `Guard::new` (the
  verify report exposes `last_contact_sequence`). If you do not, a captured
  message can be replayed until it ages out of `max_age_secs`.
- **Freshness depends on wall-clock time.** Contact freshness compares the
  message timestamp to the host clock. A host whose clock is wrong can accept
  or reject contact wrongly. Contact age itself uses monotonic time.
- **Compromised keys.** If a human key or the audit signing key is stolen,
  there are no guarantees.
- **No certification.** This is an early open-source library. It has no
  formal certification, audit or deployment history.

## Layout

```text
src/policy.rs    policy file, levels, decisions, validation
src/contact.rs   contact timer, signed contact messages, anti-replay
src/audit.rs     audit log, checkpoint, verification
src/guard.rs     the engine that ties them together
src/clock.rs     real and mock clocks
src/keys.rs      key helpers
src/bin/terminal-guard.rs   verify / check-policy CLI
examples/demo.rs            simulated lost-link demo
tests/                      unit, tamper and property tests
policies/example.toml       example policy
```

## Built with

`ed25519-dalek` (signatures), `sha2` (hashing), `serde`/`serde_json`/`toml`
(parsing), `proptest` (property tests). No custom cryptography.

Minimum Rust version: 1.85.
