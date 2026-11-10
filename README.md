# terminal-guard

[![tests](https://github.com/nsulewsky1/terminal-guard/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/nsulewsky1/terminal-guard/actions/workflows/tests.yml)

Permissions handed to an AI agent don't expire by themselves. If the people
supervising it go quiet, because the link dropped or the supervisor
crashed, the agent can keep doing everything it was allowed to do.

terminal-guard is a small Rust library for that gap. You give it a policy
that says, for each action, whether it's allowed at each of four contact
levels. As time
since the last verified human contact grows, the level drops and the
agent's permissions shrink with it. Getting the network back doesn't undo
that. Only a new message signed with a trusted human contact key does. Every
decision is written to a signed, hash-chained log that anyone with the audit
public key can check.

The library runs in-process. There's no daemon and it makes no network
calls. The optional `terminal-guard mcp-proxy` command runs as a separate
process between an MCP client and one MCP server over stdio.

Status: 0.2.0, experimental and unaudited. Nobody outside the project has
reviewed it, and it has no deployment history. Apache License 2.0 (see
[LICENSE](LICENSE)).

0.2.0 adds three things on top of 0.1.0 (details in
[CHANGELOG.md](CHANGELOG.md)):

* A one-time signed approval for a named action. It can turn a single
  `NeedsApproval` into `Allow`. It can't turn `Deny` into anything else, and
  a used approval id is refused from then on, including after the log is
  reopened. It covers the action name only, not its arguments. It isn't
  contact renewal.
* An exclusive file lock on the audit log, held for as long as the
  `AuditLog` value lives. A second open of the same log, from another
  process or the same one, gets `AuditError::Locked`.
* `terminal-guard mcp-proxy`, which sits between an MCP client and one MCP
  server on stdio. It forwards a `tools/call` only when the guard returns
  `Allow`, passes the read-only session messages a client needs
  (`initialize`, `ping`, `tools/list` and two notifications), and blocks
  everything else.

Not in this release: key ratcheting, operator countersignatures of the log
head, numeric limits, and any hardware or vehicle control.

## How it works

`guard.decide("action")` returns `Allow`, `NeedsApproval` or `Deny`. Unknown
actions, malformed names, internal errors and failed audit writes all come
back as `Deny`.

The policy file defines four levels, best to worst:
`connected -> degraded -> lost -> hold`. Each action gets a decision per
level, and the file won't load unless every action satisfies
`connected >= degraded >= lost >= hold` (with `deny < needs_approval < allow`).
That's what guarantees losing contact can't add a permission. A policy can
still allow an action at every level, including `hold`, if that's what the
author wants.

The contact timer runs on monotonic time, so changing the wall clock can't
make the agent look more connected. It steps down on schedule and never
steps up by itself, even if the clock goes backwards. `guard.tick()`
re-checks the level and logs any step-down; every `decide` call does the
same. The guard starts in `hold` on every start and restart and stays there
until it gets fresh verified contact.

The only way back up is `guard.apply_signed_approval(&msg)`. The message has
to be signed with Ed25519 (strict verification) by a pinned human key, carry
the `terminal-guard/contact/v1` domain and this engine's ID, use a sequence
number higher than any accepted before, and have a timestamp inside the
policy's freshness window. An older message counts as already that old, so
it buys less time. Replays, stale or future-dated messages, the wrong
engine, the wrong domain and the wrong key are rejected and logged.

The audit log has one JSON line per entry. Each entry records the contact
level at that moment, a SHA-256 link to the previous entry and an Ed25519
signature from a separate audit key. The hash and signature cover a
canonical, versioned, length-prefixed binary encoding of the entry, not the
JSON text, so they don't depend on how the JSON happens to be formatted.

After each entry the guard rewrites a small signed checkpoint (`log_id`,
`count`, `head`). `terminal-guard verify` checks the genesis link, the
sequence numbers, every signature and link, and that the log ends exactly
at the checkpoint's count and head. A missing checkpoint is a failure.

## Quick start

```sh
cargo test                                                      # fast suite
cargo test --test integration_loopback -- --ignored             # real-time, multi-process (~11 s)
cargo run --example demo
cargo run --bin terminal-guard -- verify \
  --log demo-out/audit.log \
  --checkpoint demo-out/audit.checkpoint \
  --audit-pubkey demo-out/audit.pub \
  --log-id demo-agent-01
cargo run --bin terminal-guard -- check-policy policies/example.toml
```

`verify` exits 0 when the log checks out, 1 when it doesn't and 2 on bad
usage. Add `--prefix` to verify against an older checkpoint you kept
elsewhere. The log can have grown since then, but it still has to contain
that checkpoint.

## Demo

`cargo run --example demo` walks a mock agent through a lost link using a
mock clock. It exercises the policy logic; it isn't evidence from unplugging
a real network. The actions are harmless local stand-ins: read a local
fixture, draft a local note, send an external message, delete a local file.
Keys are made fresh in memory on each run and private keys are never
written.

The example policy is built into the demo, so it works from any folder.
Output goes to `demo-out/` under the folder you start it from (git ignores
it inside the repo), or to the folder you give with `--out DIR`. The demo
only writes `audit.log`, `audit.checkpoint` and `audit.pub`. It refuses a
folder that holds anything else, so it can't wipe files you care about.

Cargo needs to find the project, so outside the repo pass `--manifest-path`:

```sh
cargo run --manifest-path /path/to/terminal-guard/Cargo.toml --example demo
cargo run --manifest-path /path/to/terminal-guard/Cargo.toml --bin terminal-guard -- verify \
  --log demo-out/audit.log --checkpoint demo-out/audit.checkpoint \
  --audit-pubkey demo-out/audit.pub --log-id demo-agent-01
```

Built binaries work from anywhere too. After `cargo build --examples`, run
`target/debug/examples/demo` and `target/debug/terminal-guard verify ...`
from whatever folder you like. The demo prints the absolute paths to use.

Part of the output:

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

The crate isn't on crates.io. For now, add it as a git dependency:

```toml
terminal-guard = { git = "https://github.com/nsulewsky1/terminal-guard" }
```

The core API:

| Call | What it does |
| --- | --- |
| `Guard::new(policy, engine_id, human_keys, next_sequence, audit_log, clock)` | Start a guard. Always starts in `hold`. |
| `guard.decide(action)` | `Allow`, `NeedsApproval` or `Deny`. Logged. |
| `guard.tick()` | Re-evaluate the contact level from the clock; log any step-down. Never improves it. |
| `guard.apply_signed_approval(&msg)` | Contact renewal: restores `connected` only if the signed message passes every check. |
| `guard.decide_with_approval(action, &approval)` | Like `decide`, but a valid one-time approval turns `NeedsApproval` into `Allow` once. `Deny` and `Allow` pass through unchanged and the approval isn't used up. |
| `verify_log(...)` / `terminal-guard verify` | Check a log against a signed checkpoint and a pinned audit key. |

`check` and `accept_contact` still work as older names for `decide` and
`apply_signed_approval`.

There's a complete embedding example in the crate docs (`src/lib.rs`), and
`cargo test --doc` compiles and runs it. The short version:

```rust,ignore
let mut guard = Guard::new(policy, "agent-01", vec![operator_key], next_seq, audit, SystemClock::new())?;
let _ = guard.accept_contact_json(&incoming); // operator renewal, if any arrived
match guard.decide("send_external_message") {
    Decision::Allow => { /* the caller performs the action */ }
    Decision::NeedsApproval => { /* the caller must get a human approval for this action first */ }
    Decision::Deny => { /* do not act */ }
}
```

Operators sign renewals with `ContactAuth::new(engine_id, sequence, unix_ms).sign(&key)`.
How you store keys and deliver renewal messages is up to you.

### What "signed approval" means here

There are two signed messages, and they can't stand in for each other.

`apply_signed_approval` renews the agent's contact level. Despite the name,
it doesn't approve any specific action, and it doesn't change what the
policy allows at `connected`.

`decide_with_approval` takes a one-time action approval, signed with a
trusted human key: `ActionApproval::new(engine_id, action, id, unix_ms).sign(&key)`.
The signed bytes are length-prefixed and carry their own magic, version and
domain string, separate from contact messages and audit entries. The guard
checks the domain, engine id, action name, signature (strict Ed25519), that
the id is unused, and that the timestamp is within the policy's contact
freshness window (`max_age_secs`, `max_future_skew_secs`). That window is
the only expiry. A used id is recorded in the audit log, so it stays used
after a restart as long as the same log is reopened. Rejected approvals are
logged with a reason and aren't used up. An approval doesn't change the
contact level.

The approval names an action, not its arguments. An approval for
`send_external_message` lets one call of that action through, whatever it
sends.

In both cases a valid signature shows that a trusted key signed a
fresh message for this engine. It doesn't show that a person was physically
present or reviewed anything.

### Current limitations

`tick()` takes no `now` argument. Time comes from the `Clock` you pass to
`Guard::new`: `MockClock` for deterministic tests, `SystemClock` for real
use. A per-call `now` would let a caller freeze or rewind time and stop the
decay, so the API doesn't offer one.

The audit log is required and file-based. `Guard::new` needs an `AuditLog`
backed by a log file and a checkpoint file, and both are written on every
entry. There's no in-memory or custom log sink yet, and the checkpoint
isn't optional.

Renewal freshness uses the host's wall clock, so the core is only fully
deterministic with `MockClock`.

It's not on crates.io, so there's no version line to copy yet; use the git
dependency above.

Every decision fsyncs two files. That's fine at the pace an agent takes
actions, but it isn't built for high call rates.

[ROADMAP.md](ROADMAP.md) lists what's planned. None of it exists yet.

## MCP proxy

`terminal-guard mcp-proxy` starts one MCP server as a child process and sits
between it and an MCP client, on stdio, using the MCP stdio framing (one
JSON-RPC message per line). It doesn't open any network port.

```sh
terminal-guard mcp-proxy --policy policy.toml --engine-id agent-01 \
  --log audit.log --checkpoint audit.checkpoint --create \
  --audit-key-file audit.seed --human-pubkey-file operator.pub \
  --contact-file contact.json [--timeout-secs 60] \
  -- /path/to/mcp-server --its --args
```

What it does with each client message:

| Message | What happens |
| --- | --- |
| `tools/call` with an id | Guard decision on the tool name. Forwarded only on `Allow`, with `_terminal_guard_approval` removed from the params. `Deny` gets error -32002 and `NeedsApproval` gets -32001; neither reaches the server. |
| `tools/call` with an approval | A signed approval under `params._terminal_guard_approval` can turn one `NeedsApproval` into `Allow`. It never changes `Deny`. |
| `initialize`, `ping`, `tools/list` | Passed through unchanged, without a guard decision. They don't run a tool. |
| `notifications/initialized`, `notifications/cancelled` | Passed through. |
| Anything else (other methods, `tools/call` notifications, batches, wrong `jsonrpc` version, bad JSON) | Not forwarded. Requests get an error; notifications and responses are dropped. |

On the way back, only a response whose id matches the forwarded request is
passed to the client. Server notifications are passed along. Requests from
the server (for example sampling) are answered with an error and not
passed to the client. If the server sends a response with another id,
sends something that isn't JSON-RPC, exits, or doesn't answer within
`--timeout-secs`, the client gets error -32003 for its request and the
proxy exits. A client message over 1 MiB also stops the proxy.

Limits worth knowing:

* Contact comes from one `--contact-file` read at startup. There's no live
  renewal channel yet, so after the policy's thresholds pass the proxy
  steps down to `hold` and stays there until it's restarted with a fresh
  contact message.
* `tools/list` isn't filtered by policy, so the client sees tools it may
  not be allowed to call.
* Resources, prompts, completions and other MCP features are blocked
  rather than reviewed one by one. Servers that depend on them won't work
  through the proxy.
* Requests are handled one at a time, and server notifications are only
  relayed while a request is waiting for its response.
* `--audit-key-file` is the audit private key, stored in a file as 64 hex
  characters. Keep it readable only by the account that runs the proxy.
* It has only been tested against the stand-in server in `src/bin/mcp_echo.rs`,
  not against real MCP clients or servers.

## Security boundary

The library decides; it doesn't enforce. Your code has to actually refuse a
denied action. It doesn't intercept network traffic or system calls. The
only enforcement is the optional MCP proxy, and only for tool calls that go
through it.

`NeedsApproval` isn't permission by itself. `decide` never accepts an
approval. `decide_with_approval` accepts one, for one use of that action
name, and only when the policy already says `needs_approval` at the current
level. If the log is lost or replaced with a fresh one, the record of used
approval ids is lost with it, and an approval that's still fresh could be
used again.

Human contact keys and the audit key are separate roles, and the guard
won't start if the audit key is also a trusted human key. Whoever verifies
a log has to get the audit public key from a trusted source, never from the
log or checkpoint.

Deleting the newest entry is caught only when you verify against the
trusted latest checkpoint. If someone rolls back the log and the checkpoint
together to an earlier matching pair, checking those two files can't detect
it. Copy checkpoints somewhere the agent host can't rewrite, and verify
against that copy with `--prefix`.

If the process dies after appending an entry but before rewriting the
checkpoint, verification fails because there's one extra entry. That fails
closed, and someone has to look at it.

When the guard is built on a log reopened with `AuditLog::open`, it won't
accept any renewal sequence already recorded in that log, even if you pass
a lower `next_contact_sequence`. If the log is lost or replaced with a fresh
one, that floor is gone, and a captured message that's still fresh can be
accepted once.

Freshness compares the message timestamp to the host clock, so a host with
the wrong time can accept or reject contact wrongly. Contact age itself uses
monotonic time. If the wall clock can't be read at all, `decide` returns
`Deny`.

Only one writer should use a given log. `AuditLog` takes a non-blocking
exclusive lock on the log file (`flock` on Unix, through the `fs4` crate)
and holds it until the value is dropped. A second open of the same log gets
`AuditError::Locked`. The lock is advisory: it stops other terminal-guard
writers, not a process that ignores it. The file-length and file-identity
checks before each append still stop the guard if the file changes or is
replaced underneath it. A user who can delete the files can still replace
the log and the checkpoint together. Copy checkpoints somewhere the agent
host can't rewrite.

If a human key or the audit signing key is stolen, there are no guarantees.

This is an experimental open-source library with no certification,
independent audit or deployment history. [THREAT_MODEL.md](THREAT_MODEL.md) lists the
assumptions and gaps in one place, and
[DIFFERENTIATION.md](DIFFERENTIATION.md) compares it with related projects.

## Layout

```text
src/policy.rs    policy file, levels, decisions, validation
src/contact.rs   contact timer, signed contact messages, anti-replay
src/audit.rs     audit log, checkpoint, verification
src/guard.rs     the engine that ties them together
src/clock.rs     real and mock clocks
src/keys.rs      key helpers
src/approval.rs  one-time action approvals
src/mcp.rs       MCP proxy message rules and stdio framing
src/bin/terminal-guard.rs   verify / check-policy / mcp-proxy / hold-lock CLI
src/bin/mcp_echo.rs         stand-in MCP server used by the proxy tests
examples/demo.rs            simulated lost-link demo
tests/                      API, unit, tamper and property tests;
                            integration_loopback.rs = multi-process loopback suite
.github/workflows/tests.yml GitHub test run (stable and Rust 1.85.1)
TESTING.md                  how to run the tests and what they show
THREAT_MODEL.md             assumptions, defenses and gaps
DIFFERENTIATION.md          related work and what this adds
ROADMAP.md                  planned work (not yet built)
CHANGELOG.md                what changed in each version
policies/example.toml       example policy
```

## Dependencies

`ed25519-dalek` for signatures, `sha2` for hashing, `serde`, `serde_json`
and `toml` for parsing, `fs4` for the file lock, and `proptest` for
property tests. There's no custom
cryptography. Minimum Rust version: 1.85.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) or
<https://www.apache.org/licenses/LICENSE-2.0>.
