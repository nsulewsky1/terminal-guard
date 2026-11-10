# Testing

There are two sets of tests. The fast set covers unit, tamper, property and
doc tests, plus the approval, file-lock and MCP proxy tests. Most of it uses
a mock clock in a single process with no sockets, so it's deterministic and
worth running on every change. The lock and proxy tests start child
processes of the crate's own binaries and talk to them over pipes; none of
them opens a network port.

The integration set runs separate OS processes over a real loopback TCP
channel, using the real monotonic clock and a test policy measured in
seconds. Those tests are marked `#[ignore]` to keep the fast set fast, so
you run them with `--ignored`.

## Commands

| What | Command | Typical time* |
| --- | --- | --- |
| Fast suite (80 tests; 4 integration tests listed as ignored) | `cargo test --locked` | ~8 s |
| Integration suite | `cargo test --locked --test integration_loopback -- --ignored` | ~11 s |
| Integration, with step log | `cargo test --locked --test integration_loopback -- --ignored --nocapture` | ~11 s |
| Everything (84 tests) | `cargo test --locked -- --include-ignored` | ~19 s |
| Format | `cargo fmt --check` | <1 s |
| Lint | `cargo clippy --all-targets --all-features --locked -- -D warnings` | a few s |
| Examples build | `cargo check --examples --all-features --locked` | a few s |
| Demo | `cargo run --example demo` (outside the repo, add `--manifest-path /path/to/terminal-guard/Cargo.toml`) | <1 s |

\*Measured after a build on the development machine (Linux x86_64,
rustc 1.99.1). First builds take longer. The full suite also passes on
rustc 1.85.1, the minimum supported version.

`tests/regressions.rs` holds tests for defects found in review: a renewal
accepted at the edge of its freshness window must log the level it really
produced, a missing wall clock must deny, a reopened log must keep its
replay floor even if the caller passes a lower one, a log for another engine
is refused, an outside change to the log stops the guard, and oversized
files are refused before they're read.

`tests/demo.rs` runs the demo into a temporary folder, checks its built-in
policy matches `policies/example.toml`, verifies the output with the real
`terminal-guard verify` binary started from an unrelated folder, and checks
that the demo refuses a folder holding other files.

0.2.0 tests:

- `tests/approvals.rs`: an approval turns one `NeedsApproval` into `Allow`;
  it can't change `Deny` and isn't used up by `Deny` or `Allow`; the wrong
  action, a bad signature, stale and future-dated approvals are refused;
  a used id is refused after the log is reopened.
- `tests/approval_probes.rs` (written in review): approvals for another
  engine or domain are refused and logged; contact and approval signatures
  can't be swapped; an approval doesn't renew contact; `hold` and a missing
  wall clock deny without using the approval up; edited bodies, a
  malleated signature (S + L), an untrusted key, id `u64::MAX`, unknown
  fields and oversized input are refused; an audit failure stops the guard
  and records nothing as approved.
- `tests/file_lock.rs`: a second process can't open a locked log, and
  neither can a second `AuditLog` in the same process.
- `tests/mcp.rs`: stdio framing and its size limit; which messages are
  forwarded or blocked; strict checks on what comes back. Against the real
  `mcp-proxy` command and the `mcp_echo` stand-in server: `initialize` and
  `tools/list` get through, a denied, unapproved, replayed or other-method
  message never reaches the server (checked with a message counter), the
  approval field is stripped, server notifications are relayed and server
  requests are refused, and a spoofed response id, garbage, a crash, a hang
  or an oversized client message stops the proxy with an error.

## What the integration suite does

The test process is both the harness and the supervisor. It starts its own
test binary again as a mock agent process (`agent_process_entry`). That
entry point does nothing unless the harness sets `TG_IT_AGENT=1`, so in a
normal run it just reports `ok`.

The mock agent owns a `Guard` running on `SystemClock`. It listens on
`127.0.0.1`, on a random free port, for signed renewals sent as one JSON
line each, and replies `OK level=...` or `ERR <code>`. It takes `STATUS`,
`DO <action>` and `QUIT` on stdin. It checks the decision before running a
harmless local action (read a fixture file, append a draft note, delete a
scratch file), and it never runs a `needs_approval` action.
`send_external_message` would only append to a local outbox file, and the
tests confirm that file never gets written.

The test policy steps down to degraded at 3 s, lost at 6 s and hold at 9 s,
and renewals are valid for 3 s.

`lifecycle_disconnect_decay_reconnect_restore` (about 11 s) starts the
agent in hold and sends a fresh signed renewal, which brings it to
`connected`. Then it shuts the supervisor socket down and watches the level
step to degraded, lost and hold on schedule, checking that no permission
widens along the way. Reconnecting the socket on its own changes nothing.
The agent rejects eight bad renewals: replayed, stale, future-dated, signed
with the wrong key, signed with the audit key, addressed to the wrong
engine, edited after signing, and not JSON at all. A new fresh renewal
restores `connected`, and `needs_approval` actions still don't run. At the
end the log passes `terminal-guard verify` and records each step-down.

`restart_recovers_replay_floor_from_verified_log` (about 1 s) kills the
agent and starts it again. On restart it verifies its log, restores the
replay floor, starts in hold, and rejects a renewal that's already been used
even though it's still fresh. A control run without the old log accepts
that same message. That's the documented caveat: the replay floor is only
as good as the log you keep.

`log_tampering_vs_retained_checkpoint` (about 1 s) deletes, edits and
truncates the newest log entry, and each version fails against a retained
copy of the latest checkpoint. A wrong pinned key fails too, and the agent
refuses to restart on a tampered log. The test also shows the known limit:
if the log and checkpoint are rolled back together to an earlier pair, a
check of those two files passes. Only the separately kept latest checkpoint
catches it.

Logs, checkpoints, public keys and fixture files stay under
`target/tmp/tg-integration/<test>-<pid>-<time>/` so you can look at them.
`target/` is git-ignored. Clear them with `rm -rf target/tmp/tg-integration`.

Keys are generated for each run. The audit signing key reaches the agent
process through an environment variable and is never written to disk. On a
shared machine, other processes running as the same user could read it
while a test runs.

Every wait times out after 15 s with a clear error, and agent processes are
killed when a test ends or fails.

## What these tests show, and what they don't

They show how the guard behaves across real processes, with a socket that's
actually closed and reopened, real elapsed time, real file I/O and a real
process kill and restart. All of it happens on one machine.

They don't show behavior during a physical network unplug, a partition
between separate hosts, a radio link, or with a real agent or language
model. By design, the socket being up or down doesn't affect the guard. Only
time and signed renewals do.

## CI

`.github/workflows/tests.yml` runs on every push to `main` and every pull
request. It has read-only access to the repo and uses no secrets. One job
on stable Rust runs `cargo fmt --check`, clippy on all targets and features
with warnings as errors, `cargo check --examples`, the full suite including
the loopback tests, `cargo doc` with warnings as errors, and the demo
started from a temporary folder followed by `verify`. A second job runs
`cargo check --examples` and the full suite on Rust 1.85.1. The only outside action is
`actions/checkout`, pinned to a full commit SHA. Rust is installed with the
runner's own `rustup`.

The badge at the top of the README shows the latest result of that
workflow on `main`. It isn't a fixed image.
