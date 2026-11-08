# Testing

There are two sets of tests. The fast set covers unit, tamper, property and
doc tests. It uses a mock clock in a single process with no sockets, so it's
deterministic and worth running on every change.

The integration set runs separate OS processes over a real loopback TCP
channel, using the real monotonic clock and a test policy measured in
seconds. Those tests are marked `#[ignore]` to keep the fast set fast, so
you run them with `--ignored`.

## Commands

| What | Command | Typical time* |
| --- | --- | --- |
| Fast suite (45 tests; 4 integration tests listed as ignored) | `cargo test --locked` | ~7 s |
| Integration suite | `cargo test --locked --test integration_loopback -- --ignored` | ~11 s |
| Integration, with step log | `cargo test --locked --test integration_loopback -- --ignored --nocapture` | ~11 s |
| Everything (49 tests) | `cargo test --locked -- --include-ignored` | ~17 s |
| Format | `cargo fmt --check` | <1 s |
| Lint | `cargo clippy --all-targets --locked -- -D warnings` | a few s |
| Demo | `cargo run --example demo` | <1 s |

\*Measured after a build on the development machine (Linux x86_64,
rustc 1.99.1). First builds take longer. The full suite also passes on
rustc 1.85.1, the minimum supported version.

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

No hosted CI is set up for this repository yet, and no GitHub checks have
run. Run the commands above locally.
