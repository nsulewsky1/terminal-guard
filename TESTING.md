# Testing

Two layers:

1. **Fast deterministic tests.** Unit, tamper, property and doc tests. Mock
   clock, single process, no sockets. Run on every change.
2. **Real-time integration tests.** Separate OS processes, a real loopback
   TCP approval channel, the real monotonic clock and a seconds-scale test
   policy. Marked `#[ignore]` so the fast suite stays fast; run them with
   `--ignored`.

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

\*Measured after a build, on the development machine (Linux x86_64,
rustc 1.99.1). First builds take longer. The full suite also passes on
rustc 1.85.1, the minimum supported version.

## What the integration suite does

The test process acts as harness and supervisor. It re-runs its own test
binary as a mock agent process (`agent_process_entry`, inactive unless the
harness sets `TG_IT_AGENT=1`; in a normal run it reports `ok` and does
nothing).

The mock agent:

- owns a `Guard` with `SystemClock`;
- listens on `127.0.0.1` on a random free port for signed renewals, one JSON
  line each, and replies `OK level=...` or `ERR <code>`;
- takes `STATUS`, `DO <action>` and `QUIT` on stdin;
- checks the decision **before** running a harmless local action (read a
  fixture file, append a draft note, delete a scratch file). `needs_approval`
  is never executed. "send_external_message" would only append to a local
  outbox file, and the tests confirm that file is never written.

Tests (test policy: degraded at 3 s, lost at 6 s, hold at 9 s, renewals valid
for 3 s):

- `lifecycle_disconnect_decay_reconnect_restore` (~11 s): starts in hold; a
  fresh signed renewal gives `connected`; the supervisor socket is shut down;
  the level steps to degraded, lost, hold on schedule with no permission ever
  widening; reconnecting the socket alone changes nothing; replayed, stale,
  future-dated, wrong-key, audit-key-signed, wrong-engine, edited and
  non-JSON renewals are rejected; a new fresh renewal restores `connected`
  while `needs_approval` actions still do not run; the log verifies with the
  `terminal-guard verify` CLI and records each step-down.
- `restart_recovers_replay_floor_from_verified_log` (~1 s): the agent is
  killed and restarted; it verifies its log, restores the replay floor,
  starts in hold and rejects the already-used but still-fresh renewal. A
  control run without the old log accepts that same message, which shows
  the documented caveat: the replay floor is only as good as the log you
  keep.
- `log_tampering_vs_retained_checkpoint` (~1 s): deleting, editing or
  truncating the newest entry fails against a retained copy of the latest
  checkpoint; a wrong pinned key fails; the agent refuses to restart on a
  tampered log. It also shows the **known limit**: rolling back the log and
  checkpoint together to an earlier pair passes a file-only check, and is
  caught only by the separately retained latest checkpoint.

Artifacts (logs, checkpoints, public keys, fixture files) are kept under
`target/tmp/tg-integration/<test>-<pid>-<time>/` for inspection. `target/` is
git-ignored. Delete with `rm -rf target/tmp/tg-integration`.

Keys are generated per run. The audit signing key is passed to the agent
process in an environment variable and is never written to disk; on a
shared machine, other processes of the same user could read it while the
test runs.

Every wait has a 15 s timeout with a clear error, and agent processes are
killed when a test ends or fails.

## Boundary: what these tests do and do not show

They show the guard's behavior across real processes, a real socket that is
really closed and reopened, real elapsed time, real file I/O and a real
process kill and restart, all on one machine.

They do **not** show behavior during a physical network unplug, a partition
between separate hosts, radio links, or any real agent or language model.
The socket being up or down does not affect the guard by design; only time
and signed renewals do.

## CI

No hosted CI is set up for this repository yet, and no GitHub checks have
run. Run the commands above locally.
