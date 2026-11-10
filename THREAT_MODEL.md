# Threat model

This is a short statement of what terminal-guard assumes, what it defends
against, and what it doesn't. It describes version 0.2.0.

## What it's for

An agent process calls `decide(action)` before doing things. terminal-guard
answers from a policy table and the current contact level, which drops as
time passes without a verified renewal. It writes every decision to a signed
log. It does not run actions, intercept anything, or stop the agent; the
calling code does that.

## Assumptions

- The calling code enforces decisions and treats `needs_approval` as "don't
  do this yet". If the agent can skip the call or ignore the answer,
  terminal-guard can't help.
- The agent host's monotonic clock moves forward. If it goes backwards the
  guard drops to `hold`, but a clock that stalls would stop the decay.
- The host's wall clock is roughly right. It's only used to judge whether a
  renewal is fresh and to timestamp log entries. If it's unavailable,
  decisions are denied.
- Human contact private keys and the audit signing key stay secret. If any
  of them leak, there are no guarantees.
- Only one process writes a given log. `AuditLog` holds an exclusive
  non-blocking `flock` for its lifetime, so a second process cannot open
  that log. The lock is per process. The file-length check still stops the
  writer if the file changes underneath it. Neither stops a privileged
  user from deleting both files.

## What it defends against

- Permission drift during lost contact: the level steps down on schedule,
  never steps up on its own, and the policy can't grant more at a worse
  level.
- Restoring access without a person's key: reconnecting, replaying an old
  renewal, sending one signed by the wrong key (including the audit key),
  for the wrong engine, edited after signing, stale or future-dated are all
  rejected and logged.
- Restart as a way back in: the guard always starts in `hold`, and when it
  reopens a verified log it won't accept any renewal sequence already
  recorded there, whatever the caller passes in.
- Editing or deleting log entries, including the newest, when you verify
  against the trusted latest checkpoint and a pinned audit public key.
- Oversized or malformed inputs: policy files, checkpoints, logs and renewal
  messages have size limits and strict parsing, and any error ends in a
  denial.

## What it doesn't defend against

- Rolling the log and checkpoint back together to an earlier matching pair.
  Checking those two files can't detect it. Keep checkpoints somewhere the
  agent host can't rewrite and verify against them with `--prefix`.
- A lost or replaced log. A fresh log has no replay floor, so a captured,
  still-fresh renewal that was already used elsewhere can be accepted once.
- Someone who controls the agent host: they can change the code, the clock,
  the keys or the files.
- A captured renewal that was never delivered. If an attacker holds back a
  valid message and delivers it while it's still fresh, it works, because it
  is a valid message. Short freshness windows limit this.
- Proof that a person was present. A signature shows a trusted key signed a
  fresh message, nothing more.
- Anything outside the decision: network traffic, tool calls, model output.

## Known gaps

- The audit log and checkpoint are files and are required. There's no
  in-memory or remote log option yet.
- Two files are fsynced on every decision. No throughput measurements have
  been made.
- No independent security review has been done.
- Integration tests run two processes on one machine over loopback. They
  aren't evidence about physical network loss or separate hosts.
