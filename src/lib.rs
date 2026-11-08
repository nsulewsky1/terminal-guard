//! # terminal-guard
//!
//! A small, fail-closed policy engine for AI agents that lose contact with
//! the people supervising them. No daemon and no network calls: it is a
//! library you call in-process.
//!
//! * [`Guard::decide`] maps an action name to [`Decision::Allow`],
//!   [`Decision::NeedsApproval`] or [`Decision::Deny`]. Any error, unknown
//!   action or malformed input yields `Deny`.
//! * Permissions are set per [`ContactLevel`] in a policy file. Levels only get
//!   more restrictive as time since the last verified human contact grows
//!   ([`Guard::tick`] or any `decide` call re-evaluates them).
//! * Only a new, correctly bound, Ed25519-signed [`SignedContact`] from a
//!   pinned human key, passed to [`Guard::apply_signed_approval`], moves the
//!   level back to `Connected`. Reconnecting alone does nothing.
//! * Every decision is written to a signed, SHA-256 hash-chained audit log
//!   with the contact level in every entry, plus a small signed checkpoint
//!   that [`verify_log`] and the `terminal-guard verify` command check.
//!
//! ## Minimal embedding
//!
//! ```
//! use std::time::Duration;
//! use terminal_guard::keys::generate;
//! use terminal_guard::{AuditLog, Clock, ContactAuth, Decision, Guard, MockClock, Policy};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = Policy::from_toml(r#"
//!     version = 1
//!     [levels]
//!     degraded_after_secs = 600
//!     lost_after_secs = 3600
//!     hold_after_secs = 14400
//!     [contact]
//!     max_age_secs = 120
//!     max_future_skew_secs = 30
//!     [actions.draft_local_note]
//!     connected = "allow"
//!     degraded = "allow"
//!     lost = "needs_approval"
//!     hold = "deny"
//! "#)?;
//!
//! // Two separate key roles. Real deployments load these from storage.
//! let operator = generate();
//! let audit_key = generate();
//!
//! // The audit log is file-based today (log + checkpoint are required).
//! let dir = std::env::temp_dir().join(format!("tg-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&dir)?;
//! let _ = std::fs::remove_file(dir.join("a.log"));
//! let _ = std::fs::remove_file(dir.join("a.cp"));
//! let audit = AuditLog::create(&dir.join("a.log"), &dir.join("a.cp"), "agent-01", audit_key)?;
//!
//! // MockClock for a deterministic example; use SystemClock::new() for real.
//! let clock = MockClock::new(1_800_000_000_000);
//! let mut guard = Guard::new(policy, "agent-01", vec![operator.verifying_key()], 0, audit, clock.clone())?;
//!
//! // Starts in hold: nothing allowed until a fresh signed contact arrives.
//! assert_eq!(guard.decide("draft_local_note"), Decision::Deny);
//!
//! let renewal = ContactAuth::new("agent-01", 1, clock.unix_ms().unwrap()).sign(&operator);
//! guard.apply_signed_approval(&renewal)?;
//! assert_eq!(guard.decide("draft_local_note"), Decision::Allow);
//!
//! clock.advance(Duration::from_secs(2 * 60 * 60)); // no contact for 2 h
//! guard.tick();
//! assert_eq!(guard.decide("draft_local_note"), Decision::NeedsApproval);
//! assert_eq!(guard.decide("not_in_policy"), Decision::Deny);
//! # std::fs::remove_dir_all(&dir)?;
//! # Ok(())
//! # }
//! ```
//!
//! This crate makes policy decisions only. The caller must enforce them.
//! `NeedsApproval` is not permission to act. See the README for the full
//! security boundary and current limitations.

#![forbid(unsafe_code)]

pub mod audit;
pub mod clock;
pub mod contact;
mod encode;
pub mod guard;
pub mod keys;
pub mod policy;

pub use audit::{AuditError, AuditLog, Checkpoint, VerifyMode, VerifyReport, verify_log};
pub use clock::{Clock, MockClock, SystemClock};
pub use contact::{ContactAuth, ContactError, ContactTracker, SignedContact};
pub use guard::Guard;
pub use policy::{ContactLevel, Decision, Policy, PolicyError};
