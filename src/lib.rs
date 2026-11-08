//! # terminal-guard
//!
//! A small, fail-closed policy engine for AI agents that lose contact with
//! their human operators.
//!
//! * [`Guard::check`] maps an action name to [`Decision::Allow`],
//!   [`Decision::NeedsApproval`] or [`Decision::Deny`]. Any error, unknown
//!   action or malformed input yields `Deny`.
//! * Permissions are set per [`ContactLevel`] in a policy file. Levels only get
//!   more restrictive as time since the last verified human contact grows.
//! * Only a fresh, correctly bound, Ed25519-signed [`SignedContact`] from a
//!   pinned human key moves the level back to `Connected`.
//! * Every decision is written to a signed, SHA-256 hash-chained audit log
//!   with the contact level in every entry, plus a small signed checkpoint
//!   that the `terminal-guard verify` command checks.
//!
//! This crate makes policy decisions only. The caller must enforce them.
//! `NeedsApproval` is not permission to act. See the README for the full
//! security boundary.

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
