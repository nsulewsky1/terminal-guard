//! The engine: policy + contact tracker + audit log.

use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::audit::{AuditError, AuditLog, EntryKind, INVALID_ACTION};
use crate::clock::Clock;
use crate::contact::{ContactError, ContactTracker, SignedContact};
use crate::encode::valid_ident;
use crate::policy::{ContactLevel, Decision, Policy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    InvalidEngineId,
    NoHumanKeys,
    /// The audit key must not also be a trusted human contact key.
    KeyRoleConflict,
    Audit(AuditError),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::InvalidEngineId => write!(f, "invalid engine id"),
            GuardError::NoHumanKeys => write!(f, "at least one human contact key is required"),
            GuardError::KeyRoleConflict => {
                write!(f, "audit key must not also be a human contact key")
            }
            GuardError::Audit(e) => write!(f, "audit: {e}"),
        }
    }
}

impl std::error::Error for GuardError {}

/// Fail-closed policy engine for one agent.
///
/// Once any audit write fails, the guard is *poisoned* and every later
/// `check` returns `Deny` and every contact is rejected. Build a new guard to
/// recover.
pub struct Guard<C: Clock> {
    policy: Policy,
    tracker: ContactTracker,
    audit: AuditLog,
    clock: C,
    logged_level: ContactLevel,
    poisoned: bool,
}

impl<C: Clock> fmt::Debug for Guard<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guard")
            .field("logged_level", &self.logged_level)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> Guard<C> {
    /// Start a guard. It always starts at `Hold`: a restart never grants
    /// `Connected` until a fresh verified contact arrives.
    ///
    /// `next_contact_sequence` is the smallest contact sequence that will be
    /// accepted. After a restart, pass `last accepted + 1` (for example from
    /// [`crate::audit::VerifyReport::last_contact_sequence`]).
    pub fn new(
        policy: Policy,
        engine_id: &str,
        human_keys: Vec<VerifyingKey>,
        next_contact_sequence: u64,
        mut audit: AuditLog,
        clock: C,
    ) -> Result<Self, GuardError> {
        if !valid_ident(engine_id) {
            return Err(GuardError::InvalidEngineId);
        }
        if human_keys.is_empty() {
            return Err(GuardError::NoHumanKeys);
        }
        let audit_vk = audit.verifying_key();
        if human_keys
            .iter()
            .any(|k| k.as_bytes() == audit_vk.as_bytes())
        {
            return Err(GuardError::KeyRoleConflict);
        }
        audit
            .append(
                clock.unix_ms().unwrap_or(0),
                ContactLevel::Hold,
                EntryKind::Start,
            )
            .map_err(GuardError::Audit)?;
        Ok(Guard {
            policy,
            tracker: ContactTracker::new(engine_id, human_keys, next_contact_sequence),
            audit,
            clock,
            logged_level: ContactLevel::Hold,
            poisoned: false,
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Current contact level (logs a level change if there was one). Returns
    /// `Hold` if poisoned or if logging fails.
    pub fn level(&mut self) -> ContactLevel {
        match self.current_level() {
            Ok(l) => l,
            Err(_) => {
                self.poisoned = true;
                ContactLevel::Hold
            }
        }
    }

    /// Decide an action. Returns `Deny` on any error, unknown action,
    /// malformed name, poisoned guard or failed audit write.
    ///
    /// `NeedsApproval` means the caller must get a human approval out of band
    /// before acting. It is not permission.
    pub fn check(&mut self, action: &str) -> Decision {
        match self.try_check(action) {
            Ok(d) => d,
            Err(_) => {
                self.poisoned = true;
                Decision::Deny
            }
        }
    }

    fn try_check(&mut self, action: &str) -> Result<Decision, AuditError> {
        if self.poisoned {
            return Err(AuditError::Io("guard poisoned".into()));
        }
        let level = self.current_level()?;
        let decision = self.policy.decide(action, level);
        let logged_action = if valid_ident(action) {
            action.to_string()
        } else {
            INVALID_ACTION.to_string()
        };
        self.audit.append(
            self.now_ms(),
            level,
            EntryKind::Decision {
                action: logged_action,
                decision,
            },
        )?;
        Ok(decision)
    }

    /// Offer a signed human contact message. Only an accepted message moves
    /// the level back to `Connected`. Accepts and rejects are both logged; the
    /// contact is applied only after its log entry is durably written.
    pub fn accept_contact(&mut self, msg: &SignedContact) -> Result<(), ContactError> {
        if self.poisoned {
            return Err(ContactError::AuditFailed);
        }
        let verified = self.tracker.verify(msg, &self.policy, &self.clock);
        let level = match self.current_level() {
            Ok(l) => l,
            Err(_) => {
                self.poisoned = true;
                return Err(ContactError::AuditFailed);
            }
        };
        match verified {
            Ok(v) => {
                let kind = EntryKind::ContactAccepted {
                    sequence: v.sequence(),
                };
                if self
                    .audit
                    .append(self.now_ms(), ContactLevel::Connected, kind)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(ContactError::AuditFailed);
                }
                self.tracker.apply(v, &self.clock);
                // Re-read so the stored level matches what was logged.
                self.logged_level = self.tracker.level(&self.policy, &self.clock);
                Ok(())
            }
            Err(e) => {
                let kind = EntryKind::ContactRejected {
                    reason: e.code().to_string(),
                };
                if self.audit.append(self.now_ms(), level, kind).is_err() {
                    self.poisoned = true;
                }
                Err(e)
            }
        }
    }

    /// Parse a JSON contact message and offer it. Malformed input is rejected
    /// and logged.
    pub fn accept_contact_json(&mut self, json: &str) -> Result<(), ContactError> {
        match SignedContact::from_json(json) {
            Ok(m) => self.accept_contact(&m),
            Err(e) => {
                if self.poisoned {
                    return Err(ContactError::AuditFailed);
                }
                let level = self.level();
                let kind = EntryKind::ContactRejected {
                    reason: e.code().to_string(),
                };
                if self.audit.append(self.now_ms(), level, kind).is_err() {
                    self.poisoned = true;
                }
                Err(e)
            }
        }
    }

    fn current_level(&mut self) -> Result<ContactLevel, AuditError> {
        let level = self.tracker.level(&self.policy, &self.clock);
        if level != self.logged_level {
            self.audit.append(
                self.now_ms(),
                level,
                EntryKind::LevelChanged {
                    from: self.logged_level,
                    to: level,
                },
            )?;
            self.logged_level = level;
        }
        Ok(level)
    }

    fn now_ms(&self) -> u64 {
        self.clock.unix_ms().unwrap_or(0)
    }
}
