//! Contact timer and signed human contact messages.
//!
//! The tracker starts at `Hold` (no verified contact yet), steps down on the
//! policy schedule using monotonic time, and never steps back up on its own.
//! The only way up is [`ContactTracker::accept`] with a [`SignedContact`] that:
//!
//! 1. is signed (Ed25519, strict verification) by a pinned human key,
//! 2. carries this crate's contact domain and this engine's ID,
//! 3. has a sequence number strictly greater than any accepted before, and
//! 4. has a wall-clock timestamp within the policy freshness window.
//!
//! Anti-replay state (the last accepted sequence) lives in memory. After a
//! restart the caller should restore it (e.g. from the verified audit log via
//! [`crate::audit::last_contact_sequence`]); otherwise a captured message can
//! be replayed until it ages out of the freshness window.

use std::fmt;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::encode::{Enc, valid_ident};
use crate::policy::{ContactLevel, Policy};

/// Domain string bound into every contact message.
pub const CONTACT_DOMAIN: &str = "terminal-guard/contact/v1";
const CONTACT_MAGIC: &[u8; 4] = b"TGCA";
const CONTACT_VERSION: u8 = 1;

/// The signed body of a human contact message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactAuth {
    pub domain: String,
    pub engine_id: String,
    pub sequence: u64,
    pub issued_unix_ms: u64,
}

impl ContactAuth {
    pub fn new(engine_id: &str, sequence: u64, issued_unix_ms: u64) -> Self {
        ContactAuth {
            domain: CONTACT_DOMAIN.to_string(),
            engine_id: engine_id.to_string(),
            sequence,
            issued_unix_ms,
        }
    }

    /// Canonical bytes that are signed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Enc::new(CONTACT_MAGIC, CONTACT_VERSION)
            .str(&self.domain)
            .str(&self.engine_id)
            .u64(self.sequence)
            .u64(self.issued_unix_ms)
            .finish()
    }

    /// Sign with a human contact key (operator side).
    pub fn sign(self, key: &SigningKey) -> SignedContact {
        let sig = key.sign(&self.canonical_bytes());
        SignedContact {
            body: self,
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

/// A contact message plus its hex-encoded Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContact {
    pub body: ContactAuth,
    pub signature: String,
}

impl SignedContact {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
    pub fn from_json(s: &str) -> Result<Self, ContactError> {
        if s.len() > 4096 {
            return Err(ContactError::Malformed);
        }
        serde_json::from_str(s).map_err(|_| ContactError::Malformed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactError {
    Malformed,
    WrongDomain,
    WrongEngine,
    BadSignature,
    Replay,
    Stale,
    FromFuture,
    NoWallClock,
    /// Audit logging failed, so the contact was not applied.
    AuditFailed,
}

impl ContactError {
    /// Short fixed code written to the audit log.
    pub fn code(self) -> &'static str {
        match self {
            ContactError::Malformed => "malformed",
            ContactError::WrongDomain => "wrong_domain",
            ContactError::WrongEngine => "wrong_engine",
            ContactError::BadSignature => "bad_signature",
            ContactError::Replay => "replay",
            ContactError::Stale => "stale",
            ContactError::FromFuture => "from_future",
            ContactError::NoWallClock => "no_wall_clock",
            ContactError::AuditFailed => "audit_failed",
        }
    }
}

impl fmt::Display for ContactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "contact rejected: {}", self.code())
    }
}

impl std::error::Error for ContactError {}

/// A contact message that passed every check but has not been applied yet.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedContact {
    sequence: u64,
    age: Duration,
}

impl VerifiedContact {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Tracks time since last verified human contact.
#[derive(Debug, Clone)]
pub struct ContactTracker {
    engine_id: String,
    human_keys: Vec<VerifyingKey>,
    /// Monotonic time a verified contact was applied, plus the message's age
    /// at that moment (counted as time already elapsed).
    last_contact: Option<(Duration, Duration)>,
    /// Worst level observed since last contact. Levels never improve without
    /// a verified contact, even if the clock misbehaves.
    floor: ContactLevel,
    /// Next acceptable sequence number (anti-replay).
    next_sequence: u64,
}

impl ContactTracker {
    /// New tracker. Starts at `Hold` until fresh verified contact.
    /// `next_sequence` is the smallest sequence that will be accepted; pass a
    /// persisted value after a restart.
    pub fn new(engine_id: &str, human_keys: Vec<VerifyingKey>, next_sequence: u64) -> Self {
        ContactTracker {
            engine_id: engine_id.to_string(),
            human_keys,
            last_contact: None,
            floor: ContactLevel::Hold,
            next_sequence,
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub(crate) fn engine_id(&self) -> &str {
        &self.engine_id
    }

    pub(crate) fn human_keys(&self) -> &[VerifyingKey] {
        &self.human_keys
    }

    /// Current level. Never improves without [`Self::apply`].
    pub fn level(&mut self, policy: &Policy, clock: &dyn Clock) -> ContactLevel {
        let now = clock.monotonic();
        let computed = match self.last_contact {
            None => ContactLevel::Hold,
            Some((t, _)) if now < t => ContactLevel::Hold, // clock went backwards: fail closed
            Some((t, age)) => policy.schedule().level_for((now - t).saturating_add(age)),
        };
        self.floor = self.floor.max(computed);
        self.floor
    }

    /// Check a contact message without changing state.
    pub fn verify(
        &self,
        msg: &SignedContact,
        policy: &Policy,
        clock: &dyn Clock,
    ) -> Result<VerifiedContact, ContactError> {
        let body = &msg.body;
        if body.domain != CONTACT_DOMAIN {
            return Err(ContactError::WrongDomain);
        }
        if !valid_ident(&body.engine_id) {
            return Err(ContactError::Malformed);
        }
        if body.engine_id != self.engine_id {
            return Err(ContactError::WrongEngine);
        }
        let mut sig = [0u8; 64];
        hex::decode_to_slice(&msg.signature, &mut sig).map_err(|_| ContactError::Malformed)?;
        let sig = Signature::from_bytes(&sig);
        let bytes = body.canonical_bytes();
        let signed_by_trusted = self
            .human_keys
            .iter()
            .any(|k| k.verify_strict(&bytes, &sig).is_ok());
        if !signed_by_trusted {
            return Err(ContactError::BadSignature);
        }
        if body.sequence == u64::MAX {
            return Err(ContactError::Malformed);
        }
        if body.sequence < self.next_sequence {
            return Err(ContactError::Replay);
        }
        let now_ms = clock.unix_ms().ok_or(ContactError::NoWallClock)?;
        let window = policy.contact_window();
        let skew_ms = window.max_future_skew_secs.saturating_mul(1000);
        if body.issued_unix_ms > now_ms.saturating_add(skew_ms) {
            return Err(ContactError::FromFuture);
        }
        let age_ms = now_ms.saturating_sub(body.issued_unix_ms);
        if age_ms > window.max_age_secs.saturating_mul(1000) {
            return Err(ContactError::Stale);
        }
        Ok(VerifiedContact {
            sequence: body.sequence,
            age: Duration::from_millis(age_ms),
        })
    }

    /// Apply a verified contact: level returns to `Connected`, backdated by
    /// the message's age so an old message buys less time.
    pub fn apply(&mut self, v: VerifiedContact, clock: &dyn Clock) {
        let now = clock.monotonic();
        self.last_contact = Some((now, v.age));
        self.floor = ContactLevel::Connected;
        self.next_sequence = v.sequence.saturating_add(1);
    }

    /// Verify and apply in one step.
    pub fn accept(
        &mut self,
        msg: &SignedContact,
        policy: &Policy,
        clock: &dyn Clock,
    ) -> Result<(), ContactError> {
        let v = self.verify(msg, policy, clock)?;
        self.apply(v, clock);
        Ok(())
    }
}
