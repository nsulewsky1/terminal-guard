//! One-time approvals for a specific action.
//!
//! A signed approval can turn a single `NeedsApproval` decision into `Allow`.
//! It cannot turn `Deny` into anything else, and it cannot be used twice.
//! Contact renewal ([`crate::SignedContact`]) is a different message and is
//! not an action approval.

use std::collections::BTreeSet;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::encode::{Enc, valid_ident};
use crate::policy::Policy;

/// Domain string bound into every action approval.
pub const APPROVAL_DOMAIN: &str = "terminal-guard/action-approval/v1";
const APPROVAL_MAGIC: &[u8; 4] = b"TGAA";
const APPROVAL_VERSION: u8 = 1;

/// The signed body of a one-time action approval.
///
/// `id` is an engine-wide nonce. Any unused id is acceptable; it does not
/// have to increase. After a successful use the id is dead forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionApproval {
    pub domain: String,
    pub engine_id: String,
    pub action: String,
    pub id: u64,
    pub issued_unix_ms: u64,
}

impl ActionApproval {
    pub fn new(engine_id: &str, action: &str, id: u64, issued_unix_ms: u64) -> Self {
        ActionApproval {
            domain: APPROVAL_DOMAIN.to_string(),
            engine_id: engine_id.to_string(),
            action: action.to_string(),
            id,
            issued_unix_ms,
        }
    }

    /// Canonical bytes that are signed. Not a contact message: different
    /// magic, version and fields, so a contact signature cannot be reused.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Enc::new(APPROVAL_MAGIC, APPROVAL_VERSION)
            .str(&self.domain)
            .str(&self.engine_id)
            .str(&self.action)
            .u64(self.id)
            .u64(self.issued_unix_ms)
            .finish()
    }

    /// Sign with a human contact key (operator side).
    pub fn sign(self, key: &SigningKey) -> SignedActionApproval {
        let sig = key.sign(&self.canonical_bytes());
        SignedActionApproval {
            body: self,
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

/// An action approval plus its hex-encoded Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionApproval {
    pub body: ActionApproval,
    pub signature: String,
}

impl SignedActionApproval {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Result<Self, ApprovalError> {
        if s.len() > 4096 {
            return Err(ApprovalError::Malformed);
        }
        serde_json::from_str(s).map_err(|_| ApprovalError::Malformed)
    }

    pub fn from_value(v: &serde_json::Value) -> Result<Self, ApprovalError> {
        if v.to_string().len() > 4096 {
            return Err(ApprovalError::Malformed);
        }
        serde_json::from_value(v.clone()).map_err(|_| ApprovalError::Malformed)
    }

    /// Check the approval without recording it as used.
    ///
    /// `action` is the action the caller wants to run. It must be the action
    /// named in the signed body. `used` is the set of ids already consumed.
    pub fn verify(
        &self,
        engine_id: &str,
        action: &str,
        keys: &[VerifyingKey],
        policy: &Policy,
        clock: &dyn Clock,
        used: &BTreeSet<u64>,
    ) -> Result<u64, ApprovalError> {
        let body = &self.body;
        if body.domain != APPROVAL_DOMAIN {
            return Err(ApprovalError::WrongDomain);
        }
        if !valid_ident(&body.engine_id) || !valid_ident(&body.action) {
            return Err(ApprovalError::Malformed);
        }
        if body.engine_id != engine_id {
            return Err(ApprovalError::WrongEngine);
        }
        if body.action != action {
            return Err(ApprovalError::WrongAction);
        }
        if body.id == u64::MAX {
            return Err(ApprovalError::Malformed);
        }
        let mut sig = [0u8; 64];
        hex::decode_to_slice(&self.signature, &mut sig).map_err(|_| ApprovalError::Malformed)?;
        let sig = Signature::from_bytes(&sig);
        let bytes = body.canonical_bytes();
        let signed_by_trusted = keys.iter().any(|k| k.verify_strict(&bytes, &sig).is_ok());
        if !signed_by_trusted {
            return Err(ApprovalError::BadSignature);
        }
        if used.contains(&body.id) {
            return Err(ApprovalError::Replay);
        }
        let now_ms = clock.unix_ms().ok_or(ApprovalError::NoWallClock)?;
        let window = policy.contact_window();
        let skew_ms = window.max_future_skew_secs.saturating_mul(1000);
        if body.issued_unix_ms > now_ms.saturating_add(skew_ms) {
            return Err(ApprovalError::FromFuture);
        }
        let age_ms = now_ms.saturating_sub(body.issued_unix_ms);
        if age_ms > window.max_age_secs.saturating_mul(1000) {
            return Err(ApprovalError::Stale);
        }
        Ok(body.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    Malformed,
    WrongDomain,
    WrongEngine,
    WrongAction,
    BadSignature,
    Replay,
    Stale,
    FromFuture,
    NoWallClock,
    /// Audit logging failed, so the approval was not consumed.
    AuditFailed,
}

impl ApprovalError {
    /// Short fixed code written to the audit log.
    pub fn code(self) -> &'static str {
        match self {
            ApprovalError::Malformed => "malformed",
            ApprovalError::WrongDomain => "wrong_domain",
            ApprovalError::WrongEngine => "wrong_engine",
            ApprovalError::WrongAction => "wrong_action",
            ApprovalError::BadSignature => "bad_signature",
            ApprovalError::Replay => "replay",
            ApprovalError::Stale => "stale",
            ApprovalError::FromFuture => "from_future",
            ApprovalError::NoWallClock => "no_wall_clock",
            ApprovalError::AuditFailed => "audit_failed",
        }
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "action approval rejected: {}", self.code())
    }
}

impl std::error::Error for ApprovalError {}
