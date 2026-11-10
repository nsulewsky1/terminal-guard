//! Policy file: contact-level schedule plus per-action decisions.
//!
//! Validation guarantees that, for every action, permissions never increase
//! as contact degrades: `connected >= degraded >= lost >= hold` under the
//! ordering `Deny < NeedsApproval < Allow`. Actions not listed are denied.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::encode::valid_ident;

/// Contact levels, ordered from best to worst contact.
/// `Connected < Degraded < Lost < Hold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContactLevel {
    Connected,
    Degraded,
    Lost,
    Hold,
}

impl ContactLevel {
    pub const ALL: [ContactLevel; 4] = [
        ContactLevel::Connected,
        ContactLevel::Degraded,
        ContactLevel::Lost,
        ContactLevel::Hold,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            ContactLevel::Connected => "connected",
            ContactLevel::Degraded => "degraded",
            ContactLevel::Lost => "lost",
            ContactLevel::Hold => "hold",
        }
    }
    pub(crate) fn code(self) -> u8 {
        self as u8
    }
    pub(crate) fn from_str_strict(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s)
    }
}

impl fmt::Display for ContactLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Policy decision, ordered from least to most permissive.
/// `Deny < NeedsApproval < Allow`.
///
/// `NeedsApproval` is not permission to execute. [`crate::Guard::decide`]
/// does not take an approval. [`crate::Guard::decide_with_approval`] can
/// turn one `NeedsApproval` into `Allow` for that action, once. It cannot
/// change a `Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Deny,
    NeedsApproval,
    Allow,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Deny => "deny",
            Decision::NeedsApproval => "needs_approval",
            Decision::Allow => "allow",
        }
    }
    pub(crate) fn code(self) -> u8 {
        self as u8
    }
    pub(crate) fn from_str_strict(s: &str) -> Option<Self> {
        [Decision::Deny, Decision::NeedsApproval, Decision::Allow]
            .into_iter()
            .find(|d| d.as_str() == s)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Parse(String),
    UnsupportedVersion(u32),
    BadSchedule(String),
    BadContactWindow(String),
    BadActionName(String),
    NonMonotonic(String),
    NoActions,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Parse(e) => write!(f, "policy parse error: {e}"),
            PolicyError::UnsupportedVersion(v) => write!(f, "unsupported policy version {v}"),
            PolicyError::BadSchedule(e) => write!(f, "bad level schedule: {e}"),
            PolicyError::BadContactWindow(e) => write!(f, "bad contact window: {e}"),
            PolicyError::BadActionName(a) => write!(f, "invalid action name {a:?}"),
            PolicyError::NonMonotonic(a) => write!(
                f,
                "action {a:?} gains permission as contact degrades; require connected >= degraded >= lost >= hold"
            ),
            PolicyError::NoActions => write!(f, "policy lists no actions"),
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Seconds without verified contact before `Degraded`.
    pub degraded_after_secs: u64,
    /// Seconds without verified contact before `Lost`.
    pub lost_after_secs: u64,
    /// Seconds without verified contact before `Hold`.
    pub hold_after_secs: u64,
}

impl Schedule {
    /// Level for a given time since last verified contact.
    pub fn level_for(&self, since_contact: Duration) -> ContactLevel {
        let s = since_contact.as_secs();
        if s >= self.hold_after_secs {
            ContactLevel::Hold
        } else if s >= self.lost_after_secs {
            ContactLevel::Lost
        } else if s >= self.degraded_after_secs {
            ContactLevel::Degraded
        } else {
            ContactLevel::Connected
        }
    }
}

/// Freshness bounds for signed contact messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactWindow {
    /// Maximum age of a contact message, by its signed wall-clock timestamp.
    pub max_age_secs: u64,
    /// Maximum allowed amount a message timestamp may be in the future.
    pub max_future_skew_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRule {
    pub connected: Decision,
    pub degraded: Decision,
    pub lost: Decision,
    pub hold: Decision,
}

impl ActionRule {
    pub fn at(&self, level: ContactLevel) -> Decision {
        match level {
            ContactLevel::Connected => self.connected,
            ContactLevel::Degraded => self.degraded,
            ContactLevel::Lost => self.lost,
            ContactLevel::Hold => self.hold,
        }
    }
    /// True if permissions never increase as contact degrades.
    pub fn is_monotonic(&self) -> bool {
        self.connected >= self.degraded && self.degraded >= self.lost && self.lost >= self.hold
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    levels: Schedule,
    contact: ContactWindow,
    actions: BTreeMap<String, ActionRule>,
}

/// A validated policy. Construct with [`Policy::from_toml`] or
/// [`Policy::new`]; both reject non-monotonic rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    schedule: Schedule,
    contact: ContactWindow,
    actions: BTreeMap<String, ActionRule>,
}

/// Upper bound on the policy file size we will parse.
pub const MAX_POLICY_BYTES: usize = 256 * 1024;

impl Policy {
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        if text.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::Parse("policy file too large".into()));
        }
        let raw: RawPolicy = toml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        if raw.version != 1 {
            return Err(PolicyError::UnsupportedVersion(raw.version));
        }
        Policy::new(raw.levels, raw.contact, raw.actions)
    }

    pub fn new(
        schedule: Schedule,
        contact: ContactWindow,
        actions: BTreeMap<String, ActionRule>,
    ) -> Result<Self, PolicyError> {
        if !(0 < schedule.degraded_after_secs
            && schedule.degraded_after_secs < schedule.lost_after_secs
            && schedule.lost_after_secs < schedule.hold_after_secs)
        {
            return Err(PolicyError::BadSchedule(
                "need 0 < degraded_after_secs < lost_after_secs < hold_after_secs".into(),
            ));
        }
        if contact.max_age_secs == 0 || contact.max_age_secs > schedule.degraded_after_secs {
            return Err(PolicyError::BadContactWindow(
                "need 0 < max_age_secs <= degraded_after_secs".into(),
            ));
        }
        if contact.max_future_skew_secs > contact.max_age_secs {
            return Err(PolicyError::BadContactWindow(
                "need max_future_skew_secs <= max_age_secs".into(),
            ));
        }
        if actions.is_empty() {
            return Err(PolicyError::NoActions);
        }
        for (name, rule) in &actions {
            if !valid_ident(name) {
                return Err(PolicyError::BadActionName(name.clone()));
            }
            if !rule.is_monotonic() {
                return Err(PolicyError::NonMonotonic(name.clone()));
            }
        }
        Ok(Policy {
            schedule,
            contact,
            actions,
        })
    }

    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }
    pub fn contact_window(&self) -> &ContactWindow {
        &self.contact
    }
    pub fn actions(&self) -> impl Iterator<Item = (&str, &ActionRule)> {
        self.actions.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Pure decision. Unknown or malformed action names are denied.
    pub fn decide(&self, action: &str, level: ContactLevel) -> Decision {
        if !valid_ident(action) {
            return Decision::Deny;
        }
        match self.actions.get(action) {
            Some(rule) => rule.at(level),
            None => Decision::Deny,
        }
    }
}
