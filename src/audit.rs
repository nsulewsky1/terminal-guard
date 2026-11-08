//! Signed, SHA-256 hash-chained audit log plus a signed checkpoint.
//!
//! **Log file** (`*.log`): one JSON object per line. JSON is only the storage
//! format; each entry's hash and signature cover a canonical, versioned,
//! length-prefixed binary encoding that the verifier recomputes.
//!
//! **Checkpoint file**: one JSON object holding `{log_id, count, head}` signed
//! by the audit key. It is rewritten (write temp + rename) after each append.
//!
//! What verification proves, given a *pinned* audit verifying key:
//! * every entry is signed, sequence numbers run 0..n with no gaps, each
//!   entry links to the previous hash, entry 0 links to the all-zero genesis;
//! * the log ends exactly at the checkpoint's count and head (Exact mode), so
//!   deleting or editing any entry, including the newest, is detected *as
//!   long as the checkpoint is the trusted latest one*.
//!
//! What it cannot prove: if an attacker rolls back the log *and* the
//! checkpoint together to an earlier consistent state, file-only verification
//! cannot tell. Keep a copy of recent checkpoints somewhere the agent host
//! cannot rewrite and verify against it ([`VerifyMode::Prefix`]). If the audit
//! signing key is compromised, there are no guarantees at all.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encode::{Enc, valid_ident};
use crate::policy::{ContactLevel, Decision};

const ENTRY_MAGIC: &[u8; 4] = b"TGAE";
const CHECKPOINT_MAGIC: &[u8; 4] = b"TGCK";
const FORMAT_VERSION: u8 = 1;
/// Hash that entry 0 links to, and the head of an empty log.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];
/// Hard caps so a hostile file cannot exhaust memory.
pub const MAX_LINE_BYTES: usize = 4096;
pub const MAX_LOG_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    Io(String),
    MissingCheckpoint,
    Malformed { line: u64, why: &'static str },
    BadCheckpointSignature,
    LogIdMismatch,
    BadSequence { line: u64 },
    BrokenLink { line: u64 },
    BadSignature { line: u64 },
    CountMismatch { log: u64, checkpoint: u64 },
    HeadMismatch,
    TooLarge,
    InvalidLogId,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::Io(e) => write!(f, "io error: {e}"),
            AuditError::MissingCheckpoint => write!(f, "checkpoint missing"),
            AuditError::Malformed { line, why } => {
                write!(f, "malformed entry at line {line}: {why}")
            }
            AuditError::BadCheckpointSignature => {
                write!(f, "checkpoint signature invalid for the pinned audit key")
            }
            AuditError::LogIdMismatch => write!(f, "log id mismatch"),
            AuditError::BadSequence { line } => write!(f, "sequence gap or reorder at line {line}"),
            AuditError::BrokenLink { line } => write!(f, "hash chain broken at line {line}"),
            AuditError::BadSignature { line } => {
                write!(f, "entry signature invalid at line {line}")
            }
            AuditError::CountMismatch { log, checkpoint } => write!(
                f,
                "log has {log} entries but checkpoint says {checkpoint} (entries deleted, truncated or appended)"
            ),
            AuditError::HeadMismatch => write!(f, "log head hash does not match checkpoint"),
            AuditError::TooLarge => write!(f, "input exceeds size limit"),
            AuditError::InvalidLogId => write!(f, "invalid log id"),
        }
    }
}

impl std::error::Error for AuditError {}

/// What an entry records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// Engine started (always at `Hold`).
    Start,
    /// A `check` call and its result.
    Decision { action: String, decision: Decision },
    /// Contact level changed.
    LevelChanged {
        from: ContactLevel,
        to: ContactLevel,
    },
    /// A human contact message was accepted.
    ContactAccepted { sequence: u64 },
    /// A human contact message was rejected (fixed reason code).
    ContactRejected { reason: String },
}

/// One audit entry (without signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub log_id: String,
    pub seq: u64,
    pub prev: [u8; 32],
    /// Wall-clock ms; informational only (0 if unavailable).
    pub unix_ms: u64,
    pub level: ContactLevel,
    pub kind: EntryKind,
}

impl Entry {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new(ENTRY_MAGIC, FORMAT_VERSION);
        e.str(&self.log_id)
            .u64(self.seq)
            .fixed(&self.prev)
            .u64(self.unix_ms)
            .u8(self.level.code());
        match &self.kind {
            EntryKind::Start => {
                e.u8(0);
            }
            EntryKind::Decision { action, decision } => {
                e.u8(1).str(action).u8(decision.code());
            }
            EntryKind::LevelChanged { from, to } => {
                e.u8(2).u8(from.code()).u8(to.code());
            }
            EntryKind::ContactAccepted { sequence } => {
                e.u8(3).u64(*sequence);
            }
            EntryKind::ContactRejected { reason } => {
                e.u8(4).str(reason);
            }
        }
        e.finish()
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

// ---- storage (JSON) representation -------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryJson {
    v: u8,
    log_id: String,
    seq: u64,
    prev: String,
    unix_ms: u64,
    level: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    sig: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(s, &mut b).ok()?;
    Some(b)
}

fn sig64(s: &str) -> Option<Signature> {
    let mut b = [0u8; 64];
    hex::decode_to_slice(s, &mut b).ok()?;
    Some(Signature::from_bytes(&b))
}

fn entry_to_json(e: &Entry, sig: &Signature) -> String {
    let mut j = EntryJson {
        v: FORMAT_VERSION,
        log_id: e.log_id.clone(),
        seq: e.seq,
        prev: hex::encode(e.prev),
        unix_ms: e.unix_ms,
        level: e.level.as_str().into(),
        kind: String::new(),
        action: None,
        decision: None,
        from: None,
        to: None,
        sequence: None,
        reason: None,
        sig: hex::encode(sig.to_bytes()),
    };
    match &e.kind {
        EntryKind::Start => j.kind = "start".into(),
        EntryKind::Decision { action, decision } => {
            j.kind = "decision".into();
            j.action = Some(action.clone());
            j.decision = Some(decision.as_str().into());
        }
        EntryKind::LevelChanged { from, to } => {
            j.kind = "level_changed".into();
            j.from = Some(from.as_str().into());
            j.to = Some(to.as_str().into());
        }
        EntryKind::ContactAccepted { sequence } => {
            j.kind = "contact_accepted".into();
            j.sequence = Some(*sequence);
        }
        EntryKind::ContactRejected { reason } => {
            j.kind = "contact_rejected".into();
            j.reason = Some(reason.clone());
        }
    }
    serde_json::to_string(&j).unwrap_or_default()
}

fn entry_from_json(line: &str, n: u64) -> Result<(Entry, Signature), AuditError> {
    let bad = |why| AuditError::Malformed { line: n, why };
    if line.len() > MAX_LINE_BYTES {
        return Err(bad("line too long"));
    }
    let j: EntryJson = serde_json::from_str(line).map_err(|_| bad("not a valid entry"))?;
    if j.v != FORMAT_VERSION {
        return Err(bad("unsupported version"));
    }
    if !valid_ident(&j.log_id) {
        return Err(bad("bad log id"));
    }
    let prev = hex32(&j.prev).ok_or(bad("bad prev hash"))?;
    let level = ContactLevel::from_str_strict(&j.level).ok_or(bad("bad level"))?;
    let sig = sig64(&j.sig).ok_or(bad("bad signature encoding"))?;
    // Exactly the fields for the kind, nothing else.
    let fields = (
        j.action.is_some(),
        j.decision.is_some(),
        j.from.is_some(),
        j.to.is_some(),
        j.sequence.is_some(),
        j.reason.is_some(),
    );
    let kind = match (j.kind.as_str(), fields) {
        ("start", (false, false, false, false, false, false)) => EntryKind::Start,
        ("decision", (true, true, false, false, false, false)) => {
            let action = j.action.unwrap_or_default();
            if !valid_ident(&action) && action != INVALID_ACTION {
                return Err(bad("bad action"));
            }
            let decision = Decision::from_str_strict(j.decision.as_deref().unwrap_or(""))
                .ok_or(bad("bad decision"))?;
            EntryKind::Decision { action, decision }
        }
        ("level_changed", (false, false, true, true, false, false)) => EntryKind::LevelChanged {
            from: ContactLevel::from_str_strict(j.from.as_deref().unwrap_or(""))
                .ok_or(bad("bad level"))?,
            to: ContactLevel::from_str_strict(j.to.as_deref().unwrap_or(""))
                .ok_or(bad("bad level"))?,
        },
        ("contact_accepted", (false, false, false, false, true, false)) => {
            EntryKind::ContactAccepted {
                sequence: j.sequence.unwrap_or_default(),
            }
        }
        ("contact_rejected", (false, false, false, false, false, true)) => {
            let reason = j.reason.unwrap_or_default();
            if !valid_ident(&reason) {
                return Err(bad("bad reason"));
            }
            EntryKind::ContactRejected { reason }
        }
        _ => return Err(bad("unknown kind or wrong fields")),
    };
    Ok((
        Entry {
            log_id: j.log_id,
            seq: j.seq,
            prev,
            unix_ms: j.unix_ms,
            level,
            kind,
        },
        sig,
    ))
}

/// Placeholder written instead of a malformed action name.
pub const INVALID_ACTION: &str = "<invalid>";

// ---- checkpoint --------------------------------------------------------

/// Signed statement of the log's length and head hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub log_id: String,
    pub count: u64,
    pub head: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointJson {
    v: u8,
    log_id: String,
    count: u64,
    head: String,
    sig: String,
}

impl Checkpoint {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Enc::new(CHECKPOINT_MAGIC, FORMAT_VERSION)
            .str(&self.log_id)
            .u64(self.count)
            .fixed(&self.head)
            .finish()
    }

    pub fn to_signed_json(&self, key: &SigningKey) -> String {
        let sig = key.sign(&self.canonical_bytes());
        let j = CheckpointJson {
            v: FORMAT_VERSION,
            log_id: self.log_id.clone(),
            count: self.count,
            head: hex::encode(self.head),
            sig: hex::encode(sig.to_bytes()),
        };
        let mut s = serde_json::to_string(&j).unwrap_or_default();
        s.push('\n');
        s
    }

    /// Parse and verify against a pinned audit key. The checkpoint never
    /// supplies its own key.
    pub fn from_signed_json(text: &str, pinned: &VerifyingKey) -> Result<Self, AuditError> {
        if text.len() > MAX_LINE_BYTES {
            return Err(AuditError::TooLarge);
        }
        let bad = AuditError::Malformed {
            line: 0,
            why: "bad checkpoint",
        };
        let j: CheckpointJson =
            serde_json::from_str(text.trim_end_matches('\n')).map_err(|_| bad.clone())?;
        if j.v != FORMAT_VERSION || !valid_ident(&j.log_id) {
            return Err(bad);
        }
        let cp = Checkpoint {
            log_id: j.log_id,
            count: j.count,
            head: hex32(&j.head).ok_or(bad.clone())?,
        };
        let sig = sig64(&j.sig).ok_or(bad)?;
        pinned
            .verify_strict(&cp.canonical_bytes(), &sig)
            .map_err(|_| AuditError::BadCheckpointSignature)?;
        Ok(cp)
    }
}

// ---- verification ------------------------------------------------------

/// How the log must relate to the checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Log must end exactly at the checkpoint (use with the latest checkpoint).
    Exact,
    /// Log must contain the checkpoint as a prefix and may have grown since
    /// (use with an older checkpoint retained somewhere safer).
    Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub log_id: String,
    pub entries: u64,
    pub head: [u8; 32],
    pub checkpoint_count: u64,
    pub last_contact_sequence: Option<u64>,
    pub final_level: Option<ContactLevel>,
}

/// Verify log text against checkpoint text using a pinned audit key.
pub fn verify_log(
    log_text: &str,
    checkpoint_text: &str,
    pinned: &VerifyingKey,
    expected_log_id: Option<&str>,
    mode: VerifyMode,
) -> Result<VerifyReport, AuditError> {
    if log_text.len() > MAX_LOG_BYTES {
        return Err(AuditError::TooLarge);
    }
    let cp = Checkpoint::from_signed_json(checkpoint_text, pinned)?;
    if let Some(id) = expected_log_id {
        if id != cp.log_id {
            return Err(AuditError::LogIdMismatch);
        }
    }
    if !log_text.is_empty() && !log_text.ends_with('\n') {
        return Err(AuditError::Malformed {
            line: 0,
            why: "log does not end with newline (truncated write?)",
        });
    }
    let mut head = GENESIS_HASH;
    let mut count: u64 = 0;
    let mut head_at_checkpoint = if cp.count == 0 {
        Some(GENESIS_HASH)
    } else {
        None
    };
    let mut last_contact_sequence = None;
    let mut final_level = None;
    for (i, line) in log_text.lines().enumerate() {
        let n = i as u64 + 1;
        let (entry, sig) = entry_from_json(line, n)?;
        if entry.log_id != cp.log_id {
            return Err(AuditError::LogIdMismatch);
        }
        if entry.seq != count {
            return Err(AuditError::BadSequence { line: n });
        }
        if entry.prev != head {
            return Err(AuditError::BrokenLink { line: n });
        }
        if count == 0 && !matches!(entry.kind, EntryKind::Start) {
            return Err(AuditError::Malformed {
                line: n,
                why: "first entry must be start",
            });
        }
        let bytes = entry.canonical_bytes();
        pinned
            .verify_strict(&bytes, &sig)
            .map_err(|_| AuditError::BadSignature { line: n })?;
        head = Sha256::digest(&bytes).into();
        count += 1;
        if count == cp.count {
            head_at_checkpoint = Some(head);
        }
        if let EntryKind::ContactAccepted { sequence } = entry.kind {
            last_contact_sequence = Some(sequence);
        }
        final_level = Some(entry.level);
    }
    match mode {
        VerifyMode::Exact => {
            if count != cp.count {
                return Err(AuditError::CountMismatch {
                    log: count,
                    checkpoint: cp.count,
                });
            }
            if head != cp.head {
                return Err(AuditError::HeadMismatch);
            }
        }
        VerifyMode::Prefix => {
            if count < cp.count {
                return Err(AuditError::CountMismatch {
                    log: count,
                    checkpoint: cp.count,
                });
            }
            if head_at_checkpoint != Some(cp.head) {
                return Err(AuditError::HeadMismatch);
            }
        }
    }
    Ok(VerifyReport {
        log_id: cp.log_id,
        entries: count,
        head,
        checkpoint_count: cp.count,
        last_contact_sequence,
        final_level,
    })
}

/// Sequence number of the last accepted contact in a verified log, so a
/// restarted engine can refuse to accept it again.
pub fn last_contact_sequence(report: &VerifyReport) -> Option<u64> {
    report.last_contact_sequence
}

/// Read a whole file as UTF-8, refusing files larger than `max` bytes
/// before reading them.
pub fn read_bounded(path: &Path, max: usize) -> Result<String, AuditError> {
    let f = File::open(path).map_err(io)?;
    let len = f.metadata().map_err(io)?.len();
    if len > max as u64 {
        return Err(AuditError::TooLarge);
    }
    let mut s = String::with_capacity(len as usize);
    // take() guards against a file that grows while we read it.
    f.take(max as u64 + 1).read_to_string(&mut s).map_err(io)?;
    if s.len() > max {
        return Err(AuditError::TooLarge);
    }
    Ok(s)
}

// ---- writer ------------------------------------------------------------

fn io<E: fmt::Display>(e: E) -> AuditError {
    AuditError::Io(e.to_string())
}

/// Append-only writer for a log + checkpoint pair.
pub struct AuditLog {
    log_path: PathBuf,
    checkpoint_path: PathBuf,
    key: SigningKey,
    log_id: String,
    count: u64,
    head: [u8; 32],
    last_contact_sequence: Option<u64>,
    /// Bytes we expect the log file to hold. A mismatch before an append
    /// means someone else changed the file, so the append fails closed.
    expected_len: u64,
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog")
            .field("log_path", &self.log_path)
            .field("log_id", &self.log_id)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Create a new, empty log. Fails if either file already exists.
    pub fn create(
        log_path: &Path,
        checkpoint_path: &Path,
        log_id: &str,
        key: SigningKey,
    ) -> Result<Self, AuditError> {
        if !valid_ident(log_id) {
            return Err(AuditError::InvalidLogId);
        }
        if checkpoint_path.exists() {
            return Err(AuditError::Io("checkpoint already exists".into()));
        }
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(log_path)
            .map_err(io)?;
        f.sync_all().map_err(io)?;
        let log = AuditLog {
            log_path: log_path.to_path_buf(),
            checkpoint_path: checkpoint_path.to_path_buf(),
            key,
            log_id: log_id.to_string(),
            count: 0,
            head: GENESIS_HASH,
            last_contact_sequence: None,
            expected_len: 0,
        };
        log.write_checkpoint()?;
        Ok(log)
    }

    /// Reopen an existing log after verifying it against its checkpoint.
    /// Returns the writer and the verification report.
    pub fn open(
        log_path: &Path,
        checkpoint_path: &Path,
        log_id: &str,
        key: SigningKey,
    ) -> Result<(Self, VerifyReport), AuditError> {
        let log_text = read_bounded(log_path, MAX_LOG_BYTES)?;
        let cp_text = match read_bounded(checkpoint_path, MAX_LINE_BYTES) {
            Ok(t) => t,
            Err(_) if !checkpoint_path.exists() => return Err(AuditError::MissingCheckpoint),
            Err(e) => return Err(e),
        };
        let report = verify_log(
            &log_text,
            &cp_text,
            &key.verifying_key(),
            Some(log_id),
            VerifyMode::Exact,
        )?;
        let log = AuditLog {
            log_path: log_path.to_path_buf(),
            checkpoint_path: checkpoint_path.to_path_buf(),
            key,
            log_id: log_id.to_string(),
            count: report.entries,
            head: report.head,
            last_contact_sequence: report.last_contact_sequence,
            expected_len: log_text.len() as u64,
        };
        Ok((log, report))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    pub fn log_id(&self) -> &str {
        &self.log_id
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    /// Sequence of the last accepted contact recorded in this log, if any.
    pub fn last_contact_sequence(&self) -> Option<u64> {
        self.last_contact_sequence
    }

    /// Append one entry, fsync it, then rewrite the checkpoint.
    pub fn append(
        &mut self,
        unix_ms: u64,
        level: ContactLevel,
        kind: EntryKind,
    ) -> Result<(), AuditError> {
        let entry = Entry {
            log_id: self.log_id.clone(),
            seq: self.count,
            prev: self.head,
            unix_ms,
            level,
            kind,
        };
        let bytes = entry.canonical_bytes();
        let sig = self.key.sign(&bytes);
        let mut line = entry_to_json(&entry, &sig);
        if line.is_empty() || line.len() > MAX_LINE_BYTES {
            return Err(AuditError::TooLarge);
        }
        line.push('\n');
        let mut f = OpenOptions::new()
            .append(true)
            .open(&self.log_path)
            .map_err(io)?;
        // Single writer only. If the file isn't the length we left it at,
        // another writer or an edit got in, and continuing would fork the
        // chain. This is a best-effort check, not a lock.
        let len = f.metadata().map_err(io)?.len();
        if len != self.expected_len {
            return Err(AuditError::Io(format!(
                "log file changed underneath the writer (expected {} bytes, found {len})",
                self.expected_len
            )));
        }
        f.write_all(line.as_bytes()).map_err(io)?;
        f.sync_data().map_err(io)?;
        self.expected_len += line.len() as u64;
        self.head = Sha256::digest(&bytes).into();
        self.count += 1;
        if let EntryKind::ContactAccepted { sequence } = entry.kind {
            self.last_contact_sequence = Some(sequence);
        }
        self.write_checkpoint()
    }

    fn write_checkpoint(&self) -> Result<(), AuditError> {
        let cp = Checkpoint {
            log_id: self.log_id.clone(),
            count: self.count,
            head: self.head,
        };
        let text = cp.to_signed_json(&self.key);
        let mut tmp_name = self.checkpoint_path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        {
            let mut f = File::create(&tmp).map_err(io)?;
            f.write_all(text.as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        fs::rename(&tmp, &self.checkpoint_path).map_err(io)?;
        Ok(())
    }
}
