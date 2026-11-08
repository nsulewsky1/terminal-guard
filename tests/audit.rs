mod common;

use std::process::Command;
use std::time::Duration;

use common::{ENGINE, Fixture};
use terminal_guard::audit::{Checkpoint, EntryKind};
use terminal_guard::keys::{generate, verifying_key_hex};
use terminal_guard::{AuditError, AuditLog, ContactAuth, ContactLevel, VerifyMode, verify_log};

/// Fixture with a handful of entries.
fn populated() -> Fixture {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.accept_contact(&m).unwrap();
    f.guard.check("read_local_fixture");
    f.guard.check("send_external_message");
    f.clock.advance(Duration::from_secs(4000));
    f.guard.check("draft_local_note");
    f
}

fn verify(f: &Fixture, log: &str, cp: &str) -> Result<terminal_guard::VerifyReport, AuditError> {
    verify_log(log, cp, &f.audit_pub, Some(ENGINE), VerifyMode::Exact)
}

#[test]
fn intact_log_verifies_with_level_in_every_entry() {
    let f = populated();
    let (log, cp) = f.read();
    let r = verify(&f, &log, &cp).unwrap();
    assert_eq!(r.entries as usize, log.lines().count());
    assert_eq!(r.final_level, Some(ContactLevel::Lost));
    assert!(log.lines().all(|l| l.contains("\"level\":\"")));
}

#[test]
fn empty_log_verifies_only_against_empty_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let k = generate();
    let pk = k.verifying_key();
    let mut a = AuditLog::create(&dir.path().join("l"), &dir.path().join("c"), ENGINE, k).unwrap();
    let cp0 = std::fs::read_to_string(dir.path().join("c")).unwrap();
    let r = verify_log("", &cp0, &pk, Some(ENGINE), VerifyMode::Exact).unwrap();
    assert_eq!(r.entries, 0);
    a.append(0, ContactLevel::Hold, EntryKind::Start).unwrap();
    let cp1 = std::fs::read_to_string(dir.path().join("c")).unwrap();
    assert!(matches!(
        verify_log("", &cp1, &pk, Some(ENGINE), VerifyMode::Exact),
        Err(AuditError::CountMismatch {
            log: 0,
            checkpoint: 1
        })
    ));
}

#[test]
fn deleting_newest_entry_is_detected() {
    let f = populated();
    let (log, cp) = f.read();
    let lines: Vec<&str> = log.lines().collect();
    let cut = lines[..lines.len() - 1].join("\n") + "\n";
    assert!(matches!(
        verify(&f, &cut, &cp),
        Err(AuditError::CountMismatch { .. })
    ));
}

#[test]
fn truncation_and_deleting_middle_are_detected() {
    let f = populated();
    let (log, cp) = f.read();
    assert!(matches!(
        verify(&f, "", &cp),
        Err(AuditError::CountMismatch { .. })
    ));
    let lines: Vec<&str> = log.lines().collect();
    let mut v = lines.clone();
    v.remove(2);
    let s = v.join("\n") + "\n";
    assert!(matches!(
        verify(&f, &s, &cp),
        Err(AuditError::BadSequence { line: 3 })
    ));
    // Partial last line (crash mid-write or byte truncation).
    let partial = &log[..log.len() - 10];
    assert!(verify(&f, partial, &cp).is_err());
    // Missing trailing newline only.
    assert!(verify(&f, log.trim_end(), &cp).is_err());
}

#[test]
fn reordering_is_detected() {
    let f = populated();
    let (log, cp) = f.read();
    let mut v: Vec<&str> = log.lines().collect();
    v.swap(2, 3);
    let s = v.join("\n") + "\n";
    assert!(matches!(
        verify(&f, &s, &cp),
        Err(AuditError::BadSequence { .. })
    ));
}

#[test]
fn editing_any_entry_is_detected() {
    let f = populated();
    let (log, cp) = f.read();
    // Flip a decision.
    let edited = log.replacen(
        "\"decision\":\"needs_approval\"",
        "\"decision\":\"allow\"",
        1,
    );
    assert_ne!(edited, log);
    assert!(matches!(
        verify(&f, &edited, &cp),
        Err(AuditError::BadSignature { .. })
    ));
    // Change a recorded level.
    let edited = log.replacen("\"level\":\"lost\"", "\"level\":\"connected\"", 1);
    assert_ne!(edited, log);
    assert!(verify(&f, &edited, &cp).is_err());
    // Change sequence number of an entry.
    let edited = log.replacen("\"seq\":2,", "\"seq\":3,", 1);
    assert!(matches!(
        verify(&f, &edited, &cp),
        Err(AuditError::BadSequence { .. })
    ));
    // Extra field.
    let edited = log.replacen("{\"v\":1,", "{\"v\":1,\"x\":0,", 1);
    assert!(matches!(
        verify(&f, &edited, &cp),
        Err(AuditError::Malformed { .. })
    ));
    // Blank line inserted.
    let edited = log.replacen('\n', "\n\n", 1);
    assert!(matches!(
        verify(&f, &edited, &cp),
        Err(AuditError::Malformed { .. })
    ));
}

#[test]
fn appended_entry_is_detected() {
    let f = populated();
    let (log, cp) = f.read();
    let last = log.lines().last().unwrap();
    let s = format!("{log}{last}\n");
    assert!(verify(&f, &s, &cp).is_err());
}

#[test]
fn edited_or_resigned_checkpoint_is_rejected() {
    let f = populated();
    let (log, cp) = f.read();
    let edited = cp.replacen("\"count\":", "\"count\":1", 1);
    assert!(matches!(
        verify(&f, &log, &edited),
        Err(AuditError::BadCheckpointSignature)
    ));

    // Attacker deletes newest entry and signs a matching checkpoint with
    // their own key: rejected because the verifier pins the real audit key.
    let lines: Vec<&str> = log.lines().collect();
    let cut = lines[..lines.len() - 1].join("\n") + "\n";
    let attacker = generate();
    let forged = Checkpoint {
        log_id: ENGINE.into(),
        count: (lines.len() - 1) as u64,
        head: [7u8; 32],
    }
    .to_signed_json(&attacker);
    assert!(matches!(
        verify(&f, &cut, &forged),
        Err(AuditError::BadCheckpointSignature)
    ));
    // ...and verifying with the attacker's key fails on the entries instead.
    assert!(matches!(
        verify_log(
            &cut,
            &forged,
            &attacker.verifying_key(),
            Some(ENGINE),
            VerifyMode::Exact
        ),
        Err(AuditError::BadSignature { line: 1 })
    ));
}

#[test]
fn missing_or_garbage_checkpoint_fails() {
    let f = populated();
    let (log, _) = f.read();
    assert!(verify(&f, &log, "").is_err());
    assert!(verify(&f, &log, "{}").is_err());
    std::fs::remove_file(f.cp_path()).unwrap();
    let r = AuditLog::open(&f.log_path(), &f.cp_path(), ENGINE, generate());
    assert!(matches!(r, Err(AuditError::MissingCheckpoint)));
}

#[test]
fn wrong_log_id_is_rejected() {
    let f = populated();
    let (log, cp) = f.read();
    assert!(matches!(
        verify_log(&log, &cp, &f.audit_pub, Some("other"), VerifyMode::Exact),
        Err(AuditError::LogIdMismatch)
    ));
}

#[test]
fn reopen_continues_chain() {
    let dir = tempfile::tempdir().unwrap();
    let k = generate();
    let (l, c) = (dir.path().join("l"), dir.path().join("c"));
    let mut a = AuditLog::create(&l, &c, ENGINE, k.clone()).unwrap();
    a.append(1, ContactLevel::Hold, EntryKind::Start).unwrap();
    drop(a);
    assert!(
        AuditLog::create(&l, &c, ENGINE, k.clone()).is_err(),
        "create must not overwrite"
    );
    let (mut a, r) = AuditLog::open(&l, &c, ENGINE, k.clone()).unwrap();
    assert_eq!(r.entries, 1);
    a.append(2, ContactLevel::Hold, EntryKind::Start).unwrap();
    let r = verify_log(
        &std::fs::read_to_string(&l).unwrap(),
        &std::fs::read_to_string(&c).unwrap(),
        &k.verifying_key(),
        Some(ENGINE),
        VerifyMode::Exact,
    )
    .unwrap();
    assert_eq!(r.entries, 2);
    // Opening with a different audit key fails.
    assert!(AuditLog::open(&l, &c, ENGINE, generate()).is_err());
}

#[test]
fn prefix_mode_against_retained_checkpoint() {
    let mut f = populated();
    let (_, old_cp) = f.read(); // retained elsewhere
    f.guard.check("read_local_fixture");
    let (log, cp) = f.read();
    assert!(verify(&f, &log, &cp).is_ok());
    assert!(
        verify(&f, &log, &old_cp).is_err(),
        "exact mode needs latest"
    );
    let pre = |l: &str, c: &str| verify_log(l, c, &f.audit_pub, Some(ENGINE), VerifyMode::Prefix);
    assert!(pre(&log, &old_cp).is_ok());
    // Rolling the log back past the retained checkpoint is caught.
    let lines: Vec<&str> = log.lines().collect();
    let rolled = lines[..lines.len() - 3].join("\n") + "\n";
    assert!(pre(&rolled, &old_cp).is_err());
}

/// Documents the known limit: rolling back log AND checkpoint together to an
/// earlier consistent pair is not detectable from those two files alone.
#[test]
fn known_limit_joint_rollback_passes_file_only_check() {
    let mut f = populated();
    let (old_log, old_cp) = f.read();
    f.guard.check("read_local_fixture");
    assert!(verify(&f, &old_log, &old_cp).is_ok());
}

#[test]
fn cli_verify_exit_codes() {
    let f = populated();
    let bin = env!("CARGO_BIN_EXE_terminal-guard");
    let pubf = f.dir.path().join("audit.pub");
    std::fs::write(&pubf, verifying_key_hex(&f.audit_pub)).unwrap();
    let run = |cp: &std::path::Path, key: &std::path::Path| {
        Command::new(bin)
            .args(["verify", "--log"])
            .arg(f.log_path())
            .arg("--checkpoint")
            .arg(cp)
            .arg("--audit-pubkey")
            .arg(key)
            .args(["--log-id", ENGINE])
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(run(&f.cp_path(), &pubf), Some(0));
    let wrong = f.dir.path().join("wrong.pub");
    std::fs::write(&wrong, verifying_key_hex(&generate().verifying_key())).unwrap();
    assert_eq!(run(&f.cp_path(), &wrong), Some(1));
    assert_eq!(run(&f.dir.path().join("missing.cp"), &pubf), Some(1));
    let usage = Command::new(bin)
        .arg("verify")
        .output()
        .unwrap()
        .status
        .code();
    assert_eq!(usage, Some(2));
}
