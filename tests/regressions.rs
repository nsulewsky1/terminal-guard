//! Regression tests for defects found in the readiness review.

mod common;

use std::fs;
use std::io::Write;
use std::time::Duration;

use common::{ENGINE, Fixture, T0};
use terminal_guard::audit::{MAX_LINE_BYTES, read_bounded};
use terminal_guard::keys::generate;
use terminal_guard::{
    AuditError, AuditLog, ContactAuth, ContactError, ContactLevel, Decision, Guard, MockClock,
    Policy, VerifyMode, verify_log,
};

/// A renewal accepted at the very edge of its freshness window is backdated
/// past the degrade threshold. The log must record the level it actually
/// produced, not a hard-coded `connected`.
#[test]
fn accepted_renewal_logs_the_level_it_actually_produces() {
    let policy = Policy::from_toml(
        // The example policy already has max_age_secs = 120; make the
        // degrade threshold equal to it.
        &include_str!("../policies/example.toml")
            .replace("degraded_after_secs = 600", "degraded_after_secs = 120"),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock = MockClock::new(T0);
    let human = generate();
    let audit_key = generate();
    let pk = audit_key.verifying_key();
    let audit = AuditLog::create(
        &dir.path().join("l"),
        &dir.path().join("c"),
        ENGINE,
        audit_key,
    )
    .unwrap();
    let mut g = Guard::new(
        policy,
        ENGINE,
        vec![human.verifying_key()],
        0,
        audit,
        clock.clone(),
    )
    .unwrap();

    // Exactly max_age (= degraded_after) old: accepted, but already degraded.
    let m = ContactAuth::new(ENGINE, 1, T0 - 120_000).sign(&human);
    g.apply_signed_approval(&m).unwrap();
    assert_eq!(g.tick(), ContactLevel::Degraded);
    drop(g);
    let log = fs::read_to_string(dir.path().join("l")).unwrap();
    let accepted = log
        .lines()
        .find(|l| l.contains("contact_accepted"))
        .unwrap();
    assert!(accepted.contains("\"level\":\"degraded\""), "{accepted}");
    let cp = fs::read_to_string(dir.path().join("c")).unwrap();
    verify_log(&log, &cp, &pk, Some(ENGINE), VerifyMode::Exact).unwrap();
}

/// If the wall clock is unavailable, decisions fail closed and the denial is
/// logged, instead of carrying on with a zero timestamp.
#[test]
fn missing_wall_clock_denies_decisions() {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m).unwrap();
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Allow);
    f.clock.set_unix_ms(None);
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny);
    f.clock.set_unix_ms(Some(T0 + 1));
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Allow);
    let (log, _) = f.read();
    assert!(log.contains("\"unix_ms\":0,\"level\":\"connected\",\"kind\":\"decision\",\"action\":\"read_local_fixture\",\"decision\":\"deny\""));
}

/// Reopening a verified log carries its replay floor into the new guard, and
/// a caller passing a lower `next_contact_sequence` cannot lower it.
#[test]
fn reopened_log_keeps_replay_floor_even_if_caller_passes_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (l, c) = (dir.path().join("l"), dir.path().join("c"));
    let human = generate();
    let audit_key = generate();
    let clock = MockClock::new(T0);
    let audit = AuditLog::create(&l, &c, ENGINE, audit_key.clone()).unwrap();
    let mut g = Guard::new(
        common::policy(),
        ENGINE,
        vec![human.verifying_key()],
        0,
        audit,
        clock.clone(),
    )
    .unwrap();
    let m5 = ContactAuth::new(ENGINE, 5, T0).sign(&human);
    g.apply_signed_approval(&m5).unwrap();
    drop(g);

    let (audit, report) = AuditLog::open(&l, &c, ENGINE, audit_key).unwrap();
    assert_eq!(report.last_contact_sequence, Some(5));
    let mut g = Guard::new(
        common::policy(),
        ENGINE,
        vec![human.verifying_key()],
        0,
        audit,
        MockClock::new(T0 + 1_000),
    )
    .unwrap();
    assert_eq!(g.tick(), ContactLevel::Hold);
    assert_eq!(g.apply_signed_approval(&m5), Err(ContactError::Replay));
    assert_eq!(g.tick(), ContactLevel::Hold);
    let m6 = ContactAuth::new(ENGINE, 6, T0 + 1_000).sign(&human);
    g.apply_signed_approval(&m6).unwrap();
}

#[test]
fn audit_log_for_another_engine_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::create(
        &dir.path().join("l"),
        &dir.path().join("c"),
        "other-engine",
        generate(),
    )
    .unwrap();
    let r = Guard::new(
        common::policy(),
        ENGINE,
        vec![generate().verifying_key()],
        0,
        audit,
        MockClock::new(T0),
    );
    assert!(r.is_err());
}

/// A second writer (or an edit) changing the log file under a running guard
/// is detected at the next append, and the guard fails closed.
#[test]
fn external_change_to_log_poisons_guard() {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m).unwrap();
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Allow);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(f.log_path())
        .unwrap();
    writeln!(file, "{{\"forged\":true}}").unwrap();
    drop(file);
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny);
    assert!(f.guard.is_poisoned());
    f.clock.advance(Duration::from_secs(1));
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny);
}

#[test]
fn oversized_inputs_are_refused_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big");
    fs::write(&big, vec![b'a'; 10_000]).unwrap();
    assert_eq!(read_bounded(&big, 9_999), Err(AuditError::TooLarge));
    assert!(read_bounded(&big, 10_000).is_ok());

    // An oversized checkpoint stops a reopen.
    let k = generate();
    let (l, c) = (dir.path().join("l"), dir.path().join("c"));
    drop(AuditLog::create(&l, &c, ENGINE, k.clone()).unwrap());
    fs::write(&c, vec![b' '; MAX_LINE_BYTES + 1]).unwrap();
    assert!(matches!(
        AuditLog::open(&l, &c, ENGINE, k),
        Err(AuditError::TooLarge)
    ));
}
