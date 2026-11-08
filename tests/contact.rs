mod common;

use std::time::Duration;

use common::{ENGINE, Fixture};
use terminal_guard::contact::CONTACT_DOMAIN;
use terminal_guard::keys::generate;
use terminal_guard::{
    AuditLog, ContactAuth, ContactError, ContactLevel, Decision, Guard, MockClock, VerifyMode,
    verify_log,
};

#[test]
fn starts_in_hold_and_denies_everything() {
    let mut f = Fixture::new();
    assert_eq!(f.guard.level(), ContactLevel::Hold);
    assert_eq!(f.guard.check("read_local_fixture"), Decision::Deny);
    // Time alone never moves out of hold.
    f.clock.advance(Duration::from_secs(10));
    assert_eq!(f.guard.level(), ContactLevel::Hold);
}

#[test]
fn fresh_contact_connects_and_timer_steps_down() {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.accept_contact(&m).unwrap();
    assert_eq!(f.guard.level(), ContactLevel::Connected);
    f.clock.advance(Duration::from_secs(599));
    assert_eq!(f.guard.level(), ContactLevel::Connected);
    f.clock.advance(Duration::from_secs(1));
    assert_eq!(f.guard.level(), ContactLevel::Degraded);
    f.clock.advance(Duration::from_secs(3000));
    assert_eq!(f.guard.level(), ContactLevel::Lost);
    f.clock.advance(Duration::from_secs(10800));
    assert_eq!(f.guard.level(), ContactLevel::Hold);
}

#[test]
fn clock_going_backwards_never_restores() {
    let mut f = Fixture::new();
    f.clock.advance(Duration::from_secs(100));
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.accept_contact(&m).unwrap();
    f.clock.advance(Duration::from_secs(4000));
    assert_eq!(f.guard.level(), ContactLevel::Lost);
    f.clock.set_monotonic(Duration::from_secs(1));
    assert_eq!(f.guard.level(), ContactLevel::Hold);
    f.clock.set_monotonic(Duration::from_secs(4000));
    assert_eq!(f.guard.level(), ContactLevel::Hold);
}

#[test]
fn old_message_buys_less_time() {
    let mut f = Fixture::new();
    // 100 s old, within the 120 s window.
    let m = ContactAuth::new(ENGINE, 1, f.now_ms() - 100_000).sign(&f.human);
    f.guard.accept_contact(&m).unwrap();
    f.clock.advance(Duration::from_secs(500));
    assert_eq!(f.guard.level(), ContactLevel::Degraded);
}

fn expect_reject(f: &mut Fixture, m: &terminal_guard::SignedContact, e: ContactError) {
    assert_eq!(f.guard.accept_contact(m), Err(e));
    assert_eq!(
        f.guard.level(),
        ContactLevel::Hold,
        "rejected contact must not restore"
    );
}

#[test]
fn rejects_wrong_key_engine_domain_and_tampering() {
    let mut f = Fixture::new();
    let now = f.now_ms();
    let other = generate();
    let h = f.human.clone();
    expect_reject(
        &mut f,
        &ContactAuth::new(ENGINE, 1, now).sign(&other),
        ContactError::BadSignature,
    );
    expect_reject(
        &mut f,
        &ContactAuth::new("other-engine", 1, now).sign(&h),
        ContactError::WrongEngine,
    );

    let mut body = ContactAuth::new(ENGINE, 1, now);
    body.domain = "something-else/v1".into();
    let m = body.sign(&h);
    expect_reject(&mut f, &m, ContactError::WrongDomain);

    // Valid signature, then body edited after signing.
    let mut m = ContactAuth::new(ENGINE, 1, now).sign(&h);
    m.body.sequence = 7;
    expect_reject(&mut f, &m, ContactError::BadSignature);
    let mut m = ContactAuth::new(ENGINE, 1, now - 200_000).sign(&h);
    m.body.issued_unix_ms = now;
    expect_reject(&mut f, &m, ContactError::BadSignature);

    // Garbage signatures.
    let mut m = ContactAuth::new(ENGINE, 1, now).sign(&h);
    m.signature = "zz".into();
    expect_reject(&mut f, &m, ContactError::Malformed);
    m.signature = "00".repeat(64);
    expect_reject(&mut f, &m, ContactError::BadSignature);
    assert_eq!(CONTACT_DOMAIN, "terminal-guard/contact/v1");
}

#[test]
fn rejects_stale_future_and_no_wall_clock() {
    let mut f = Fixture::new();
    let now = f.now_ms();
    let h = f.human.clone();
    expect_reject(
        &mut f,
        &ContactAuth::new(ENGINE, 1, now - 121_000).sign(&h),
        ContactError::Stale,
    );
    expect_reject(
        &mut f,
        &ContactAuth::new(ENGINE, 1, now + 31_000).sign(&h),
        ContactError::FromFuture,
    );
    f.clock.set_unix_ms(None);
    expect_reject(
        &mut f,
        &ContactAuth::new(ENGINE, 1, now).sign(&h),
        ContactError::NoWallClock,
    );
}

#[test]
fn rejects_replay_and_lower_sequence() {
    let mut f = Fixture::new();
    let h = f.human.clone();
    let m5 = ContactAuth::new(ENGINE, 5, f.now_ms()).sign(&h);
    f.guard.accept_contact(&m5).unwrap();
    f.clock.advance(Duration::from_secs(700));
    assert_eq!(f.guard.level(), ContactLevel::Degraded);
    // Same message again, and a fresh-but-lower sequence.
    assert_eq!(f.guard.accept_contact(&m5), Err(ContactError::Replay));
    let m4 = ContactAuth::new(ENGINE, 4, f.now_ms()).sign(&h);
    assert_eq!(f.guard.accept_contact(&m4), Err(ContactError::Replay));
    assert_eq!(f.guard.level(), ContactLevel::Degraded);
    let m6 = ContactAuth::new(ENGINE, 6, f.now_ms()).sign(&h);
    f.guard.accept_contact(&m6).unwrap();
    assert_eq!(f.guard.level(), ContactLevel::Connected);
    // u64::MAX is refused so the counter can never saturate.
    let mx = ContactAuth::new(ENGINE, u64::MAX, f.now_ms()).sign(&h);
    assert_eq!(f.guard.accept_contact(&mx), Err(ContactError::Malformed));
}

#[test]
fn malformed_json_contact_is_rejected_and_logged() {
    let mut f = Fixture::new();
    for bad in [
        "",
        "{",
        "null",
        "{\"body\":1,\"signature\":\"\"}",
        &"x".repeat(10_000),
    ] {
        assert_eq!(
            f.guard.accept_contact_json(bad),
            Err(ContactError::Malformed)
        );
    }
    let good = ContactAuth::new(ENGINE, 1, f.now_ms())
        .sign(&f.human)
        .to_json();
    let extra = good.replacen('{', "{\"extra\":1,", 1);
    assert_eq!(
        f.guard.accept_contact_json(&extra),
        Err(ContactError::Malformed)
    );
    f.guard.accept_contact_json(&good).unwrap();
    let (log, _) = f.read();
    assert_eq!(log.matches("\"reason\":\"malformed\"").count(), 6);
}

#[test]
fn restart_starts_in_hold_and_restores_anti_replay_from_log() {
    let f = Fixture::new();
    let dir = f.dir;
    let mut guard = f.guard;
    let h = f.human.clone();
    let clock = f.clock.clone();
    let m = ContactAuth::new(ENGINE, 3, {
        use terminal_guard::Clock;
        clock.unix_ms().unwrap()
    })
    .sign(&h);
    guard.accept_contact(&m).unwrap();
    assert_eq!(guard.level(), ContactLevel::Connected);
    drop(guard);

    // "Restart": a new process gets a fresh monotonic clock, same wall time.
    let new_clock = MockClock::new(common::T0 + 1_000);
    // The audit key must be the same one, but this test uses a new key on a
    // new log; reopen path is covered in audit tests. Here: anti-replay seed.
    let (log, cp) = (
        std::fs::read_to_string(dir.path().join("a.log")).unwrap(),
        std::fs::read_to_string(dir.path().join("a.cp")).unwrap(),
    );
    let report = verify_log(&log, &cp, &f.audit_pub, Some(ENGINE), VerifyMode::Exact).unwrap();
    assert_eq!(report.last_contact_sequence, Some(3));

    let audit_key = generate();
    let audit = AuditLog::create(
        &dir.path().join("b.log"),
        &dir.path().join("b.cp"),
        ENGINE,
        audit_key,
    )
    .unwrap();
    let next = report.last_contact_sequence.map_or(0, |s| s + 1);
    let mut g2 = Guard::new(
        common::policy(),
        ENGINE,
        vec![h.verifying_key()],
        next,
        audit,
        new_clock,
    )
    .unwrap();
    assert_eq!(g2.level(), ContactLevel::Hold);
    assert_eq!(g2.check("read_local_fixture"), Decision::Deny);
    assert_eq!(g2.accept_contact(&m), Err(ContactError::Replay));
    assert_eq!(g2.level(), ContactLevel::Hold);
}

#[test]
fn audit_key_cannot_be_a_human_key() {
    let dir = tempfile::tempdir().unwrap();
    let k = generate();
    let audit = AuditLog::create(
        &dir.path().join("l"),
        &dir.path().join("c"),
        ENGINE,
        k.clone(),
    )
    .unwrap();
    let r = Guard::new(
        common::policy(),
        ENGINE,
        vec![k.verifying_key()],
        0,
        audit,
        MockClock::new(0),
    );
    assert!(r.is_err());
    let audit = AuditLog::create(
        &dir.path().join("l2"),
        &dir.path().join("c2"),
        ENGINE,
        generate(),
    )
    .unwrap();
    assert!(
        Guard::new(
            common::policy(),
            ENGINE,
            vec![],
            0,
            audit,
            MockClock::new(0)
        )
        .is_err()
    );
}

#[test]
fn audit_write_failure_poisons_guard() {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.accept_contact(&m).unwrap();
    assert_eq!(f.guard.check("read_local_fixture"), Decision::Allow);
    // Remove the log file so the next append fails.
    std::fs::remove_file(f.log_path()).unwrap();
    assert_eq!(f.guard.check("read_local_fixture"), Decision::Deny);
    assert!(f.guard.is_poisoned());
    // Stays denied, and contact cannot un-poison it.
    let m2 = ContactAuth::new(ENGINE, 2, f.now_ms()).sign(&f.human);
    assert_eq!(f.guard.accept_contact(&m2), Err(ContactError::AuditFailed));
    assert_eq!(f.guard.check("read_local_fixture"), Decision::Deny);
}
