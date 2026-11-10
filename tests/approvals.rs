//! One-time action approvals. A valid approval can upgrade NeedsApproval
//! once. It cannot upgrade Deny, and a later reopen still rejects the replay.

mod common;

use std::time::Duration;

use common::{ENGINE, Fixture, T0};
use terminal_guard::keys::generate;
use terminal_guard::{
    ActionApproval, ApprovalError, AuditLog, Clock, ContactAuth, Decision, Guard, MockClock,
    SignedActionApproval,
};

fn connect(f: &mut Fixture, sequence: u64) {
    let msg = ContactAuth::new(ENGINE, sequence, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&msg).unwrap();
}

fn approval(f: &Fixture, action: &str, id: u64) -> SignedActionApproval {
    ActionApproval::new(ENGINE, action, id, f.now_ms()).sign(&f.human)
}

#[test]
fn approval_upgrades_needs_approval_once() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let token = approval(&f, "send_external_message", 7);
    assert_eq!(
        f.guard.decide("send_external_message"),
        Decision::NeedsApproval
    );
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &token)
            .unwrap(),
        Decision::Allow
    );
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &token),
        Err(ApprovalError::Replay)
    );
    assert_eq!(
        f.guard.decide("send_external_message"),
        Decision::NeedsApproval
    );
}

#[test]
fn approval_cannot_override_deny_and_remains_usable() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    // lost: send_external_message is deny. The approval must not be consumed.
    f.clock.advance(Duration::from_secs(3600));
    let token = approval(&f, "send_external_message", 9);
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &token)
            .unwrap(),
        Decision::Deny
    );
    connect(&mut f, 2);
    assert_eq!(f.guard.level().to_string(), "connected");
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &token)
            .unwrap(),
        Decision::Allow
    );
}

#[test]
fn allow_does_not_consume_an_approval() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let token = approval(&f, "send_external_message", 3);
    assert_eq!(
        f.guard
            .decide_with_approval("read_local_fixture", &token)
            .unwrap(),
        Decision::Allow
    );
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &token)
            .unwrap(),
        Decision::Allow
    );
}

#[test]
fn wrong_action_is_not_consumed() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let token = approval(&f, "delete_local_file", 4);
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &token),
        Err(ApprovalError::WrongAction)
    );
    assert_eq!(
        f.guard
            .decide_with_approval("delete_local_file", &token)
            .unwrap(),
        Decision::Allow
    );
}

#[test]
fn bad_signature_stale_and_future_are_rejected() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let other = generate();
    let forged = ActionApproval::new(ENGINE, "send_external_message", 1, f.now_ms()).sign(&other);
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &forged),
        Err(ApprovalError::BadSignature)
    );

    let stale = approval(&f, "send_external_message", 2);
    f.clock.advance(Duration::from_secs(200));
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &stale),
        Err(ApprovalError::Stale)
    );

    let future =
        ActionApproval::new(ENGINE, "send_external_message", 5, f.now_ms() + 60_000).sign(&f.human);
    assert_eq!(
        f.guard
            .decide_with_approval("send_external_message", &future),
        Err(ApprovalError::FromFuture)
    );
}

#[test]
fn consumed_approval_is_rejected_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let clock = MockClock::new(T0);
    let human = generate();
    let audit_key = generate();
    let audit = AuditLog::create(
        &dir.path().join("a.log"),
        &dir.path().join("a.cp"),
        ENGINE,
        audit_key.clone(),
    )
    .unwrap();
    let mut guard = Guard::new(
        common::policy(),
        ENGINE,
        vec![human.verifying_key()],
        0,
        audit,
        clock.clone(),
    )
    .unwrap();
    let now = clock.unix_ms().unwrap();
    guard
        .apply_signed_approval(&ContactAuth::new(ENGINE, 1, now).sign(&human))
        .unwrap();
    let token = ActionApproval::new(ENGINE, "send_external_message", 11, now).sign(&human);
    assert_eq!(
        guard
            .decide_with_approval("send_external_message", &token)
            .unwrap(),
        Decision::Allow
    );
    drop(guard);

    let (audit, report) = AuditLog::open(
        &dir.path().join("a.log"),
        &dir.path().join("a.cp"),
        ENGINE,
        audit_key,
    )
    .unwrap();
    assert!(report.used_approval_ids.contains(&11));
    let mut guard = Guard::new(
        common::policy(),
        ENGINE,
        vec![human.verifying_key()],
        0,
        audit,
        clock.clone(),
    )
    .unwrap();
    let now = clock.unix_ms().unwrap();
    guard
        .apply_signed_approval(&ContactAuth::new(ENGINE, 2, now).sign(&human))
        .unwrap();
    assert_eq!(
        guard.decide_with_approval("send_external_message", &token),
        Err(ApprovalError::Replay)
    );
}
