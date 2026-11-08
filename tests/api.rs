//! Tests for the primary public API: decide, tick, apply_signed_approval.

mod common;

use std::time::Duration;

use common::{ENGINE, Fixture};
use terminal_guard::{ContactAuth, ContactError, ContactLevel, Decision, VerifyMode, verify_log};

#[test]
fn decide_matches_check_and_fails_closed() {
    let mut f = Fixture::new();
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny); // hold
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m).unwrap();
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Allow);
    assert_eq!(f.guard.check("read_local_fixture"), Decision::Allow);
    assert_eq!(f.guard.decide("unknown_action"), Decision::Deny);
    assert_eq!(f.guard.decide("bad name\n"), Decision::Deny);
}

#[test]
fn tick_steps_down_on_schedule_and_never_improves() {
    let mut f = Fixture::new();
    assert_eq!(f.guard.tick(), ContactLevel::Hold);
    f.clock.advance(Duration::from_secs(10_000));
    assert_eq!(
        f.guard.tick(),
        ContactLevel::Hold,
        "time alone never leaves hold"
    );

    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m).unwrap();
    assert_eq!(f.guard.tick(), ContactLevel::Connected);
    let mut last = ContactLevel::Connected;
    for _ in 0..40 {
        f.clock.advance(Duration::from_secs(450));
        let l = f.guard.tick();
        assert!(l >= last);
        last = l;
    }
    assert_eq!(last, ContactLevel::Hold);
    // Rewinding the clock cannot improve the level either.
    f.clock.set_monotonic(Duration::ZERO);
    assert_eq!(f.guard.tick(), ContactLevel::Hold);
}

#[test]
fn tick_writes_level_changes_to_the_log() {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m).unwrap();
    f.clock.advance(Duration::from_secs(700));
    assert_eq!(f.guard.tick(), ContactLevel::Degraded);
    let (log, cp) = f.read();
    assert!(log.contains("\"kind\":\"level_changed\",\"from\":\"connected\",\"to\":\"degraded\""));
    verify_log(&log, &cp, &f.audit_pub, Some(ENGINE), VerifyMode::Exact).unwrap();
}

/// There is no network in this crate. "Reconnect" is modelled as: the link
/// comes back, time keeps passing, the agent keeps calling tick/decide, and
/// old (already used) messages may be re-delivered. None of that restores.
#[test]
fn reconnect_alone_does_not_restore() {
    let mut f = Fixture::new();
    let old = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&old).unwrap();
    f.clock.advance(Duration::from_secs(4000));
    assert_eq!(f.guard.tick(), ContactLevel::Lost);

    // "Link restored": keep ticking and deciding, re-deliver the old message.
    for _ in 0..10 {
        f.clock.advance(Duration::from_secs(1));
        f.guard.tick();
        f.guard.decide("send_external_message");
    }
    assert_eq!(
        f.guard.apply_signed_approval(&old),
        Err(ContactError::Replay)
    );
    assert_eq!(f.guard.tick(), ContactLevel::Lost);
    assert_eq!(f.guard.decide("send_external_message"), Decision::Deny);

    // Only a NEW signed message restores.
    let new = ContactAuth::new(ENGINE, 2, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&new).unwrap();
    assert_eq!(f.guard.tick(), ContactLevel::Connected);
}

/// A contact renewal restores the contact level only. It is not approval of
/// any action the policy marks needs_approval.
#[test]
fn signed_approval_is_contact_renewal_not_action_approval() {
    let mut f = Fixture::new();
    let m = ContactAuth::new(ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m).unwrap();
    assert_eq!(
        f.guard.decide("send_external_message"),
        Decision::NeedsApproval
    );
    let m2 = ContactAuth::new(ENGINE, 2, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&m2).unwrap();
    assert_eq!(
        f.guard.decide("send_external_message"),
        Decision::NeedsApproval
    );
}
