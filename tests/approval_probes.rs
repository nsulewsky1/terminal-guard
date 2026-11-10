//! Adversarial checks on one-time action approvals, written in review.

mod common;

use std::time::Duration;

use common::{ENGINE, Fixture};
use terminal_guard::keys::generate;
use terminal_guard::{
    ActionApproval, ApprovalError, ContactAuth, ContactLevel, Decision, SignedActionApproval,
    SignedContact, VerifyMode, verify_log,
};

const ACTION: &str = "send_external_message";

fn connect(f: &mut Fixture, sequence: u64) {
    let msg = ContactAuth::new(ENGINE, sequence, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&msg).unwrap();
}

fn verified_log(f: &Fixture) -> String {
    let (log, cp) = f.read();
    verify_log(&log, &cp, &f.audit_pub, Some(ENGINE), VerifyMode::Exact).expect("log verifies");
    log
}

#[test]
fn approval_for_another_engine_or_domain_is_rejected_and_logged() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let other = ActionApproval::new("other-engine", ACTION, 1, f.now_ms()).sign(&f.human);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &other),
        Err(ApprovalError::WrongEngine)
    );
    let mut body = ActionApproval::new(ENGINE, ACTION, 2, f.now_ms());
    body.domain = "terminal-guard/contact/v1".into();
    let wrong_domain = body.sign(&f.human);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &wrong_domain),
        Err(ApprovalError::WrongDomain)
    );
    let log = verified_log(&f);
    assert!(log.contains(r#""reason":"wrong_engine""#));
    assert!(log.contains(r#""reason":"wrong_domain""#));
    assert!(!log.contains("approved_decision"));
    // Neither id was consumed by a failed attempt.
    let good = ActionApproval::new(ENGINE, ACTION, 1, f.now_ms()).sign(&f.human);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &good),
        Ok(Decision::Allow)
    );
}

#[test]
fn contact_and_approval_signatures_are_not_interchangeable() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let now = f.now_ms();
    // A real contact signature moved onto an approval body.
    let contact = ContactAuth::new(ENGINE, 5, now).sign(&f.human);
    let forged = SignedActionApproval {
        body: ActionApproval::new(ENGINE, ACTION, 5, now),
        signature: contact.signature.clone(),
    };
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &forged),
        Err(ApprovalError::BadSignature)
    );
    // An approval's JSON is not a contact message, and its signature does
    // not verify as one.
    let approval = ActionApproval::new(ENGINE, ACTION, 6, now).sign(&f.human);
    assert!(SignedContact::from_json(&approval.to_json()).is_err());
    let as_contact = SignedContact {
        body: ContactAuth::new(ENGINE, 6, now),
        signature: approval.signature.clone(),
    };
    assert!(f.guard.apply_signed_approval(&as_contact).is_err());
}

#[test]
fn approval_does_not_renew_contact() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    f.clock.advance(Duration::from_secs(20 * 60)); // past degraded (600 s)
    assert_eq!(f.guard.tick(), ContactLevel::Degraded);
    // Degraded: send_external_message is NeedsApproval in the example policy.
    let token = ActionApproval::new(ENGINE, ACTION, 1, f.now_ms()).sign(&f.human);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &token),
        Ok(Decision::Allow)
    );
    assert_eq!(f.guard.tick(), ContactLevel::Degraded);
    f.clock.advance(Duration::from_secs(60 * 60));
    assert_eq!(f.guard.tick(), ContactLevel::Lost);
}

#[test]
fn approval_in_hold_or_without_wall_clock_is_denied_and_not_consumed() {
    let mut f = Fixture::new();
    // Fresh guard is in Hold.
    let token = ActionApproval::new(ENGINE, ACTION, 1, f.now_ms()).sign(&f.human);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &token),
        Ok(Decision::Deny)
    );
    connect(&mut f, 1);
    let now = f.now_ms();
    f.clock.set_unix_ms(None);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &token),
        Ok(Decision::Deny)
    );
    f.clock.set_unix_ms(Some(now));
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &token),
        Ok(Decision::Allow)
    );
}

#[test]
fn tampered_or_malleable_signatures_are_rejected() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let now = f.now_ms();
    let good = ActionApproval::new(ENGINE, ACTION, 1, now).sign(&f.human);

    let mut changed_id = good.clone();
    changed_id.body.id = 2;
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &changed_id),
        Err(ApprovalError::BadSignature)
    );
    let mut changed_action = good.clone();
    changed_action.body.action = "delete_local_file".into();
    assert_eq!(
        f.guard
            .decide_with_approval("delete_local_file", &changed_action),
        Err(ApprovalError::BadSignature)
    );

    // Same signature with S + L (a second encoding of the same scalar).
    let mut sig = hex::decode(&good.signature).unwrap();
    add_group_order(&mut sig[32..]);
    let malleated = SignedActionApproval {
        body: good.body.clone(),
        signature: hex::encode(&sig),
    };
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &malleated),
        Err(ApprovalError::BadSignature)
    );

    // Signed by a key the guard doesn't trust.
    let stranger = ActionApproval::new(ENGINE, ACTION, 3, now).sign(&generate());
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &stranger),
        Err(ApprovalError::BadSignature)
    );

    // The untouched approval still works once.
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &good),
        Ok(Decision::Allow)
    );
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &good),
        Err(ApprovalError::Replay)
    );
}

/// Little-endian add of the Ed25519 group order L.
fn add_group_order(s: &mut [u8]) {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = s[i] as u16 + L[i] as u16 + carry;
        s[i] = v as u8;
        carry = v >> 8;
    }
}

#[test]
fn malformed_approvals_are_rejected() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let max = ActionApproval::new(ENGINE, ACTION, u64::MAX, f.now_ms()).sign(&f.human);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &max),
        Err(ApprovalError::Malformed)
    );
    let big = format!(
        r#"{{"body":{{"pad":"{}"}},"signature":""}}"#,
        "x".repeat(5000)
    );
    assert_eq!(
        SignedActionApproval::from_json(&big),
        Err(ApprovalError::Malformed)
    );
    let good = ActionApproval::new(ENGINE, ACTION, 1, f.now_ms()).sign(&f.human);
    let extra = good.to_json().replacen('{', r#"{"args":"anything","#, 1);
    assert_eq!(
        SignedActionApproval::from_json(&extra),
        Err(ApprovalError::Malformed)
    );
    let mut short_sig = good.clone();
    short_sig.signature.truncate(10);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &short_sig),
        Err(ApprovalError::Malformed)
    );
}

#[test]
fn audit_failure_consumes_nothing_and_poisons_the_guard() {
    let mut f = Fixture::new();
    connect(&mut f, 1);
    let token = ActionApproval::new(ENGINE, ACTION, 9, f.now_ms()).sign(&f.human);
    // Someone appends to the log behind the writer's back.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(f.log_path())
        .unwrap();
    writeln!(file, "junk").unwrap();
    drop(file);
    assert_eq!(
        f.guard.decide_with_approval(ACTION, &token),
        Err(ApprovalError::AuditFailed)
    );
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny);
    let (log, _) = f.read();
    assert!(!log.contains("approved_decision"));
}
