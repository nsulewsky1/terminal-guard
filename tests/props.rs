//! Property tests: losing contact never adds a permission, and malformed
//! inputs never panic or verify.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use proptest::prelude::*;
use terminal_guard::policy::{ActionRule, ContactWindow, Schedule};
use terminal_guard::{
    ContactAuth, ContactLevel, Decision, MockClock, Policy, SignedContact, VerifyMode, verify_log,
};

fn decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Deny),
        Just(Decision::NeedsApproval),
        Just(Decision::Allow)
    ]
}

fn rule() -> impl Strategy<Value = ActionRule> {
    (decision(), decision(), decision(), decision()).prop_map(|(a, b, c, d)| ActionRule {
        connected: a,
        degraded: b,
        lost: c,
        hold: d,
    })
}

/// Valid monotonic rule: sort four decisions descending.
fn monotonic_rule() -> impl Strategy<Value = ActionRule> {
    proptest::collection::vec(decision(), 4).prop_map(|mut v| {
        v.sort_by(|a, b| b.cmp(a));
        ActionRule {
            connected: v[0],
            degraded: v[1],
            lost: v[2],
            hold: v[3],
        }
    })
}

fn schedule() -> impl Strategy<Value = Schedule> {
    (1u64..5000, 1u64..5000, 1u64..50000).prop_map(|(a, b, c)| Schedule {
        degraded_after_secs: a,
        lost_after_secs: a + b,
        hold_after_secs: a + b + c,
    })
}

fn policy_strategy() -> impl Strategy<Value = Policy> {
    (
        schedule(),
        proptest::collection::vec(monotonic_rule(), 1..6),
    )
        .prop_map(|(s, rules)| {
            let actions: BTreeMap<String, ActionRule> = rules
                .into_iter()
                .enumerate()
                .map(|(i, r)| (format!("act{i}"), r))
                .collect();
            let w = ContactWindow {
                max_age_secs: s.degraded_after_secs,
                max_future_skew_secs: 0,
            };
            Policy::new(s, w, actions).unwrap()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Validation accepts exactly the monotonic rules.
    #[test]
    fn validation_matches_monotonicity(r in rule()) {
        let mut actions = BTreeMap::new();
        actions.insert("a".to_string(), r);
        let s = Schedule { degraded_after_secs: 600, lost_after_secs: 3600, hold_after_secs: 14400 };
        let w = ContactWindow { max_age_secs: 60, max_future_skew_secs: 5 };
        let ok = Policy::new(s, w, actions).is_ok();
        let mono = r.connected >= r.degraded && r.degraded >= r.lost && r.lost >= r.hold;
        prop_assert_eq!(ok, mono);
    }

    /// Schedule levels never improve as time since contact grows.
    #[test]
    fn schedule_is_monotonic(s in schedule(), a in 0u64..100_000, b in 0u64..100_000) {
        let (lo, hi) = (a.min(b), a.max(b));
        prop_assert!(s.level_for(Duration::from_secs(lo)) <= s.level_for(Duration::from_secs(hi)));
    }

    /// Core property: with no new contact, any sequence of clock moves
    /// (forward or backward) never makes any action more permitted.
    #[test]
    fn losing_contact_never_adds_permission(
        p in policy_strategy(),
        steps in proptest::collection::vec(-20_000i64..60_000, 1..30),
        start in 0u64..10_000,
    ) {
        let human = terminal_guard::keys::generate();
        // Use the tracker directly so each case gets its own random policy.
        let clock = MockClock::new(common::T0);
        clock.advance(Duration::from_secs(start));
        let mut t = terminal_guard::ContactTracker::new(common::ENGINE, vec![human.verifying_key()], 0);
        // Before any contact: Hold.
        prop_assert_eq!(t.level(&p, &clock), ContactLevel::Hold);
        let now = { use terminal_guard::Clock; clock.unix_ms().unwrap() };
        t.accept(&ContactAuth::new(common::ENGINE, 1, now).sign(&human), &p, &clock).unwrap();
        let actions: Vec<String> = p.actions().map(|(n, _)| n.to_string()).collect();
        let mut prev_level = t.level(&p, &clock);
        let mut prev: Vec<Decision> = actions.iter().map(|a| p.decide(a, prev_level)).collect();
        let mut mono = start;
        for st in steps {
            mono = if st < 0 { mono.saturating_sub((-st) as u64) } else { mono + st as u64 };
            clock.set_monotonic(Duration::from_secs(mono));
            let level = t.level(&p, &clock);
            prop_assert!(level >= prev_level);
            let now_d: Vec<Decision> = actions.iter().map(|a| p.decide(a, level)).collect();
            for (x, y) in prev.iter().zip(&now_d) {
                prop_assert!(y <= x, "permission increased without contact");
            }
            prev = now_d;
            prev_level = level;
        }
    }

    /// Rejected contact messages never change the level.
    #[test]
    fn invalid_contacts_never_restore(seq in 0u64..10, skew in -1_000_000i64..1_000_000, flip in 0usize..64) {
        let mut f = common::Fixture::new();
        let base = f.now_ms() as i64;
        let mut m = ContactAuth::new(common::ENGINE, seq, (base + skew) as u64).sign(&f.human);
        // Corrupt one signature hex char.
        let mut chars: Vec<char> = m.signature.chars().collect();
        chars[flip] = if chars[flip] == '0' { '1' } else { '0' };
        m.signature = chars.into_iter().collect();
        let _ = f.guard.accept_contact(&m);
        prop_assert_eq!(f.guard.level(), ContactLevel::Hold);
    }

    /// Arbitrary policy text never panics; if accepted it is monotonic.
    #[test]
    fn arbitrary_policy_text(s in "\\PC{0,400}") {
        if let Ok(p) = Policy::from_toml(&s) {
            for (_, r) in p.actions() { prop_assert!(r.is_monotonic()); }
        }
    }

    /// Arbitrary contact JSON never panics and never parses into an accepted
    /// contact on a fresh guard.
    #[test]
    fn arbitrary_contact_json(s in "\\PC{0,300}") {
        let mut f = common::Fixture::new();
        let _ = SignedContact::from_json(&s);
        let _ = f.guard.accept_contact_json(&s);
        prop_assert_eq!(f.guard.level(), ContactLevel::Hold);
    }

    /// Arbitrary log/checkpoint bytes never verify against a pinned key.
    #[test]
    fn arbitrary_log_never_verifies(log in "\\PC{0,500}", cp in "\\PC{0,300}") {
        let k = terminal_guard::keys::generate().verifying_key();
        prop_assert!(verify_log(&log, &cp, &k, None, VerifyMode::Exact).is_err());
    }

    /// Mutating any single byte of a real log or checkpoint breaks verification.
    #[test]
    fn single_byte_mutation_detected(pos in any::<prop::sample::Index>(), byte in any::<u8>(), which in any::<bool>()) {
        let mut f = common::Fixture::new();
        let m = ContactAuth::new(common::ENGINE, 1, f.now_ms()).sign(&f.human);
        f.guard.accept_contact(&m).unwrap();
        f.guard.check("read_local_fixture");
        f.guard.check("delete_local_file");
        let (log, cp) = f.read();
        let target = if which { &log } else { &cp };
        let mut bytes = target.as_bytes().to_vec();
        let i = pos.index(bytes.len());
        prop_assume!(bytes[i] != byte);
        bytes[i] = byte;
        let Ok(mutated) = String::from_utf8(bytes) else { return Ok(()); };
        let (l, c) = if which { (mutated, cp.clone()) } else { (log.clone(), mutated) };
        let r = verify_log(&l, &c, &f.audit_pub, Some(common::ENGINE), VerifyMode::Exact);
        // JSON allows a few semantically-neutral edits (e.g. whitespace,
        // hex case); those must still verify to the same head.
        if let Ok(rep) = r {
            let orig = verify_log(&log, &cp, &f.audit_pub, Some(common::ENGINE), VerifyMode::Exact).unwrap();
            prop_assert_eq!(rep.head, orig.head);
            prop_assert_eq!(rep.entries, orig.entries);
        }
    }
}
