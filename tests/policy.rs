mod common;

use terminal_guard::policy::{ActionRule, ContactWindow, Schedule};
use terminal_guard::{ContactLevel, Decision, Policy, PolicyError};

const BASE: &str = r#"
version = 1
[levels]
degraded_after_secs = 600
lost_after_secs = 3600
hold_after_secs = 14400
[contact]
max_age_secs = 120
max_future_skew_secs = 30
"#;

fn with_action(rule: &str) -> String {
    format!("{BASE}\n[actions.a]\n{rule}\n")
}

#[test]
fn example_policy_is_valid() {
    let p = common::policy();
    assert_eq!(
        p.decide("read_local_fixture", ContactLevel::Connected),
        Decision::Allow
    );
    assert_eq!(
        p.decide("read_local_fixture", ContactLevel::Hold),
        Decision::Deny
    );
}

#[test]
fn unknown_and_malformed_actions_are_denied() {
    let p = common::policy();
    for level in ContactLevel::ALL {
        assert_eq!(p.decide("not_in_policy", level), Decision::Deny);
        assert_eq!(p.decide("", level), Decision::Deny);
        assert_eq!(p.decide("read_local_fixture\n", level), Decision::Deny);
        assert_eq!(p.decide(&"a".repeat(500), level), Decision::Deny);
    }
}

#[test]
fn rejects_permission_gain_as_contact_degrades() {
    let t = with_action(
        r#"connected="deny"
degraded="allow"
lost="deny"
hold="deny""#,
    );
    assert!(matches!(
        Policy::from_toml(&t),
        Err(PolicyError::NonMonotonic(_))
    ));
    let t = with_action(
        r#"connected="allow"
degraded="allow"
lost="deny"
hold="needs_approval""#,
    );
    assert!(matches!(
        Policy::from_toml(&t),
        Err(PolicyError::NonMonotonic(_))
    ));
}

#[test]
fn rejects_bad_schedule_and_window() {
    let bad = BASE.replace("lost_after_secs = 3600", "lost_after_secs = 600");
    assert!(matches!(
        Policy::from_toml(&format!(
            "{bad}[actions.a]\nconnected=\"deny\"\ndegraded=\"deny\"\nlost=\"deny\"\nhold=\"deny\"\n"
        )),
        Err(PolicyError::BadSchedule(_))
    ));
    let bad = BASE.replace("max_age_secs = 120", "max_age_secs = 9999");
    assert!(matches!(
        Policy::from_toml(&format!(
            "{bad}[actions.a]\nconnected=\"deny\"\ndegraded=\"deny\"\nlost=\"deny\"\nhold=\"deny\"\n"
        )),
        Err(PolicyError::BadContactWindow(_))
    ));
}

#[test]
fn rejects_unknown_fields_versions_and_values() {
    let ok = with_action("connected=\"allow\"\ndegraded=\"allow\"\nlost=\"allow\"\nhold=\"deny\"");
    assert!(Policy::from_toml(&ok).is_ok());
    assert!(Policy::from_toml(&ok.replace("version = 1", "version = 2")).is_err());
    assert!(Policy::from_toml(&format!("{ok}extra = 1\n")).is_err());
    assert!(Policy::from_toml(&ok.replace("hold=\"deny\"", "hold=\"maybe\"")).is_err());
    assert!(Policy::from_toml(&ok.replace("hold=\"deny\"", "")).is_err());
    assert!(Policy::from_toml(BASE).is_err()); // no actions table
    assert!(
        Policy::from_toml(
            &with_action("connected=\"allow\"\ndegraded=\"allow\"\nlost=\"allow\"\nhold=\"deny\"")
                .replace("[actions.a]", "[actions.\"bad name\"]")
        )
        .is_err()
    );
}

#[test]
fn new_validates_too() {
    let mut actions = std::collections::BTreeMap::new();
    actions.insert(
        "x".to_string(),
        ActionRule {
            connected: Decision::NeedsApproval,
            degraded: Decision::Allow,
            lost: Decision::Deny,
            hold: Decision::Deny,
        },
    );
    let s = Schedule {
        degraded_after_secs: 600,
        lost_after_secs: 3600,
        hold_after_secs: 7200,
    };
    let w = ContactWindow {
        max_age_secs: 60,
        max_future_skew_secs: 5,
    };
    assert!(matches!(
        Policy::new(s, w, actions),
        Err(PolicyError::NonMonotonic(_))
    ));
}
