#![allow(dead_code)]

use std::path::PathBuf;

use terminal_guard::keys::{SigningKey, generate};
use terminal_guard::{AuditLog, Guard, MockClock, Policy};

pub const ENGINE: &str = "test-engine";
pub const T0: u64 = 1_800_000_000_000;

pub fn policy() -> Policy {
    Policy::from_toml(include_str!("../../policies/example.toml")).expect("example policy")
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub guard: Guard<MockClock>,
    pub clock: MockClock,
    pub human: SigningKey,
    pub audit_pub: terminal_guard::keys::VerifyingKey,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = MockClock::new(T0);
        let human = generate();
        let audit_key = generate();
        let audit_pub = audit_key.verifying_key();
        let audit = AuditLog::create(
            &dir.path().join("a.log"),
            &dir.path().join("a.cp"),
            ENGINE,
            audit_key,
        )
        .unwrap();
        let guard = Guard::new(
            policy(),
            ENGINE,
            vec![human.verifying_key()],
            0,
            audit,
            clock.clone(),
        )
        .unwrap();
        Fixture {
            dir,
            guard,
            clock,
            human,
            audit_pub,
        }
    }
    pub fn log_path(&self) -> PathBuf {
        self.dir.path().join("a.log")
    }
    pub fn cp_path(&self) -> PathBuf {
        self.dir.path().join("a.cp")
    }
    pub fn now_ms(&self) -> u64 {
        use terminal_guard::Clock;
        self.clock.unix_ms().unwrap()
    }
    pub fn read(&self) -> (String, String) {
        (
            std::fs::read_to_string(self.log_path()).unwrap(),
            std::fs::read_to_string(self.cp_path()).unwrap(),
        )
    }
}
