//! The audit log holds an exclusive flock. A second process must fail to open it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use terminal_guard::keys::{generate, signing_key_hex};
use terminal_guard::{AuditError, AuditLog};

#[test]
fn second_process_cannot_open_a_locked_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("a.log");
    let cp = dir.path().join("a.cp");
    let key = generate();
    let key_path = dir.path().join("audit.seed");
    std::fs::write(&key_path, signing_key_hex(&key)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_terminal-guard"))
        .args([
            "hold-lock",
            "--create",
            "--log",
            log.to_str().unwrap(),
            "--checkpoint",
            cp.to_str().unwrap(),
            "--audit-key-file",
            key_path.to_str().unwrap(),
            "--log-id",
            "test-engine",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hold-lock");

    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read LOCKED");
    assert_eq!(line.trim(), "LOCKED", "hold-lock did not report the lock");

    let err = AuditLog::open(&log, &cp, "test-engine", key.clone()).unwrap_err();
    assert!(
        matches!(err, AuditError::Locked),
        "second process should fail with Locked, got {err}"
    );

    let mut stdin = child.stdin.take().unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    let status = child.wait().expect("wait for hold-lock");
    assert!(status.success(), "hold-lock exited {status}");

    let (reopened, report) = AuditLog::open(&log, &cp, "test-engine", key).unwrap();
    assert_eq!(report.entries, 0);
    drop(reopened);
}
