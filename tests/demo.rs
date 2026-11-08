//! The demo must not depend on the folder it's started from, and the files it
//! writes must pass the real `verify` command. The demo source is compiled in
//! here as a module so the test can call it with an explicit output folder.

#[allow(dead_code)]
#[path = "../examples/demo.rs"]
mod demo;

use std::fs;
use std::process::Command;

#[test]
fn embedded_policy_matches_the_file() {
    assert_eq!(
        demo::EXAMPLE_POLICY,
        fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/policies/example.toml"
        ))
        .unwrap()
    );
}

#[test]
fn demo_output_verifies_from_another_folder() {
    let out = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let dir = demo::run(out.path()).expect("demo runs");
    // A second run into the same folder replaces its own files.
    let dir2 = demo::run(out.path()).expect("demo reruns");
    assert_eq!(dir, dir2);

    // Run the real CLI with an unrelated working folder and absolute paths.
    let status = Command::new(env!("CARGO_BIN_EXE_terminal-guard"))
        .current_dir(elsewhere.path())
        .args(["verify", "--log"])
        .arg(dir.join("audit.log"))
        .arg("--checkpoint")
        .arg(dir.join("audit.checkpoint"))
        .arg("--audit-pubkey")
        .arg(dir.join("audit.pub"))
        .args(["--log-id", "demo-agent-01"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn demo_refuses_a_folder_with_other_files() {
    let out = tempfile::tempdir().unwrap();
    let keep = out.path().join("keep.txt");
    fs::write(&keep, "mine").unwrap();
    assert!(demo::run(out.path()).is_err());
    assert_eq!(fs::read_to_string(&keep).unwrap(), "mine");
    assert!(!out.path().join("audit.log").exists());
}
