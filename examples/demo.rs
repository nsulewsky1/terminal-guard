//! Mock-agent demo with a SIMULATED lost link.
//!
//! Uses a mock clock to step through time, so it runs in under a second. It
//! is a simulation of the policy logic only, not evidence from a real network
//! disconnect. All actions are harmless local stand-ins.
//!
//! Keys are generated fresh in memory each run and private keys are never
//! written to disk. Output goes to ./demo-out/ (git-ignored).
//!
//! Run: cargo run --example demo

use std::fs;
use std::path::Path;
use std::time::Duration;

use terminal_guard::keys::{generate, verifying_key_hex};
use terminal_guard::{
    AuditLog, ContactAuth, Decision, Guard, MockClock, Policy, VerifyMode, verify_log,
};

const ENGINE_ID: &str = "demo-agent-01";
const ACTIONS: [&str; 5] = [
    "read_local_fixture",
    "draft_local_note",
    "send_external_message",
    "delete_local_file",
    "unlisted_action",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = Path::new("demo-out");
    if out.exists() {
        fs::remove_dir_all(out)?;
    }
    fs::create_dir_all(out)?;
    let log_path = out.join("audit.log");
    let cp_path = out.join("audit.checkpoint");
    let pub_path = out.join("audit.pub");

    let policy = Policy::from_toml(&fs::read_to_string("policies/example.toml")?)?;

    // Two separate key roles, ephemeral, in memory only.
    let human_key = generate();
    let audit_key = generate();
    fs::write(
        &pub_path,
        verifying_key_hex(&audit_key.verifying_key()) + "\n",
    )?;
    let pinned_audit = audit_key.verifying_key();

    // Fixed start time so the run is deterministic apart from the keys.
    let clock = MockClock::new(1_800_000_000_000);
    let audit = AuditLog::create(&log_path, &cp_path, ENGINE_ID, audit_key)?;
    let mut guard = Guard::new(
        policy,
        ENGINE_ID,
        vec![human_key.verifying_key()],
        0,
        audit,
        clock.clone(),
    )?;

    println!("terminal-guard demo (simulated time, simulated lost link)\n");
    step(&mut guard, "t+0      engine start, no contact yet");

    let now = || clock_ms(&clock);
    let first = ContactAuth::new(ENGINE_ID, 1, now()).sign(&human_key);
    println!(
        "  -> fresh signed human contact (seq 1): {:?}",
        guard.apply_signed_approval(&first)
    );
    step(&mut guard, "t+0      after verified contact");

    clock.advance(Duration::from_secs(5 * 60));
    step(&mut guard, "t+5m     link up");

    println!("\n  ** network link simulated as lost; no more contact messages **\n");
    clock.advance(Duration::from_secs(10 * 60));
    step(&mut guard, "t+15m    no contact for 15 min");

    clock.advance(Duration::from_secs(60 * 60));
    step(&mut guard, "t+1h15m  no contact for 75 min");

    println!(
        "  -> replay of old contact (seq 1): {:?}",
        guard.apply_signed_approval(&first)
    );
    let forged = ContactAuth::new(ENGINE_ID, 2, now()).sign(&generate());
    println!(
        "  -> contact signed by unknown key: {:?}",
        guard.apply_signed_approval(&forged)
    );

    clock.advance(Duration::from_secs(3 * 60 * 60));
    step(&mut guard, "t+4h15m  no contact for over 4 h");

    println!("\n  ** link simulated as restored; operator sends fresh contact **\n");
    let fresh = ContactAuth::new(ENGINE_ID, 2, now()).sign(&human_key);
    println!(
        "  -> fresh signed human contact (seq 2): {:?}",
        guard.apply_signed_approval(&fresh)
    );
    step(&mut guard, "t+4h15m  after verified contact");

    drop(guard);
    let report = verify_log(
        &fs::read_to_string(&log_path)?,
        &fs::read_to_string(&cp_path)?,
        &pinned_audit,
        Some(ENGINE_ID),
        VerifyMode::Exact,
    )?;
    println!(
        "\naudit log verified: {} entries, head {}",
        report.entries,
        hex::encode(report.head)
    );
    println!(
        "verify yourself:\n  cargo run --bin terminal-guard -- verify --log {} --checkpoint {} --audit-pubkey {} --log-id {}",
        log_path.display(),
        cp_path.display(),
        pub_path.display(),
        ENGINE_ID
    );
    Ok(())
}

fn clock_ms(c: &MockClock) -> u64 {
    use terminal_guard::Clock;
    c.unix_ms().unwrap_or(0)
}

fn step(guard: &mut Guard<MockClock>, label: &str) {
    let level = guard.tick();
    let cells: Vec<String> = ACTIONS
        .iter()
        .map(|a| format!("{a}={}", short(guard.decide(a))))
        .collect();
    println!(
        "{label:<38} level={:<9} {}",
        level.as_str(),
        cells.join("  ")
    );
}

fn short(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "ALLOW",
        Decision::NeedsApproval => "APPROVAL",
        Decision::Deny => "deny",
    }
}
