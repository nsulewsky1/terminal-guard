//! Mock-agent demo with a SIMULATED lost link.
//!
//! Uses a mock clock to step through time, so it runs in under a second. It
//! is a simulation of the policy logic only, not evidence from a real network
//! disconnect. All actions are harmless local stand-ins.
//!
//! Keys are generated fresh in memory each run and private keys are never
//! written to disk. The example policy is built into the program, so the demo
//! doesn't depend on the folder you start it from.
//!
//! Output goes to `demo-out/` under the current folder, or to the folder given
//! with `--out DIR`. The demo only writes `audit.log`, `audit.checkpoint` and
//! `audit.pub` there, and it refuses a folder that holds anything else.
//!
//! Run from the repo:   cargo run --example demo
//! Run from elsewhere:  cargo run --manifest-path /path/to/terminal-guard/Cargo.toml --example demo
//! Pick the folder:     cargo run --example demo -- --out /some/empty/folder

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
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
/// The example policy, embedded at build time.
pub const EXAMPLE_POLICY: &str = include_str!("../policies/example.toml");
const OUTPUT_FILES: [&str; 3] = ["audit.log", "audit.checkpoint", "audit.pub"];
const USAGE: &str = "usage: demo [--out DIR]   (default: ./demo-out)";

type DemoResult<T> = Result<T, Box<dyn Error>>;

fn main() {
    let out = match parse_args(std::env::args().skip(1)) {
        Ok(Some(out)) => out,
        Ok(None) => {
            println!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("demo: {e}\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&out) {
        eprintln!("demo: {e}");
        std::process::exit(1);
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> DemoResult<Option<PathBuf>> {
    let mut out = PathBuf::from("demo-out");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--out" => out = PathBuf::from(args.next().ok_or("--out needs a folder")?),
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    Ok(Some(out))
}

/// Make `out` ready for a fresh run. Creates it if needed. If it exists, it
/// must be a real folder (not a symlink) holding nothing but earlier demo
/// output, which is removed file by file. Nothing else is ever deleted.
fn prepare_output(out: &Path) -> DemoResult<PathBuf> {
    match fs::symlink_metadata(out) {
        Ok(meta) if meta.is_dir() => {
            for entry in fs::read_dir(out)
                .map_err(|e| format!("can't read output folder {}: {e}", out.display()))?
            {
                let entry = entry?;
                let name = entry.file_name();
                let ours = OUTPUT_FILES.iter().any(|f| name == *f);
                if !ours || !entry.file_type()?.is_file() {
                    return Err(format!(
                        "output folder {} holds {:?}, which isn't demo output; \
                         pick an empty folder with --out",
                        out.display(),
                        name
                    )
                    .into());
                }
            }
            for f in OUTPUT_FILES {
                let p = out.join(f);
                if p.exists() {
                    fs::remove_file(&p)
                        .map_err(|e| format!("can't remove old {}: {e}", p.display()))?;
                }
            }
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "output path {} is a symlink; give the real folder instead",
                out.display()
            )
            .into());
        }
        Ok(_) => {
            return Err(format!("output path {} exists and isn't a folder", out.display()).into());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(out)
                .map_err(|e| format!("can't create output folder {}: {e}", out.display()))?;
        }
        Err(e) => return Err(format!("can't check output folder {}: {e}", out.display()).into()),
    }
    Ok(fs::canonicalize(out)?)
}

/// Run the whole demo, writing its audit files into `out`. Returns the
/// absolute output folder.
pub fn run(out: &Path) -> DemoResult<PathBuf> {
    let out = prepare_output(out)?;
    let log_path = out.join("audit.log");
    let cp_path = out.join("audit.checkpoint");
    let pub_path = out.join("audit.pub");

    let policy = Policy::from_toml(EXAMPLE_POLICY)
        .map_err(|e| format!("built-in example policy is invalid: {e:?}"))?;

    // Two separate key roles, ephemeral, in memory only.
    let human_key = generate();
    let audit_key = generate();
    fs::write(
        &pub_path,
        verifying_key_hex(&audit_key.verifying_key()) + "\n",
    )
    .map_err(|e| format!("can't write {}: {e}", pub_path.display()))?;
    let pinned_audit = audit_key.verifying_key();

    // Fixed start time so the run is deterministic apart from the keys.
    let clock = MockClock::new(1_800_000_000_000);
    let audit = AuditLog::create(&log_path, &cp_path, ENGINE_ID, audit_key)
        .map_err(|e| format!("can't create audit log in {}: {e:?}", out.display()))?;
    let mut guard = Guard::new(
        policy,
        ENGINE_ID,
        vec![human_key.verifying_key()],
        0,
        audit,
        clock.clone(),
    )
    .map_err(|e| format!("can't start guard: {e:?}"))?;

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
    )
    .map_err(|e| format!("demo audit log failed verification: {e:?}"))?;
    println!(
        "\naudit log verified: {} entries, head {}",
        report.entries,
        hex::encode(report.head)
    );
    println!("output folder: {}", out.display());
    println!(
        "verify yourself (from the repo, or add --manifest-path /path/to/terminal-guard/Cargo.toml):\n  \
         cargo run --bin terminal-guard -- verify --log {} --checkpoint {} --audit-pubkey {} --log-id {}",
        log_path.display(),
        cp_path.display(),
        pub_path.display(),
        ENGINE_ID
    );
    Ok(out)
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
