//! `terminal-guard` command-line tool.
//!
//! ```text
//! terminal-guard verify --log FILE --checkpoint FILE --audit-pubkey FILE [--log-id ID] [--prefix]
//! terminal-guard check-policy FILE
//! ```
//!
//! Exit codes: 0 = OK, 1 = verification/validation failed, 2 = usage error.

use std::fs;
use std::process::ExitCode;

use terminal_guard::keys::parse_verifying_key_hex;
use terminal_guard::{Policy, VerifyMode, verify_log};

const USAGE: &str = "usage:
  terminal-guard verify --log FILE --checkpoint FILE --audit-pubkey FILE [--log-id ID] [--prefix]
  terminal-guard check-policy FILE

--audit-pubkey is a file holding the trusted audit verifying key (64 hex chars),
obtained independently of the log. --prefix verifies against an older,
separately retained checkpoint and allows the log to have grown since.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("verify") => verify(&args[1..]),
        Some("check-policy") if args.len() == 2 => check_policy(&args[1]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check_policy(path: &str) -> ExitCode {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    match Policy::from_toml(&text) {
        Ok(p) => {
            println!(
                "OK: policy valid ({} actions, monotonic)",
                p.actions().count()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn verify(args: &[String]) -> ExitCode {
    let (mut log, mut cp, mut key, mut log_id) = (None, None, None, None);
    let mut mode = VerifyMode::Exact;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let slot = match a.as_str() {
            "--log" => &mut log,
            "--checkpoint" => &mut cp,
            "--audit-pubkey" => &mut key,
            "--log-id" => &mut log_id,
            "--prefix" => {
                mode = VerifyMode::Prefix;
                continue;
            }
            _ => {
                eprintln!("unknown argument {a:?}\n{USAGE}");
                return ExitCode::from(2);
            }
        };
        match it.next() {
            Some(v) if slot.is_none() => *slot = Some(v.clone()),
            _ => {
                eprintln!("missing or repeated value for {a}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(log), Some(cp), Some(key)) = (log, cp, key) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let fail = |msg: String| {
        eprintln!("FAIL: {msg}");
        ExitCode::from(1)
    };
    let key_text = match fs::read_to_string(&key) {
        Ok(t) => t,
        Err(e) => return fail(format!("cannot read audit key {key}: {e}")),
    };
    let Some(vk) = parse_verifying_key_hex(&key_text) else {
        return fail("audit key file is not a valid Ed25519 verifying key".into());
    };
    let cp_text = match fs::read_to_string(&cp) {
        Ok(t) => t,
        Err(e) => return fail(format!("checkpoint {cp} unreadable: {e}")),
    };
    let log_text = match fs::read_to_string(&log) {
        Ok(t) => t,
        Err(e) => return fail(format!("log {log} unreadable: {e}")),
    };
    match verify_log(&log_text, &cp_text, &vk, log_id.as_deref(), mode) {
        Ok(r) => {
            println!(
                "OK: {} entries verified for log {:?}; checkpoint count {}; head {}",
                r.entries,
                r.log_id,
                r.checkpoint_count,
                hex::encode(r.head)
            );
            if let Some(l) = r.final_level {
                println!("last recorded contact level: {l}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(e.to_string()),
    }
}
