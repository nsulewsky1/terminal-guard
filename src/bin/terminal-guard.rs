//! `terminal-guard` command-line tool.
//!
//! ```text
//! terminal-guard verify --log FILE --checkpoint FILE --audit-pubkey FILE [--log-id ID] [--prefix]
//! terminal-guard check-policy FILE
//! terminal-guard hold-lock --log FILE --checkpoint FILE --audit-key-file FILE --log-id ID [--create]
//! terminal-guard mcp-proxy --policy FILE --engine-id ID --log FILE --checkpoint FILE \
//!     --audit-key-file FILE --human-pubkey-file FILE [--contact-file FILE] [--create] \
//!     [--timeout-secs N] -- DOWNSTREAM_CMD...
//! ```
//!
//! Exit codes: 0 = OK, 1 = verification/validation failed, 2 = usage error.
//!
//! `--audit-key-file` for `hold-lock` and `mcp-proxy` is the audit **private**
//! seed (64 hex characters). `--audit-pubkey` for `verify` is the public key.
//! The private seed is never printed.

use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use terminal_guard::audit::{MAX_LINE_BYTES, MAX_LOG_BYTES, read_bounded};
use terminal_guard::keys::{parse_signing_key_hex, parse_verifying_key_hex};
use terminal_guard::mcp::{
    DownstreamMessage, ProxyOutcome, classify_downstream, error_body, evaluate, read_message,
    write_message,
};
use terminal_guard::policy::MAX_POLICY_BYTES;
use terminal_guard::{AuditLog, Guard, Policy, SignedContact, SystemClock, VerifyMode, verify_log};

const USAGE: &str = "usage:
  terminal-guard verify --log FILE --checkpoint FILE --audit-pubkey FILE [--log-id ID] [--prefix]
  terminal-guard check-policy FILE
  terminal-guard hold-lock --log FILE --checkpoint FILE --audit-key-file FILE --log-id ID [--create]
  terminal-guard mcp-proxy --policy FILE --engine-id ID --log FILE --checkpoint FILE \\
      --audit-key-file FILE --human-pubkey-file FILE [--contact-file FILE] [--create] \\
      [--timeout-secs N] -- DOWNSTREAM_CMD...

verify --audit-pubkey is a file holding the trusted audit verifying key (64 hex chars).
hold-lock and mcp-proxy --audit-key-file is the audit private seed (64 hex chars).
mcp-proxy speaks MCP over stdio (one JSON message per line). It forwards a
tools/call only when the guard allows it. initialize, ping, tools/list and the
initialized/cancelled notifications pass through unchanged. Every other
message is answered with an error, or dropped if it is a notification, and is
not sent to DOWNSTREAM_CMD. The proxy exits if the downstream server sends a
response with the wrong id, sends garbage, exits, or doesn't answer within
--timeout-secs (default 60).";

const DEFAULT_TIMEOUT_SECS: u64 = 60;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("verify") => verify(&args[1..]),
        Some("check-policy") if args.len() == 2 => check_policy(&args[1]),
        Some("hold-lock") => hold_lock(&args[1..]),
        Some("mcp-proxy") => mcp_proxy(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check_policy(path: &str) -> ExitCode {
    let text = match read_bounded(Path::new(path), MAX_POLICY_BYTES) {
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
    let key_text = match read_bounded(Path::new(&key), MAX_LINE_BYTES) {
        Ok(t) => t,
        Err(e) => return fail(format!("cannot read audit key {key}: {e}")),
    };
    let Some(vk) = parse_verifying_key_hex(&key_text) else {
        return fail("audit key file is not a valid Ed25519 verifying key".into());
    };
    let cp_text = match read_bounded(Path::new(&cp), MAX_LINE_BYTES) {
        Ok(t) => t,
        Err(e) => return fail(format!("checkpoint {cp} unreadable: {e}")),
    };
    let log_text = match read_bounded(Path::new(&log), MAX_LOG_BYTES) {
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

struct LockArgs {
    log: String,
    checkpoint: String,
    audit_key_file: String,
    log_id: String,
    create: bool,
}

fn parse_lock_args(args: &[String]) -> Result<LockArgs, ExitCode> {
    let mut log = None;
    let mut checkpoint = None;
    let mut audit_key_file = None;
    let mut log_id = None;
    let mut create = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--create" => create = true,
            "--log" | "--checkpoint" | "--audit-key-file" | "--log-id" => {
                let Some(v) = it.next() else {
                    eprintln!("missing value for {a}\n{USAGE}");
                    return Err(ExitCode::from(2));
                };
                let slot = match a.as_str() {
                    "--log" => &mut log,
                    "--checkpoint" => &mut checkpoint,
                    "--audit-key-file" => &mut audit_key_file,
                    "--log-id" => &mut log_id,
                    _ => unreachable!(),
                };
                if slot.is_some() {
                    eprintln!("repeated argument {a}\n{USAGE}");
                    return Err(ExitCode::from(2));
                }
                *slot = Some(v.clone());
            }
            _ => {
                eprintln!("unknown argument {a:?}\n{USAGE}");
                return Err(ExitCode::from(2));
            }
        }
    }
    match (log, checkpoint, audit_key_file, log_id) {
        (Some(log), Some(checkpoint), Some(audit_key_file), Some(log_id)) => Ok(LockArgs {
            log,
            checkpoint,
            audit_key_file,
            log_id,
            create,
        }),
        _ => {
            eprintln!("{USAGE}");
            Err(ExitCode::from(2))
        }
    }
}

fn load_audit_seed(path: &str) -> Result<terminal_guard::keys::SigningKey, ExitCode> {
    let text = match read_bounded(Path::new(path), MAX_LINE_BYTES) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL: cannot read audit key file: {e}");
            return Err(ExitCode::from(1));
        }
    };
    parse_signing_key_hex(&text).ok_or_else(|| {
        eprintln!("FAIL: audit key file is not a 64-character hex seed");
        ExitCode::from(1)
    })
}

fn open_log(args: &LockArgs) -> Result<AuditLog, ExitCode> {
    let key = load_audit_seed(&args.audit_key_file)?;
    let log = Path::new(&args.log);
    let cp = Path::new(&args.checkpoint);
    let result = if args.create {
        AuditLog::create(log, cp, &args.log_id, key)
    } else {
        AuditLog::open(log, cp, &args.log_id, key).map(|(log, _)| log)
    };
    result.map_err(|e| {
        eprintln!("FAIL: {e}");
        ExitCode::from(1)
    })
}

/// Take the exclusive log lock, print `LOCKED`, and hold it until stdin closes.
fn hold_lock(args: &[String]) -> ExitCode {
    let args = match parse_lock_args(args) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let log = match open_log(&args) {
        Ok(log) => log,
        Err(code) => return code,
    };
    println!("LOCKED");
    let _ = io::stdout().flush();
    let mut stdin = io::stdin();
    let mut sink = [0u8; 256];
    loop {
        match stdin.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    drop(log);
    ExitCode::SUCCESS
}

struct ProxyArgs {
    policy: String,
    engine_id: String,
    log: String,
    checkpoint: String,
    audit_key_file: String,
    human_pubkey_file: String,
    contact_file: Option<String>,
    create: bool,
    timeout_secs: u64,
    downstream: Vec<String>,
}

fn parse_proxy_args(args: &[String]) -> Result<ProxyArgs, ExitCode> {
    let mut policy = None;
    let mut engine_id = None;
    let mut log = None;
    let mut checkpoint = None;
    let mut audit_key_file = None;
    let mut human_pubkey_file = None;
    let mut contact_file = None;
    let mut create = false;
    let mut timeout = None;
    let mut downstream = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            downstream.extend(it.cloned());
            break;
        }
        match a.as_str() {
            "--create" => create = true,
            "--policy"
            | "--engine-id"
            | "--log"
            | "--checkpoint"
            | "--audit-key-file"
            | "--human-pubkey-file"
            | "--contact-file"
            | "--timeout-secs" => {
                let Some(v) = it.next() else {
                    eprintln!("missing value for {a}\n{USAGE}");
                    return Err(ExitCode::from(2));
                };
                let slot = match a.as_str() {
                    "--policy" => &mut policy,
                    "--engine-id" => &mut engine_id,
                    "--log" => &mut log,
                    "--checkpoint" => &mut checkpoint,
                    "--audit-key-file" => &mut audit_key_file,
                    "--human-pubkey-file" => &mut human_pubkey_file,
                    "--contact-file" => &mut contact_file,
                    "--timeout-secs" => &mut timeout,
                    _ => unreachable!(),
                };
                if slot.is_some() {
                    eprintln!("repeated argument {a}\n{USAGE}");
                    return Err(ExitCode::from(2));
                }
                *slot = Some(v.clone());
            }
            _ => {
                eprintln!("unknown argument {a:?}\n{USAGE}");
                return Err(ExitCode::from(2));
            }
        }
    }
    let timeout_secs = match timeout.as_deref().map(str::parse::<u64>) {
        None => DEFAULT_TIMEOUT_SECS,
        Some(Ok(t)) if (1..=3600).contains(&t) => t,
        Some(_) => {
            eprintln!("--timeout-secs must be 1 to 3600\n{USAGE}");
            return Err(ExitCode::from(2));
        }
    };
    if downstream.is_empty() {
        eprintln!("mcp-proxy requires a downstream command after --\n{USAGE}");
        return Err(ExitCode::from(2));
    }
    match (
        policy,
        engine_id,
        log,
        checkpoint,
        audit_key_file,
        human_pubkey_file,
    ) {
        (
            Some(policy),
            Some(engine_id),
            Some(log),
            Some(checkpoint),
            Some(audit_key_file),
            Some(human_pubkey_file),
        ) => Ok(ProxyArgs {
            policy,
            engine_id,
            log,
            checkpoint,
            audit_key_file,
            human_pubkey_file,
            contact_file,
            create,
            timeout_secs,
            downstream,
        }),
        _ => {
            eprintln!("{USAGE}");
            Err(ExitCode::from(2))
        }
    }
}

fn mcp_proxy(args: &[String]) -> ExitCode {
    let args = match parse_proxy_args(args) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let fail = |msg: String| {
        eprintln!("FAIL: {msg}");
        ExitCode::from(1)
    };
    let policy_text = match read_bounded(Path::new(&args.policy), MAX_POLICY_BYTES) {
        Ok(t) => t,
        Err(e) => return fail(format!("cannot read policy: {e}")),
    };
    let policy = match Policy::from_toml(&policy_text) {
        Ok(p) => p,
        Err(e) => return fail(e.to_string()),
    };
    let human_text = match read_bounded(Path::new(&args.human_pubkey_file), MAX_LINE_BYTES) {
        Ok(t) => t,
        Err(e) => return fail(format!("cannot read human key: {e}")),
    };
    let Some(human) = parse_verifying_key_hex(&human_text) else {
        return fail("human pubkey file is not a valid Ed25519 verifying key".into());
    };
    let lock_args = LockArgs {
        log: args.log,
        checkpoint: args.checkpoint,
        audit_key_file: args.audit_key_file,
        log_id: args.engine_id.clone(),
        create: args.create,
    };
    let audit = match open_log(&lock_args) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let clock = SystemClock::new();
    let mut guard = match Guard::new(policy, &args.engine_id, vec![human], 0, audit, clock) {
        Ok(g) => g,
        Err(e) => return fail(e.to_string()),
    };
    if let Some(path) = &args.contact_file {
        let text = match read_bounded(Path::new(path), MAX_LINE_BYTES) {
            Ok(t) => t,
            Err(e) => return fail(format!("cannot read contact file: {e}")),
        };
        let contact = match SignedContact::from_json(&text) {
            Ok(c) => c,
            Err(e) => return fail(format!("contact file rejected: {e}")),
        };
        if let Err(e) = guard.apply_signed_approval(&contact) {
            return fail(format!("contact rejected: {e}"));
        }
    }

    let mut child = match Command::new(&args.downstream[0])
        .args(&args.downstream[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot start downstream: {e}")),
    };
    let mut downstream_in = match child.stdin.take() {
        Some(s) => s,
        None => return fail("downstream stdin missing".into()),
    };
    let downstream_out = match child.stdout.take() {
        Some(s) => s,
        None => return fail("downstream stdout missing".into()),
    };
    // A reader thread lets the proxy give up on a downstream server that
    // stops answering, instead of blocking forever.
    let (tx, rx) = mpsc::channel::<io::Result<Option<String>>>();
    thread::spawn(move || {
        let mut reader = BufReader::new(downstream_out);
        loop {
            let msg = read_message(&mut reader);
            let stop = !matches!(msg, Ok(Some(_)));
            if tx.send(msg).is_err() || stop {
                break;
            }
        }
    });
    let timeout = Duration::from_secs(args.timeout_secs);
    let stdin = io::stdin();
    let mut client_in = BufReader::new(stdin.lock());
    let mut client_out = io::stdout();

    loop {
        let text = match read_message(&mut client_in) {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(e) => {
                eprintln!("FAIL: client message: {e}");
                let _ = child.kill();
                return ExitCode::from(1);
            }
        };
        match evaluate(&mut guard, &text) {
            ProxyOutcome::Forward { request, id } => {
                if let Err(e) = write_message(&mut downstream_in, &request) {
                    eprintln!("FAIL: downstream write: {e}");
                    let _ = child.kill();
                    return ExitCode::from(1);
                }
                let Some(id) = id else { continue };
                if let Err(why) =
                    relay_response(&rx, &id, timeout, &mut downstream_in, &mut client_out)
                {
                    eprintln!("FAIL: {why}");
                    let body =
                        error_body(Some(id), -32003, &format!("terminal-guard: {why}"), None);
                    let _ = write_message(&mut client_out, &body);
                    let _ = child.kill();
                    return ExitCode::from(1);
                }
            }
            ProxyOutcome::Block { response } => {
                if let Some(response) = response {
                    if write_message(&mut client_out, &response).is_err() {
                        let _ = child.kill();
                        return ExitCode::from(1);
                    }
                }
            }
        }
    }
    drop(downstream_in);
    let _ = child.wait();
    ExitCode::SUCCESS
}

/// Wait for the downstream response to `id` and relay it to the client.
///
/// Notifications on the way are relayed. Requests from the server are
/// answered with an error and not relayed. Anything else (bad JSON, a
/// response with another id, a timeout, the server exiting) is an error, and
/// the caller shuts the proxy down.
fn relay_response(
    rx: &mpsc::Receiver<io::Result<Option<String>>>,
    id: &serde_json::Value,
    timeout: Duration,
    downstream_in: &mut impl Write,
    client_out: &mut impl Write,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let msg = match rx.recv_timeout(left) {
            Ok(Ok(Some(m))) => m,
            Ok(Ok(None)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("downstream server closed".into());
            }
            Ok(Err(e)) => return Err(format!("downstream message: {e}")),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("downstream server timed out".into());
            }
        };
        match classify_downstream(&msg, id) {
            DownstreamMessage::Response => {
                return write_message(client_out, &msg).map_err(|e| format!("client write: {e}"));
            }
            DownstreamMessage::Notification => {
                write_message(client_out, &msg).map_err(|e| format!("client write: {e}"))?;
            }
            DownstreamMessage::ServerRequest { id: server_id } => {
                let body = error_body(
                    Some(server_id),
                    -32601,
                    "server requests are not supported through terminal-guard mcp-proxy",
                    None,
                );
                write_message(downstream_in, &body)
                    .map_err(|e| format!("downstream write: {e}"))?;
            }
            DownstreamMessage::Invalid(why) => return Err(format!("downstream sent {why}")),
        }
    }
}
