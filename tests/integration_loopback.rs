//! Real-time, multi-process integration tests over a loopback-only approval
//! channel.
//!
//! Run with:
//!   cargo test --test integration_loopback -- --ignored
//!
//! What is real here: separate OS processes, a real TCP socket bound to
//! 127.0.0.1 that is actually closed and reopened, the real monotonic clock
//! (`SystemClock`) with a seconds-scale test policy, real Ed25519 signing by
//! a supervisor key, real files and a real process kill/restart.
//!
//! What it is NOT: evidence of a physical network unplug, a remote-host
//! partition, or behavior on other machines. Both processes run on one host.
//!
//! Layout: the test process is the harness and plays the supervisor. It
//! re-runs its own test binary as the mock agent (`agent_process_entry`,
//! which does nothing unless `TG_IT_AGENT=1`). The agent:
//!   * owns a `Guard` with `SystemClock`,
//!   * listens on 127.0.0.1:<ephemeral> for signed renewal messages (one JSON
//!     line each, reply `OK ...` or `ERR <code>`),
//!   * takes harness commands on stdin (`STATUS`, `DO <action>`, `QUIT`) and
//!     answers on stdout with lines prefixed `TG|`,
//!   * enforces each decision before running a harmless local action;
//!     `needs_approval` is never executed.
//!
//! Keys are generated per run in memory. The audit signing key reaches the
//! child through an environment variable and is never written to disk.
//! Artifacts go under `target/tmp/tg-integration/` (git-ignored).

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use terminal_guard::keys::{SigningKey, VerifyingKey, generate, verifying_key_hex};
use terminal_guard::{AuditLog, ContactAuth, Decision, Guard, Policy, SignedContact, SystemClock};

const ENGINE: &str = "it-agent-01";
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_LINE: u64 = 8192;

/// Seconds-scale policy for the real-time lifecycle test.
const FAST_POLICY: &str = r#"
version = 1
[levels]
degraded_after_secs = 3
lost_after_secs = 6
hold_after_secs = 9
[contact]
max_age_secs = 3
max_future_skew_secs = 1
[actions.read_local_fixture]
connected = "allow"
degraded = "allow"
lost = "allow"
hold = "deny"
[actions.draft_local_note]
connected = "allow"
degraded = "allow"
lost = "needs_approval"
hold = "deny"
[actions.send_external_message]
connected = "needs_approval"
degraded = "needs_approval"
lost = "deny"
hold = "deny"
[actions.delete_local_file]
connected = "needs_approval"
degraded = "deny"
lost = "deny"
hold = "deny"
"#;

const ACTIONS: [&str; 4] = [
    "read_local_fixture",
    "draft_local_note",
    "send_external_message",
    "delete_local_file",
];

/// Same actions, slower schedule and a 30 s freshness window, so the restart
/// test can re-present a still-fresh message without tight timing.
fn slow_policy() -> String {
    FAST_POLICY
        .replace("degraded_after_secs = 3", "degraded_after_secs = 60")
        .replace("lost_after_secs = 6", "lost_after_secs = 120")
        .replace("hold_after_secs = 9", "hold_after_secs = 180")
        .replace("max_age_secs = 3", "max_age_secs = 30")
}

// =====================================================================
// Mock agent (child process)
// =====================================================================

enum Event {
    Cmd(String),
    StdinClosed,
    Contact(String, Sender<String>),
    Conn(i32),
}

/// Entry point for the agent child process. No-op in a normal test run.
#[test]
#[ignore = "mock agent entry point; only active when spawned by the harness"]
fn agent_process_entry() {
    if std::env::var("TG_IT_AGENT").as_deref() != Ok("1") {
        return;
    }
    let code = match run_agent() {
        Ok(()) => 0,
        Err(e) => {
            println!("TG|FATAL {e}");
            3
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing env {name}"))
}

fn run_agent() -> Result<(), String> {
    let dir = PathBuf::from(env("TG_IT_DIR")?);
    let human = parse_pub(&env("TG_IT_HUMAN_PUB")?)?;
    let audit_key = parse_secret(&env("TG_IT_AUDIT_SK")?)?;
    let policy =
        Policy::from_toml(&fs::read_to_string(dir.join("policy.toml")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;

    let (log_path, cp_path) = (dir.join("audit.log"), dir.join("audit.cp"));
    // Restart path: verify the existing log first and restore the replay
    // floor from it. Any verification failure refuses to start.
    let (audit, next_seq) = if log_path.exists() {
        let (a, report) = AuditLog::open(&log_path, &cp_path, ENGINE, audit_key)
            .map_err(|e| format!("audit log failed verification on startup: {e}"))?;
        (a, report.last_contact_sequence.map_or(0, |s| s + 1))
    } else {
        let a =
            AuditLog::create(&log_path, &cp_path, ENGINE, audit_key).map_err(|e| e.to_string())?;
        (a, 0)
    };
    let mut guard = Guard::new(
        policy,
        ENGINE,
        vec![human],
        next_seq,
        audit,
        SystemClock::new(),
    )
    .map_err(|e| e.to_string())?;

    // Loopback only.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;

    let (tx, rx) = mpsc::channel::<Event>();
    let tx_net = tx.clone();
    thread::spawn(move || accept_loop(listener, tx_net));
    let tx_in = tx;
    thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx_in.send(Event::Cmd(l)).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx_in.send(Event::StdinClosed);
    });

    let level = guard.tick();
    println!(
        "TG|READY addr={addr} level={} next_seq={next_seq}",
        level.as_str()
    );
    let _ = std::io::stdout().flush();

    let mut links: i32 = 0;
    while let Ok(ev) = rx.recv() {
        match ev {
            Event::Conn(d) => links += d,
            Event::Contact(line, reply) => {
                let r = match guard.accept_contact_json(&line) {
                    Ok(()) => format!("OK level={}", guard.tick().as_str()),
                    Err(e) => format!("ERR {}", e.code()),
                };
                let _ = reply.send(r);
            }
            Event::StdinClosed => break,
            Event::Cmd(c) => {
                let c = c.trim();
                if c == "QUIT" {
                    println!("TG|BYE");
                    break;
                } else if c == "STATUS" {
                    let level = guard.tick();
                    let mut s = format!(
                        "TG|STATUS level={} transport={} poisoned={}",
                        level.as_str(),
                        if links > 0 { "up" } else { "down" },
                        guard.is_poisoned()
                    );
                    // Pure policy lookup: does not log a decision.
                    for a in ACTIONS {
                        s.push_str(&format!(
                            " {a}={}",
                            guard.policy().decide(a, level).as_str()
                        ));
                    }
                    println!("{s}");
                } else if let Some(action) = c.strip_prefix("DO ") {
                    let decision = guard.decide(action);
                    // Enforce BEFORE acting. Only Allow executes.
                    let executed = match decision {
                        Decision::Allow => perform(&dir, action).is_ok(),
                        Decision::NeedsApproval | Decision::Deny => false,
                    };
                    println!(
                        "TG|DID action={action} decision={} executed={executed}",
                        decision.as_str()
                    );
                } else {
                    println!("TG|UNKNOWN");
                }
            }
        }
        let _ = std::io::stdout().flush();
    }
    let _ = std::io::stdout().flush();
    Ok(())
}

/// Harmless local stand-ins. Nothing leaves the work directory and nothing
/// touches the network; "send_external_message" only appends to a local
/// outbox file, and only if the policy said Allow (it never does here).
fn perform(dir: &Path, action: &str) -> std::io::Result<()> {
    let append = |name: &str, text: &str| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))?;
        writeln!(f, "{text}")
    };
    match action {
        "read_local_fixture" => fs::read_to_string(dir.join("fixture.txt")).map(|_| ())?,
        "draft_local_note" => append("drafts.txt", "draft note")?,
        "send_external_message" => append("outbox.txt", "MOCK message (never sent anywhere)")?,
        "delete_local_file" => {
            let _ = fs::remove_file(dir.join("scratch.txt"));
        }
        _ => return Err(std::io::Error::other("no such action")),
    }
    append("executed.txt", action)
}

fn accept_loop(listener: TcpListener, tx: Sender<Event>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // Defense in depth: only loopback peers.
        if !stream
            .peer_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false)
        {
            continue;
        }
        let tx = tx.clone();
        thread::spawn(move || handle_link(stream, tx));
    }
}

fn handle_link(stream: TcpStream, tx: Sender<Event>) {
    if tx.send(Event::Conn(1)).is_err() {
        return;
    }
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match (&mut reader).take(MAX_LINE).read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let reply = if !line.ends_with('\n') {
            // Over-long line: reject and drop the link.
            let _ = writer.write_all(b"ERR malformed\n");
            break;
        } else if is_scanner_noise(&line) {
            // Something other than the harness connected (a port probe).
            // Do not log it as a contact attempt.
            continue;
        } else {
            let (rtx, rrx) = mpsc::channel();
            if tx
                .send(Event::Contact(line.trim_end().to_string(), rtx))
                .is_err()
            {
                break;
            }
            rrx.recv_timeout(STEP_TIMEOUT)
                .unwrap_or_else(|_| "ERR timeout".into())
        };
        if writer.write_all(format!("{reply}\n").as_bytes()).is_err() {
            break;
        }
    }
    let _ = tx.send(Event::Conn(-1));
}

/// The harness speaks JSON lines, plus one deliberate `not json` probe.
/// Anything else on the loopback port is a scanner, not a contact attempt.
fn is_scanner_noise(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || (!t.starts_with('{') && t != "not json")
}

fn parse_pub(s: &str) -> Result<VerifyingKey, String> {
    terminal_guard::keys::parse_verifying_key_hex(s).ok_or_else(|| "bad human pubkey".into())
}

fn parse_secret(s: &str) -> Result<SigningKey, String> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut b).map_err(|_| "bad audit key".to_string())?;
    Ok(SigningKey::from_bytes(&b))
}

// =====================================================================
// Harness (test process)
// =====================================================================

struct Run {
    dir: PathBuf,
    human: SigningKey,
    audit: SigningKey,
}

impl Run {
    fn new(name: &str, policy: &str) -> Run {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("tg-integration")
            .join(format!("{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("policy.toml"), policy).unwrap();
        fs::write(dir.join("fixture.txt"), "harmless local fixture\n").unwrap();
        fs::write(dir.join("scratch.txt"), "scratch\n").unwrap();
        let audit = generate();
        // Public key only, for the verify CLI. Private keys never touch disk.
        fs::write(
            dir.join("audit.pub"),
            verifying_key_hex(&audit.verifying_key()) + "\n",
        )
        .unwrap();
        eprintln!("[harness] artifacts: {}", dir.display());
        Run {
            dir,
            human: generate(),
            audit,
        }
    }

    fn spawn(&self) -> Result<Agent, String> {
        Agent::spawn(&self.dir, &self.human.verifying_key(), &self.audit)
    }

    fn sign(&self, seq: u64, issued_ms: u64) -> String {
        ContactAuth::new(ENGINE, seq, issued_ms)
            .sign(&self.human)
            .to_json()
    }

    fn verify_cli(&self, log: &Path, cp: &Path, prefix: bool) -> (i32, String) {
        verify_cli(log, cp, &self.dir.join("audit.pub"), prefix)
    }
}

fn verify_cli(log: &Path, cp: &Path, pubf: &Path, prefix: bool) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_terminal-guard"));
    c.arg("verify")
        .arg("--log")
        .arg(log)
        .arg("--checkpoint")
        .arg(cp);
    c.arg("--audit-pubkey").arg(pubf).args(["--log-id", ENGINE]);
    if prefix {
        c.arg("--prefix");
    }
    let out = c.output().expect("run terminal-guard verify");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text.trim().to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct Agent {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
    addr: SocketAddr,
    ready: BTreeMap<String, String>,
}

impl Agent {
    fn spawn(dir: &Path, human: &VerifyingKey, audit: &SigningKey) -> Result<Agent, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut child = Command::new(exe)
            .args([
                "--exact",
                "agent_process_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("TG_IT_AGENT", "1")
            .env("TG_IT_DIR", dir)
            .env("TG_IT_HUMAN_PUB", verifying_key_hex(human))
            .env("TG_IT_AUDIT_SK", hex::encode(audit.to_bytes()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn agent: {e}"))?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stdin = child.stdin.take();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                // libtest prints its own text (possibly on the same line);
                // keep only what follows the protocol marker.
                if let Some(i) = line.find("TG|") {
                    if tx.send(line[i + 3..].to_string()).is_err() {
                        return;
                    }
                }
            }
        });
        let mut a = Agent {
            child,
            stdin,
            rx,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            ready: BTreeMap::new(),
        };
        let line = a.next_line("READY")?;
        if let Some(fatal) = line.strip_prefix("FATAL ") {
            let _ = a.child.wait();
            return Err(fatal.to_string());
        }
        a.ready = kv(&line);
        a.addr = a.ready["addr"].parse().map_err(|_| "bad addr")?;
        assert!(a.addr.ip().is_loopback(), "agent must bind loopback only");
        Ok(a)
    }

    fn next_line(&self, waiting_for: &str) -> Result<String, String> {
        match self.rx.recv_timeout(STEP_TIMEOUT) {
            Ok(l) => Ok(l),
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "timed out after {STEP_TIMEOUT:?} waiting for agent {waiting_for}"
            )),
            Err(RecvTimeoutError::Disconnected) => {
                Err(format!("agent exited while waiting for {waiting_for}"))
            }
        }
    }

    fn cmd(&mut self, c: &str, expect: &str) -> String {
        let stdin = self.stdin.as_mut().expect("agent stdin open");
        writeln!(stdin, "{c}").expect("write to agent");
        stdin.flush().unwrap();
        let line = self.next_line(expect).unwrap();
        assert!(line.starts_with(expect), "expected {expect}, got {line:?}");
        line
    }

    fn status(&mut self) -> BTreeMap<String, String> {
        kv(&self.cmd("STATUS", "STATUS"))
    }

    fn level(&mut self) -> String {
        self.status()["level"].clone()
    }

    fn act(&mut self, action: &str) -> (String, bool) {
        let m = kv(&self.cmd(&format!("DO {action}"), "DID"));
        (m["decision"].clone(), m["executed"] == "true")
    }

    fn quit(mut self) {
        self.cmd("QUIT", "BYE");
        drop(self.stdin.take());
        let start = Instant::now();
        while start.elapsed() < STEP_TIMEOUT {
            if let Ok(Some(st)) = self.child.try_wait() {
                assert!(st.success(), "agent exit status {st}");
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("agent did not exit within {STEP_TIMEOUT:?}");
    }

    /// Hard kill (simulated crash). Caller should make sure the agent is idle.
    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kv(line: &str) -> BTreeMap<String, String> {
    line.split_whitespace()
        .filter_map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Supervisor side of the approval channel.
struct Link {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Link {
    fn connect(addr: SocketAddr) -> Link {
        let stream = TcpStream::connect_timeout(&addr, STEP_TIMEOUT).expect("connect to agent");
        stream.set_read_timeout(Some(STEP_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(STEP_TIMEOUT)).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        Link { stream, reader }
    }
    fn send(&mut self, line: &str) -> String {
        self.stream
            .write_all(format!("{line}\n").as_bytes())
            .expect("send renewal");
        let mut r = String::new();
        self.reader
            .read_line(&mut r)
            .expect("reply from agent (timed out?)");
        r.trim().to_string()
    }
    /// Real disconnect: shut the socket down in both directions and drop it.
    fn close(self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

fn rank(d: &str) -> u8 {
    match d {
        "deny" => 0,
        "needs_approval" => 1,
        "allow" => 2,
        other => panic!("unknown decision {other}"),
    }
}

fn lvl_rank(l: &str) -> u8 {
    match l {
        "connected" => 0,
        "degraded" => 1,
        "lost" => 2,
        "hold" => 3,
        other => panic!("unknown level {other}"),
    }
}

/// Poll until the agent reaches `target`, checking that levels never improve
/// and no action ever gains permission along the way. Returns levels seen.
fn watch_decay(agent: &mut Agent, target: &str, limit: Duration) -> Vec<String> {
    let start = Instant::now();
    let mut seen: Vec<String> = Vec::new();
    let mut prev: Option<BTreeMap<String, String>> = None;
    loop {
        let s = agent.status();
        if let Some(p) = &prev {
            assert!(
                lvl_rank(&s["level"]) >= lvl_rank(&p["level"]),
                "level improved: {p:?} -> {s:?}"
            );
            for a in ACTIONS {
                assert!(
                    rank(&s[a]) <= rank(&p[a]),
                    "{a} widened: {} -> {}",
                    p[a],
                    s[a]
                );
            }
        }
        if seen.last() != Some(&s["level"]) {
            eprintln!(
                "[harness] t+{:>5.1}s level={}",
                start.elapsed().as_secs_f32(),
                s["level"]
            );
            seen.push(s["level"].clone());
        }
        if s["level"] == target {
            return seen;
        }
        assert!(
            start.elapsed() < limit,
            "did not reach {target} within {limit:?}; seen {seen:?}"
        );
        prev = Some(s);
        thread::sleep(Duration::from_millis(200));
    }
}

// =====================================================================
// Tests
// =====================================================================

/// Full lost-link lifecycle over a real loopback socket and real time.
#[test]
#[ignore = "real-time multi-process test (~12 s); run with --ignored"]
fn lifecycle_disconnect_decay_reconnect_restore() {
    let run = Run::new("lifecycle", FAST_POLICY);
    let mut agent = run.spawn().unwrap();

    // 1. Starts in hold; nothing runs.
    assert_eq!(agent.ready["level"], "hold");
    assert_eq!(agent.act("read_local_fixture"), ("deny".into(), false));

    // 2. Supervisor connects and sends a fresh signed renewal.
    let mut link = Link::connect(agent.addr);
    assert_eq!(link.send(&run.sign(1, now_ms())), "OK level=connected");
    let s = agent.status();
    assert_eq!(
        (s["level"].as_str(), s["transport"].as_str()),
        ("connected", "up")
    );
    assert_eq!(agent.act("read_local_fixture"), ("allow".into(), true));
    // needs_approval is reported, never executed.
    assert_eq!(
        agent.act("send_external_message"),
        ("needs_approval".into(), false)
    );
    assert!(
        !run.dir.join("outbox.txt").exists(),
        "needs_approval must not execute"
    );

    // 3. Real disconnect. Permissions decay on schedule, never widen.
    link.close();
    let seen = watch_decay(&mut agent, "hold", Duration::from_secs(20));
    assert!(
        seen.contains(&"degraded".into()) && seen.contains(&"lost".into()),
        "seen {seen:?}"
    );
    assert_eq!(agent.status()["transport"], "down");

    // 4. Reconnect alone does nothing.
    let mut link = Link::connect(agent.addr);
    thread::sleep(Duration::from_millis(1500));
    let s = agent.status();
    assert_eq!(
        (s["level"].as_str(), s["transport"].as_str()),
        ("hold", "up")
    );
    assert_eq!(agent.act("read_local_fixture"), ("deny".into(), false));

    // 5. Bad renewals are rejected and change nothing.
    let other = generate();
    let n = now_ms();
    assert_eq!(link.send(&run.sign(1, n)), "ERR replay"); // already-used sequence
    assert_eq!(link.send(&run.sign(2, n - 10_000)), "ERR stale");
    assert_eq!(link.send(&run.sign(2, n + 10_000)), "ERR from_future");
    assert_eq!(
        link.send(&ContactAuth::new(ENGINE, 2, n).sign(&other).to_json()),
        "ERR bad_signature"
    );
    assert_eq!(
        link.send(&run.audit_sign_as_contact(2, n)),
        "ERR bad_signature"
    );
    assert_eq!(
        link.send(
            &ContactAuth::new("other-engine", 2, n)
                .sign(&run.human)
                .to_json()
        ),
        "ERR wrong_engine"
    );
    let mut tampered: SignedContact = serde_json::from_str(&run.sign(2, n)).unwrap();
    tampered.body.sequence = 99;
    assert_eq!(link.send(&tampered.to_json()), "ERR bad_signature");
    assert_eq!(link.send("not json"), "ERR malformed");
    assert_eq!(agent.level(), "hold");

    // 6. A new, fresh signed renewal restores contact permissions only.
    assert_eq!(link.send(&run.sign(2, now_ms())), "OK level=connected");
    assert_eq!(agent.act("draft_local_note"), ("allow".into(), true));
    assert_eq!(
        agent.act("send_external_message"),
        ("needs_approval".into(), false)
    );
    assert!(!run.dir.join("outbox.txt").exists());
    link.close();
    agent.quit();

    // 7. The log verifies against the pinned audit key and records levels.
    let (code, out) = run.verify_cli(&run.dir.join("audit.log"), &run.dir.join("audit.cp"), false);
    eprintln!("[harness] verify: {out}");
    assert_eq!(code, 0, "{out}");
    let log = fs::read_to_string(run.dir.join("audit.log")).unwrap();
    for to in ["degraded", "lost", "hold"] {
        assert!(
            log.contains(&format!("\"to\":\"{to}\"")),
            "missing step-down to {to}"
        );
    }
    assert_eq!(log.matches("\"kind\":\"contact_rejected\"").count(), 8);
    let executed = fs::read_to_string(run.dir.join("executed.txt")).unwrap();
    assert_eq!(executed, "read_local_fixture\ndraft_local_note\n");
}

impl Run {
    /// A renewal signed with the AUDIT key (wrong role) must be rejected.
    fn audit_sign_as_contact(&self, seq: u64, issued: u64) -> String {
        ContactAuth::new(ENGINE, seq, issued)
            .sign(&self.audit)
            .to_json()
    }
}

/// Replay floor survives a real process kill and restart, via the verified
/// audit log. Also shows the caveat when no log is carried over.
#[test]
#[ignore = "real-time multi-process test (~2 s); run with --ignored"]
fn restart_recovers_replay_floor_from_verified_log() {
    let run = Run::new("restart", &slow_policy());
    let mut agent = run.spawn().unwrap();
    assert_eq!(agent.ready["next_seq"], "0");
    let msg1 = run.sign(1, now_ms());
    let mut link = Link::connect(agent.addr);
    assert_eq!(link.send(&msg1), "OK level=connected");
    assert_eq!(agent.act("read_local_fixture"), ("allow".into(), true));
    link.close();
    agent.status(); // round trip: agent is idle
    agent.kill(); // simulated crash

    // Restart: verifies the log, restores next_seq = 2, starts in hold.
    let mut agent = run.spawn().unwrap();
    assert_eq!(agent.ready["level"], "hold");
    assert_eq!(agent.ready["next_seq"], "2");
    let mut link = Link::connect(agent.addr);
    // msg1 is still inside the 30 s freshness window, but already used.
    assert_eq!(link.send(&msg1), "ERR replay");
    assert_eq!(agent.level(), "hold");
    assert_eq!(link.send(&run.sign(2, now_ms())), "OK level=connected");
    link.close();
    agent.quit();
    let (code, out) = run.verify_cli(&run.dir.join("audit.log"), &run.dir.join("audit.cp"), false);
    assert_eq!(code, 0, "{out}");

    // Caveat demo: an instance with the same engine ID but WITHOUT the old
    // log has no replay floor, so the still-fresh msg1 is accepted there.
    let fresh = Run {
        dir: run.dir.join("no-log-carried-over"),
        human: run.human.clone(),
        audit: generate(),
    };
    fs::create_dir_all(&fresh.dir).unwrap();
    fs::write(fresh.dir.join("policy.toml"), slow_policy()).unwrap();
    let agent = fresh.spawn().unwrap();
    let mut link = Link::connect(agent.addr);
    assert_eq!(
        link.send(&msg1),
        "OK level=connected",
        "documented caveat: no floor without the log"
    );
    link.close();
    agent.quit();
}

/// Tampering with the newest entries is caught against a retained latest
/// checkpoint; a joint rollback of log + checkpoint is NOT caught file-only.
#[test]
#[ignore = "multi-process test (~1 s); run with --ignored"]
fn log_tampering_vs_retained_checkpoint() {
    let run = Run::new("tamper", &slow_policy());
    let mut agent = run.spawn().unwrap();
    let mut link = Link::connect(agent.addr);
    assert_eq!(link.send(&run.sign(1, now_ms())), "OK level=connected");
    agent.act("read_local_fixture");
    agent.status();
    // Early consistent snapshot (what an attacker might roll back to).
    let snap = run.dir.join("snapshot");
    fs::create_dir_all(&snap).unwrap();
    fs::copy(run.dir.join("audit.log"), snap.join("audit.log")).unwrap();
    fs::copy(run.dir.join("audit.cp"), snap.join("audit.cp")).unwrap();
    agent.act("draft_local_note");
    agent.act("send_external_message");
    link.close();
    agent.quit();

    // Retained copy of the latest checkpoint, kept "somewhere else".
    let retained = run.dir.join("retained-latest.cp");
    fs::copy(run.dir.join("audit.cp"), &retained).unwrap();
    let log_path = run.dir.join("audit.log");
    let original = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = original.lines().collect();
    let write_variant = |name: &str, text: &str| -> PathBuf {
        let p = run.dir.join(name);
        fs::write(&p, text).unwrap();
        p
    };

    let (code, out) = run.verify_cli(&log_path, &retained, false);
    assert_eq!(code, 0, "intact: {out}");

    let deleted = write_variant(
        "deleted-newest.log",
        &(lines[..lines.len() - 1].join("\n") + "\n"),
    );
    let (code, out) = run.verify_cli(&deleted, &retained, false);
    eprintln!("[harness] deleted newest: {out}");
    assert_eq!(code, 1);

    let last = lines[lines.len() - 1];
    let edited_last = last.replacen(
        "\"decision\":\"needs_approval\"",
        "\"decision\":\"allow\"",
        1,
    );
    assert_ne!(edited_last, last);
    let mut v = lines.clone();
    let n = v.len();
    v[n - 1] = &edited_last;
    let edited = write_variant("edited-newest.log", &(v.join("\n") + "\n"));
    let (code, out) = run.verify_cli(&edited, &retained, false);
    eprintln!("[harness] edited newest: {out}");
    assert_eq!(code, 1);

    let truncated = write_variant("truncated-newest.log", &original[..original.len() - 25]);
    let (code, out) = run.verify_cli(&truncated, &retained, false);
    eprintln!("[harness] truncated newest: {out}");
    assert_eq!(code, 1);

    let wrong_pub = run.dir.join("wrong.pub");
    fs::write(&wrong_pub, verifying_key_hex(&generate().verifying_key())).unwrap();
    assert_eq!(
        verify_cli(&log_path, &retained, &wrong_pub, false).0,
        1,
        "wrong pinned key"
    );

    // Agent refuses to restart on a tampered log.
    fs::write(&log_path, fs::read_to_string(&deleted).unwrap()).unwrap();
    let err = run.spawn().err().expect("agent must refuse a tampered log");
    eprintln!("[harness] restart on tampered log refused: {err}");
    assert!(err.contains("failed verification"));
    fs::write(&log_path, &original).unwrap();

    // KNOWN LIMIT: roll back log AND checkpoint together to the snapshot.
    let (code, out) = run.verify_cli(&snap.join("audit.log"), &snap.join("audit.cp"), false);
    eprintln!("[harness] joint rollback, file-only check (limitation): {out}");
    assert_eq!(
        code, 0,
        "file-only verification cannot detect a joint rollback"
    );
    // Only the separately retained latest checkpoint catches it.
    assert_eq!(
        run.verify_cli(&snap.join("audit.log"), &retained, false).0,
        1
    );
    assert_eq!(
        run.verify_cli(&snap.join("audit.log"), &retained, true).0,
        1
    );
    // And an older retained checkpoint still accepts the grown, honest log.
    assert_eq!(run.verify_cli(&log_path, &snap.join("audit.cp"), true).0, 0);
}
