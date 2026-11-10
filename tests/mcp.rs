//! MCP proxy: only an allowed tools/call is forwarded. Everything else is blocked.
//! The process test runs the real command against a downstream echo binary.

mod common;

use std::io::BufReader;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::Fixture;
use serde_json::{Value, json};
use terminal_guard::keys::{signing_key_hex, verifying_key_hex};
use terminal_guard::mcp::{ProxyOutcome, evaluate, read_frame, write_frame};
use terminal_guard::{ActionApproval, ContactAuth, Decision};

const PROXY_POLICY: &str = r#"
version = 1
[levels]
degraded_after_secs = 600
lost_after_secs = 3600
hold_after_secs = 14400
[contact]
max_age_secs = 120
max_future_skew_secs = 30
[actions.safe_tool]
connected = "allow"
degraded = "allow"
lost = "allow"
hold = "deny"
[actions.careful_tool]
connected = "needs_approval"
degraded = "needs_approval"
lost = "deny"
hold = "deny"
[actions.never_tool]
connected = "deny"
degraded = "deny"
lost = "deny"
hold = "deny"
"#;

fn call(id: i64, name: &str, approval: Option<Value>) -> String {
    let mut params = json!({ "name": name, "arguments": { "x": 1 } });
    if let Some(approval) = approval {
        params["_terminal_guard_approval"] = approval;
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": params
    })
    .to_string()
}

#[test]
fn framing_roundtrip() {
    let mut buf = Vec::new();
    write_frame(&mut buf, r#"{"ok":true}"#).unwrap();
    let mut cursor = std::io::Cursor::new(buf);
    let body = read_frame(&mut cursor).unwrap().unwrap();
    assert_eq!(body, br#"{"ok":true}"#);
}

#[test]
fn evaluate_blocks_everything_except_an_allowed_tool_call() {
    let mut f = Fixture::new();
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    assert!(matches!(
        evaluate(&mut f.guard, init),
        ProxyOutcome::Block { .. }
    ));

    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    assert!(matches!(
        evaluate(&mut f.guard, list),
        ProxyOutcome::Block { .. }
    ));

    // Still in hold: the example policy denies read_local_fixture.
    match evaluate(&mut f.guard, &call(3, "read_local_fixture", None)) {
        ProxyOutcome::Block { response } => {
            let v: Value = serde_json::from_str(response.unwrap().as_str()).unwrap();
            assert_eq!(v["error"]["code"], -32002);
        }
        ProxyOutcome::Forward { .. } => panic!("deny must not be forwarded"),
    }

    let msg = ContactAuth::new(common::ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&msg).unwrap();

    match evaluate(&mut f.guard, &call(4, "read_local_fixture", None)) {
        ProxyOutcome::Forward { request } => {
            let v: Value = serde_json::from_str(&request).unwrap();
            assert!(v["params"].get("_terminal_guard_approval").is_none());
            assert_eq!(v["params"]["name"], "read_local_fixture");
        }
        ProxyOutcome::Block { response } => panic!("allow was blocked: {response:?}"),
    }

    match evaluate(&mut f.guard, &call(5, "send_external_message", None)) {
        ProxyOutcome::Block { response } => {
            let v: Value = serde_json::from_str(response.unwrap().as_str()).unwrap();
            assert_eq!(v["error"]["code"], -32001);
        }
        ProxyOutcome::Forward { .. } => panic!("needs_approval must not be forwarded"),
    }
}

#[test]
fn proxy_forwards_only_allowed_calls_to_a_real_process() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, PROXY_POLICY).unwrap();

    let human = terminal_guard::keys::generate();
    let audit = terminal_guard::keys::generate();
    let human_path = dir.path().join("human.pub");
    let audit_path = dir.path().join("audit.seed");
    std::fs::write(&human_path, verifying_key_hex(&human.verifying_key())).unwrap();
    std::fs::write(&audit_path, signing_key_hex(&audit)).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let contact = ContactAuth::new("proxy-engine", 1, now).sign(&human);
    let contact_path = dir.path().join("contact.json");
    std::fs::write(&contact_path, contact.to_json()).unwrap();

    let careful = ActionApproval::new("proxy-engine", "careful_tool", 1, now).sign(&human);
    let careful_json = serde_json::to_value(&careful).unwrap();
    let never = ActionApproval::new("proxy-engine", "never_tool", 2, now).sign(&human);
    let never_json = serde_json::to_value(&never).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_terminal-guard"))
        .args([
            "mcp-proxy",
            "--policy",
            policy_path.to_str().unwrap(),
            "--engine-id",
            "proxy-engine",
            "--log",
            dir.path().join("a.log").to_str().unwrap(),
            "--checkpoint",
            dir.path().join("a.cp").to_str().unwrap(),
            "--audit-key-file",
            audit_path.to_str().unwrap(),
            "--human-pubkey-file",
            human_path.to_str().unwrap(),
            "--contact-file",
            contact_path.to_str().unwrap(),
            "--create",
            "--",
            env!("CARGO_BIN_EXE_mcp_echo"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-proxy");

    let mut to_proxy = child.stdin.take().unwrap();
    let from_proxy = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(from_proxy);
        while let Ok(Some(body)) = read_frame(&mut reader) {
            if tx.send(body).is_err() {
                break;
            }
        }
    });

    let roundtrip = |writer: &mut std::process::ChildStdin, raw: &str| -> Value {
        write_frame(writer, raw).unwrap();
        let body = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("proxy timed out answering {raw}"));
        serde_json::from_slice(&body).unwrap()
    };

    let init = roundtrip(
        &mut to_proxy,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );
    assert_eq!(
        init["error"]["code"], -32601,
        "initialize was forwarded or not blocked"
    );

    let denied = roundtrip(&mut to_proxy, &call(2, "never_tool", Some(never_json)));
    assert_eq!(
        denied["error"]["code"], -32002,
        "deny must not be forwarded: {denied}"
    );

    let safe = roundtrip(&mut to_proxy, &call(3, "safe_tool", None));
    assert_eq!(safe["result"]["name"], "safe_tool");
    assert_eq!(safe["result"]["saw_approval"], false);
    assert_eq!(safe["result"]["arguments"]["x"], 1);

    let needs = roundtrip(&mut to_proxy, &call(4, "careful_tool", None));
    assert_eq!(needs["error"]["code"], -32001);

    let allowed = roundtrip(
        &mut to_proxy,
        &call(5, "careful_tool", Some(careful_json.clone())),
    );
    assert_eq!(allowed["result"]["name"], "careful_tool", "{allowed}");
    assert_eq!(allowed["result"]["saw_approval"], false);
    assert_eq!(allowed["result"]["arguments"]["x"], 1);

    let replay = roundtrip(&mut to_proxy, &call(6, "careful_tool", Some(careful_json)));
    assert_eq!(
        replay["error"]["code"], -32001,
        "replay must not be forwarded: {replay}"
    );

    // If a blocked call had been forwarded, this response would be the
    // leftover echo of that call instead of safe_tool.
    let still = roundtrip(&mut to_proxy, &call(7, "safe_tool", None));
    assert_eq!(still["result"]["name"], "safe_tool");

    drop(to_proxy);
    let status = child.wait().expect("wait for proxy");
    assert!(status.success(), "proxy exited {status}");
}

#[test]
fn library_decision_matches_the_proxy_policy_shape() {
    // Keeps the example policy's NeedsApproval distinct from the proxy test.
    let mut f = Fixture::new();
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny);
}
