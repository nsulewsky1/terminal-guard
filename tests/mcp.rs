//! MCP proxy: only an allowed tools/call runs a tool. Read-only session
//! messages pass through; everything else is blocked. The process tests run
//! the real command against a downstream echo binary.

mod common;

use std::io::{BufReader, Cursor};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::Fixture;
use serde_json::{Value, json};
use terminal_guard::keys::{signing_key_hex, verifying_key_hex};
use terminal_guard::mcp::{
    DownstreamMessage, MAX_MESSAGE_BYTES, ProxyOutcome, classify_downstream, evaluate,
    read_message, write_message,
};
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
[actions.chatty]
connected = "allow"
degraded = "allow"
lost = "allow"
hold = "deny"
[actions.spoof_id]
connected = "allow"
degraded = "allow"
lost = "allow"
hold = "deny"
[actions.garbage]
connected = "allow"
degraded = "allow"
lost = "allow"
hold = "deny"
[actions.crash]
connected = "allow"
degraded = "allow"
lost = "allow"
hold = "deny"
[actions.hang]
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
fn message_framing_roundtrip_and_limits() {
    let mut buf = Vec::new();
    write_message(&mut buf, r#"{"ok":true}"#).unwrap();
    assert_eq!(buf, b"{\"ok\":true}\n");
    assert!(write_message(&mut Vec::new(), "{\"a\":\n1}").is_err());

    let mut c = Cursor::new(b"\n\r\n{\"a\":1}\r\n{\"b\":2}\n".to_vec());
    assert_eq!(read_message(&mut c).unwrap().unwrap(), r#"{"a":1}"#);
    assert_eq!(read_message(&mut c).unwrap().unwrap(), r#"{"b":2}"#);
    assert!(read_message(&mut c).unwrap().is_none());

    let mut c = Cursor::new(b"{\"cut\":".to_vec());
    assert!(read_message(&mut c).is_err(), "unterminated line accepted");
    let mut c = Cursor::new(b"\xff\xfe\n".to_vec());
    assert!(read_message(&mut c).is_err(), "non-UTF-8 accepted");
    let mut big = vec![b'x'; MAX_MESSAGE_BYTES + 1];
    big.push(b'\n');
    assert!(
        read_message(&mut Cursor::new(big)).is_err(),
        "oversized accepted"
    );
    let mut ok = vec![b'x'; MAX_MESSAGE_BYTES];
    ok.push(b'\n');
    assert!(read_message(&mut Cursor::new(ok)).unwrap().is_some());
}

fn forwarded_id(o: ProxyOutcome) -> Option<Value> {
    match o {
        ProxyOutcome::Forward { id, .. } => id,
        ProxyOutcome::Block { response } => panic!("blocked: {response:?}"),
    }
}

fn blocked(o: ProxyOutcome) -> Option<Value> {
    match o {
        ProxyOutcome::Block { response } => response.map(|r| serde_json::from_str(&r).unwrap()),
        ProxyOutcome::Forward { request, .. } => panic!("forwarded: {request}"),
    }
}

#[test]
fn evaluate_forwards_session_messages_and_only_allowed_tool_calls() {
    let mut f = Fixture::new();
    // Read-only session messages pass, even in hold.
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    assert_eq!(forwarded_id(evaluate(&mut f.guard, init)), Some(json!(1)));
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    assert_eq!(forwarded_id(evaluate(&mut f.guard, note)), None);
    let list = r#"{"jsonrpc":"2.0","id":"l","method":"tools/list"}"#;
    assert_eq!(forwarded_id(evaluate(&mut f.guard, list)), Some(json!("l")));
    let ping = r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#;
    assert_eq!(forwarded_id(evaluate(&mut f.guard, ping)), Some(json!(3)));

    // Other methods, wrong shapes and notifications that would run a tool.
    let read = r#"{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{}}"#;
    assert_eq!(
        blocked(evaluate(&mut f.guard, read)).unwrap()["error"]["code"],
        -32601
    );
    let init_note = r#"{"jsonrpc":"2.0","method":"initialize"}"#;
    assert!(blocked(evaluate(&mut f.guard, init_note)).is_none());
    let list_note = r#"{"jsonrpc":"2.0","method":"notifications/initialized","id":9}"#;
    assert_eq!(
        blocked(evaluate(&mut f.guard, list_note)).unwrap()["error"]["code"],
        -32601
    );
    let call_note =
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_local_fixture"}}"#;
    assert!(blocked(evaluate(&mut f.guard, call_note)).is_none());
    let reply = r#"{"jsonrpc":"2.0","id":"srv","result":{}}"#;
    assert!(blocked(evaluate(&mut f.guard, reply)).is_none());
    let batch = format!("[{}]", call(5, "read_local_fixture", None));
    assert_eq!(
        blocked(evaluate(&mut f.guard, &batch)).unwrap()["error"]["code"],
        -32600
    );
    let v1 =
        r#"{"jsonrpc":"1.0","id":6,"method":"tools/call","params":{"name":"read_local_fixture"}}"#;
    assert_eq!(
        blocked(evaluate(&mut f.guard, v1)).unwrap()["error"]["code"],
        -32600
    );
    assert_eq!(
        blocked(evaluate(&mut f.guard, "{nope")).unwrap()["error"]["code"],
        -32700
    );
    let no_name = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}"#;
    assert_eq!(
        blocked(evaluate(&mut f.guard, no_name)).unwrap()["error"]["code"],
        -32002
    );

    // Still in hold: the example policy denies read_local_fixture.
    let v = blocked(evaluate(&mut f.guard, &call(8, "read_local_fixture", None))).unwrap();
    assert_eq!(v["error"]["code"], -32002);
    assert_eq!(v["id"], 8);

    let msg = ContactAuth::new(common::ENGINE, 1, f.now_ms()).sign(&f.human);
    f.guard.apply_signed_approval(&msg).unwrap();

    match evaluate(
        &mut f.guard,
        &call(9, "read_local_fixture", Some(json!({"junk": 1}))),
    ) {
        ProxyOutcome::Forward { request, id } => {
            assert_eq!(id, Some(json!(9)));
            let v: Value = serde_json::from_str(&request).unwrap();
            assert!(v["params"].get("_terminal_guard_approval").is_none());
            assert_eq!(v["params"]["name"], "read_local_fixture");
        }
        ProxyOutcome::Block { response } => panic!("allow was blocked: {response:?}"),
    }

    let v = blocked(evaluate(
        &mut f.guard,
        &call(10, "send_external_message", None),
    ))
    .unwrap();
    assert_eq!(v["error"]["code"], -32001);
}

#[test]
fn downstream_messages_are_classified_strictly() {
    let id = json!(7);
    let c = |raw: &str| classify_downstream(raw, &id);
    assert_eq!(
        c(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#),
        DownstreamMessage::Response
    );
    assert_eq!(
        c(r#"{"jsonrpc":"2.0","id":7,"error":{"code":1,"message":"x"}}"#),
        DownstreamMessage::Response
    );
    assert!(matches!(
        c(r#"{"jsonrpc":"2.0","id":8,"result":{}}"#),
        DownstreamMessage::Invalid(_)
    ));
    assert!(matches!(
        c(r#"{"jsonrpc":"2.0","id":"7","result":{}}"#),
        DownstreamMessage::Invalid(_)
    ));
    assert!(matches!(
        c(r#"{"jsonrpc":"2.0","result":{}}"#),
        DownstreamMessage::Invalid(_)
    ));
    assert!(matches!(
        c(r#"{"jsonrpc":"2.0","id":7,"result":{},"error":{}}"#),
        DownstreamMessage::Invalid(_)
    ));
    assert!(matches!(
        c(r#"{"jsonrpc":"2.0","id":7}"#),
        DownstreamMessage::Invalid(_)
    ));
    assert!(matches!(
        c(r#"{"id":7,"result":{}}"#),
        DownstreamMessage::Invalid(_)
    ));
    assert!(matches!(c("not json"), DownstreamMessage::Invalid(_)));
    assert!(matches!(c("[]"), DownstreamMessage::Invalid(_)));
    assert_eq!(
        c(r#"{"jsonrpc":"2.0","method":"notifications/message"}"#),
        DownstreamMessage::Notification
    );
    assert_eq!(
        c(r#"{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage"}"#),
        DownstreamMessage::ServerRequest { id: json!(7) }
    );
}

struct Proxy {
    child: Child,
    to: Option<ChildStdin>,
    rx: mpsc::Receiver<Value>,
    _dir: tempfile::TempDir,
}

impl Proxy {
    fn start(extra: &[&str]) -> (Proxy, Value, Value) {
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
        let careful = serde_json::to_value(
            ActionApproval::new("proxy-engine", "careful_tool", 1, now).sign(&human),
        )
        .unwrap();
        let never = serde_json::to_value(
            ActionApproval::new("proxy-engine", "never_tool", 2, now).sign(&human),
        )
        .unwrap();

        let log = dir.path().join("a.log");
        let cp = dir.path().join("a.cp");
        let mut args: Vec<&str> = vec![
            "mcp-proxy",
            "--policy",
            policy_path.to_str().unwrap(),
            "--engine-id",
            "proxy-engine",
            "--log",
            log.to_str().unwrap(),
            "--checkpoint",
            cp.to_str().unwrap(),
            "--audit-key-file",
            audit_path.to_str().unwrap(),
            "--human-pubkey-file",
            human_path.to_str().unwrap(),
            "--contact-file",
            contact_path.to_str().unwrap(),
            "--create",
        ];
        args.extend_from_slice(extra);
        args.push("--");
        args.push(env!("CARGO_BIN_EXE_mcp_echo"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_terminal-guard"))
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mcp-proxy");
        let to = child.stdin.take();
        let from = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(from);
            while let Ok(Some(text)) = read_message(&mut reader) {
                let v: Value = serde_json::from_str(&text).expect("proxy wrote non-JSON");
                if tx.send(v).is_err() {
                    break;
                }
            }
        });
        (
            Proxy {
                child,
                to,
                rx,
                _dir: dir,
            },
            careful,
            never,
        )
    }

    fn send(&mut self, raw: &str) {
        write_message(self.to.as_mut().unwrap(), raw).unwrap();
    }

    fn recv(&self) -> Value {
        self.rx
            .recv_timeout(Duration::from_secs(10))
            .expect("proxy did not answer in time")
    }

    fn roundtrip(&mut self, raw: &str) -> Value {
        self.send(raw);
        self.recv()
    }

    fn finish(mut self) -> std::process::ExitStatus {
        drop(self.to.take());
        self.child.wait().expect("wait for proxy")
    }
}

#[test]
fn proxy_forwards_only_allowed_calls_to_a_real_process() {
    let (mut p, careful, never) = Proxy::start(&[]);

    // A real MCP client starts with these; they must reach the server.
    let init = p.roundtrip(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    assert_eq!(init["result"]["serverInfo"]["name"], "mcp-echo", "{init}");
    assert_eq!(init["result"]["seen"], 1);
    p.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let list = p.roundtrip(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    assert_eq!(list["result"]["seen"], 3, "{list}");

    // Blocked: never reaches the server, so `seen` must not move.
    let denied = p.roundtrip(&call(3, "never_tool", Some(never)));
    assert_eq!(denied["error"]["code"], -32002, "{denied}");
    let needs = p.roundtrip(&call(4, "careful_tool", None));
    assert_eq!(needs["error"]["code"], -32001);
    let other = p.roundtrip(r#"{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{}}"#);
    assert_eq!(other["error"]["code"], -32601);
    p.send(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe_tool"}}"#);

    let safe = p.roundtrip(&call(6, "safe_tool", None));
    assert_eq!(safe["id"], 6);
    assert_eq!(safe["result"]["name"], "safe_tool");
    assert_eq!(safe["result"]["saw_approval"], false);
    assert_eq!(safe["result"]["arguments"]["x"], 1);
    assert_eq!(
        safe["result"]["seen"], 4,
        "a blocked message reached the server"
    );

    let allowed = p.roundtrip(&call(7, "careful_tool", Some(careful.clone())));
    assert_eq!(allowed["result"]["name"], "careful_tool", "{allowed}");
    assert_eq!(allowed["result"]["saw_approval"], false);
    assert_eq!(allowed["result"]["seen"], 5);

    let replay = p.roundtrip(&call(8, "careful_tool", Some(careful)));
    assert_eq!(replay["error"]["code"], -32001, "{replay}");

    let still = p.roundtrip(&call(9, "safe_tool", None));
    assert_eq!(still["result"]["seen"], 6, "replay reached the server");

    let status = p.finish();
    assert!(status.success(), "proxy exited {status}");
}

#[test]
fn proxy_relays_notifications_and_refuses_server_requests() {
    let (mut p, _, _) = Proxy::start(&[]);
    p.send(&call(1, "chatty", None));
    let first = p.recv();
    assert_eq!(first["method"], "notifications/message", "{first}");
    let second = p.recv();
    // The server's sampling request is answered by the proxy, not relayed.
    assert_eq!(second["id"], 1, "{second}");
    assert_eq!(second["result"]["name"], "chatty");
    let next = p.roundtrip(&call(2, "safe_tool", None));
    // chatty + the proxy's error reply to srv-1 + this call.
    assert_eq!(next["result"]["seen"], 3, "{next}");
    assert!(p.finish().success());
}

fn assert_fails_closed(tool: &str, extra: &[&str]) {
    let (mut p, _, _) = Proxy::start(extra);
    let v = p.roundtrip(&call(41, tool, None));
    assert_eq!(v["id"], 41, "{v}");
    assert_eq!(v["error"]["code"], -32003, "{tool}: {v}");
    assert!(v.get("result").is_none());
    let status = p.child.wait().expect("wait for proxy");
    assert!(!status.success(), "{tool}: proxy kept running");
    assert!(
        p.rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "{tool}: extra output after failure"
    );
}

#[test]
fn proxy_fails_closed_on_a_spoofed_response_id() {
    assert_fails_closed("spoof_id", &[]);
}

#[test]
fn proxy_fails_closed_on_downstream_garbage() {
    assert_fails_closed("garbage", &[]);
}

#[test]
fn proxy_fails_closed_when_downstream_exits() {
    assert_fails_closed("crash", &[]);
}

#[test]
fn proxy_fails_closed_when_downstream_hangs() {
    assert_fails_closed("hang", &["--timeout-secs", "1"]);
}

#[test]
fn proxy_stops_on_an_oversized_client_message() {
    let (mut p, _, _) = Proxy::start(&[]);
    let huge = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"safe_tool","pad":"{}"}}}}"#,
        "x".repeat(MAX_MESSAGE_BYTES)
    );
    // The proxy may close its stdin before all of this is written.
    let _ = write_message(p.to.as_mut().unwrap(), &huge);
    let status = p.child.wait().expect("wait for proxy");
    assert!(!status.success());
    assert!(p.rx.recv_timeout(Duration::from_millis(200)).is_err());
}

#[test]
fn library_decision_matches_the_proxy_policy_shape() {
    // Keeps the example policy's NeedsApproval distinct from the proxy test.
    let mut f = Fixture::new();
    assert_eq!(f.guard.decide("read_local_fixture"), Decision::Deny);
}
