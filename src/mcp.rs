//! MCP stdio proxy decisions.
//!
//! [`evaluate`] looks at one JSON-RPC message from the MCP client and says
//! whether the `mcp-proxy` command may send it to the downstream server.
//!
//! * A `tools/call` is forwarded only when the guard decision is `Allow`.
//! * The read-only session messages a client needs before it can call a tool
//!   (`initialize`, `ping`, `tools/list`, and the `notifications/initialized`
//!   and `notifications/cancelled` notifications) are forwarded unchanged.
//!   They don't run a tool and don't go through the guard.
//! * Everything else (other methods, responses, batches, malformed input) is
//!   blocked and the downstream server is not contacted.
//!
//! Framing follows the MCP stdio transport: one JSON-RPC message per line,
//! UTF-8, no embedded newlines ([`read_message`], [`write_message`]). This
//! module does not spawn processes; the `mcp-proxy` command does.

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use crate::approval::SignedActionApproval;
use crate::clock::Clock;
use crate::guard::Guard;
use crate::policy::Decision;

/// Largest MCP message (one line, without its newline) this proxy will read.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

const APPROVAL_PARAM: &str = "_terminal_guard_approval";

/// Requests forwarded without a guard decision. None of them runs a tool.
pub const PASS_THROUGH_REQUESTS: [&str; 3] = ["initialize", "ping", "tools/list"];
/// Notifications forwarded without a guard decision.
pub const PASS_THROUGH_NOTIFICATIONS: [&str; 2] =
    ["notifications/initialized", "notifications/cancelled"];

/// What the proxy should do with one client message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// Write `request` to the downstream server. `id` is the JSON-RPC id of
    /// the response to wait for, or `None` for a notification (no response).
    Forward { request: String, id: Option<Value> },
    /// Do not contact the downstream server.
    /// `response` is a JSON-RPC message for the client, or `None` when the
    /// client sent a notification or a response, where a reply would be
    /// illegal.
    Block { response: Option<String> },
}

/// Decide whether one raw JSON-RPC message may be forwarded.
///
/// A `tools/call` is forwarded only when the guard returns `Allow`. A signed
/// one-time approval, if present under `params._terminal_guard_approval`, can
/// upgrade `NeedsApproval` to `Allow` for that single call. It is removed
/// before forwarding. It never upgrades `Deny`.
///
/// The read-only session messages in [`PASS_THROUGH_REQUESTS`] and
/// [`PASS_THROUGH_NOTIFICATIONS`] are forwarded as-is. Anything else is
/// blocked.
pub fn evaluate<C: Clock>(guard: &mut Guard<C>, raw: &str) -> ProxyOutcome {
    let value: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => {
            return ProxyOutcome::Block {
                response: Some(error_body(Some(Value::Null), -32700, "Parse error", None)),
            };
        }
    };
    let Some(obj) = value.as_object() else {
        return ProxyOutcome::Block {
            response: Some(error_body(
                Some(Value::Null),
                -32600,
                "Invalid request",
                None,
            )),
        };
    };
    let has_id = obj.contains_key("id");
    let id = obj.get("id").cloned();
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return block(has_id, id, -32600, "Invalid request", None);
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // A response from the client. The proxy never relays server
        // requests, so there is nothing for it to answer. Drop it.
        return ProxyOutcome::Block { response: None };
    };

    if has_id && PASS_THROUGH_REQUESTS.contains(&method) {
        return ProxyOutcome::Forward {
            request: value.to_string(),
            id,
        };
    }
    if !has_id && PASS_THROUGH_NOTIFICATIONS.contains(&method) {
        return ProxyOutcome::Forward {
            request: value.to_string(),
            id: None,
        };
    }

    if method != "tools/call" {
        return block(
            has_id,
            id,
            -32601,
            "blocked by terminal-guard: method not forwarded",
            None,
        );
    }
    if !has_id {
        // A tools/call notification would still execute a tool if forwarded.
        return ProxyOutcome::Block { response: None };
    }

    let name = obj
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let approval = obj
        .get("params")
        .and_then(|p| p.get(APPROVAL_PARAM))
        .cloned();

    let decision = match approval {
        Some(raw_approval) => match SignedActionApproval::from_value(&raw_approval) {
            Ok(approval) => guard.decide_with_approval(name, &approval),
            Err(e) => {
                return match guard.decide(name) {
                    Decision::Allow => forward_stripped(&value, id),
                    Decision::Deny => block(true, id, -32002, "Denied by terminal-guard", None),
                    Decision::NeedsApproval => block(
                        true,
                        id,
                        -32001,
                        "NeedsApproval",
                        Some(json!({ "reason": e.code() })),
                    ),
                };
            }
        },
        None => Ok(guard.decide(name)),
    };

    match decision {
        Ok(Decision::Allow) => forward_stripped(&value, id),
        Ok(Decision::Deny) => block(true, id, -32002, "Denied by terminal-guard", None),
        Ok(Decision::NeedsApproval) => block(
            true,
            id,
            -32001,
            "NeedsApproval",
            Some(json!({ "reason": "needs_approval" })),
        ),
        Err(e) => block(
            true,
            id,
            -32001,
            "NeedsApproval",
            Some(json!({ "reason": e.code() })),
        ),
    }
}

fn forward_stripped(value: &Value, id: Option<Value>) -> ProxyOutcome {
    let mut out = value.clone();
    if let Some(params) = out.get_mut("params").and_then(Value::as_object_mut) {
        params.remove(APPROVAL_PARAM);
    }
    ProxyOutcome::Forward {
        request: out.to_string(),
        id,
    }
}

fn block(
    has_id: bool,
    id: Option<Value>,
    code: i32,
    message: &str,
    data: Option<Value>,
) -> ProxyOutcome {
    if !has_id {
        return ProxyOutcome::Block { response: None };
    }
    ProxyOutcome::Block {
        response: Some(error_body(id, code, message, data)),
    }
}

/// A JSON-RPC error response body.
pub fn error_body(id: Option<Value>, code: i32, message: &str, data: Option<Value>) -> String {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": error,
    })
    .to_string()
}

/// Write one MCP stdio message: the JSON text and a newline.
///
/// Fails if `body` contains a newline, which the transport forbids.
pub fn write_message<W: Write>(writer: &mut W, body: &str) -> io::Result<()> {
    if body.contains(['\n', '\r']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MCP message contains a newline",
        ));
    }
    writer.write_all(body.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Read one MCP stdio message (one line).
///
/// Returns `Ok(None)` at a clean end of stream. Blank lines are skipped. A
/// line longer than [`MAX_MESSAGE_BYTES`], a final line with no newline, or
/// invalid UTF-8 is an error. The size limit is enforced while reading, so an
/// oversized line is never buffered in full.
pub fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    loop {
        let mut buf = Vec::new();
        loop {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "MCP message ended without a newline",
                ));
            }
            let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
                Some(i) => (i + 1, true),
                None => (chunk.len(), false),
            };
            if buf.len() + take > MAX_MESSAGE_BYTES + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MCP message exceeds size limit",
                ));
            }
            buf.extend_from_slice(&chunk[..take]);
            reader.consume(take);
            if done {
                break;
            }
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        if buf.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP message exceeds size limit",
            ));
        }
        if buf.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        return String::from_utf8(buf)
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "MCP message is not UTF-8"));
    }
}

/// How the proxy should treat one message from the downstream server while
/// it waits for the response to `expected_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownstreamMessage {
    /// The response to the forwarded request. Relay it to the client.
    Response,
    /// A notification. Relay it to the client.
    Notification,
    /// A request from the server (for example sampling). It is not relayed;
    /// the proxy answers the server with an error itself.
    ServerRequest { id: Value },
    /// Anything else, including a response with the wrong id. The proxy must
    /// stop rather than guess.
    Invalid(&'static str),
}

/// Classify one downstream message. Only a well-formed JSON-RPC 2.0 response
/// whose id equals `expected_id` counts as the response.
pub fn classify_downstream(raw: &str, expected_id: &Value) -> DownstreamMessage {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return DownstreamMessage::Invalid("not JSON");
    };
    let Some(obj) = value.as_object() else {
        return DownstreamMessage::Invalid("not a JSON-RPC object");
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return DownstreamMessage::Invalid("not JSON-RPC 2.0");
    }
    if let Some(method) = obj.get("method") {
        if !method.is_string() {
            return DownstreamMessage::Invalid("bad method");
        }
        return match obj.get("id") {
            Some(id) => DownstreamMessage::ServerRequest { id: id.clone() },
            None => DownstreamMessage::Notification,
        };
    }
    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");
    if has_result == has_error {
        return DownstreamMessage::Invalid("response needs exactly one of result or error");
    }
    match obj.get("id") {
        Some(id) if id == expected_id => DownstreamMessage::Response,
        _ => DownstreamMessage::Invalid("response id does not match the forwarded request"),
    }
}
