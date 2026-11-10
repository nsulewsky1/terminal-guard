//! MCP stdio proxy decisions.
//!
//! [`evaluate`] looks at one JSON-RPC message. It returns [`ProxyOutcome::Forward`]
//! only for a `tools/call` whose guard decision is `Allow`. Everything else is
//! [`ProxyOutcome::Block`]: the downstream server must not be contacted.
//!
//! Framing helpers speak the MCP stdio transport (`Content-Length`, then the
//! body). This module does not spawn processes; the `mcp-proxy` command does.

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use crate::approval::SignedActionApproval;
use crate::clock::Clock;
use crate::guard::Guard;
use crate::policy::Decision;

/// Largest MCP message body this proxy will read.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

const APPROVAL_PARAM: &str = "_terminal_guard_approval";

/// What the proxy should do with one client message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// Write `request` to the downstream server and return its response.
    Forward { request: String },
    /// Do not contact the downstream server.
    /// `response` is a JSON-RPC message for the client, or `None` when the
    /// client sent a notification (no `id`) and a response would be illegal.
    Block { response: Option<String> },
}

/// Decide whether one raw JSON-RPC message may be forwarded.
///
/// A `tools/call` is forwarded only when the guard returns `Allow`. A signed
/// one-time approval, if present under `params._terminal_guard_approval`, can
/// upgrade `NeedsApproval` to `Allow` for that single call. It is removed
/// before forwarding. It never upgrades `Deny`.
///
/// Any other method, including `initialize` and `tools/list`, is blocked.
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
    let method = obj.get("method").and_then(Value::as_str).unwrap_or("");

    if method != "tools/call" {
        return block(
            has_id,
            id,
            -32601,
            "blocked by terminal-guard: only tools/call can be forwarded",
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
                    Decision::Allow => forward_stripped(&value),
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
        Ok(Decision::Allow) => forward_stripped(&value),
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

fn forward_stripped(value: &Value) -> ProxyOutcome {
    let mut out = value.clone();
    if let Some(params) = out.get_mut("params").and_then(Value::as_object_mut) {
        params.remove(APPROVAL_PARAM);
    }
    ProxyOutcome::Forward {
        request: out.to_string(),
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

fn error_body(id: Option<Value>, code: i32, message: &str, data: Option<Value>) -> String {
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

/// Write one MCP stdio frame.
pub fn write_frame<W: Write>(writer: &mut W, body: impl AsRef<[u8]>) -> io::Result<()> {
    let body = body.as_ref();
    let len = body.len();
    write!(writer, "Content-Length: {len}\r\n\r\n")?;
    writer.write_all(body)?;
    writer.flush()
}

/// Read one MCP stdio frame.
///
/// Returns `Ok(None)` on a clean end of stream before the next header.
/// A frame that starts and then ends early is an error.
pub fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut content_length: Option<usize> = None;
    let mut saw_byte = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            if !saw_byte {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated MCP header",
            ));
        }
        saw_byte = true;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                let parsed = value.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad Content-Length")
                })?;
                if parsed > MAX_FRAME_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP frame exceeds limit",
                    ));
                }
                content_length = Some(parsed);
            }
        }
    }
    let len = content_length.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "MCP frame missing Content-Length",
        )
    })?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}
