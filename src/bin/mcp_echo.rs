//! Downstream stand-in for the MCP proxy tests. Not a real tool server.
//!
//! Speaks MCP stdio (one JSON message per line). It answers `initialize`,
//! `ping` and `tools/list`, and answers each `tools/call` with the tool name
//! and arguments it actually received. `seen` counts every message it has
//! received, so a test can tell if a blocked message got through.
//! `saw_approval` is true when the proxy failed to strip
//! `_terminal_guard_approval`.
//!
//! A few tool names make it misbehave on purpose, to test the proxy:
//! `spoof_id` answers with a different id, `hang` never answers, `crash`
//! exits, `chatty` sends a notification and a server request first, and
//! `garbage` writes a line that isn't JSON.

use std::io::{self, BufReader, Write};
use std::process::ExitCode;

use serde_json::{Value, json};
use terminal_guard::mcp::{read_message, write_message};

fn main() -> ExitCode {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = io::stdout();
    let mut seen: u64 = 0;
    loop {
        let text = match read_message(&mut reader) {
            Ok(Some(t)) => t,
            Ok(None) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mcp-echo: {e}");
                return ExitCode::from(1);
            }
        };
        seen += 1;
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            let _ = write_message(
                &mut stdout,
                &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
                    .to_string(),
            );
            continue;
        };
        let Some(id) = value.get("id").cloned() else {
            continue; // notification or a reply to our own request
        };
        if value.get("method").is_none() {
            continue; // the proxy answering our server request
        }
        let method = value.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mcp-echo", "version": "0" },
                "seen": seen
            }),
            "ping" => json!({}),
            "tools/list" => json!({ "tools": [], "seen": seen }),
            "tools/call" => {
                let name = value
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match name {
                    "spoof_id" => {
                        let _ = write_message(
                            &mut stdout,
                            &json!({"jsonrpc":"2.0","id":"not-yours","result":{"spoofed":true}})
                                .to_string(),
                        );
                        continue;
                    }
                    "hang" => continue,
                    "crash" => return ExitCode::from(3),
                    "garbage" => {
                        let _ = writeln!(stdout, "this is not json");
                        let _ = stdout.flush();
                        continue;
                    }
                    "chatty" => {
                        let _ = write_message(
                            &mut stdout,
                            &json!({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hi"}}).to_string(),
                        );
                        let _ = write_message(
                            &mut stdout,
                            &json!({"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{}}).to_string(),
                        );
                    }
                    _ => {}
                }
                json!({
                    "name": name,
                    "arguments": value.pointer("/params/arguments").cloned().unwrap_or(json!({})),
                    "saw_approval": value.pointer("/params/_terminal_guard_approval").is_some(),
                    "seen": seen
                })
            }
            _ => {
                let _ = write_message(
                    &mut stdout,
                    &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"unknown"},"seen":seen})
                        .to_string(),
                );
                continue;
            }
        };
        let response = json!({ "jsonrpc": "2.0", "id": id, "result": result });
        if write_message(&mut stdout, &response.to_string()).is_err() {
            return ExitCode::from(1);
        }
    }
}
