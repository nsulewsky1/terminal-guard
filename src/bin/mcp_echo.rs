//! Downstream stand-in for the MCP proxy test.
//!
//! Reads MCP stdio frames and answers each `tools/call` with the tool name
//! and arguments it actually received. `saw_approval` is true when the
//! proxy failed to strip `_terminal_guard_approval`.

use std::io::{self, BufReader};
use std::process::ExitCode;

use serde_json::{Value, json};
use terminal_guard::mcp::{read_frame, write_frame};

fn main() -> ExitCode {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = io::stdout();
    loop {
        let body = match read_frame(&mut reader) {
            Ok(Some(b)) => b,
            Ok(None) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mcp-echo: {e}");
                return ExitCode::from(1);
            }
        };
        let text = String::from_utf8_lossy(&body);
        let value: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                let _ = write_frame(
                    &mut stdout,
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}).to_string(),
                );
                continue;
            }
        };
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        let name = value
            .pointer("/params/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let arguments = value
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or(json!({}));
        let saw_approval = value.pointer("/params/_terminal_guard_approval").is_some();
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "name": name,
                "arguments": arguments,
                "saw_approval": saw_approval
            }
        });
        if write_frame(&mut stdout, response.to_string()).is_err() {
            return ExitCode::from(1);
        }
    }
}
