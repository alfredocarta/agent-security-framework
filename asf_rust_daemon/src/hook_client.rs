use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    const MAX_STDIN_BYTES: u64 = 256 * 1024;
    let mut raw = Vec::new();
    let bytes_read = {
        use std::io::Read;
        std::io::stdin()
            .lock()
            .take(MAX_STDIN_BYTES + 1)
            .read_to_end(&mut raw)
            .unwrap_or(0)
    };
    if bytes_read as u64 > MAX_STDIN_BYTES {
        std::process::exit(0);
    }
    let input = String::from_utf8_lossy(&raw);

    let payload: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => std::process::exit(0),
    };

    let tool_name = payload["tool_name"].as_str().unwrap_or("").to_string();
    let tool_input = payload["tool_input"].clone();
    let session_id = payload["session_id"].as_str().map(|s| s.to_string());
    let transcript_path = payload["transcript_path"].as_str().map(|s| s.to_string());

    const SUPPORTED: &[&str] = &[
        "Bash",
        "Read",
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Glob",
        "Grep",
        "WebFetch",
    ];
    if !SUPPORTED.contains(&tool_name.as_str()) {
        std::process::exit(0);
    }

    let monitor_only = std::env::var("ASF_HOOK_MONITOR_ONLY")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true);
    let fail_closed = std::env::var("ASF_HOOK_FAIL_CLOSED")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false);

    let request = serde_json::json!({
        "tool_name": tool_name.clone(),
        "tool_input": tool_input,
        "session_id": session_id,
        "transcript_path": transcript_path,
        "agent_id": "claude-code",
    });

    match query_rust_daemon(&request) {
        Ok((verdict, reason)) => {
            if verdict == "DENY" {
                if monitor_only {
                    eprintln!("[ASF monitor] would block {tool_name}: {reason}");
                    std::process::exit(0);
                }
                print!("{}", block_message(&tool_name, &reason));
                std::io::stdout().flush().ok();
                std::process::exit(2);
            }
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("[ASF] rust daemon error: {err}");
            if fail_closed && !monitor_only {
                print!("{}", block_message(&tool_name, "rust_daemon_unavailable"));
                std::io::stdout().flush().ok();
                std::process::exit(2);
            }
            std::process::exit(0);
        }
    }
}

fn query_rust_daemon(request: &serde_json::Value) -> Result<(String, String), String> {
    let socket_path = cache_dir()?.join("asf_rust.sock");

    let stream =
        UnixStream::connect(&socket_path).map_err(|e| format!("connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set_write_timeout: {e}"))?;

    let encoded = serde_json::to_string(request).map_err(|e| format!("serialize: {e}"))?;

    {
        let mut writer = &stream;
        writer
            .write_all(encoded.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        writer
            .write_all(b"\n")
            .map_err(|e| format!("write newline: {e}"))?;
    }

    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .map_err(|e| format!("read: {e}"))?;

    let resp: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(|e| format!("parse response: {e}"))?;

    let verdict = resp["verdict"]
        .as_str()
        .ok_or("missing verdict")?
        .to_string();
    let reason = resp["reason"].as_str().unwrap_or("").to_string();

    if verdict != "ALLOW" && verdict != "DENY" {
        return Err(format!("unexpected verdict: {verdict}"));
    }
    Ok((verdict, reason))
}

fn block_message(tool_name: &str, reason: &str) -> String {
    format!(
        "[ASF SECURITY BLOCK]\n\
         Tool blocked: {tool_name}\n\
         Reason: {reason}\n\
         \n\
         The tool call was NOT executed. Next steps:\n\
         1. Ask the user to explicitly review and approve this specific action.\n\
         2. Reformulate the request to avoid the flagged pattern.\n\
         3. If this is a false positive, the user can disable enforcement:\n\
              export ASF_HOOK_MONITOR_ONLY=true\n"
    )
}

fn cache_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".cache").join("asf-hook"))
        .ok_or_else(|| "HOME not set".to_string())
}
