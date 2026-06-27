use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub async fn forward_to_python(
    req: &crate::protocol::CheckRequest,
    extracted_text: &str,
) -> Result<(String, String), String> {
    let asf_tool = asf_tool_name(&req.tool_name);
    let args_hash = crate::db::compute_args_hash(&req.tool_input);
    let tool_call_id = crate::db::effective_tool_call_id(
        req.tool_use_id.as_deref(),
        req.session_id.as_deref(),
        req.transcript_path.as_deref(),
        &req.tool_name,
        &args_hash,
    );
    let payload = json!({
        "tool": asf_tool,
        "input": extracted_text,
        "tool_name": req.tool_name,
        "tool_input": req.tool_input,
        "tool_call_id": tool_call_id,
        "session_id": req.session_id,
        "transcript_path": req.transcript_path,
    });

    let socket_path = default_cache_dir()?.join("asf_hook.sock");
    let stream = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
        .await
        .map_err(|_| format!("connect to {} timed out", socket_path.display()))?
        .map_err(|err| format!("connect to {} failed: {err}", socket_path.display()))?;

    let mut reader = BufReader::new(stream);
    let encoded = serde_json::to_string(&payload)
        .map_err(|err| format!("serialize python request failed: {err}"))?;
    tokio::time::timeout(Duration::from_secs(2), async {
        let stream = reader.get_mut();
        stream.write_all(encoded.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await
    })
    .await
    .map_err(|_| "write to python daemon timed out".to_string())?
    .map_err(|err| format!("write to python daemon failed: {err}"))?;

    let mut line = String::new();
    let bytes_read = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
        .await
        .map_err(|_| "read from python daemon timed out".to_string())?
        .map_err(|err| format!("read from python daemon failed: {err}"))?;
    if bytes_read == 0 {
        return Err("python daemon closed connection without response".to_string());
    }

    let response: serde_json::Value = serde_json::from_str(&line)
        .map_err(|err| format!("parse python response failed: {err}"))?;
    let verdict = response
        .get("verdict")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "python response missing verdict".to_string())?;
    if verdict != "ALLOW" && verdict != "DENY" {
        return Err(format!("python response invalid verdict: {verdict}"));
    }
    let reason = response
        .get("reason")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "python response missing reason".to_string())?;

    Ok((verdict.to_string(), reason.to_string()))
}

pub(crate) fn asf_tool_name(tool_name: &str) -> &'static str {
    match tool_name {
        "Bash" => "shell",
        "Read" => "file_read",
        "Write" => "file_write",
        "Edit" | "MultiEdit" | "NotebookEdit" => "code_edit",
        "Glob" | "Grep" => "file_search",
        "WebFetch" => "web",
        _ => "shell",
    }
}

fn default_cache_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".cache").join("asf-hook"))
        .ok_or_else(|| "HOME not set".to_string())
}
