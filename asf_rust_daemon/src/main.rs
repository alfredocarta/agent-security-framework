pub mod assessment;
mod audit;
mod checker;
mod db;
mod forwarder;
mod hardening;
mod interceptor;
mod key_authority;
mod output_guard;
mod patterns;
mod protocol;
mod registry;
mod sandbox;
pub mod trace_preview;
pub mod trace_store;
mod validator;

use crate::protocol::{CheckRequest, CheckResponse, Verdict};
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const SOCKET_NAME: &str = "asf_rust.sock";
const PID_NAME: &str = "asf_rust.pid";
const LOG_NAME: &str = "asf_rust.log";

#[tokio::main]
async fn main() -> io::Result<()> {
    hardening::force_regexes();

    let config = Config::from_args()?;
    fs::create_dir_all(&config.cache_dir).await?;
    prepare_socket(&config.socket_path).await?;
    fs::write(&config.pid_path, process::id().to_string()).await?;

    let listener = UnixListener::bind(&config.socket_path)?;
    log_line(
        &config.log_path,
        "INFO",
        &format!("daemon started, socket={}", config.socket_path.display()),
    );

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let log_path = config.log_path.clone();
                spawn_connection_task(stream, log_path);
            }
            Err(err) => {
                log_line(&config.log_path, "ERROR", &format!("accept failed: {err}"));
            }
        }
    }
}

struct Config {
    cache_dir: PathBuf,
    socket_path: PathBuf,
    pid_path: PathBuf,
    log_path: PathBuf,
}

impl Config {
    fn from_args() -> io::Result<Self> {
        let cache_dir = default_cache_dir()?;
        let mut socket_path = cache_dir.join(SOCKET_NAME);
        let mut pid_path = cache_dir.join(PID_NAME);
        let mut log_path = cache_dir.join(LOG_NAME);

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => socket_path = next_path(&mut args, "--socket")?,
                "--pid-file" => pid_path = next_path(&mut args, "--pid-file")?,
                "--log-file" => log_path = next_path(&mut args, "--log-file")?,
                "--help" | "-h" => {
                    print_usage();
                    process::exit(0);
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown argument: {arg}"),
                    ));
                }
            }
        }

        Ok(Self {
            cache_dir,
            socket_path,
            pid_path,
            log_path,
        })
    }
}

fn next_path(args: &mut impl Iterator<Item = String>, flag: &str) -> io::Result<PathBuf> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {flag} value")))
}

fn default_cache_dir() -> io::Result<PathBuf> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(home.join(".cache").join("asf-hook"))
}

fn print_usage() {
    eprintln!("usage: asf-rust-daemon [--socket PATH] [--pid-file PATH] [--log-file PATH]");
}

async fn prepare_socket(socket_path: &Path) -> io::Result<()> {
    if fs::try_exists(socket_path).await? {
        match UnixStream::connect(socket_path).await {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("socket already has a listener: {}", socket_path.display()),
                ));
            }
            Err(_) => fs::remove_file(socket_path).await?,
        }
    }
    Ok(())
}

fn spawn_connection_task(stream: UnixStream, log_path: PathBuf) {
    tokio::spawn(async move {
        let task_log_path = log_path.clone();
        let join =
            tokio::spawn(async move { handle_connection(stream, &task_log_path).await }).await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => log_line(&log_path, "ERROR", &format!("connection failed: {err}")),
            Err(err) if err.is_panic() => {
                log_line(&log_path, "ERROR", "connection task panicked");
            }
            Err(err) => log_line(
                &log_path,
                "ERROR",
                &format!("connection task failed: {err}"),
            ),
        }
    });
}

async fn handle_connection(stream: UnixStream, log_path: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reader.read_line(&mut line),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client read timed out"))??;

    if bytes_read == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<CheckRequest>(&line) {
        Ok(request) => {
            let _ = (
                &request.session_id,
                &request.transcript_path,
                &request.agent_id,
            );
            // NOTE: Stage 1 now runs through interceptor::check_value(), which loads
            // detection patterns from the SQLite policies DB at request time. The
            // static regexes in patterns.rs remain in the codebase but are no longer
            // the active detection set for daemon requests.
            let (verdict, reason, db_outcome, extracted_text) = interceptor::check_value(
                &request.agent_id,
                &request.tool_name,
                request.session_id.as_deref(),
                &request.tool_input,
            );
            let mut write_allow_trace = false;
            let (final_verdict, final_reason): (Verdict, String) = match verdict {
                Verdict::Deny => (Verdict::Deny, reason.to_string()),
                Verdict::Uncertain => {
                    let fail_closed = env::var("ASF_HOOK_FAIL_CLOSED")
                        .map(|value| value.to_lowercase() == "true")
                        .unwrap_or(false);
                    match forwarder::forward_to_python(&request, &extracted_text).await {
                        Ok((verdict, reason)) => {
                            let parsed = if verdict == "ALLOW" {
                                Verdict::Allow
                            } else {
                                Verdict::Deny
                            };
                            (parsed, reason)
                        }
                        Err(err) => {
                            log_line(log_path, "ERROR", &format!("python forward failed: {err}"));
                            if fail_closed {
                                (Verdict::Deny, "python_daemon_unavailable".to_string())
                            } else {
                                write_allow_trace = true;
                                (
                                    Verdict::Allow,
                                    "python_daemon_unavailable_allow".to_string(),
                                )
                            }
                        }
                    }
                }
                Verdict::Allow => {
                    write_allow_trace = true;
                    (Verdict::Allow, reason.to_string())
                }
            };

            log_check(log_path, &request.tool_name, final_verdict, &final_reason);

            if matches!(final_verdict, Verdict::Deny) {
                let db_path = db::resolve_db_path();
                let db_outcome_owned = if db_outcome.is_empty() {
                    "BLOCKED".to_string()
                } else {
                    db_outcome.to_string()
                };
                let final_reason_clone = final_reason.clone();
                if let Err(err) = tokio::task::spawn_blocking(move || {
                    db::write_deny_record(
                        &db_path,
                        &request,
                        &final_reason_clone,
                        &db_outcome_owned,
                    )
                })
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r.map_err(|e| e.to_string()))
                {
                    log_line(
                        log_path,
                        "ERROR",
                        &format!("failed to write deny record: {err}"),
                    );
                }
            } else if matches!(final_verdict, Verdict::Allow) && write_allow_trace {
                let db_path = db::resolve_db_path();
                let allow_outcome = if final_reason == "python_daemon_unavailable_allow" {
                    "FAIL_OPEN_ALLOW".to_string()
                } else if db_outcome.is_empty() {
                    "HEURISTIC_CLEAR".to_string()
                } else {
                    db_outcome.to_string()
                };
                let final_reason_clone = final_reason.clone();
                if let Err(err) = tokio::task::spawn_blocking(move || {
                    db::write_claude_trace(
                        &db_path,
                        &request,
                        "ALLOW",
                        &allow_outcome,
                        &final_reason_clone,
                    )
                })
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r.map_err(|e| e.to_string()))
                {
                    log_line(
                        log_path,
                        "ERROR",
                        &format!("failed to write allow trace: {err}"),
                    );
                }
            }
            CheckResponse {
                verdict: final_verdict,
                reason: final_reason,
            }
        }
        Err(err) => {
            log_line(
                log_path,
                "CHECK",
                &format!("tool=<invalid> verdict=DENY reason=\"invalid_json: {err}\""),
            );
            CheckResponse {
                verdict: Verdict::Deny,
                reason: "invalid_json".to_string(),
            }
        }
    };

    let mut stream = reader.into_inner();
    let encoded = serde_json::to_string(&response)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    stream.write_all(encoded.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await
}

fn log_check(log_path: &Path, tool_name: &str, verdict: Verdict, reason: &str) {
    let verdict_text = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
        Verdict::Uncertain => "UNCERTAIN",
    };
    log_line(
        log_path,
        "CHECK",
        &format!("tool={tool_name} verdict={verdict_text} reason=\"{reason}\""),
    );
}

fn log_line(log_path: &Path, level: &str, message: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let line = format!("{timestamp} [{level}] {message}");

    eprintln!("{line}");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{line}");
    }
}
