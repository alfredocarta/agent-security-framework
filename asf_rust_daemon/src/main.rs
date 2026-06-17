mod checker;
mod db;
mod forwarder;
mod hardening;
mod patterns;
mod protocol;

use crate::checker::check;
use crate::patterns::{KILL_SWITCH_PATTERNS, SEMANTIC_PROBE_PATTERNS};
use crate::protocol::{CheckRequest, CheckResponse, Verdict};
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const SOCKET_NAME: &str = "asf_rust.sock";
const PID_NAME: &str = "asf_rust.pid";
const LOG_NAME: &str = "asf_rust.log";

#[tokio::main]
async fn main() -> io::Result<()> {
    LazyLock::force(&KILL_SWITCH_PATTERNS);
    LazyLock::force(&SEMANTIC_PROBE_PATTERNS);
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
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, &log_path).await {
                        log_line(&log_path, "ERROR", &format!("connection failed: {err}"));
                    }
                });
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

async fn handle_connection(stream: UnixStream, log_path: &Path) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).await?;

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
            let (verdict, reason, db_outcome, extracted_text) = check(&request.tool_input);
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
                                (
                                    Verdict::Allow,
                                    "python_daemon_unavailable_allow".to_string(),
                                )
                            }
                        }
                    }
                }
                Verdict::Allow => (Verdict::Allow, reason.to_string()),
            };

            log_check(log_path, &request.tool_name, final_verdict, &final_reason);

            if matches!(final_verdict, Verdict::Deny) {
                let db_path = db::resolve_db_path();
                let db_outcome_owned = db_outcome.to_string();
                let final_reason_clone = final_reason.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(err) = db::write_deny_record(
                        &db_path,
                        &request,
                        &final_reason_clone,
                        &db_outcome_owned,
                    ) {
                        eprintln!("failed to write deny record to DB: {err}");
                    }
                });
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
