use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub fn ensure_running(runtime_dir: &Path, asf_root: &Path) -> Result<(), String> {
    let pid_path = runtime_dir.join("asf_rust.pid");
    let sock_path = runtime_dir.join("asf_rust.sock");

    if is_running(&pid_path) && UnixStream::connect(&sock_path).is_ok() {
        return Ok(());
    }

    let daemon_bin = asf_root
        .join("asf_rust_daemon")
        .join("target")
        .join("release")
        .join("asf-rust-daemon");

    Command::new(&daemon_bin)
        .arg("--socket")
        .arg(&sock_path)
        .spawn()
        .map_err(|e| format!("impossibile avviare il daemon {:?}: {e}", daemon_bin))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if UnixStream::connect(&sock_path).is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(50));
    }

    Err(format!(
        "daemon avviato ma il socket {:?} non risponde entro 5s",
        sock_path
    ))
}

fn is_running(pid_path: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(pid_path) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<i32>() else {
        return false;
    };
    unsafe { libc::kill(pid, 0) == 0 }
}
