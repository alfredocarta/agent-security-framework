#[path = "wrapper/agent.rs"]   mod agent;
#[path = "wrapper/claude.rs"]  mod claude;
#[path = "wrapper/daemon.rs"]  mod daemon;
#[path = "wrapper/hermes.rs"]  mod hermes;
#[path = "wrapper/session.rs"] mod session;

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("update") {
        let current_exe = std::env::current_exe().unwrap_or_else(|e| {
            eprintln!("[asf-run] impossibile determinare il binario corrente: {e}");
            std::process::exit(1);
        });
        let asf_root = resolve_asf_root();

        println!("asf-run versione {}", env!("CARGO_PKG_VERSION"));
        println!("binario:  {}", current_exe.display());
        println!("asf root: {}", asf_root.display());
        println!();
        println!("Per aggiornare:");
        println!("  cd {}", asf_root.display());
        println!("  git pull");
        println!("  cd asf_rust_daemon && cargo build --release");
        std::process::exit(0);
    }

    let agent_name = match args.get(1) {
        Some(n) => n.clone(),
        None => {
            eprintln!("uso: asf-run <claude|hermes> [args...]");
            std::process::exit(1);
        }
    };
    let agent_args = &args[2..];

    let asf_root = resolve_asf_root();
    let runtime  = default_runtime_dir();

    let adapter = agent::detect(&agent_name).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    adapter.preflight(&asf_root).unwrap_or_else(|e| {
        eprintln!("[asf-run] preflight fallito: {e}");
        std::process::exit(1);
    });

    let session_id = session::new_session_id();

    daemon::ensure_running(&runtime, &asf_root).unwrap_or_else(|e| {
        eprintln!("[asf-run] daemon: {e}");
        std::process::exit(1);
    });

    eprintln!("[asf-run] sessione {} — avvio {agent_name}", session_id);

    let err = Command::new(adapter.executable())
        .args(agent_args)
        .env("ASF_SESSION_ID",       &session_id)
        .env("ASF_ROOT",             asf_root.display().to_string())
        .env("ASF_HOOK_RUNTIME_DIR", runtime.display().to_string())
        .envs(adapter.extra_env())
        .exec();

    eprintln!("[asf-run] exec fallito: {err}");
    std::process::exit(1);
}

fn resolve_asf_root() -> PathBuf {
    // binary: <asf_root>/asf_rust_daemon/target/release/asf-run
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            // release/ -> target/ -> asf_rust_daemon/ -> asf_root/
            p.parent()?.parent()?.parent()?.parent().map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            eprintln!("[asf-run] impossibile determinare ASF_ROOT dall'eseguibile");
            std::process::exit(1);
        })
}

fn default_runtime_dir() -> PathBuf {
    std::env::var("ASF_HOOK_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp"));
            home.join(".cache").join("asf-hook")
        })
}
