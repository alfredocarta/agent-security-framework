#[path = "wrapper/agent.rs"]
mod agent;
#[path = "wrapper/claude.rs"]
mod claude;
#[path = "wrapper/daemon.rs"]
mod daemon;
#[path = "wrapper/hermes.rs"]
mod hermes;
#[path = "wrapper/session.rs"]
mod session;

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

    if args.get(1).map(String::as_str) == Some("dashboard") {
        let asf_root = resolve_asf_root();
        let dashboard_dir = std::env::var("ASF_DASHBOARD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                asf_root
                    .parent()
                    .map(|parent| {
                        parent
                            .join("agent-security-evaluation")
                            .join("dashboard_v2")
                    })
                    .unwrap_or_else(|| {
                        PathBuf::from("agent-security-evaluation").join("dashboard_v2")
                    })
            });

        if !dashboard_dir.is_dir() {
            eprintln!(
                "[asf-run] dashboard non trovata: {}",
                dashboard_dir.display()
            );
            eprintln!(
                "[asf-run] imposta ASF_DASHBOARD_DIR per specificare la directory di dashboard_v2"
            );
            std::process::exit(1);
        }

        let python = resolve_python().unwrap_or_else(|e| {
            eprintln!("[asf-run] {e}");
            std::process::exit(1);
        });

        let mut port_arg = None;
        let mut iter = args[2..].iter();
        while let Some(arg) = iter.next() {
            if arg == "--port" {
                port_arg = iter.next();
                break;
            }
        }

        let port = match port_arg {
            Some(value) => value.parse::<u16>().unwrap_or_else(|_| {
                eprintln!("[asf-run] --port richiede un numero valido");
                std::process::exit(1);
            }),
            None => std::env::var("ASF_DASHBOARD_PORT")
                .ok()
                .map(|value| {
                    value.parse::<u16>().unwrap_or_else(|_| {
                        eprintln!("[asf-run] --port richiede un numero valido");
                        std::process::exit(1);
                    })
                })
                .unwrap_or(8080u16),
        };

        eprintln!("[asf-run] avvio dashboard — http://localhost:{port}/overview");
        eprintln!("[asf-run] directory: {}", dashboard_dir.display());

        let err = Command::new(python)
            .args(["-m", "backend.main"])
            .current_dir(&dashboard_dir)
            .env("ASF_ROOT", asf_root.display().to_string())
            .env("ASF_DASHBOARD_PORT", port.to_string())
            .exec();

        eprintln!("[asf-run] exec fallito: {err}");
        std::process::exit(1);
    }

    let agent_name = match args.get(1) {
        Some(n) => n.clone(),
        None => {
            eprintln!("uso: asf-run <claude|hermes|dashboard> [args...]");
            std::process::exit(1);
        }
    };
    let agent_args = &args[2..];

    let asf_root = resolve_asf_root();
    let runtime = default_runtime_dir();

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
        .env("ASF_SESSION_ID", &session_id)
        .env("ASF_ROOT", asf_root.display().to_string())
        .env("ASF_HOOK_RUNTIME_DIR", runtime.display().to_string())
        .envs(adapter.extra_env())
        .exec();

    eprintln!("[asf-run] exec fallito: {err}");
    std::process::exit(1);
}

fn resolve_asf_root() -> PathBuf {
    // binary: <asf_root>/asf_rust_daemon/target/release/asf-run
    // canonicalize() follows symlinks so ~/.local/bin/asf-run resolves correctly
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .and_then(|p| {
            // release/ -> target/ -> asf_rust_daemon/ -> asf_root/
            p.parent()?.parent()?.parent()?.parent().map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            eprintln!("[asf-run] impossibile determinare ASF_ROOT dall'eseguibile");
            std::process::exit(1);
        })
}

fn resolve_python() -> Result<String, String> {
    if let Ok(prefix) = std::env::var("CONDA_PREFIX") {
        let p = PathBuf::from(prefix).join("bin/python");
        if p.exists() {
            return Ok(p.display().to_string());
        }
    }
    for candidate in &["python3", "python"] {
        if let Ok(out) = Command::new("which").arg(candidate).output() {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(path);
                }
            }
        }
    }
    Err("nessun interprete Python trovato (CONDA_PREFIX, python3, python)".to_string())
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
