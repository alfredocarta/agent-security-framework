#[path = "../db.rs"]
mod db;
#[path = "../forwarder.rs"]
mod forwarder;
#[path = "../protocol.rs"]
mod protocol;
#[path = "../registry.rs"]
mod registry;

use serde_json::Value;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process;

fn main() {
    if let Err(err) = run() {
        eprintln!("asf-admin: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;

    match command.as_str() {
        "unsuspend" => {
            let agent_id = args.next().ok_or("usage: asf-admin unsuspend <agent_id>")?;
            if args.next().is_some() {
                return Err("usage: asf-admin unsuspend <agent_id>".into());
            }
            unsuspend(&agent_id)
        }
        "migrate" => {
            let policies_path = parse_migrate_args(args)?;
            migrate(policies_path)
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'\n{}", usage()).into()),
    }
}

fn unsuspend(agent_id: &str) -> Result<(), Box<dyn Error>> {
    let db_path = db::resolve_db_path();
    let db = registry::open_db(&db_path);
    registry::reinstate_agent(&db, agent_id)?;
    println!("[HUMAN OVERSIGHT] Agent '{agent_id}' successfully reinstated.");
    Ok(())
}

fn migrate(policies_path: PathBuf) -> Result<(), Box<dyn Error>> {
    let content = fs::read_to_string(&policies_path)
        .map_err(|err| format!("failed to read {}: {err}", policies_path.display()))?;
    let policies: Value = serde_yaml::from_str(&content)
        .map_err(|err| format!("failed to parse {}: {err}", policies_path.display()))?;

    let patterns = policies
        .get("detection")
        .and_then(|value| value.get("patterns"))
        .ok_or("policies file missing detection.patterns")?;

    let db_path = db::resolve_db_path();
    let db = registry::open_db(&db_path);
    registry::store_detection_patterns(&db, patterns)?;

    let agents = policies
        .get("agents")
        .and_then(Value::as_object)
        .ok_or("policies file missing agents mapping")?;

    for (agent_id, config) in agents {
        let risk_level = config
            .get("risk_level")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("agent '{agent_id}' missing string risk_level"))?;
        let permissions = config
            .get("permissions")
            .ok_or_else(|| format!("agent '{agent_id}' missing permissions"))?;

        registry::add_or_update_agent(&db, agent_id, risk_level, permissions)?;
        println!("[MIGRATE] Agent '{agent_id}' configured.");
    }

    println!("[MIGRATE] Done.");
    Ok(())
}

fn parse_migrate_args<I>(mut args: I) -> Result<PathBuf, Box<dyn Error>>
where
    I: Iterator<Item = String>,
{
    let mut policies_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policies" => {
                let path = args.next().ok_or("--policies requires a path")?;
                policies_path = Some(PathBuf::from(path));
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => return Err(format!("unexpected migrate argument '{other}'").into()),
        }
    }

    match policies_path {
        Some(path) => Ok(path),
        None => Ok(PathBuf::from(
            env::var_os("ASF_ROOT").ok_or("ASF_ROOT is not set; pass --policies PATH")?,
        )
        .join("policies.yaml")),
    }
}

fn usage() -> String {
    "usage:\n  asf-admin unsuspend <agent_id>\n  asf-admin migrate [--policies PATH]".to_string()
}

fn print_usage() {
    println!("{}", usage());
}
