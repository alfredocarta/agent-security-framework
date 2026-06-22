use std::path::{Path, PathBuf};
use std::process::Command;
use serde_json::{json, Value};

pub struct ClaudeAdapter;

impl ClaudeAdapter {
    pub fn new() -> Self { ClaudeAdapter }
}

impl crate::agent::AgentAdapter for ClaudeAdapter {
    fn preflight(&self, asf_root: &Path) -> Result<(), String> {
        let python = resolve_python()?;
        let hook_bin = asf_root
            .join("asf_rust_daemon/target/release/asf-rust-hook")
            .display()
            .to_string();
        let hook_py = format!("{} {}", python, asf_root.join("asf_hook.py").display());

        let settings_path = settings_json_path();
        let mut root: Value = if settings_path.exists() {
            let raw = std::fs::read_to_string(&settings_path)
                .map_err(|e| format!("lettura settings.json fallita: {e}"))?;
            serde_json::from_str(&raw)
                .map_err(|e| format!("settings.json non è JSON valido: {e}"))?
        } else {
            json!({})
        };

        let changed = ensure_hooks(&mut root, &hook_bin, &hook_py);
        if changed {
            if let Some(parent) = settings_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("impossibile creare ~/.claude/: {e}"))?;
            }
            let out = serde_json::to_string_pretty(&root)
                .map_err(|e| format!("serializzazione settings.json fallita: {e}"))?;
            std::fs::write(&settings_path, out)
                .map_err(|e| format!("scrittura settings.json fallita: {e}"))?;
            eprintln!("[asf-run] preflight: hook ASF aggiornati in ~/.claude/settings.json");
        }
        Ok(())
    }

    fn extra_env(&self) -> Vec<(String, String)> { vec![] }

    fn executable(&self) -> String { "claude".to_string() }
}

const MATCHER: &str = "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch";

fn ensure_hooks(root: &mut Value, hook_bin: &str, hook_py: &str) -> bool {
    let hooks = root.as_object_mut().unwrap();
    let section = hooks.entry("hooks").or_insert_with(|| json!({}));
    let hooks_obj = section.as_object_mut().unwrap();

    let mut changed = false;

    // PreToolUse: needs both hook_bin and hook_py
    let pre = hooks_obj.entry("PreToolUse").or_insert_with(|| json!([]));
    changed |= ensure_entry(pre, MATCHER, &[
        json!({"type": "command", "command": hook_bin}),
        json!({"type": "command", "command": hook_py}),
    ]);

    // PostToolUse: needs only hook_py
    let post = hooks_obj.entry("PostToolUse").or_insert_with(|| json!([]));
    changed |= ensure_entry(post, MATCHER, &[
        json!({"type": "command", "command": hook_py}),
    ]);

    changed
}

fn ensure_entry(array: &mut Value, matcher: &str, required: &[Value]) -> bool {
    let arr = array.as_array_mut().unwrap();
    if let Some(entry) = arr.iter_mut().find(|e| e["matcher"] == matcher) {
        let existing = entry["hooks"].as_array().cloned().unwrap_or_default();
        let missing: Vec<Value> = required
            .iter()
            .filter(|r| !existing.iter().any(|e| e["command"] == r["command"]))
            .cloned()
            .collect();
        if missing.is_empty() {
            return false;
        }
        let hooks_arr = entry["hooks"].as_array_mut().unwrap();
        hooks_arr.extend(missing);
        true
    } else {
        arr.push(json!({"matcher": matcher, "hooks": required}));
        true
    }
}

fn settings_json_path() -> PathBuf {
    dirs_next_home().join(".claude").join("settings.json")
}

fn dirs_next_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn resolve_python() -> Result<String, String> {
    if let Ok(prefix) = std::env::var("CONDA_PREFIX") {
        let p = PathBuf::from(prefix).join("bin/python");
        if p.exists() { return Ok(p.display().to_string()); }
    }
    for candidate in &["python3", "python"] {
        if let Ok(out) = Command::new("which").arg(candidate).output() {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() { return Ok(path); }
            }
        }
    }
    Err("nessun interprete Python trovato (CONDA_PREFIX, python3, python)".to_string())
}
