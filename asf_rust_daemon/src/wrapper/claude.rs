use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct ClaudeAdapter;

impl ClaudeAdapter {
    pub fn new() -> Self {
        ClaudeAdapter
    }
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

    fn extra_env(&self) -> Vec<(String, String)> {
        vec![]
    }

    fn executable(&self) -> String {
        "claude".to_string()
    }
}

const MATCHER: &str = "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch";

fn ensure_hooks(root: &mut Value, hook_bin: &str, hook_py: &str) -> bool {
    let hooks = root.as_object_mut().unwrap();
    let section = hooks.entry("hooks").or_insert_with(|| json!({}));
    let hooks_obj = section.as_object_mut().unwrap();

    let mut changed = false;

    // PreToolUse: needs both hook_bin and hook_py
    let pre = hooks_obj.entry("PreToolUse").or_insert_with(|| json!([]));
    changed |= ensure_entry(
        pre,
        MATCHER,
        &[
            json!({"type": "command", "command": hook_bin}),
            json!({"type": "command", "command": hook_py}),
        ],
    );

    // PostToolUse: needs only hook_py
    let post = hooks_obj.entry("PostToolUse").or_insert_with(|| json!([]));
    changed |= ensure_entry(
        post,
        MATCHER,
        &[json!({"type": "command", "command": hook_py})],
    );

    changed
}

fn ensure_entry(array: &mut Value, matcher: &str, required: &[Value]) -> bool {
    let arr = array.as_array_mut().unwrap();
    if let Some(entry) = arr.iter_mut().find(|e| e["matcher"] == matcher) {
        let hooks_arr = entry["hooks"].as_array_mut().unwrap();
        let mut changed = false;

        for required_hook in required {
            if is_asf_hook_command(required_hook) {
                changed |= ensure_single_asf_hook_entry(hooks_arr, required_hook);
            } else if !hooks_arr
                .iter()
                .any(|existing| existing["command"] == required_hook["command"])
            {
                hooks_arr.push(required_hook.clone());
                changed = true;
            }
        }

        changed
    } else {
        arr.push(json!({"matcher": matcher, "hooks": required}));
        true
    }
}

fn ensure_single_asf_hook_entry(hooks_arr: &mut Vec<Value>, required_hook: &Value) -> bool {
    let Some(first_idx) = hooks_arr.iter().position(is_asf_hook_command) else {
        hooks_arr.push(required_hook.clone());
        return true;
    };

    let mut changed = false;
    if hooks_arr[first_idx] != *required_hook {
        hooks_arr[first_idx] = required_hook.clone();
        changed = true;
    }

    let original_len = hooks_arr.len();
    let mut seen_asf_hook = false;
    hooks_arr.retain(|hook| {
        if is_asf_hook_command(hook) {
            if seen_asf_hook {
                return false;
            }
            seen_asf_hook = true;
        }
        true
    });

    changed || hooks_arr.len() != original_len
}

fn is_asf_hook_command(hook: &Value) -> bool {
    hook["command"]
        .as_str()
        .and_then(|command| command.split_whitespace().last())
        .is_some_and(|last_arg| last_arg.ends_with("asf_hook.py"))
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

#[cfg(test)]
mod tests {
    use super::*;

    const STALE_HOOK_PY: &str = "/usr/bin/python3 /repo/asf_hook.py";
    const CURRENT_HOOK_PY: &str = "/repo/asf-venv/bin/python3 /repo/asf_hook.py";
    const HOOK_BIN: &str = "/repo/asf_rust_daemon/target/release/asf-rust-hook";

    #[test]
    fn ensure_hooks_rewrites_stale_asf_hook_without_duplicates() {
        let mut root = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": MATCHER,
                    "hooks": [
                        {"type": "command", "command": HOOK_BIN},
                        {"type": "command", "command": STALE_HOOK_PY},
                        {"type": "command", "command": "/custom/python /custom/other_hook.py"},
                        {"type": "command", "command": "/another/python /repo/asf_hook.py"}
                    ]
                }],
                "PostToolUse": [{
                    "matcher": MATCHER,
                    "hooks": [
                        {"type": "command", "command": STALE_HOOK_PY},
                        {"type": "command", "command": "/custom/python /custom/other_hook.py"}
                    ]
                }]
            }
        });

        assert!(ensure_hooks(&mut root, HOOK_BIN, CURRENT_HOOK_PY));

        assert_asf_hook_commands(&root, "PreToolUse", &[CURRENT_HOOK_PY]);
        assert_asf_hook_commands(&root, "PostToolUse", &[CURRENT_HOOK_PY]);
        assert!(matcher_hooks(&root, "PreToolUse")
            .iter()
            .any(|hook| hook["command"] == HOOK_BIN));
        assert!(matcher_hooks(&root, "PreToolUse")
            .iter()
            .any(|hook| hook["command"] == "/custom/python /custom/other_hook.py"));
        assert!(matcher_hooks(&root, "PostToolUse")
            .iter()
            .any(|hook| hook["command"] == "/custom/python /custom/other_hook.py"));
    }

    #[test]
    fn ensure_hooks_is_noop_with_current_asf_hook() {
        let mut root = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": MATCHER,
                    "hooks": [
                        {"type": "command", "command": HOOK_BIN},
                        {"type": "command", "command": CURRENT_HOOK_PY},
                        {"type": "command", "command": "/custom/python /custom/other_hook.py"}
                    ]
                }],
                "PostToolUse": [{
                    "matcher": MATCHER,
                    "hooks": [
                        {"type": "command", "command": CURRENT_HOOK_PY}
                    ]
                }]
            }
        });
        let before = root.clone();

        assert!(!ensure_hooks(&mut root, HOOK_BIN, CURRENT_HOOK_PY));
        assert_eq!(root, before);
    }

    fn matcher_hooks<'a>(root: &'a Value, section: &str) -> &'a Vec<Value> {
        root["hooks"][section]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["matcher"] == MATCHER)
            .unwrap()["hooks"]
            .as_array()
            .unwrap()
    }

    fn assert_asf_hook_commands(root: &Value, section: &str, expected: &[&str]) {
        let commands: Vec<&str> = matcher_hooks(root, section)
            .iter()
            .filter(|hook| is_asf_hook_command(hook))
            .map(|hook| hook["command"].as_str().unwrap())
            .collect();

        assert_eq!(commands, expected);
    }
}
