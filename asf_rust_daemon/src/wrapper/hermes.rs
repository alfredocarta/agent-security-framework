use std::path::{Path, PathBuf};

pub struct HermesAdapter;

impl HermesAdapter {
    pub fn new() -> Self {
        HermesAdapter
    }
}

impl crate::agent::AgentAdapter for HermesAdapter {
    fn preflight(&self, asf_root: &Path) -> Result<(), String> {
        let plugin_dst = hermes_plugin_dir();
        let plugin_file = plugin_dst.join("__init__.py");

        if plugin_file.exists() {
            return Ok(());
        }

        let plugin_src = asf_root
            .join("integrations")
            .join("hermes")
            .join("asf_tracker_plugin.py");

        if !plugin_src.exists() {
            return Err(format!("sorgente plugin non trovata: {:?}", plugin_src));
        }

        std::fs::create_dir_all(&plugin_dst)
            .map_err(|e| format!("impossibile creare {:?}: {e}", plugin_dst))?;

        std::fs::copy(&plugin_src, &plugin_file)
            .map_err(|e| format!("copia plugin fallita: {e}"))?;

        eprintln!(
            "[asf-run] preflight: plugin asf-tracker installato in {:?}",
            plugin_file
        );
        Ok(())
    }

    fn extra_env(&self) -> Vec<(String, String)> {
        vec![
            ("ASF_HERMES_ENABLED".to_string(), "true".to_string()),
            ("ASF_HERMES_MODE".to_string(), "monitor".to_string()),
        ]
    }

    fn executable(&self) -> String {
        "python".to_string()
    }
}

fn hermes_plugin_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    home.join(".hermes").join("plugins").join("asf-tracker")
}
