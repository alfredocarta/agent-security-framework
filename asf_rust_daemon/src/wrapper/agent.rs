use std::path::Path;

pub trait AgentAdapter {
    fn preflight(&self, asf_root: &Path) -> Result<(), String>;
    fn extra_env(&self) -> Vec<(String, String)>;
    fn executable(&self) -> String;
}

pub fn detect(name: &str) -> Result<Box<dyn AgentAdapter>, String> {
    match name {
        "claude" => Ok(Box::new(crate::claude::ClaudeAdapter::new())),
        "hermes" => Ok(Box::new(crate::hermes::HermesAdapter::new())),
        other => Err(format!(
            "agente non riconosciuto: '{other}'. Usa: claude | hermes"
        )),
    }
}
