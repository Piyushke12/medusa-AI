//! Installation recommendations: informational only, never executed.
//! Rendering rules:
//! * verified package-manager entries → show the command, tagged `verified`.
//! * unverified entries → show the suggestion PLUS `verify with <mgr> search`
//!   and always link the official docs.
//! * docs-only entries → show steps + official URL, no command invented.

use crate::model::{Platform, ToolDefinition};

/// One platform's recommendation, ready to render.
#[derive(Debug, Clone)]
pub struct PlatformRecommendation {
    pub platform: Platform,
    pub lines: Vec<String>,
    pub docs_url: String,
}

/// Full recommendation for a tool.
#[derive(Debug, Clone)]
pub struct InstallRecommendation {
    pub tool_id: String,
    pub tool_name: String,
    pub provides: Vec<String>,
    pub per_platform: Vec<PlatformRecommendation>,
    pub docs_url: String,
}

fn recommend_for(def: &ToolDefinition, platform: Platform) -> PlatformRecommendation {
    let install = def.install_for(platform);
    let docs_fallback = def.docs_url.clone();
    match install {
        None => PlatformRecommendation {
            platform,
            lines: vec!["No installation guidance registered yet.".into()],
            docs_url: docs_fallback,
        },
        Some(entry) => {
            let mut lines = Vec::new();
            match (&entry.manager, &entry.package) {
                (Some(mgr), Some(pkg)) if entry.verified => {
                    let command = format!("{mgr} install {pkg}");
                    lines.push(format!("{command}  [verified]"));
                    // Registry instructions sometimes restate the command; skip
                    // the duplicate so output stays clean.
                    if !entry.instructions.is_empty() && entry.instructions != command {
                        lines.push(entry.instructions.clone());
                    }
                }
                (Some(mgr), Some(pkg)) => {
                    lines.push(format!("Suggested (verify first): {mgr} install {pkg}"));
                    lines.push(format!("Verify: {mgr} search {}", def.id));
                    if !entry.instructions.is_empty() {
                        lines.push(entry.instructions.clone());
                    }
                }
                _ => {
                    lines.push(entry.instructions.clone());
                }
            }
            PlatformRecommendation {
                platform,
                lines,
                docs_url: entry.docs_url.clone(),
            }
        }
    }
}

pub fn recommend(def: &ToolDefinition) -> InstallRecommendation {
    InstallRecommendation {
        tool_id: def.id.clone(),
        tool_name: def.name.clone(),
        provides: def.capabilities.clone(),
        per_platform: vec![
            recommend_for(def, Platform::Windows),
            recommend_for(def, Platform::Macos),
            recommend_for(def, Platform::Linux),
        ],
        docs_url: def.docs_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ToolRegistry;

    #[test]
    fn unverified_entries_force_verify_hint() {
        let tools = ToolRegistry::builtin();
        // trivy linux entry is intentionally unverified (repo-setup step).
        let rec = recommend(tools.get("trivy").unwrap());
        let linux = rec
            .per_platform
            .iter()
            .find(|p| p.platform == Platform::Linux)
            .unwrap();
        assert!(linux
            .lines
            .iter()
            .any(|l| l.contains("verify first") || l.contains("Verify:")));
    }

    #[test]
    fn verified_entries_are_tagged() {
        let tools = ToolRegistry::builtin();
        let rec = recommend(tools.get("nmap").unwrap());
        let mac = rec
            .per_platform
            .iter()
            .find(|p| p.platform == Platform::Macos)
            .unwrap();
        assert!(mac.lines.iter().any(|l| l.contains("[verified]")));
    }
}
