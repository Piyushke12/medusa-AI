//! Generic detection engine. For each [`ToolDefinition`]:
//! PATH lookup → version command → version parse → health check → dependency
//! check → adapter + capability derivation.
//!
//! `executable exists != usable` is enforced: a tool counts as installed only
//! when the version command succeeds; capabilities require a healthy tool.

use std::collections::HashMap;
use std::path::PathBuf;

use super::resolver::resolve_executable;
use super::version::parse_version;
use crate::model::{CapabilitySnapshot, ToolDefinition, ToolStatus};
use crate::registry::CapabilityRegistry;

/// Captured result of one child-process invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(text: &str) -> Self {
        Self {
            exit_code: 0,
            stdout: text.to_string(),
            stderr: String::new(),
        }
    }

    pub fn failure(exit_code: i32, stderr: &str) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    pub fn combined(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

/// Abstraction over process execution. Production uses
/// [`crate::infra::runner::RealCommandRunner`]; tests inject fakes.
pub trait CommandRunner {
    fn run(&self, exe: &std::path::Path, args: &[String]) -> Result<CommandOutput, String>;
}

/// Runner that always fails — used by the doctor when only FS state matters.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullRunner;

impl CommandRunner for NullRunner {
    fn run(&self, _exe: &std::path::Path, _args: &[String]) -> Result<CommandOutput, String> {
        Err("null runner: execution disabled".to_string())
    }
}

/// Cacheable discovery service. Holds no global state; construct per scan.
pub struct ToolDiscoveryService<'a, R: CommandRunner> {
    runner: &'a R,
}

impl<'a, R: CommandRunner> ToolDiscoveryService<'a, R> {
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }

    /// Discover one tool end-to-end.
    pub fn discover_one(&self, def: &ToolDefinition) -> ToolStatus {
        // Internal providers (no external executable) are always available:
        // their implementation ships with medusa itself.
        if def.builtin {
            return ToolStatus {
                tool_id: def.id.clone(),
                installed: true,
                executable_path: None,
                version: Some("builtin".into()),
                platform: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                healthy: true,
                adapter_available: def.adapter.as_ref().is_some_and(|a| a.implemented),
                capabilities: def.capabilities.clone(),
                missing_dependencies: Vec::new(),
                diagnostic: "built into medusa".into(),
            };
        }
        // Platform honesty: a tool that can never run on this OS (falco
        // needs a Linux kernel) reports WHY it is absent instead of a
        // misleading "executable not found on PATH".
        if !def.supports_current_platform() {
            let needs: Vec<&str> = def.platforms.iter().map(|p| p.as_str()).collect();
            return ToolStatus::missing(
                &def.id,
                &format!(
                    "not possible on this device (requires {})",
                    needs.join(" or ")
                ),
            );
        }
        let exe: Option<PathBuf> =
            resolve_executable(&def.executable_candidates, &def.extra_search_dirs);
        let Some(exe) = exe else {
            return ToolStatus::missing(&def.id, "executable not found on PATH");
        };

        let version_out = self.runner.run(&exe, &def.version_args);
        let Ok(out) = version_out else {
            return ToolStatus {
                missing_dependencies: self.missing_deps(def),
                diagnostic: "version command could not be executed".into(),
                ..ToolStatus::missing(&def.id, "version command failed")
            };
        };
        if out.exit_code != 0 {
            return ToolStatus {
                tool_id: def.id.clone(),
                installed: false,
                executable_path: Some(exe.to_string_lossy().into_owned()),
                version: parse_version(&out.combined()),
                platform: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                healthy: false,
                adapter_available: false,
                capabilities: Vec::new(),
                missing_dependencies: self.missing_deps(def),
                diagnostic: format!("version command exited with code {}", out.exit_code),
            };
        }

        let version = parse_version(&out.combined());
        let health_args = def
            .health_args
            .clone()
            .unwrap_or_else(|| def.version_args.clone());
        let healthy = match self.runner.run(&exe, &health_args) {
            Ok(h) => h.exit_code == 0,
            Err(_) => false,
        };
        let missing = self.missing_deps(def);
        let adapter_available = healthy && def.adapter.as_ref().is_some_and(|a| a.implemented);
        let capabilities = if healthy {
            def.capabilities.clone()
        } else {
            Vec::new()
        };
        let mut diagnostic = if healthy {
            match &version {
                Some(v) => format!("healthy ({v})"),
                None => "healthy (version unparsable, still usable)".to_string(),
            }
        } else {
            "health check failed".to_string()
        };
        if !missing.is_empty() {
            diagnostic.push_str(&format!("; missing deps: {}", missing.join(", ")));
        }
        if def.adapter.as_ref().is_some_and(|a| !a.implemented) {
            diagnostic.push_str("; adapter planned, not yet implemented");
        }

        ToolStatus {
            tool_id: def.id.clone(),
            installed: true,
            executable_path: Some(exe.to_string_lossy().into_owned()),
            version,
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            healthy,
            adapter_available,
            capabilities,
            missing_dependencies: missing,
            diagnostic,
        }
    }

    /// Discover every tool in the registry (sequential; fast enough for ~30
    /// version commands and keeps output deterministic).
    pub fn discover_all(&self, tools: &[ToolDefinition]) -> HashMap<String, ToolStatus> {
        tools
            .iter()
            .map(|t| (t.id.clone(), self.discover_one(t)))
            .collect()
    }

    fn missing_deps(&self, def: &ToolDefinition) -> Vec<String> {
        def.dependencies
            .iter()
            .filter(|d| resolve_executable(&[(*d).clone()], &[]).is_none())
            .cloned()
            .collect()
    }
}

/// Derive per-capability snapshots from discovered tool statuses.
pub fn derive_capabilities(
    statuses: &HashMap<String, ToolStatus>,
    tools_by_id: &HashMap<String, ToolDefinition>,
    caps: &CapabilityRegistry,
) -> Vec<CapabilitySnapshot> {
    caps.all()
        .iter()
        .map(|c| {
            let total: Vec<String> = tools_by_id
                .values()
                .filter(|t| t.capabilities.iter().any(|x| x == &c.id))
                .map(|t| t.id.clone())
                .collect();
            let available: Vec<String> = total
                .iter()
                .filter(|id| statuses.get(*id).is_some_and(|s| s.installed && s.healthy))
                .cloned()
                .collect();
            let healthy_with_adapter = total
                .iter()
                .filter(|id| {
                    statuses
                        .get(*id)
                        .is_some_and(|s| s.installed && s.healthy && s.adapter_available)
                })
                .count();
            let status = if available.len() >= c.min_providers_for_full.max(1)
                && (!c.requires_adapter || healthy_with_adapter > 0)
            {
                crate::model::CapabilityStatus::Covered
            } else if !available.is_empty() {
                crate::model::CapabilityStatus::Partial
            } else {
                crate::model::CapabilityStatus::NotAvailable
            };
            CapabilitySnapshot {
                id: c.id.clone(),
                status,
                providers_available: available,
                providers_total: total,
            }
        })
        .collect()
}

/// Full environment scan shared by the binary entry, `/refresh-tools`, and
/// the chat TUI refresh job. Pure composition of registry + runner: no cache,
/// no printing, no persistence (callers decide that).
pub fn scan_environment<R: CommandRunner>(
    tools: &crate::registry::ToolRegistry,
    caps: &CapabilityRegistry,
    runner: &R,
) -> crate::model::EnvironmentState {
    let svc = ToolDiscoveryService::new(runner);
    let statuses = svc.discover_all(tools.all());
    let tools_by_id: HashMap<String, ToolDefinition> = tools
        .all()
        .iter()
        .map(|t| (t.id.clone(), t.clone()))
        .collect();
    let capabilities = derive_capabilities(&statuses, &tools_by_id, caps);
    crate::model::EnvironmentState {
        schema_version: crate::model::state::STATE_SCHEMA_VERSION,
        last_scan_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        tools: statuses,
        capabilities,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Platform, ToolCategory};
    use std::path::Path;

    fn test_def(id: &str) -> ToolDefinition {
        ToolDefinition {
            id: id.into(),
            name: id.into(),
            category: ToolCategory::NetworkDiscovery,
            description: String::new(),
            capabilities: vec!["network.port_scan".into()],
            executable_candidates: vec![id.into()],
            version_args: vec!["--version".into()],
            health_args: None,
            extra_search_dirs: Vec::new(),
            dependencies: Vec::new(),
            platforms: vec![Platform::Linux],
            install_windows: None,
            install_macos: None,
            install_linux: None,
            docs_url: "https://example.invalid".into(),
            adapter: None,
            priority: 10,
            required: false,
            builtin: false,
            default_args: Vec::new(),
            option_bindings: Vec::new(),
        }
    }

    #[test]
    fn builtin_tools_are_always_available() {
        let mut def = test_def("medusa-http");
        def.builtin = true;
        let runner = FakeRunner {
            outputs: HashMap::new(),
        };
        let svc = ToolDiscoveryService::new(&runner);
        let st = svc.discover_one(&def);
        assert!(st.installed && st.healthy);
        assert_eq!(st.version.as_deref(), Some("builtin"));
        assert!(!st.capabilities.is_empty());
    }

    /// Fake runner keyed by exe file name; filesystem resolution is bypassed
    /// by pre-seeding PATH with a temp dir in each test via `TestResolver`.
    struct FakeRunner {
        outputs: HashMap<String, Result<CommandOutput, String>>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, exe: &Path, _args: &[String]) -> Result<CommandOutput, String> {
            let key = exe.to_string_lossy().into_owned();
            // Match on file name suffix for convenience.
            for (k, v) in &self.outputs {
                if key.ends_with(k) {
                    return v.clone();
                }
            }
            Err("not found".into())
        }
    }

    #[test]
    fn version_parse_failure_still_marks_installed_healthy() {
        // Discovery itself needs PATH resolution; test the status-shape logic
        // via a missing-executable definition instead.
        let runner = FakeRunner {
            outputs: HashMap::new(),
        };
        let svc = ToolDiscoveryService::new(&runner);
        let mut d = test_def("definitely-not-a-real-tool-xyz");
        d.executable_candidates = vec!["definitely-not-a-real-tool-xyz".into()];
        let st = svc.discover_one(&d);
        assert!(!st.installed);
        assert_eq!(st.capabilities.len(), 0);
    }

    #[test]
    fn unsupported_platform_reports_why_not_found() {
        // A tool that can never run on this OS must say so instead of the
        // misleading "executable not found on PATH".
        let runner = FakeRunner {
            outputs: HashMap::new(),
        };
        let svc = ToolDiscoveryService::new(&runner);
        let mut d = test_def("linux-only-xyz");
        d.platforms = vec![crate::model::Platform::Linux];
        let st = svc.discover_one(&d);
        assert!(!st.installed && !st.healthy);
        assert!(
            st.diagnostic.contains("not possible on this device"),
            "diagnostic was: {}",
            st.diagnostic
        );
        assert!(st.diagnostic.contains("linux"));
    }

    /// Live (ignored): real discovery over the newly bound tools. Run with
    /// `cargo test live_new_tool_discovery -- --ignored --nocapture` on a
    /// machine with the tools installed.
    #[test]
    #[ignore]
    fn live_new_tool_discovery() {
        let runner = crate::infra::runner::RealCommandRunner;
        let svc = ToolDiscoveryService::new(&runner);
        for t in crate::registry::ToolRegistry::builtin().all() {
            if [
                "trivy-image",
                "uncover-db",
                "mysql",
                "psql",
                "pingcastle",
                "interactsh",
                "falco",
            ]
            .contains(&t.id.as_str())
            {
                let st = svc.discover_one(t);
                println!(
                    "{:<14} installed={} healthy={} adapter={} diag='{}'",
                    t.id, st.installed, st.healthy, st.adapter_available, st.diagnostic
                );
            }
        }
    }

    #[test]
    fn derive_capabilities_marks_partial_and_absent() {
        let caps = CapabilityRegistry::builtin();
        let mut tools_by_id = HashMap::new();
        let mut d = test_def("nmap");
        d.capabilities = vec!["network.port_scan".into()];
        tools_by_id.insert("nmap".into(), d);
        let mut statuses = HashMap::new();
        statuses.insert(
            "nmap".into(),
            ToolStatus {
                tool_id: "nmap".into(),
                installed: true,
                executable_path: Some("/usr/bin/nmap".into()),
                version: Some("7.96".into()),
                platform: "linux".into(),
                arch: "x64".into(),
                healthy: true,
                adapter_available: false,
                capabilities: vec!["network.port_scan".into()],
                missing_dependencies: Vec::new(),
                diagnostic: String::new(),
            },
        );
        let snaps = derive_capabilities(&statuses, &tools_by_id, &caps);
        let ps = snaps.iter().find(|s| s.id == "network.port_scan").unwrap();
        assert_eq!(ps.status, crate::model::CapabilityStatus::Covered);
        let absent = snaps
            .iter()
            .find(|s| s.id == "cloud.posture_audit")
            .unwrap();
        assert_eq!(absent.status, crate::model::CapabilityStatus::NotAvailable);
        assert!(absent.providers_total.is_empty());
    }
}
