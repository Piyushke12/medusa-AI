//! Environment Doctor: aggregates platform facts + tool/capability state into
//! a deterministic diagnosis. Explains *why* each dependency matters and never
//! fails hard on a missing probe.

use crate::core::discovery::CommandRunner;
use crate::infra::platform::{collect_platform_info, PlatformInfo};
use crate::infra::runner::exe_exists;
use crate::model::EnvironmentState;

/// One diagnosed problem with remediation guidance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorIssue {
    /// `!` warning vs `x` blocker. Phase 0 never blocks; all are warnings.
    pub severity: char,
    pub message: String,
    pub why_it_matters: String,
    pub remediation: String,
}

/// Full doctor report. Rendered by `cli::render`; data stays UI-free.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub platform: PlatformInfo,
    pub tools_installed: usize,
    pub tools_total: usize,
    pub capabilities_covered: usize,
    pub capabilities_total: usize,
    pub packet_capture_ok: bool,
    pub issues: Vec<DoctorIssue>,
}

pub fn diagnose<R: CommandRunner>(
    runner: &R,
    state: &EnvironmentState,
    tools_total: usize,
) -> DoctorReport {
    let platform = collect_platform_info(runner);
    let tools_installed = state.installed_tool_count();
    let capabilities_covered = state.available_capabilities().len();
    let capabilities_total = state.capabilities.len();
    let packet_capture_ok = state
        .available_capabilities()
        .iter()
        .any(|c| *c == "packet.capture");

    let mut issues = Vec::new();

    if !packet_capture_ok {
        issues.push(DoctorIssue {
            severity: '!',
            message: "Packet capture unavailable (no provider for packet.capture)".into(),
            why_it_matters:
                "Raw traffic capture backs protocol analysis and evidence-grade findings.".into(),
            remediation: "Install Wireshark/TShark (includes Npcap on Windows) or tcpdump.".into(),
        });
    }
    #[cfg(target_os = "windows")]
    if exe_exists("tshark").is_some() && std::env::var_os("NPCAP").is_none() {
        // Npcap presence is hard to probe without registry access; phrase as check.
        issues.push(DoctorIssue {
            severity: '!',
            message: "Npcap status could not be confirmed".into(),
            why_it_matters: "Nmap/Npcap-based scanning and capture need the Npcap driver.".into(),
            remediation: "Re-run the Nmap installer with Npcap, or install Npcap OEM.".into(),
        });
    }
    // Cloud gaps are aggregated into one issue naming the canonical provider
    // instead of one issue per capability.
    let missing_cloud: Vec<&str> = state
        .unavailable_capabilities()
        .into_iter()
        .filter(|c| c.starts_with("cloud."))
        .collect();
    if !missing_cloud.is_empty() {
        issues.push(DoctorIssue {
            severity: '!',
            message: format!(
                "{} cloud capabilities uncovered ({})",
                missing_cloud.len(),
                missing_cloud.join(", ")
            ),
            why_it_matters: "Cloud posture/IAM/storage gaps stay invisible without a provider."
                .into(),
            remediation:
                "Install the canonical provider Prowler (`/install prowler`), then /refresh-tools."
                    .into(),
        });
    }
    // Zero-provider families (identity/database/api) are structural gaps, not
    // missing installs — one pointer issue is enough.
    let structural: Vec<&str> = state
        .capabilities
        .iter()
        .filter(|s| {
            matches!(s.status, crate::model::CapabilityStatus::NotAvailable)
                && s.providers_total.is_empty()
                && (s.id.starts_with("identity.")
                    || s.id.starts_with("database.")
                    || s.id.starts_with("api."))
        })
        .map(|s| s.id.as_str())
        .collect();
    if !structural.is_empty() {
        issues.push(DoctorIssue {
            severity: '!',
            message: format!(
                "{} capabilities have no registered provider yet (identity/database/api)",
                structural.len()
            ),
            why_it_matters: "The registry tracks these families so the future agent can reason about the gap instead of silently skipping it.".into(),
            remediation: "Register a specialized provider via ToolRegistry::register when that family is implemented."
                .into(),
        });
    }
    if !platform.has_docker {
        issues.push(DoctorIssue {
            severity: '!',
            message: "Docker not detected".into(),
            why_it_matters:
                "Several scanners (ZAP, Semgrep, Falco lab setups) ship first-class Docker images."
                    .into(),
            remediation: "Install Docker Desktop (Windows/macOS) or docker.io (Linux).".into(),
        });
    }
    if !platform.network_ok {
        issues.push(DoctorIssue {
            severity: '!',
            message: "Outbound network probe failed (8.8.8.8:53 unreachable)".into(),
            why_it_matters: "DNS enumeration, template updates and most scanning need egress."
                .into(),
            remediation: "Check VPN/proxy/firewall rules for outbound UDP/53 + TCP/443.".into(),
        });
    }
    if platform.path_entries == 0 {
        issues.push(DoctorIssue {
            severity: 'x',
            message: "PATH is empty or unreadable".into(),
            why_it_matters: "No executable can be resolved without PATH.".into(),
            remediation: "Restore the system PATH and re-run /refresh-tools.".into(),
        });
    }
    // Missing baseline deps surfaced per-tool.
    for st in state.tools.values().filter(|t| t.installed) {
        for dep in &st.missing_dependencies {
            issues.push(DoctorIssue {
                severity: '!',
                message: format!("{} is missing dependency `{dep}`", st.tool_id),
                why_it_matters: "The tool is installed but may fail at runtime.".into(),
                remediation: format!("Install `{dep}`, then run /refresh-tools."),
            });
        }
    }

    DoctorReport {
        platform,
        tools_installed,
        tools_total,
        capabilities_covered,
        capabilities_total,
        packet_capture_ok,
        issues,
    }
}
