//! Tool data model: definition (static, declarative) vs status (dynamic, discovered).

use serde::{Deserialize, Serialize};

/// Assessment area a tool belongs to. Categories group *tools* for display;
/// capabilities group *what the agent can do* (see `model::capability`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    NetworkDiscovery,
    DnsAsset,
    ExternalSurface,
    HttpWebDiscovery,
    WebSecurity,
    TrafficAnalysis,
    SourceAnalysis,
    SupplyChain,
    ContainerK8s,
    BinaryRe,
    Cloud,
    Database,
    Identity,
}

impl ToolCategory {
    pub fn id(self) -> &'static str {
        match self {
            Self::NetworkDiscovery => "network",
            Self::DnsAsset => "dns",
            Self::ExternalSurface => "external",
            Self::HttpWebDiscovery => "http",
            Self::WebSecurity => "web",
            Self::TrafficAnalysis => "traffic",
            Self::SourceAnalysis => "source",
            Self::SupplyChain => "supply_chain",
            Self::ContainerK8s => "container",
            Self::BinaryRe => "binary",
            Self::Cloud => "cloud",
            Self::Database => "database",
            Self::Identity => "identity",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::NetworkDiscovery => "Network Recon",
            Self::DnsAsset => "DNS / Asset Discovery",
            Self::ExternalSurface => "External Attack Surface",
            Self::HttpWebDiscovery => "HTTP / Web",
            Self::WebSecurity => "Web Security Testing",
            Self::TrafficAnalysis => "Traffic Analysis",
            Self::SourceAnalysis => "Source Analysis",
            Self::SupplyChain => "Dependency / Supply Chain",
            Self::ContainerK8s => "Container / Runtime",
            Self::BinaryRe => "Binary / Reverse Engineering",
            Self::Cloud => "Cloud Security",
            Self::Database => "Database Security",
            Self::Identity => "Identity / Directory",
        }
    }

    pub fn all() -> &'static [ToolCategory] {
        use ToolCategory::*;
        &[
            NetworkDiscovery,
            DnsAsset,
            ExternalSurface,
            HttpWebDiscovery,
            WebSecurity,
            TrafficAnalysis,
            SourceAnalysis,
            SupplyChain,
            ContainerK8s,
            BinaryRe,
            Cloud,
            Database,
            Identity,
        ]
    }

    pub fn from_id(id: &str) -> Option<Self> {
        let norm = id.to_ascii_lowercase();
        Self::all()
            .iter()
            .find(|c| c.id() == norm || c.display_name().to_ascii_lowercase() == norm)
            .copied()
    }
}

/// Target operating system for an installation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        return Self::Windows;
        #[cfg(target_os = "macos")]
        return Self::Macos;
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        return Self::Linux;
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
        }
    }
}

/// How an installation method is sourced. Only `PackageManager` entries with
/// `verified == true` may be rendered as copy-paste commands; everything else
/// is rendered as "see official docs" to avoid fabricating install commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    PackageManager,
    BinaryRelease,
    Documentation,
}

/// Per-platform installation guidance for one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInstall {
    pub kind: InstallKind,
    /// e.g. "brew", "apt", "winget". `None` for docs-only entries.
    pub manager: Option<String>,
    /// Package id within the manager. `None` for docs-only entries.
    pub package: Option<String>,
    /// Human-readable steps. Never auto-executed.
    pub instructions: String,
    /// True only when manager+package were verified against official docs.
    pub verified: bool,
    /// Official documentation URL (not a mirror, not a blog).
    pub docs_url: String,
}

impl PlatformInstall {
    pub fn docs_only(instructions: &str, docs_url: &str) -> Self {
        Self {
            kind: InstallKind::Documentation,
            manager: None,
            package: None,
            instructions: instructions.to_string(),
            verified: false,
            docs_url: docs_url.to_string(),
        }
    }
}

/// Adapter binding between medusa's future ToolRuntime and the real tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterInfo {
    /// Stable adapter id, e.g. "nmap_xml".
    pub id: String,
    /// False means "planned but not implemented in Phase 0".
    pub implemented: bool,
}

/// Semantic option → provider flag binding. This is the trusted
/// provider-specific argument translation data: a whitelisted semantic
/// option (declared by the capability's schema) is mapped onto this
/// tool's CLI flag. The model never sees or constructs flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionBinding {
    /// Capability the binding applies to (one tool may bind the same
    /// option name differently per capability).
    pub capability: String,
    /// Semantic option name from the capability schema, e.g. "ports".
    pub option: String,
    /// Provider flag, e.g. "-p".
    pub flag: String,
    /// True emits `-pVALUE`, false emits `-p VALUE`.
    pub joined: bool,
    /// Optional enum-value translation, e.g. "slow" → "2" for nmap -T.
    pub value_map: Vec<(String, String)>,
}

/// Static, declarative description of a security tool.
/// Detection logic must NOT live here — see `core::discovery`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub id: String,
    pub name: String,
    pub category: ToolCategory,
    pub description: String,
    /// Capability ids this tool provides, e.g. "network.port_scan".
    pub capabilities: Vec<String>,
    /// Executable names to search on PATH, in preference order.
    pub executable_candidates: Vec<String>,
    /// Args for the version command, e.g. ["--version"].
    pub version_args: Vec<String>,
    /// Optional extra health-check args (default: reuse version command).
    pub health_args: Option<Vec<String>>,
    /// Extra dirs to search beyond PATH (platform-specific locations).
    pub extra_search_dirs: Vec<String>,
    /// Executable names that must also resolve (e.g. "java" for ZAP).
    pub dependencies: Vec<String>,
    pub platforms: Vec<Platform>,
    pub install_windows: Option<PlatformInstall>,
    pub install_macos: Option<PlatformInstall>,
    pub install_linux: Option<PlatformInstall>,
    pub docs_url: String,
    pub adapter: Option<AdapterInfo>,
    /// 0-100: higher wins when the agent must choose between providers.
    pub priority: u8,
    /// True marks baseline tooling (git, runtimes) vs assessment tools.
    pub required: bool,
    /// True for internal providers with no external executable: discovery
    /// reports them installed + healthy without a PATH probe, and provider
    /// construction swaps the CLI ProcessProvider for the internal
    /// implementation (e.g. the medusa-http request provider).
    #[serde(default)]
    pub builtin: bool,
    /// Default arguments for invocation against a target. Contains
    /// `{target}` placeholder which the executor substitutes. E.g.
    /// `["-sV", "{target}"]` for nmap service detection.
    pub default_args: Vec<String>,
    /// Semantic option bindings (trusted translation table).
    pub option_bindings: Vec<OptionBinding>,
}

impl ToolDefinition {
    pub fn install_for(&self, platform: Platform) -> Option<&PlatformInstall> {
        match platform {
            Platform::Windows => self.install_windows.as_ref(),
            Platform::Macos => self.install_macos.as_ref(),
            Platform::Linux => self.install_linux.as_ref(),
        }
    }

    pub fn supports_current_platform(&self) -> bool {
        let cur = Platform::current();
        self.platforms.contains(&cur)
    }
}

/// Dynamic result of discovering one tool. Produced by `core::discovery`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStatus {
    pub tool_id: String,
    pub installed: bool,
    pub executable_path: Option<String>,
    pub version: Option<String>,
    pub platform: String,
    pub arch: String,
    pub healthy: bool,
    pub adapter_available: bool,
    /// Capabilities actually available (empty when not installed/healthy).
    pub capabilities: Vec<String>,
    pub missing_dependencies: Vec<String>,
    pub diagnostic: String,
}

impl ToolStatus {
    pub fn missing(tool_id: &str, diagnostic: &str) -> Self {
        Self {
            tool_id: tool_id.to_string(),
            installed: false,
            executable_path: None,
            version: None,
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            healthy: false,
            adapter_available: false,
            capabilities: Vec::new(),
            missing_dependencies: Vec::new(),
            diagnostic: diagnostic.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_round_trips_by_id() {
        for c in ToolCategory::all() {
            assert_eq!(ToolCategory::from_id(c.id()), Some(*c));
        }
        assert_eq!(ToolCategory::from_id("nope"), None);
    }
}
