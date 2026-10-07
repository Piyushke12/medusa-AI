//! Persisted environment state: the single structured snapshot the future
//! AgentRuntime will consume. Serializable to JSON for caching.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::capability::CapabilitySnapshot;
use super::tool::ToolStatus;

/// Schema version for the on-disk cache. Bump on breaking changes.
pub const STATE_SCHEMA_VERSION: u32 = 1;

/// Complete, deterministic snapshot of the security-assessment environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentState {
    pub schema_version: u32,
    /// Unix timestamp of the scan that produced this state.
    pub last_scan_unix: i64,
    pub platform: String,
    pub arch: String,
    pub tools: HashMap<String, ToolStatus>,
    pub capabilities: Vec<CapabilitySnapshot>,
}

impl EnvironmentState {
    pub fn empty() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            last_scan_unix: 0,
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            tools: HashMap::new(),
            capabilities: Vec::new(),
        }
    }

    /// Capability ids with at least one healthy provider.
    pub fn available_capabilities(&self) -> Vec<&str> {
        self.capabilities
            .iter()
            .filter(|c| {
                matches!(
                    c.status,
                    super::capability::CapabilityStatus::Covered
                        | super::capability::CapabilityStatus::Partial
                )
            })
            .map(|c| c.id.as_str())
            .collect()
    }

    /// Capability ids with no provider at all.
    pub fn unavailable_capabilities(&self) -> Vec<&str> {
        self.capabilities
            .iter()
            .filter(|c| matches!(c.status, super::capability::CapabilityStatus::NotAvailable))
            .map(|c| c.id.as_str())
            .collect()
    }

    /// Providers per capability for agent consumption.
    pub fn providers(&self) -> HashMap<&str, &[String]> {
        self.capabilities
            .iter()
            .map(|c| (c.id.as_str(), c.providers_available.as_slice()))
            .collect()
    }

    pub fn installed_tool_count(&self) -> usize {
        self.tools.values().filter(|t| t.installed).count()
    }
}
