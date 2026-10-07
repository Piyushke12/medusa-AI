//! Declarative registries. Containers + builtin data only.
//! No detection logic, no I/O, no process execution.

pub mod capabilities;
pub mod tools;

use std::collections::HashMap;

use crate::model::{CapabilityDefinition, ToolDefinition};

/// Container for tool definitions. New tools are added by registering a
/// [`ToolDefinition`] — the discovery engine never changes.
#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    tools: Vec<ToolDefinition>,
    by_id: HashMap<String, usize>,
}

impl ToolRegistry {
    pub fn builtin() -> Self {
        let mut reg = Self::default();
        for t in tools::builtin_tools() {
            reg.register(t);
        }
        reg
    }

    /// Add (or replace) a tool without touching the discovery engine.
    pub fn register(&mut self, def: ToolDefinition) {
        if let Some(&idx) = self.by_id.get(&def.id) {
            self.tools[idx] = def;
        } else {
            self.by_id.insert(def.id.clone(), self.tools.len());
            self.tools.push(def);
        }
    }

    pub fn get(&self, id: &str) -> Option<&ToolDefinition> {
        self.by_id.get(id).map(|&i| &self.tools[i])
    }

    pub fn all(&self) -> &[ToolDefinition] {
        &self.tools
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// All tools claiming to provide `capability`, ordered by priority desc.
    pub fn providers_of(&self, capability: &str) -> Vec<&ToolDefinition> {
        let mut out: Vec<&ToolDefinition> = self
            .tools
            .iter()
            .filter(|t| t.capabilities.iter().any(|c| c == capability))
            .collect();
        out.sort_by_key(|t| std::cmp::Reverse(t.priority));
        out
    }
}

/// Container for capability definitions.
#[derive(Debug, Clone, Default)]
pub struct CapabilityRegistry {
    caps: Vec<CapabilityDefinition>,
    by_id: HashMap<String, usize>,
}

impl CapabilityRegistry {
    pub fn builtin() -> Self {
        let mut reg = Self::default();
        for c in capabilities::builtin_capabilities() {
            reg.register(c);
        }
        reg
    }

    /// Add a capability without modifying the agent.
    pub fn register(&mut self, def: CapabilityDefinition) {
        if let Some(&idx) = self.by_id.get(&def.id) {
            self.caps[idx] = def;
        } else {
            self.by_id.insert(def.id.clone(), self.caps.len());
            self.caps.push(def);
        }
    }

    pub fn get(&self, id: &str) -> Option<&CapabilityDefinition> {
        self.by_id.get(id).map(|&i| &self.caps[i])
    }

    pub fn all(&self) -> &[CapabilityDefinition] {
        &self.caps
    }

    pub fn len(&self) -> usize {
        self.caps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_are_priority_ordered() {
        let tools = ToolRegistry::builtin();
        let p = tools.providers_of("network.port_scan");
        let ids: Vec<_> = p.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"nmap"));
        assert!(ids.contains(&"naabu"));
        // priority descending
        let pris: Vec<u8> = p.iter().map(|t| t.priority).collect();
        let mut sorted = pris.clone();
        sorted.sort_by_key(|&x| std::cmp::Reverse(x));
        assert_eq!(pris, sorted);
    }

    #[test]
    fn register_adds_tool_without_engine_change() {
        let mut reg = ToolRegistry::builtin();
        let n = reg.len();
        let mut def = reg.get("nmap").unwrap().clone();
        def.id = "nmap_test_clone".into();
        reg.register(def);
        assert_eq!(reg.len(), n + 1);
        assert!(reg.get("nmap_test_clone").is_some());
    }

    #[test]
    fn destructive_capabilities_are_marked() {
        let caps = CapabilityRegistry::builtin();
        assert_eq!(
            caps.get("web.vulnerability_scan").unwrap().risk,
            crate::model::RiskLevel::Destructive
        );
        assert_eq!(
            caps.get("web.oob_testing").unwrap().risk,
            crate::model::RiskLevel::Destructive
        );
        // Ordinary capabilities stay safe.
        assert_eq!(
            caps.get("network.port_scan").unwrap().risk,
            crate::model::RiskLevel::Safe
        );
    }
}
