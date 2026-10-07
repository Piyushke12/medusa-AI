//! Capability data model. A capability is *what* can be tested;
//! a tool is *how*. Many tools may provide the same capability.

use serde::{Deserialize, Serialize};

/// Severity of a capability gap for assessment planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Importance {
    High,
    Medium,
    Low,
}

impl Importance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// Availability of a single capability after discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityStatus {
    Covered,
    Partial,
    NotAvailable,
}

impl CapabilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "COVERED",
            Self::Partial => "PARTIAL",
            Self::NotAvailable => "NOT_AVAILABLE",
        }
    }
}

/// How much load/risk a capability imposes on the target. The risk gate
/// in `policy.rs` blocks Destructive capabilities without explicit user
/// approval, regardless of what the model requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Read-only probing, indistinguishable from normal traffic.
    #[default]
    Safe,
    /// Generates noticeable request volume or touches many paths.
    Intrusive,
    /// Could disrupt the target (active exploitation, DoS-class checks).
    /// Requires explicit approval before execution.
    Destructive,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Safe => "safe",
                Self::Intrusive => "intrusive",
                Self::Destructive => "destructive",
            }
        )
    }
}

/// Static definition of one testable capability.
/// `options` is the capability's semantic argument schema: the ONLY
/// arguments the model may supply for this capability. Values are
/// validated against this schema before provider selection; raw flags
/// or commands can never pass through it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDefinition {
    pub id: String,
    pub category: String,
    pub description: String,
    pub importance: Importance,
    /// Healthy providers required for full coverage (default 1).
    pub min_providers_for_full: usize,
    /// When true, at least one provider must expose a medusa adapter.
    pub requires_adapter: bool,
    /// Risk classification for the policy gate. Destructive capabilities
    /// need explicit user approval before execution.
    #[serde(default)]
    pub risk: RiskLevel,
    /// Semantic options the model may pass with an execute decision.
    pub options: Vec<OptionSpec>,
}

/// One semantic option of a capability (e.g. `ports` for a port scan).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptionSpec {
    pub name: String,
    pub kind: OptionKind,
    pub description: String,
}

impl OptionSpec {
    /// Compact model-facing hint, e.g. `ports=<string>` or
    /// `intensity=<slow|normal|fast>`.
    pub fn hint(&self) -> String {
        match &self.kind {
            OptionKind::Str => format!("{}=<string>", self.name),
            OptionKind::Number { .. } => format!("{}=<number>", self.name),
            OptionKind::Bool => format!("{}=<true|false>", self.name),
            OptionKind::Enum { values } => {
                format!("{}=<{}>", self.name, values.join("|"))
            }
        }
    }
}

/// Allowed value shape for one option. Constraints (enum values, numeric
/// ranges) are enforced by the ExecutionPolicy before any provider runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OptionKind {
    Str,
    Number { min: Option<f64>, max: Option<f64> },
    Bool,
    Enum { values: Vec<String> },
}

/// Dynamic per-capability snapshot computed from tool statuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub id: String,
    pub status: CapabilityStatus,
    pub providers_available: Vec<String>,
    pub providers_total: Vec<String>,
}
