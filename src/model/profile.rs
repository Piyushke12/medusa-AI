//! Assessment profiles: declarative sets of recommended capabilities.
//! Profiles never contain tool names — only capability ids.

use serde::{Deserialize, Serialize};

use super::capability::Importance;

/// One capability required/recommended by a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRequirement {
    pub capability: String,
    pub importance: Importance,
}

/// A named assessment profile, e.g. `high_coverage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub required: Vec<ProfileRequirement>,
}

/// Result of evaluating the current environment against a profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileEvaluation {
    pub profile_id: String,
    pub coverage_pct: f64,
    pub covered: Vec<String>,
    pub missing_high: Vec<String>,
    pub missing_medium: Vec<String>,
    pub missing_low: Vec<String>,
    /// Suggested tool ids that would close the gaps, ordered by impact.
    pub recommended_tools: Vec<String>,
}
