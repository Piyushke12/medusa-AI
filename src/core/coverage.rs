//! Coverage computation: capability snapshots → category bars + profile gaps.
//! Pure functions; all inputs are explicit parameters.

use std::collections::{HashMap, HashSet};

use crate::model::{
    AssessmentProfile, CapabilityStatus, Importance, ProfileEvaluation, ToolStatus,
};
use crate::registry::{CapabilityRegistry, ToolRegistry};

/// Coverage percentage per display category (0–100), sorted by name.
#[derive(Debug, Clone, PartialEq)]
pub struct CategoryCoverage {
    pub category: String,
    pub pct: f64,
    pub covered: usize,
    pub total: usize,
}

pub fn category_coverage(
    caps: &CapabilityRegistry,
    statuses: &HashMap<String, ToolStatus>,
    tools: &ToolRegistry,
) -> Vec<CategoryCoverage> {
    let tools_by_id: HashMap<String, crate::model::ToolDefinition> = tools
        .all()
        .iter()
        .map(|t| (t.id.clone(), t.clone()))
        .collect();
    let snaps = super::discovery::derive_capabilities(statuses, &tools_by_id, caps);
    let by_id: HashMap<&str, &CapabilityStatus> =
        snaps.iter().map(|s| (s.id.as_str(), &s.status)).collect();

    let mut groups: HashMap<String, Vec<&str>> = HashMap::new();
    for c in caps.all() {
        groups
            .entry(c.category.clone())
            .or_default()
            .push(c.id.as_str());
    }
    let mut out: Vec<CategoryCoverage> = groups
        .into_iter()
        .map(|(category, ids)| {
            let total = ids.len();
            let covered = ids
                .iter()
                .filter(|id| {
                    matches!(
                        by_id.get(*id),
                        Some(CapabilityStatus::Covered) | Some(CapabilityStatus::Partial)
                    )
                })
                .count();
            let pct = if total == 0 {
                0.0
            } else {
                covered as f64 / total as f64 * 100.0
            };
            CategoryCoverage {
                category,
                pct,
                covered,
                total,
            }
        })
        .collect();
    out.sort_by(|a, b| a.category.cmp(&b.category));
    out
}

/// Evaluate the environment against one profile: coverage %, gaps by
/// importance, and recommended tools (providers of missing HIGH first,
// deduped, ordered by tool priority).
pub fn evaluate_profile(
    profile: &AssessmentProfile,
    statuses: &HashMap<String, ToolStatus>,
    tools: &ToolRegistry,
    caps: &CapabilityRegistry,
) -> ProfileEvaluation {
    let tools_by_id: HashMap<String, crate::model::ToolDefinition> = tools
        .all()
        .iter()
        .map(|t| (t.id.clone(), t.clone()))
        .collect();
    let snaps = super::discovery::derive_capabilities(statuses, &tools_by_id, caps);
    let by_id: HashMap<&str, &super::discovery::CommandOutput> = HashMap::new();
    let _ = by_id;
    let snap_by_id: HashMap<&str, _> = snaps.iter().map(|s| (s.id.as_str(), s)).collect();

    let mut covered = Vec::new();
    let mut missing_high = Vec::new();
    let mut missing_medium = Vec::new();
    let mut missing_low = Vec::new();

    for r in &profile.required {
        let is_up = snap_by_id.get(r.capability.as_str()).is_some_and(|s| {
            matches!(
                s.status,
                CapabilityStatus::Covered | CapabilityStatus::Partial
            )
        });
        if is_up {
            covered.push(r.capability.clone());
        } else {
            match r.importance {
                Importance::High => missing_high.push(r.capability.clone()),
                Importance::Medium => missing_medium.push(r.capability.clone()),
                Importance::Low => missing_low.push(r.capability.clone()),
            }
        }
    }

    let total = profile.required.len();
    let coverage_pct = if total == 0 {
        100.0
    } else {
        covered.len() as f64 / total as f64 * 100.0
    };

    // Recommend tools: providers of missing caps, HIGH first.
    let mut seen = HashSet::new();
    let mut scored: Vec<(u8, String)> = Vec::new();
    for cap_id in missing_high
        .iter()
        .chain(missing_medium.iter())
        .chain(missing_low.iter())
    {
        for p in tools.providers_of(cap_id) {
            if statuses
                .get(&p.id)
                .is_some_and(|s| s.installed && s.healthy)
            {
                continue; // already have it via another capability
            }
            if seen.insert(p.id.clone()) {
                scored.push((p.priority, p.id.clone()));
            }
        }
    }
    scored.sort_by_key(|(pri, _)| std::cmp::Reverse(*pri));
    let recommended_tools = scored.into_iter().map(|(_, id)| id).collect();

    ProfileEvaluation {
        profile_id: profile.id.clone(),
        coverage_pct,
        covered,
        missing_high,
        missing_medium,
        missing_low,
        recommended_tools,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statuses_with(installed: &[&str]) -> HashMap<String, ToolStatus> {
        let set: HashSet<&str> = installed.iter().copied().collect();
        let tools = ToolRegistry::builtin();
        tools
            .all()
            .iter()
            .map(|t| {
                let up = set.contains(t.id.as_str());
                (
                    t.id.clone(),
                    ToolStatus {
                        tool_id: t.id.clone(),
                        installed: up,
                        executable_path: up.then(|| format!("/usr/bin/{}", t.id)),
                        version: up.then(|| "1.0".to_string()),
                        platform: "linux".into(),
                        arch: "x64".into(),
                        healthy: up,
                        adapter_available: false,
                        capabilities: if up { t.capabilities.clone() } else { vec![] },
                        missing_dependencies: Vec::new(),
                        diagnostic: String::new(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn profile_coverage_counts_and_recommends() {
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let st = statuses_with(&["nmap", "httpx"]);
        let p = synthetic_profile(&caps);
        let ev = evaluate_profile(&p, &st, &tools, &caps);
        assert!(ev.coverage_pct < 100.0);
        assert!(!ev.missing_high.is_empty());
        // Recommendations must be installable providers, never already-installed.
        assert!(!ev.recommended_tools.contains(&"nmap".to_string()));
    }

    #[test]
    fn empty_environment_scores_zero_with_all_missing() {
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let st = statuses_with(&[]);
        let p = synthetic_profile(&caps);
        let ev = evaluate_profile(&p, &st, &tools, &caps);
        assert_eq!(ev.coverage_pct, 0.0);
        assert_eq!(ev.covered.len(), 0);
    }

    /// Every capability required — the registry presets are gone, so
    /// coverage tests evaluate the full set.
    fn synthetic_profile(caps: &CapabilityRegistry) -> crate::model::AssessmentProfile {
        crate::model::AssessmentProfile {
            id: "all".into(),
            name: "All capabilities".into(),
            description: String::new(),
            required: caps
                .all()
                .iter()
                .map(|c| crate::model::ProfileRequirement {
                    capability: c.id.clone(),
                    importance: c.importance,
                })
                .collect(),
        }
    }
}
