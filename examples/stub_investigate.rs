//! Offline demo of the Phase 1 investigation loop.
//!
//! Run: `cargo run --example stub_investigate`
//!
//! Uses the REAL tool registry + cached environment state, but a SCRIPTED
//! model (no network, no API key). Shows: Execute → provider resolution →
//! Hypothesis → Finish, with one policy rejection fed back to the model.

use std::collections::HashMap;

use medusa_lib::agent::{AgentRuntime, Decision, StubProvider, Target};
use medusa_lib::core::discovery::derive_capabilities;
use medusa_lib::infra::cache::{load_state, now_unix, state_is_fresh};
use medusa_lib::model::EnvironmentState;
use medusa_lib::registry::{CapabilityRegistry, ToolRegistry};

fn main() {
    let tools = ToolRegistry::builtin();
    let caps = CapabilityRegistry::builtin();
    let state: EnvironmentState = load_state()
        .filter(|s| state_is_fresh(s, 6 * 60 * 60, now_unix()))
        .unwrap_or_else(|| {
            // No cache: empty state still demonstrates rejections + hypotheses.
            let tools_by_id: HashMap<String, medusa_lib::model::ToolDefinition> = tools
                .all()
                .iter()
                .map(|t| (t.id.clone(), t.clone()))
                .collect();
            let mut s = EnvironmentState::empty();
            s.capabilities = derive_capabilities(&s.tools, &tools_by_id, &caps);
            s
        });

    // Script: valid execute → invalid execute (rejected, fed back) → hypothesis → finish.
    let script = vec![
        Decision::Execute {
            capability: "network.port_scan".into(),
            target: "127.0.0.1".into(),
            options: Default::default(),
            reason: "open ports unknown on loopback".into(),
        },
        Decision::Execute {
            capability: "cloud.posture_audit".into(),
            target: "127.0.0.1".into(),
            options: Default::default(),
            reason: "deliberate mistake: no cloud provider installed".into(),
        },
        Decision::CreateHypothesis {
            statement: "Only loopback was assessed; external surface unknown".into(),
            confidence: "low".into(),
        },
    ];
    let rt = AgentRuntime::new(Box::new(StubProvider::new(script)), &tools, &caps, &state);
    let res = rt.investigate(Target::new("127.0.0.1"));

    println!("Target: {}", res.target.address);
    println!("Steps taken: {}", res.steps_taken);
    println!("Finish: {:?}", res.finish_reason);
    println!("\nPlanned actions (validated, NOT executed - execution is Phase 4):");
    for a in &res.planned_actions {
        println!(
            "  step {}: {} via {} on {} ({})",
            a.step, a.capability, a.provider, a.target, a.reason
        );
    }
}
