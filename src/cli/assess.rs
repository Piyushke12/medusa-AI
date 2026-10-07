//! Rich inline investigation UI (Phase 1.6).
//!
//! Renders the [`AgentEvent`] stream with colors (`console`) and a thinking
//! spinner (`indicatif`). No hand-rolled escape sequences; output degrades to
//! plain text when piped. The full-screen ratatui UI will consume the same
//! event stream later.

use console::style;
use indicatif::{ProgressBar, ProgressDrawTarget};

use crate::agent::{
    AgentEvent, AgentRuntime, CliProvider, Decision, FinishReason, InvestigationResult,
    ModelProvider, OpenAiCompatibleProvider, OptionSet, ProviderRegistry, StubProvider, Target,
};
use crate::model::EnvironmentState;
use crate::registry::{CapabilityRegistry, ToolRegistry};

/// Spinner wrapper: started on `ModelThinking`, cleared by the next event.
struct Spinner {
    bar: Option<ProgressBar>,
}

impl Spinner {
    fn start(&mut self, msg: &str) {
        self.stop();
        let bar = ProgressBar::new_spinner();
        bar.set_draw_target(ProgressDrawTarget::stderr());
        bar.set_message(msg.to_string());
        bar.enable_steady_tick(std::time::Duration::from_millis(80));
        self.bar = Some(bar);
    }

    fn stop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}

pub struct EventRenderer {
    spinner: Spinner,
}

impl EventRenderer {
    pub fn new() -> Self {
        Self {
            spinner: Spinner { bar: None },
        }
    }

    pub fn on_event(&mut self, ev: &AgentEvent) {
        // Any real event supersedes the thinking spinner.
        if !matches!(ev, AgentEvent::ModelThinking) {
            self.spinner.stop();
        }
        match ev {
            AgentEvent::InvestigationStarted { target } => {
                println!(
                    "\n{}",
                    style(format!("Medusa — investigating {target}"))
                        .cyan()
                        .bold()
                );
                println!("{}", style("â”€".repeat(45)).dim());
            }
            AgentEvent::StepStarted { step } => {
                println!("{}", style(format!("Step {}", step + 1)).dim());
            }
            AgentEvent::ModelThinking => {
                self.spinner.start("Agent thinking…");
            }
            AgentEvent::ScopeGranted { target } => {
                println!("{}", style(format!("Scope: {target}")).dim());
            }
            AgentEvent::Reply { text } => {
                // Autonomous runs have no user; replies surface as narration.
                println!("\n{text}\n");
            }
            AgentEvent::Narrated { text } => {
                println!("\n{text}\n");
            }
            AgentEvent::CapabilityRequested {
                capability,
                target,
                reason,
                ..
            } => {
                // Verbal preamble (codex parity): show reason as agent thinking before tool, not just dim.
                if !reason.is_empty() {
                    println!("  {}", style(format!("â–£ thinking: {reason}")).cyan());
                }
                println!("  â””â”€ {capability} on {target}");
            }
            AgentEvent::ProviderSelected {
                capability,
                provider,
            } => {
                println!(
                    "     â””â”€ {}",
                    style(format!("{provider} selected for {capability}")).green()
                );
            }
            AgentEvent::ToolStarted {
                capability,
                provider,
            } => {
                println!("     â””â”€ executing {capability} via {provider}…");
            }
            AgentEvent::ToolFinished {
                capability,
                provider,
            } => {
                println!("     â””â”€ {capability} via {provider} done");
            }
            AgentEvent::ToolExecuted {
                tool_id,
                capability,
                target,
                exit_code,
                success,
                timed_out,
                output: _,
                ..
            } => {
                let status = if *timed_out {
                    "timed out"
                } else if *success {
                    "ok"
                } else {
                    "failed"
                };
                println!(
                    "     â””â”€ {tool_id} on {target} [{capability}] exit={exit_code} {status}"
                );
            }
            AgentEvent::ObservationAdded { summary } => {
                println!("  {} {summary}", style("â—‹").cyan());
            }
            AgentEvent::HypothesisAdded {
                id,
                statement,
                confidence,
            } => {
                println!(
                    "  {}",
                    style(format!("H{id} [{confidence}]: {statement}")).yellow()
                );
            }
            AgentEvent::ActionRejected { reason } => {
                println!(
                    "  {} {}",
                    style("? rejected:").red().bold(),
                    style(reason).red()
                );
            }
            AgentEvent::ApprovalRequested { capability, reason } => {
                println!(
                    "  {} {} — {}",
                    style("! approval:").yellow().bold(),
                    style(capability).yellow(),
                    style(reason).yellow()
                );
            }
            AgentEvent::Finished { reason } => {
                println!("{}", style(format!("Finished: {reason}")).bold());
            }
            AgentEvent::Error { message } => {
                eprintln!("  {} {}", style("!").red().bold(), style(message).red());
            }
            AgentEvent::Status { message } => {
                println!("  {} {}", style("~").dim().bold(), style(message).dim());
            }
            AgentEvent::FindingRecorded {
                id,
                severity,
                title,
                target,
                status,
                ..
            } => {                println!(
                    "  {}",
                    style(format!("F{id} [{severity}/{status}] {title} ({target})")).bold()
                );
            }
            AgentEvent::ContextUsage {
                used_tokens,
                limit_tokens,
                pct,
                estimated,
            } => {
                println!(
                    "  {}",
                    style(format!(
                        "context {used_tokens}/{limit_tokens} ({pct}%){}",
                        if *estimated { " (est.)" } else { "" }
                    ))
                    .dim()
                );
            }
            AgentEvent::Compacted {
                before_tokens,
                after_tokens,
                freed_tokens,
                fallback,
            } => {
                println!(
                    "  {}",
                    style(format!(
                        "compacted{}: {before_tokens} → {after_tokens} (freed {freed_tokens})",
                        if *fallback { " (fallback)" } else { "" }
                    ))
                    .yellow()
                );
            }
            AgentEvent::VaultStored { key, kind, refreshed } => {
                println!(
                    "  {}",
                    style(format!(
                        "vault: {key} [{kind}] {}",
                        if *refreshed { "refreshed" } else { "stored" }
                    ))
                    .dim()
                );
            }
            AgentEvent::VaultRecalled { key } => {
                println!("  {}", style(format!("vault: recalled {key}")).dim());
            }
        }
    }

    pub fn summary(&mut self, res: &InvestigationResult) {
        self.spinner.stop();
        println!("\n{}", style("Investigation summary").bold());
        println!("  steps: {}", res.steps_taken);
        println!("  finish: {}", finish_text(&res.finish_reason));
        if let Some(err) = &res.model_error {
            println!("  model error: {}", style(err).red());
        }
        println!("  planned actions (validated, NOT executed — execution is Phase 4):");
        if res.planned_actions.is_empty() {
            println!("    (none)");
        }
        for a in &res.planned_actions {
            println!(
                "    {} {} via {} on {}",
                style("•").green(),
                a.capability,
                a.provider,
                a.target
            );
        }
    }
}

impl Default for EventRenderer {
    fn default() -> Self {
        Self::new()
    }
}

fn finish_text(reason: &FinishReason) -> String {
    match reason {
        FinishReason::ModelFinished(r) => r.clone(),
        FinishReason::MaxSteps(n) => format!("max steps ({n})"),
        FinishReason::Cancelled => "cancelled".to_string(),
        FinishReason::TooManyModelErrors { count, last_error } => {
            format!("model failed {count} times in a row: {last_error}")
        }
        FinishReason::ConfigError(e) => format!("misconfigured: {e}"),
        FinishReason::ContextExhausted => {
            "context exhausted even after compaction — findings and vault kept".to_string()
        }
    }
}

/// Demo script used when no model endpoint is configured: one valid execute,
/// one deliberate rejection, one hypothesis. Real provider when env is set.
fn demo_script(state: &EnvironmentState) -> Vec<Decision> {
    let mut script = Vec::new();
    if state
        .available_capabilities()
        .contains(&"network.port_scan")
    {
        script.push(Decision::Execute {
            capability: "network.port_scan".into(),
            target: "127.0.0.1".into(),
            options: OptionSet::new(),
            reason: "demo: show provider resolution".into(),
        });
    }
    script.push(Decision::CreateHypothesis {
        statement: "demo hypothesis: external surface unknown".into(),
        confidence: "low".into(),
    });
    script
}

fn print_capability_table(state: &EnvironmentState, tools: &ToolRegistry) {
    let providers = ProviderRegistry::from_tools(tools);
    let mut available: Vec<String> = state
        .available_capabilities()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    available.sort();
    println!("{}", style("Capabilities").bold());
    if available.is_empty() {
        println!("  (none available — install tools first, see /install)");
    }
    for cap in &available {
        // Provider resolution as the runtime would do it: capability â†’
        // best healthy provider (policy/scope do not apply to display).
        match providers.select(cap, &OptionSet::new(), state) {
            Ok(p) => println!(
                "  {} {cap} {} {}",
                style("âœ“").green(),
                style("â†’").dim(),
                p.id()
            ),
            Err(_) => println!("  {} {cap} (no healthy provider)", style("~").yellow()),
        }
    }
    let missing = state.unavailable_capabilities().len();
    println!(
        "  {}",
        style(format!("âœ— {missing} capabilities unavailable",)).dim()
    );
}

/// Model selection shared by inline (`/assess`) and fullscreen (`/tui`) UI.
/// Real provider when file/env config resolves, otherwise the offline demo.
pub fn select_model(state: &EnvironmentState) -> (Box<dyn ModelProvider>, String) {
    match crate::infra::resolve_model_config(&crate::infra::load_file_config()) {
        Ok(crate::infra::ModelBackend::Http(cfg)) => {
            let base = cfg.base_url.clone();
            let p = OpenAiCompatibleProvider::new(cfg);
            let label = format!("{} ({base})", p.name());
            (Box::new(p), label)
        }
        Ok(crate::infra::ModelBackend::Cli(cfg)) => {
            let p = CliProvider::new(
                cfg.exe.clone(),
                cfg.args.clone(),
                cfg.label.clone(),
                cfg.timeout_secs,
            );
            let label = format!("{} (local harness `{}`)", p.name(), cfg.exe);
            (Box::new(p), label)
        }
        Err(_) => (
            Box::new(StubProvider::new(demo_script(state))),
            "stub (demo — no model configured)".to_string(),
        ),
    }
}

/// Entry point for `/assess <target>`. Picks the real model when
/// `MEDUSA_MODEL_*` is configured, otherwise the offline demo script.
pub fn run_assessment(
    target: &str,
    state: &EnvironmentState,
    tools: &ToolRegistry,
    caps: &CapabilityRegistry,
) {
    println!("\n{}", style("Target").bold());
    println!("  {target}");
    print_capability_table(state, tools);

    let (model, label) = select_model(state);
    if label.starts_with("stub") {
        println!("Model: {}", style(label).dim());
        println!("  {}", style(crate::infra::config_location_help()).dim());
    } else {
        println!("Model: {label}");
    }

    println!("\n{}", style("Investigation").bold());
    let rt = AgentRuntime::new(model, tools, caps, state);
    let mut ui = EventRenderer::new();
    let res = rt.investigate_with(Target::new(target), &mut |ev| ui.on_event(&ev));
    ui.summary(&res);
}
