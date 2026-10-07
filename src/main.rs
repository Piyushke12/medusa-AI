//! medusa binary entry point (thin by design).
//!
//! Boot: environment scan → chat TUI.
//! CLI flags for one-shot queries: `--doctor`, `--tools`, `--coverage`, `--json`.

use std::collections::HashMap;

use medusa_lib::cli::{Command, Ctx, Signal};
use medusa_lib::core::discovery::{derive_capabilities, scan_environment};
use medusa_lib::doctor::diagnose;
use medusa_lib::infra::cache::{load_state, now_unix, save_state, state_is_fresh};
use medusa_lib::infra::runner::RealCommandRunner;
use medusa_lib::model::EnvironmentState;
use medusa_lib::registry::{CapabilityRegistry, ToolRegistry};

const CACHE_TTL_SECS: i64 = 6 * 60 * 60;

fn full_scan(
    tools: &ToolRegistry,
    caps: &CapabilityRegistry,
    runner: &RealCommandRunner,
) -> EnvironmentState {
    let state = scan_environment(tools, caps, runner);
    if let Err(e) = save_state(&state) {
        eprintln!("warning: could not persist environment state: {e}");
    }
    state
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let force_refresh = args.iter().any(|a| a == "--refresh" || a == "-r");
    let no_scan = args.iter().any(|a| a == "--no-scan");
    let as_json = args.iter().any(|a| a == "--json");
    let once = args
        .iter()
        .find(|a| a.starts_with("--"))
        .and_then(|a| match a.as_str() {
            "--doctor" => Some("doctor"),
            "--tools" => Some("tools"),
            "--coverage" => Some("coverage"),
            _ => None,
        });

    let tools = ToolRegistry::builtin();
    let caps = CapabilityRegistry::builtin();
    let runner = RealCommandRunner;

    let mut state = if !force_refresh {
        load_state().filter(|s| state_is_fresh(s, CACHE_TTL_SECS, now_unix()))
    } else {
        None
    }
    .unwrap_or_else(|| EnvironmentState::empty());

    let needs_scan = force_refresh || state.tools.is_empty();
    if !no_scan && needs_scan {
        state = full_scan(&tools, &caps, &runner);
    } else if no_scan && state.tools.is_empty() {
        let tools_by_id: HashMap<String, medusa_lib::model::ToolDefinition> = tools
            .all()
            .iter()
            .map(|t| (t.id.clone(), t.clone()))
            .collect();
        state.capabilities = derive_capabilities(&state.tools, &tools_by_id, &caps);
    }

    if as_json {
        match serde_json::to_string_pretty(&state) {
            Ok(j) => println!("{j}"),
            Err(e) => eprintln!("serialize error: {e}"),
        }
        return;
    }

    if let Some("doctor") = once {
        let report = diagnose(&runner, &state, tools.len());
        println!("{}", medusa_lib::cli::render::render_doctor(&report));
        return;
    }

    if let Some(cmd) = once {
        let ctx = Ctx {
            state: &state,
            tools: &tools,
            caps: &caps,
        };
        let c = match cmd {
            "tools" => Command::Tools(None),
            "coverage" => Command::Coverage,
            _ => Command::Help,
        };
        let signal = medusa_lib::cli::dispatch(c, &ctx);
        match signal {
            Signal::Output(s) => println!("{s}"),
            Signal::Doctor => {
                let report = diagnose(&runner, &state, tools.len());
                println!("{}", medusa_lib::cli::render::render_doctor(&report));
            }
            _ => {}
        }
        return;
    }

    medusa_lib::cli::tui::run_chat_tui(&mut state, &tools, &caps);
}
