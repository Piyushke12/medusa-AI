//! Slash-command parsing + deterministic dispatch. No LLM, no I/O here:
//! the caller supplies `state` + registries; dispatch returns either printable
//! output or a control signal. Exception: `/assess` hands off to the agentic
//! runtime (non-deterministic by nature) via `Signal::Assess`.

use crate::core::coverage::evaluate_profile;
use crate::model::{EnvironmentState, ToolCategory};
use crate::registry::{CapabilityRegistry, ToolRegistry};

/// Parsed slash command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Tools(Option<String>),
    Tool(String),
    Capabilities(Option<String>),
    Coverage,
    Doctor,
    Install(Option<String>),
    RefreshTools,
    Help,
    Exit,
    /// Agentic investigation (non-deterministic; everything else is pure).
    Assess(String),
    /// Fullscreen TUI investigation (same event stream as Assess).
    Tui(String),
    Unknown(String),
}

impl Command {
    pub fn parse(line: &str) -> Self {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        let head = parts.next().unwrap_or("");
        let arg = parts.next().map(|s| s.to_string());
        match head {
            "/tools" => Self::Tools(arg),
            "/tool" => match arg {
                Some(a) => Self::Tool(a),
                None => Self::Unknown("/tool requires a tool name".into()),
            },
            "/capabilities" => Self::Capabilities(arg),
            "/coverage" => Self::Coverage,
            "/doctor" => Self::Doctor,
            "/install" => Self::Install(arg),
            "/refresh-tools" => Self::RefreshTools,
            "/help" => Self::Help,
            "/assess" => match arg {
                Some(a) => Self::Assess(a),
                None => Self::Unknown("/assess requires a target, e.g. /assess 127.0.0.1".into()),
            },
            "/tui" => match arg {
                Some(a) => Self::Tui(a),
                None => Self::Unknown("/tui requires a target, e.g. /tui 127.0.0.1".into()),
            },
            "/exit" | "/quit" => Self::Exit,
            _ => Self::Unknown(line.to_string()),
        }
    }
}

/// Control signals for the REPL loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// Render the string.
    Output(String),
    /// Rescan the environment, then render the string.
    Refresh(String),
    /// Render the environment-doctor report for current state.
    Doctor,
    /// Run an agentic investigation (handled by cli::assess, not here).
    Assess(String),
    /// Fullscreen TUI investigation (handled by cli::tui, not here).
    Tui(String),
    Exit,
}

/// Application context passed to dispatch (borrowed; dispatch never mutates).
pub struct Ctx<'a> {
    pub state: &'a EnvironmentState,
    pub tools: &'a ToolRegistry,
    pub caps: &'a CapabilityRegistry,
}

pub fn dispatch(cmd: Command, ctx: &Ctx) -> Signal {
    use super::render as R;
    match cmd {
        Command::Tools(filter) => {
            let cat = filter.as_deref().and_then(ToolCategory::from_id);
            if filter.is_some() && cat.is_none() {
                return Signal::Output(format!(
                    "unknown category `{}`. Known: {}",
                    filter.unwrap(),
                    ToolCategory::all()
                        .iter()
                        .map(|c| c.id())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Signal::Output(R::render_tools_table(ctx.state, ctx.tools, cat))
        }
        Command::Tool(id) => match R::render_tool_detail(ctx.state, ctx.tools, &id) {
            Ok(s) => Signal::Output(s),
            Err(e) => Signal::Output(e),
        },
        Command::Capabilities(None) => Signal::Output(R::render_capabilities(ctx.state)),
        Command::Capabilities(Some(id)) => {
            match R::render_capability_detail(ctx.state, ctx.tools, &id) {
                Ok(s) => Signal::Output(s),
                Err(e) => Signal::Output(e),
            }
        }
        Command::Coverage => {
            // Profile presets are gone; coverage now evaluates the full
            // capability set against the current environment.
            let all: crate::model::AssessmentProfile = crate::model::AssessmentProfile {
                id: "all".into(),
                name: "All capabilities".into(),
                description: "Every registered capability.".into(),
                required: ctx
                    .caps
                    .all()
                    .iter()
                    .map(|c| crate::model::ProfileRequirement {
                        capability: c.id.clone(),
                        importance: c.importance,
                    })
                    .collect(),
            };
            let ev = evaluate_profile(&all, &ctx.state.tools, ctx.tools, ctx.caps);
            Signal::Output(R::render_coverage(&ev))
        }
        Command::Doctor => Signal::Doctor,
        Command::Install(None) => {
            let mut missing: Vec<&str> = ctx
                .tools
                .all()
                .iter()
                .filter(|t| !ctx.state.tools.get(&t.id).is_some_and(|s| s.installed))
                .map(|t| t.id.as_str())
                .collect();
            missing.sort();
            if missing.is_empty() {
                Signal::Output("All registered tools are installed.".to_string())
            } else {
                Signal::Output(format!(
                    "Missing tools ({}):\n  {}\n\nRun /install <tool> for guidance.",
                    missing.len(),
                    missing.join("\n  ")
                ))
            }
        }
        Command::Install(Some(id)) => match ctx.tools.get(&id) {
            Some(def) => Signal::Output(R::render_install(&crate::install::recommend(def))),
            None => Signal::Output(format!("unknown tool `{id}`. Run /tools to list.")),
        },
        Command::RefreshTools => Signal::Refresh("Refreshing tool discovery...".to_string()),
        Command::Help => Signal::Output(super::render::HELP.to_string()),
        Command::Exit => Signal::Exit,
        Command::Assess(target) => Signal::Assess(target),
        Command::Tui(target) => Signal::Tui(target),
        Command::Unknown(line) => Signal::Output(format!(
            "unknown command `{line}`. Run /help for the command list."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        state: &'a EnvironmentState,
        tools: &'a ToolRegistry,
        caps: &'a CapabilityRegistry,
    ) -> Ctx<'a> {
        Ctx { state, tools, caps }
    }

    #[test]
    fn parses_all_slash_commands() {
        assert_eq!(Command::parse("/tools"), Command::Tools(None));
        assert_eq!(
            Command::parse("/tools network"),
            Command::Tools(Some("network".into()))
        );
        assert_eq!(Command::parse("/tool nmap"), Command::Tool("nmap".into()));
        assert_eq!(Command::parse("/doctor"), Command::Doctor);
        assert_eq!(
            Command::parse("/install nuclei"),
            Command::Install(Some("nuclei".into()))
        );
        assert_eq!(Command::parse("/refresh-tools"), Command::RefreshTools);
        assert_eq!(Command::parse("/exit"), Command::Exit);
        assert_eq!(
            Command::parse("/assess 127.0.0.1"),
            Command::Assess("127.0.0.1".into())
        );
        assert_eq!(
            Command::parse("/tui 127.0.0.1"),
            Command::Tui("127.0.0.1".into())
        );
    }

    #[test]
    fn unknown_tool_and_profile_are_deterministic_errors() {
        let state = EnvironmentState::empty();
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let c = ctx(&state, &tools, &caps);
        match dispatch(Command::Tool("nope".into()), &c) {
            Signal::Output(s) => assert!(s.contains("unknown tool")),
            _ => panic!("expected output"),
        }
        match dispatch(Command::Coverage, &c) {
            Signal::Output(s) => assert!(s.contains("coverage")),
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn install_without_arg_lists_missing() {
        let state = EnvironmentState::empty();
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let c = ctx(&state, &tools, &caps);
        match dispatch(Command::Install(None), &c) {
            Signal::Output(s) => assert!(s.contains("Missing tools")),
            _ => panic!("expected output"),
        }
    }
}
