//! Chat-first inline TUI (opencode/Claude-CLI style).
//!
//! `medusa` boots here: a conversation, not a command prompt. Natural
//! language goes to the model via [`route_utterance`] — `chat` replies
//! render as messages, `assess <target>` runs the SAME `AgentRuntime` loop
//! as `/assess`, its [`AgentEvent`] stream rendered inline. Slash commands
//! (`/tools`, `/doctor`, …) keep working inside the input box.
//!
//! Architecture:
//! * Messages are printed ONCE into the terminal's real scrollback via
//!   [`Terminal::insert_before`] — never redrawn, so native click-drag
//!   text selection is stable and the conversation survives app exit.
//! * The inline viewport anchors at the CURSOR row (ratatui semantics):
//!   at startup we place it so the input row sits mid-screen (claude-code
//!   style) and paint the rest of the screen with static theme-background
//!   rows. As messages print, `insert_before` pushes the viewport down
//!   until it settles at the bottom — no alternate screen, no mouse
//!   capture, only a 3-row live area ever redraws.
//!
//! Keys (opencode parity): type + `Enter` send · `↑`/`↓` prompt history ·
//! `PgUp`/`PgDn` scroll the transcript (temporary overlay) · `Esc` clears
//! input / interrupts · `Ctrl+C` cancels (quits when idle) · `Ctrl+D`
//! quits. Mouse wheel always scrolls the terminal's native scrollback.

use std::io::IsTerminal;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use crossterm::{
    cursor::MoveTo,
    event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    style::Color as CColor,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Terminal, TerminalOptions, Viewport,
};

use crate::agent::{AgentEvent, AgentRuntime, ModelProvider, Target};
use crate::cli::{dispatch, Command, Ctx, Signal};
use crate::core::discovery::scan_environment;
use crate::infra::runner::RealCommandRunner;
use crate::model::EnvironmentState;
use crate::registry::{CapabilityRegistry, ToolRegistry};

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Rows the live area reserves: status, input, footer.
const LIVE_ROWS: u16 = 3;
/// Left/right inset so printed text never touches the terminal edge.
const MARGIN: u16 = 2;

/// Input placeholder suggestions (opencode-style cycling hints).
const PROMPT_PLACEHOLDERS: &[&str] = &[
    "assess scanme.nmap.org",
    "what can you test?",
    "assess https://example.com",
    "/doctor",
];

/// Lines the landing cluster (logo + blank) occupies before the input.
const LANDING_LINES: u16 = 4;

/// Error dialog (opencode-style DialogAlert) for showing critical errors.
struct ErrorDialog {
    title: String,
    message: String,
    visible: bool,
}

impl ErrorDialog {
    fn new(title: String, message: String) -> Self {
        Self {
            title,
            message,
            visible: true,
        }
    }

    fn close(&mut self) {
        self.visible = false;
    }

    fn is_open(&self) -> bool {
        self.visible
    }

    fn render(&self, f: &mut ratatui::Frame<'_>, area: ratatui::layout::Rect) {
        use crate::cli::theme as t;
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::style::{Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Paragraph};

        if area.height < 6 {
            let text = format!(
                "{}: {} [press enter/esc to dismiss]",
                self.title, self.message
            );
            let para = Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: true })
                .style(Style::default().fg(t::TEXT).bg(t::BG));
            f.render_widget(para, area);
            return;
        }

        let block = Block::default()
            .style(Style::default().bg(t::BG))
            .title(Span::styled(
                format!(" {} ", self.title),
                Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
            ))
            .title_alignment(ratatui::layout::Alignment::Center)
            .borders(ratatui::widgets::Borders::ALL)
            .border_style(Style::default().fg(t::PRIMARY));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let inner_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .horizontal_margin(2)
            .vertical_margin(1)
            .split(inner);

        // Message
        let message = Paragraph::new(self.message.as_str())
            .wrap(ratatui::widgets::Wrap { trim: true })
            .style(Style::default().fg(crate::cli::theme::TEXT));
        f.render_widget(message, inner_layout[1]);

        // Footer with key hint
        let footer = Line::from(Span::styled(
            " press enter/esc to dismiss ",
            Style::default().fg(crate::cli::theme::TEXT_MUTED),
        ));
        f.render_widget(Paragraph::new(footer).alignment(Alignment::Center), area);
    }
}

/// Approval dialog for high-risk capabilities (Destructive tests) and generic chat questions.
/// Single-select with ↑/↓ and Enter, third option is always "Type your own answer".
struct ApprovalDialog {
    title: String,
    message: String,
    options: Vec<String>,
    selected: usize,
    visible: bool,
    /// True if this dialog was created from a chat question (e.g. "Do you approve web.vulnerability_scan? - Yes - No")
    /// vs high-risk policy gate. Affects Enter handling: chat Yes → send "Yes" as next input.
    is_chat_question: bool,
}

impl ApprovalDialog {
    fn new(title: String, message: String) -> Self {
        Self {
            title,
            message,
            options: vec![
                "Allow once".to_string(),
                "Deny".to_string(),
                "Type your own answer".to_string(),
            ],
            selected: 0,
            visible: true,
            is_chat_question: false,
        }
    }
    fn new_chat_question(title: String, message: String) -> Self {
        Self {
            title,
            message,
            options: vec![
                "Yes".to_string(),
                "No".to_string(),
                "Type your own answer".to_string(),
            ],
            selected: 0,
            visible: true,
            is_chat_question: true,
        }
    }
    fn up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }
    fn down(&mut self) {
        if self.selected + 1 < self.options.len() {
            self.selected += 1;
        }
    }
    fn selected_option(&self) -> &str {
        &self.options[self.selected]
    }
    fn close(&mut self) {
        self.visible = false;
    }
    fn is_open(&self) -> bool {
        self.visible
    }
    fn render(&self, f: &mut ratatui::Frame<'_>, area: ratatui::layout::Rect) {
        use crate::cli::theme as t;
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::style::{Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Paragraph};

        // For inline viewport (height 3), render compact without border to avoid buffer overflow.
        if area.height < 6 {
            let opts: Vec<String> = self
                .options
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    if i == self.selected {
                        format!("▸{o}")
                    } else {
                        format!(" {o}")
                    }
                })
                .collect();
            let text = format!("{}: {} [{}]", self.title, self.message, opts.join(" | "));
            let para = Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: true })
                .style(Style::default().fg(t::TEXT).bg(t::BG));
            f.render_widget(para, area);
            return;
        }

        let block = Block::default()
            .style(Style::default().bg(t::BG))
            .title(Span::styled(
                format!(" {} ", self.title),
                Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
            ))
            .title_alignment(ratatui::layout::Alignment::Center)
            .borders(ratatui::widgets::Borders::ALL)
            .border_style(Style::default().fg(t::PRIMARY));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let inner_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .horizontal_margin(2)
            .vertical_margin(1)
            .split(inner);

        let question = Paragraph::new(self.message.as_str())
            .wrap(ratatui::widgets::Wrap { trim: true })
            .style(Style::default().fg(crate::cli::theme::TEXT));
        f.render_widget(question, inner_layout[0]);

        let mut lines: Vec<Line> = Vec::new();
        for (i, opt) in self.options.iter().enumerate() {
            let is_sel = i == self.selected;
            let prefix = if is_sel { "▸ " } else { "  " };
            let style = if is_sel {
                Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(t::TEXT_MUTED)
            };
            lines.push(Line::from(Span::styled(format!("{prefix}{opt}"), style)));
        }
        let opts = Paragraph::new(lines);
        f.render_widget(opts, inner_layout[1]);

        let footer = Line::from(Span::styled(
            " ↑↓ navigate · enter select · esc deny ",
            Style::default().fg(crate::cli::theme::TEXT_MUTED),
        ));
        f.render_widget(
            Paragraph::new(footer).alignment(ratatui::layout::Alignment::Center),
            inner_layout[2],
        );
    }
}

fn extract_target_from_question(msg: &str) -> Option<String> {
    for token in msg.split_whitespace() {
        let t = token.trim_matches(|c| {
            matches!(
                c,
                '"' | '\'' | ',' | '.' | ';' | ':' | '!' | '?' | ')' | '(' | '`'
            )
        });
        if t.starts_with("http://") || t.starts_with("https://") {
            return Some(t.to_string());
        }
    }
    // Fallback: look for host-like token with dot
    for token in msg.split_whitespace() {
        let t = token.trim_matches(|c| {
            matches!(
                c,
                '"' | '\'' | ',' | '.' | ';' | ':' | '!' | '?' | ')' | '(' | '`'
            )
        });
        if t.contains('.') && !t.contains(' ') && t.len() > 4 {
            // crude host detection
            if t.contains("itsecgames") || t.contains("scanme") || t.contains("example") {
                return Some(format!("http://{t}"));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Router: natural language → chat vs investigation
// ---------------------------------------------------------------------------

/// Where one user utterance goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Chat,
    Assess(String),
}

const ROUTER_SYSTEM: &str = "You route user messages for medusa, a security assessment agent. \
Reply with EXACTLY ONE JSON object and nothing else. \
If the user wants to assess/scan/test/audit a target (IP, hostname, URL, path), reply {\"intent\":\"assess\",\"target\":\"<the target>\"}. \
Otherwise (greetings, questions, help, discussion) reply {\"intent\":\"chat\"}.";

pub fn route_utterance(model: &dyn ModelProvider, utterance: &str) -> Route {
    // Bare "continue"/"resume"/"go on" should resume the last assessed target
    // without re-asking the LLM (which hallucinates targets and causes the
    // second-investigation → vague Chat fallback seen in the itsecgames loop).
    let low = utterance.trim().to_ascii_lowercase();
    if matches!(
        low.as_str(),
        "continue" | "resume" | "proceed" | "go on" | "next"
    ) {
        return Route::Chat; // let the caller handle resume; don't start a new assess
    }
    if model.name() == "stub" {
        return keyword_route(utterance);
    }
    match model.chat(ROUTER_SYSTEM, utterance) {
        Ok(text) => parse_route(&text).unwrap_or(Route::Chat),
        Err(_) => keyword_route(utterance),
    }
}

fn parse_route(text: &str) -> Option<Route> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).ok()?;
    match v.get("intent")?.as_str()? {
        "assess" => {
            let t = v.get("target")?.as_str()?.trim();
            if t.is_empty() {
                None
            } else {
                Some(Route::Assess(t.to_string()))
            }
        }
        _ => Some(Route::Chat),
    }
}

/// Offline fallback: assess-verbs + a target-looking token. Fail-open to Chat.
pub fn keyword_route(utterance: &str) -> Route {
    let low = utterance.to_lowercase();
    let wants = [
        "assess",
        "scan",
        "audit",
        "test",
        "check",
        "probe",
        "investigate",
    ]
    .into_iter()
    .any(|w| {
        low.split_whitespace()
            .any(|tok| tok.trim_matches(|c: char| !c.is_alphanumeric()) == w)
    });
    if !wants {
        return Route::Chat;
    }
    for tok in utterance.split_whitespace() {
        let t = tok.trim_matches(|c| matches!(c, '"' | '\'' | ',' | '.' | ';' | ':' | '!' | '?'));
        if t.contains("://")
            || (t.contains(':') && t.matches(':').count() <= 5)
            || looks_like_host(t)
        {
            if !t.is_empty() {
                return Route::Assess(t.to_string());
            }
        }
    }
    Route::Chat
}

fn looks_like_host(t: &str) -> bool {
    if t.is_empty() || t.len() > 253 {
        return false;
    }
    t.contains('.')
        && t.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '/'))
}

const CHAT_SYSTEM: &str = "You are Medusa, a security assessment assistant inside a terminal UI. \
Be helpful and concise (this is a terminal, not a web page). You know the user's environment capabilities \
(they are listed in the conversation context). If the user asks you to assess/scan something, briefly say what \
you can do and ask them to confirm the target — do NOT pretend to run tools. Never emit shell commands.";

// ---------------------------------------------------------------------------
// Chat state (pure data; tests drive it without a terminal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Role {
    User,
    Agent,
    Step,
    System,
    Error,
}

#[derive(Debug, Clone)]
struct Msg {
    role: Role,
    text: String,
}

/// Worker traffic: investigation events plus completed job outputs.
enum WorkerMsg {
    Event(AgentEvent),
    Investigated(InvestigationDone),
    Chatted(Result<String, String>),
    Refreshed(EnvironmentState, String),
}

struct InvestigationDone {
    steps: usize,
    actions: Vec<(String, String)>,

    finish: String,
}

/// Chat session state. With inline printing the terminal's scrollback IS
/// the render surface; the bounded `messages` Vec only exists so tests can
/// drive the session headlessly and the printed-cursor stays in sync.
struct App {
    model_line: String,
    model_name: String,
    env_line: String,
    messages: Vec<Msg>,
    /// How many messages have been printed to scrollback already.
    printed: usize,
    history: Vec<(String, String)>,
    hypotheses: Vec<String>,
    actions: Vec<String>,
    input: String,
    /// Submitted prompts (oldest first) for ↑/↓ navigation, like a shell.
    inputs: Vec<String>,
    /// `Some(i)` while browsing `inputs[i]`; `None` at the live draft.
    history_index: Option<usize>,
    /// Unsent text preserved while browsing history.
    draft: String,
    busy: bool,
    thinking: bool,
    tick: usize,
    /// Error dialog (opencode-style DialogAlert) for critical errors.
    error_dialog: Option<ErrorDialog>,
    /// Last error text the dialog was opened for — prevents re-opening
    /// on every frame while the message stays in the log.
    error_ack: Option<String>,
    /// Approval dialog for high-risk (Destructive) capabilities.
    approval_dialog: Option<ApprovalDialog>,
    /// Last assessed target for `continue`/`resume` resume handling.
    last_target: Option<String>,
    /// Shared flag that the runtime's ExecutionPolicy checks for Destructive approval.
    approval_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Hard cap on retained messages (scrollback is unlimited; this is not).
const MAX_MESSAGES: usize = 1_000;

impl App {
    fn new(model_line: String, model_name: String, env_line: String) -> Self {
        Self {
            model_line,
            model_name,
            env_line,
            messages: Vec::new(),
            printed: 0,
            history: Vec::new(),
            hypotheses: Vec::new(),
            actions: Vec::new(),
            input: String::new(),
            inputs: Vec::new(),
            history_index: None,
            draft: String::new(),
            busy: false,
            thinking: false,
            tick: 0,
            error_dialog: None,
            error_ack: None,
            approval_dialog: None,
            last_target: None,
            approval_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Remember a submitted prompt and stop browsing history.
    fn record_input(&mut self, text: &str) {
        let t = text.trim();
        if t.is_empty() {
            return;
        }
        if self.inputs.last().map(|l| l.as_str()) != Some(t) {
            self.inputs.push(t.to_string());
            if self.inputs.len() > 50 {
                self.inputs.remove(0);
            }
            save_prompt_history(self);
        }
        self.history_index = None;
        self.draft.clear();
    }

    /// ↑ — walk to the previous (older) prompt, stashing the draft first.
    fn history_prev(&mut self) {
        if self.inputs.is_empty() {
            return;
        }
        match self.history_index {
            None => {
                self.draft = self.input.clone();
                let i = self.inputs.len() - 1;
                self.history_index = Some(i);
                self.input = self.inputs[i].clone();
            }
            Some(0) => {}
            Some(i) => {
                self.history_index = Some(i - 1);
                self.input = self.inputs[i - 1].clone();
            }
        }
    }

    /// ↓ — walk to the next (newer) prompt, restoring the draft at the end.
    fn history_next(&mut self) {
        match self.history_index {
            None => {}
            Some(i) => {
                if i + 1 >= self.inputs.len() {
                    self.history_index = None;
                    self.input = std::mem::take(&mut self.draft);
                } else {
                    self.history_index = Some(i + 1);
                    self.input = self.inputs[i + 1].clone();
                }
            }
        }
    }

    fn push(&mut self, role: Role, text: impl Into<String>) {
        self.messages.push(Msg {
            role,
            text: text.into(),
        });
        // Keep the in-memory log bounded; the printed-scrollback cursor
        // shifts with any dropped prefix.
        if self.messages.len() > MAX_MESSAGES {
            let drop = self.messages.len() - MAX_MESSAGES;
            self.messages.drain(0..drop);
            self.printed = self.printed.saturating_sub(drop);
        }
    }

    /// Static placeholder hint shown while the input is empty.
    fn placeholder_suggestion(&self) -> Option<&'static str> {
        if !self.input.is_empty() {
            return None;
        }
        Some(PROMPT_PLACEHOLDERS[0])
    }

    fn apply_event(&mut self, ev: &AgentEvent) {
        match ev {
            AgentEvent::InvestigationStarted { target } => {
                self.thinking = false;
                self.last_target = Some(target.clone());
                self.push(Role::Step, format!("investigating {target}"));
            }
            AgentEvent::StepStarted { step } => {
                self.push(Role::Step, format!("step {}", step + 1));
            }
            AgentEvent::ModelThinking => {
                self.thinking = true;
            }
            AgentEvent::ScopeGranted { target } => {
                self.push(Role::Step, format!("scope: {target}"));
            }
            AgentEvent::Reply { text } => {
                self.thinking = false;
                self.push(Role::Agent, text.clone());
            }
            AgentEvent::Narrated { text } => {
                self.push(Role::Agent, text.clone());
            }
            AgentEvent::CapabilityRequested {
                capability,
                target,
                reason,
                ..
            } => {
                self.thinking = false;
                // Verbal preamble (codex parity, no plan): reason is shown as agent thinking/preamble before tool.
                if !reason.is_empty() {
                    // Push verbal reasoning as Agent message (distinct from muted Step) so it reads like codex's 1-2 sentence preamble.
                    self.push(Role::Agent, reason.clone());
                }
                let mut t = format!("▸ {capability} on {target}");
                if !reason.is_empty() {
                    t.push_str(&format!(" — {reason}"));
                }
                self.push(Role::Step, t);
            }
            AgentEvent::ProviderSelected {
                capability,
                provider,
            } => {
                self.actions.push(format!("{capability} via {provider}"));
                self.push(Role::Step, format!("✓ {provider} ← {capability}"));
            }
            AgentEvent::ToolStarted { .. } | AgentEvent::ToolFinished { .. } => {}
            AgentEvent::ToolExecuted {
                tool_id,
                success,
                timed_out,
                ..
            } => {
                let status = if *timed_out {
                    "timed out"
                } else if *success {
                    "ok"
                } else {
                    "failed"
                };
                self.push(Role::Step, format!("⚡ {tool_id} {status}"));
            }
            AgentEvent::ObservationAdded { summary } => {
                self.push(Role::Step, format!("○ {summary}"));
            }
            AgentEvent::HypothesisAdded {
                id,
                statement,
                confidence,
            } => {
                let line = format!("H{id} [{confidence}]: {statement}");
                self.hypotheses.push(line.clone());
                self.push(Role::Step, format!("◈ {line}"));
            }
            AgentEvent::ActionRejected { reason } => {
                self.thinking = false;
                self.push(Role::Error, format!("rejected: {reason}"));
            }
            AgentEvent::ApprovalRequested { capability, reason } => {
                // Surfaced as an error-line so the approval dialog pick-up
                // below (which keys on "requires explicit approval" inside
                // the reason) opens the Allow/Deny single-select.
                self.push(
                    Role::Error,
                    format!("approval needed for `{capability}`: {reason}"),
                );
            }
            AgentEvent::Finished { reason } => {
                self.thinking = false;
                self.push(Role::Step, format!("■ finished: {reason}"));
            }
            AgentEvent::Error { message } => {
                self.thinking = false;
                self.push(Role::Error, message.clone());
            }
            AgentEvent::Status { message } => {
                self.push(Role::Step, message.clone());
            }
            AgentEvent::FindingRecorded {
                id,
                severity,
                title,
                target,
                status,
                ..
            } => {
                self.push(
                    Role::Step,
                    format!("◆ F{id} [{severity}/{status}] {title} ({target})"),
                );
            }
            AgentEvent::ContextUsage {
                used_tokens,
                limit_tokens,
                pct,
                ..
            } => {
                self.push(
                    Role::Step,
                    format!("context {used_tokens}/{limit_tokens} ({pct}%)"),
                );
            }
            AgentEvent::Compacted {
                before_tokens,
                after_tokens,
                freed_tokens,
                fallback,
            } => {
                self.push(
                    Role::Step,
                    format!(
                        "compacted{}: {before_tokens} → {after_tokens} (freed {freed_tokens})",
                        if *fallback { " (fallback)" } else { "" }
                    ),
                );
            }
            AgentEvent::VaultStored { key, kind, refreshed } => {
                self.push(
                    Role::Step,
                    format!(
                        "vault: {key} [{kind}] {}",
                        if *refreshed { "refreshed" } else { "stored" }
                    ),
                );
            }
            AgentEvent::VaultRecalled { key } => {
                self.push(Role::Step, format!("vault: recalled {key}"));
            }
        }
    }
}

/// Word-wrap `text` to `width` columns (unicode-safe). Blank lines preserved.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        if para.trim().is_empty() {
            out.push(String::new());
            continue;
        }
        let mut line = String::new();
        let mut len = 0usize;
        for word in para.split_whitespace() {
            let w = word.chars().count();
            if line.is_empty() {
                line.push_str(word);
                len = w;
            } else if len + 1 + w <= width {
                line.push(' ');
                line.push_str(word);
                len += 1 + w;
            } else {
                out.push(std::mem::take(&mut line));
                line.push_str(word);
                len = w;
            }
        }
        out.push(line);
    }
    out
}

/// Gap between the card border and its text.
const CARD_GAP: usize = 2;

/// Render one message as styled lines, copying the opencode theme:
/// - user:   `┃` left border (primary) + panel background card with a
///           2-column gap between border and text, text bright
/// - agent:  plain text, `▣ medusa · model` label in primary/muted
/// - step:   muted
/// - system: muted
/// - error:  `┃` left border (error red) + panel card, muted text
fn render_msg(role: &Role, text: &str, width: usize, model_name: &str) -> Vec<Line<'static>> {
    use crate::cli::theme as t;
    let mut lines: Vec<Line> = Vec::new();
    match role {
        Role::User => {
            // Card: border + CARD_GAP inset each side; content padded right
            // so the panel background spans the full card width.
            let inner_w = width.saturating_sub(3).max(10);
            let border = || Span::styled("┃", Style::default().fg(t::PRIMARY));
            let pad_bg = |s: String| {
                Span::styled(
                    format!(
                        "{:<w$}",
                        format!("{}{s}", " ".repeat(CARD_GAP)),
                        w = inner_w
                    ),
                    Style::default().fg(t::TEXT).bg(t::PANEL),
                )
            };
            lines.push(Line::from(vec![border(), pad_bg(String::new())]));
            for l in wrap(text, inner_w.saturating_sub(CARD_GAP)) {
                lines.push(Line::from(vec![border(), pad_bg(l)]));
            }
            lines.push(Line::from(vec![border(), pad_bg(String::new())]));
        }
        Role::Agent => {
            lines.push(Line::from(vec![
                Span::styled("▣ ", Style::default().fg(t::PRIMARY)),
                Span::styled(
                    "medusa".to_string(),
                    Style::default().fg(t::TEXT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" · {model_name}"),
                    Style::default().fg(t::TEXT_MUTED),
                ),
            ]));
            let style = Style::default().fg(t::TEXT);
            for l in wrap(text, width.saturating_sub(2)) {
                lines.push(Line::from(Span::styled(format!("  {l}"), style)));
            }
        }
        Role::Step => {
            let style = Style::default().fg(t::TEXT_MUTED);
            for l in wrap(text, width.saturating_sub(4)) {
                lines.push(Line::from(Span::styled(format!("  ⋯ {l}"), style)));
            }
        }
        Role::System => {
            let style = Style::default().fg(t::TEXT_MUTED);
            for l in wrap(text, width.saturating_sub(4)) {
                lines.push(Line::from(Span::styled(format!("  · {l}"), style)));
            }
        }
        Role::Error => {
            let inner_w = width.saturating_sub(3).max(10);
            let border = || Span::styled("┃", Style::default().fg(t::ERROR));
            let pad_bg = |s: String| {
                Span::styled(
                    format!(
                        "{:<w$}",
                        format!("{}{s}", " ".repeat(CARD_GAP)),
                        w = inner_w
                    ),
                    Style::default().fg(t::TEXT_MUTED).bg(t::PANEL),
                )
            };
            lines.push(Line::from(vec![border(), pad_bg(String::new())]));
            for l in wrap(text, inner_w.saturating_sub(CARD_GAP)) {
                lines.push(Line::from(vec![border(), pad_bg(l)]));
            }
            lines.push(Line::from(vec![border(), pad_bg(String::new())]));
        }
    }
    lines
}

// ---------------------------------------------------------------------------
// Action: what the main loop should do after handling input
// ---------------------------------------------------------------------------

/// Returned by `handle_input` to tell the main loop what to spawn.
enum Action {
    Quit,
    None,
    /// A natural-language turn: the worker routes it (network) and then
    /// chats or investigates. Nothing blocking happens on the UI thread.
    Turn {
        model: Box<dyn ModelProvider>,
        text: String,
        user: String,
    },
    Assess(String),
    Refresh,
}

// ---------------------------------------------------------------------------
// Chat session
// ---------------------------------------------------------------------------

/// Lines one message occupies in scrollback (separator blank + content).
/// Shared by the printer and the startup geometry so both agree on height.
fn message_lines(msg: &Msg, model_name: &str, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    lines.extend(render_msg(&msg.role, &msg.text, width, model_name));
    lines
}

/// The opencode landing "go" wordmark, one visual row per entry. `_`,`^`
/// render as filled background cells to make the blocky letters pop.
fn logo_lines() -> Vec<String> {
    vec![
        "   ".to_string(),
        "O_^".to_string(),
        "O__".to_string(),
        "O__".to_string(),
    ]
}

/// Render the landing logo as styled lines for `width` columns.
fn landing_logo(width: usize) -> Vec<Line<'static>> {
    use crate::cli::theme as t;
    let mut out = Vec::new();
    let width = width.max(6);
    for glyph in logo_lines() {
        let mut spans: Vec<Span> = Vec::new();
        for ch in glyph.chars() {
            let fg = match ch {
                'O' => t::PRIMARY,
                _ => t::BG,
            };
            spans.push(Span::styled(
                " ".to_string(),
                Style::default().fg(fg).bg(t::BG),
            ));
        }
        spans.push(Span::styled(
            " ".repeat(width.saturating_sub(glyph.chars().count())),
            Style::default().bg(t::BG),
        ));
        out.push(Line::from(spans));
    }
    out
}

/// Startup geometry: where to anchor the inline viewport so that the
/// landing cluster [logo · gap · input] is vertically centered on a
/// `rows`-tall screen. `insert_before` pushes the viewport down by exactly
/// the lines printed ABOVE the input row (logo + blanks); we pre-bump the
/// cursor by that amount so the input lands at the center.
fn centered_anchor(rows: u16) -> u16 {
    let max_top = rows.saturating_sub(LIVE_ROWS);
    // Input = viewport row 1; center it at rows/2.
    let input_row = rows / 2;
    let viewport_top_after_insert = input_row.saturating_sub(1);
    let top = viewport_top_after_insert.min(max_top);
    top.saturating_sub(4) // logo(3 visual rows) + 1 blank above it
}

/// Paint static rows with the theme background, directly — no viewport,
/// no redraws. The rows become plain terminal text: selection over them
/// is stable, and they cover whatever was on screen before medusa started.
fn paint_bg_rows(from: u16, to: u16, width: u16) {
    use crate::cli::theme as t;
    use crossterm::style::{Print, SetBackgroundColor};
    if from >= to || width == 0 {
        return;
    }
    let bg = match t::BG {
        ratatui::style::Color::Rgb(r, g, b) => CColor::Rgb { r, g, b },
        _ => CColor::Reset,
    };
    let mut stdout = std::io::stdout();
    let blank = " ".repeat(width as usize);
    for y in from..to {
        let _ = execute!(
            stdout,
            MoveTo(0, y),
            SetBackgroundColor(bg),
            Print(blank.as_str()),
        );
    }
    let _ = execute!(stdout, SetBackgroundColor(CColor::Reset));
}

/// Build the landing-cluster lines to insert (everything above the input):
/// the 4-row logo (its first row is blank breathing room). The viewport
/// (input) follows after. Height = 4, aligning with [`LANDING_LINES`] and
/// the `-4` in [`centered_anchor`].
fn landing_lines(width: usize) -> Vec<Line<'static>> {
    landing_logo(width)
}

/// Offset clamp for the transcript browser: never scroll past the first
/// line of content. Pure — unit tested.
fn clamp_browse_offset(offset: usize, total_lines: usize, visible: usize) -> usize {
    offset.min(total_lines.saturating_sub(visible))
}

/// Open the transcript browser: a temporary alternate-screen overlay that
/// renders the message log with scroll. The primary screen (inline chat +
/// scrollback) is saved by the terminal and restored on close — printing
/// resumes exactly where it paused.
fn open_browse(
    browse: &mut Option<usize>,
    fs_term: &mut Option<Terminal<CrosstermBackend<std::io::Stdout>>>,
) {
    if browse.is_some() {
        return;
    }
    let _ = execute!(std::io::stdout(), EnterAlternateScreen);
    match Terminal::new(CrosstermBackend::new(std::io::stdout())) {
        Ok(t) => {
            *fs_term = Some(t);
            *browse = Some(0);
        }
        Err(_) => {
            let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        }
    }
}

/// Close the transcript browser and return to the inline chat.
fn close_browse(
    browse: &mut Option<usize>,
    fs_term: &mut Option<Terminal<CrosstermBackend<std::io::Stdout>>>,
) {
    if browse.take().is_none() {
        return;
    }
    if let Some(mut t) = fs_term.take() {
        let _ = execute!(t.backend_mut(), LeaveAlternateScreen);
    }
}

/// Render the transcript browser frame. Shows the whole message log
/// (including events that arrived while browsing) with the scroll offset
/// applied from the bottom.
fn draw_browse(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &App, offset: usize) {
    use crate::cli::theme as t;
    let _ = term.draw(|f| {
        let area = f.area();
        f.render_widget(
            ratatui::widgets::Block::default().style(Style::default().bg(t::BG)),
            area,
        );
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .horizontal_margin(MARGIN)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);

        // Status row: browsing hints, spinner while the agent is busy.
        let status = Line::from(vec![
            Span::styled(
                if app.busy {
                    format!("{} ", SPINNER[app.tick % SPINNER.len()])
                } else {
                    "↕ ".to_string()
                },
                Style::default().fg(t::PRIMARY),
            ),
            Span::styled(
                "transcript".to_string(),
                Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " — ↑↓ scroll · esc return".to_string(),
                Style::default().fg(t::TEXT_MUTED),
            ),
        ]);
        f.render_widget(Paragraph::new(status), rows[0]);

        let body = rows[1];
        let width = body.width.saturating_sub(MARGIN * 2).max(10) as usize;
        let mut lines: Vec<Line> = Vec::new();
        for m in &app.messages {
            lines.extend(message_lines(m, &app.model_name, width));
        }
        let visible = body.height as usize;
        let off = clamp_browse_offset(offset, lines.len(), visible);
        let start = lines.len().saturating_sub(visible + off);
        let end = (start + visible).min(lines.len());
        let view: Vec<Line> = lines[start..end].to_vec();
        f.render_widget(Paragraph::new(view), body);
    });
}

fn draw_approval(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>, dialog: &ApprovalDialog) {
    let _ = term.draw(|f| {
        let area = f.area();
        // For inline viewport (height 3), use the whole area compact; for alternate screen, centering would be handled by dialog's own layout.
        dialog.render(f, area);
    });
}

/// Inline chat entry point: `medusa` with no args boots here.
pub fn run_chat_tui(state: &mut EnvironmentState, tools: &ToolRegistry, caps: &CapabilityRegistry) {
    if enable_raw_mode().is_err() || !std::io::stdin().is_terminal() {
        eprintln!("chat UI needs an interactive terminal");
        return;
    }

    let (model_line, model_name, has_model) =
        match crate::infra::resolve_model_config(&crate::infra::load_file_config()) {
            Ok(cfg) => (
                format!("{} · {}", cfg.model, host_of(&cfg.base_url)),
                cfg.model,
                true,
            ),
            Err(_) => ("offline stub".to_string(), "stub".to_string(), false),
        };
    let env_line = format!(
        "{} tools · {} caps",
        state.installed_tool_count(),
        state.available_capabilities().len()
    );

    // Startup geometry: the landing cluster (blank + logo) is vertically
    // centered. The WHOLE screen gets a static black cover (selection-safe,
    // never redrawn): the inline viewport only ever repaints its own 3
    // rows, so any row left unpainted here would keep the terminal default
    // background (the "transparent gap" below the input). Over-painting the
    // viewport rows is harmless — every frame redraws them anyway.
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let anchor = centered_anchor(rows);
    paint_bg_rows(0, rows, cols);

    // Anchor the inline viewport; the first print_pending drops in the
    // landing cluster, pushing the empty input to the vertical center.
    // Later messages push it down until it settles at the bottom.
    let _ = execute!(std::io::stdout(), MoveTo(0, anchor));
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut term = match Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Inline(LIVE_ROWS),
        },
    ) {
        Ok(t) => t,
        Err(_) => {
            let _ = disable_raw_mode();
            return;
        }
    };

    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel::<WorkerMsg>();
        let mut app = App::new(model_line, model_name, env_line);
        load_prompt_history(&mut app);
        if !has_model {
            app.push(
                Role::System,
                "no model configured — offline demo mode. add %APPDATA%\\medusa\\config.json",
            );
        }
        // Eager landing print (see `print_landing`): centers the input
        // even with an empty message log.
        print_landing(&mut term);

        let mut cancel_handle: Option<crate::agent::RuntimeHandle> = None;
        let mut quit = false;
        // Transcript browser: Some(scroll offset from bottom) while open.
        let mut browse: Option<usize> = None;
        let mut fs_term: Option<Terminal<CrosstermBackend<std::io::Stdout>>> = None;

        while !quit {
            // Drain worker traffic.
            loop {
                match rx.try_recv() {
                    Ok(msg) => match msg {
                        WorkerMsg::Event(ev) => app.apply_event(&ev),
                        WorkerMsg::Investigated(done) => {
                            app.busy = false;
                            app.thinking = false;
                            cancel_handle = None;
                            // Reset one-time approval after investigation ends (Allow once semantics)
                            app.approval_flag
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            let summary = format!(
                                "Investigation complete - {} steps, {} planned actions.\n{}",
                                done.steps,
                                done.actions.len(),
                                done.finish
                            );
                            // Persist to chat history so follow-up "did you find anything?" has context.
                            // Without this, `handle_input` history (6 turns) had no investigation evidence
                            // and the model replied "I haven't run anything" despite 11 steps just executed.
                            push_history(&mut app, "medusa", &summary);
                            // Also persist a compact transcript of recent steps/observations so the next
                            // chat turn can answer with specifics (ports, HTTP status, etc.) instead of generic.
                            let transcript: String = app
                                .messages
                                .iter()
                                .rev()
                                .filter(|m| {
                                    matches!(m.role, Role::Step | Role::Error | Role::System)
                                })
                                .take(20)
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .map(|m| m.text.clone())
                                .collect::<Vec<_>>()
                                .join("\n");
                            if !transcript.is_empty() {
                                push_history(
                                    &mut app,
                                    "medusa",
                                    &format!("Transcript:\n{transcript}"),
                                );
                            }
                            app.push(Role::Agent, summary);
                        }
                        WorkerMsg::Chatted(reply) => {
                            app.busy = false;
                            app.thinking = false;
                            match reply {
                                Ok(text) => {
                                    push_history(&mut app, "medusa", &text);
                                    app.push(Role::Agent, text.clone());
                                    // If the reply is a permission question with Yes/No options, show interactive UI
                                    // instead of plain text — single-select with ↑↓ + Enter, third option always "Type your own answer".
                                    if text.contains("Do you approve")
                                        || (text.contains("- Yes") && text.contains("- No"))
                                        || text.contains("approve and run")
                                    {
                                        let question = text.chars().take(500).collect::<String>();
                                        app.approval_dialog =
                                            Some(ApprovalDialog::new_chat_question(
                                                "Confirm".to_string(),
                                                question,
                                            ));
                                        app.error_ack = None;
                                    }
                                }
                                Err(e) => app.push(Role::Error, e),
                            }
                        }
                        WorkerMsg::Refreshed(new_state, summary) => {
                            app.busy = false;
                            *state = new_state;
                            app.env_line = format!(
                                "{} tools · {} caps",
                                state.installed_tool_count(),
                                state.available_capabilities().len()
                            );
                            app.push(Role::System, summary);
                        }
                    },
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        app.busy = false;
                        break;
                    }
                }
            }

            app.tick += 1;

            // Surface approval for high-risk vs generic model errors.
            // High-risk (Destructive) rejections show ApprovalDialog with single-select (↑/↓ + Enter) and third option "Type your own answer".
            if app
                .approval_dialog
                .as_ref()
                .map(|d| d.is_open())
                .unwrap_or(false)
            {
                // already showing; keys handled below
            } else if app
                .error_dialog
                .as_ref()
                .map(|d| d.is_open())
                .unwrap_or(false)
            {
                // already showing; keys are handled below
            } else if let Some(latest) = app.messages.iter().rev().find_map(|msg| {
                if msg.role == Role::Error {
                    Some(msg.text.clone())
                } else {
                    None
                }
            }) {
                if app.error_ack.as_deref() != Some(latest.as_str()) {
                    app.error_ack = Some(latest.clone());
                    if latest.contains("requires explicit approval") {
                        // High-risk Destructive — show approval single-select instead of generic error dismiss.
                        app.approval_dialog = Some(ApprovalDialog::new(
                            "Approval Required".to_string(),
                            latest.clone(),
                        ));
                    } else {
                        app.error_dialog =
                            Some(ErrorDialog::new("Model Error".to_string(), latest));
                    }
                }
            }

            if let (Some(off), Some(t)) = (browse, fs_term.as_mut()) {
                // Browsing: render the transcript overlay. Printing to the
                // primary screen is paused; the printed-cursor catches up
                // when the browser closes.
                draw_browse(t, &app, off);
            } else if app
                .approval_dialog
                .as_ref()
                .map(|d| d.is_open())
                .unwrap_or(false)
            {
                // Approval dialog for Destructive (high-risk) capabilities — single-select with ↑↓ + Enter, third option always "Type your own answer".
                draw_approval(&mut term, app.approval_dialog.as_ref().unwrap());
            } else if app
                .error_dialog
                .as_ref()
                .map(|d| d.is_open())
                .unwrap_or(false)
            {
                // Error dialog is open: render it on top
                draw(&mut term, &app);
            } else {
                // Print new messages into real scrollback (never redrawn →
                // selection on them is stable), then repaint the live area.
                print_pending(&mut term, &mut app);
                draw(&mut term, &app);
            }

            if event::poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(CEvent::Key(key)) = event::read() {
                    // Windows fires Press AND Release for every key — only
                    // react to Press or the user gets doubled characters.
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    // Handle approval dialog (high-risk) before error dialog — single-select with ↑↓ + Enter, third option always "Type your own answer"
                    if app
                        .approval_dialog
                        .as_ref()
                        .map(|d| d.is_open())
                        .unwrap_or(false)
                    {
                        match (key.code, key.modifiers) {
                            (KeyCode::Up, _) => {
                                if let Some(d) = &mut app.approval_dialog {
                                    d.up();
                                }
                                continue;
                            }
                            (KeyCode::Down, _) => {
                                if let Some(d) = &mut app.approval_dialog {
                                    d.down();
                                }
                                continue;
                            }
                            (KeyCode::Enter, _) => {
                                if let Some(d) = app.approval_dialog.take() {
                                    let is_chat = d.is_chat_question;
                                    let choice = d.selected_option().to_string();
                                    let msg = d.message.clone();
                                    if is_chat {
                                        match choice.as_str() {
                                            "Yes" => {
                                                // Extract target URL from the question text for direct Assess
                                                let target = extract_target_from_question(&msg)
                                                    .or_else(|| app.last_target.clone())
                                                    .unwrap_or_else(|| {
                                                        "http://www.itsecgames.com/".to_string()
                                                    });
                                                app.push(Role::User, "Yes".to_string());
                                                push_history(&mut app, "you", "Yes");
                                                app.push(
                                                    Role::System,
                                                    format!("approved: running {target}"),
                                                );
                                                // Allow high-risk for this run and start investigation directly
                                                app.approval_flag.store(
                                                    true,
                                                    std::sync::atomic::Ordering::SeqCst,
                                                );
                                                let txc = tx.clone();
                                                let state_snap = state.clone();
                                                let handle = crate::agent::RuntimeHandle::default();
                                                cancel_handle = Some(handle.clone());
                                                let approval = app.approval_flag.clone();
                                                app.busy = true;
                                                app.thinking = true;
                                                let (model, _) = super::assess::select_model(state);
                                                // Clone refs for move closure
                                                let tools_ref = tools;
                                                let caps_ref = caps;
                                                s.spawn(move || {
                                                    let rt = AgentRuntime::new(
                                                        model,
                                                        tools_ref,
                                                        caps_ref,
                                                        &state_snap,
                                                    )
                                                    .with_handle(handle)
                                                    .with_approval_flag(approval);
                                                    let res = rt.investigate_with(
                                                        Target::new(&target),
                                                        &mut |ev| {
                                                            let _ = txc.send(WorkerMsg::Event(ev));
                                                        },
                                                    );
                                                    let done = InvestigationDone {
                                                        steps: res.steps_taken,
                                                        actions: res
                                                            .planned_actions
                                                            .iter()
                                                            .map(|a| {
                                                                (
                                                                    a.capability.clone(),
                                                                    a.provider.clone(),
                                                                )
                                                            })
                                                            .collect(),
                                                        finish: finish_summary(&res.finish_reason),
                                                    };
                                                    let _ = txc.send(WorkerMsg::Investigated(done));
                                                });
                                            }
                                            "No" => {
                                                app.push(Role::User, "No".to_string());
                                                push_history(&mut app, "you", "No");
                                                app.push(Role::System, "denied");
                                            }
                                            "Type your own answer" => {
                                                app.push(
                                                    Role::System,
                                                    "type your custom answer below and press enter",
                                                );
                                            }
                                            _ => {}
                                        }
                                    } else {
                                        match choice.as_str() {
                                            "Allow once" => {
                                                app.approval_flag.store(
                                                    true,
                                                    std::sync::atomic::Ordering::SeqCst,
                                                );
                                                app.push(
                                                    Role::System,
                                                    "approved: high-risk capability allowed once — retrying",
                                                );
                                                app.error_ack = None;
                                            }
                                            "Deny" => {
                                                app.approval_flag.store(
                                                    false,
                                                    std::sync::atomic::Ordering::SeqCst,
                                                );
                                                app.push(
                                                    Role::System,
                                                    "denied: high-risk capability blocked",
                                                );
                                            }
                                            "Type your own answer" => {
                                                app.push(
                                                    Role::System,
                                                    "type your custom answer below and press enter (e.g. allow for this target only)",
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                continue;
                            }
                            (KeyCode::Esc, _) => {
                                if let Some(d) = &mut app.approval_dialog {
                                    d.close();
                                }
                                app.approval_dialog = None;
                                app.push(
                                    Role::System,
                                    "denied: high-risk capability blocked (esc)",
                                );
                                continue;
                            }
                            _ => continue,
                        }
                    }
                    // Handle error dialog keys (next priority)
                    if app
                        .error_dialog
                        .as_ref()
                        .map(|d| d.is_open())
                        .unwrap_or(false)
                    {
                        match (key.code, key.modifiers) {
                            (KeyCode::Enter, _) | (KeyCode::Esc, _) => {
                                if let Some(dialog) = &mut app.error_dialog {
                                    dialog.close();
                                }
                                continue;
                            }
                            _ => continue, // Ignore other keys when error dialog is open
                        }
                    }

                    match (key.code, key.modifiers) {
                        (KeyCode::Up, _) => {
                            if browse.is_some() {
                                browse = browse.map(|o| o + 3);
                            } else {
                                // opencode `history_previous`: ↑ recalls the
                                // previous prompt (single-line input).
                                app.history_prev();
                            }
                        }
                        (KeyCode::Down, _) => {
                            if let Some(o) = browse.as_mut() {
                                *o = o.saturating_sub(3);
                            } else {
                                // opencode `history_next`: ↓ recalls the
                                // next prompt (or restores the draft).
                                app.history_next();
                            }
                        }
                        (KeyCode::PageUp, _) => {
                            if let Some(o) = browse.as_mut() {
                                *o += 10;
                            } else {
                                // opencode `messages_page_up`: PgUp opens
                                // the transcript browser.
                                open_browse(&mut browse, &mut fs_term);
                            }
                        }
                        (KeyCode::PageDown, _) => {
                            if let Some(o) = browse.as_mut() {
                                *o = o.saturating_sub(10);
                            } else {
                                // opencode `messages_page_down`.
                                open_browse(&mut browse, &mut fs_term);
                            }
                        }
                        (KeyCode::Char('p'), m) if m.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+P: Previous history item (opencode compatible)
                            app.history_prev();
                        }
                        (KeyCode::Char('n'), m) if m.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+N: Next history item
                            app.history_next();
                        }
                        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+C: cancel when busy, quit when idle (header comment promise)
                            if app.busy {
                                if let Some(h) = cancel_handle.take() {
                                    h.cancel();
                                    app.busy = false;
                                    app.thinking = false;
                                    app.push(Role::System, "cancelled");
                                }
                            } else {
                                quit = true;
                            }
                        }
                        (KeyCode::Char('d'), m) if m.contains(KeyModifiers::CONTROL) => {
                            // Ctrl+D: quit
                            quit = true;
                        }
                        (KeyCode::Enter, _) => {
                            if browse.is_some() {
                                close_browse(&mut browse, &mut fs_term);
                                continue;
                            }
                            let text = std::mem::take(&mut app.input);
                            if text.trim().is_empty() {
                                continue;
                            }
                            app.record_input(&text);
                            if app.busy {
                                if let Some(h) = cancel_handle.take() {
                                    h.cancel();
                                }
                                app.busy = false;
                                app.push(Role::System, "interrupted — new instruction");
                            }
                            match handle_input(&mut app, &text, state, tools, caps) {
                                Action::Quit => quit = true,
                                Action::None => {}
                                Action::Turn { model, text, user } => {
                                    // Routing is a network call — run it in the
                                    // worker so the UI (and the user message)
                                    // render instantly with a spinner.
                                    let txc = tx.clone();
                                    let state_snap = state.clone();
                                    let handle = crate::agent::RuntimeHandle::default();
                                    cancel_handle = Some(handle.clone());
                                    let approval = app.approval_flag.clone();
                                    app.busy = true;
                                    app.thinking = true;
                                    s.spawn(move || match route_utterance(model.as_ref(), &text) {
                                        Route::Chat => {
                                            let out = match model.chat(CHAT_SYSTEM, &user) {
                                                Ok(reply) => WorkerMsg::Chatted(Ok(reply)),
                                                Err(e) => WorkerMsg::Chatted(Err(format!(
                                                    "model error: {e}"
                                                ))),
                                            };
                                            let _ = txc.send(out);
                                        }
                                        Route::Assess(target) => {
                                            let rt =
                                                AgentRuntime::new(model, tools, caps, &state_snap)
                                                    .with_handle(handle)
                                                    .with_approval_flag(approval);
                                            let res = rt.investigate_with(
                                                Target::new(&target),
                                                &mut |ev| {
                                                    let _ = txc.send(WorkerMsg::Event(ev));
                                                },
                                            );
                                            let done = InvestigationDone {
                                                steps: res.steps_taken,
                                                actions: res
                                                    .planned_actions
                                                    .iter()
                                                    .map(|a| {
                                                        (a.capability.clone(), a.provider.clone())
                                                    })
                                                    .collect(),
                                                finish: finish_summary(&res.finish_reason),
                                            };
                                            let _ = txc.send(WorkerMsg::Investigated(done));
                                        }
                                    });
                                }
                                Action::Assess(target) => {
                                    let (model, _) = super::assess::select_model(state);
                                    push_history(&mut app, "you", &format!("assess {target}"));
                                    app.busy = true;
                                    let txc = tx.clone();
                                    let address = target.to_string();
                                    let state_snap = state.clone();
                                    let handle = crate::agent::RuntimeHandle::default();
                                    cancel_handle = Some(handle.clone());
                                    let approval = app.approval_flag.clone();
                                    s.spawn(move || {
                                        let rt = AgentRuntime::new(model, tools, caps, &state_snap)
                                            .with_handle(handle)
                                            .with_approval_flag(approval);
                                        let res =
                                            rt.investigate_with(Target::new(&address), &mut |ev| {
                                                let _ = txc.send(WorkerMsg::Event(ev));
                                            });
                                        let done = InvestigationDone {
                                            steps: res.steps_taken,
                                            actions: res
                                                .planned_actions
                                                .iter()
                                                .map(|a| (a.capability.clone(), a.provider.clone()))
                                                .collect(),
                                            finish: finish_summary(&res.finish_reason),
                                        };
                                        let _ = txc.send(WorkerMsg::Investigated(done));
                                    });
                                }
                                Action::Refresh => {
                                    let txc = tx.clone();
                                    let tools_snap = tools.clone();
                                    let caps_snap = caps.clone();
                                    s.spawn(move || {
                                        let runner = RealCommandRunner;
                                        let fresh =
                                            scan_environment(&tools_snap, &caps_snap, &runner);
                                        let summary = format!(
                                            "environment refreshed — {} tools, {} capabilities",
                                            fresh.installed_tool_count(),
                                            fresh.available_capabilities().len()
                                        );
                                        if let Err(e) = crate::infra::save_state(&fresh) {
                                            let _ = txc.send(WorkerMsg::Refreshed(
                                                fresh,
                                                format!("{summary} (cache write failed: {e})"),
                                            ));
                                        } else {
                                            let _ = txc.send(WorkerMsg::Refreshed(fresh, summary));
                                        }
                                    });
                                    app.push(Role::System, "refreshing environment…");
                                    app.busy = true;
                                }
                            }
                        }
                        (KeyCode::Esc, _) => {
                            if browse.is_some() {
                                close_browse(&mut browse, &mut fs_term);
                            } else if !app.input.is_empty() {
                                app.input.clear();
                            } else if app.busy {
                                if let Some(h) = cancel_handle.take() {
                                    h.cancel();
                                    app.busy = false;
                                    app.push(Role::System, "cancelled");
                                }
                            }
                        }
                        (KeyCode::Backspace, _) => {
                            if browse.is_some() {
                                close_browse(&mut browse, &mut fs_term);
                            } else {
                                app.input.pop();
                            }
                        }
                        (KeyCode::Char(c), m)
                            if !m.contains(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                        {
                            // Typing always returns to the input line.
                            if browse.is_some() {
                                close_browse(&mut browse, &mut fs_term);
                            }
                            app.input.push(c);
                        }
                        _ => {}
                    }
                }
            }
        }

        close_browse(&mut browse, &mut fs_term);
        drop(cancel_handle);
    });

    let _ = disable_raw_mode();
    let _ = term.show_cursor();
    // Move past the live area so the shell prompt lands on a fresh line.
    println!();
}

/// Print the landing cluster (blank + logo) immediately after terminal
/// creation — eager, not deferred to the first message — so the input
/// lands centered even when the message log starts empty.
fn print_landing(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>) {
    use crate::cli::theme as t;
    use ratatui::widgets::Widget;
    let w = term.size().map(|s| s.width).unwrap_or(80) as usize;
    let lines = landing_lines(w);
    debug_assert_eq!(lines.len() as u16, LANDING_LINES);
    let height = lines.len() as u16;
    let _ = term.insert_before(height, move |buf| {
        ratatui::widgets::Block::default()
            .style(Style::default().bg(t::BG))
            .render(buf.area, buf);
        Paragraph::new(lines).render(buf.area, buf);
    });
}

/// Print every not-yet-printed message into the terminal's real scrollback.
/// Printed lines are never redrawn — that is what keeps native text
/// selection stable while the app runs.
fn print_pending(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &mut App) {
    while app.printed < app.messages.len() {
        let msg = app.messages[app.printed].clone();
        app.printed += 1;
        let _ = print_message(term, &msg, &app.model_name);
    }
}

/// One message → scrollback. `insert_before` hands us the raw `&mut
/// Buffer` (full width × `height`) to render into — Widget::render writes
/// directly, no Frame involved. A full-width background block is painted
/// first so every printed row carries the theme background — same look
/// as the old fullscreen mode, but the rows are real scrollback text.
fn print_message(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    msg: &Msg,
    model_name: &str,
) -> std::io::Result<()> {
    use crate::cli::theme as t;
    use ratatui::widgets::Widget;
    let term_w = term.size().map(|s| s.width).unwrap_or(80);
    let inner_w = term_w.saturating_sub(MARGIN * 2).max(10) as usize;
    let lines = message_lines(msg, model_name, inner_w);
    let height = lines.len() as u16;
    term.insert_before(height, move |buf| {
        // Full-width theme background for the whole inserted region.
        ratatui::widgets::Block::default()
            .style(Style::default().bg(t::BG))
            .render(buf.area, buf);
        let inner = Rect {
            x: buf.area.x + MARGIN,
            width: buf.area.width.saturating_sub(MARGIN * 2),
            ..buf.area
        };
        Paragraph::new(lines).render(inner, buf);
    })
}

/// Prompt-history file (opencode parity: JSONL, oldest-first, cap 50,
/// consecutive duplicates collapsed). Lives next to the medusa config.
fn history_path() -> std::path::PathBuf {
    crate::infra::config_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("prompt-history.jsonl")
}

/// Load persisted prompt history into the app (newest 50, in order).
fn load_prompt_history(app: &mut App) {
    let Ok(text) = std::fs::read_to_string(history_path()) else {
        return;
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(50);
    for line in &lines[start..] {
        // JSON strings (forward-compatible with richer entries later).
        let entry: String = serde_json::from_str(line).unwrap_or_else(|_| line.to_string());
        if app.inputs.last().map(|l| l.as_str()) != Some(entry.as_str()) {
            app.inputs.push(entry);
        }
    }
    app.inputs.truncate(50);
}

/// Persist prompt history (best-effort; a chat UI must never fail on it).
fn save_prompt_history(app: &App) {
    let entries: Vec<String> = app.inputs.iter().rev().take(50).rev().cloned().collect();
    let mut text: String = entries
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    let _ = std::fs::write(history_path(), text);
}

fn push_history(app: &mut App, who: &str, text: &str) {
    app.history.push((who.to_string(), text.to_string()));
    while app.history.len() > 12 {
        app.history.remove(0);
    }
}

/// Handle one submitted line. Returns an Action for the main loop to execute.
/// Never borrows state with scope lifetime — all spawns happen in the caller.
fn handle_input(
    app: &mut App,
    text: &str,
    state: &EnvironmentState,
    tools: &ToolRegistry,
    caps: &CapabilityRegistry,
) -> Action {
    let text = text.trim();
    if text.is_empty() {
        return Action::None;
    }
    // Bare continue/resume should resume the last target without routing via LLM.
    let low = text.to_ascii_lowercase();
    if matches!(
        low.as_str(),
        "continue" | "resume" | "proceed" | "go on" | "next"
    ) {
        if let Some(target) = app.last_target.clone() {
            push_history(app, "you", text);
            app.push(Role::User, text.to_string());
            // Direct assess resume — avoids Router hallucinating a new target
            // and the vague CHAT_SYSTEM confirmation loop.
            return Action::Assess(target);
        }
        // No prior target: fall through to normal Chat handling with a hint.
        push_history(app, "you", text);
        app.push(Role::User, text.to_string());
        app.push(
            Role::System,
            "no previous target to continue — try `assess <target>`",
        );
        return Action::None;
    }
    push_history(app, "you", text);
    app.push(Role::User, text.to_string());

    // Slash commands
    if text.starts_with('/') {
        return handle_slash(app, text, state, tools, caps);
    }

    // Natural language: hand the whole turn to the worker — routing is a
    // network call and must never block the UI thread.
    let (model, _) = super::assess::select_model(state);
    let history: String = app
        .history
        .iter()
        .rev()
        .take(6)
        .rev()
        .map(|(a, b)| format!("{a}: {b}"))
        .collect::<Vec<_>>()
        .join("\n");
    // Also surface the live investigation transcript (Steps) so a follow-up
    // "did you find anything?" asked while/just-after an investigation is
    // cancelled still has evidence — otherwise model hallucinates "I haven't
    // run anything" despite 11 steps in `app.messages`.
    let transcript: String = app
        .messages
        .iter()
        .rev()
        .filter(|m| matches!(m.role, Role::Step | Role::Error | Role::System))
        .take(15)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|m| m.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let mut caps_list: Vec<String> = state
        .available_capabilities()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    caps_list.sort();
    let user = if transcript.is_empty() {
        format!(
            "Available capabilities: {}\nConversation:\n{history}\nCurrent message: {text}",
            caps_list.join(", ")
        )
    } else {
        format!(
            "Available capabilities: {}\nConversation:\n{history}\nRecent investigation transcript:\n{transcript}\nCurrent message: {text}",
            caps_list.join(", ")
        )
    };
    Action::Turn {
        model,
        text: text.to_string(),
        user,
    }
}

/// Handle a slash command. Returns an Action for the main loop.
fn handle_slash(
    app: &mut App,
    text: &str,
    state: &EnvironmentState,
    tools: &ToolRegistry,
    caps: &CapabilityRegistry,
) -> Action {
    let cmd = Command::parse(text);
    match cmd {
        Command::Assess(target) => Action::Assess(target),
        Command::RefreshTools => Action::Refresh,
        Command::Tui(_) => {
            app.push(
                Role::System,
                "you're already in the chat UI — just type, e.g. \"assess 127.0.0.1\"",
            );
            Action::None
        }
        Command::Exit => Action::Quit,
        other => {
            let ctx = Ctx { state, tools, caps };
            match dispatch(other, &ctx) {
                Signal::Output(s) => {
                    app.push(Role::Agent, s);
                    push_history(app, "medusa", "(command output)");
                }
                Signal::Doctor => {
                    let runner = RealCommandRunner;
                    let report = crate::doctor::diagnose(&runner, state, tools.len());
                    let text = crate::cli::render::render_doctor(&report);
                    app.push(Role::Agent, text);
                    push_history(app, "medusa", "(doctor report)");
                }
                Signal::Refresh(_) => {
                    app.push(Role::System, "use /refresh-tools to rescan");
                }
                Signal::Assess(_) | Signal::Tui(_) => {
                    app.push(Role::System, "unexpected signal");
                }
                Signal::Exit => return Action::Quit,
            }
            Action::None
        }
    }
}

fn finish_summary(reason: &crate::agent::FinishReason) -> String {
    use crate::agent::FinishReason as F;
    match reason {
        F::ModelFinished(r) => r.clone(),
        F::MaxSteps(n) => format!("stopped after {n} steps"),
        F::Cancelled => "cancelled".to_string(),
        F::TooManyModelErrors { count, last_error } => {
            format!("model failed {count} times in a row: {last_error}")
        }
        F::ConfigError(e) => format!("misconfigured: {e}"),
        F::ContextExhausted => {
            "context exhausted even after compaction — findings and vault kept".to_string()
        }
    }
}

/// Extract `host.tld` from a base URL ("https://x.example.com/v1" → "x.example.com").
fn host_of(url: &str) -> &str {
    let no_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    no_scheme.split('/').next().unwrap_or(no_scheme)
}

// ---------------------------------------------------------------------------
// Live area rendering: status · input · footer (the only rows that redraw)
// ---------------------------------------------------------------------------

fn draw(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &App) {
    use crate::cli::theme as t;
    let _ = term.draw(|f| {
        let area = f.area();
        f.render_widget(
            ratatui::widgets::Block::default().style(Style::default().bg(t::BG)),
            area,
        );
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .horizontal_margin(MARGIN) // align live rows with printed text
            .constraints([
                Constraint::Length(1), // status
                Constraint::Length(1), // input
                Constraint::Length(1), // footer
            ])
            .split(area);

        // -- status: identity left (spinner while busy), facts right -------
        let status_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
            .split(rows[0]);

        let identity = if app.busy {
            Line::from(vec![
                Span::styled(
                    format!("{} ", SPINNER[app.tick % SPINNER.len()]),
                    Style::default().fg(t::PRIMARY),
                ),
                Span::styled(
                    "medusa".to_string(),
                    Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" working…", Style::default().fg(t::PRIMARY)),
            ])
        } else {
            Line::from(vec![
                Span::styled("● ", Style::default().fg(t::PRIMARY)),
                Span::styled(
                    "medusa".to_string(),
                    Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" v{}", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(t::TEXT_MUTED),
                ),
            ])
        };
        f.render_widget(Paragraph::new(identity), status_cols[0]);

        let facts = Line::from(Span::styled(
            format!("{} · {}", app.model_line, app.env_line),
            Style::default().fg(t::TEXT_MUTED),
        ));
        f.render_widget(
            Paragraph::new(facts).alignment(Alignment::Right),
            status_cols[1],
        );

        // -- input line ------------------------------------------------------
        let input = if app.input.is_empty() {
            let placeholder = app
                .placeholder_suggestion()
                .unwrap_or("assess scanme.nmap.org");
            Line::from(vec![
                Span::styled(
                    "❯ ",
                    Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
                ),
                Span::styled(placeholder, Style::default().fg(t::TEXT_MUTED)),
            ])
        } else {
            Line::from(vec![
                Span::styled(
                    "❯ ",
                    Style::default().fg(t::PRIMARY).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{}█", app.input), Style::default().fg(t::TEXT)),
            ])
        };
        f.render_widget(Paragraph::new(input), rows[1]);

        // -- footer: dim keybind hints ----------------------------------------
        let footer = Line::from(Span::styled(
            "enter send · ↑↓ history · pgup/pgdn scroll · / commands · ctrl+c cancel · ctrl+d quit",
            Style::default().fg(t::TEXT_MUTED),
        ));
        f.render_widget(Paragraph::new(footer), rows[2]);

        // -- error dialog overlay (opencode DialogAlert parity) --------------
        if let Some(dialog) = app.error_dialog.as_ref() {
            if dialog.is_open() {
                let popup = centered_rect(area, 70, 9);
                f.render_widget(ratatui::widgets::Clear, popup);
                dialog.render(f, popup);
            }
        }
    });
}

/// Centered rectangle of `width`×`height` cells inside `area`
/// (opencode dialog-overlay geometry). Pure — unit tested.
fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_router_finds_assess_target() {
        assert_eq!(
            keyword_route("assess 127.0.0.1 please"),
            Route::Assess("127.0.0.1".into())
        );
        assert_eq!(
            keyword_route("can you scan https://example.com?"),
            Route::Assess("https://example.com".into())
        );
        assert_eq!(keyword_route("hi, what can you do?"), Route::Chat);
        assert_eq!(keyword_route("hello"), Route::Chat);
        assert_eq!(keyword_route("scan"), Route::Chat);
    }

    #[test]
    fn route_parser_fails_open_to_chat() {
        assert_eq!(
            parse_route(r#"{"intent":"assess","target":"10.0.0.1"}"#),
            Some(Route::Assess("10.0.0.1".into()))
        );
        assert_eq!(parse_route(r#"{"intent":"chat"}"#), Some(Route::Chat));
        assert_eq!(parse_route("garbage"), None);
        assert_eq!(parse_route(r#"{"intent":"assess"}"#), None);
    }

    #[test]
    fn wrap_respects_width_and_keeps_words() {
        let text = "aaa bbb ccc ddd";
        assert_eq!(
            wrap(text, 7),
            vec!["aaa bbb".to_string(), "ccc ddd".to_string()]
        );
        assert_eq!(wrap("one", 10), vec!["one".to_string()]);
        assert_eq!(wrap("", 10), vec!["".to_string()]);
        // unicode: counts chars, not bytes
        assert_eq!(wrap("ααα βββ", 3).len(), 2);
    }

    #[test]
    fn render_msg_wraps_long_lines() {
        let lines = render_msg(&Role::Agent, &"word ".repeat(50), 30, "stub");
        assert!(lines.len() > 3);
        assert!(lines[0].to_string().contains("medusa"));
    }

    #[test]
    fn user_message_renders_as_panel_card() {
        let lines = render_msg(&Role::User, "hello", 40, "stub");
        // border + blank pad + content + blank pad
        assert!(lines.len() >= 3);
        let first = lines[0].to_string();
        assert!(first.contains('┃'));
    }

    #[test]
    fn user_card_has_gap_between_border_and_text() {
        let lines = render_msg(&Role::User, "hello", 40, "stub");
        let content = lines[1].to_string();
        assert!(
            content.starts_with("┃  "),
            "border needs breathing room: {content}"
        );
        assert!(content.contains("  hello"));
    }

    #[test]
    fn error_card_has_same_gap() {
        let lines = render_msg(&Role::Error, "boom", 40, "stub");
        let content = lines[1].to_string();
        assert!(content.starts_with("┃  "), "got: {content}");
    }

    #[test]
    fn host_of_strips_scheme_and_path() {
        assert_eq!(host_of("https://grid.ai.juspay.net"), "grid.ai.juspay.net");
        assert_eq!(host_of("https://api.example.com/v1"), "api.example.com");
        assert_eq!(host_of("http://x.io/"), "x.io");
        assert_eq!(host_of("bare.example.com"), "bare.example.com");
    }

    #[test]
    fn app_applies_investigation_events() {
        let mut app = App::new("offline stub".into(), "stub".into(), "env".into());
        app.apply_event(&AgentEvent::HypothesisAdded {
            id: 1,
            statement: "s".into(),
            confidence: "low".into(),
        });
        assert_eq!(app.hypotheses.len(), 1);
        assert!(!app.messages.is_empty());
    }

    #[test]
    fn message_log_is_bounded_and_printed_cursor_follows() {
        let mut app = App::new("m".into(), "stub".into(), "e".into());
        for i in 0..(MAX_MESSAGES + 50) {
            app.push(Role::Step, format!("m{i}"));
        }
        assert_eq!(app.messages.len(), MAX_MESSAGES);
        // Cursor shifted with the dropped prefix, never out of bounds.
        app.printed = app.messages.len();
        app.push(Role::Step, "one more");
        // The trim dropped one old message; exactly the new one is unprinted.
        assert_eq!(app.printed, MAX_MESSAGES - 1);
        assert_eq!(app.messages.len() - app.printed, 1);
    }

    #[test]
    fn message_lines_count_includes_separator() {
        let m = Msg {
            role: Role::Agent,
            text: "hello world".into(),
        };
        // blank separator + agent label + one text line
        assert_eq!(message_lines(&m, "stub", 80).len(), 3);
        let m = Msg {
            role: Role::User,
            text: "hello".into(),
        };
        // blank + card blank + content + card blank
        assert_eq!(message_lines(&m, "stub", 80).len(), 4);
    }

    #[test]
    fn centered_anchor_geometry() {
        // 40-row screen: landing = 4 lines, input centered at row 20,
        // viewport top after insert = 19, anchor = 19 - 4 = 15.
        assert_eq!(centered_anchor(40), 15);
        // Odd height rounds down.
        assert_eq!(centered_anchor(41), 15);
        // Tiny terminals clamp everything sanely.
        assert_eq!(centered_anchor(2), 0);
        // 6 rows: max_top=3, input_row=3, viewport_top=2, top=min(2,3)=2, anchor=2-4=0 (clamped)
        assert_eq!(centered_anchor(6), 0);
    }

    #[test]
    fn centered_rect_geometry() {
        let area = Rect::new(0, 0, 100, 40);
        let r = centered_rect(area, 70, 9);
        assert_eq!(r, Rect::new(15, 15, 70, 9));
        // Clamps to the area when bigger than the screen.
        let r = centered_rect(area, 200, 100);
        assert_eq!(r, area);
        // Zero-size area stays sane.
        let tiny = Rect::new(0, 0, 0, 0);
        assert_eq!(centered_rect(tiny, 70, 9), tiny);
    }

    #[test]
    fn landing_height_matches_geometry_constant() {
        // print_landing debug-asserts this in debug builds; a mismatch
        // panics at startup (input lands off-center).
        assert_eq!(landing_lines(80).len() as u16, LANDING_LINES);
        assert_eq!(landing_lines(10).len() as u16, LANDING_LINES);
    }

    #[test]
    fn browse_offset_clamps_to_content() {
        // Normal clamp: cannot scroll past the first line.
        assert_eq!(clamp_browse_offset(100, 50, 20), 30);
        assert_eq!(clamp_browse_offset(5, 50, 20), 5);
        // Content shorter than the screen: no scrolling at all.
        assert_eq!(clamp_browse_offset(10, 10, 20), 0);
        assert_eq!(clamp_browse_offset(0, 0, 20), 0);
    }

    #[test]
    fn history_navigation_walks_prompts_and_restores_draft() {
        let mut app = App::new("m".into(), "stub".into(), "e".into());
        app.record_input("first");
        app.record_input("second");

        // start with an unsent draft, ↑ stashes it and jumps to newest
        app.input = "unsent".into();
        app.history_prev();
        assert_eq!(app.input, "second");
        app.history_prev();
        assert_eq!(app.input, "first");
        app.history_prev(); // clamps at oldest
        assert_eq!(app.input, "first");

        // ↓ walks forward and restores the draft at the end
        app.history_next();
        assert_eq!(app.input, "second");
        app.history_next();
        assert_eq!(app.input, "unsent");
        assert_eq!(app.history_index, None);

        // submitting resets browsing state
        app.record_input("third");
        assert_eq!(app.inputs, vec!["first", "second", "third"]);
        // consecutive duplicates are not recorded twice
        app.history_prev();
        app.record_input("third");
        assert_eq!(app.inputs.len(), 3);
    }
}
