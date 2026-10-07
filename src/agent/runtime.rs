//! The generic investigation loop. Target in, findings out —
//! the loop body never branches on assessment type.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::model::EnvironmentState;
use crate::registry::{CapabilityRegistry, ToolRegistry};

use super::context::{ContextManager, Finding};
use super::events::AgentEvent;
use super::executor::{LocalProcessExecutor, ProcessExecutor, ToolResult};
use super::model::{ContextView, Decision, ModelError, ModelProvider};
use super::policy::{ExecutionPolicy, PolicyError};
use super::provider::{CapabilityRequest, ExecutionContext, ProviderRegistry};
use super::vault::VaultManager;

/// What is being assessed. Deliberately thin in Phase 1; the world model
/// (Phase 3) builds the asset graph from this seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// e.g. "10.0.0.10", "https://example.internal", "/path/to/repo".
    pub address: String,
    /// Optional scope note, e.g. profile id ("high_coverage").
    pub profile: Option<String>,
}

impl Target {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            profile: None,
        }
    }
}

/// A validated-but-not-yet-executed action. Phase 4 turns these into real
/// `ToolCall`s; until then they prove the loop resolves capabilities to
/// providers correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    pub step: usize,
    pub capability: String,
    pub provider: String,
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    ModelFinished(String),
    MaxSteps(usize),
    Cancelled,
    TooManyModelErrors { count: usize, last_error: String },
    ConfigError(String),
    ContextExhausted,
}

#[derive(Debug, Clone)]
pub struct InvestigationResult {
    pub target: Target,
    pub steps_taken: usize,
    pub planned_actions: Vec<PlannedAction>,
    pub tool_results: Vec<ToolResult>,
    pub finish_reason: FinishReason,
    /// If the investigation ended due to model errors, the last error message.
    pub model_error: Option<String>,
}

/// External cancellation handle. Clone it into another thread / Ctrl-C
/// handler and call `cancel()`; the loop observes it every iteration.
#[derive(Debug, Clone, Default)]
pub struct RuntimeHandle {
    cancelled: Arc<AtomicBool>,
}

impl RuntimeHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Clear a previous cancellation. Called at every turn boundary so
    /// Stop applies to the turn in flight only: without this, one Stop
    /// latches the flag and every later turn insta-cancels at the top
    /// of the drive loop — the session looks alive but never acts again.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

pub struct AgentRuntime<'a> {
    model: std::cell::RefCell<Box<dyn ModelProvider>>,
    policy: ExecutionPolicy,
    /// Optional decision budget. `None` (default) = unlimited: turns end
    /// when the model replies/finishes, the user cancels, or a circuit
    /// breaker (consecutive model errors, tool failures) trips.
    max_steps: Option<usize>,
    max_consecutive_errors: usize,
    /// Model context window in tokens (default 128k). The drive loop
    /// tracks per-decision usage against this for the context meter and
    /// auto-compaction. Provider `usage` blocks are authoritative; a
    /// char/4 estimate fills in when the endpoint omits them.
    context_tokens: u64,
    /// Auto-compact when usage reaches this percent of `context_tokens`
    /// (default 85). At least `MIN_STEPS_BETWEEN_COMPACTIONS` decisions
    /// of progress are required between compactions — re-crossing the
    /// threshold sooner means even a fresh summary cannot fit, and the
    /// turn ends with `ContextExhausted` instead of thrashing.
    compaction_threshold_pct: u8,
    /// Conversation turns kept verbatim across a compaction (default 4).
    compact_keep_turns: usize,
    handle: RuntimeHandle,
    caps: &'a CapabilityRegistry,
    state: &'a EnvironmentState,
    /// Capability → provider resolution (the allow-list). Built from the
    /// tool registry; the LLM never selects providers.
    providers: ProviderRegistry,
    /// Injectable executor (tests, dry runs). Production defaults to the
    /// local process executor: direct spawn, no shell, with timeout.
    executor: Option<Arc<dyn ProcessExecutor>>,
    /// Blocking approval gate for interactive UIs (see
    /// [`AgentRuntime::with_approval_gate`]). `None` in headless/CLI runs.
    approval_gate: Option<std::sync::Arc<std::sync::Mutex<Option<bool>>>>,
}

impl<'a> AgentRuntime<'a> {
    pub fn new(
        model: Box<dyn ModelProvider>,
        tools: &'a ToolRegistry,
        caps: &'a CapabilityRegistry,
        state: &'a EnvironmentState,
    ) -> Self {
        let mut providers = ProviderRegistry::from_tools(tools);
        // Internal providers ship with medusa itself (no external tool):
        // the raw HTTP request provider behind http.request /
        // api.auth_testing / api.bola_testing, and the web-research
        // provider behind web.research (fetch + extract).
        providers.register(std::sync::Arc::new(
            super::http_provider::HttpRequestProvider::new(),
        ));
        providers.register(std::sync::Arc::new(super::research::ResearchProvider::new()));
        Self {
            model: std::cell::RefCell::new(model),
            policy: ExecutionPolicy::default(),
            max_steps: None,
            max_consecutive_errors: 5,
            context_tokens: 128_000,
            compaction_threshold_pct: 85,
            compact_keep_turns: 4,
            handle: RuntimeHandle::default(),
            caps,
            state,
            providers,
            executor: None,
            approval_gate: None,
        }
    }

    /// Swap the model provider at runtime (e.g. the desktop's provider
    /// switch). Interior mutability: the session borrows the runtime
    /// immutably, so a plain `&mut self` setter would not compile — and
    /// would race a running turn anyway. Between turns this is safe: the
    /// worker mailbox is drained sequentially on one thread.
    pub fn swap_model(&self, model: Box<dyn ModelProvider>) {
        *self.model.borrow_mut() = model;
    }

    /// Display name of the active model (for UI labels).
    pub fn model_name(&self) -> String {
        self.model.borrow().name().to_string()
    }

    /// Cap model-decisions per turn (per run when autonomous). Unbounded by
    /// default; set only when a hard budget is explicitly wanted.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.max_steps = Some(n);
        self
    }

    /// Model context window in tokens for the context meter and
    /// auto-compaction threshold.
    pub fn with_context_window(mut self, tokens: u64) -> Self {
        if tokens > 0 {
            self.context_tokens = tokens;
        }
        self
    }

    /// Auto-compact threshold as a 0-100 percent of the context window.
    pub fn with_compaction_threshold(mut self, pct: u8) -> Self {
        if pct > 0 && pct <= 100 {
            self.compaction_threshold_pct = pct;
        }
        self
    }

    /// Conversation turns kept verbatim across a compaction.
    pub fn with_compact_keep_turns(mut self, n: usize) -> Self {
        self.compact_keep_turns = n;
        self
    }

    /// Inject a process executor (tests, dry runs). Production defaults to
    /// the local process executor — direct `Command::new(exe).args(argv)`,
    /// never a shell.
    pub fn with_executor(mut self, executor: Arc<dyn ProcessExecutor>) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Inject an externally-created handle so callers can cancel before
    /// the runtime is even moved into its worker thread.
    pub fn with_handle(mut self, handle: RuntimeHandle) -> Self {
        self.handle = handle;
        self
    }

    /// Share the TUI approval flag so high-risk Destructive tests can be
    /// approved mid-investigation without restarting the runtime.
    pub fn with_approval_flag(
        mut self,
        flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.policy.allow_destructive = flag;
        self
    }

    /// Blocking approval gate for interactive UIs: when a high-risk
    /// capability is rejected, the drive loop WAITS here for the user's
    /// decision instead of racing ahead (the model would retry before the
    /// dialog is even clicked). `Some(true)` approves (and latches the
    /// flag), `Some(false)` denies and feeds the rejection back. `None`
    /// means undecided; without a gate (CLI), behavior is unchanged.
    pub fn with_approval_gate(
        mut self,
        gate: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
    ) -> Self {
        self.approval_gate = Some(gate);
        self
    }

    pub fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    /// Headless entry point: same loop, events discarded. Tests and
    /// `--json` flows use this; live UI uses [`Self::investigate_with`].
    pub fn investigate(&self, target: Target) -> InvestigationResult {
        self.investigate_with(target, &mut |_| {})
    }

    /// Investigation loop with an event listener. The listener is passive:
    /// it observes but never influences the loop, so replaying recorded
    /// events reproduces the run deterministically. `FnMut` (not `Fn`) so
    /// live renderers can hold UI state; tests use a `RefCell<Vec>`.
    pub fn investigate_with(
        &self,
        target: Target,
        emit: &mut dyn FnMut(AgentEvent),
    ) -> InvestigationResult {
        use super::events::AgentEvent as Ev;

        emit(Ev::InvestigationStarted {
            target: target.address.clone(),
        });
        // Autonomous (CLI) semantics: the declared target IS the scope.
        let mut sess = self.session();
        sess.policy = self.policy.for_target(&target.address);
        sess.scope_label = target.address.clone();
        let outcome = sess.drive(true, emit);
        let finish_reason = match outcome {
            DriveOutcome::Finished(r) => FinishReason::ModelFinished(r),
            DriveOutcome::MaxSteps(n) => FinishReason::MaxSteps(n),
            DriveOutcome::Cancelled => FinishReason::Cancelled,
            DriveOutcome::TooManyModelErrors { count, last_error } => {
                FinishReason::TooManyModelErrors { count, last_error }
            }
            DriveOutcome::ConfigError(e) => FinishReason::ConfigError(e),
            DriveOutcome::ContextExhausted => FinishReason::ContextExhausted,
            // Unreachable: autonomous drive treats reply as narration and
            // continues. Mapped defensively regardless.
            DriveOutcome::Replied(r) => FinishReason::ModelFinished(r),
        };
        emit(Ev::Finished {
            reason: match &finish_reason {
                FinishReason::ModelFinished(r) => r.clone(),
                FinishReason::MaxSteps(n) => format!("max steps ({n}) reached"),
                FinishReason::Cancelled => "cancelled".to_string(),
                FinishReason::TooManyModelErrors { count, last_error } => {
                    format!("model failed {count} times in a row: {last_error}")
                }
                FinishReason::ConfigError(e) => format!("misconfigured: {e}"),
                FinishReason::ContextExhausted => {
                    "context window exhausted even after compaction — findings and vault preserved; start a new run to continue".to_string()
                }
            },
        });
        sess.into_result(target, finish_reason)
    }

    /// A fresh interactive session: persistent context and scope across
    /// turns. Scope starts EMPTY — nothing may execute until the user
    /// mentions a target (parsed by us, never the model).
    pub fn session(&self) -> AgentSession<'_, 'a> {
        AgentSession {
            rt: self,
            env: self.state.clone(),
            cm: ContextManager::new(),
            tool_results: Vec::new(),
            consecutive_errors: 0,
            step: 0,
            hypothesis_seq: 0,
            policy: self.policy.for_session(),
            scope_label: String::new(),
            approval_denied: false,
            model_secs_step: 0.0,
            used_tokens: 0,
            // Start "long ago" so the first threshold crossing compacts
            // immediately instead of looking like thrash.
            steps_since_compact: 1_000_000,
            vault: None,
        }
    }

    fn context_view(
        &self,
        env: &EnvironmentState,
        target: &Target,
        step: usize,
        cm: &ContextManager,
    ) -> ContextView {
        // Advertise only what provider selection would actually accept:
        // env health says a tool is installed, but the argv guard (no
        // `{target}` slot — zap GUI, rizin REPL, …) can still make every
        // provider of a capability unusable. Advertising those lures the
        // model into guaranteed rejections.
        let mut available: Vec<String> = env
            .available_capabilities()
            .into_iter()
            .filter(|cap| {
                self.providers
                    .all()
                    .iter()
                    .any(|p| p.capabilities().iter().any(|c| c == cap) && p.is_available(env))
            })
            .map(|s| s.to_string())
            .collect();
        available.sort();
        // Semantic option schemas for available capabilities, so the model
        // knows which options it may pass (and only those).
        let capability_schemas: Vec<String> = self
            .caps
            .all()
            .iter()
            .filter(|c| available.contains(&c.id))
            .map(|c| {
                if c.options.is_empty() {
                    format!("{}: no options", c.id)
                } else {
                    format!(
                        "{}: {}",
                        c.id,
                        c.options
                            .iter()
                            .map(|o| o.hint())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            })
            .collect();
        let (view, _report) = cm.build_view_with_schemas(
            target,
            step,
            available,
            env.unavailable_capabilities().len(),
            capability_schemas,
        );
        view
    }
}

/// Outcome of a blocking approval wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDecision {
    Allow,
    Deny,
    /// No gate wired (headless) or the user never answered.
    None,
}

/// System prompt for the compaction summarizer. The summary REPLACES
/// older conversation turns: it must preserve conclusions, not prose.
/// Vault values are never in the materials, and the instruction forbids
/// inventing findings beyond the registry (the registry itself is
/// re-injected verbatim every turn, so the summary cannot corrupt it).
const COMPACT_SYSTEM: &str = r#"You are compacting a security-assessment conversation that outgrew the model's context window. Write a dense structured summary of the MATERIALS below (which end with the oldest retained conversation turns).

Sections (keep each tight, ~1500 words total):
1. GOAL + TARGET — what is being assessed.
2. WHAT WAS TRIED — tools/capabilities run and what each learned (1 line each).
3. CURRENT UNDERSTANDING — hypotheses, validated paths, dead ends.
4. PENDING NEXT STEPS — what to try next and why.
5. LAST ERROR — only if one is present.

Rules:
- Carry the FINDINGS REGISTRY over faithfully (ids, severities, statuses). NEVER invent findings beyond it.
- Carry VAULT KEY NAMES over (you do not have the values; never ask for them to be repeated here).
- Preserve concrete facts (hosts, ports, paths, versions, exact error strings); drop chit-chat and intermediate reasoning.
- Plain text, no JSON, no markdown headers beyond the numbered sections."#;

/// Why a turn or investigation ended.
#[derive(Debug, Clone)]
pub enum DriveOutcome {
    /// Model answered the user (interactive sessions only).
    Replied(String),
    /// Model declared the assessment complete.
    Finished(String),
    /// Step budget exhausted (per-turn in interactive mode).
    MaxSteps(usize),
    Cancelled,
    TooManyModelErrors {
        count: usize,
        last_error: String,
    },
    ConfigError(String),
    /// The context window stayed exhausted across a compaction (even a
    /// fresh summary cannot fit): the turn ends gracefully with findings
    /// and vault intact instead of thrashing.
    ContextExhausted,
}

/// One interactive session: persistent context and scope across turns.
/// Created via [`AgentRuntime::session`]; the runtime stays stateless so
/// several sessions can share one process (desktop actor model: one
/// `AgentSession` per conversation worker).
pub struct AgentSession<'r, 'a> {
    rt: &'r AgentRuntime<'a>,
    /// Owned env clone: held so provider selection and the
    /// available-capability list stay honest about the original scan
    /// state without mutating the shared environment snapshot.
    env: EnvironmentState,
    cm: ContextManager,
    tool_results: Vec<ToolResult>,
    consecutive_errors: usize,
    step: usize,
    /// Monotonic id for hypothesis events (event-only: the model's
    /// reasoning, not a store we rank).
    hypothesis_seq: usize,
    policy: ExecutionPolicy,
    scope_label: String,
    /// Set after the user denied (or never answered) a high-risk approval:
    /// further high-risk rejections don't block again — the model gets the
    /// feedback and pivots. Cleared on a fresh approval.
    approval_denied: bool,
    /// Cumulative LLM seconds for the step in flight. Failed/retried
    /// model calls accumulate here; consumed (taken) when the decision's
    /// events are emitted so the UI can attribute latency honestly.
    model_secs_step: f64,
    /// Latest context-window usage in tokens (provider `usage` when
    /// reported, char/4 estimate otherwise). Drives the context meter
    /// and auto-compaction.
    used_tokens: u64,
    /// Loop iterations since the last compaction. Guards against
    /// auto-compact thrashing: re-crossing the threshold with fewer
    /// than `MIN_STEPS_BETWEEN_COMPACTIONS` decisions of progress ends
    /// the turn instead of compacting again.
    steps_since_compact: usize,
    /// Per-target vault, loaded lazily once scope exists. `None` until
    /// the first vault decision (vaults are per-target; an unscoped
    /// session has nowhere to store).
    vault: Option<VaultManager>,
}

/// Decisions of progress required between two auto-compactions.
const MIN_STEPS_BETWEEN_COMPACTIONS: usize = 2;

/// Attempts per execute decision before the failure is reported to the
/// model. Transient blips (fast exits, network hiccups) recover here;
/// timeouts are never retried (they already burned the full budget).
const MAX_ATTEMPTS: usize = 3;

impl<'r, 'a> AgentSession<'r, 'a> {
    /// Interactive turn: user message in, terminal Reply event out.
    /// Executes tools in between as the model decides. Guarantees exactly
    /// one terminal event per completed turn (`Reply` — or none when the
    /// turn was cancelled).
    pub fn run_turn(
        &mut self,
        user_message: &str,
        emit: &mut dyn FnMut(AgentEvent),
    ) -> DriveOutcome {
        use super::events::AgentEvent as Ev;

        // A Stop applies to the turn in flight only: clear any previous
        // cancellation so a fresh user message always gets a working
        // turn. (Autonomous `investigate` deliberately does NOT reset —
        // a pre-cancelled run must stay cancelled.)
        self.rt.handle.reset();
        // Fresh turn: nothing is disabled. Tools are never taken away
        // from the model — it has full visibility of what already ran
        // (prior_actions) and decides when to retry. Removing tools was
        // the original loop hazard: without that hindsight the model kept
        // re-running a failing tool, so we removed the tool instead of
        // fixing the visibility.
        self.grant_scope_from_message(user_message, emit);
        self.cm.begin_turn(user_message);
        let outcome = self.drive(false, emit);
        match &outcome {
            DriveOutcome::Replied(text) => {
                let text = text.clone();
                self.cm.end_turn(&text);
                // The reply is user-facing speech too — record it so the
                // next turn knows what was already said.
                self.cm.add_narration(&text);
                emit(Ev::Reply { text });
            }
            DriveOutcome::Finished(reason) => {
                let reason = reason.clone();
                self.cm.end_turn(&reason);
                emit(Ev::Finished {
                    reason: reason.clone(),
                });
                emit(Ev::Reply { text: reason });
            }
            DriveOutcome::MaxSteps(n) => {
                let text = format!(
                    "I hit the per-turn step limit ({n}). Ask me to continue and I'll pick up where I left off."
                );
                self.cm.end_turn(&text);
                emit(Ev::Reply { text });
            }
            DriveOutcome::TooManyModelErrors { last_error, .. } => {
                let text =
                    format!("I couldn't reach the model repeatedly and stopped: {last_error}");
                self.cm.end_turn(&text);
                emit(Ev::Reply { text });
            }
            DriveOutcome::ConfigError(e) => {
                let text = format!("Model configuration problem: {e}");
                self.cm.end_turn(&text);
                emit(Ev::Reply { text });
            }
            DriveOutcome::ContextExhausted => {
                let text = "My context filled up and even a compacted summary can't fit what remains — I've kept every finding and vault key, so nothing confirmed is lost. Start a new turn or session and I'll continue from the registry.".to_string();
                self.cm.end_turn(&text);
                emit(Ev::Reply { text });
            }
            DriveOutcome::Cancelled => {}
        }
        outcome
    }

    /// Grant scope for every host-like token the user mentioned. WE parse
    /// the message — the model can never grant scope. Emits `ScopeGranted`
    /// per newly added root so UIs can show the live scope.
    fn grant_scope_from_message(&mut self, message: &str, emit: &mut dyn FnMut(AgentEvent)) {
        for host in hosts_in(message) {
            if self.policy.grant_scope(&host) {
                self.scope_label = host.clone();
                emit(AgentEvent::ScopeGranted { target: host });
            }
        }
        // Late grants (message after the first) still update the label.
        if self.scope_label.is_empty() {
            if let Some(first) = self.policy_scope_first() {
                self.scope_label = first;
            }
        }
    }

    fn policy_scope_first(&self) -> Option<String> {
        let roots = self.policy.scope_roots();
        roots.first().cloned()
    }

    /// Current window usage as a 0-100 percent, capped (estimates can
    /// overshoot the configured window).
    fn usage_pct(&self) -> u8 {
        let limit = self.rt.context_tokens.max(1);
        ((self.used_tokens.saturating_mul(100) / limit).min(100)) as u8
    }

    fn over_threshold(&self) -> bool {
        self.usage_pct() >= self.rt.compaction_threshold_pct
    }

    /// The session's vault, loaded lazily per scope target. Vaults are
    /// per-target: an unscoped session has nowhere to store.
    fn vault_mut(&mut self) -> Result<&mut VaultManager, String> {
        if self.scope_label.trim().is_empty() {
            return Err(
                "no assessment target in scope yet — the vault is per-target, tell me what to assess first"
                    .to_string(),
            );
        }
        let stale = match &self.vault {
            Some(v) => v.target() != self.scope_label,
            None => true,
        };
        if stale {
            self.vault = Some(VaultManager::load(&self.scope_label));
        }
        Ok(self.vault.as_mut().expect("vault just loaded"))
    }

    fn vault_key_lines(&self) -> Vec<String> {
        self.vault
            .as_ref()
            .filter(|v| v.target() == self.scope_label)
            .map(|v| v.key_lines())
            .unwrap_or_default()
    }

    fn refresh_vault_keys(&mut self) {
        let keys = self.vault_key_lines();
        self.cm.set_vault_keys(keys);
    }

    /// Char/4 estimate of the live window: conversation + observations +
    /// findings + vault keys + narrations. Used after a compaction (the
    /// provider's next `usage` block takes over from there).
    fn estimate_window_tokens(&self) -> u64 {
        let conv: usize = self
            .cm
            .conversation()
            .iter()
            .map(|t| t.user.len() + t.assistant.len())
            .sum();
        let obs: usize = self.cm.observations().iter().map(|o| o.summary.len()).sum();
        let fnd: usize = self
            .cm
            .findings()
            .iter()
            .map(|f| f.title.len() + f.detail.len())
            .sum();
        ((conv + obs + fnd) / 4) as u64 + 512
    }

    /// Bounded materials for the summarizer call: the summarization
    /// request itself must fit the window, so history is capped (newest
    /// observations/actions, truncated conversation text). Findings and
    /// vault KEY NAMES ride in full — the summary must never lose them,
    /// and vault VALUES are never present to leak.
    fn compaction_materials(&self) -> String {
        const MAX_CONV_CHARS: usize = 60_000;
        let mut out = String::new();
        out.push_str(&format!(
            "Assessment target: {}\nSteps so far: {}\n\n",
            self.scope_label, self.step
        ));
        out.push_str("FINDINGS REGISTRY (complete — carry these over by id, severity, status; do not re-derive or invent):\n");
        if self.cm.findings().is_empty() {
            out.push_str("(none yet)\n");
        }
        for f in self.cm.findings() {
            out.push_str(&format!(
                "F{} [{}|{}] {} ({}) — {}\n",
                f.id, f.severity, f.status, f.title, f.target, f.detail
            ));
        }
        out.push_str("\nVAULT KEYS (names only — carry the names over so they stay known):\n");
        let keys = self.vault_key_lines();
        if keys.is_empty() {
            out.push_str("(vault empty)\n");
        }
        for k in &keys {
            out.push_str(&format!("{k}\n"));
        }
        out.push_str("\nRECENT OBSERVATIONS (newest last):\n");
        let obs = self.cm.observations();
        for o in obs.iter().rev().take(30).collect::<Vec<_>>().into_iter().rev() {
            out.push_str(&format!("O{}: {}\n", o.id, o.summary));
        }
        out.push_str("\nCONVERSATION (oldest first, truncated to fit):\n");
        let mut budget = MAX_CONV_CHARS;
        let turns = self.cm.conversation();
        let start = turns.len().saturating_sub(40);
        for t in &turns[start..] {
            for (role, text) in [("user", &t.user), ("assistant", &t.assistant)] {
                if budget == 0 {
                    break;
                }
                let take = text.len().min(budget);
                let mut cut = take;
                while cut > 0 && !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                out.push_str(&format!("{role}: {}\n", &text[..cut]));
                budget -= cut;
            }
        }
        if start > 0 || budget == 0 {
            out.push_str("[older turns omitted for size]\n");
        }
        out
    }

    /// Replace older turns with a model-written summary (or oldest-first
    /// truncation when the summarizer call fails). Findings, vault keys,
    /// narrations, and recent turns survive verbatim.
    fn run_compaction(&mut self, emit: &mut dyn FnMut(AgentEvent)) {
        use super::events::AgentEvent as Ev;
        let before = self.used_tokens;
        let keep = self.rt.compact_keep_turns;
        let materials = self.compaction_materials();
        match self.rt.model.borrow().chat(COMPACT_SYSTEM, &materials) {
            Ok(summary) => {
                self.cm.compact(&summary, keep);
                self.refresh_vault_keys();
                let after = self.estimate_window_tokens();
                self.used_tokens = after;
                emit(Ev::Compacted {
                    before_tokens: before,
                    after_tokens: after,
                    freed_tokens: before.saturating_sub(after),
                    fallback: false,
                });
            }
            Err(e) => {
                // The summarizer failed (transport, bad response): degrade
                // to oldest-first truncation. The registry and vault keys
                // are still intact — only prose history is lost.
                self.cm.compact(
                    &format!(
                        "(summarizer unavailable: {e}) Earlier turns truncated oldest-first; the findings registry and vault keys below are complete — trust them."
                    ),
                    keep,
                );
                self.refresh_vault_keys();
                let after = self.estimate_window_tokens();
                self.used_tokens = after;
                emit(Ev::Compacted {
                    before_tokens: before,
                    after_tokens: after,
                    freed_tokens: before.saturating_sub(after),
                    fallback: true,
                });
            }
        }
    }

    /// Manual compaction (desktop "Compact now"): same path as
    /// auto-compaction, unconditional.
    pub fn compact_now(&mut self, emit: &mut dyn FnMut(AgentEvent)) {
        self.run_compaction(emit);
        self.steps_since_compact = 0;
    }

    /// Rebuild live model state (scope, conversation, observations) from a
    /// persisted session file. Without this, reopening a session after an
    /// app restart shows the transcript in the UI while the model starts
    /// blank: no target in scope, no memory of prior turns or findings, so
    /// a follow-up like "try other severities" has nothing to point at.
    /// Replaying is silent (no events — the UI already has the records)
    /// and idempotent (grants and observations dedupe).
    pub fn rehydrate(&mut self, records: &[crate::infra::sessions::TimedRecord]) {
        use crate::infra::sessions::SessionRecord as Rec;
        for timed in records {
            match &timed.record {
                Rec::Target { target } => {
                    self.policy.grant_scope(target);
                    self.scope_label = target.clone();
                }
                Rec::Chat { user, agent, .. } => {
                    // Dedupe: replaying a file twice (or a crash-resume
                    // retry) must not stack duplicate turns.
                    let seen = self
                        .cm
                        .last_turn()
                        .is_some_and(|t| t.user == *user && t.assistant == *agent);
                    if !seen {
                        self.cm.begin_turn(user);
                        self.cm.end_turn(agent);
                    }
                }
                Rec::Obs { text } => {
                    let target = self.scope_label.clone();
                    let step = self.step;
                    self.cm.add_observation(&target, text, "replay", step);
                }
                Rec::Note { text } => {
                    // Replayed narrations keep the model aware of what
                    // the user was already told in prior sessions.
                    self.cm.add_narration(text);
                }
                Rec::Finding {
                    id,
                    severity,
                    title,
                    target,
                    status,
                    detail,
                    step,
                } => {
                    // Registry rows replay verbatim (records are
                    // chronological, so a later row for the same id
                    // carries the newer status). Double-load safe.
                    if self.cm.findings().iter().any(|f| f.id == *id) {
                        self.cm.update_finding(*id, status, *step);
                    } else {
                        self.cm.replay_finding(Finding {
                            id: *id,
                            severity: severity.clone(),
                            title: title.clone(),
                            target: target.clone(),
                            source: "replay".into(),
                            detail: detail.clone(),
                            status: status.clone(),
                            step_found: *step,
                            step_updated: *step,
                        });
                    }
                }
                Rec::CtxUsage { used, .. } => {
                    // Resume the meter where the session left off so a
                    // reopened long session compacts on schedule.
                    self.used_tokens = *used;
                }
                Rec::Compacted { .. } => {
                    // A compaction happened in a prior process lifetime:
                    // keep the continuity note; the summary itself was
                    // already folded into the replayed conversation.
                    self.cm.note_replayed_compaction();
                }
                Rec::VaultOp { .. } => {
                    // Vault state loads from disk on demand — nothing to
                    // replay (and values are never in records by design).
                }
                _ => {}
            }
        }
    }

    /// Direct `file_read` implementation: resolve the model's path to a
    /// confined location and read a bounded slice of it. Rather than
    /// dumping a large file into context, `grep` returns only matching
    /// lines (with context) and a plain read returns a head window. This
    /// keeps a big file (bundle.js, logs) from blowing the budget.
    fn run_file_read(
        &mut self,
        path: &str,
        grep: &Option<String>,
        lines: &Option<u32>,
        reason: &str,
        model_secs: f64,
        emit: &mut dyn FnMut(AgentEvent),
    ) {
        use super::events::AgentEvent as Ev;
        use super::file_tools::{grep_file, read_n_lines, ReadSlice};
        let roots = self.policy.scope_roots();
        emit(Ev::CapabilityRequested {
            capability: "file.read".into(),
            target: path.to_string(),
            reason: reason.to_string(),
            model_secs,
        });
        match super::file_tools::resolve_path(path, &roots) {
            Err(e) => {
                let msg = format!("file read not allowed for \"{path}\": {e}");
                emit(Ev::ToolExecuted {
                    tool_id: "file-read".into(),
                    capability: "file.read".into(),
                    target: path.to_string(),
                    exit_code: 1,
                    success: false,
                    timed_out: false,
                    output: msg.clone(),
                    tool_secs: 0.0,
                });
                self.cm.set_last_error(Some(msg));
            }
            Ok(real) => {
                // Wall-clock for the operation (read/grep slice) so the
                // UI's duration chip shows why an op was slow.
                let t0 = std::time::Instant::now();
                let sliced: Result<ReadSlice, String> = if let Some(pat) = grep {
                    grep_file(&real, pat)
                } else {
                    let n = lines
                        .map(|l| l as usize)
                        .unwrap_or(super::file_tools::DEFAULT_READ_LINES);
                    read_n_lines(&real, n)
                };
                match sliced {
                    Ok(slice) => {
                        let body = slice.lines.join("\n");
                        let total = slice.total_lines;
                        let returned = slice.lines.len();
                        let elided = total.saturating_sub(returned);
                        let mode = if grep.is_some() {
                            "match"
                        } else {
                            "window"
                        };
                        let evidence = serde_json::json!({
                            "tool": "file-read",
                            "path": real.display().to_string(),
                            "mode": mode,
                            "total_lines": total,
                            "returned_lines": returned,
                            "elided_lines": elided,
                            "complete": slice.complete,
                            "content": body,
                        });
                        emit(Ev::ToolExecuted {
                            tool_id: "file-read".into(),
                            capability: "file.read".into(),
                            target: path.to_string(),
                            exit_code: 0,
                            success: true,
                            timed_out: false,
                            output: serde_json::to_string(&evidence).unwrap_or_default(),
                            tool_secs: t0.elapsed().as_secs_f64(),
                        });
                        // CRITICAL: ride the raw content into the model's
                        // `recent_evidence` on the next step — WITHOUT this,
                        // the UI shows "file-read ok" but the model never
                        // sees the lines it read, so it has nothing to work
                        // from and keeps re-reading the same file.
                        self.cm.add_evidence("file-read", path, &body);
                        let step = self.step;
                        let summary = if returned == 0 {
                            format!(
                                "{} ({} lines): no lines matched the grep",
                                real.display(),
                                total
                            )
                        } else {
                            format!(
                                "{}: {} lines returned{}",
                                real.display(),
                                returned,
                                if elided > 0 {
                                    format!(" of {total}, {elided} elided")
                                } else {
                                    " (complete)".to_string()
                                }
                            )
                        };
                        self.cm.add_observation(&path, &summary, "file.read", step);
                        emit(Ev::ObservationAdded { summary });
                    }
                    Err(e) => {
                        let msg = format!("file read failed: {e}");
                        emit(Ev::ToolExecuted {
                            tool_id: "file-read".into(),
                            capability: "file.read".into(),
                            target: path.to_string(),
                            exit_code: 1,
                            success: false,
                            timed_out: false,
                            output: msg.clone(),
                            tool_secs: t0.elapsed().as_secs_f64(),
                        });
                        self.cm.set_last_error(Some(msg));
                    }
                }
            }
        }
    }

    /// Direct `file_write` implementation: resolve to a confined location
    /// (creating the work dir), write the content, and confirm to the
    /// model. Confinement takes precedence — a refused path is never
    /// written anywhere.
    fn run_file_write(
        &mut self,
        path: &str,
        content: &str,
        reason: &str,
        model_secs: f64,
        emit: &mut dyn FnMut(AgentEvent),
    ) {
        use super::events::AgentEvent as Ev;
        let roots = self.policy.scope_roots();
        emit(Ev::CapabilityRequested {
            capability: "file.write".into(),
            target: path.to_string(),
            reason: reason.to_string(),
            model_secs,
        });
        match super::file_tools::resolve_path(path, &roots) {
            Err(e) => {
                let msg = format!("file write not allowed for \"{path}\": {e}");
                emit(Ev::ToolExecuted {
                    tool_id: "file-write".into(),
                    capability: "file.write".into(),
                    target: path.to_string(),
                    exit_code: 1,
                    success: false,
                    timed_out: false,
                    output: msg.clone(),
                    tool_secs: 0.0,
                });
                self.cm.set_last_error(Some(msg));
            }
            Ok(real) => {
                let t0 = std::time::Instant::now();
                match super::file_tools::write_file(&real, content) {
                Ok(bytes) => {
                    let wrapped = match serde_json::to_string(&serde_json::json!({
                        "tool": "file-write",
                        "path": real.display().to_string(),
                        "bytes": bytes,
                    })) {
                        Ok(s) => s,
                        Err(_) => real.display().to_string(),
                    };
                    emit(Ev::ToolExecuted {
                        tool_id: "file-write".into(),
                        capability: "file.write".into(),
                        target: path.to_string(),
                        exit_code: 0,
                        success: true,
                        timed_out: false,
                        output: wrapped,
                        tool_secs: t0.elapsed().as_secs_f64(),
                    });
                    let step = self.step;
                    let summary =
                        format!("wrote {} ({} bytes)", real.display(), bytes);
                    self.cm.add_observation(&path, &summary, "file.write", step);
                    emit(Ev::ObservationAdded { summary });
                }
                Err(e) => {
                    let msg = format!("file write failed: {e}");
                    emit(Ev::ToolExecuted {
                        tool_id: "file-write".into(),
                        capability: "file.write".into(),
                        target: path.to_string(),
                        exit_code: 1,
                        success: false,
                        timed_out: false,
                        output: msg.clone(),
                        tool_secs: t0.elapsed().as_secs_f64(),
                    });
                    self.cm.set_last_error(Some(msg));
                }
                }
            }
        }
    }

    /// Block until the user answers the approval dialog (interactive UIs).
    /// `Some(true)` latches the destructive flag so the model's retry
    /// passes validation; deny/timeout leave it off. Cancel-aware.
    fn wait_for_approval(&mut self) -> ApprovalDecision {
        let Some(gate) = self.rt.approval_gate.clone() else {
            return ApprovalDecision::None;
        };
        const TIMEOUT_MS: u64 = 180_000;
        const POLL_MS: u64 = 150;
        let mut waited = 0u64;
        loop {
            if self.rt.handle.is_cancelled() {
                return ApprovalDecision::None;
            }
            let decision = { gate.lock().unwrap().take() };
            match decision {
                Some(true) => {
                    self.policy.allow_destructive.store(true, Ordering::SeqCst);
                    return ApprovalDecision::Allow;
                }
                Some(false) => return ApprovalDecision::Deny,
                None => {}
            }
            if waited >= TIMEOUT_MS {
                return ApprovalDecision::None;
            }
            std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
            waited += POLL_MS;
        }
    }

    /// The shared decision loop. `autonomous = true` drives to
    /// Finish/limits (CLI `assess`); `false` additionally stops on Reply.
    fn drive(&mut self, autonomous: bool, emit: &mut dyn FnMut(AgentEvent)) -> DriveOutcome {
        use super::events::AgentEvent as Ev;

        let executor: Arc<dyn ProcessExecutor> = self
            .rt
            .executor
            .clone()
            .unwrap_or_else(|| Arc::new(LocalProcessExecutor::new()));
        let turn_start_step = self.step;
        loop {
            if self.rt.handle.is_cancelled() {
                return DriveOutcome::Cancelled;
            }
            // Optional decision budget (None = unlimited): interactive
            // turns get a per-turn budget; autonomous runs a total budget.
            if let Some(limit) = self.rt.max_steps {
                let budget = if autonomous {
                    limit
                } else {
                    turn_start_step.saturating_add(limit)
                };
                if self.step >= budget {
                    return DriveOutcome::MaxSteps(limit);
                }
            }

            emit(Ev::StepStarted { step: self.step });
            // Auto-compaction BEFORE the view is built: when the last
            // reading crossed the threshold, older turns are summarized
            // so the next decision fits the window. Findings and vault
            // keys survive verbatim (see ContextManager::compact).
            self.steps_since_compact = self.steps_since_compact.saturating_add(1);
            if self.over_threshold() {
                if self.steps_since_compact < MIN_STEPS_BETWEEN_COMPACTIONS {
                    // Re-crossed with no progress in between: even a fresh
                    // summary cannot fit. End gracefully instead of
                    // thrashing (compact → still over → compact → ...).
                    emit(Ev::Error {
                        message: "context window exhausted even after compaction — findings and vault preserved".to_string(),
                    });
                    return DriveOutcome::ContextExhausted;
                }
                self.run_compaction(emit);
                self.steps_since_compact = 0;
                if self.over_threshold() {
                    emit(Ev::Error {
                        message: "context window exhausted even after compaction — findings and vault preserved".to_string(),
                    });
                    return DriveOutcome::ContextExhausted;
                }
            }
            emit(Ev::ModelThinking);
            let target = Target::new(&self.scope_label);
            let mut ctx = self
                .rt
                .context_view(&self.env, &target, self.step, &self.cm);
            ctx.autonomous = autonomous;
            ctx.vault_keys = self.vault_key_lines();
            let decision = {
                // LLM latency attribution: every model call (failed or
                // not) accumulates into the step's model_secs.
                let model_t0 = std::time::Instant::now();
                let (outcome, usage) = self.rt.model.borrow().decide_reported(&ctx);
                self.model_secs_step += model_t0.elapsed().as_secs_f64();
                // Context meter: the provider's usage block is
                // authoritative; the char/4 estimate fills in when the
                // endpoint omits it.
                self.used_tokens = usage.total_tokens;
                emit(Ev::ContextUsage {
                    used_tokens: usage.total_tokens,
                    limit_tokens: self.rt.context_tokens,
                    pct: self.usage_pct(),
                    estimated: usage.estimated,
                });
                match outcome {
                    Ok(d) => {
                        self.consecutive_errors = 0;
                        self.cm.set_last_error(None);
                        d
                    }
                    Err(ModelError::Transport(e)) | Err(ModelError::BadResponse(e)) => {
                        self.consecutive_errors += 1;
                        if self.consecutive_errors >= self.rt.max_consecutive_errors {
                            emit(Ev::Error {
                                message: format!(
                                    "model failed {} times in a row: {e}",
                                    self.consecutive_errors
                                ),
                            });
                            return DriveOutcome::TooManyModelErrors {
                                count: self.consecutive_errors,
                                last_error: e,
                            };
                        }
                        // Visible retry feedback: a timed-out call otherwise
                        // looks like the agent froze (minutes of silent
                        // waiting). Show a short cause + attempt count.
                        let brief: String = e.chars().take(80).collect();
                        emit(Ev::Status {
                            message: format!(
                                "model call failed ({brief}) — retrying {}/{}",
                                self.consecutive_errors, self.rt.max_consecutive_errors
                            ),
                        });
                        // Backoff before the same-step retry so we don't hammer
                        // the endpoint (exponential; cancellation-aware).
                        let backoff_ms = 500u64 * (1u64 << (self.consecutive_errors - 1));
                        for _ in 0..(backoff_ms / 50) {
                            if self.rt.handle.is_cancelled() {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        if self.rt.handle.is_cancelled() {
                            return DriveOutcome::Cancelled;
                        }
                        self.cm.set_last_error(Some(format!(
                            "{e} (retry {}/{}) after {backoff_ms}ms)",
                            self.consecutive_errors, self.rt.max_consecutive_errors
                        )));
                        continue; // same step retried with error surfaced to the model
                    }
                    Err(ModelError::MissingConfig(e)) => {
                        // Config errors never heal by retrying.
                        emit(Ev::Error { message: e.clone() });
                        return DriveOutcome::ConfigError(e);
                    }
                }
            };

            // Hand the accumulated LLM time to this decision's events,
            // then start the next step's accumulation from zero.
            let model_secs = std::mem::take(&mut self.model_secs_step);
            // Recalled vault values ride exactly ONE decision: they were
            // staged by a vault_recall on the previous step and served in
            // the view just consumed. Clear before executing.
            self.cm.clear_vault_values();

            match decision {
                Decision::Finish { reason } => {
                    return DriveOutcome::Finished(reason);
                }
                Decision::Reply { text } => {
                    // Autonomous runs have no user to answer: treat the
                    // reply as narration, count it as a step (so a
                    // reply-loop cannot spin forever) and keep driving.
                    if autonomous {
                        self.step += 1;
                        continue;
                    }
                    return DriveOutcome::Replied(text);
                }
                Decision::Narrate { text } => {
                    // A verbal update that does NOT end the turn: tell
                    // the user what was found, then keep working. Costs a
                    // step so a narrate-loop cannot spin forever. The
                    // text lands in the context too — otherwise the model
                    // cannot tell what the user already knows and
                    // re-announces the same finding after every tool.
                    self.cm.add_narration(&text);
                    emit(Ev::Narrated { text });
                    self.step += 1;
                }
                Decision::WebSearch { query, reason } => {
                    // Direct LLM tool (not a capability): the runtime
                    // executes the search itself and feeds the results
                    // back as observations. Reuses the tool-card events so
                    // UIs and session replay need no changes.
                    emit(Ev::CapabilityRequested {
                        capability: "web.search".into(),
                        target: query.clone(),
                        reason,
                        model_secs,
                    });
                    let t0 = std::time::Instant::now();
                    let results = super::web_search::search(
                        &query,
                        std::time::Duration::from_secs(20),
                    );
                    match results {
                        Ok(results) => {
                            let evidence = serde_json::json!({
                                "query": query,
                                "engine": "duckduckgo",
                                "result_count": results.len(),
                                "results": results.iter().map(|r| serde_json::json!({
                                    "title": r.title,
                                    "url": r.url,
                                    "snippet": r.snippet,
                                })).collect::<Vec<_>>(),
                            });
                            emit(Ev::ToolExecuted {
                                tool_id: "web-search".into(),
                                capability: "web.search".into(),
                                target: query.clone(),
                                exit_code: 0,
                                success: true,
                                timed_out: false,
                                output: serde_json::to_string(&evidence)
                                    .unwrap_or_default(),
                                tool_secs: t0.elapsed().as_secs_f64(),
                            });
                            let step = self.step;
                            if results.is_empty() {
                                let summary = format!(
                                    "web search for \"{query}\" returned no results"
                                );
                                self.cm.add_observation(
                                    &query, &summary, "web.search", step,
                                );
                                emit(Ev::ObservationAdded { summary });
                            } else {
                                for r in results.iter().take(8) {
                                    let mut summary =
                                        format!("web: {} — {}", r.title, r.url);
                                    if !r.snippet.is_empty() {
                                        let snip: String =
                                            r.snippet.chars().take(160).collect();
                                        summary.push_str(&format!(" · {snip}"));
                                    }
                                    self.cm.add_observation(
                                        &r.url, &summary, "web.search", step,
                                    );
                                    emit(Ev::ObservationAdded { summary });
                                }
                            }
                        }
                        Err(e) => {
                            let msg = format!("web search failed: {e}");
                            emit(Ev::ToolExecuted {
                                tool_id: "web-search".into(),
                                capability: "web.search".into(),
                                target: query.clone(),
                                exit_code: 1,
                                success: false,
                                timed_out: false,
                                output: msg.clone(),
                                tool_secs: t0.elapsed().as_secs_f64(),
                            });
                            self.cm.set_last_error(Some(msg));
                        }
                    }
                    self.step += 1;
                }
                Decision::CreateHypothesis {
                    statement,
                    confidence,
                } => {
                    // Event-only: the hypothesis is surfaced to the user
                    // (and persisted as a Think record). The model owns
                    // its reasoning; we do not rank or link it.
                    self.hypothesis_seq += 1;
                    emit(Ev::HypothesisAdded {
                        id: self.hypothesis_seq,
                        statement,
                        confidence,
                    });
                    self.step += 1;
                }
                Decision::FileRead {
                    path,
                    grep,
                    lines,
                    reason,
                } => {
                    self.run_file_read(
                        &path,
                        &grep,
                        &lines,
                        &reason,
                        model_secs,
                        &mut *emit,
                    );
                    self.step += 1;
                }
                Decision::FileWrite { path, content, reason } => {
                    self.run_file_write(&path, &content, &reason, model_secs, &mut *emit);
                    self.step += 1;
                }
                Decision::ReportFinding {
                    severity,
                    title,
                    target,
                    detail,
                } => {
                    // Model-reported registry entry: blank target means
                    // the assessment target in scope.
                    let tgt = if target.trim().is_empty() {
                        self.scope_label.clone()
                    } else {
                        target
                    };
                    let step = self.step;
                    let id =
                        self.cm
                            .add_finding(&severity, &title, &tgt, "model", &detail, step);
                    let status = self
                        .cm
                        .findings()
                        .iter()
                        .find(|f| f.id == id)
                        .map(|f| f.status.clone())
                        .unwrap_or_else(|| "open".into());
                    emit(Ev::FindingRecorded {
                        id,
                        severity,
                        title,
                        target: tgt,
                        status,
                        detail,
                        step,
                    });
                    self.step += 1;
                }
                Decision::UpdateFinding { id, status, note } => {
                    let step = self.step;
                    if self.cm.update_finding(id, &status, step) {
                        let (severity, title, target, detail) = self
                            .cm
                            .findings()
                            .iter()
                            .find(|f| f.id == id)
                            .map(|f| {
                                (
                                    f.severity.clone(),
                                    f.title.clone(),
                                    f.target.clone(),
                                    if note.trim().is_empty() {
                                        f.detail.clone()
                                    } else {
                                        note.clone()
                                    },
                                )
                            })
                            .unwrap_or_default();
                        emit(Ev::FindingRecorded {
                            id,
                            severity,
                            title,
                            target,
                            status,
                            detail,
                            step,
                        });
                    } else {
                        let known: Vec<String> = self
                            .cm
                            .findings()
                            .iter()
                            .map(|f| format!("F{}:{}", f.id, f.title))
                            .collect();
                        self.cm.set_last_error(Some(format!(
                            "no finding with id {id} (registry: {})",
                            if known.is_empty() {
                                "(empty — report findings with report_finding first)".to_string()
                            } else {
                                known.join(", ")
                            }
                        )));
                    }
                    self.step += 1;
                }
                Decision::VaultStore {
                    key,
                    value,
                    kind,
                    source,
                } => {
                    // Values never touch events/records/logs — the event
                    // carries the key only (see VaultStored).
                    let step = self.step;
                    match self.vault_mut() {
                        Err(e) => self.cm.set_last_error(Some(e)),
                        Ok(v) => match v.store(&key, &value, &kind, &source, step) {
                            Ok(refreshed) => {
                                let keys = v.key_lines();
                                let kind = kind.trim().to_string();
                                let key = key.trim().to_string();
                                self.cm.set_vault_keys(keys);
                                emit(Ev::VaultStored { key, kind, refreshed });
                            }
                            Err(e) => self.cm.set_last_error(Some(e)),
                        },
                    }
                    self.step += 1;
                }
                Decision::VaultRecall { query } => {
                    // The value is staged into the ContextManager (one
                    // decision only) — never into an event or record.
                    match self.vault_mut() {
                        Err(e) => self.cm.set_last_error(Some(e)),
                        Ok(v) => match v.recall(&query) {
                            Ok((key, value)) => {
                                let (key, value) =
                                    (key.to_string(), value.to_string());
                                self.cm.recall_vault_value(&key, &value);
                                emit(Ev::VaultRecalled { key });
                            }
                            Err(e) => self.cm.set_last_error(Some(e)),
                        },
                    }
                    self.step += 1;
                }
                Decision::Execute {
                    capability,
                    target: action_target,
                    options,
                    reason,
                } => {
                    emit(Ev::CapabilityRequested {
                        capability: capability.clone(),
                        target: action_target.clone(),
                        reason: reason.clone(),
                        model_secs,
                    });
                    let request = CapabilityRequest {
                        capability,
                        target: action_target,
                        options,
                        reason,
                    };
                    // Validation order is a security property: policy
                    // (capability exists → arguments valid → scope → risk)
                    // runs BEFORE provider selection, so no out-of-scope
                    // target can be executed regardless of provider.
                    match self.policy.validate(&request, self.rt.caps) {
                        Err(err) => {
                            let msg = err.to_string();
                            // High-risk requests become an approval REQUEST:
                            // the UI shows a dialog and the runtime blocks
                            // on the gate. Only a denial (or no gate /
                            // timeout) becomes rejection feedback. Emitting
                            // ActionRejected here made dialogs read
                            // "rejected: ..." before anything was rejected.
                            let needs_approval =
                                matches!(err, PolicyError::HighRiskRequiresApproval { .. })
                                    && !self.policy.allow_destructive.load(Ordering::SeqCst)
                                    && !self.approval_denied;
                            if needs_approval {
                                emit(Ev::ApprovalRequested {
                                    capability: request.capability.clone(),
                                    reason: msg,
                                });
                                match self.wait_for_approval() {
                                    ApprovalDecision::Allow => {
                                        self.approval_denied = false;
                                        // allow_destructive was latched with
                                        // the approval; the model's next
                                        // decision executes.
                                    }
                                    ApprovalDecision::Deny | ApprovalDecision::None => {
                                        // Deny (or no gate / timeout): the
                                        // model pivots. Don't block again.
                                        self.approval_denied = true;
                                        let feedback = format!(
                                            "high-risk capability `{}` requires approval that was not granted — pick a non-destructive capability, reply to the user, or finish",
                                            request.capability
                                        );
                                        emit(Ev::ActionRejected {
                                            reason: feedback.clone(),
                                        });
                                        self.cm.set_last_error(Some(feedback));
                                    }
                                }
                            } else {
                                // Feed the rejection back; the model
                                // self-corrects next iteration without
                                // consuming a step.
                                emit(Ev::ActionRejected {
                                    reason: msg.clone(),
                                });
                                self.cm.set_last_error(Some(msg));
                            }
                        }
                        Ok(()) => {
                            match self.rt.providers.select(
                                &request.capability,
                                &request.options,
                                &self.env,
                            ) {
                                Err(err) => {
                                    let msg = err.to_string();
                                    emit(Ev::ActionRejected {
                                        reason: msg.clone(),
                                    });
                                    self.cm.set_last_error(Some(msg));
                                }
                                Ok(provider) => {
                                    let provider_id = provider.id().to_string();
                                    emit(Ev::ProviderSelected {
                                        capability: request.capability.clone(),
                                        provider: provider_id.clone(),
                                    });
                                    let ctx = ExecutionContext {
                                        executor: executor.as_ref(),
                                        env: &self.env,
                                    };
                                    // Automatic retries for fast failures:
                                    // transient blips recover without the
                                    // model burning a step. Timeouts are
                                    // never retried (the budget is spent),
                                    // and neither are deterministic
                                    // connection refusals (service down or
                                    // wrong port — retrying burns budget).
                                    // Tool-phase wall time: all attempts
                                    // plus inter-attempt backoff. Excludes
                                    // LLM time and approval waits.
                                    let exec_t0 = std::time::Instant::now();
                                    let mut attempt = 0usize;
                                    let result = loop {
                                        attempt += 1;
                                        emit(Ev::ToolStarted {
                                            capability: request.capability.clone(),
                                            provider: provider_id.clone(),
                                        });
                                        let result = provider.execute(&request, &ctx);
                                        emit(Ev::ToolFinished {
                                            capability: request.capability.clone(),
                                            provider: provider_id.clone(),
                                        });
                                        if result.success()
                                            || result.timed_out
                                            || result.is_non_retryable()
                                            || attempt >= MAX_ATTEMPTS
                                        {
                                            break result;
                                        }
                                        // Cancellation-aware pause between attempts.
                                        for _ in 0..10 {
                                            if self.rt.handle.is_cancelled() {
                                                break;
                                            }
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                100,
                                            ));
                                        }
                                        if self.rt.handle.is_cancelled() {
                                            break result;
                                        }
                                    };
                                    let mut output_note = String::new();
                                    if !result.success() {
                                        // Failure reason must be visible: errors that
                                        // never reach stdout/stderr (provider guards,
                                        // internal providers) otherwise show as a bare
                                        // "failed (exit -1)" card with no explanation.
                                        if let Some(err) = &result.error {
                                            output_note
                                                .push_str(&format!("\n[medusa] error: {err}"));
                                        }
                                        if attempt > 1 {
                                            output_note.push_str(&format!(
                                                "\n[medusa] failed after {attempt} attempts"
                                            ));
                                        }
                                    }
                                    // Empty SUCCESS needs an explanation, or the
                                    // model (and user) can't tell a filter from
                                    // a dead target: annotate the card output
                                    // and record an observation the model sees.
                                    let empty_success = result.success()
                                        && result.combined_output().trim().is_empty();
                                    let option_list = request
                                        .options
                                        .iter()
                                        .map(|(k, v)| format!("{k}={v}"))
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    if empty_success {
                                        output_note = if !option_list.is_empty() {
                                            format!(
                                                "\n[medusa] completed successfully with no output — the applied filters ({option_list}) may have excluded all results; consider re-running without filters"
                                            )
                                        } else {
                                            format!(
                                                "\n[medusa] completed successfully with no output — the target may be unreachable or returned nothing"
                                            )
                                        };
                                    }
                                    emit(Ev::ToolExecuted {
                                        tool_id: result.tool_id.clone(),
                                        capability: result.capability.clone(),
                                        target: result.target.clone(),
                                        exit_code: result.exit_code,
                                        success: result.success(),
                                        timed_out: result.timed_out,
                                        output: format!(
                                            "{}{}",
                                            truncate_evidence(&result.combined_output()),
                                            output_note
                                        ),
                                        tool_secs: exec_t0.elapsed().as_secs_f64(),
                                    });
                                    // Raw evidence for the model: the
                                    // undistilled output rides the context
                                    // alongside the parsed observations.
                                    self.cm.add_evidence(
                                        &result.tool_id,
                                        &result.target,
                                        &result.combined_output(),
                                    );
                                    // Distill raw output into normalized
                                    // observations and feed BOTH stores — the
                                    // context manager for budgeted model
                                    // visibility, the world model for the
                                    // asset graph.
                                    if result.error.is_none() && !result.timed_out {
                                        let parsed = super::parsers::parse_tool_output(
                                            &result.tool_id,
                                            &result.combined_output(),
                                            &request.target,
                                        );
                                        for p in &parsed {
                                            let step = self.step;
                                            self.cm.add_observation(
                                                &p.target, &p.summary, &p.source, step,
                                            );
                                            emit(Ev::ObservationAdded {
                                                summary: p.summary.clone(),
                                            });
                                        }
                                        // The empty-success explanation as a
                                        // first-class observation: the model
                                        // sees WHY there is nothing instead of
                                        // guessing (and re-probing).
                                        if empty_success {
                                            let summary = if !option_list.is_empty() {
                                                format!(
                                                    "{} on {} completed with zero findings — filters ({}) excluded all results, output was empty (not a failure)",
                                                    result.tool_id, result.target, option_list
                                                )
                                            } else {
                                                format!(
                                                    "{} on {} completed with no output — the target may be unreachable or returns nothing (not a failure)",
                                                    result.tool_id, result.target
                                                )
                                            };
                                            let step = self.step;
                                            self.cm.add_observation(
                                                &result.target,
                                                &summary,
                                                &result.tool_id,
                                                step,
                                            );
                                            emit(Ev::ObservationAdded { summary });
                                        }
                                    }
                                    // Feed execution failures back so the model
                                    // can self-correct on the next step.
                                    if !result.success() {
                                        self.cm.set_last_error(Some(format!(
                                            "{} on {} failed: {}",
                                            result.tool_id,
                                            result.target,
                                            result.error.clone().unwrap_or_else(|| {
                                                format!("exit code {}", result.exit_code)
                                            })
                                        )));
                                    }
                                    // Honest completion: an exit-0 run can
                                    // still have tested nothing (sqlmap
                                    // "[CRITICAL] no parameter(s) found",
                                    // trivy "FATAL" on a URL target). Such
                                    // runs are recorded as INEFFECTIVE so
                                    // the planner keeps the unknown open
                                    // instead of declaring victory.
                                    let mut effective = result.success();
                                    if effective {
                                        if let Some(note) = execution_ineffective_note(&result) {
                                            effective = false;
                                            let summary = format!(
                                                "{} on {} ran but tested nothing — {}",
                                                result.tool_id, result.target, note
                                            );
                                            let step = self.step;
                                            self.cm.add_observation(
                                                &result.target,
                                                &summary,
                                                &result.tool_id,
                                                step,
                                            );
                                            self.cm.set_last_error(Some(summary.clone()));
                                            emit(Ev::ObservationAdded { summary });
                                        }
                                    }
                                    let step = self.step;
                                    self.cm.add_action(
                                        step,
                                        request.capability.clone(),
                                        provider_id,
                                        request.target.clone(),
                                        request.reason.clone(),
                                        effective,
                                    );
                                    self.tool_results.push(result);
                                    self.step += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Consume the session into the headless result shape (CLI/tests).
    fn into_result(mut self, target: Target, finish_reason: FinishReason) -> InvestigationResult {
        let model_error = match &finish_reason {
            FinishReason::TooManyModelErrors { last_error, .. } => Some(last_error.clone()),
            _ => None,
        };
        InvestigationResult {
            target,
            steps_taken: self.step,
            planned_actions: self
                .cm
                .actions()
                .iter()
                .map(|a| PlannedAction {
                    step: a.step,
                    capability: a.capability.clone(),
                    provider: a.provider.clone(),
                    target: a.target.clone(),
                    reason: a.reason.clone(),
                })
                .collect(),
            tool_results: std::mem::take(&mut self.tool_results),
            finish_reason,
            model_error,
        }
    }
}

/// Extract host-like tokens from free user text. Deliberately
/// conservative: only URLs, dotted domains with a plausible last label,
/// and IPv4 literals. WE control this — the model never grants scope.
fn hosts_in(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in message.split_whitespace() {
        let tok = tok
            .trim_matches(|c: char| c.is_ascii_punctuation() && c != '.' && c != ':' && c != '-');
        let tok = tok.trim_matches(|c: char| c.is_ascii_punctuation());
        if tok.is_empty() {
            continue;
        }
        // URL: strip to host.
        if tok.starts_with("http://") || tok.starts_with("https://") {
            let host = super::policy::host_of(tok);
            if is_grantable_host(&host) && !out.contains(&host) {
                out.push(host);
            }
            continue;
        }
        // Strip an explicit :port before host matching — "localhost:3000",
        // "127.0.0.1:8080", "example.com:8080" are host mentions too.
        // (Port must be all digits so "12:30" times and "::1" literals
        // are left alone.)
        let bare = match tok.split_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => tok,
        };
        // IPv4 literal.
        if is_ipv4(bare) && !out.contains(&bare.to_string()) {
            out.push(bare.to_string());
            continue;
        }
        // localhost — dotless but an explicit, unambiguous host.
        if bare.eq_ignore_ascii_case("localhost") && !out.contains(&"localhost".to_string()) {
            out.push("localhost".to_string());
            continue;
        }
        // Dotted domain: labels of alnum/hyphen, last label ≥ 2 alpha.
        if is_plausible_host(bare) && bare.contains('.') && !out.contains(&bare.to_string()) {
            out.push(bare.to_string());
        }
    }
    out
}

/// Hosts that may be granted scope from a user mention. `localhost` is
/// dotless and IPv4 literals fail the domain-shape check, so both are
/// accepted explicitly — "http://127.0.0.1:3000/" is a host mention.
fn is_grantable_host(s: &str) -> bool {
    is_plausible_host(s) || is_ipv4(s) || s.eq_ignore_ascii_case("localhost")
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn is_plausible_host(s: &str) -> bool {
    if s.len() > 253 || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    }) && labels
        .last()
        .is_some_and(|l| l.len() >= 2 && l.chars().all(|c| c.is_ascii_alphabetic()))
}

/// Cap raw evidence carried in `ToolExecuted` events. UIs show the head of
/// the output; full output stays in the `ToolResult` for parsing.
fn truncate_evidence(raw: &str) -> String {
    const CAP: usize = 12_000;
    if raw.len() <= CAP {
        raw.to_string()
    } else {
        // Cut on a char boundary to avoid slicing mid-UTF-8.
        let mut end = CAP;
        while end > 0 && !raw.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\n… [truncated {} bytes]", &raw[..end], raw.len() - end)
    }
}

/// Marker sniffing for exit-0 runs that did no useful work. sqlmap exits
/// 0 while printing "[CRITICAL] no parameter(s) found"; trivy prints
/// "FATAL" (stderr) and exits non-zero (already a failure). Only called
/// for nominally successful runs.
fn execution_ineffective_note(result: &super::executor::ToolResult) -> Option<&'static str> {
    if result.combined_output().contains("[CRITICAL]") {
        return Some(
            "the tool reported a CRITICAL condition, e.g. sqlmap without testable parameters — re-run against the full endpoint URL with `data` for parameters",
        );
    }
    if result.stderr.contains("FATAL") {
        return Some("the tool hit a FATAL error — this invocation cannot apply to the target (e.g. a filesystem scanner pointed at a URL)");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::model::StubProvider;
    use crate::agent::model::{OptionSet, OptionValue};
    use crate::model::ToolStatus;
    use std::collections::HashMap;

    fn harness(installed: &[&str]) -> (ToolRegistry, CapabilityRegistry, EnvironmentState) {
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let mut state = EnvironmentState::empty();
        state.tools = tools
            .all()
            .iter()
            .map(|t| {
                let up = installed.contains(&t.id.as_str());
                (
                    t.id.clone(),
                    ToolStatus {
                        tool_id: t.id.clone(),
                        installed: up,
                        executable_path: up.then(|| format!("/bin/{}", t.id)),
                        version: up.then(|| "1.0".into()),
                        platform: "linux".into(),
                        arch: "x64".into(),
                        healthy: up,
                        adapter_available: false,
                        capabilities: if up { t.capabilities.clone() } else { vec![] },
                        missing_dependencies: vec![],
                        diagnostic: String::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        // Capability snapshots must exist for available/unavailable queries.
        let tools_by_id = tools
            .all()
            .iter()
            .map(|t| (t.id.clone(), t.clone()))
            .collect::<HashMap<_, _>>();
        state.capabilities =
            crate::core::discovery::derive_capabilities(&state.tools, &tools_by_id, &caps);
        (tools, caps, state)
    }

    #[test]
    fn loop_resolves_execute_hypothesis_finish() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "open ports unknown".into(),
            },
            Decision::CreateHypothesis {
                statement: "SSH may be exposed".into(),
                confidence: "low".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        assert_eq!(res.steps_taken, 2);
        assert_eq!(res.planned_actions.len(), 1);
        assert_eq!(res.planned_actions[0].provider, "nmap");
    }

    #[test]
    fn file_write_then_file_read_roundtrips_confined() {
        let (tools, caps, state) = harness(&[]);
        // Point the work root at a temp dir so the test never touches the
        // real medusa state dir.
        let workroot = std::env::temp_dir().join(format!(
            "medusa-file-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workroot).unwrap();
        std::env::set_var("MEDUSA_WORK_ROOT", &workroot);
        // Stub: write, then read the same file, then reply.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::FileWrite {
                path: "poc.txt".into(),
                content: "FORGED-JWT".into(),
                reason: "write a proof".into(),
            },
            Decision::FileRead {
                path: "poc.txt".into(),
                grep: Some("FORGED".into()),
                lines: None,
                reason: "verify the write".into(),
            },
            Decision::Reply {
                text: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("127.0.0.1"));
        // Confined path: %TEMP%/.../work/127.0.0.1/poc.txt — NOT in the cwd.
        let confined = workroot.join("127.0.0.1").join("poc.txt");
        assert_eq!(
            std::fs::read_to_string(&confined).unwrap(),
            "FORGED-JWT"
        );
        // Reaching this far means the read happened (Stub drives on).
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        // Cleanup.
        let _ = std::fs::remove_dir_all(&workroot);
        std::env::remove_var("MEDUSA_WORK_ROOT");
    }

    #[test]
    fn policy_rejection_is_fed_back_without_consuming_steps() {
        let (tools, caps, state) = harness(&[]); // nothing installed
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![Decision::Execute {
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "try anyway".into(),
        }]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        // Rejected (no provider), stub exhausts, finishes. No steps consumed.
        assert_eq!(res.planned_actions.len(), 0);
        assert_eq!(res.steps_taken, 0);
    }

    #[test]
    fn session_reply_ends_turn_and_persists_conversation() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![Decision::Reply {
            text: "Ready when you are.".into(),
        }]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let out = sess.run_turn("hello there", &mut |ev| seen.push(ev));
        assert!(matches!(out, DriveOutcome::Replied(t) if t == "Ready when you are."));
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::Reply { text } if text == "Ready when you are."
        )));
        // The user message is in the conversation even though no scope was
        // granted (no host-like token in "hello there").
        assert!(seen
            .iter()
            .all(|e| !matches!(e, AgentEvent::ScopeGranted { .. })));
    }

    #[test]
    fn session_grants_scope_only_from_user_mentions() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            // First tries a target the user NEVER mentioned → rejected.
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "evil.example.net".into(),
                options: OptionSet::new(),
                reason: "not mentioned".into(),
            },
            // Then the mentioned one → executes.
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "scanme.example.com".into(),
                options: OptionSet::new(),
                reason: "user asked".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        let out = sess.run_turn("please assess scanme.example.com when you can", &mut |ev| {
            seen.push(ev)
        });
        assert!(matches!(out, DriveOutcome::Finished(_)));
        // Scope granted exactly for the mentioned host.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ScopeGranted { target } if target == "scanme.example.com"
        )));
        // The unmentioned target was rejected by policy before execution.
        assert!(seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ActionRejected { reason } if reason.contains("outside assessment scope"))));
        // And the mentioned one actually ran (stub executor not wired, so
        // provider executes via LocalProcessExecutor on /bin/nmap — which
        // does not exist; what matters here is that it was NOT scope-
        // rejected: no second rejection event).
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ActionRejected { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn autonomous_mode_treats_reply_as_step_and_continues() {
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Reply {
                text: "narration".into(),
            },
            Decision::Finish {
                reason: "wrapped up".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        // The reply did not terminate the autonomous run.
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(r) if r == "wrapped up"));
        assert_eq!(res.steps_taken, 1);
    }

    #[test]
    fn max_steps_bounds_the_loop() {
        let (tools, caps, state) = harness(&["nmap"]);
        // Infinite script of hypotheses; runtime must stop anyway.
        struct Infinite;
        impl ModelProvider for Infinite {
            fn name(&self) -> &str {
                "infinite"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::CreateHypothesis {
                    statement: "more".into(),
                    confidence: "low".into(),
                })
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("more".to_string())
            }
        }
        let rt = AgentRuntime::new(Box::new(Infinite), &tools, &caps, &state).with_max_steps(5);
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::MaxSteps(5)));
        assert_eq!(res.steps_taken, 5);
    }

    #[test]
    fn interactive_turn_after_max_steps_continues_from_the_same_session() {
        // The actor model keeps ONE AgentSession across messages. The first
        // turn burns the per-turn budget (MaxSteps) but must NOT reset
        // step/context: a "continue" turn drives forward from step 25 with
        // a fresh budget of 25 more, so an investigation split across
        // turns is genuinely resumed rather than restarted.
        let (tools, caps, state) = harness(&["nmap"]);
        struct Infinite;
        impl ModelProvider for Infinite {
            fn name(&self) -> &str {
                "infinite"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::CreateHypothesis {
                    statement: "more".into(),
                    confidence: "low".into(),
                })
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("more".to_string())
            }
        }
        let rt = AgentRuntime::new(Box::new(Infinite), &tools, &caps, &state).with_max_steps(5);
        let mut sess = rt.session();
        // First turn: hits the 5-step budget on-turn.
        let out1 = sess.run_turn("assess scanme.example.com", &mut |_| {});
        assert!(matches!(out1, DriveOutcome::MaxSteps(5)));

        // A "continue" turn must advance budget (turn_start_step)
        // WITHOUT resetting the environment/scope. With an infinite script
        // it reaches a second MaxSteps — proof it ran MORE steps, i.e. it
        // really continued.
        let out2 = sess.run_turn("continue", &mut |_| {});
        assert!(
            matches!(out2, DriveOutcome::MaxSteps(5)),
            "second turn must run another budget of steps, got {out2:?}"
        );
        assert_eq!(sess.step, 10, "continue must not reset the step counter");
        // Scope survived across turns.
        assert!(sess
            .policy
            .scope_roots()
            .contains(&"scanme.example.com".to_string()));
    }

    #[test]
    fn cancellation_stops_mid_investigation() {
        let (tools, caps, state) = harness(&["nmap"]);
        struct Infinite;
        impl ModelProvider for Infinite {
            fn name(&self) -> &str {
                "infinite"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                Ok(Decision::CreateHypothesis {
                    statement: "more".into(),
                    confidence: "low".into(),
                })
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("more".to_string())
            }
        }
        let rt = AgentRuntime::new(Box::new(Infinite), &tools, &caps, &state);
        rt.handle().cancel(); // cancel before starting
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::Cancelled));
        assert_eq!(res.steps_taken, 0);
    }

    #[test]
    fn stop_applies_to_the_turn_in_flight_only() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        // Regression: one Stop latched the shared handle forever, so
        // every later turn insta-cancelled at the top of the drive loop
        // (session looks alive — messages recorded — but never acts).
        // The provider below cancels mid-turn, exactly like a user
        // pressing Stop while the agent works.
        struct CancelMidTurn {
            handle: RuntimeHandle,
            first: std::sync::atomic::AtomicBool,
        }
        impl ModelProvider for CancelMidTurn {
            fn name(&self) -> &str {
                "cancel-mid-turn"
            }
            fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
                if self
                    .first
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    self.handle.cancel();
                    Ok(Decision::Narrate {
                        text: "working".into(),
                    })
                } else {
                    Ok(Decision::Reply {
                        text: "alive".into(),
                    })
                }
            }
            fn chat(&self, _system: &str, _user: &str) -> Result<String, ModelError> {
                Ok("chat".into())
            }
        }
        let (tools, caps, state) = harness(&[]);
        let handle = RuntimeHandle::default();
        let model: Box<dyn ModelProvider> = Box::new(CancelMidTurn {
            handle: handle.clone(),
            first: std::sync::atomic::AtomicBool::new(true),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_handle(handle);
        let mut sess = rt.session();
        let seen = RefCell::new(Vec::new());
        let outcome = sess.run_turn("go", &mut |ev| {
            seen.borrow_mut().push(ev);
        });
        // The turn did real work (a narration) before the Stop landed.
        assert!(seen.borrow().iter().any(|e| matches!(
            e,
            AgentEvent::Narrated { .. }
        )));
        assert!(
            matches!(outcome, DriveOutcome::Cancelled),
            "mid-turn Stop still aborts the turn, got: {outcome:?}"
        );
        // The next turn starts fresh: the latch does not leak across
        // the turn boundary.
        let outcome = sess.run_turn("are you there?", &mut |_| {});
        assert!(
            matches!(outcome, DriveOutcome::Replied(_)),
            "got: {outcome:?}"
        );
    }

    /// Fails the first `fails` executions of `exe`, then succeeds.
    struct FlakyExecutor {
        exe: &'static str,
        fails: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FlakyExecutor {
        fn new(exe: &'static str, fails: usize) -> Self {
            Self {
                exe,
                fails: std::sync::atomic::AtomicUsize::new(fails),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn total_calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProcessExecutor for FlakyExecutor {
        fn run(
            &self,
            exe: &str,
            _args: &[String],
            _timeout: std::time::Duration,
        ) -> crate::agent::executor::ProcessOutput {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if exe.contains(self.exe)
                && self
                    .fails
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |n| if n == 0 { None } else { Some(n - 1) },
                    )
                    .is_ok()
            {
                crate::agent::executor::ProcessOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "transient blip".into(),
                    timed_out: false,
                    error: None,
                }
            } else {
                crate::agent::executor::ProcessOutput {
                    exit_code: 0,
                    stdout: "port 80 open".into(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                }
            }
        }
    }

    #[test]
    fn transient_failure_is_retried_automatically() {
        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "one decision".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 1));
        let rt = rt.with_executor(flaky.clone());
        let res = rt.investigate(Target::new("10.0.0.1"));
        // One decision, two executions (1 fail + 1 success), step consumed,
        // action recorded, no disable.
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        assert_eq!(flaky.total_calls(), 2);
        assert_eq!(res.steps_taken, 1);
        assert_eq!(res.planned_actions.len(), 1);
    }

    #[test]
    fn narrate_updates_user_without_ending_the_turn() {
        let (tools, caps, state) = harness(&["httpx"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "http.probe".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "probe".into(),
            },
            Decision::Narrate {
                text: "Found exposed admin configuration endpoint.".into(),
            },
            Decision::Execute {
                capability: "http.probe".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "keep going".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(Arc::new(
            crate::agent::executor::StubExecutor::success("httpx", "up"),
        ));
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        // The narration reached the user as an event...
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::Narrated { text } if text.starts_with("Found exposed admin")
        )));
        // ...AND the model's own context: the next decision sees what was
        // already reported, so it cannot re-announce the same finding.
        let view = rt.context_view(&sess.env, &Target::new("10.0.0.1"), sess.step, &sess.cm);
        assert!(view
            .narrations
            .iter()
            .any(|n| n.starts_with("Found exposed admin")));
        // The turn did NOT end at the narration: both executes ran.
        assert_eq!(sess.cm.actions().len(), 2);
    }

    #[test]
    fn high_risk_approval_gate_allows_after_user_consent() {
        use crate::agent::executor::StubExecutor;
        // web.vulnerability_scan is gated by the Destructive
        // web.rce_chain_validation test: without approval it is rejected.
        let (tools, caps, state) = harness(&["nuclei"]);
        let exec = || Decision::Execute {
            capability: "web.vulnerability_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "scan it".into(),
        };
        // First Execute is rejected (dialog), second is the model's retry.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            exec(),
            exec(),
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(Arc::new(
            StubExecutor::success("nuclei", "{\"findings\":[]}"),
        ));
        // The user's dialog answer, already waiting when the runtime blocks.
        let gate = Arc::new(std::sync::Mutex::new(Some(true)));
        let rt = rt.with_approval_gate(gate);
        let mut seen: Vec<AgentEvent> = Vec::new();
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| seen.push(ev));
        // The high-risk block is an approval REQUEST (dialog), not a
        // rejection; the gate's approval latched the flag and the retry
        // executed.
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ApprovalRequested { .. }))
                .count(),
            1
        );
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ActionRejected { .. }))
                .count(),
            0
        );
        assert_eq!(res.planned_actions.len(), 1);
        assert_eq!(res.planned_actions[0].provider, "nuclei");
    }

    #[test]
    fn high_risk_denial_does_not_block_the_loop() {
        use crate::agent::executor::StubExecutor;
        let (tools, caps, state) = harness(&["nuclei"]);
        let exec = || Decision::Execute {
            capability: "web.vulnerability_scan".into(),
            target: "10.0.0.1".into(),
            options: OptionSet::new(),
            reason: "try again".into(),
        };
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            exec(),
            exec(),
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nuclei", "{}")));
        // User denied: the first rejection consumes the denial, the second
        // must NOT block again (no gate decision pending) — the run
        // terminates instead of deadlocking.
        let gate = Arc::new(std::sync::Mutex::new(Some(false)));
        let rt = rt.with_approval_gate(gate);
        let mut seen: Vec<AgentEvent> = Vec::new();
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| seen.push(ev));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
        // One approval request (dialog trigger), then the denial feedback
        // and the un-gated second attempt's rejection.
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ApprovalRequested { .. }))
                .count(),
            1
        );
        assert_eq!(
            seen.iter()
                .filter(|e| matches!(e, AgentEvent::ActionRejected { .. }))
                .count(),
            2
        );
        assert_eq!(res.planned_actions.len(), 0);
    }

    #[test]
    fn empty_success_with_filters_explains_itself() {
        use crate::agent::executor::StubExecutor;
        use crate::agent::model::{OptionSet, OptionValue};
        let (tools, caps, state) = harness(&["nuclei"]);
        let mut options = OptionSet::new();
        options.insert("severity".into(), OptionValue::Str("high".into()));
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "web.vulnerability_scan".into(),
                target: "10.0.0.1".into(),
                options,
                reason: "filtered scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nuclei", "")))
            // web.vulnerability_scan is high-risk gated: pre-approve so this
            // test exercises the empty-output path, not the approval gate.
            .with_approval_flag(Arc::new(AtomicBool::new(true)));
        let mut seen: Vec<AgentEvent> = Vec::new();
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| seen.push(ev));
        // Executed fine, but with empty output and a filter applied...
        assert_eq!(res.planned_actions.len(), 1);
        let executed = seen.iter().find_map(|e| match e {
            AgentEvent::ToolExecuted { output, .. } => Some(output.clone()),
            _ => None,
        });
        // ...the card output explains the filter (not "no output" silence)...
        assert!(executed
            .as_deref()
            .is_some_and(|o| o.contains("filters (severity=high) may have excluded all results")));
        // ...and the model's context gets an observation saying the same.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ObservationAdded { summary }
                if summary.contains("filters (severity=high) excluded all results")
        )));
    }

    #[test]
    fn argv_guarded_tools_are_not_advertised_as_available() {
        // ghidra is "installed and healthy" in the env, but its argv is
        // empty on purpose (headless needs a two-step workflow), so every
        // provider of binary.analysis is structurally unusable — the
        // capability must not be advertised. zap, by contrast, now has a
        // real headless argv (-cmd -quickurl) and IS advertised.
        let (tools, caps, state) = harness(&["ghidra", "zap", "nuclei"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let sess = rt.session();
        let target = Target::new("example.com");
        let view = rt.context_view(&sess.env, &target, sess.step, &sess.cm);
        assert!(!view
            .available_capabilities
            .contains(&"binary.analysis".to_string()));
        assert!(!view
            .capability_schemas
            .iter()
            .any(|s| s.starts_with("binary.analysis")));
        assert!(view
            .available_capabilities
            .contains(&"web.dynamic_testing".to_string()));
        // nuclei still covers vulnerability_scan.
        assert!(view
            .available_capabilities
            .contains(&"web.vulnerability_scan".to_string()));
    }

    #[test]
    fn localhost_and_host_port_mentions_grant_scope() {
        // localhost in all three shapes is a host mention.
        assert_eq!(hosts_in("assess localhost"), vec!["localhost".to_string()]);
        assert_eq!(
            hosts_in("probe localhost:3000"),
            vec!["localhost".to_string()]
        );
        assert_eq!(
            hosts_in("scan http://localhost:3000/"),
            vec!["localhost".to_string()]
        );
        // host:port for IPs and domains too (port must not leak into the
        // granted root).
        assert_eq!(
            hosts_in("hit 127.0.0.1:8080"),
            vec!["127.0.0.1".to_string()]
        );
        assert_eq!(
            hosts_in("test example.com:8080"),
            vec!["example.com".to_string()]
        );
        // URL-wrapped IPv4 is a host mention as well.
        assert_eq!(
            hosts_in("assess http://127.0.0.1:3000/"),
            vec!["127.0.0.1".to_string()]
        );
        // Ordinary words and time-like tokens still grant nothing.
        assert!(hosts_in("run this tool again now").is_empty());
        assert!(hosts_in("meet at 12:30 sharp").is_empty());
    }

    #[test]
    fn loopback_forms_are_interchangeable_in_scope() {
        use crate::agent::policy::ScopePolicy;
        // The user mentions one loopback form; the model targets another.
        let mut scope = ScopePolicy::empty();
        assert!(scope.grant("localhost"));
        assert!(scope.is_in_scope("http://127.0.0.1:3000/"));
        assert!(scope.is_in_scope("http://[::1]:3000/"));
        assert!(!scope.is_in_scope("http://example.com/"));
        // And the reverse direction.
        let mut scope = ScopePolicy::empty();
        assert!(scope.grant("127.0.0.1"));
        assert!(scope.is_in_scope("localhost:3000"));
        assert!(!scope.is_in_scope("example.com"));
    }

    #[test]
    fn rehydrate_restores_scope_conversation_and_observations() {
        use crate::infra::sessions::{SessionRecord, TimedRecord};
        let (tools, caps, state) = harness(&["nuclei"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let mut sess = rt.session();
        let records = vec![
            TimedRecord {
                time: 1,
                record: SessionRecord::Target {
                    target: "owasp.org".into(),
                },
            },
            TimedRecord {
                time: 2,
                record: SessionRecord::Chat {
                    user: "assess owasp.org".into(),
                    agent: "starting recon".into(),
                    user_time: 0,
                },
            },
            TimedRecord {
                time: 3,
                record: SessionRecord::Obs {
                    text: "nuclei on owasp.org completed with zero findings".into(),
                },
            },
        ];
        sess.rehydrate(&records);
        // Scope root and label restored - the model can target it again.
        assert!(sess.policy.scope_roots().contains(&"owasp.org".to_string()));
        assert_eq!(sess.scope_label, "owasp.org");
        // Conversation and observations are visible in the next view.
        let target = Target::new(&sess.scope_label);
        let view = rt.context_view(&sess.env, &target, sess.step, &sess.cm);
        assert_eq!(view.conversation.len(), 1);
        assert_eq!(view.conversation[0].user, "assess owasp.org");
        assert!(view
            .observations
            .iter()
            .any(|o| o.contains("zero findings")));
        // Idempotent: replaying the same file changes nothing.
        sess.rehydrate(&records);
        assert_eq!(sess.policy.scope_roots().len(), 1);
        let view = rt.context_view(&sess.env, &target, sess.step, &sess.cm);
        assert_eq!(view.conversation.len(), 1);
    }

    #[test]
    fn tool_is_never_disabled_across_repeated_failures() {
        // Tools are never removed from the model. Repeated failure feeds
        // the model (last_error + the observations), and a later attempt
        // against a now-healthy target still executes — the model's full
        // hindsight (prior_actions) prevents the retry loop, not a breaker.
        let (tools, caps, state) = harness(&["nmap"]);
        // Fail the first 3 executions (1 decision x 3 retries), then let
        // the 4th decision succeed.
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 1 - fails 3x".into(),
            },
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "attempt 2 - now succeeds".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let flaky = Arc::new(FlakyExecutor::new("nmap", 3));
        let rt = rt.with_executor(flaky.clone());
        let mut sess = rt.session();
        let mut seen: Vec<AgentEvent> = Vec::new();
        sess.run_turn("assess 10.0.0.1", &mut |ev| seen.push(ev));
        // The second decision executed the tool successfully — nothing
        // disabled it for the first decision's failures.
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::ToolExecuted { tool_id, success, .. } if tool_id == "nmap" && *success
        )));
        // No "disabled" notices of any kind were emitted.
        assert!(!seen
            .iter()
            .any(|e| matches!(e, AgentEvent::Error { message } if message.contains("disabled") || message.contains("disabled for"))));
    }

    #[test]
    fn runtime_builds_views_through_context_manager() {
        use std::sync::{Arc, Mutex};

        // Records every ContextView the model receives, then delegates to
        // the scripted stub. Shares the log via Arc<Mutex> (provider is Send).
        struct Capturing {
            inner: StubProvider,
            views: Arc<Mutex<Vec<ContextView>>>,
        }
        impl ModelProvider for Capturing {
            fn name(&self) -> &str {
                "capturing"
            }
            fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
                self.views.lock().unwrap().push(ctx.clone());
                self.inner.decide(ctx)
            }
            fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
                self.inner.chat(system, user)
            }
        }

        let (tools, caps, state) = harness(&["nmap"]);
        let views: Arc<Mutex<Vec<ContextView>>> = Arc::new(Mutex::new(Vec::new()));
        let model = Capturing {
            inner: StubProvider::new(vec![
                Decision::Execute {
                    capability: "network.port_scan".into(),
                    target: "10.0.0.1".into(),
                    options: OptionSet::new(),
                    reason: "ports unknown".into(),
                },
                Decision::CreateHypothesis {
                    statement: "SSH exposed".into(),
                    confidence: "low".into(),
                },
                Decision::Finish {
                    reason: "enough for the test".into(),
                },
            ]),
            views: views.clone(),
        };
        let rt = AgentRuntime::new(Box::new(model), &tools, &caps, &state);
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));

        let seen = views.lock().unwrap().clone();
        assert_eq!(
            seen.len(),
            3,
            "one view per model call (execute, hypothesis, finish)"
        );

        // Step 0: empty memory, capabilities visible.
        assert!(seen[0].prior_actions.is_empty());
        assert!(seen[0].observations.is_empty()); // parsers arrive in Phase 5
        assert!(seen[0]
            .available_capabilities
            .contains(&"network.port_scan".to_string()));

        // Step 1: the execute decision is in memory.
        assert_eq!(seen[1].prior_actions.len(), 1);
        assert_eq!(
            seen[1].prior_actions[0],
            "network.port_scan on 10.0.0.1 via nmap"
        );
    }

    #[test]
    fn parsed_output_flows_to_model_and_events() {
        use crate::agent::events::AgentEvent;
        use crate::agent::executor::StubExecutor;
        use std::cell::RefCell;

        // nmap XML fixture — what `-oX -` writes to stdout.
        let nmap_xml = "<?xml version=\"1.0\"?>\
<nmaprun scanner=\"nmap\"><host><status state=\"up\"/>\
<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/><hostnames><hostname name=\"web01\" type=\"PTR\"/></hostnames>\
<ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/>\
<service name=\"ssh\" product=\"OpenSSH\" version=\"8.9p1\"/></port>\
<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
<service name=\"http\" product=\"nginx\" version=\"1.24.0\"/></port></ports></host></nmaprun>";

        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.service_detection".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "identify services".into(),
            },
            Decision::CreateHypothesis {
                statement: "outdated SSH may be exploitable".into(),
                confidence: "low".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nmap", nmap_xml)));
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = seen.into_inner();

        // Observations reached the event stream.
        let obs_events: Vec<_> = seen
            .iter()
            .filter_map(|e| match e {
                AgentEvent::ObservationAdded { summary } => Some(summary.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(obs_events.len(), 3, "hostname + 2 ports");
        assert!(obs_events
            .iter()
            .any(|s| s.contains("port 22/tcp open (ssh)")));
        assert!(obs_events.iter().any(|s| s.contains("nginx 1.24.0")));

        // One tool result recorded, executed successfully.
        assert_eq!(res.tool_results.len(), 1);
        assert!(res.tool_results[0].success());
        assert_eq!(res.tool_results[0].tool_id, "nmap");
    }

    #[test]
    fn full_loop_surfaces_unknowns_and_suggestions_to_the_model() {
        use crate::agent::executor::StubExecutor;
        use std::sync::{Arc, Mutex};

        // nmap output discovering an http port → world gets a host+port →
        // Phase 6 derives the http-probe unknown → Phase 8 suggests the
        // probe test. All of it must be visible in the model's next view.
        let nmap_xml = "<nmaprun><host><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>\
<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>\
<service name=\"http\" product=\"nginx\" version=\"1.24.0\"/></port></ports></host></nmaprun>";

        struct Capturing {
            inner: StubProvider,
            views: Arc<Mutex<Vec<ContextView>>>,
        }
        impl ModelProvider for Capturing {
            fn name(&self) -> &str {
                "capturing"
            }
            fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
                self.views.lock().unwrap().push(ctx.clone());
                self.inner.decide(ctx)
            }
            fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
                self.inner.chat(system, user)
            }
        }

        let (tools, caps, state) = harness(&["nmap", "httpx", "nuclei"]);
        let views: Arc<Mutex<Vec<ContextView>>> = Arc::new(Mutex::new(Vec::new()));
        let model = Capturing {
            inner: StubProvider::new(vec![
                Decision::Execute {
                    capability: "network.service_detection".into(),
                    target: "10.0.0.1".into(),
                    options: OptionSet::new(),
                    reason: "identify services".into(),
                },
                Decision::Finish {
                    reason: "loop verified".into(),
                },
            ]),
            views: views.clone(),
        };
        let rt = AgentRuntime::new(Box::new(model), &tools, &caps, &state)
            .with_executor(Arc::new(StubExecutor::success("nmap", nmap_xml)));
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));

        let seen = views.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);

        // After the nmap result was parsed:
        let step1 = &seen[1];
        assert!(
            step1
                .observations
                .iter()
                .any(|o| o.contains("nginx 1.24.0")),
            "parsed observation visible: {:?}",
            step1.observations
        );
    }

    #[test]
    fn events_fire_in_loop_order_including_rejection() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["nmap"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "r".into(),
            },
            Decision::Execute {
                capability: "cloud.posture_audit".into(), // no provider installed
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "mistake".into(),
            },
            Decision::CreateHypothesis {
                statement: "h".into(),
                confidence: "low".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = seen.into_inner();

        assert!(matches!(seen[0], AgentEvent::InvestigationStarted { .. }));
        assert!(seen.contains(&AgentEvent::StepStarted { step: 0 }));
        assert!(seen.iter().any(|e| matches!(e,
            AgentEvent::CapabilityRequested { capability, target, reason, model_secs, .. }
                if capability == "network.port_scan"
                    && target == "10.0.0.1"
                    && reason == "r"
                    && *model_secs >= 0.0
        )));
        assert!(seen.contains(&AgentEvent::ProviderSelected {
            capability: "network.port_scan".into(),
            provider: "nmap".into(),
        }));
        assert!(seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ActionRejected { .. })));
        assert!(seen.contains(&AgentEvent::HypothesisAdded {
            id: 1,
            statement: "h".into(),
            confidence: "low".into(),
        }));
        assert!(matches!(seen.last(), Some(AgentEvent::Finished { .. })));
        // Rejection consumed no step: 1 execute + 1 hypothesis.
        assert_eq!(res.steps_taken, 2);
    }

    #[test]
    fn out_of_scope_targets_are_rejected_before_execution() {
        // The itsecgames/mmebvba case: a co-hosted site discovered during
        // the investigation must NOT become an active assessment target.
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["httpx"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "http.probe".into(),
                target: "http://mmebvba.com/".into(), // discovered, not declared
                options: OptionSet::new(),
                reason: "probe the co-hosted site".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("www.itsecgames.com"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = seen.into_inner();

        // Rejected with a distinct scope message…
        let rejection = seen
            .iter()
            .find_map(|e| match e {
                AgentEvent::ActionRejected { reason } => Some(reason.clone()),
                _ => None,
            })
            .expect("scope violation must be rejected");
        assert!(
            rejection.contains("outside assessment scope"),
            "got: {rejection}"
        );
        // …before any provider was selected or tool executed.
        assert!(!seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ProviderSelected { .. })));
        assert!(!seen
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolExecuted { .. })));
        assert_eq!(res.tool_results.len(), 0);
        assert_eq!(res.steps_taken, 0);
        // In-scope subdomain paths remain executable (sanity).
        let model2: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "http.probe".into(),
                target: "http://www.itsecgames.com/bWAPP/".into(),
                options: OptionSet::new(),
                reason: "probe in-scope path".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt2 = AgentRuntime::new(model2, &tools, &caps, &state);
        let res2 = rt2.investigate(Target::new("www.itsecgames.com"));
        assert_eq!(res2.tool_results.len(), 1, "in-scope path must execute");
    }

    #[test]
    fn options_flow_through_translation_into_provider_argv() {
        // Semantic options from the model become provider flags via the
        // trusted binding table — never raw model input in argv.
        use crate::agent::executor::{ProcessOutput, RecordingExecutor};

        let (tools, caps, state) = harness(&["nmap"]);
        let mut options = OptionSet::new();
        options.insert("ports".into(), OptionValue::Str("80,443".into()));
        options.insert("intensity".into(), OptionValue::Str("fast".into()));
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options,
                reason: "focused scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let shared = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: ProcessOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: None,
            },
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(shared.clone());
        let res = rt.investigate(Target::new("10.0.0.1"));
        assert_eq!(res.tool_results.len(), 1);
        let calls = shared.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_exe, argv) = &calls[0];
        assert!(argv.contains(&"-p".to_string()));
        assert!(argv.contains(&"80,443".to_string()));
        assert!(
            argv.contains(&"-T4".to_string()),
            "intensity=fast → -T4: {argv:?}"
        );
        // No raw model text ever appears as an ad-hoc flag.
        assert!(!argv.iter().any(|a| a.starts_with("--")));
    }

    #[test]
    fn provider_fallback_in_the_loop_when_primary_unavailable() {
        // nmap absent, naabu installed → the loop still executes
        // network.port_scan, through naabu.
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["naabu"]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "scan".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state).with_executor(Arc::new(
            crate::agent::executor::StubExecutor::success("naabu", "{}"),
        ));
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        assert!(seen.contains(&AgentEvent::ProviderSelected {
            capability: "network.port_scan".into(),
            provider: "naabu".into(),
        }));
        assert_eq!(res.tool_results.len(), 1);
        assert_eq!(res.tool_results[0].tool_id, "naabu");
        assert_eq!(res.planned_actions[0].provider, "naabu");
    }

    #[test]
    fn invalid_options_are_rejected_and_fed_back() {
        // A model passing an undeclared option gets a distinct
        // invalid-arguments rejection and nothing executes.
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;

        let (tools, caps, state) = harness(&["nmap"]);
        let mut options = OptionSet::new();
        options.insert("flags".into(), OptionValue::Str("--privileged".into()));
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options,
                reason: "smuggle flags".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        let rejection = seen
            .iter()
            .find_map(|e| match e {
                AgentEvent::ActionRejected { reason } => Some(reason.clone()),
                _ => None,
            })
            .expect("invalid arguments must be rejected");
        assert!(
            rejection.contains("unknown option `flags`"),
            "got: {rejection}"
        );
        assert_eq!(res.tool_results.len(), 0);
        assert_eq!(res.steps_taken, 0);
    }

    #[test]
    fn report_and_update_finding_flow_through_drive() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::ReportFinding {
                severity: "high".into(),
                title: "SQLi in login".into(),
                target: "".into(),
                detail: "error-based".into(),
            },
            Decision::UpdateFinding {
                id: 1,
                status: "confirmed".into(),
                note: "validated with sleep".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        let recorded: Vec<_> = seen
            .iter()
            .filter_map(|e| match e {
                AgentEvent::FindingRecorded { status, .. } => Some(status.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(recorded, vec!["open".to_string(), "confirmed".to_string()]);
        // Blank report target resolves to the assessment target.
        let first_target = seen.iter().find_map(|e| match e {
            AgentEvent::FindingRecorded { target, .. } => Some(target.clone()),
            _ => None,
        });
        assert_eq!(first_target.as_deref(), Some("10.0.0.1"));
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
    }

    #[test]
    fn unknown_finding_id_and_ephemeral_vault_value_are_corrected_not_stored() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        let (tools, caps, state) = harness(&[]);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::UpdateFinding {
                id: 99,
                status: "confirmed".into(),
                note: "".into(),
            },
            Decision::VaultStore {
                key: "session".into(),
                value: jwt.into(),
                kind: "secret".into(),
                source: "cookie".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                AgentEvent::FindingRecorded { .. } | AgentEvent::VaultStored { .. }
            )),
            "nothing must be recorded for unknown ids / ephemeral values"
        );
    }

    #[test]
    fn vault_store_and_recall_never_leak_values_to_events() {
        use crate::agent::events::AgentEvent;
        use std::cell::RefCell;
        // Redirect the state dir so the test vault never touches the
        // real %APPDATA%\medusa.
        let old_appdata = std::env::var_os("APPDATA");
        let tmp = std::env::temp_dir().join(format!("medusa-vault-test-{}", std::process::id()));
        std::env::set_var("APPDATA", &tmp);
        let (tools, caps, state) = harness(&[]);
        let model: Box<dyn ModelProvider> = Box::new(StubProvider::new(vec![
            Decision::VaultStore {
                key: "db_password".into(),
                value: "s3cr3t-vault-value".into(),
                kind: "password".into(),
                source: "env dump".into(),
            },
            Decision::VaultRecall {
                query: "db_password".into(),
            },
            Decision::Finish {
                reason: "done".into(),
            },
        ]));
        let rt = AgentRuntime::new(model, &tools, &caps, &state);
        let seen = RefCell::new(Vec::new());
        rt.investigate_with(Target::new("10.9.9.9"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::VaultStored { key, .. } if key == "db_password"
        )));
        assert!(seen.iter().any(|e| matches!(
            e,
            AgentEvent::VaultRecalled { key } if key == "db_password"
        )));
        let debug: String = seen.iter().map(|e| format!("{e:?}")).collect();
        assert!(
            !debug.contains("s3cr3t-vault-value"),
            "vault values must never reach the event stream"
        );
        // Restore the real state dir for the rest of the suite.
        match old_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn auto_compaction_triggers_at_threshold_and_preserves_registry() {
        use crate::agent::events::AgentEvent;
        use crate::agent::model::{ContextView, ModelError, UsageReport};
        use std::cell::RefCell;
        use std::sync::{Arc, Mutex};

        /// Scripted provider whose FIRST decision reports a hot window
        /// (9000/10000 tokens) and the rest report real estimates.
        /// Records how many registry findings each decision's view held.
        struct HotProvider {
            script: Vec<Decision>,
            pos: Mutex<usize>,
            hot_calls: Mutex<usize>,
            seen_findings: Arc<Mutex<Vec<usize>>>,
        }
        impl ModelProvider for HotProvider {
            fn name(&self) -> &str {
                "hot"
            }
            fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
                self.seen_findings.lock().unwrap().push(ctx.findings.len());
                let mut pos = self.pos.lock().unwrap();
                let i = *pos;
                *pos += 1;
                Ok(self.script.get(i).cloned().unwrap_or(Decision::Finish {
                    reason: "script exhausted".into(),
                }))
            }
            fn decide_reported(
                &self,
                ctx: &ContextView,
            ) -> (Result<Decision, ModelError>, UsageReport) {
                let outcome = self.decide(ctx);
                let mut hot = self.hot_calls.lock().unwrap();
                let n = *hot;
                *hot += 1;
                if n == 0 {
                    (
                        outcome,
                        UsageReport {
                            prompt_tokens: 9000,
                            completion_tokens: 0,
                            total_tokens: 9000,
                            estimated: false,
                        },
                    )
                } else {
                    let chars = serde_json::to_string(ctx).map(|s| s.len()).unwrap_or(0);
                    (outcome, UsageReport::estimate(chars, 0))
                }
            }
            fn chat(&self, _system: &str, user: &str) -> Result<String, ModelError> {
                let snip: String = user.chars().take(60).collect();
                Ok(format!("SUMMARY: {snip}"))
            }
        }

        let (tools, caps, state) = harness(&[]);
        let seen_findings: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let model: Box<dyn ModelProvider> = Box::new(HotProvider {
            script: vec![
                Decision::ReportFinding {
                    severity: "High".into(),
                    title: "kept finding".into(),
                    target: "".into(),
                    detail: "must survive".into(),
                },
                Decision::Narrate {
                    text: "progress".into(),
                },
                Decision::Finish {
                    reason: "done".into(),
                },
            ],
            pos: Mutex::new(0),
            hot_calls: Mutex::new(0),
            seen_findings: Arc::clone(&seen_findings),
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &state)
            .with_context_window(10_000)
            .with_compaction_threshold(80);
        let seen = RefCell::new(Vec::new());
        let res = rt.investigate_with(Target::new("10.0.0.1"), &mut |ev| {
            seen.borrow_mut().push(ev)
        });
        let seen = RefCell::into_inner(seen);
        let (freed, fallback) = seen
            .iter()
            .find_map(|e| match e {
                AgentEvent::Compacted {
                    freed_tokens,
                    fallback,
                    ..
                } => Some((*freed_tokens, *fallback)),
                _ => None,
            })
            .expect("threshold crossing must compact");
        assert!(!fallback, "summarizer succeeds — no fallback");
        assert!(freed > 0, "compaction must free tokens");
        // The decision AFTER the compaction still saw the registry
        // finding (first decide ran before it was reported).
        assert_eq!(*seen_findings.lock().unwrap(), vec![0, 1, 1]);
        assert!(matches!(res.finish_reason, FinishReason::ModelFinished(_)));
    }
}
