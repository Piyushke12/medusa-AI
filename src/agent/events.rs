//! Agent event stream (Phase 1.5).
//!
//! ```text
//! AgentRuntime ─┬─ executes (Phase 4+)
//!               └─ emits AgentEvent ─┬─ CLI renderer (Phase 1.6, this tree)
//!                                    ├─ Ratatui UI (later)
//!                                    ├─ JSON output (--json)
//!                                    └─ tests (collect to Vec)
//! ```
//!
//! The loop is unchanged; listeners are passive observers. Variants marked
//! with the phase that fires them; unimplemented producers simply never emit
//! those variants yet.

/// Everything observable about an investigation, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    /// Interactive sessions: a user-mentioned target was granted to the
    /// scope. UIs use it to show the live scope line.
    ScopeGranted {
        target: String,
    },
    InvestigationStarted {
        target: String,
    },
    StepStarted {
        step: usize,
    },
    /// The runtime is waiting on the model. UI shows a spinner; tests ignore it.
    ModelThinking,
    /// Transient status line for UIs (e.g. "model call failed — retrying
    /// 1/5"). Not persisted; replaces the working-row status text.
    Status {
        message: String,
    },
    CapabilityRequested {
        capability: String,
        target: String,
        reason: String,
        /// Cumulative LLM time (seconds) spent deciding this step,
        /// including failed/retried model calls. UIs show it so the user
        /// can tell LLM latency from tool runtime.
        model_secs: f64,
    },
    ProviderSelected {
        capability: String,
        provider: String,
    },
    /// Phase 4: real process started.
    ToolStarted {
        capability: String,
        provider: String,
    },
    /// Phase 4: real process finished.
    ToolFinished {
        capability: String,
        provider: String,
    },
    /// Phase 4: full execution result (exit code, output, errors).
    /// `output` carries the (truncated) raw evidence so UIs can show it
    /// even when no parser produces observations.
    ToolExecuted {
        tool_id: String,
        capability: String,
        target: String,
        exit_code: i32,
        success: bool,
        timed_out: bool,
        output: String,
        /// Wall-clock seconds of the execution phase: all attempts plus
        /// inter-attempt backoff. Excludes LLM time and approval waits.
        tool_secs: f64,
    },
    /// Phase 5: a parser produced a normalized observation.
    ObservationAdded {
        summary: String,
    },
    /// The model reported a finding into the session registry (or
    /// updated one's status). UIs render registry cards from this;
    /// persisted as a `finding` session record (values: registry data,
    /// no secrets involved).
    FindingRecorded {
        id: usize,
        severity: String,
        title: String,
        target: String,
        status: String,
        detail: String,
        step: usize,
    },
    /// Per-decision context-meter reading: tokens used vs the model's
    /// window. UIs show the header chip; persisted for replay continuity.
    ContextUsage {
        used_tokens: u64,
        limit_tokens: u64,
        /// 0-100.
        pct: u8,
        /// True when the numbers are a char/4 estimate (endpoint omitted
        /// the `usage` block) rather than provider-reported.
        estimated: bool,
    },
    /// Auto (or manual) compaction replaced older turns with a summary.
    /// `before_tokens`/`after_tokens` are the window usage around the
    /// compaction; `fallback` means the summarizer call failed and the
    /// runtime truncated oldest-first instead.
    Compacted {
        before_tokens: u64,
        after_tokens: u64,
        freed_tokens: u64,
        fallback: bool,
    },
    /// A vault operation completed. Carries the KEY only — values never
    /// enter the event stream (or session files, or logs).
    VaultStored {
        key: String,
        kind: String,
        refreshed: bool,
    },
    /// A vault value was recalled for the model's immediate use. The
    /// value itself is NOT in the event — it rides one decision inside
    /// the ContextView and is cleared afterwards.
    VaultRecalled {
        key: String,
    },
    HypothesisAdded {
        id: usize,
        statement: String,
        confidence: String,
    },
    ActionRejected {
        reason: String,
    },
    /// Policy blocked a high-risk capability and the runtime is WAITING
    /// on the user. This is a request, not a rejection: UIs show an
    /// approval dialog and the verdict arrives through the approval gate.
    ApprovalRequested {
        capability: String,
        reason: String,
    },
    /// Conversational answer to the user (unified chat+agent loop).
    /// Terminates the turn; the session persists.
    Reply {
        text: String,
    },
    /// Mid-turn verbal update to the user (a narrated finding or
    /// milestone). Does NOT end the turn — the loop continues. UIs
    /// render it as a normal agent message, not a thinking card.
    Narrated {
        text: String,
    },
    Finished {
        reason: String,
    },
    Error {
        message: String,
    },
}
