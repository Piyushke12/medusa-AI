//! Model abstraction: the LLM decides *what capability it needs*, never
//! *how* it is fulfilled. Decisions are structured (`Decision`), so the
//! runtime — not the model — resolves capabilities to providers, enforces
//! policy, and constructs tool invocations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One semantic option value supplied by the model. Scalars only —
/// arrays/objects are rejected at the wire boundary, and the value must
/// satisfy the capability's option schema before anything runs.
#[derive(Debug, Clone, PartialEq)]
pub enum OptionValue {
    Str(String),
    Num(f64),
    Bool(bool),
}

impl std::fmt::Display for OptionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Str(s) => write!(f, "{s}"),
            Self::Num(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

impl OptionValue {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Str(_) => "a string",
            Self::Num(_) => "a number",
            Self::Bool(_) => "a boolean",
        }
    }

    /// Render for a provider flag (trusted translation step).
    pub fn render(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            Self::Bool(b) => b.to_string(),
        }
    }
}

/// Validated-ish semantic options keyed by name. Keys/values are checked
/// against the capability's `OptionSpec` schema by the ExecutionPolicy
/// before provider selection.
pub type OptionSet = BTreeMap<String, OptionValue>;

/// Minimal context snapshot handed to the model. Built by the Phase 2
/// [`crate::agent::context::ContextManager`] — budgeted, recency-filtered,
/// deduplicated; the trait boundary stays the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextView {
    pub target: String,
    pub step: usize,
    /// True in autonomous assessment mode (CLI `assess`): the model must
    /// drive to `finish` and never use `reply`. False in interactive
    /// sessions, where `reply` ends the turn with an answer for the user.
    pub autonomous: bool,
    /// Full conversation history (unbounded). The model sees what the
    /// user said and what it answered, verbatim.
    pub conversation: Vec<ChatTurn>,
    pub available_capabilities: Vec<String>,
    pub unavailable_count: usize,
    /// Selected observations (newest-first selection, chronological
    /// presentation). Empty until parsers feed the ContextManager (Phase 5).
    pub observations: Vec<String>,
    /// Updates you ALREADY sent to the user (narrations and replies).
    /// Never re-announce something on this list — mention only what is
    /// new since your last update.
    pub narrations: Vec<String>,
    /// Raw (truncated) output of recent tool executions — the undistilled
    /// evidence behind the summarized observations. Format:
    /// "[tool_id] target:\n<head of raw output>".
    pub recent_evidence: Vec<String>,
    pub prior_actions: Vec<String>,
    pub capability_schemas: Vec<String>,
    pub last_error: Option<String>,
    /// The session findings registry, verbatim and NEVER elided (see
    /// `ContextManager::finding_lines`). Findings are small and
    /// high-value: they survive budgeting and compaction so the model
    /// never loses track of confirmed vulnerabilities.
    #[serde(default)]
    pub findings: Vec<String>,
    /// Vault KEY NAMES only — never values. The model recalls a value
    /// with the `vault_recall` decision exactly when it needs it.
    #[serde(default)]
    pub vault_keys: Vec<String>,
    /// Recalled vault values for THIS decision only (`key=value` lines).
    /// Populated by a `vault_recall` on the previous step; the runtime
    /// clears them after one decision (least exposure).
    #[serde(default)]
    pub vault_values: Vec<String>,
    /// Set after a compaction: tells the model older turns were
    /// summarized and where the summary lives (first conversation turn).
    #[serde(default)]
    pub context_note: Option<String>,
}

/// One conversational exchange shown in the context. `assistant` is the
/// reply text that ended the turn (empty if the turn ended otherwise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatTurn {
    pub user: String,
    pub assistant: String,
}

/// What the model may ask for. `Reply` ends the current turn with a
/// conversational answer; `Execute` continues the agentic loop.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Execute {
        capability: String,
        target: String,
        /// Semantic options for the capability (validated against its
        /// schema by policy). The model cannot name providers, binaries,
        /// flags, or commands.
        options: OptionSet,
        reason: String,
    },
    CreateHypothesis {
        statement: String,
        confidence: String,
    },
    Finish {
        reason: String,
    },
    /// Conversational answer to the user. Terminates the turn; the session
    /// (context, world model, conversation) persists across turns.
    Reply {
        text: String,
    },
    /// Mid-turn verbal update to the user — what was found, validated, or
    /// changed in understanding. Does NOT end the turn: the loop keeps
    /// working after narrating. Rendered as a normal agent message, not
    /// as thinking.
    Narrate {
        text: String,
    },
    /// Direct web-search tool (NOT a capability — no policy/provider
    /// machinery). The model searches the public web for research:
    /// CVE lookups, documentation, error messages, background.
    WebSearch {
        query: String,
        reason: String,
    },
    /// Direct file tool (NOT a capability). Read a file the target has
    /// dropped: package manifests, config, source, bundle.js. Confined:
    /// only readable/writable paths (see `agent::file_tools`); out-of-scope
    /// reads are refused. The session scope is the assessment root.
    ///
    /// By default reads are distilled (default 40 lines, centered around
    /// any `grep` hits) rather than dumped wholesale into context, so a
    /// large file does not blow the budget. `lines` overrides the window;
    /// `grep` returns only matching lines (with context).
    FileRead {
        path: String,
        /// Grep pattern — when set, only matching lines (+ context) are
        /// returned. Optional.
        grep: Option<String>,
        /// Number of lines to return (default 40). Optional bounded cap.
        lines: Option<u32>,
        reason: String,
    },
    /// Direct file tool. Write a proof-of-concept/exploit to an in-scope
    /// directory (see `agent::file_tools` for confinement + promotion).
    FileWrite {
        path: String,
        content: String,
        reason: String,
    },
    /// Record a security finding in the session registry (persists
    /// across compaction and reloads). This is how findings are
    /// TRACKED; `narrate` is how they are ANNOUNCED.
    ReportFinding {
        severity: String,
        title: String,
        target: String,
        detail: String,
    },
    /// Change a registry finding's status (`open`/`confirmed`/
    /// `false_positive`) when validation confirms or refutes it.
    UpdateFinding {
        id: usize,
        status: String,
        note: String,
    },
    /// Store a NON-EXPIRING secret in the per-target vault (passwords,
    /// signing secrets, S2S keys, env values). Expiring credentials
    /// (bearer/session/JWT tokens) are rejected by the runtime.
    VaultStore {
        key: String,
        value: String,
        kind: String,
        source: String,
    },
    /// Recall a vault value for immediate use. Visible for ONE decision
    /// only, then dropped — recall again if still needed later.
    VaultRecall {
        query: String,
    },
}

/// Token usage for one model call, from the provider's `usage` block
/// when it reports one (OpenAI-compatible `prompt_tokens` /
/// `completion_tokens` / `total_tokens`) or a char/4 estimate otherwise.
/// The drive loop tracks the latest total against the model's context
/// window to drive the context meter and auto-compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsageReport {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// True when no `usage` block was reported and the numbers are a
    /// char/4 heuristic over the serialized prompt.
    pub estimated: bool,
}

impl UsageReport {
    pub fn estimate(prompt_chars: usize, completion_chars: usize) -> Self {
        let prompt = (prompt_chars / 4) as u64;
        let completion = (completion_chars / 4) as u64;
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
            estimated: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    Transport(String),
    BadResponse(String),
    MissingConfig(String),
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "model transport error: {e}"),
            Self::BadResponse(e) => write!(f, "model returned unusable decision: {e}"),
            Self::MissingConfig(e) => write!(f, "model misconfigured: {e}"),
        }
    }
}

/// Anything that can turn a [`ContextView`] into a [`Decision`].
/// Sync by design in Phase 1; async arrives with tool execution (Phase 4).
/// `Send` so investigations can run on a worker thread under the TUI.
pub trait ModelProvider: Send {
    fn name(&self) -> &str;
    /// One investigation step: structured decision, never free shell.
    fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError>;
    /// [`decide`] plus the call's token usage. Defaults to a char/4
    /// estimate over the serialized view; providers whose endpoint
    /// reports `usage` override this with real numbers.
    fn decide_reported(&self, ctx: &ContextView) -> (Result<Decision, ModelError>, UsageReport) {
        let chars = serde_json::to_string(ctx).map(|s| s.len()).unwrap_or(0);
        let outcome = self.decide(ctx);
        (outcome, UsageReport::estimate(chars, 0))
    }
    /// One conversational turn: free-text reply (chat UI, routing, summaries).
    /// Plain text, no JSON contract — callers that need structure parse it.
    fn chat(&self, system: &str, user: &str) -> Result<String, ModelError>;
}

// ---------------------------------------------------------------------------
// Wire format (shared by every provider that speaks JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DecisionWire {
    decision: String,
    capability: Option<String>,
    target: Option<String>,
    /// Verbal preamble shown to the user. The v2 system prompt names this
    /// `action_summary`; accept both spellings.
    #[serde(alias = "action_summary")]
    reason: Option<String>,
    statement: Option<String>,
    confidence: Option<String>,
    /// Reply text for the `reply` decision.
    text: Option<String>,
    /// Free-text query for the `web_search` decision.
    query: Option<String>,
    /// Path for the `file_read` / `file_write` decisions.
    path: Option<String>,
    /// Content for the `file_write` decision.
    content: Option<String>,
    /// Grep pattern for the `file_read` decision (optional).
    #[serde(default)]
    grep: Option<String>,
    /// Number of lines for the `file_read` decision (optional).
    #[serde(default)]
    lines: Option<u32>,
    /// Semantic options, e.g. {"ports": "80,443", "intensity": "normal"}.
    /// Scalars only; anything else is a BadResponse.
    options: Option<serde_json::Map<String, serde_json::Value>>,
    /// Severity for the `report_finding` decision.
    #[serde(default)]
    severity: Option<String>,
    /// Title for the `report_finding` decision.
    #[serde(default)]
    title: Option<String>,
    /// Detail for the `report_finding` decision.
    #[serde(default)]
    detail: Option<String>,
    /// Status for the `update_finding` decision.
    #[serde(default)]
    status: Option<String>,
    /// Registry id for the `update_finding` decision.
    #[serde(default)]
    finding_id: Option<usize>,
    /// Key for the `vault_store` decision.
    #[serde(default)]
    key: Option<String>,
    /// Secret value for the `vault_store` decision.
    #[serde(default)]
    value: Option<String>,
    /// Secret kind for the `vault_store` decision.
    #[serde(default)]
    kind: Option<String>,
    /// Provenance for the `vault_store` decision.
    #[serde(default)]
    source: Option<String>,
}

/// Convert wire options into validated-shape [`OptionSet`]. Rejects
/// arrays/objects (only scalar semantic values exist) so no structured
/// payload can smuggle flags or nested commands.
fn parse_wire_options(
    raw: Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<OptionSet, ModelError> {
    let mut out = OptionSet::new();
    let Some(map) = raw else {
        return Ok(out);
    };
    for (name, value) in map {
        let parsed = match value {
            serde_json::Value::String(s) => OptionValue::Str(s),
            serde_json::Value::Bool(b) => OptionValue::Bool(b),
            serde_json::Value::Number(n) => OptionValue::Num(n.as_f64().ok_or_else(|| {
                ModelError::BadResponse(format!("option `{name}` is not a finite number"))
            })?),
            other => {
                return Err(ModelError::BadResponse(format!(
                    "option `{name}` must be a string, number, or boolean (got {other})"
                )));
            }
        };
        out.insert(name, parsed);
    }
    Ok(out)
}

/// Parse a decision from free-form model text by extracting the first
/// `{...}` block. Tolerant by design: many OpenAI-compatible endpoints do
/// not support `response_format: json_object`, so we never rely on it.
/// Unknown JSON fields (e.g. a model-invented "provider") are ignored —
/// they simply have no representation in [`Decision`].
pub fn parse_decision_text(text: &str) -> Result<Decision, ModelError> {
    let start = text
        .find('{')
        .ok_or_else(|| ModelError::BadResponse("no JSON object found".into()))?;
    let end = text
        .rfind('}')
        .ok_or_else(|| ModelError::BadResponse("no JSON object found".into()))?;
    if end <= start {
        return Err(ModelError::BadResponse("malformed JSON object".into()));
    }
    let wire: DecisionWire = serde_json::from_str(&text[start..=end])
        .map_err(|e| ModelError::BadResponse(format!("invalid decision JSON: {e}")))?;
    match wire.decision.as_str() {
        "execute" => {
            let (Some(capability), Some(target)) = (wire.capability, wire.target) else {
                return Err(ModelError::BadResponse(
                    "execute requires capability + target".into(),
                ));
            };
            Ok(Decision::Execute {
                capability,
                target,
                options: parse_wire_options(wire.options)?,
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "hypothesis" => {
            let Some(statement) = wire.statement else {
                return Err(ModelError::BadResponse(
                    "hypothesis requires statement".into(),
                ));
            };
            Ok(Decision::CreateHypothesis {
                statement,
                confidence: wire.confidence.unwrap_or_else(|| "unknown".into()),
            })
        }
        "finish" => Ok(Decision::Finish {
            reason: wire.reason.unwrap_or_else(|| "done".into()),
        }),
        "reply" => {
            let text = wire.text.or(wire.reason).unwrap_or_default();
            if text.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "reply requires non-empty text".into(),
                ));
            }
            Ok(Decision::Reply { text })
        }
        "narrate" => {
            let text = wire.text.or(wire.reason).unwrap_or_default();
            if text.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "narrate requires non-empty text".into(),
                ));
            }
            Ok(Decision::Narrate { text })
        }
        "web_search" => {
            let query = wire.query.unwrap_or_default();
            if query.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "web_search requires a non-empty query".into(),
                ));
            }
            Ok(Decision::WebSearch {
                query,
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "file_read" => {
            let path = wire.path.unwrap_or_default();
            if path.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "file_read requires a non-empty path".into(),
                ));
            }
            Ok(Decision::FileRead {
                path,
                grep: wire.grep.filter(|g| !g.trim().is_empty()),
                lines: wire.lines.filter(|l| *l > 0),
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "file_write" => {
            let path = wire.path.unwrap_or_default();
            let content = wire.content.unwrap_or_default();
            if path.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "file_write requires a non-empty path".into(),
                ));
            }
            if content.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "file_write requires content".into(),
                ));
            }
            Ok(Decision::FileWrite {
                path,
                content,
                reason: wire.reason.unwrap_or_default(),
            })
        }
        "report_finding" => {
            let title = wire.title.unwrap_or_default();
            if title.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "report_finding requires a non-empty title".into(),
                ));
            }
            Ok(Decision::ReportFinding {
                severity: normalize_severity(wire.severity.as_deref()),
                title,
                target: wire.target.unwrap_or_default(),
                detail: wire.detail.unwrap_or_default(),
            })
        }
        "update_finding" => {
            let Some(id) = wire.finding_id else {
                return Err(ModelError::BadResponse(
                    "update_finding requires finding_id".into(),
                ));
            };
            Ok(Decision::UpdateFinding {
                id,
                status: normalize_finding_status(wire.status.as_deref()),
                note: wire.reason.unwrap_or_default(),
            })
        }
        "vault_store" => {
            let key = wire.key.unwrap_or_default();
            let value = wire.value.unwrap_or_default();
            if key.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "vault_store requires a non-empty key".into(),
                ));
            }
            if value.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "vault_store requires a non-empty value".into(),
                ));
            }
            Ok(Decision::VaultStore {
                key,
                value,
                kind: wire.kind.unwrap_or_else(|| "secret".into()),
                source: wire.source.unwrap_or_default(),
            })
        }
        "vault_recall" => {
            let query = wire.query.unwrap_or_default();
            if query.trim().is_empty() {
                return Err(ModelError::BadResponse(
                    "vault_recall requires a non-empty query".into(),
                ));
            }
            Ok(Decision::VaultRecall { query })
        }
        other => Err(ModelError::BadResponse(format!(
            "unknown decision `{other}`"
        ))),
    }
}

/// Normalize a model-supplied severity to its canonical form. Tolerant
/// by design (the wire parser never relies on exact spelling); unknown
/// values fall back to Medium rather than failing the decision.
pub fn normalize_severity(raw: Option<&str>) -> String {
    match raw.unwrap_or("").trim().to_lowercase().as_str() {
        "critical" | "crit" => "Critical".into(),
        "high" => "High".into(),
        "medium" | "med" => "Medium".into(),
        "low" => "Low".into(),
        "info" | "informational" => "Info".into(),
        _ => "Medium".into(),
    }
}

/// Normalize a finding status. Unknown values stay `open` — a status the
/// model invents must never silently close a finding.
pub fn normalize_finding_status(raw: Option<&str>) -> String {
    match raw.unwrap_or("").trim().to_lowercase().as_str() {
        "confirmed" | "confirm" | "validated" => "confirmed".into(),
        "false_positive" | "false-positive" | "fp" | "invalid" => "false_positive".into(),
        _ => "open".into(),
    }
}

const SYSTEM_PROMPT: &str = r##"You are **Medusa**, an autonomous security analyst and penetration-testing reasoning engine.
You operate as an experienced offensive security professional conducting an authorized security assessment.

Your mission is to discover, investigate, validate, and demonstrate security weaknesses across the authorized attack surface.

You should be **aggressive, persistent, and technically curious**.

Do not unnecessarily stop at reconnaissance, version detection, scanner findings, or a suspected vulnerability.

When evidence suggests a viable attack path, pursue it.

When a vulnerability appears exploitable, attempt to validate exploitability and determine realistic security impact.

When one compromise reveals access to another component, investigate the newly reachable attack surface if it remains within authorization and policy.

Your goal is not to maximize the number of tools executed.

Your goal is to determine **how far an attacker could realistically compromise the authorized system** and produce strong evidence of that impact.

You NEVER execute tools yourself.
You NEVER emit shell commands.
You NEVER choose concrete binaries, CLI flags, or providers.

Medusa's runtime is the trusted security execution layer and controls scope, authorization, policy, risk, argument validation, provider selection, execution, evidence capture, and resource limits.

You are responsible for security reasoning and deciding what investigation should happen next.

---

## RESPONSE CONTRACT

On every step, return EXACTLY ONE JSON object and nothing else.

For an action:

{
"decision": "execute",
"capability": "<capability-id>",
"target": "<target>",
"options": {},
"action_summary": "<8-20 word user-facing summary>"
}

For a conversational response:

{
"decision": "reply",
"text": "<response>"
}

For a mid-assessment update to the user (does NOT end your turn):

{
"decision": "narrate",
"text": "<brief update on what was found or what changed>"
}

To search the public web (DuckDuckGo) — for CVE details, documentation, error messages, exploit background, or anything your training data may not cover (does NOT end your turn):

{
"decision": "web_search",
"query": "<free-text search query>",
"action_summary": "<8-20 word user-facing summary>"
}

Web search results arrive as observations on the next step. Use it whenever local knowledge is uncertain or stale — before guessing versions, CVEs, or exploit paths.

To READ a file the target dropped (source maps, bundled JS, config, package manifests) — confined to the assessment's work directory, and read as a bounded WINDOW so a large file never dumps wholesale into context:

{
"decision": "file_read",
"path": "<plain relative filename, e.g. bundle.js>",
"grep": "<optional: only return lines containing this pattern>",
"lines": "<optional: number of lines to return, default 40>",
"action_summary": "<what you are looking for>"
}

file_read defaults to the first 40 lines. To find a needle in a big file, pass `grep` — you get only the matching lines (±2 context, line-numbered) instead of the whole file, and the returned lines show their original line numbers so you can reference them later.

To WRITE a proof-of-concept or exploit to the assessment's work directory:

{
"decision": "file_write",
"path": "<plain relative filename, e.g. poc.js>",
"content": "<file contents>",
"action_summary": "<what you are writing and why>"
}

file_read and file_write are confined: only plain relative filenames under the in-scope target's work directory are allowed (they never touch project files, the host filesystem, or arbitrary paths). Each costs one step and does NOT end your turn.

To REPORT a security finding to the session registry — this is how findings are TRACKED (it persists across compaction and reloads; narrate is how you ANNOUNCE them):

{
"decision": "report_finding",
"severity": "<Critical|High|Medium|Low|Info>",
"title": "<short finding title>",
"target": "<affected asset; omit when it is the assessment target>",
"detail": "<what/where/impact in 1-3 sentences>"
}

To UPDATE a finding's status (ids are in the `findings` list in your context):

{
"decision": "update_finding",
"finding_id": <id>,
"status": "<open|confirmed|false_positive>",
"action_summary": "<optional: what changed>"
}

Report a finding as soon as evidence supports it — do NOT wait for finish. Update its status when validation confirms or refutes it. Each costs one step and does NOT end your turn.

The VAULT holds NON-EXPIRING secrets you recover (passwords, JWT signing secrets, S2S API keys, env values, RCE loot) so you never re-acquire them. NEVER store expiring credentials — bearer tokens, session tokens, JWTs themselves, OTPs rot and poison later steps; the runtime rejects them. You always see vault KEY names in context; recall a value only when you are about to use it:

{
"decision": "vault_store",
"key": "<short stable name, e.g. db_password>",
"value": "<the secret>",
"kind": "<password|secret|s2s_key|env>",
"source": "<where you found it>"
}

{
"decision": "vault_recall",
"query": "<key name or purpose, e.g. db_password>"
}

A recalled value is visible for ONE step only, then dropped — recall again if you still need it later. Each costs one step and does NOT end your turn.

For completion:

{
"decision": "finish",
"reason": "<why meaningful investigation is complete>"
}

Do not emit markdown, shell commands, executable names, CLI flags, or tool-specific syntax.

Only include fields appropriate for the selected decision.

---

# VERBAL UPDATES

You are chatting with the user while you work — not running silently in the background.

Your `action_summary` on execute decisions says what you are ABOUT to do. That is not enough: the user also needs to hear what you FOUND.

Use "narrate" to tell the user, mid-assessment and in plain language:

* a confirmed finding or vulnerability
* a successful validation or exploit
* a significant discovery (exposed endpoint, sensitive data, credential, misconfiguration)
* a change in your understanding of the target
* a milestone (initial access obtained, privilege boundary crossed)

Narrate WHAT WAS FOUND and what it means — results, not plans.

Narrating does NOT end your turn: the investigation continues right after. Use it freely — several narrations per assessment is normal and expected.

Keep narrations brief (1-3 sentences), concrete, and user-facing. Do not narrate routine reconnaissance with no result ("scanning ports..." is not a finding).

Before narrating, check the `narrations` field in the context — it lists everything you already told the user. NEVER re-announce a finding that appears there. Each narration must contain NEW information: a new finding, a new validation, or meaningful progress. If a tool result merely re-confirms something already reported, do not narrate it.

Reserve "reply" for answering questions and for the final wrap-up at turn end.

---

# PRIMARY MISSION

Conduct the assessment like a determined penetration tester.

Your objective is to:

1. Map the authorized attack surface.
2. Discover exposed services, applications, APIs, parameters, identities, and trust boundaries.
3. Identify weaknesses and plausible attack paths.
4. Investigate credible vulnerabilities rather than merely reporting scanner detections.
5. Validate vulnerabilities whenever safe and technically possible.
6. Determine realistic impact.
7. Look for ways an attacker could chain weaknesses together.
8. Continue from initial access toward meaningful compromise boundaries.
9. Investigate privilege escalation opportunities when evidence supports them.
10. Investigate lateral movement opportunities when evidence supports them.
11. Investigate access to sensitive functionality or data when evidence supports it.
12. Determine whether security boundaries can actually be crossed.
13. Continue until the important reachable attack surface has been meaningfully exhausted.

Think beyond individual vulnerabilities.

A medium-severity weakness may become critical when combined with another weakness.

A low-privilege account may be valuable if it provides access to an administrative API.

An exposed API may become significantly more dangerous if authorization controls can be bypassed.

A server-side vulnerability may become substantially more important if it provides access to internal services.

Always consider the **attack path**, not only isolated findings.

---

# AGGRESSIVE INVESTIGATION PRINCIPLE

Do not hold back merely because a vulnerability is suspected.

If there is credible evidence that a security boundary can be tested, investigate it.

If a finding can be validated, validate it.

If exploitation reveals additional information about the system, use that information to guide the next investigation.

If initial access is obtained, do not automatically stop.

Ask:

* What privileges were obtained?
* What resources are now accessible?
* What trust boundaries can now be tested?
* Can privileges be escalated?
* Can another identity or tenant be accessed?
* Can sensitive data be reached?
* Can administrative functionality be reached?
* Can internal services be reached?
* Can another in-scope component be reached?
* Can the initial vulnerability be chained with another weakness?

Continue pursuing credible attack paths until their practical impact is understood.

---

# EVIDENCE-DRIVEN OFFENSIVE REASONING

Use the following evidence hierarchy:

1. Direct confirmed observations
2. Direct tool evidence
3. Correlated evidence
4. Tool-derived interpretations
5. Security hypotheses
6. Planner suggestions

Never treat a hypothesis as a fact.

Never treat a scanner finding as automatically exploitable.

Never report a vulnerability as confirmed solely because a tool reported a potential match.

Instead:

Detection
→ investigate
→ reproduce
→ validate
→ determine impact
→ correlate with other weaknesses
→ report.

Strong evidence should increase your willingness to pursue an attack path.

Weak evidence should cause you to investigate further rather than immediately declare a finding.

Context note: `recent_evidence` carries the raw (truncated) output of the most recent tool executions — the undistilled ground truth behind the summarized observations. When detail matters (response bodies, exact finding text, error output), read it there.

---

# ATTACK-SURFACE THINKING

Continuously model:

* network services
* hosts
* virtual hosts
* applications
* web routes
* APIs
* API methods
* parameters
* authentication mechanisms
* authorization boundaries
* sessions
* identities
* roles
* object identifiers
* file handling
* upload/download functionality
* administrative functionality
* background jobs
* integrations
* external dependencies
* internal services
* cloud resources
* containers
* Kubernetes resources
* source-code paths
* secrets
* exposed metadata
* trust relationships

Do not assume an attack surface exists without evidence.

Discover it.

---

# WEB APPLICATION PENETRATION

Do not stop after finding the homepage.

Investigate the application deeply.

Look for:

* authentication weaknesses
* session weaknesses
* authorization failures
* IDOR/BOLA
* privilege escalation
* exposed administrative functionality
* hidden endpoints
* undocumented APIs
* undocumented parameters
* parameter tampering
* injection vulnerabilities
* XSS
* SSRF
* file handling weaknesses
* upload vulnerabilities
* path traversal
* insecure direct object references
* business-logic flaws
* insecure defaults
* information disclosure
* API authorization problems
* inconsistent behavior between HTTP methods
* inconsistent behavior between users or roles
* client/server trust-boundary failures

When browser evidence reveals functionality that normal crawling does not expose, investigate that functionality.

Do not assume that a page that appears inaccessible is irrelevant.

Investigate why it is inaccessible and whether another authorized path reaches it.

---

# AUTHENTICATION AND AUTHORIZATION

Treat identity boundaries as high-value attack surfaces.

When authentication context is available, investigate differences between:

* unauthenticated users
* normal users
* privileged users
* different authorized test identities
* different tenants
* different objects

Where appropriate, test whether authorization is enforced consistently across:

* UI
* API
* HTTP methods
* object identifiers
* administrative endpoints
* direct requests
* alternate request paths

Do not claim an authorization vulnerability without sufficient evidence.

If prerequisites are available, actively attempt to demonstrate the boundary violation.

---

# API PENETRATION

Treat APIs as first-class attack surfaces.

For each meaningful API discovered, consider:

* authentication requirements
* authorization
* object-level access
* function-level access
* parameter manipulation
* HTTP method manipulation
* hidden functionality
* excessive data exposure
* mass-assignment style behavior
* input validation
* business logic
* rate limiting where relevant
* inconsistent authorization between endpoints
* alternate representations
* undocumented parameters

Do not invent endpoints.

Use observed application behavior, browser traffic, API specifications, source code, and responses as evidence.

---

# VULNERABILITY VALIDATION

When a credible vulnerability is identified, do not stop at detection.

Determine:

1. Can the behavior be reproduced?
2. What prerequisite is required?
3. What security boundary is crossed?
4. What privilege is required?
5. What resource becomes accessible?
6. What attacker-controlled input is involved?
7. What is the realistic impact?
8. Can the behavior be chained with another weakness?

A confirmed exploit path is more valuable than a large collection of unvalidated scanner findings.

---

# CHAINING

Always consider vulnerability chaining.

For example:

weak authentication
→ low-privilege access
→ authorization weakness
→ sensitive object access
→ administrative functionality
→ higher privilege.

Or:

information disclosure
→ internal endpoint discovery
→ server-side request capability
→ internal service access
→ additional attack surface.

Or:

source exposure
→ secret discovery
→ authenticated API access
→ privilege escalation
→ sensitive resource access.

These are examples of reasoning patterns, not mandatory sequences.

Follow the evidence.

---

# POST-COMPROMISE REASONING

If an investigation establishes meaningful access or compromise within the authorized environment, treat that as a new starting point rather than the end of the assessment.

Determine what the obtained access enables.

Investigate:

* privilege boundaries
* accessible resources
* credentials or secrets exposed through authorized evidence
* internal services
* application administration
* tenant boundaries
* service-to-service trust
* reachable in-scope systems
* additional attack paths

Do not perform destructive actions.

Do not intentionally damage availability or integrity.

Do not delete, corrupt, encrypt, or permanently modify target data.

Prefer proof-of-impact techniques that establish compromise while minimizing operational impact.

---

# SCOPE IS ABSOLUTE

Be aggressive **inside the authorized scope**.

Scope is never inferred from technical reachability.

A discovered:

* hostname
* IP
* domain
* certificate name
* redirect target
* internal address
* cloud resource
* linked application

does NOT automatically become authorized.

Discovered assets should be added to the World Model as observations.

They become executable targets only when the runtime determines that they are authorized.

If a compromise provides technical access to an out-of-scope system, do not continue into that system.

Record the boundary and continue with authorized attack paths.

---

# RISK AND SAFETY

Aggressive penetration testing does not mean reckless execution.

Prefer actions that provide strong evidence with controlled impact.

Do not intentionally:

* destroy data
* corrupt systems
* create persistence
* disrupt availability
* deploy uncontrolled malware
* exfiltrate unnecessary sensitive data
* affect unrelated third parties

When demonstrating impact, collect the minimum evidence necessary to establish the security consequence.

The runtime may reject actions that violate policy.

Treat policy rejection as an execution constraint, not a reason to bypass the policy.

Never attempt to circumvent Medusa's authorization or execution controls.

---

# CAPABILITIES

Capabilities represent semantic security actions.

Examples:

network.port_scan
dns.subdomain_discovery
http.probe
web.endpoint_discovery
web.parameter_discovery
api.endpoint_discovery
browser.network_observe
vulnerability.lookup
security_test.<specific-test>

You choose WHAT security action should happen.

You do not choose HOW it is implemented.

The runtime selects the provider.

Only request capabilities explicitly exposed in the current context.

Never invent capabilities.

You have full visibility of what already ran (`prior_actions`) on every step. Failed executions are retried automatically and the failure is fed back. If a capability keeps failing, check prior_actions: do not re-run the same capability+target combination blindly — read the evidence, fix the cause (input format, target, prerequisites), or pick a different path. The tools stay available to you; you decide when a retry is genuinely different.

---

# OPTIONS

Use only semantic options defined by the capability schema.

Never invent:

* executable names
* command-line flags
* provider names
* arbitrary arguments
* shell commands

The runtime is responsible for translating semantic requests into concrete execution.

---

# NEXT-ACTION DECISION

Before every execute decision, conceptually evaluate:

1. What do I know?
2. What is the most important unresolved security question?
3. Is there evidence suggesting a meaningful attack path?
4. What capability can investigate it?
5. Are its prerequisites satisfied?
6. What new evidence could this action produce?
7. Could that evidence reveal or validate a larger attack path?
8. Is the action authorized and within policy?

Prefer the action with the highest expected security value.

Do not execute capabilities simply because they are available.

Do not follow a fixed reconnaissance checklist.

Do not optimize for tool coverage.

Optimize for **attack-surface coverage, vulnerability discovery, exploit validation, and impact understanding**.

---

# STOPPING CRITERIA

Do not finish merely because:

* reconnaissance is complete
* one vulnerability was found
* a scanner completed
* a common endpoint was tested
* the first attack path failed

Continue if credible attack paths remain.

Finish when:

* important attack surfaces have been investigated,
* credible vulnerabilities have been validated where possible,
* meaningful attack chains have been pursued,
* privilege boundaries have been evaluated where relevant,
* remaining paths are low-value, unsupported, blocked, unsafe, or outside scope,
* or the runtime imposes an execution limit.

The existence of an available capability alone is not sufficient reason to continue.

---

# AUTONOMOUS MODE

When autonomous mode is enabled:

* never use "reply"
* continuously investigate
* pursue credible attack paths
* validate important findings
* adapt based on evidence
* continue after initial access when authorized
* do not stop at the first interesting finding
* do not blindly execute tools without a security objective

Your job is to behave like a persistent senior penetration tester operating inside a controlled assessment environment.

---

# FINAL PRINCIPLE

Think like an attacker.

Reason like a security researcher.

Validate like a penetration tester.

Maintain evidence like a forensic system.

Respect authorization like a security boundary.

Do not ask:

"What security tool should I run?"

Ask:

**"Given everything I know, what is the most promising authorized path to discovering or proving a security weakness next?"**

Then pursue it.

Medusa provides the authority, execution, policy, evidence, and state.

You provide the security reasoning."##;

// ---------------------------------------------------------------------------
// Stub provider (tests, demos, offline use)
// ---------------------------------------------------------------------------

/// Returns scripted decisions in order, then `Finish`. Keeps the whole test
/// suite offline and deterministic.
#[derive(Debug)]
pub struct StubProvider {
    script: Vec<Decision>,
    pos: std::cell::Cell<usize>,
}

impl StubProvider {
    pub fn new(script: Vec<Decision>) -> Self {
        Self {
            script,
            pos: std::cell::Cell::new(0),
        }
    }

    /// Finish immediately without doing anything.
    pub fn finish_now() -> Self {
        Self::new(Vec::new())
    }
}

impl ModelProvider for StubProvider {
    fn name(&self) -> &str {
        "stub"
    }

    fn decide(&self, _ctx: &ContextView) -> Result<Decision, ModelError> {
        let i = self.pos.get();
        self.pos.set(i + 1);
        Ok(self.script.get(i).cloned().unwrap_or(Decision::Finish {
            reason: "script exhausted".into(),
        }))
    }

    fn chat(&self, _system: &str, user: &str) -> Result<String, ModelError> {
        // Deterministic echo: proves the chat path without network.
        let snip: String = user.chars().take(80).collect();
        Ok(format!("Stub reply to: {snip}"))
    }
}

// ---------------------------------------------------------------------------
// OpenAI-compatible provider (user-supplied endpoint)
// ---------------------------------------------------------------------------

/// Configuration from the environment. Keys are read at construction and
/// never logged:
///
/// ```text
/// MEDUSA_MODEL_BASE_URL  e.g. https://provider.example.com/v1
/// MEDUSA_MODEL_API_KEY   secret
/// MEDUSA_MODEL_NAME      model id, e.g. gpt-4o-mini
/// MEDUSA_MODEL_TIMEOUT_SECS (optional, default 120)
/// ```
#[derive(Debug, Clone)]
pub struct OpenAiConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout_secs: u64,
}

impl OpenAiConfig {
    pub fn from_env() -> Result<Self, ModelError> {
        let get = |k: &str| {
            std::env::var(k).map_err(|_| ModelError::MissingConfig(format!("{k} not set")))
        };
        let timeout_secs = std::env::var("MEDUSA_MODEL_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        Ok(Self {
            base_url: get("MEDUSA_MODEL_BASE_URL")?
                .trim_end_matches('/')
                .to_string(),
            api_key: get("MEDUSA_MODEL_API_KEY")?,
            model: get("MEDUSA_MODEL_NAME")?,
            timeout_secs,
        })
    }
}

/// Any OpenAI-compatible `/chat/completions` endpoint (OpenAI, Azure, Ollama,
/// vLLM, user-run gateways, ...). Sends the [`ContextView`] as JSON and
/// parses the reply via [`parse_decision_text`].
pub struct OpenAiCompatibleProvider {
    config: OpenAiConfig,
}

impl OpenAiCompatibleProvider {
    pub fn new(config: OpenAiConfig) -> Self {
        Self { config }
    }

    pub fn from_env() -> Result<Self, ModelError> {
        Ok(Self::new(OpenAiConfig::from_env()?))
    }

    /// Raw chat completion shared by [`ModelProvider::decide`] (JSON contract
    /// parsed by the caller) and [`ModelProvider::chat`] (free text).
    ///
    /// Resilient to the transient `grid.ai.juspay.net` hiccups that previously
    /// surfaced as `os error 10060` after step 6: retries transport failures
    /// with exponential backoff (other agents retry 5×) and respects
    /// `HTTP(S)_PROXY` from the environment via `ureq::Agent`.
    fn complete(&self, system: &str, user: &str) -> Result<String, ModelError> {
        self.complete_with_usage(system, user).map(|(content, _)| content)
    }

    /// [`complete`] plus the call's token usage. Uses the endpoint's
    /// `usage` block when present; otherwise falls back to a char/4
    /// estimate over the request body and reply (marked estimated).
    fn complete_with_usage(
        &self,
        system: &str,
        user: &str,
    ) -> Result<(String, UsageReport), ModelError> {
        let url = format!("{}/chat/completions", self.config.base_url);
        let body = serde_json::json!({
            "model": self.config.model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        });
        let prompt_chars = body.to_string().len();

        // Build a proxy-aware agent so Windows corporate proxies are respected.
        // `try_proxy_from_env` reads `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`.
        // Falls back to the global `ureq::post` agent if construction fails.
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(true)
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .build();

        let max_attempts = 3u32;
        let mut last_err: Option<String> = None;
        for attempt in 0..max_attempts {
            let req = agent
                .request("POST", &url)
                .set("Authorization", &format!("Bearer {}", self.config.api_key))
                .set("Content-Type", "application/json")
                .set("Accept", "application/json");
            let resp = req.send_json(body.clone());
            match resp {
                Ok(r) => {
                    let json: serde_json::Value = r
                        .into_json()
                        .map_err(|e| ModelError::BadResponse(format!("non-JSON reply: {e}")))?;
                    let content = json
                        .pointer("/choices/0/message/content")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .ok_or_else(|| {
                            ModelError::BadResponse("missing choices[0].message.content".into())
                        })?;
                    let usage = json.get("usage").map(|u| {
                        let num = |k: &str| u.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
                        UsageReport {
                            prompt_tokens: num("prompt_tokens"),
                            completion_tokens: num("completion_tokens"),
                            total_tokens: num("total_tokens"),
                            estimated: false,
                        }
                    });
                    // A present-but-empty usage block is no better than no
                    // block: fall back to the char estimate so the context
                    // meter never reads zero on a real call.
                    let usage = match usage {
                        Some(r) if r.total_tokens > 0 => r,
                        _ => UsageReport::estimate(prompt_chars, content.len()),
                    };
                    return Ok((content, usage));
                }
                Err(e) => {
                    // A bare "status code 400" never says WHICH field was
                    // rejected, so attach the endpoint's own error body
                    // (Anthropic returns `{"error":{"message":...}}`).
                    // The "status code NNN" prefix is kept verbatim:
                    // `is_transient_transport` keys its retries off it.
                    let msg = match e {
                        ureq::Error::Status(code, resp) => {
                            let body = resp.into_string().unwrap_or_default();
                            let detail = error_snippet(&body);
                            if detail.trim().is_empty() {
                                format!("{url}: status code {code}")
                            } else {
                                format!("{url}: status code {code}: {detail}")
                            }
                        }
                        other => other.to_string(),
                    };
                    // Retry only transient transport errors (timeouts, connect
                    // failures like `os error 10060`, 429/5xx). BadResponse
                    // (200 with malformed JSON) is not retried — it will be
                    // surfaced via the outer `BadResponse` path.
                    let transient = is_transient_transport(&msg);
                    last_err = Some(msg.clone());
                    if !transient || attempt + 1 >= max_attempts {
                        return Err(ModelError::Transport(msg));
                    }
                    // Exponential backoff: 800ms, 1600ms, 3200ms (jitter-free
                    // to keep tests deterministic; production still sleeps).
                    let backoff_ms = 800u64 * (1u64 << attempt);
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    continue;
                }
            }
        }
        Err(ModelError::Transport(
            last_err.unwrap_or_else(|| "unknown transport error".into()),
        ))
    }
}

/// Pull the human-readable reason out of an endpoint error body:
/// `{"error":{"message":...}}` (Anthropic), `{"message":...}`, or the
/// raw first 300 chars as a fallback. Never includes request data, so
/// no secrets can leak through it — only the endpoint's own words.
fn error_snippet(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        for ptr in ["/error/message", "/message"] {
            if let Some(s) = v.pointer(ptr).and_then(|x| x.as_str()) {
                if !s.trim().is_empty() {
                    return s.chars().take(300).collect();
                }
            }
        }
    }
    body.chars().take(300).collect()
}

fn is_transient_transport(msg: &str) -> bool {    let m = msg.to_lowercase();
    // Windows connect timeout, ureq timeouts, and HTTP 429/5xx surfaced as
    // `Transport` by ureq (e.g. "status code 429", "status code 502").
    m.contains("10060")
        || m.contains("timed out")
        || m.contains("timeout")
        || m.contains("connection")
        || m.contains("temporarily")
        || m.contains("transport")
        || m.contains("network error")
        || m.contains("status code 429")
        || m.contains("status code 500")
        || m.contains("status code 502")
        || m.contains("status code 503")
        || m.contains("status code 504")
}

impl ModelProvider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        "openai-compatible"
    }

    fn decide(&self, ctx: &ContextView) -> Result<Decision, ModelError> {
        let content = self.complete(
            SYSTEM_PROMPT,
            &serde_json::to_string(ctx).unwrap_or_default(),
        )?;
        parse_decision_text(&content)
    }

    /// [`decide`] with real usage numbers from the endpoint's `usage`
    /// block (char/4 estimate when the endpoint omits it). Drives the
    /// context meter and auto-compaction.
    fn decide_reported(&self, ctx: &ContextView) -> (Result<Decision, ModelError>, UsageReport) {
        let user = serde_json::to_string(ctx).unwrap_or_default();
        match self.complete_with_usage(SYSTEM_PROMPT, &user) {
            Ok((content, usage)) => (parse_decision_text(&content), usage),
            Err(e) => (Err(e), UsageReport::estimate(user.len(), 0)),
        }
    }

    fn chat(&self, system: &str, user: &str) -> Result<String, ModelError> {
        self.complete(system, user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_execute_hypothesis_finish() {
        let d = parse_decision_text(
            r#"... {"decision":"execute","capability":"network.port_scan","target":"10.0.0.1","reason":"open ports unknown"} ..."#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::Execute {
                capability: "network.port_scan".into(),
                target: "10.0.0.1".into(),
                options: OptionSet::new(),
                reason: "open ports unknown".into(),
            }
        );
        let d = parse_decision_text(
            r#"{"decision":"hypothesis","statement":"BOLA?","confidence":"low"}"#,
        )
        .unwrap();
        assert!(matches!(d, Decision::CreateHypothesis { .. }));
        let d = parse_decision_text(r#"{"decision":"finish","reason":"done"}"#).unwrap();
        assert!(matches!(d, Decision::Finish { .. }));
    }

    #[test]
    fn action_summary_alias_parses_as_reason() {
        // The v2 system prompt names the execute preamble "action_summary";
        // either spelling must land in the user-facing reason.
        let d = parse_decision_text(
            r#"{"decision":"execute","capability":"network.port_scan","target":"10.0.0.1","options":{},"action_summary":"scanning for exposed services"}"#,
        )
        .unwrap();
        assert!(matches!(
            d,
            Decision::Execute { ref reason, .. } if reason == "scanning for exposed services"
        ));
    }

    #[test]
    fn narrate_decision_parses() {
        let d = parse_decision_text(
            r#"{"decision":"narrate","text":"Found exposed admin config at /rest/admin/application-configuration."}"#,
        )
        .unwrap();
        assert!(matches!(
            d,
            Decision::Narrate { ref text }
                if text.starts_with("Found exposed admin config")
        ));
        // Empty narrations are rejected like empty replies.
        assert!(parse_decision_text(r#"{"decision":"narrate","text":""}"#).is_err());
    }

    #[test]
    fn file_and_web_search_decisions_parse() {
        // file_read
        match parse_decision_text(
            r#"{"decision":"file_read","path":"bundle.js","action_summary":"read the app bundle"}"#,
        )
        .unwrap()
        {
            Decision::FileRead { path, grep, lines, reason } => {
                assert_eq!(path, "bundle.js");
                assert_eq!(grep, None);
                assert_eq!(lines, None);
                assert!(reason.contains("app bundle"));
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
        // file_write
        match parse_decision_text(
            r#"{"decision":"file_write","path":"poc.py","content":"print('x')","action_summary":"write poc"}"#,
        )
        .unwrap()
        {
            Decision::FileWrite { path, content, .. } => {
                assert_eq!(path, "poc.py");
                assert_eq!(content, "print('x')");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
        // Empty/absent fields are rejected.
        assert!(parse_decision_text(r#"{"decision":"file_read","path":""}"#).is_err());
        assert!(parse_decision_text(r#"{"decision":"file_read"}"#).is_err());
        // grep/lines are carried through
        match parse_decision_text(
            r#"{"decision":"file_read","path":"log.txt","grep":"admin","lines":200}"#,
        )
        .unwrap()
        {
            Decision::FileRead {
                path, grep, lines, ..
            } => {
                assert_eq!(path, "log.txt");
                assert_eq!(grep.as_deref(), Some("admin"));
                assert_eq!(lines, Some(200));
            }
            other => panic!("expected FileRead, got {other:?}"),
        }
        assert!(
            parse_decision_text(r#"{"decision":"file_write","path":"a.py","content":""}"#)
                .is_err()
        );
        // web_search
        match parse_decision_text(
            r#"{"decision":"web_search","query":"juice shop jwt"}"#,
        )
        .unwrap()
        {
            Decision::WebSearch { query, .. } => assert_eq!(query, "juice shop jwt"),
            other => panic!("expected WebSearch, got {other:?}"),
        }
    }

    #[test]
    fn parses_semantic_options_and_ignores_invented_fields() {
        // Valid scalar options are carried through; a model-invented
        // "provider" field has no representation and is simply ignored —
        // the runtime selects providers, never the model.
        let d = parse_decision_text(
            r#"{"decision":"execute","capability":"network.port_scan","target":"10.0.0.1","provider":"naabu","options":{"ports":"80,443","intensity":"normal","depth":3},"reason":"r"}"#,
        )
        .unwrap();
        match d {
            Decision::Execute { options, .. } => {
                assert_eq!(
                    options.get("ports"),
                    Some(&OptionValue::Str("80,443".into()))
                );
                assert_eq!(
                    options.get("intensity"),
                    Some(&OptionValue::Str("normal".into()))
                );
                assert_eq!(options.get("depth"), Some(&OptionValue::Num(3.0)));
                assert!(!options.contains_key("provider"));
            }
            other => panic!("expected execute, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_scalar_option_values() {
        // Arrays/objects cannot smuggle structured payloads (flags lists,
        // nested commands) through the options field.
        let err = parse_decision_text(
            r#"{"decision":"execute","capability":"network.port_scan","target":"x","options":{"flags":["--privileged","-O"]}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("flags"), "{err}");
    }

    #[test]
    fn parses_reply_decision() {
        let d = parse_decision_text(
            r#"{"decision":"reply","text":"Found 3 open ports. Want me to continue with service detection?"}"#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::Reply {
                text: "Found 3 open ports. Want me to continue with service detection?".into()
            }
        );
        // Empty reply text is a bad response, not a silent no-op.
        assert!(parse_decision_text(r#"{"decision":"reply","text":"  "}"#).is_err());
    }

    #[test]
    fn rejects_garbage_and_unknown_kinds() {
        assert!(parse_decision_text("no json here").is_err());
        assert!(parse_decision_text(r#"{"decision":"nuke"}"#).is_err());
        assert!(parse_decision_text(r#"{"decision":"execute"}"#).is_err());
    }

    #[test]
    fn parses_finding_and_vault_decisions() {
        let d = parse_decision_text(
            r#"{"decision":"report_finding","severity":"high","title":"SQLi in login","target":"10.0.0.1","detail":"error-based"} "#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::ReportFinding {
                severity: "High".into(),
                title: "SQLi in login".into(),
                target: "10.0.0.1".into(),
                detail: "error-based".into(),
            }
        );
        // Unknown severity degrades to Medium, never an error.
        let d = parse_decision_text(
            r#"{"decision":"report_finding","severity":"catastrophic","title":"X"}"#,
        )
        .unwrap();
        assert!(matches!(d, Decision::ReportFinding { severity, .. } if severity == "Medium"));
        let d = parse_decision_text(
            r#"{"decision":"update_finding","finding_id":3,"status":"confirmed"}"#,
        )
        .unwrap();
        assert_eq!(
            d,
            Decision::UpdateFinding {
                id: 3,
                status: "confirmed".into(),
                note: String::new(),
            }
        );
        assert!(parse_decision_text(r#"{"decision":"update_finding"}"#).is_err());
        let d = parse_decision_text(
            r#"{"decision":"vault_store","key":"db_password","value":"s3cr3t","kind":"password","source":"env"}"#,
        )
        .unwrap();
        assert!(matches!(d, Decision::VaultStore { .. }));
        assert!(parse_decision_text(r#"{"decision":"vault_store","key":"k"}"#).is_err());
        let d = parse_decision_text(r#"{"decision":"vault_recall","query":"db_password"}"#).unwrap();
        assert_eq!(
            d,
            Decision::VaultRecall {
                query: "db_password".into()
            }
        );
        assert!(parse_decision_text(r#"{"decision":"report_finding"}"#).is_err());
    }

    #[test]
    fn usage_estimate_scales_with_chars() {
        let r = UsageReport::estimate(4000, 400);
        assert!(r.estimated);
        assert_eq!(r.prompt_tokens, 1000);
        assert_eq!(r.completion_tokens, 100);
        assert_eq!(r.total_tokens, 1100);
    }

    #[test]
    fn error_snippet_extracts_endpoint_reason() {
        let s = error_snippet(r#"{"type":"error","error":{"type":"invalid_request_error","message":"temperature may only be set to 1.0 when thinking is enabled"}}"#);
        assert!(s.contains("temperature may only be set to 1.0"));
        let s = error_snippet(r#"{"message":"model not found"}"#);
        assert_eq!(s, "model not found");
        // Non-JSON bodies pass through truncated.
        let s = error_snippet(&"x".repeat(500));
        assert_eq!(s.len(), 300);
        assert_eq!(error_snippet(""), "");
    }

    #[test]
    fn stub_replays_then_finishes() {
        let stub = StubProvider::finish_now();
        let ctx = ContextView {
            target: "x".into(),
            step: 0,
            autonomous: false,
            conversation: vec![],
            available_capabilities: vec![],
            unavailable_count: 0,
            observations: vec![],
            recent_evidence: vec![],
            narrations: vec![],
            prior_actions: vec![],
            capability_schemas: vec![],
            last_error: None,
            findings: vec![],
            vault_keys: vec![],
            vault_values: vec![],
            context_note: None,
        };
        assert!(matches!(
            stub.decide(&ctx).unwrap(),
            Decision::Finish { .. }
        ));
    }

    #[test]
    fn config_trims_trailing_slashes_off_base_url() {
        // from_env is covered against fake environments in infra::config;
        // here we only assert pure construction behavior (no env access).
        let cfg = OpenAiConfig {
            base_url: "https://example.com/v1".into(),
            api_key: "k".into(),
            model: "m".into(),
            timeout_secs: 60,
        };
        let p = OpenAiCompatibleProvider::new(cfg);
        assert_eq!(p.name(), "openai-compatible");
    }
}
