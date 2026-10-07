//! Phase 2: the ContextManager — budgeted, relevance-filtered model context.
//!
//! The investigation loop records everything (actions, hypotheses, parsed
//! observations); the ContextManager decides what the model *sees* on each
//! step. Selection signals in Phase 2:
//!
//! * **Token budgeting** — a char-approximated ceiling (~4 chars â‰ˆ 1 token)
//!   on the serialized decision prompt, so long investigations cannot bloat
//!   context until the model degrades.
//! * **Recency filtering** — within each category the newest records win
//!   (the freshest state is the most relevant while iterating).
//! * **Deduplication** — identical observation summaries collapse; tools
//!   re-run on overlapping scope must not pay context twice.
//! * **Never-elided essentials** — target, step, the capability action
//!   space, and the last error always reach the model. A model that cannot
//!   see what it may do, or why its last action failed, cannot recover.
//!
//! Richer relevance (world-model affinity, hypothesis linkage) arrives with
//! Phase 3/6; the [`ContextManager`] interface stays the same.
//!
//! Purity: recording and selection are pure — no I/O, no events, no clocks.
//! The runtime decides when to record and which events to emit.

use serde::{Deserialize, Serialize};

use super::model::ContextView;
use super::runtime::Target;

/// One normalized finding from a tool run. Parsers (Phase 5) produce these;
/// raw scanner output never reaches the model directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub id: usize,
    /// The asset the observation is about (host, URL, path, ...).
    pub target: String,
    /// Human- and model-readable one-liner, e.g. "10.0.0.1 port 22 open (ssh)".
    pub summary: String,
    /// Capability that produced it, e.g. "network.port_scan".
    pub source: String,
    /// Investigation step at which it was recorded.
    pub step: usize,
}

/// One registry finding, reported by the model via `report_finding`.
/// Unlike observations (distilled tool output that budgets and compaction
/// may elide), findings are NEVER elided from the view: the model must
/// not lose track of confirmed vulnerabilities in a long investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: usize,
    /// Critical | High | Medium | Low | Info (normalized at parse).
    pub severity: String,
    pub title: String,
    /// The asset the finding is about.
    pub target: String,
    /// Capability that produced the evidence, e.g. "web.vulnerability_scan".
    pub source: String,
    /// What/where/impact in a few sentences.
    pub detail: String,
    /// open | confirmed | false_positive.
    pub status: String,
    /// Investigation step at which it was reported.
    pub step_found: usize,
    /// Investigation step of the last status/detail change.
    pub step_updated: usize,
}

/// A validated execute decision. Phase 4 executes these for real; until
/// then they record that the loop resolved capability → provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {    pub step: usize,
    pub capability: String,
    pub provider: String,
    pub target: String,
    pub reason: String,
    /// Did the execution actually produce usable coverage? `false` for
    /// failed runs and for exit-0-but-ineffective runs (sqlmap "no
    /// parameter(s) found", trivy FATAL on a URL target). The planner
    /// only counts effective actions as resolving an unknown — an
    /// ineffective run must not let the investigation declare victory.
    #[serde(default = "default_true")]
    pub effective: bool,
}

fn default_true() -> bool {
    true
}

/// Char-approximated context ceiling for one decision prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBudget {
    /// Maximum serialized characters (~4 chars â‰ˆ 1 token).
    pub max_chars: usize,
}

impl Default for TokenBudget {
    fn default() -> Self {
        // ≈ 12k tokens — generous enough that payload-verification tools
        // (http.request bodies, rendered SSTI/SQLi output) reach the model
        // in an analyzable form, while still eliding long before provider
        // context limits.
        Self { max_chars: 48_000 }
    }
}

/// What the budget cost the model this step (telemetry for tests/debug).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetReport {
    /// Serialized size of the final view.
    pub total_chars: usize,
    pub elided_observations: usize,
    pub elided_evidence: usize,
    pub elided_narrations: usize,
    pub elided_actions: usize,
}

/// Investigation memory + the selection policy that turns it into a
/// [`ContextView`]. One instance per investigation; the runtime owns it.
#[derive(Debug, Clone, Default)]
pub struct ContextManager {
    observations: Vec<Observation>,
    actions: Vec<ActionRecord>,
    last_error: Option<String>,
    budget: TokenBudget,
    /// User/assistant turns (unified chat+agent loop). Unbounded: the
    /// model sees the full dialogue verbatim. Context-overflow handling
    /// (compaction) is a future concern, not a silent truncation here.
    conversation: Vec<crate::agent::model::ChatTurn>,
    /// Raw (truncated) tool outputs — the undistilled evidence the model
    /// sees alongside parsed observations. Ring buffer: newest
    /// executions win, capped in entries and per-entry chars.
    evidence: Vec<EvidenceEntry>,
    /// Updates the model already sent to the user this session
    /// (`narrate` decisions and turn-ending replies). Without this the
    /// model cannot tell what the user already knows and re-announces
    /// the same finding after every tool call.
    narrations: Vec<String>,
    /// Session findings registry (model-reported). Never elided from
    /// the view and never summarized away by compaction.
    findings: Vec<Finding>,
    /// Vault KEY NAMES visible in context (values never live here).
    vault_keys: Vec<String>,
    /// Recalled vault values for the NEXT decision only (`key=value`
    /// lines). Cleared by the runtime after one decision (least
    /// exposure); never persisted, never emitted.
    vault_values: Vec<String>,
    /// Set when the conversation was compacted: the view carries a note
    /// pointing the model at the summary turn.
    compacted: bool,
    /// How many times auto/manual compaction ran this session.
    pub compaction_count: usize,
}

/// One raw tool output kept for model visibility.
#[derive(Debug, Clone, PartialEq)]
struct EvidenceEntry {
    tool_id: String,
    target: String,
    output: String,
}

/// Per-entry raw-output cap (chars). Long outputs keep their head —
/// findings and status lines come first in every tool's format. Raised
/// for evidence-heavy tools the model needs to reason over (response
/// bodies, payload render results) rather than just acknowledge.
const EVIDENCE_ENTRY_CAP: usize = 12_000;
/// How many raw outputs ride the context. Newest last.
const MAX_EVIDENCE_ENTRIES: usize = 10;
/// Observations retained across a compaction. Findings carry the durable
/// conclusions; observations past this cap are expendable history.
const MAX_OBSERVATIONS_AFTER_COMPACT: usize = 50;
/// Loopback/HTTP requests are payload verification targets: the rendered
/// body often sits mid-page, so these get the full allowance.
const EVIDENCE_FULL_CAP_TOOL: &str = "medusa-http";
/// How many user-facing updates the model remembers sending.
const MAX_NARRATIONS: usize = 15;

fn evidence_line(e: &EvidenceEntry) -> String {
    format!("[{}] {}:\n{}", e.tool_id, e.target, e.output)
}

impl ContextManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_budget(budget: TokenBudget) -> Self {
        Self {
            budget,
            ..Self::default()
        }
    }

    /// Record a parsed observation. Exact-duplicate summaries are collapsed
    /// (the first occurrence is kept). Returns the observation id.
    pub fn add_observation(
        &mut self,
        target: &str,
        summary: &str,
        source: &str,
        step: usize,
    ) -> usize {
        if let Some(existing) = self.observations.iter().find(|o| o.summary == summary) {
            return existing.id;
        }
        let id = self.observations.len() + 1;
        self.observations.push(Observation {
            id,
            target: target.to_string(),
            summary: summary.to_string(),
            source: source.to_string(),
            step,
        });
        id
    }

    /// Record a validated execute decision.
    pub fn add_action(
        &mut self,
        step: usize,
        capability: String,
        provider: String,
        target: String,
        reason: String,
        effective: bool,
    ) {
        self.actions.push(ActionRecord {
            step,
            capability,
            provider,
            target,
            reason,
            effective,
        });
    }

    /// Feedback channel for self-correction: policy rejections and model
    /// errors. Always included in the next view.
    pub fn set_last_error(&mut self, error: Option<String>) {
        self.last_error = error;
    }

    /// Open a turn: records the user message with an empty assistant
    /// reply. [`Self::end_turn`] fills the reply when the turn completes.
    pub fn begin_turn(&mut self, user: &str) {
        self.conversation.push(crate::agent::model::ChatTurn {
            user: user.to_string(),
            assistant: String::new(),
        });
    }

    /// Close the turn opened by [`Self::begin_turn`] with the assistant
    /// text that ended it (reply or finish reason).
    pub fn end_turn(&mut self, assistant: &str) {
        if let Some(last) = self.conversation.last_mut() {
            last.assistant = assistant.to_string();
        }
    }

    /// The most recent turn, if any. Used to dedupe session replay.
    pub fn last_turn(&self) -> Option<&crate::agent::model::ChatTurn> {
        self.conversation.last()
    }

    /// Full conversation (oldest first). Used for compaction materials
    /// and window estimates — never serialized to session records.
    pub fn conversation(&self) -> &[crate::agent::model::ChatTurn] {
        &self.conversation
    }

    /// Mark a replayed compaction (session reload): the model sees the
    /// continuity note without a new summary turn being fabricated.
    pub fn note_replayed_compaction(&mut self) {
        if !self.compacted {
            self.compacted = true;
            self.compaction_count += 1;
        }
    }

    /// Record one tool's raw output for model visibility. Truncated to
    /// the entry cap (head kept) unless the tool is a payload-verification
    /// tool that gets the full allowance; only the newest
    /// [`MAX_EVIDENCE_ENTRIES`] executions are retained. Empty outputs
    /// are skipped — the empty-success observation covers that case.
    pub fn add_evidence(&mut self, tool_id: &str, target: &str, output: &str) {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            return;
        }
        let cap = if tool_id == EVIDENCE_FULL_CAP_TOOL {
            EVIDENCE_ENTRY_CAP
        } else {
            EVIDENCE_ENTRY_CAP / 2
        };
        let mut cut = cap.min(trimmed.len());
        while cut > 0 && !trimmed.is_char_boundary(cut) {
            cut -= 1;
        }
        let output = if cut < trimmed.len() {
            format!(
                "{}\n... [truncated, {} chars total]",
                &trimmed[..cut],
                trimmed.len()
            )
        } else {
            trimmed.to_string()
        };
        self.evidence.push(EvidenceEntry {
            tool_id: tool_id.to_string(),
            target: target.to_string(),
            output,
        });
        let overflow = self.evidence.len().saturating_sub(MAX_EVIDENCE_ENTRIES);
        if overflow > 0 {
            self.evidence.drain(0..overflow);
        }
    }

    /// Record an update sent to the user (narrate decision or turn-end
    /// reply). The model sees these so it does not re-announce findings
    /// it already reported. Newest kept, bounded.
    pub fn add_narration(&mut self, text: &str) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        self.narrations.push(trimmed.to_string());
        let overflow = self.narrations.len().saturating_sub(MAX_NARRATIONS);
        if overflow > 0 {
            self.narrations.drain(0..overflow);
        }
    }

    fn recent_conversation(&self) -> Vec<crate::agent::model::ChatTurn> {
        self.conversation.clone()
    }

    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Record a model-reported finding. Same title+target collapses to
    /// an update (detail refreshed, step bumped) so re-reporting never
    /// duplicates the registry. Returns the finding id.
    pub fn add_finding(
        &mut self,
        severity: &str,
        title: &str,
        target: &str,
        source: &str,
        detail: &str,
        step: usize,
    ) -> usize {
        if let Some(existing) = self
            .findings
            .iter_mut()
            .find(|f| f.title == title && f.target == target)
        {
            if !detail.trim().is_empty() {
                existing.detail = detail.to_string();
            }
            existing.severity = severity.to_string();
            existing.step_updated = step;
            return existing.id;
        }
        let id = self.findings.len() + 1;
        self.findings.push(Finding {
            id,
            severity: severity.to_string(),
            title: title.to_string(),
            target: target.to_string(),
            source: source.to_string(),
            detail: detail.to_string(),
            status: "open".to_string(),
            step_found: step,
            step_updated: step,
        });
        id
    }

    /// Re-insert a finding with its persisted id (session replay). Used
    /// only by rehydration; live reporting goes through `add_finding`.
    pub fn replay_finding(&mut self, finding: Finding) {
        if self.findings.iter().any(|f| f.id == finding.id) {
            return;
        }
        self.findings.push(finding);
        self.findings.sort_by_key(|f| f.id);
    }

    /// Change a finding's status. Returns false for an unknown id (the
    /// runtime feeds that back to the model as a correction).
    pub fn update_finding(&mut self, id: usize, status: &str, step: usize) -> bool {
        if let Some(f) = self.findings.iter_mut().find(|f| f.id == id) {
            f.status = status.to_string();
            f.step_updated = step;
            true
        } else {
            false
        }
    }

    /// One line per registry finding for the view. The FULL list rides
    /// every view — findings are never budgeted or elided.
    fn finding_lines(&self) -> Vec<String> {
        self.findings
            .iter()
            .map(|f| {
                let detail = if f.detail.trim().is_empty() {
                    String::new()
                } else {
                    format!(" — {}", f.detail)
                };
                format!(
                    "F{} [{}|{}] {} ({}){}",
                    f.id, f.severity, f.status, f.title, f.target, detail
                )
            })
            .collect()
    }

    /// Advertise vault key names to the model (values never enter the
    /// ContextManager — they ride one decision via `recall_vault_value`).
    pub fn set_vault_keys(&mut self, keys: Vec<String>) {
        self.vault_keys = keys;
    }

    /// Stage recalled `key=value` lines for the NEXT view only. The
    /// runtime clears them after one decision.
    pub fn recall_vault_value(&mut self, key: &str, value: &str) {
        self.vault_values.retain(|l| !l.starts_with(&format!("{key}=")));
        self.vault_values.push(format!("{key}={value}"));
    }

    pub fn clear_vault_values(&mut self) {
        self.vault_values.clear();
    }

    /// Compact the conversation: replace older turns with a model-written
    /// summary turn, drop the raw evidence ring (already distilled into
    /// observations/findings), and cap observations to the newest
    /// `MAX_OBSERVATIONS_AFTER_COMPACT`. Findings, vault keys, narrations,
    /// and actions survive verbatim — compaction must never lose track
    /// of what was confirmed or what the user was told.
    pub fn compact(&mut self, summary: &str, keep_turns: usize) {
        let keep = keep_turns.min(self.conversation.len());
        let tail: Vec<crate::agent::model::ChatTurn> =
            self.conversation[self.conversation.len() - keep..].to_vec();
        self.conversation = Vec::with_capacity(tail.len() + 1);
        self.conversation.push(crate::agent::model::ChatTurn {
            user: "[Earlier conversation compacted — read the assistant summary, then continue from the turns below.]".to_string(),
            assistant: summary.to_string(),
        });
        self.conversation.extend(tail);
        self.evidence.clear();
        let overflow = self
            .observations
            .len()
            .saturating_sub(MAX_OBSERVATIONS_AFTER_COMPACT);
        if overflow > 0 {
            self.observations.drain(0..overflow);
        }
        self.compacted = true;
        self.compaction_count += 1;
    }

    pub fn was_compacted(&self) -> bool {
        self.compacted
    }

    pub fn actions(&self) -> &[ActionRecord] {
        &self.actions
    }

    /// Build the budgeted view for one model call.
    ///
    /// Essentials (target, step, capabilities, last error) are never
    /// elided. The remaining budget splits across raw evidence (the
    /// ground truth), observations (the distillate), and prior actions
    /// (the anti-loop record). Within a category the newest records win
    /// and the selection is presented chronologically with an elision
    /// marker so the model knows older history exists.
    pub fn build_view(
        &self,
        target: &Target,
        step: usize,
        available_capabilities: Vec<String>,
        unavailable_count: usize,
    ) -> (ContextView, BudgetReport) {
        self.build_view_with_schemas(
            target,
            step,
            available_capabilities,
            unavailable_count,
            Vec::new(),
        )
    }

    /// [`build_view`] with the semantic option schemas for available
    /// capabilities, so the model knows which options it may pass.
    pub fn build_view_with_schemas(
        &self,
        target: &Target,
        step: usize,
        available_capabilities: Vec<String>,
        unavailable_count: usize,
        capability_schemas: Vec<String>,
    ) -> (ContextView, BudgetReport) {
        let essentials = target.address.len()
            + step.to_string().len()
            + unavailable_count.to_string().len()
            + available_capabilities
                .iter()
                .map(|c| c.len() + 8)
                .sum::<usize>()
            + capability_schemas
                .iter()
                .map(|s| s.len() + 8)
                .sum::<usize>()
            + self.last_error.as_ref().map_or(0, |e| e.len() + 24)
            + 160; // JSON skeleton, field names, slack

        let remaining = self.budget.max_chars.saturating_sub(essentials);
        let mut report = BudgetReport::default();

        let observations = select_newest(
            self.observations.iter().map(observation_line),
            remaining * 25 / 100,
            &mut report.elided_observations,
        );
        let prior_actions = select_newest(
            self.actions.iter().map(action_line),
            remaining * 25 / 100,
            &mut report.elided_actions,
        );
        // Raw tool output gets the largest share: it is the ground truth
        // the observations merely summarize.
        let recent_evidence = select_newest(
            self.evidence.iter().map(evidence_line),
            remaining * 40 / 100,
            &mut report.elided_evidence,
        );
        // What the user was already told — small but essential for not
        // repeating narrations.
        let narrations = select_newest(
            self.narrations.iter().cloned(),
            remaining * 10 / 100,
            &mut report.elided_narrations,
        );

        let view = ContextView {
            target: target.address.clone(),
            step,
            autonomous: false,
            conversation: self.recent_conversation(),
            available_capabilities,
            unavailable_count,
            observations,
            recent_evidence,
            narrations,
            prior_actions,
            capability_schemas,
            last_error: self.last_error.clone(),
            findings: self.finding_lines(),
            vault_keys: self.vault_keys.clone(),
            vault_values: self.vault_values.clone(),
            context_note: self.compacted.then(|| {
                format!(
                    "The conversation was compacted {} time(s); older turns are summarized in the first conversation turn. The findings registry above is complete and current — trust it over the summary for what is confirmed.",
                    self.compaction_count
                )
            }),
        };
        report.total_chars = serde_json::to_string(&view)
            .map(|s| s.len())
            .unwrap_or_default();
        (view, report)
    }
}

fn observation_line(o: &Observation) -> String {
    format!("O{}: {}", o.id, o.summary)
}

fn action_line(a: &ActionRecord) -> String {
    format!("{} on {} via {}", a.capability, a.target, a.provider)
}

/// Ranked-order selection under `budget` chars: keep items in the given
/// order (highest priority first) while they fit; drop the rest with a
/// trailing omission marker.
#[cfg(test)]
fn select_first(items: Vec<String>, budget: usize, elided_out: &mut usize) -> Vec<String> {
    if items.is_empty() {
        return Vec::new();
    }
    let total = items.len();
    let mut out = Vec::new();
    let mut used = 0usize;
    let mut kept_all = true;
    for line in items {
        let cost = line.len() + 8;
        if !out.is_empty() && used + cost > budget {
            kept_all = false;
            break;
        }
        used += cost;
        out.push(line);
    }
    if !kept_all {
        *elided_out = total - out.len();
        out.push(format!(
            "[... {elided_out} lower-priority suggestions omitted ...]"
        ));
    } else {
        *elided_out = 0;
    }
    out
}

/// Newest-wins selection under `budget` chars. The single newest item is
/// always kept (a non-empty category must not vanish silently); older items
/// are kept while they fit. Result is chronological with a leading elision
/// marker when anything was dropped.
fn select_newest<I>(lines: I, budget: usize, elided_out: &mut usize) -> Vec<String>
where
    I: Iterator<Item = String>,
{
    let all: Vec<String> = lines.collect();
    if all.is_empty() {
        return Vec::new();
    }
    let mut kept: Vec<&String> = Vec::new();
    let mut used = 0usize;
    for line in all.iter().rev() {
        let cost = line.len() + 8; // quotes, comma, overhead
        if used + cost > budget && !kept.is_empty() {
            break;
        }
        used += cost;
        kept.push(line);
    }
    *elided_out = all.len() - kept.len();
    kept.reverse(); // chronological
    let mut out = Vec::with_capacity(kept.len() + 1);
    if *elided_out > 0 {
        out.push(format!("[... {elided_out} older elided ...]"));
    }
    out.extend(kept.into_iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::new("10.0.0.1")
    }

    fn caps() -> Vec<String> {
        vec!["network.port_scan".to_string(), "http.probe".to_string()]
    }

    #[test]
    fn evidence_truncates_and_rides_the_view() {
        let mut cm = ContextManager::default();
        // Long output keeps its head (scanners get half the allowance)...
        let long = "FINDING one\n".repeat(1_000); // ~12k chars > 6k scanner cap
        cm.add_evidence("nuclei", "10.0.0.1", &long);
        assert_eq!(cm.evidence.len(), 1);
        assert!(cm.evidence[0].output.contains("FINDING one"));
        assert!(cm.evidence[0].output.contains("[truncated,"));
        // ...empty output is skipped...
        cm.add_evidence("httpx", "10.0.0.1", "   ");
        assert_eq!(cm.evidence.len(), 1);
        // ...and only the newest 10 executions are kept.
        for i in 0..12 {
            cm.add_evidence("httpx", "10.0.0.1", &format!("run {i}"));
        }
        assert_eq!(cm.evidence.len(), 10);
        assert!(cm.evidence[0].output.contains("run 2"));
        assert!(cm.evidence[9].output.contains("run 11"));
        // The evidence reaches the model's view.
        let (view, _) = cm.build_view(&target(), 0, caps(), 0);
        assert!(view
            .recent_evidence
            .iter()
            .any(|e| e.contains("[httpx] 10.0.0.1") && e.contains("run 11")));
        // Payload-verification tools get the full allowance (the whole
        // rendered body), scanners get half.
        cm.add_evidence("medusa-http", "10.0.0.1", &("X".repeat(30_000)));
        assert!(cm.evidence.last().unwrap().output.len() >= 12_000);
    }

    #[test]
    fn default_budget_fits_a_full_investigation() {
        let mut cm = ContextManager::new();
        for i in 0..25 {
            cm.add_action(
                i,
                "network.port_scan".into(),
                "nmap".into(),
                "10.0.0.1".into(),
                format!("r{i}"),
                true,
            );
            cm.add_observation(
                "10.0.0.1",
                &format!("port {} open", 1000 + i),
                "network.port_scan",
                i,
            );
        }
        let (view, report) = cm.build_view(&target(), 25, caps(), 9);
        assert_eq!(report.elided_observations, 0);
        assert_eq!(report.elided_actions, 0);
        assert_eq!(view.observations.len(), 25);
        assert_eq!(view.prior_actions.len(), 25);
        assert!(report.total_chars <= TokenBudget::default().max_chars);
    }

    #[test]
    fn tight_budget_keeps_newest_and_marks_elision() {
        let mut cm = ContextManager::with_budget(TokenBudget { max_chars: 1_200 });
        for i in 0..60 {
            cm.add_observation(
                "10.0.0.1",
                &format!("observation number {i} with some detail"),
                "network.port_scan",
                i,
            );
        }
        let (view, report) = cm.build_view(&target(), 30, caps(), 9);
        assert!(report.elided_observations > 0);
        assert!(report.elided_observations < 60);
        // elision marker is the first entry, selection is chronological after it
        assert!(view.observations[0].starts_with("[..."));
        let selected = &view.observations[1..];
        let last = selected.last().unwrap();
        assert!(
            last.contains("observation number 59"),
            "newest must survive: {last}"
        );
        // chronological: numbers ascending
        let nums: Vec<usize> = selected
            .iter()
            .filter_map(|l| l.split(' ').nth_back(1).and_then(|n| n.parse().ok()))
            .collect();
        let mut sorted = nums.clone();
        sorted.sort_unstable();
        assert_eq!(nums, sorted);
        assert_eq!(report.elided_observations + selected.len(), 60);
    }

    #[test]
    fn newest_item_survives_even_with_zero_category_budget() {
        let mut cm = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        cm.add_observation("10.0.0.1", "the only observation", "s", 1);
        let (view, _report) = cm.build_view(&target(), 1, caps(), 0);
        // Essentials plus at least the newest entry per non-empty category.
        assert_eq!(view.observations.len(), 1);
        assert!(view.observations[0].contains("the only observation"));
    }

    #[test]
    fn capabilities_are_never_elided() {
        let cm = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        let many: Vec<String> = (0..61)
            .map(|i| format!("category.capability_{i}"))
            .collect();
        let (view, _) = cm.build_view(&target(), 1, many.clone(), 5);
        assert_eq!(view.available_capabilities, many);
    }

    #[test]
    fn last_error_always_reaches_the_model() {
        let mut cm = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        cm.set_last_error(Some("no provider for cloud.posture_audit".into()));
        let (view, _) = cm.build_view(&target(), 1, caps(), 0);
        assert_eq!(
            view.last_error.as_deref(),
            Some("no provider for cloud.posture_audit")
        );
    }

    #[test]
    fn duplicate_observation_summaries_collapse() {
        let mut cm = ContextManager::new();
        let a = cm.add_observation("10.0.0.1", "port 22 open", "network.port_scan", 1);
        let b = cm.add_observation("10.0.0.1", "port 22 open", "network.port_scan", 4);
        assert_eq!(a, b, "duplicate must return the original id");
        assert_eq!(cm.observations().len(), 1);
        let (view, _) = cm.build_view(&target(), 5, caps(), 0);
        assert_eq!(view.observations.len(), 1);
    }

    #[test]
    fn action_lines_carry_target_and_provider() {
        let mut cm = ContextManager::new();
        cm.add_action(
            2,
            "network.port_scan".into(),
            "nmap".into(),
            "10.0.0.9".into(),
            "unknown services".into(),
            true,
        );
        let (view, _) = cm.build_view(&target(), 3, caps(), 0);
        assert_eq!(
            view.prior_actions,
            vec!["network.port_scan on 10.0.0.9 via nmap".to_string()]
        );
    }

    #[test]
    fn ids_are_stable_and_sequential() {
        let mut cm = ContextManager::new();
        assert_eq!(cm.add_observation("t", "a", "s", 0), 1);
        assert_eq!(cm.add_observation("t", "b", "s", 0), 2);
    }

    #[test]
    fn findings_dedupe_and_update() {
        let mut cm = ContextManager::new();
        let a = cm.add_finding("High", "SQLi in login", "10.0.0.1", "web.scan", "error-based", 3);
        assert_eq!(a, 1);
        // Same title+target re-report updates instead of duplicating.
        let b = cm.add_finding("Critical", "SQLi in login", "10.0.0.1", "web.scan", "confirmed blind", 5);
        assert_eq!(b, 1);
        assert_eq!(cm.findings().len(), 1);
        assert_eq!(cm.findings()[0].severity, "Critical");
        assert_eq!(cm.findings()[0].step_updated, 5);
        // Status transitions work; unknown ids fail loudly.
        assert!(cm.update_finding(1, "confirmed", 6));
        assert_eq!(cm.findings()[0].status, "confirmed");
        assert!(!cm.update_finding(99, "confirmed", 6));
        // The full registry rides the view even on a zero budget.
        let starved = ContextManager::with_budget(TokenBudget { max_chars: 0 });
        let mut starved = starved;
        starved.add_finding("Low", "banner", "10.0.0.1", "s", "", 1);
        let (view, _) = starved.build_view(&target(), 1, caps(), 0);
        assert_eq!(view.findings.len(), 1);
        assert!(view.findings[0].contains("F1"));
        assert!(view.context_note.is_none());
    }

    #[test]
    fn replay_finding_restores_ids_without_dupes() {
        let mut cm = ContextManager::new();
        cm.replay_finding(Finding {
            id: 2,
            severity: "High".into(),
            title: "RCE".into(),
            target: "10.0.0.1".into(),
            source: "s".into(),
            detail: "d".into(),
            status: "confirmed".into(),
            step_found: 4,
            step_updated: 7,
        });
        cm.replay_finding(Finding {
            id: 2,
            severity: "High".into(),
            title: "RCE".into(),
            target: "10.0.0.1".into(),
            source: "s".into(),
            detail: "d".into(),
            status: "confirmed".into(),
            step_found: 4,
            step_updated: 7,
        });
        assert_eq!(cm.findings().len(), 1);
        assert_eq!(cm.findings()[0].status, "confirmed");
    }

    #[test]
    fn compact_keeps_findings_vault_and_tail() {
        let mut cm = ContextManager::new();
        for i in 0..6 {
            cm.begin_turn(&format!("user {i}"));
            cm.end_turn(&format!("assistant {i}"));
            cm.add_observation("10.0.0.1", &format!("obs {i}"), "s", i);
            cm.add_evidence("nmap", "10.0.0.1", &format!("raw {i}"));
        }
        cm.add_finding("High", "SQLi", "10.0.0.1", "web.scan", "d", 5);
        cm.set_vault_keys(vec!["db_password [password]".into()]);
        cm.add_narration("told the user about SQLi");
        cm.compact("summary of six turns", 2);
        // Summary turn + last two verbatim turns.
        assert_eq!(cm.conversation.len(), 3);
        assert!(cm.conversation[0].assistant.contains("summary of six turns"));
        assert_eq!(cm.conversation[1].user, "user 4");
        // Evidence dropped, findings/vault/narrations intact.
        assert!(cm.evidence.is_empty());
        assert_eq!(cm.findings().len(), 1);
        assert_eq!(cm.vault_keys.len(), 1);
        assert!(cm.was_compacted());
        assert_eq!(cm.compaction_count, 1);
        let (view, _) = cm.build_view(&target(), 6, caps(), 0);
        assert_eq!(view.findings.len(), 1);
        assert!(view.context_note.is_some());
        assert_eq!(view.vault_keys.len(), 1);
        assert_eq!(view.narrations.len(), 1);
    }

    #[test]
    fn vault_values_ride_one_view() {
        let mut cm = ContextManager::new();
        cm.recall_vault_value("db_password", "s3cr3t");
        let (view, _) = cm.build_view(&target(), 0, caps(), 0);
        assert_eq!(view.vault_values, vec!["db_password=s3cr3t".to_string()]);
        cm.clear_vault_values();
        let (view, _) = cm.build_view(&target(), 0, caps(), 0);
        assert!(view.vault_values.is_empty());
    }
}
