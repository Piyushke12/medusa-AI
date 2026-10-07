use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};

use medusa_lib::agent::{AgentRuntime, AgentSession, RuntimeHandle};
use medusa_lib::core::discovery::scan_environment;
use medusa_lib::infra::runner::RealCommandRunner;
use medusa_lib::infra::sessions::{SessionRecord, SessionSummary, SessionWriter, TimedRecord};
use medusa_lib::registry::{CapabilityRegistry, ToolRegistry};

// Same freshness window as the CLI (src/main.rs CACHE_TTL_SECS).
const ENV_TTL_SECS: i64 = 6 * 60 * 60;

// Actor-per-session worker: one thread + mailbox per conversation. The
// worker OWNS the AgentSession (context, world model, scope) and the
// session file — no shared mutable state, messages queue in order.

/// Messages a session worker accepts, in order.
enum WorkerMsg {
    /// A user chat message: runs one full agent turn.
    User(String),
    /// Swap the model provider (desktop provider switch): the worker
    /// rebuilds its model from the persisted config; takes effect from
    /// this session's NEXT turn.
    SwapModel,
    /// Manual compaction ("Compact now" button): summarize older turns
    /// immediately, same path as auto-compaction.
    CompactNow,
}

pub struct SessionWorker {
    tx: mpsc::Sender<WorkerMsg>,
    handle: RuntimeHandle,
    approval: Arc<AtomicBool>,
    /// Decision gate the runtime BLOCKS on after a high-risk rejection:
    /// `Some(true)`/`Some(false)` is the user's dialog answer. Without
    /// this the model retries before the user can click and every
    /// approval lands too late.
    gate: Arc<Mutex<Option<bool>>>,
    /// True while a turn is executing (surfaced on session switch so the
    /// UI can restore the "running" state of a background session).
    busy: Arc<AtomicBool>,
    /// Set when the worker thread exits (seen by `delete_session`, which
    /// must wait for the thread to release the session file — Windows
    /// refuses to delete a file with an open handle).
    exited: Arc<AtomicBool>,
}

/// Shared app state: the worker registry, the session the UI is watching
/// (workers emit ALL events tagged with their session id; the backend
/// forwards only the active session's events live, everything is
/// persisted), and the cached environment scan.
pub struct AppState {
    pub workers: Mutex<HashMap<String, SessionWorker>>,
    pub active: Arc<Mutex<Option<String>>>,
    pub env: Arc<Mutex<Option<medusa_lib::model::EnvironmentState>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            workers: Mutex::new(HashMap::new()),
            active: Arc::new(Mutex::new(None)),
            env: Arc::new(Mutex::new(None)),
        }
    }
}

/// Environment scan with memory + disk caching. HEAVY: spawns ~31
/// subprocess version checks, so callers must run it via
/// `tauri::async_runtime::spawn_blocking` (sync commands run on the
/// main thread and freeze the window).
fn env_state(
    cache: &Arc<Mutex<Option<medusa_lib::model::EnvironmentState>>>,
) -> medusa_lib::model::EnvironmentState {
    if let Some(e) = cache.lock().unwrap().clone() {
        return e;
    }
    if let Some(st) = medusa_lib::infra::cache::load_state() {
        if medusa_lib::infra::cache::state_is_fresh(
            &st,
            ENV_TTL_SECS,
            medusa_lib::infra::cache::now_unix(),
        ) {
            *cache.lock().unwrap() = Some(st.clone());
            return st;
        }
    }
    let tools = ToolRegistry::builtin();
    let caps = CapabilityRegistry::builtin();
    let runner = RealCommandRunner;
    let env = scan_environment(&tools, &caps, &runner);
    let _ = medusa_lib::infra::cache::save_state(&env);
    *cache.lock().unwrap() = Some(env.clone());
    env
}

/// Run the (possibly cached) environment scan off the main thread.
async fn env_async(
    state: &State<'_, AppState>,
) -> Result<medusa_lib::model::EnvironmentState, String> {
    let cache = state.env.clone();
    tauri::async_runtime::spawn_blocking(move || env_state(&cache))
        .await
        .map_err(|e| e.to_string())
}

fn doctor_info(env: &medusa_lib::model::EnvironmentState) -> DoctorInfo {
    let tools = ToolRegistry::builtin();
    let runner = RealCommandRunner;
    let doctor = medusa_lib::doctor::diagnose(&runner, env, tools.all().len());
    DoctorInfo {
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        tools_installed: env.installed_tool_count(),
        tools_total: tools.all().len(),
        caps_covered: env.available_capabilities().len(),
        caps_total: CapabilityRegistry::builtin().all().len(),
        issues: doctor.issues.iter().map(|i| i.message.clone()).collect(),
    }
}

fn tools_info(env: &medusa_lib::model::EnvironmentState) -> Vec<ToolInfo> {
    let tools = ToolRegistry::builtin();
    tools
        .all()
        .iter()
        .map(|t| {
            let st = env.tools.get(&t.id);
            ToolInfo {
                id: t.id.clone(),
                name: t.name.clone(),
                installed: st.map(|s| s.installed).unwrap_or(false),
                version: st.and_then(|s| s.version.clone()),
                caps: t.capabilities.clone(),
                healthy: st.map(|s| s.healthy).unwrap_or(false),
                category: format!("{:?}", t.category),
                description: t.description.clone(),
                path: st.and_then(|s| s.executable_path.clone()),
                docs_url: t.docs_url.clone(),
            }
        })
        .collect()
}

fn caps_info(env: &medusa_lib::model::EnvironmentState) -> Vec<CapInfo> {
    let tools = ToolRegistry::builtin();
    let caps = CapabilityRegistry::builtin();
    let available = env.available_capabilities();
    caps.all()
        .iter()
        .map(|c| {
            let providers: Vec<String> = tools
                .providers_of(&c.id)
                .iter()
                .map(|t| t.id.clone())
                .collect();
            CapInfo {
                id: c.id.clone(),
                description: c.description.clone(),
                importance: format!("{:?}", c.importance),
                providers,
                available: available.iter().any(|a| *a == c.id),
            }
        })
        .collect()
}

/* ---------- actor-per-session workers ---------- */

/// Persist one agent event into the session file (JSONL). Every event is
/// recorded for replay; the file is the source of truth when switching.
fn persist_event(
    writer: &mut SessionWriter,
    ev: &medusa_lib::agent::AgentEvent,
    turn_user: &str,
    turn_user_at: i64,
) {
    use medusa_lib::agent::AgentEvent;
    let record = match ev {
        AgentEvent::Reply { text } => SessionRecord::Chat {
            user: turn_user.to_string(),
            agent: text.clone(),
            user_time: turn_user_at,
        },
        AgentEvent::Narrated { text } => SessionRecord::Note { text: text.clone() },
        AgentEvent::ScopeGranted { target } => SessionRecord::Target {
            target: target.clone(),
        },
        AgentEvent::CapabilityRequested {
            capability,
            target,
            reason,
            model_secs,
            ..
        } => SessionRecord::Tool {
            cap: capability.clone(),
            target: target.clone(),
            reason: reason.clone(),
            model_secs: *model_secs,
        },
        AgentEvent::ProviderSelected { provider, .. } => SessionRecord::Provider {
            provider: provider.clone(),
        },
        AgentEvent::ToolExecuted {
            tool_id,
            success,
            timed_out,
            exit_code,
            output,
            tool_secs,
            ..
        } => SessionRecord::ToolDone {
            summary: format!(
                "{} {} (exit {})",
                tool_id,
                if *timed_out {
                    "timed out"
                } else if *success {
                    "ok"
                } else {
                    "failed"
                },
                exit_code
            ),
            output: output.clone(),
            tool_secs: *tool_secs,
        },
        AgentEvent::ObservationAdded { summary } => SessionRecord::Obs {
            text: summary.clone(),
        },
        AgentEvent::HypothesisAdded {
            id,
            statement,
            confidence,
        } => SessionRecord::Think {
            text: format!("H{id} [{confidence}]: {statement}"),
        },
        AgentEvent::ActionRejected { reason } => SessionRecord::Think {
            text: format!("rejected: {reason}"),
        },
        AgentEvent::ApprovalRequested { capability, reason } => SessionRecord::Think {
            text: format!("approval needed for `{capability}`: {reason}"),
        },
        AgentEvent::Error { message } => SessionRecord::Think {
            text: format!("Error: {message}"),
        },
        AgentEvent::FindingRecorded {
            id,
            severity,
            title,
            target,
            status,
            detail,
            step,
        } => SessionRecord::Finding {
            id: *id,
            severity: severity.clone(),
            title: title.clone(),
            target: target.clone(),
            status: status.clone(),
            detail: detail.clone(),
            step: *step,
        },
        AgentEvent::ContextUsage {
            used_tokens,
            limit_tokens,
            pct,
            estimated,
        } => SessionRecord::CtxUsage {
            used: *used_tokens,
            limit: *limit_tokens,
            pct: *pct,
            estimated: *estimated,
        },
        AgentEvent::Compacted {
            before_tokens,
            after_tokens,
            freed_tokens,
            fallback,
        } => SessionRecord::Compacted {
            before: *before_tokens,
            after: *after_tokens,
            freed: *freed_tokens,
            fallback: *fallback,
        },
        AgentEvent::VaultStored { key, kind, .. } => SessionRecord::VaultOp {
            op: "stored".to_string(),
            key: key.clone(),
            kind: kind.clone(),
        },
        AgentEvent::VaultRecalled { key } => SessionRecord::VaultOp {
            op: "recalled".to_string(),
            key: key.clone(),
            kind: String::new(),
        },
        _ => return, // lifecycle/status events are not replayed
    };
    let _ = writer.append(record);
}

/// Forward one event to the frontend, tagged with its session id.
fn emit_event(app: &tauri::AppHandle, session_id: &str, ev: &medusa_lib::agent::AgentEvent) {
    use medusa_lib::agent::AgentEvent;
    let payload = serde_json::to_string(&format!("{:?}", ev)).unwrap_or_default();
    let _ = app.emit(
        "agent-event",
        serde_json::json!({
            "type": event_type(ev),
            "session": session_id,
            "payload": payload,
            "summary": match ev {
                AgentEvent::Reply { text } => text.clone(),
                AgentEvent::Narrated { text } => text.clone(),
                AgentEvent::ScopeGranted { target } => format!("Scope: {target}"),
                AgentEvent::ObservationAdded { summary } => summary.clone(),
                AgentEvent::ToolExecuted { tool_id, success, timed_out, exit_code, .. } => format!("{} {} (exit {})", tool_id, if *timed_out { "timed out" } else if *success { "ok" } else { "failed" }, exit_code),
                AgentEvent::CapabilityRequested { capability, target, reason, .. } => format!("{} on {} — {}", capability, target, reason),
                AgentEvent::ProviderSelected { capability, provider } => format!("{} via {}", capability, provider),
                AgentEvent::HypothesisAdded { id, statement, confidence } => format!("H{} [{}]: {}", id, confidence, statement),
                AgentEvent::ActionRejected { reason } => format!("rejected: {}", reason),
                AgentEvent::ApprovalRequested { reason, .. } => reason.clone(),
                AgentEvent::Finished { reason } => reason.clone(),
                AgentEvent::StepStarted { step } => format!("Starting step {}", step + 1),
                AgentEvent::InvestigationStarted { target } => format!("Investigating {}", target),
                AgentEvent::ToolStarted { capability, provider } => format!("Running {} via {}…", provider, capability),
                AgentEvent::ToolFinished { capability, provider } => format!("{} via {} done", provider, capability),
                AgentEvent::Error { message } => message.clone(),
                AgentEvent::Status { message } => message.clone(),
                AgentEvent::ModelThinking => "Agent thinking.".to_string(),
                AgentEvent::FindingRecorded { severity, title, target, status, .. } => format!("[{severity}/{status}] {title} ({target})"),
                AgentEvent::ContextUsage { used_tokens, limit_tokens, pct, .. } => format!("context {used_tokens}/{limit_tokens} ({pct}%)"),
                AgentEvent::Compacted { before_tokens, after_tokens, freed_tokens, fallback } => format!("compacted{}: {before_tokens} → {after_tokens} (freed {freed_tokens})", if *fallback { " (fallback)" } else { "" }),
                AgentEvent::VaultStored { key, kind, refreshed } => format!("vault: {key} [{kind}] {}", if *refreshed { "refreshed" } else { "stored" }),
                AgentEvent::VaultRecalled { key } => format!("vault: recalled {key}"),
            },
            "capability": match ev {
                AgentEvent::CapabilityRequested { capability, .. } => Some(capability.clone()),
                AgentEvent::ToolExecuted { capability, .. } => Some(capability.clone()),
                _ => None,
            },
            "target": match ev {
                AgentEvent::CapabilityRequested { target, .. } => Some(target.clone()),
                AgentEvent::ToolExecuted { target, .. } => Some(target.clone()),
                _ => None,
            },
            "model_secs": match ev {
                AgentEvent::CapabilityRequested { model_secs, .. } => Some(*model_secs),
                _ => None,
            },
            "tool_secs": match ev {
                AgentEvent::ToolExecuted { tool_secs, .. } => Some(*tool_secs),
                _ => None,
            },
            "output": match ev {
                AgentEvent::ToolExecuted { output, .. } => Some(output.clone()),
                _ => None,
            },
            "ctx": match ev {
                AgentEvent::ContextUsage { used_tokens, limit_tokens, pct, estimated } => Some(serde_json::json!({
                    "used": used_tokens,
                    "limit": limit_tokens,
                    "pct": pct,
                    "estimated": estimated,
                })),
                _ => None,
            },
            "finding": match ev {
                AgentEvent::FindingRecorded { id, severity, title, target, status, detail, .. } => Some(serde_json::json!({
                    "id": id,
                    "severity": severity,
                    "title": title,
                    "target": target,
                    "status": status,
                    "detail": detail,
                })),
                _ => None,
            },
            "compact": match ev {
                AgentEvent::Compacted { before_tokens, after_tokens, freed_tokens, fallback } => Some(serde_json::json!({
                    "before": before_tokens,
                    "after": after_tokens,
                    "freed": freed_tokens,
                    "fallback": fallback,
                })),
                _ => None,
            },
            "vault_key": match ev {
                AgentEvent::VaultStored { key, kind, refreshed } => Some(serde_json::json!({
                    "op": "stored",
                    "key": key,
                    "kind": kind,
                    "refreshed": refreshed,
                })),
                AgentEvent::VaultRecalled { key } => Some(serde_json::json!({
                    "op": "recalled",
                    "key": key,
                })),
                _ => None,
            }
        }),
    );
}

/// Spawn the worker thread for one session. It owns the AgentSession and
/// the session file; user messages arrive via the channel one at a time.
fn spawn_worker(
    app: tauri::AppHandle,
    env: medusa_lib::model::EnvironmentState,
    session_id: String,
    mut writer: SessionWriter,
    active: Arc<Mutex<Option<String>>>,
) -> SessionWorker {
    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let handle = RuntimeHandle::default();
    let approval = Arc::new(AtomicBool::new(false));
    let gate: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let busy = Arc::new(AtomicBool::new(false));
    let exited = Arc::new(AtomicBool::new(false));
    let worker = SessionWorker {
        tx: tx.clone(),
        handle: handle.clone(),
        approval: Arc::clone(&approval),
        gate: Arc::clone(&gate),
        busy: Arc::clone(&busy),
        exited: Arc::clone(&exited),
    };
    let sid = session_id;
    let app = app;
    std::thread::spawn(move || {
        // Marks the worker exited even on panic, so `delete_session`
        // never waits forever for a dead thread's file handle.
        struct ExitGuard(Arc<AtomicBool>);
        impl Drop for ExitGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _exit = ExitGuard(exited);
        // Registries live inside the thread so references outlive the runtime.
        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let (model, _) = medusa_lib::cli::assess::select_model(&env);
        let file_cfg = medusa_lib::infra::config::load_file_config();
        let ctx_cfg = medusa_lib::infra::config::resolve_context_settings(&file_cfg, &|k| {
            std::env::var(k).ok()
        });
        let rt = AgentRuntime::new(model, &tools, &caps, &env)
            .with_handle(handle)
            .with_approval_flag(approval)
            .with_approval_gate(gate)
            .with_context_window(ctx_cfg.context_tokens)
            .with_compaction_threshold(ctx_cfg.compaction_threshold_pct)
            .with_compact_keep_turns(ctx_cfg.compact_keep_turns);
        let mut sess: AgentSession<'_, '_> = rt.session();
        // Reopened session (worker spawned after a restart): replay the
        // persisted records so the model regains scope, conversation, and
        // observations. New sessions load an empty/header-only file - a
        // no-op.
        if let Ok(records) = medusa_lib::infra::sessions::load_session(&sid) {
            sess.rehydrate(&records);
        }
        // Drain the mailbox in order; dropping the sender closes the loop.
        while let Ok(message) = rx.recv() {
            match message {
                WorkerMsg::SwapModel => {
                    // Provider switch: rebuild from the persisted config.
                    // The session's context, scope, and world model are
                    // untouched — only the brain changes.
                    let (model, _) = medusa_lib::cli::assess::select_model(&env);
                    rt.swap_model(model);
                }
                WorkerMsg::User(message) => {
                    busy.store(true, Ordering::SeqCst);
                    let sid = sid.clone();
                    let turn_user = message.clone();
                    // When this user message arrived — preserved on the Chat
                    // record so replay keeps the user bubble at send time.
                    let turn_user_at = medusa_lib::infra::sessions::now_ms();
                    // Persist the message itself immediately: a turn that never
                    // completes (Stop, crash, model failures) must not lose the
                    // user's words from the transcript.
                    let _ = writer.append(medusa_lib::infra::sessions::SessionRecord::User {
                        text: message.clone(),
                    });
                    sess.run_turn(&message, &mut |ev: medusa_lib::agent::AgentEvent| {
                        persist_event(&mut writer, &ev, &turn_user, turn_user_at);
                        let is_active = *active.lock().unwrap() == Some(sid.clone());
                        if is_active {
                            emit_event(&app, &sid, &ev);
                        }
                    });
                    busy.store(false, Ordering::SeqCst);
                }
                WorkerMsg::CompactNow => {
                    busy.store(true, Ordering::SeqCst);
                    let sid = sid.clone();
                    sess.compact_now(&mut |ev: medusa_lib::agent::AgentEvent| {
                        persist_event(&mut writer, &ev, "", 0);
                        let is_active = *active.lock().unwrap() == Some(sid.clone());
                        if is_active {
                            emit_event(&app, &sid, &ev);
                        }
                    });
                    busy.store(false, Ordering::SeqCst);
                }
            }
        }
    });
    worker
}

/// The single entry point for user input. Routes the message to the
/// session's worker (spawning it lazily) and returns immediately —
/// replies and tool events stream back as `agent-event`s.
#[tauri::command]
async fn send_message(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    session_id: Option<String>,
    message: String,
) -> Result<String, String> {
    let env = env_async(&state).await?;
    // Resolve which session this message belongs to: the given id, else
    // the active session, else a brand-new file.
    let sid = {
        let workers = state.workers.lock().unwrap();
        match session_id.or_else(|| state.active.lock().unwrap().clone()) {
            Some(id) if workers.contains_key(&id) || session_exists(&id) => id,
            _ => {
                let title: String = message.chars().take(60).collect();
                let title = if title.trim().is_empty() {
                    "New session".to_string()
                } else {
                    title.trim().to_string()
                };
                SessionWriter::create(&title, None)?.id().to_string()
            }
        }
    };
    *state.active.lock().unwrap() = Some(sid.clone());
    // Lazily spawn the worker for this session.
    let already_running = state.workers.lock().unwrap().contains_key(&sid);
    if !already_running {
        // Open (append mode) or continue the file; the worker owns it now.
        let writer = match session_exists(&sid) {
            true => SessionWriter::open(&sid)?,
            false => SessionWriter::create(&sid, None)?,
        };
        let worker = spawn_worker(
            app.clone(),
            env,
            sid.clone(),
            writer,
            Arc::clone(&state.active),
        );
        state.workers.lock().unwrap().insert(sid.clone(), worker);
    }
    // Synchronous ack so the UI can show something instantly.
    let _ = app.emit(
        "agent-event",
        serde_json::json!({
            "type": "Status", "payload": "", "summary": "Thinking…", "session": sid,
        }),
    );
    state
        .workers
        .lock()
        .unwrap()
        .get(&sid)
        .map(|w| w.tx.send(WorkerMsg::User(message.clone())))
        .transpose()
        .map_err(|e| e.to_string())?;
    Ok(sid)
}

fn session_exists(id: &str) -> bool {
    medusa_lib::infra::sessions::list_sessions()
        .iter()
        .any(|s| s.id == id)
}

/// Set the session whose events stream live to the UI.
#[tauri::command]
fn set_active_session(state: State<AppState>, id: Option<String>) -> Result<(), String> {
    *state.active.lock().unwrap() = id;
    Ok(())
}

#[tauri::command]
fn approve(
    state: State<AppState>,
    session_id: Option<String>,
    allow: bool,
) -> Result<String, String> {
    let id = session_id.or_else(|| state.active.lock().unwrap().clone());
    let Some(id) = id else {
        return Ok("no active session".into());
    };
    let workers = state.workers.lock().unwrap();
    if let Some(w) = workers.get(&id) {
        w.approval.store(allow, Ordering::SeqCst);
        // Wake the blocked runtime with the decision.
        *w.gate.lock().unwrap() = Some(allow);
        Ok(if allow {
            "approved".into()
        } else {
            "denied".into()
        })
    } else {
        Ok("no worker for that session".into())
    }
}

/// Cancel the current turn of a session. The worker stays alive with its
/// memory — the next message continues the same conversation.
#[tauri::command]
fn cancel_assess(state: State<AppState>, session_id: Option<String>) -> Result<String, String> {
    let id = session_id.or_else(|| state.active.lock().unwrap().clone());
    let Some(id) = id else {
        return Ok("no active session".into());
    };
    let workers = state.workers.lock().unwrap();
    if let Some(w) = workers.get(&id) {
        w.handle.cancel();
        Ok("cancelled".into())
    } else {
        Ok("no active investigation".into())
    }
}

/// Manually compact a session: summarize older turns now instead of
/// waiting for the auto-compaction threshold. Findings and vault keys
/// are preserved; the summary streams back as a `Compacted` event.
#[tauri::command]
fn compact_session(state: State<AppState>, session_id: Option<String>) -> Result<String, String> {
    let id = session_id.or_else(|| state.active.lock().unwrap().clone());
    let Some(id) = id else {
        return Ok("no active session".into());
    };
    let workers = state.workers.lock().unwrap();
    if let Some(w) = workers.get(&id) {
        let _ = w.tx.send(WorkerMsg::CompactNow);
        Ok("compacting".into())
    } else {
        Ok("no worker for that session".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorInfo {
    pub platform: String,
    pub tools_installed: usize,
    pub tools_total: usize,
    pub caps_covered: usize,
    pub caps_total: usize,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub id: String,
    pub name: String,
    pub installed: bool,
    pub version: Option<String>,
    pub caps: Vec<String>,
    pub healthy: bool,
    pub category: String,
    pub description: String,
    pub path: Option<String>,
    pub docs_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapInfo {
    pub id: String,
    pub description: String,
    pub importance: String,
    pub providers: Vec<String>,
    pub available: bool,
}

#[tauri::command]
async fn get_doctor(state: State<'_, AppState>) -> Result<DoctorInfo, String> {
    let env = env_async(&state).await?;
    Ok(doctor_info(&env))
}

#[tauri::command]
async fn get_tools(state: State<'_, AppState>) -> Result<Vec<ToolInfo>, String> {
    let env = env_async(&state).await?;
    Ok(tools_info(&env))
}

#[tauri::command]
fn get_capabilities() -> Vec<String> {
    let caps = CapabilityRegistry::builtin();
    caps.all().iter().map(|c| c.id.clone()).collect()
}

#[tauri::command]
async fn get_capability_details(state: State<'_, AppState>) -> Result<Vec<CapInfo>, String> {
    let env = env_async(&state).await?;
    Ok(caps_info(&env))
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub message: String,
}

/// One prior conversational turn, sent by the frontend with each chat call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryMsg {
    pub user: String,
    pub agent: String,
}

// `AgentEvent` variants are struct-style (`CapabilityRequested { ... }`),
// so `{:?}` contains `{`, never `(`. Split on either (or space) to get
// the bare variant name the frontend matches on.
fn event_type(ev: &medusa_lib::agent::AgentEvent) -> String {
    format!("{:?}", ev)
        .split(|c| c == '(' || c == '{' || c == ' ')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}
/* ---------- persisted sessions (JSONL under the medusa data dir) ---------- */

/// Sidebar list, newest first.
#[tauri::command]
fn list_sessions() -> Vec<SessionSummary> {
    medusa_lib::infra::sessions::list_sessions()
}

/// Replay payload: the session's records plus whether its worker is
/// mid-turn right now (so the UI can restore the running state).
#[derive(Serialize)]
struct OpenSession {
    records: Vec<TimedRecord>,
    running: bool,
}

/// Load one session for replay and make it the live-viewed session. A
/// running worker is NOT touched — background sessions keep working and
/// persisting; switching back resumes live streaming.
#[tauri::command]
fn open_session(state: State<AppState>, id: String) -> Result<OpenSession, String> {
    let records = medusa_lib::infra::sessions::load_session(&id)?;
    let running = state
        .workers
        .lock()
        .unwrap()
        .get(&id)
        .is_some_and(|w| w.busy.load(Ordering::SeqCst));
    *state.active.lock().unwrap() = Some(id);
    Ok(OpenSession { records, running })
}

/// Detach the live view from the current session. The worker keeps
/// running in the background (actor model) — this does NOT cancel it;
/// use `cancel_assess` to stop a turn.
#[tauri::command]
fn close_session(state: State<AppState>) -> Result<(), String> {
    *state.active.lock().unwrap() = None;
    Ok(())
}

/// Delete a session's transcript file. A live worker is cancelled and
/// dropped first; the delete waits (off the main thread) for the worker
/// thread to exit and release the file — Windows refuses to delete a
/// file with an open handle. If the worker is mid-turn past the wait
/// budget, the turn was still cancelled, so retrying succeeds.
#[tauri::command]
async fn delete_session(state: State<'_, AppState>, id: String) -> Result<String, String> {
    if !medusa_lib::infra::sessions::is_valid_id(&id) {
        return Err("invalid session id".into());
    }
    let exited = state
        .workers
        .lock()
        .unwrap()
        .remove(&id)
        .map(|w| {
            w.handle.cancel();
            w.exited.clone()
        });
    if let Some(exited) = exited {
        let released = tauri::async_runtime::spawn_blocking(move || {
            for _ in 0..160 {
                if exited.load(Ordering::SeqCst) {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            exited.load(Ordering::SeqCst)
        })
        .await
        .map_err(|e| e.to_string())?;
        if !released {
            return Err("session is still stopping — try again in a moment".into());
        }
    }
    medusa_lib::infra::sessions::delete_session(&id)?;
    // Detach the live view if it was showing this session.
    let mut active = state.active.lock().unwrap();
    if *active == Some(id) {
        *active = None;
    }
    Ok("deleted".into())
}

#[tauri::command]
async fn refresh_tools(state: State<'_, AppState>) -> Result<DoctorInfo, String> {
    // Drop memory + disk cache so the next env_state call rescans for real.
    *state.env.lock().unwrap() = None;
    let _ = std::fs::remove_file(medusa_lib::infra::cache::cache_path());
    let env = env_async(&state).await?;
    Ok(doctor_info(&env))
}

/// One selectable model/provider row for the UI switch.
#[derive(Serialize, Clone)]
pub struct ProviderInfo {
    /// Selection id; empty = the plain `model` block in config.json.
    pub id: String,
    /// Tag shown in front of the model name.
    pub tag: String,
    pub model: String,
    /// False when the choice cannot resolve (e.g. NVIDIA_API_KEY unset) —
    /// the UI disables it and shows the reason instead of letting a
    /// session silently fall back to the offline stub.
    pub ready: bool,
    pub active: bool,
}

fn provider_list() -> Vec<ProviderInfo> {
    let file = medusa_lib::infra::load_file_config();
    let lookup = |k: &str| std::env::var(k).ok();
    let active = medusa_lib::infra::active_provider_id(&file, &lookup);
    medusa_lib::infra::list_provider_choices(&file)
        .into_iter()
        .map(|c| {
            let ready = medusa_lib::infra::resolve_selection(
                &file,
                if c.id.is_empty() {
                    None
                } else {
                    Some(c.id.as_str())
                },
                &lookup,
            )
            .is_ok();
            let is_active = match &active {
                Some(a) => *a == c.id,
                None => c.id.is_empty(),
            };
            ProviderInfo {
                id: c.id.clone(),
                tag: c.tag,
                model: c.model.unwrap_or_else(|| "unknown".into()),
                ready,
                active: is_active,
            }
        })
        .collect()
}

#[tauri::command]
fn list_providers() -> Vec<ProviderInfo> {
    provider_list()
}

/// Switch the model provider: validate, persist to config.json, and tell
/// every live session worker to swap its model before the next turn.
#[tauri::command]
async fn set_provider(
    state: State<'_, AppState>,
    id: Option<String>,
) -> Result<Vec<ProviderInfo>, String> {
    // Validate BEFORE persisting: a broken selection would silently
    // downgrade sessions to the offline demo stub.
    let file = medusa_lib::infra::load_file_config();
    let sel = id.as_deref().filter(|s| !s.trim().is_empty());
    medusa_lib::infra::resolve_selection(&file, sel, &|k| std::env::var(k).ok())
        .map_err(|e| format!("not switching: {e}"))?;
    medusa_lib::infra::set_provider_in_config(sel)?;
    // Live workers swap their model; sessions spawned later read the
    // updated config at spawn.
    let workers = state.workers.lock().unwrap();
    for w in workers.values() {
        let _ = w.tx.send(WorkerMsg::SwapModel);
    }
    drop(workers);
    Ok(provider_list())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            get_doctor,
            get_tools,
            get_capabilities,
            get_capability_details,
            send_message,
            set_active_session,
            approve,
            cancel_assess,
            compact_session,
            refresh_tools,
            list_providers,
            set_provider,
            list_sessions,
            open_session,
            close_session,
            delete_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
