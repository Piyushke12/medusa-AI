//! Persistent sessions: append-only JSONL, one file per session under
//! `<state_dir>/sessions/`. Same convention as Claude Code / codex / pi:
//! the first line is a session header, every later line is one timestamped
//! record, and malformed lines are skipped on load — a crash mid-write can
//! never make a session unreadable.
//!
//! Records mirror what the desktop UI renders (chat turns, reasoning,
//! tool steps), so restoring a session is replaying the file.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::cache::state_dir;

/// Bump when the record set changes; loaders skip files with older headers.
pub const SESSIONS_VERSION: u32 = 1;

/// One persisted line: a record plus its wall-clock time in milliseconds
/// (matching the UI's `Date.now()` domain).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimedRecord {
    pub time: i64,
    #[serde(flatten)]
    pub record: SessionRecord,
}

/// Persisted session records, internally tagged (`{"type":"chat",...}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionRecord {
    /// First line of every file, written once at creation.
    Session {
        version: u32,
        id: String,
        title: String,
        target: Option<String>,
    },
    /// A user message, written the moment it arrives — BEFORE the turn
    /// runs. Without this, a turn that never completes (crash, Stop,
    /// model failures) loses the user's message from the transcript on
    /// replay, and mid-turn replays drop the pending bubble.
    User { text: String },
    /// Mid-turn agent message to the user (a narrated finding or
    /// milestone). Rendered as a normal agent chat bubble on replay —
    /// distinct from thinking cards and from turn-ending replies.
    Note { text: String },
    /// One completed user↔assistant exchange. `user_time` is when the
    /// USER message was sent (ms epoch) — without it, replay would stamp
    /// the user bubble with the reply's time and reorder the transcript.
    /// 0 on legacy records; loaders fall back to `time`. The `user` text
    /// duplicates the preceding `User` record (arrival-time persistence);
    /// replay fills the pending bubble instead of duplicating.
    Chat {
        user: String,
        agent: String,
        #[serde(default)]
        user_time: i64,
    },
    /// Reasoning / hypothesis / error card.
    Think { text: String },
    /// Assessment started (or re-scoped) on a target.
    Target { target: String },
    /// Capability requested — opens a tool step card. `model_secs` is the
    /// cumulative LLM time for the decision that requested it (incl.
    /// retries); 0 on legacy records.
    Tool {
        cap: String,
        target: String,
        reason: String,
        #[serde(default)]
        model_secs: f64,
    },
    /// Provider chosen for the running step.
    Provider { provider: String },
    /// Observation text appended to the running step.
    Obs { text: String },
    /// Tool execution finished — closes the running step. `tool_secs` is
    /// the execution wall time (all attempts); 0 on legacy records.
    ToolDone {
        summary: String,
        output: String,
        #[serde(default)]
        tool_secs: f64,
    },
    /// A registry finding reported or updated by the model. Replayed
    /// verbatim into the ContextManager on session load, so findings
    /// survive restarts as well as compaction. Carries no secrets.
    Finding {
        id: usize,
        severity: String,
        title: String,
        target: String,
        status: String,
        detail: String,
        #[serde(default)]
        step: usize,
    },
    /// Context-meter reading after one model call. `used` resumes the
    /// meter on reload so long sessions compact on schedule.
    CtxUsage {
        used: u64,
        limit: u64,
        pct: u8,
        #[serde(default)]
        estimated: bool,
    },
    /// A compaction replaced older turns with a summary (`fallback` =
    /// the summarizer failed and oldest-first truncation was used).
    Compacted {
        before: u64,
        after: u64,
        freed: u64,
        #[serde(default)]
        fallback: bool,
    },
    /// A vault operation. `op` is `stored` or `recalled`; carries the
    /// KEY only — values are never persisted here by design.
    VaultOp {
        op: String,
        key: String,
        #[serde(default)]
        kind: String,
    },
}

/// Sidebar-facing digest of one session file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub target: Option<String>,
    pub time_created: i64,
    pub time_updated: i64,
    pub records: usize,
}

pub fn sessions_dir() -> PathBuf {
    state_dir().join("sessions")
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Time-first id so lexicographic file order is chronological.
fn new_session_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("ses-{}-{:09}", now_ms(), nanos)
}

/// Session ids are filename stems; reject anything that could traverse.
pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Appends records to one session file. The header line is written on
/// create; `append` writes one JSON line and flushes immediately so a
/// crash between turns loses at most the turn in flight.
pub struct SessionWriter {
    file: File,
    id: String,
}

impl SessionWriter {
    pub fn create(title: &str, target: Option<&str>) -> Result<Self, String> {
        Self::create_in(&sessions_dir(), title, target)
    }

    pub fn create_in(dir: &Path, title: &str, target: Option<&str>) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("create sessions dir: {e}"))?;
        let id = new_session_id();
        let path = dir.join(format!("{id}.jsonl"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("create session file: {e}"))?;
        let header = TimedRecord {
            time: now_ms(),
            record: SessionRecord::Session {
                version: SESSIONS_VERSION,
                id: id.clone(),
                title: title.to_string(),
                target: target.map(str::to_string),
            },
        };
        let line = serde_json::to_string(&header).map_err(|e| format!("serialize header: {e}"))?;
        writeln!(file, "{line}").map_err(|e| format!("write header: {e}"))?;
        file.flush().map_err(|e| format!("flush header: {e}"))?;
        Ok(Self { file, id })
    }

    /// Reopen an existing session for appending (resume).
    pub fn open(id: &str) -> Result<Self, String> {
        Self::open_in(&sessions_dir(), id)
    }

    pub fn open_in(dir: &Path, id: &str) -> Result<Self, String> {
        if !is_valid_id(id) {
            return Err(format!("invalid session id: {id}"));
        }
        let path = dir.join(format!("{id}.jsonl"));
        if !path.is_file() {
            return Err(format!("session not found: {id}"));
        }
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| format!("open session file: {e}"))?;
        Ok(Self {
            file,
            id: id.to_string(),
        })
    }

    pub fn append(&mut self, record: SessionRecord) -> Result<(), String> {
        let timed = TimedRecord {
            time: now_ms(),
            record,
        };
        let line = serde_json::to_string(&timed).map_err(|e| format!("serialize record: {e}"))?;
        writeln!(self.file, "{line}").map_err(|e| format!("append record: {e}"))?;
        self.file
            .flush()
            .map_err(|e| format!("flush record: {e}"))?;
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Delete one session file. The id is validated the same way as on
/// open — a traversal attempt is rejected before touching the fs.
pub fn delete_session(id: &str) -> Result<(), String> {
    delete_session_in(&sessions_dir(), id)
}

pub fn delete_session_in(dir: &Path, id: &str) -> Result<(), String> {
    if !is_valid_id(id) {
        return Err(format!("invalid session id: {id}"));
    }
    let path = dir.join(format!("{id}.jsonl"));
    if !path.is_file() {
        return Err(format!("session not found: {id}"));
    }
    fs::remove_file(&path).map_err(|e| format!("delete session file: {e}"))?;
    Ok(())
}

/// All sessions in `dir`, newest first. Reads each file fully (session
/// files are small chat transcripts) to pick up the active target and
/// record count. Unreadable files are skipped, never fatal.
pub fn list_sessions_in(dir: &Path) -> Vec<SessionSummary> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(summary) = summarize(&path, id) {
            out.push(summary);
        }
    }
    out.sort_by(|a, b| b.time_updated.cmp(&a.time_updated).then(a.id.cmp(&b.id)));
    out
}

pub fn list_sessions() -> Vec<SessionSummary> {
    list_sessions_in(&sessions_dir())
}

fn summarize(path: &Path, id: &str) -> Option<SessionSummary> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut summary = SessionSummary {
        id: id.to_string(),
        title: id.to_string(),
        target: None,
        time_created: 0,
        time_updated: 0,
        records: 0,
    };
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Ok(timed) = serde_json::from_str::<TimedRecord>(&line) else {
            continue; // malformed / partial line: skip, keep going
        };
        match timed.record {
            SessionRecord::Session { title, target, .. } => {
                summary.title = title;
                summary.target = target;
                if summary.time_created == 0 {
                    summary.time_created = timed.time;
                    summary.time_updated = timed.time;
                }
            }
            SessionRecord::Target { target } => {
                if summary.target.is_none() {
                    summary.target = Some(target);
                }
            }
            _ => {}
        }
        summary.time_updated = timed.time;
        summary.records += 1;
    }
    // Header line counts as the session record, not activity.
    summary.records = summary.records.saturating_sub(1);
    Some(summary)
}

/// Full replay of one session. Malformed lines are skipped; unknown ids
/// and path-traversal attempts are rejected.
pub fn load_session_in(dir: &Path, id: &str) -> Result<Vec<TimedRecord>, String> {
    if !is_valid_id(id) {
        return Err(format!("invalid session id: {id}"));
    }
    let path = dir.join(format!("{id}.jsonl"));
    if !path.is_file() {
        return Err(format!("session not found: {id}"));
    }
    let file = File::open(&path).map_err(|e| format!("open session: {e}"))?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { break };
        if let Ok(timed) = serde_json::from_str::<TimedRecord>(&line) {
            out.push(timed);
        }
    }
    Ok(out)
}

pub fn load_session(id: &str) -> Result<Vec<TimedRecord>, String> {
    load_session_in(&sessions_dir(), id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("medusa-sessions-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn user_records_persist_before_reply() {
        let dir = temp_dir("userrec");
        let mut w = SessionWriter::create_in(&dir, "T", None).unwrap();
        let id = w.id().to_string();
        // Written the moment the message arrives...
        w.append(SessionRecord::User {
            text: "assess localhost".into(),
        })
        .unwrap();
        // ...then the completed exchange lands after the turn.
        w.append(SessionRecord::Chat {
            user: "assess localhost".into(),
            agent: "done".into(),
            user_time: 123,
        })
        .unwrap();
        let recs = load_session_in(&dir, &id).unwrap();
        // [0] is the session header.
        assert!(matches!(recs[1].record, SessionRecord::User { .. }));
        assert!(matches!(recs[2].record, SessionRecord::Chat { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trip_skips_malformed_lines() {
        let dir = temp_dir("roundtrip");
        let mut w = SessionWriter::create_in(&dir, "First scan", None).unwrap();
        let id = w.id().to_string();
        w.append(SessionRecord::Chat {
            user: "assess scanme.nmap.org".into(),
            agent: "Starting…".into(),
            user_time: 0,
        })
        .unwrap();
        w.append(SessionRecord::Target {
            target: "scanme.nmap.org".into(),
        })
        .unwrap();
        // Simulate a crash mid-write: a truncated final line.
        let path = dir.join(format!("{id}.jsonl"));
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{{\"type\":\"chat\",\"user\":\"trun").unwrap();
        drop(f);

        let recs = load_session_in(&dir, &id).unwrap();
        assert_eq!(recs.len(), 3); // header + chat + target, garbage skipped
        assert!(
            matches!(&recs[0].record, SessionRecord::Session { title, .. } if title == "First scan")
        );
        assert!(
            matches!(&recs[2].record, SessionRecord::Target { target } if target == "scanme.nmap.org")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_is_newest_first_and_tracks_target() {
        let dir = temp_dir("list");
        let mut a = SessionWriter::create_in(&dir, "Chat only", None).unwrap();
        a.append(SessionRecord::Chat {
            user: "hi".into(),
            agent: "hello".into(),
            user_time: 0,
        })
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut b = SessionWriter::create_in(&dir, "Assess", None).unwrap();
        let b_id = b.id().to_string();
        b.append(SessionRecord::Target {
            target: "example.com".into(),
        })
        .unwrap();

        let list = list_sessions_in(&dir);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, b_id, "newest first");
        assert_eq!(list[0].target.as_deref(), Some("example.com"));
        assert_eq!(list[0].records, 1);
        assert_eq!(list[1].target, None);
        assert_eq!(list[1].title, "Chat only");
        assert!(list[0].time_updated >= list[1].time_updated);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopen_appends_to_same_file() {
        let dir = temp_dir("reopen");
        let w = SessionWriter::create_in(&dir, "Again", None).unwrap();
        let id = w.id().to_string();
        drop(w);
        let mut w2 = SessionWriter::open_in(&dir, &id).unwrap();
        w2.append(SessionRecord::Think { text: "hmm".into() })
            .unwrap();
        let recs = load_session_in(&dir, &id).unwrap();
        assert_eq!(recs.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_ids_and_missing_files() {
        let dir = temp_dir("badids");
        assert!(load_session_in(&dir, "../evil").is_err());
        assert!(load_session_in(&dir, "a/b").is_err());
        assert!(load_session_in(&dir, "no-such-session").is_err());
        assert!(SessionWriter::open_in(&dir, "../evil").is_err());
        assert!(SessionWriter::open_in(&dir, "no-such-session").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_the_file_and_rejects_traversal() {
        let dir = temp_dir("delete");
        let w = SessionWriter::create_in(&dir, "Doomed", None).unwrap();
        let id = w.id().to_string();
        drop(w);
        assert!(dir.join(format!("{id}.jsonl")).is_file());
        delete_session_in(&dir, &id).unwrap();
        assert!(!dir.join(format!("{id}.jsonl")).exists());
        // Second delete reports not-found; traversal never touches the fs.
        assert!(delete_session_in(&dir, &id).is_err());
        assert!(delete_session_in(&dir, "../evil").is_err());
        assert!(delete_session_in(&dir, "no-such-session").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn timed_record_json_shape() {
        let timed = TimedRecord {
            time: 1234,
            record: SessionRecord::Chat {
                user: "u".into(),
                agent: "a".into(),
                user_time: 0,
            },
        };
        let json = serde_json::to_string(&timed).unwrap();
        assert!(json.contains(r#""type":"chat""#));
        assert!(json.contains(r#""time":1234"#));
        let back: TimedRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, timed);
    }
}
