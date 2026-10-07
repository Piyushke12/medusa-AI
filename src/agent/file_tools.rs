//! Direct file tools (`file_read` / `file_write` decisions) — NOT
//! capabilities. The model names a path; the runtime reads or writes it,
//! exactly like the direct `web_search`/`reply`/`narrate` decisions.
//!
//! # Confinement (the security guarantee)
//! The model can never name an arbitrary path. Every file op funnels
//! through [`resolve_path`], which maps a model-supplied RELATIVE filename
//! onto a work directory under `<state_dir>/work/<scope-host>/`. Out-of-
//! scope references (absolute, drive-prefixed, traversal, dotfiles) are
//! refused and fed back as `last_error` — the model cannot read
//! `/etc/passwd` or `C:\Windows`, and cannot write outside the assessment's
//! work root.
//!
//! # Scope
//! File access exists only while the session targets a SINGLE flat host
//! (the common `assess <host>` case). Wildcard/multi-root/empty scopes grant
//! no file access — the work directory would be ambiguous. The host name
//! keys the directory: `assess 127.0.0.1` → `<work>/127.0.0.1/`.
//!
//! # Work-root override (headless/CI)
//! `MEDUSA_WORK_ROOT` replaces the default `%APPDATA%\medusa\work` so
//! automated runs write to a caller-chosen directory.

use std::path::Path;
use std::path::PathBuf;

use crate::infra::cache::state_dir;

/// Default work root; override via `MEDUSA_WORK_ROOT`.
pub fn work_root() -> PathBuf {
    if let Ok(over) = std::env::var("MEDUSA_WORK_ROOT") {
        if !over.trim().is_empty() {
            return PathBuf::from(over.trim());
        }
    }
    state_dir().join("work")
}

/// Whether the scope grants file access: exactly one flat, non-wildcard
/// host. Returns the host when granted.
pub fn file_scope_host(scope_roots: &[String]) -> Option<&str> {
    if scope_roots.len() == 1 && !scope_roots[0].is_empty() && scope_roots[0] != "*" {
        Some(scope_roots[0].as_str())
    } else {
        None
    }
}

/// Sanitize a host name into a safe directory component.
pub fn host_dir_component(host: &str) -> String {
    let mut clean: String = host
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    clean = clean
        .trim_matches('.')
        .trim_matches('-')
        .trim_matches('_')
        .to_string();
    if clean.is_empty() || clean == "." || clean == ".." {
        return "default".to_string();
    }
    if clean.len() > 60 {
        clean.chars().take(60).collect()
    } else {
        clean
    }
}

/// Sanitize a leaf filename: alphanumerics + `. - _`; no separators,
/// traversal, or leading dot.
pub fn sanitize_leaf(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();
    let clean = clean.trim_matches('.').to_string();
    if clean.is_empty() || clean == "." || clean == ".." {
        "artifact".to_string()
    } else {
        clean
    }
}

/// Is `model_path` a plain relative single-component reference (safe to
/// map into the work dir)?
fn is_plain_relative(model_path: &Path) -> bool {
    let s = model_path.to_string_lossy();
    model_path.components().count() == 1
        && !s.starts_with('/')
        && !s.starts_with('\\')
        && !s.contains(':')
        && !s.starts_with('~')
        && !s.ends_with('/')
        && !s.ends_with('\\')
}

/// Resolve a model-requested path to the canonical on-disk location the
/// runtime will actually touch. Returns `Err` with a user-facing reason
/// when the path is not confined safely.
pub fn resolve_path(
    model_path: &str,
    scope_roots: &[String],
) -> Result<PathBuf, String> {
    let m = model_path.trim();
    if m.is_empty() {
        return Err("empty path".into());
    }
    let Some(host) = file_scope_host(scope_roots) else {
        return Err(
            "file access requires a single, non-wildcard target scope (one host)"
                .into(),
        );
    };
    let base = work_root().join(host_dir_component(host));
    let mp = PathBuf::from(m);
    if !is_plain_relative(&mp) {
        return Err(
            "path is outside the assessment's work directory — use a plain relative filename".into(),
        );
    }
    Ok(base.join(sanitize_leaf(m)))
}

/// The work directory for a given scope host, if file access is granted.
pub fn work_dir_for_host(scope_roots: &[String]) -> Option<PathBuf> {
    file_scope_host(scope_roots).map(|h| work_root().join(host_dir_component(h)))
}

/// Read a file's contents (UTF-8 lossy), capped.
pub fn read_file(real: &Path) -> Result<String, String> {
    if !real.is_file() {
        return Err(format!("not a readable file: {}", real.display()));
    }
    let data = std::fs::read(real).map_err(|e| format!("read failed: {e}"))?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// Default number of lines returned by a plain `file_read` (when neither
/// `grep` nor `lines` is given): the file's head, loosely the first N.
pub const DEFAULT_READ_LINES: usize = 40;
/// Upper bound on how many lines a single read may return, whatever the
/// caller asks for — a bounded window degenerates to a tail window.
pub const MAX_READ_LINES: usize = 5_000;

/// Result of a smart (trimmed) read.
pub struct ReadSlice {
    /// The lines actually returned.
    pub lines: Vec<String>,
    /// Total lines in the file.
    pub total_lines: usize,
    /// Whether the full file was returned (i.e. it was small enough that
    /// nothing was elided).
    pub complete: bool,
}

/// Read a file without dumping it wholesale into context.
///
/// - `pattern`: grep mode — return only matching lines (with a small
///   context window around each hit).
/// - `lines`: plain mode — return up to `lines` lines. When `lines` is
///   `None`, the default head window is used.
///
/// Both are bounded by [`MAX_READ_LINES`]. The original line numbers are
/// preserved so the model can reference them.
pub fn grep_file(real: &Path, pattern: &str) -> Result<ReadSlice, String> {
    let content = read_file(real)?;
    let all: Vec<&str> = content.lines().collect();
    let total = all.len();
    let needle = pattern.to_lowercase();
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (i, line) in all.iter().enumerate() {
        if line.to_lowercase().contains(&needle) {
            hits.push((i, (*line).to_string()));
        }
    }
    if hits.is_empty() {
        return Ok(ReadSlice {
            lines: Vec::new(),
            total_lines: total,
            complete: false,
        });
    }
    // Build a context window: ±2 lines around each hit, deduplicated,
    // ordered, line-numbered.
    let ctx = 2usize;
    let mut seen = std::collections::BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for (i, _) in &hits {
        let lo = i.saturating_sub(ctx);
        let hi = (*i + ctx).min(total.saturating_sub(1));
        for ln in lo..=hi {
            if seen.insert(ln) {
                out.push(format!("{:>5}  {}", ln + 1, all[ln]));
            }
        }
    }
    let cap = MAX_READ_LINES.min(total);
    let complete = out.len() <= cap;
    if out.len() > cap {
        out.truncate(cap);
        out.push(format!("... [{} of {} lines shown]", cap, total));
    }
    Ok(ReadSlice {
        lines: out,
        total_lines: total,
        complete,
    })
}

/// Plain line-window read (head by default, or a specific count).
pub fn read_n_lines(real: &Path, n: usize) -> Result<ReadSlice, String> {
    let content = read_file(real)?;
    let all: Vec<&str> = content.lines().collect();
    let total = all.len();
    let n = n.min(MAX_READ_LINES).max(0);
    let from = 0usize;
    let take = n.min(total);
    let mut out: Vec<String> = Vec::new();
    for i in from..from + take {
        out.push(format!("{:>5}  {}", i + 1, all[i]));
    }
    let complete = n >= total;
    Ok(ReadSlice {
        lines: out,
        total_lines: total,
        complete,
    })
}

/// Write content, creating parent dirs.
pub fn write_file(real: &Path, content: &str) -> Result<u64, String> {
    if let Some(parent) = real.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir failed: {e}"))?;
    }
    std::fs::write(real, content).map_err(|e| format!("write failed: {e}"))?;
    Ok(content.len() as u64)
}

/// Max bytes of file content carried into the model-visible evidence.
pub const MAX_FILE_BYTES: usize = 32_000;

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(host: &str) -> Vec<String> {
        vec![host.to_string()]
    }

    #[test]
    fn relative_path_confines_to_work_dir() {
        // Uses a `[santized]` explicit host; env-free.
        let r = resolve_path("config.yml", &roots("127.0.0.1")).unwrap();
        assert!(r.file_name().and_then(|s| s.to_str()) == Some("config.yml"));
        assert!(r.starts_with(work_root().join("127.0.0.1")));
    }

    #[test]
    fn host_sanitizes_into_dir_component() {
        assert_eq!(host_dir_component("127.0.0.1"), "127.0.0.1");
        // ':' maps to '_' (port stripped only in host_of, not here).
        assert_eq!(host_dir_component("scanme.nmap.org:443"), "scanme.nmap.org_443");
        assert_eq!(host_dir_component("***"), "default");
    }

    #[test]
    fn traversal_drive_and_absolute_are_rejected() {
        let r = roots("127.0.0.1");
        for bad in [
            "../../etc/passwd",
            "C:\\Windows\\system32",
            "/etc/passwd",
            "~/.ssh/id_rsa",
            "a/b.txt",
            "x/",
        ] {
            assert!(resolve_path(bad, &r).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn empty_and_whitespace_rejected() {
        let r = roots("127.0.0.1");
        assert!(resolve_path("", &r).is_err());
        assert!(resolve_path("   ", &r).is_err());
    }

    #[test]
    fn wildcard_multi_or_empty_scope_denies() {
        assert!(resolve_path("a.txt", &["*".into()]).is_err());
        assert!(resolve_path("a.txt", &["h1".into(), "h2".into()]).is_err());
        assert!(resolve_path("a.txt", &Vec::<String>::new()).is_err());
    }

    #[test]
    fn roundtrip_write_then_read() {
        let real = resolve_path("note.txt", &roots("127.0.0.1")).unwrap();
        write_file(&real, "hello").unwrap();
        assert_eq!(read_file(&real).unwrap(), "hello");
        std::fs::remove_file(&real).ok();
    }

    #[test]
    fn grep_filters_to_matching_lines_with_context() {
        // grep_file takes the real path — no scope/env needed.
        let dir = std::env::temp_dir();
        let real = dir.join("medusa-grep-test.log");
        write_file(&real, "one\nadmin login\ntwo\nthree\nadmin token=abc\nfour\n").unwrap();
        let slice = grep_file(&real, "admin").unwrap();
        assert_eq!(slice.total_lines, 6);
        assert!(slice.lines.iter().any(|l| l.contains("admin login")));
        assert!(slice.lines.iter().any(|l| l.contains("admin token=abc")));
        // Line-numbered: the second hit is on line 5.
        assert!(slice.lines.iter().any(|l| l.contains("5  admin token=abc")));
        std::fs::remove_file(&real).ok();
    }

    #[test]
    fn grep_no_match_returns_empty() {
        let dir = std::env::temp_dir();
        let real = dir.join("medusa-grep-none.txt");
        write_file(&real, "aaa\nbbb\n").unwrap();
        let slice = grep_file(&real, "zzz").unwrap();
        assert!(slice.lines.is_empty());
        assert_eq!(slice.total_lines, 2);
        std::fs::remove_file(&real).ok();
    }

    #[test]
    fn read_n_lines_bounds_to_head() {
        let dir = std::env::temp_dir();
        let real = dir.join("medusa-lines-test.txt");
        let content = (1..=100).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        write_file(&real, &content).unwrap();
        let slice = read_n_lines(&real, 10).unwrap();
        assert_eq!(slice.total_lines, 100);
        assert_eq!(slice.lines.len(), 10);
        assert!(!slice.complete);
        assert!(slice.lines[0].contains("    1"));
        std::fs::remove_file(&real).ok();
    }
}