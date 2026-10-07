//! Embedded sidecar scripts. Small helper programs (Node/Playwright) that
//! back tool definitions whose real CLI cannot express the invocation
//! (e.g. the playwright CLI has no "observe network" mode). The script is
//! written into `<state_dir>/scripts/` on first use and kept in sync with
//! the embedded copy, so the binary is self-contained.

use std::path::PathBuf;

use super::cache::state_dir;

/// Scripts embedded at compile time, keyed by file name.
pub fn embedded_script(name: &str) -> Option<&'static str> {
    match name {
        "browser-observe.mjs" => Some(include_str!("../../scripts/browser-observe.mjs")),
        "medusa-oob.mjs" => Some(include_str!("../../scripts/medusa-oob.mjs")),
        "web-search.mjs" => Some(include_str!("../../scripts/web-search.mjs")),
        _ => None,
    }
}

/// Absolute path of `name` under `<state_dir>/scripts/`, writing the
/// embedded contents there first (and refreshing stale copies). Returns
/// `None` for unknown script names or unwritable state dirs — callers
/// fall back to the placeholder and the invocation fails honestly.
pub fn ensure_script(name: &str) -> Option<PathBuf> {
    let contents = embedded_script(name)?;
    let dir = state_dir().join("scripts");
    let path = dir.join(name);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if existing == contents {
            return Some(path);
        }
    }
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(&path, contents).ok()?;
    Some(path)
}
