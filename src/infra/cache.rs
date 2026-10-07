//! On-disk cache for `EnvironmentState` (JSON). The agent never rescans on
//! every command: it loads the cache when fresh and rescans on
//! `/refresh-tools`, `--refresh`, or when a tool execution fails.

use std::path::PathBuf;

use crate::model::EnvironmentState;

/// Directory holding medusa state: `%APPDATA%\medusa` on Windows,
/// `~/.medusa` elsewhere.
pub fn state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("medusa");
        }
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(home).join(".medusa");
    }
    PathBuf::from(".medusa")
}

pub fn cache_path() -> PathBuf {
    state_dir().join("env_state.json")
}

/// Cache envelope: the environment state plus a fingerprint of the builtin
/// registry's detection-relevant fields. Any change to tool ids, executable
/// candidates, or version probes invalidates the cache — otherwise a stale
/// "installed" verdict (e.g. `browser` bound to the npm playwright CLI)
/// survives the registry fix that removed the binding.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEnvelope {
    fingerprint: String,
    state: EnvironmentState,
}

/// Stable-enough fingerprint of the registry's detection semantics.
pub fn registry_fingerprint() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for t in crate::registry::ToolRegistry::builtin().all() {
        t.id.hash(&mut h);
        for exe in &t.executable_candidates {
            exe.hash(&mut h);
        }
        for a in &t.version_args {
            a.hash(&mut h);
        }
    }
    format!("{:016x}", h.finish())
}

pub fn load_state() -> Option<EnvironmentState> {
    let path = cache_path();
    let text = std::fs::read_to_string(path).ok()?;
    let envelope: CacheEnvelope = serde_json::from_str(&text).ok()?;
    if envelope.fingerprint != registry_fingerprint() {
        return None; // registry changed since this scan: force rescan
    }
    if envelope.state.schema_version != crate::model::state::STATE_SCHEMA_VERSION {
        return None; // stale schema: force rescan
    }
    Some(envelope.state)
}

pub fn save_state(state: &EnvironmentState) -> Result<(), String> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create state dir: {e}"))?;
    let envelope = CacheEnvelope {
        fingerprint: registry_fingerprint(),
        state: state.clone(),
    };
    let text = serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(cache_path(), text).map_err(|e| format!("write cache: {e}"))?;
    Ok(())
}

/// Fresh if scanned within `ttl_secs` and the schema matches.
pub fn state_is_fresh(state: &EnvironmentState, ttl_secs: i64, now_unix: i64) -> bool {
    now_unix >= state.last_scan_unix && now_unix - state.last_scan_unix <= ttl_secs
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn freshness_window() {
        let mut s = EnvironmentState::empty();
        s.last_scan_unix = 1000;
        assert!(state_is_fresh(&s, 60, 1059));
        assert!(!state_is_fresh(&s, 60, 1061));
        assert!(!state_is_fresh(&s, 60, 999)); // clock skew
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut s = EnvironmentState::empty();
        s.tools.insert(
            "nmap".into(),
            crate::model::ToolStatus::missing("nmap", "test"),
        );
        let text = serde_json::to_string(&s).unwrap();
        let back: EnvironmentState = serde_json::from_str(&text).unwrap();
        assert_eq!(s, back);
        let _ = HashMap::<String, String>::new(); // keep import honest in isolation
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(registry_fingerprint(), registry_fingerprint());
    }

    #[test]
    fn envelope_round_trip_and_legacy_files_are_stale() {
        let mut s = EnvironmentState::empty();
        s.last_scan_unix = 42;
        let env = CacheEnvelope {
            fingerprint: registry_fingerprint(),
            state: s.clone(),
        };
        let text = serde_json::to_string(&env).unwrap();
        let back: CacheEnvelope = serde_json::from_str(&text).unwrap();
        assert_eq!(back.fingerprint, registry_fingerprint());
        assert_eq!(back.state.last_scan_unix, 42);
        // A legacy bare-state cache file (pre-envelope format) must parse as
        // stale — its fingerprint is unknown, so a rescan is forced.
        let legacy = serde_json::to_string(&s).unwrap();
        assert!(serde_json::from_str::<CacheEnvelope>(&legacy).is_err());
    }
}
