//! Per-target vault: non-expiring secrets the investigation recovers
//! (passwords, JWT signing secrets, S2S API keys, env values, RCE loot).
//!
//! The model stores via `vault_store` and recalls via `vault_recall`
//! instead of re-acquiring the same credential again and again. Only
//! things that do NOT expire belong here — the runtime rejects bearer /
//! session / JWT tokens and anything shaped like one.
//!
//! Redaction contract (security-critical): vault VALUES never enter
//! session records, observations, narrations, evidence, compaction
//! summaries, logs, or the UI event stream. Records and views carry key
//! names only; a recalled value rides exactly one decision inside the
//! [`ContextView`] and is cleared afterwards.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One vaulted secret. The `value` is the only sensitive field in the
/// whole agent tree — it is serialized to the vault file and nowhere else.
///
/// `Debug` is redacted by hand: a stray `{:?}` in a log or event
/// payload must never carry a secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub key: String,
    pub value: String,
    /// password | secret | s2s_key | env (free-form; model-supplied).
    pub kind: String,
    /// Where it was found (URL, tool output, file...).
    pub source: String,
    pub step_found: usize,
    pub note: String,
}

impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntry")
            .field("key", &self.key)
            .field("value", &"[redacted]")
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("step_found", &self.step_found)
            .finish()
    }
}

/// Per-target secret store, loaded on demand and saved on every store.
#[derive(Debug, Clone, Default)]
pub struct VaultManager {
    target: String,
    entries: HashMap<String, VaultEntry>,
}

impl VaultManager {
    pub fn load(target: &str) -> Self {
        let mut mgr = Self {
            target: target.to_string(),
            entries: HashMap::new(),
        };
        let path = vault_path(target);
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(saved) = serde_json::from_str::<Vec<VaultEntry>>(&text) {
                for e in saved {
                    mgr.entries.insert(e.key.clone(), e);
                }
            }
        }
        mgr
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Key names advertised to the model (`key [kind]` lines). Values
    /// never leave through this method.
    pub fn key_lines(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .entries
            .values()
            .map(|e| format!("{} [{}]", e.key, e.kind))
            .collect();
        keys.sort();
        keys
    }

    /// Store a secret. Rejects expiring credentials and empty keys;
    /// overwriting an existing key refreshes it (same credential
    /// re-found later in the investigation).
    pub fn store(
        &mut self,
        key: &str,
        value: &str,
        kind: &str,
        source: &str,
        step: usize,
    ) -> Result<bool, String> {
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err("vault key must not be empty".to_string());
        }
        if value.is_empty() {
            return Err("vault value must not be empty".to_string());
        }
        if key.len() > 64 {
            return Err(format!("vault key too long ({} chars, max 64)", key.len()));
        }
        if value.len() > 4096 {
            return Err("vault value too long (max 4096 chars)".to_string());
        }
        if looks_ephemeral(key, value) {
            return Err(format!(
                "vault rejects `{key}`: expiring credentials (bearer/session/JWT tokens, OTPs) do not belong in the vault — only non-expiring secrets (passwords, signing secrets, S2S keys, env values)"
            ));
        }
        let refreshed = self.entries.contains_key(key);
        self.entries.insert(
            key.to_string(),
            VaultEntry {
                key: key.to_string(),
                value: value.to_string(),
                kind: kind.trim().to_string(),
                source: source.trim().to_string(),
                step_found: step,
                note: String::new(),
            },
        );
        self.save();
        Ok(refreshed)
    }

    /// Recall by exact key, else by substring over key/kind/source.
    /// Exactly one hit returns its value; zero hits and ambiguous
    /// queries return a `Err` listing candidate keys so the model can
    /// disambiguate (values are never listed).
    pub fn recall(&self, query: &str) -> Result<(&str, &str), String> {
        let q = query.trim().to_lowercase();
        if let Some(e) = self.entries.get(query.trim()) {
            return Ok((e.key.as_str(), e.value.as_str()));
        }
        let hits: Vec<&VaultEntry> = self
            .entries
            .values()
            .filter(|e| {
                e.key.to_lowercase().contains(&q)
                    || e.kind.to_lowercase().contains(&q)
                    || e.source.to_lowercase().contains(&q)
            })
            .collect();
        match hits.len() {
            0 => Err(format!(
                "vault has no entry matching `{query}` (keys: {})",
                self.key_list_or_none()
            )),
            1 => Ok((hits[0].key.as_str(), hits[0].value.as_str())),
            _ => {
                let mut names: Vec<&str> =
                    hits.iter().map(|e| e.key.as_str()).collect();
                names.sort();
                Err(format!(
                    "vault query `{query}` is ambiguous ({}); recall one key by name",
                    names.join(", ")
                ))
            }
        }
    }

    fn key_list_or_none(&self) -> String {
        if self.entries.is_empty() {
            "(vault is empty)".to_string()
        } else {
            let mut names: Vec<&str> =
                self.entries.keys().map(|k| k.as_str()).collect();
            names.sort();
            names.join(", ")
        }
    }

    fn save(&self) {
        let path = vault_path(&self.target);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut entries: Vec<&VaultEntry> = self.entries.values().collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        if let Ok(text) = serde_json::to_string_pretty(&entries) {
            let _ = std::fs::write(&path, text);
        }
    }
}

/// Filename-safe target slug: one vault file per assessment target.
fn sanitize_target(target: &str) -> String {
    let slug: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
        let slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        "untargeted".to_string()
    } else {
        slug.chars().take(128).collect()
    }
}

pub fn vault_path(target: &str) -> PathBuf {
    crate::infra::cache::state_dir()
        .join("vault")
        .join(format!("{}.json", sanitize_target(target)))
}

/// True for credentials that expire: bearer/session/access tokens by
/// NAME, and anything shaped like a JWT by VALUE (three base64url
/// segments). JWT *signing secrets* (key contains "secret") are
/// non-expiring and explicitly allowed.
pub fn looks_ephemeral(key: &str, value: &str) -> bool {
    let k = key.to_lowercase();
    // A key that is itself a signing secret is always vault-worthy,
    // even if its name mentions "jwt".
    let is_signing_secret = k.contains("secret");
    if !is_signing_secret {
        for marker in [
            "bearer",
            "access_token",
            "session_token",
            "id_token",
            "refresh_token",
            "otp",
            "one_time",
        ] {
            if k.contains(marker) {
                return true;
            }
        }
        // Bare "token" keys (api_token, jwt_token) are ephemeral unless
        // qualified as a secret.
        if k == "token" || k.ends_with("_token") || k.ends_with("-token") {
            return true;
        }
    }
    looks_like_jwt(value)
}

/// Three dot-separated base64url segments, each long enough to be a
/// real header/payload/signature (not version strings like "1.2.3").
fn looks_like_jwt(value: &str) -> bool {
    let v = value.trim();
    if v.contains(' ') || v.contains('\n') {
        return false;
    }
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| {
        p.len() >= 8
            && p.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'='
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_recall_roundtrip() {
        let mut v = VaultManager::default();
        assert!(v.store("db_password", "s3cr3t", "password", "env dump", 4).unwrap() == false);
        assert_eq!(v.len(), 1);
        assert_eq!(v.recall("db_password").unwrap(), ("db_password", "s3cr3t"));
        // Substring recall works; re-store refreshes.
        assert_eq!(v.recall("db_").unwrap(), ("db_password", "s3cr3t"));
        assert!(v.store("db_password", "n3w", "password", "again", 9).unwrap());
        assert_eq!(v.recall("db_password").unwrap().1, "n3w");
        assert_eq!(v.key_lines(), vec!["db_password [password]".to_string()]);
    }

    #[test]
    fn rejects_ephemeral_credentials() {
        let mut v = VaultManager::default();
        // JWT-shaped values are rejected whatever the key.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(v.store("auth", jwt, "secret", "resp", 1).is_err());
        // Bearer/session token names are rejected.
        assert!(v.store("bearer", "abc123", "secret", "header", 1).is_err());
        assert!(v.store("session_token", "abc123", "secret", "cookie", 1).is_err());
        // ...but the SIGNING secret behind that JWT is vault-worthy.
        assert!(v.store("jwt_secret", "my-hmac-key", "secret", "config", 1).is_ok());
        assert!(v.store("s2s_key_billing", "sk-live-abc", "s2s_key", "env", 1).is_ok());
        assert!(v.store("DB_PASSWORD", "p@ss", "env", "rce env", 1).is_ok());
        assert!(v.is_empty() == false);
    }

    #[test]
    fn ambiguous_and_missing_recalls_list_keys_not_values() {
        let mut v = VaultManager::default();
        v.store("db_password", "s3cr3t", "password", "", 1).unwrap();
        v.store("db_user", "admin", "env", "", 1).unwrap();
        let err = v.recall("db").unwrap_err();
        assert!(err.contains("db_password") && err.contains("db_user"));
        assert!(!err.contains("s3cr3t"), "values must never leak into errors");
        let err = v.recall("nope").unwrap_err();
        assert!(!err.contains("s3cr3t"));
    }

    #[test]
    fn sanitize_target_is_filesafe() {
        assert_eq!(sanitize_target("http://127.0.0.1:3000/x"), "http___127.0.0.1_3000_x");
        assert_eq!(sanitize_target("///"), "untargeted");
        assert!(vault_path("10.0.0.1").ends_with("vault/10.0.0.1.json".replace('/', &std::path::MAIN_SEPARATOR.to_string())));
    }

    #[test]
    fn jwt_shape_detection() {
        assert!(looks_like_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
        assert!(!looks_like_jwt("s3cr3t"));
        assert!(!looks_like_jwt("1.2.3"));
        assert!(!looks_like_jwt("a.b.c"));
        assert!(!looks_like_jwt("not a jwt at all"));
    }
}
