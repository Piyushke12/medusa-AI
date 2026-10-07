//! Persistent configuration: `config.json` next to the state cache
//! (`%APPDATA%\medusa\` on Windows, `~/.medusa/` elsewhere).
//!
//! Precedence (highest wins): environment variables → selected provider →
//! config file → error. The API key is read into memory only and never
//! logged.
//!
//! Example `config.json` with a named provider selected:
//!
//! ```json
//! {
//!   "provider": "nvidia",
//!   "model": {
//!     "base_url": "https://provider.example.com/v1",
//!     "api_key": "sk-...",
//!     "model": "gpt-4o-mini",
//!     "timeout_secs": 60
//!   },
//!   "providers": {
//!     "my-gateway": {
//!       "base_url": "https://gw.internal/v1",
//!       "api_key_env": "GW_API_KEY",
//!       "model": "some-model"
//!     }
//!   }
//! }
//! ```
//!
//! `"provider"` (or `MEDUSA_MODEL_PROVIDER`) selects a named provider: a
//! builtin catalog entry (e.g. `nvidia`, `claude-code`, `opencode`) or one
//! from `"providers"`. The provider supplies base_url/model defaults and
//! reads its key from the env var named by `api_key_env` — so secrets stay
//! out of the file. The plain `"model"` block remains the fallback when no
//! provider is selected, and every field is still overridable via
//! `MEDUSA_MODEL_*`.
//!
//! A provider entry (or the model block) with a `"command"` resolves to a
//! local harness instead of HTTP — no key or URL needed:
//!
//! ```json
//! {
//!   "provider": "claude-code",
//!   "providers": {
//!     "my-cli": {
//!       "command": "opencode",
//!       "args": ["run", "{prompt}"],
//!       "timeout_secs": 300
//!     }
//!   }
//! }
//! ```
//!
//! `"{prompt}"` is replaced with the model prompt; without it the prompt
//! is appended as the last argument.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::agent::model::{ModelError, OpenAiConfig};

/// Builtin provider catalog: public endpoint metadata only — never
/// secrets. Keys are read from each provider's env var at runtime.
/// CLI entries (`command` set) run a local harness instead of HTTP and
/// need no key, base URL, or model id.
pub struct BuiltinProvider {
    pub id: &'static str,
    pub base_url: Option<&'static str>,
    pub api_key_env: Option<&'static str>,
    pub default_model: Option<&'static str>,
    /// Local executable (e.g. `"claude"`). When set, this entry resolves
    /// to a CLI backend: the harness is spawned per model call with
    /// `args` (see [`CliBackendConfig`]).
    pub command: Option<&'static str>,
    pub args: Option<&'static [&'static str]>,
}

pub const BUILTIN_PROVIDERS: &[BuiltinProvider] = &[
    BuiltinProvider {
        id: "nvidia",
        base_url: Some("https://integrate.api.nvidia.com/v1"),
        api_key_env: Some("NVIDIA_API_KEY"),
        default_model: Some("deepseek-ai/deepseek-v4.1-flash"),
        command: None,
        args: None,
    },
    // Anthropic Claude via its OpenAI-compatible endpoint
    // (`{base}/chat/completions` with a Bearer key — the same wire
    // shape `OpenAiCompatibleProvider` already speaks, including the
    // `usage` block that drives the context meter). Key from
    // `ANTHROPIC_API_KEY`, never from the config file.
    BuiltinProvider {
        id: "claude",
        base_url: Some("https://api.anthropic.com/v1"),
        api_key_env: Some("ANTHROPIC_API_KEY"),
        default_model: Some("claude-opus-5-5"),
        command: None,
        args: None,
    },
    // Claude Code CLI: uses the subscription login (`claude login`),
    // not API credits. One-shot `-p` invocation per model call.
    BuiltinProvider {
        id: "claude-code",
        base_url: None,
        api_key_env: None,
        default_model: None,
        command: Some("claude"),
        args: Some(&["-p", "{prompt}"]),
    },
    // opencode CLI, same one-shot shape (`opencode run <message>`).
    // Authenticates via its own `opencode auth` setup.
    BuiltinProvider {
        id: "opencode",
        base_url: None,
        api_key_env: None,
        default_model: None,
        command: Some("opencode"),
        args: Some(&["run", "{prompt}"]),
    },
];

pub fn builtin_provider(id: &str) -> Option<&'static BuiltinProvider> {
    BUILTIN_PROVIDERS.iter().find(|p| p.id == id)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFileConfig {
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Local harness executable (e.g. `"claude"`). When set, the model
    /// block resolves to a CLI backend: no base URL or key is needed.
    #[serde(default)]
    pub command: Option<String>,
    /// Static argv for the harness. `"{prompt}"` is replaced with the
    /// model prompt; when absent, the prompt is appended as the last
    /// argument. E.g. `["-p", "{prompt}"]` for Claude Code.
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

/// One named provider entry in the config file (custom gateways).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderFileConfig {
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    /// Env var to read the key from (keeps secrets out of the file).
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Local harness executable — see [`ModelFileConfig::command`].
    /// Takes precedence over `base_url`: a `command` entry always
    /// resolves to a CLI backend, never HTTP.
    #[serde(default)]
    pub command: Option<String>,
    /// Static argv for the harness — see [`ModelFileConfig::args`].
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

/// A resolved local-harness backend: what to spawn per model call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliBackendConfig {
    pub exe: String,
    pub args: Vec<String>,
    pub label: String,
    pub timeout_secs: u64,
}

/// A resolved model backend: an HTTP endpoint or a local harness
/// subprocess. Both implement the same `ModelProvider` contract, so the
/// drive loop, context meter (char/4 estimate for CLI output), retries,
/// and compaction behave identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelBackend {
    Http(OpenAiConfig),
    Cli(CliBackendConfig),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MedusaConfig {
    /// Active provider name: selects from the builtin catalog or the
    /// `providers` map. Overridable via `MEDUSA_MODEL_PROVIDER`.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: ModelFileConfig,
    #[serde(default)]
    pub providers: HashMap<String, ProviderFileConfig>,
    /// Model context window in tokens (context meter + auto-compaction).
    /// Overridable via `MEDUSA_MODEL_CONTEXT_TOKENS`. Default 128000.
    #[serde(default)]
    pub context_tokens: Option<u64>,
    /// Auto-compact at this percent of the window. Overridable via
    /// `MEDUSA_COMPACTION_THRESHOLD_PCT`. Default 85.
    #[serde(default)]
    pub compaction_threshold_pct: Option<u8>,
    /// Conversation turns kept verbatim across a compaction.
    /// Overridable via `MEDUSA_COMPACT_KEEP_TURNS`. Default 4.
    #[serde(default)]
    pub compact_keep_turns: Option<usize>,
}

/// Resolved context/compaction settings: file values, else env, else
/// builtins. `lookup` is injectable so tests never touch the real
/// process environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextSettings {
    pub context_tokens: u64,
    pub compaction_threshold_pct: u8,
    pub compact_keep_turns: usize,
}

impl Default for ContextSettings {
    fn default() -> Self {
        Self {
            context_tokens: 128_000,
            compaction_threshold_pct: 85,
            compact_keep_turns: 4,
        }
    }
}

pub fn resolve_context_settings(
    file: &MedusaConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> ContextSettings {
    let tokens = lookup("MEDUSA_MODEL_CONTEXT_TOKENS")
        .and_then(|v| v.parse().ok())
        .or(file.context_tokens)
        .filter(|t| *t > 0)
        .unwrap_or(128_000);
    let pct = lookup("MEDUSA_COMPACTION_THRESHOLD_PCT")
        .and_then(|v| v.parse().ok())
        .or(file.compaction_threshold_pct)
        .filter(|p| *p > 0 && *p <= 100)
        .unwrap_or(85);
    let keep = lookup("MEDUSA_COMPACT_KEEP_TURNS")
        .and_then(|v| v.parse().ok())
        .or(file.compact_keep_turns)
        .unwrap_or(4);
    ContextSettings {
        context_tokens: tokens,
        compaction_threshold_pct: pct,
        compact_keep_turns: keep,
    }
}

pub fn config_path() -> std::path::PathBuf {
    super::cache::state_dir().join("config.json")
}

/// Load the file; missing/unparsable file == empty config (env may still
/// provide everything). A corrupt file is NOT fatal: the error surfaces only
/// if the final merged config is incomplete. A leading UTF-8 BOM (written
/// by PowerShell `Set-Content -Encoding UTF8` and some Windows editors)
/// is stripped — `serde_json` rejects BOM-prefixed text and a stray BOM
/// must not silently wipe the whole config.
pub fn load_file_config() -> MedusaConfig {
    let path = config_path();
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    if text.trim().is_empty() {
        return MedusaConfig::default();
    }
    serde_json::from_str(text).unwrap_or_default()
}

/// Merge env over file over selected provider. `lookup` is injectable so
/// tests never touch the real process environment.
pub fn resolve_with(
    file: &MedusaConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ModelBackend, ModelError> {
    let selected = nonempty(lookup("MEDUSA_MODEL_PROVIDER")).or_else(|| file.provider.clone());
    resolve_selection(file, selected.as_deref(), lookup)
}

/// Resolve with an EXPLICIT provider selection (env `MEDUSA_MODEL_PROVIDER`
/// does not apply) — used by the desktop switch to validate a choice
/// before persisting it.
pub fn resolve_selection(
    file: &MedusaConfig,
    selected: Option<&str>,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ModelBackend, ModelError> {
    let nonempty = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    let missing = |env_key: &str| {
        ModelError::MissingConfig(format!(
            "{env_key} not set and no config file value (see {})",
            config_path().display()
        ))
    };

    // Resolve the named entry (if any) once; unknown names fail here for
    // both backends.
    let custom = selected.and_then(|name| file.providers.get(name));
    let builtin = selected.and_then(builtin_provider);
    if selected.is_some() && custom.is_none() && builtin.is_none() {
        let name = selected.unwrap_or("?");
        return Err(ModelError::MissingConfig(format!(
            "unknown provider `{name}` — builtin providers: {}; custom ones come from the `providers` map in {}",
            BUILTIN_PROVIDERS
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>()
                .join(", "),
            config_path().display()
        )));
    }

    // CLI backend: a `command` on the selected entry (or the model block
    // when nothing is selected) routes to a local harness subprocess.
    // No API key is required; `command` wins over `base_url` when both
    // are set.
    let cli_command: Option<String> = custom
        .and_then(|c| c.command.clone())
        .or_else(|| builtin.and_then(|b| b.command.map(str::to_string)))
        .or_else(|| {
            if selected.is_none() {
                file.model.command.clone()
            } else {
                None
            }
        });
    if let Some(exe) = cli_command.filter(|c| !c.trim().is_empty()) {
        let entry_args: Option<Vec<String>> = custom
            .and_then(|c| c.args.clone())
            .or_else(|| {
                builtin.and_then(|b| {
                    b.args
                        .map(|a| a.iter().map(|s| s.to_string()).collect())
                })
            })
            .or_else(|| {
                if selected.is_none() {
                    file.model.args.clone()
                } else {
                    None
                }
            });
        let entry_timeout: Option<u64> = custom
            .and_then(|c| c.timeout_secs)
            .or_else(|| {
                if selected.is_none() {
                    file.model.timeout_secs
                } else {
                    None
                }
            });
        // Local harnesses are slow (process spawn, subscription routing):
        // default 300s, still overridable per entry or via env.
        let timeout_secs = lookup("MEDUSA_MODEL_TIMEOUT_SECS")
            .and_then(|v| v.parse().ok())
            .or(entry_timeout)
            .unwrap_or(300);
        return Ok(ModelBackend::Cli(CliBackendConfig {
            exe: exe.trim().to_string(),
            args: entry_args
                .unwrap_or_else(|| vec!["{prompt}".to_string()]),
            label: selected.unwrap_or("cli").to_string(),
            timeout_secs,
        }));
    }

    let mut p_base: Option<String> = None;
    let mut p_key: Option<String> = None;
    let mut p_model: Option<String> = None;
    let mut p_timeout: Option<u64> = None;
    if selected.is_some() {
        p_base = custom
            .and_then(|c| c.base_url.clone())
            .or_else(|| builtin.and_then(|b| b.base_url.map(str::to_string)));
        // Key: inline file value first, then the provider's env var.
        p_key = custom.and_then(|c| c.api_key.clone()).or_else(|| {
            let env_name = custom
                .and_then(|c| c.api_key_env.clone())
                .or_else(|| builtin.and_then(|b| b.api_key_env.map(str::to_string)))?;
            nonempty(lookup(&env_name))
        });
        if p_key.is_none() {
            let name = selected.unwrap_or("?");
            let env_name = custom
                .and_then(|c| c.api_key_env.clone())
                .or_else(|| builtin.and_then(|b| b.api_key_env.map(str::to_string)));
            let hint = match env_name {
                Some(e) => format!(
                    "set {e} (or add \"api_key\" to the `{name}` entry in {})",
                    config_path().display()
                ),
                None => format!(
                    "add \"api_key\" to the `{name}` entry in {}",
                    config_path().display()
                ),
            };
            return Err(ModelError::MissingConfig(format!(
                "provider `{name}` selected but no API key available — {hint}"
            )));
        }
        p_model = custom
            .and_then(|c| c.model.clone())
            .or_else(|| builtin.and_then(|b| b.default_model.map(str::to_string)));
        p_timeout = custom.and_then(|c| c.timeout_secs);
    }

    // Field precedence: MEDUSA_MODEL_* env > selected provider > model block.
    // Values are trimmed: copy-pasted secrets routinely carry a trailing
    // newline, which would otherwise ride into the auth header and fail.
    let mut base_url = nonempty(lookup("MEDUSA_MODEL_BASE_URL"))
        .or(p_base)
        .or(file.model.base_url.clone())
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| missing("MEDUSA_MODEL_BASE_URL"))?;
    while base_url.ends_with('/') {
        base_url.pop();
    }
    let api_key = nonempty(lookup("MEDUSA_MODEL_API_KEY"))
        .or(p_key)
        .or(file.model.api_key.clone())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| missing("MEDUSA_MODEL_API_KEY"))?;
    let model = nonempty(lookup("MEDUSA_MODEL_NAME"))
        .or(p_model)
        .or(file.model.model.clone())
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .ok_or_else(|| missing("MEDUSA_MODEL_NAME"))?;
    let timeout_secs = lookup("MEDUSA_MODEL_TIMEOUT_SECS")
        .and_then(|v| v.parse().ok())
        .or(p_timeout)
        .or(file.model.timeout_secs)
        .unwrap_or(120);
    Ok(ModelBackend::Http(OpenAiConfig {
        base_url,
        api_key,
        model,
        timeout_secs,
    }))
}

/// One selectable provider/model choice for UIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSummary {
    /// Selection id; empty string = the plain `model` block (no provider).
    pub id: String,
    /// Short tag shown in front of the model name (provider id, or the
    /// gateway host for the model block).
    pub tag: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    /// `builtin` | `config` | `model-block`
    pub kind: String,
}

/// Every provider the user can switch to: the plain `model` block plus the
/// builtin catalog plus custom `providers` entries (a custom entry with a
/// builtin's id overrides it).
pub fn list_provider_choices(file: &MedusaConfig) -> Vec<ProviderSummary> {
    let mut out = Vec::new();
    let tag = file
        .model
        .base_url
        .as_deref()
        .and_then(|u| u.split_once("://").map(|(_, rest)| rest))
        .and_then(|u| u.split(['/', '?', '#']).next())
        .map(|h| h.to_string())
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());
    out.push(ProviderSummary {
        id: String::new(),
        tag,
        model: file.model.model.clone(),
        base_url: file.model.base_url.clone(),
        kind: "model-block".into(),
    });
    for b in BUILTIN_PROVIDERS {
        if file.providers.contains_key(b.id) {
            continue;
        }
        let cli = b.command.is_some();
        out.push(ProviderSummary {
            id: b.id.to_string(),
            tag: b.id.to_string(),
            model: b
                .default_model
                .map(|m| m.to_string())
                .or_else(|| b.command.map(|c| c.to_string())),
            base_url: b.base_url.map(|u| u.to_string()),
            kind: if cli { "cli".into() } else { "builtin".into() },
        });
    }
    for (id, p) in &file.providers {
        let cli = p.command.as_ref().is_some_and(|c| !c.trim().is_empty());
        out.push(ProviderSummary {
            id: id.clone(),
            tag: id.clone(),
            model: p.model.clone().or_else(|| p.command.clone()),
            base_url: p.base_url.clone(),
            kind: if cli { "cli".into() } else { "config".into() },
        });
    }
    out
}

/// Which provider is currently selected (env override wins, mirroring
/// resolution).
pub fn active_provider_id(
    file: &MedusaConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    nonempty(lookup("MEDUSA_MODEL_PROVIDER")).or_else(|| file.provider.clone())
}

fn nonempty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

/// Set (or clear) the `"provider"` field in `config.json`, preserving all
/// other fields. Pure JSON-in/JSON-out core for testability.
pub fn set_provider_in_value(root: &mut serde_json::Value, id: Option<&str>) -> Result<(), String> {
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "config root is not a JSON object".to_string())?;
    match id.filter(|s| !s.trim().is_empty()) {
        Some(id) => {
            obj.insert("provider".into(), serde_json::json!(id));
        }
        None => {
            obj.remove("provider");
        }
    }
    Ok(())
}

/// Persist the provider selection to `config.json` (creates the file when
/// missing; unknown fields are preserved).
pub fn set_provider_in_config(id: Option<&str>) -> Result<(), String> {
    let path = config_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut root: serde_json::Value = if text.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&text).map_err(|e| format!("config parse: {e}"))?
    };
    set_provider_in_value(&mut root, id)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create config dir: {e}"))?;
    }
    let pretty = serde_json::to_string_pretty(&root).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&path, pretty).map_err(|e| format!("write config: {e}"))?;
    Ok(())
}

/// Production entry point: real process environment over the config file.
pub fn resolve_model_config(file: &MedusaConfig) -> Result<ModelBackend, ModelError> {
    resolve_with(file, &|k| std::env::var(k).ok())
}

/// Where to create the file, for help text.
pub fn config_location_help() -> String {
    format!(
        "Create {} with a \"model\" object (base_url, api_key, model), a \"provider\" name (e.g. nvidia), or set MEDUSA_MODEL_PROVIDER/BASE_URL/_API_KEY/_NAME.",
        config_path().display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(map: &'a HashMap<&str, &str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| map.get(k).map(|v| v.to_string())
    }

    /// Resolve and unwrap the HTTP backend (all pre-existing tests are
    /// HTTP selections; CLI selections have their own tests below).
    fn http(file: &MedusaConfig, env: &HashMap<&str, &str>) -> OpenAiConfig {
        match resolve_with(file, &lookup(env)).unwrap() {
            ModelBackend::Http(cfg) => cfg,
            ModelBackend::Cli(_) => panic!("expected HTTP backend"),
        }
    }

    /// Resolve and unwrap the CLI backend.
    fn cli(file: &MedusaConfig, env: &HashMap<&str, &str>) -> CliBackendConfig {
        match resolve_with(file, &lookup(env)).unwrap() {
            ModelBackend::Cli(cfg) => cfg,
            ModelBackend::Http(_) => panic!("expected CLI backend"),
        }
    }

    #[test]
    fn empty_file_config_resolves_nothing() {
        let file = MedusaConfig::default();
        let env = HashMap::new();
        assert!(resolve_with(&file, &lookup(&env)).is_err());
    }

    #[test]
    fn context_settings_default_and_resolve() {
        let env = HashMap::new();
        let s = resolve_context_settings(&MedusaConfig::default(), &lookup(&env));
        assert_eq!(s, ContextSettings::default());
        assert_eq!(s.context_tokens, 128_000);
        // Env beats file; invalid values fall back to defaults.
        let env: HashMap<&str, &str> = [
            ("MEDUSA_MODEL_CONTEXT_TOKENS", "64000"),
            ("MEDUSA_COMPACTION_THRESHOLD_PCT", "0"),
            ("MEDUSA_COMPACT_KEEP_TURNS", "7"),
        ]
        .into_iter()
        .collect();
        let file = MedusaConfig {
            compaction_threshold_pct: Some(90),
            ..MedusaConfig::default()
        };
        let s = resolve_context_settings(&file, &lookup(&env));
        assert_eq!(s.context_tokens, 64_000);
        assert_eq!(s.compaction_threshold_pct, 85, "0 is invalid → default");
        assert_eq!(s.compact_keep_turns, 7);
        // File value applies when env is silent.
        let env = HashMap::new();
        let s = resolve_context_settings(&file, &lookup(&env));
        assert_eq!(s.compaction_threshold_pct, 90);
    }

    #[test]
    fn file_values_fill_gaps_env_leaves() {
        let env = HashMap::new();
        let file = MedusaConfig {
            model: ModelFileConfig {
                base_url: Some("https://example.com/v1/".into()),
                api_key: Some("k".into()),
                model: Some("m".into()),
                timeout_secs: Some(33),
                command: None,
                args: None,
            },
            ..MedusaConfig::default()
        };
        let cfg = http(&file, &env);
        assert_eq!(cfg.base_url, "https://example.com/v1"); // trailing slash trimmed
        assert_eq!(cfg.timeout_secs, 33);
    }

    #[test]
    fn env_beats_file() {
        let env: HashMap<&str, &str> = [
            ("MEDUSA_MODEL_BASE_URL", "https://env.example.com/v1"),
            ("MEDUSA_MODEL_API_KEY", "env-key"),
            ("MEDUSA_MODEL_NAME", "from-env"),
        ]
        .into_iter()
        .collect();
        let file = MedusaConfig {
            model: ModelFileConfig {
                base_url: Some("https://file.example.com/v1".into()),
                api_key: Some("file-key".into()),
                model: Some("from-file".into()),
                timeout_secs: None,
                command: None,
                args: None,
            },
            ..MedusaConfig::default()
        };
        let cfg = http(&file, &env);
        assert_eq!(cfg.model, "from-env");
        assert_eq!(cfg.base_url, "https://env.example.com/v1");
        assert_eq!(cfg.api_key, "env-key");
    }

    #[test]
    fn file_config_parses_from_json() {
        let file: MedusaConfig = serde_json::from_str(
            r#"{"model":{"base_url":"https://x/v1","api_key":"k","model":"m"}}"#,
        )
        .unwrap();
        assert_eq!(file.model.model.as_deref(), Some("m"));
    }

    #[test]
    fn builtin_nvidia_provider_resolves_from_its_env_key() {
        let env: HashMap<&str, &str> = [
            ("MEDUSA_MODEL_PROVIDER", "nvidia"),
            ("NVIDIA_API_KEY", "nv-secret"),
        ]
        .into_iter()
        .collect();
        let file = MedusaConfig::default();
        let cfg = http(&file, &env);
        assert_eq!(cfg.base_url, "https://integrate.api.nvidia.com/v1");
        assert_eq!(cfg.api_key, "nv-secret");
        assert_eq!(cfg.model, "deepseek-ai/deepseek-v4.1-flash");
    }

    #[test]
    fn provider_selected_via_file_field() {
        let env: HashMap<&str, &str> = [("NVIDIA_API_KEY", "nv-secret")].into_iter().collect();
        let file = MedusaConfig {
            provider: Some("nvidia".into()),
            ..MedusaConfig::default()
        };
        let cfg = http(&file, &env);
        assert_eq!(cfg.model, "deepseek-ai/deepseek-v4.1-flash");
    }

    #[test]
    fn builtin_claude_provider_resolves_from_its_env_key() {
        // Claude serves OpenAI-compatible /chat/completions off the same
        // base URL with a Bearer key, so the shared provider speaks it
        // with no wire changes.
        let env: HashMap<&str, &str> = [("ANTHROPIC_API_KEY", "sk-ant-secret")].into_iter().collect();
        let file = MedusaConfig {
            provider: Some("claude".into()),
            ..MedusaConfig::default()
        };
        let cfg = http(&file, &env);
        assert_eq!(cfg.base_url, "https://api.anthropic.com/v1");
        assert_eq!(cfg.api_key, "sk-ant-secret");
        assert_eq!(cfg.model, "claude-opus-5-5");
    }

    #[test]
    fn missing_claude_key_names_the_env_var() {
        let env: HashMap<&str, &str> = [("MEDUSA_MODEL_PROVIDER", "claude")].into_iter().collect();
        let file = MedusaConfig::default();
        let err = resolve_with(&file, &lookup(&env)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("ANTHROPIC_API_KEY"), "error was: {msg}");
    }

    #[test]
    fn pasted_secrets_with_surrounding_whitespace_are_trimmed() {
        // Copy-paste from a browser routinely trails a newline; it must
        // not ride into the auth header (401) or model id (404).
        let env: HashMap<&str, &str> = [
            ("MEDUSA_MODEL_PROVIDER", "claude"),
            ("ANTHROPIC_API_KEY", "sk-ant-secret\n"),
        ]
        .into_iter()
        .collect();
        let file = MedusaConfig::default();
        let cfg = http(&file, &env);
        assert_eq!(cfg.api_key, "sk-ant-secret");
    }

    #[test]
    fn builtin_cli_harness_resolves_without_a_key() {
        // `opencode` needs no API key in Medusa config — it authenticates
        // itself (`opencode auth`). Resolution must not demand one.
        let env = HashMap::new();
        let file = MedusaConfig {
            provider: Some("opencode".into()),
            ..MedusaConfig::default()
        };
        let cfg = cli(&file, &env);
        assert_eq!(cfg.exe, "opencode");
        assert_eq!(cfg.args, vec!["run".to_string(), "{prompt}".to_string()]);
        assert_eq!(cfg.label, "opencode");
        assert_eq!(cfg.timeout_secs, 300);
    }

    #[test]
    fn builtin_claude_code_resolves_without_a_key() {
        let env = HashMap::new();
        let file = MedusaConfig {
            provider: Some("claude-code".into()),
            ..MedusaConfig::default()
        };
        let cfg = cli(&file, &env);
        assert_eq!(cfg.exe, "claude");
        assert_eq!(cfg.args, vec!["-p".to_string(), "{prompt}".to_string()]);
    }

    #[test]
    fn custom_command_wins_over_base_url_and_takes_timeout() {
        let env: HashMap<&str, &str> =
            [("MEDUSA_MODEL_TIMEOUT_SECS", "42")].into_iter().collect();
        let file: MedusaConfig = serde_json::from_str(
            r#"{"provider":"local","providers":{"local":{"command":"myharness","args":["ask","{prompt}"],"timeout_secs":60,"base_url":"https://unused/v1"}}}"#,
        )
        .unwrap();
        let cfg = cli(&file, &env);
        assert_eq!(cfg.exe, "myharness");
        assert_eq!(cfg.args, vec!["ask".to_string(), "{prompt}".to_string()]);
        // Env beats the entry timeout.
        assert_eq!(cfg.timeout_secs, 42);
        let env = HashMap::new();
        let cfg = cli(&file, &env);
        assert_eq!(cfg.timeout_secs, 60);
    }

    #[test]
    fn model_block_command_resolves_cli_by_default() {
        let env = HashMap::new();
        let file: MedusaConfig =
            serde_json::from_str(r#"{"model":{"command":"claude"}}"#).unwrap();
        let cfg = cli(&file, &env);
        assert_eq!(cfg.exe, "claude");
        // No `{prompt}` placeholder: the prompt is appended.
        assert_eq!(cfg.args, vec!["{prompt}".to_string()]);
        assert_eq!(cfg.label, "cli");
    }

    #[test]
    fn cli_choices_carry_cli_kind() {
        let file = MedusaConfig::default();
        let choices = list_provider_choices(&file);
        let kinds: std::collections::HashMap<&str, &str> = choices
            .iter()
            .map(|c| (c.id.as_str(), c.kind.as_str()))
            .collect();
        assert_eq!(kinds["opencode"], "cli");
        assert_eq!(kinds["claude-code"], "cli");
        assert_eq!(kinds["nvidia"], "builtin");
    }

    #[test]
    fn bom_prefixed_config_still_parses() {
        // PowerShell's `Set-Content -Encoding UTF8` writes a BOM; the
        // loader must strip it instead of silently falling to empty.
        let dir = std::env::temp_dir().join(format!("medusa-cfg-bom-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bom.json");
        std::fs::write(
            &path,
            format!("\u{feff}{{\"model\":{{\"model\":\"glm-latest\"}}}}"),
        )
        .unwrap();
        let parsed: MedusaConfig = serde_json::from_str(
            std::fs::read_to_string(&path)
                .unwrap()
                .trim_start_matches('\u{feff}'),
        )
        .unwrap();
        assert_eq!(parsed.model.model.as_deref(), Some("glm-latest"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_provider_entry_with_api_key_env() {
        let env: HashMap<&str, &str> = [("GRID_KEY", "grid-secret")].into_iter().collect();
        let file: MedusaConfig = serde_json::from_str(
            r#"{"provider":"gw","providers":{"gw":{"base_url":"https://gw.internal/v1/","api_key_env":"GRID_KEY","model":"m1","timeout_secs":42}}}"#,
        )
        .unwrap();
        let cfg = http(&file, &env);
        assert_eq!(cfg.base_url, "https://gw.internal/v1"); // slash trimmed
        assert_eq!(cfg.api_key, "grid-secret");
        assert_eq!(cfg.model, "m1");
        assert_eq!(cfg.timeout_secs, 42);
    }

    #[test]
    fn medusa_env_overrides_beat_the_selected_provider() {
        let env: HashMap<&str, &str> = [
            ("MEDUSA_MODEL_PROVIDER", "nvidia"),
            ("NVIDIA_API_KEY", "nv-secret"),
            ("MEDUSA_MODEL_NAME", "other-model"),
        ]
        .into_iter()
        .collect();
        let file = MedusaConfig::default();
        let cfg = http(&file, &env);
        assert_eq!(cfg.model, "other-model");
        assert_eq!(cfg.base_url, "https://integrate.api.nvidia.com/v1");
    }

    #[test]
    fn unknown_provider_fails_with_known_list() {
        let env: HashMap<&str, &str> = [("MEDUSA_MODEL_PROVIDER", "nope")].into_iter().collect();
        let file = MedusaConfig::default();
        let err = resolve_with(&file, &lookup(&env)).unwrap_err();
        assert!(format!("{err:?}").contains("unknown provider `nope`"));
    }

    #[test]
    fn missing_provider_key_names_the_env_var() {
        let env: HashMap<&str, &str> = [("MEDUSA_MODEL_PROVIDER", "nvidia")].into_iter().collect();
        let file = MedusaConfig::default();
        let err = resolve_with(&file, &lookup(&env)).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("NVIDIA_API_KEY"), "error was: {msg}");
    }

    #[test]
    fn provider_choices_list_default_builtin_and_custom() {
        let file: MedusaConfig = serde_json::from_str(
            r#"{"model":{"base_url":"https://grid.ai.juspay.net/","api_key":"k","model":"glm-latest"},"providers":{"gw":{"base_url":"https://gw/v1","model":"m1"}}}"#,
        )
        .unwrap();
        let choices = list_provider_choices(&file);
        let ids: Vec<&str> = choices.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["", "nvidia", "claude", "claude-code", "opencode", "gw"]
        );
        assert_eq!(choices[0].tag, "grid.ai.juspay.net");
        assert_eq!(choices[0].model.as_deref(), Some("glm-latest"));
        assert_eq!(
            choices[1].model.as_deref(),
            Some("deepseek-ai/deepseek-v4.1-flash")
        );
        assert_eq!(choices[2].model.as_deref(), Some("claude-opus-5-5"));
        // A custom entry may override a builtin id.
        let file2: MedusaConfig = serde_json::from_str(
            r#"{"providers":{"nvidia":{"base_url":"https://mirror/v1","model":"m2"}}}"#,
        )
        .unwrap();
        let c2 = list_provider_choices(&file2);
        let ids2: Vec<&str> = c2.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids2, vec!["", "claude", "claude-code", "opencode", "nvidia"]);
        assert_eq!(c2[4].base_url.as_deref(), Some("https://mirror/v1"));
        assert_eq!(c2[4].kind, "config");
    }

    #[test]
    fn set_provider_round_trips_in_json_value() {
        let mut root: serde_json::Value =
            serde_json::from_str(r#"{"model":{"base_url":"x"}}"#).unwrap();
        set_provider_in_value(&mut root, Some("nvidia")).unwrap();
        assert_eq!(root["provider"], "nvidia");
        assert_eq!(root["model"]["base_url"], "x"); // other fields kept
        set_provider_in_value(&mut root, None).unwrap();
        assert!(root.get("provider").is_none());
    }

    #[test]
    fn resolve_selection_ignores_env_provider_var() {
        // The desktop switch validates an explicit choice; MEDUSA_MODEL_PROVIDER
        // must not hijack it.
        let env: HashMap<&str, &str> = [
            ("MEDUSA_MODEL_PROVIDER", "nvidia"),
            ("NVIDIA_API_KEY", "nv"),
        ]
        .into_iter()
        .collect();
        let file: MedusaConfig = serde_json::from_str(
            r#"{"providers":{"gw":{"base_url":"https://gw/v1","api_key":"k","model":"m1"}}}"#,
        )
        .unwrap();
        let cfg = match resolve_selection(&file, Some("gw"), &lookup(&env)).unwrap() {
            ModelBackend::Http(cfg) => cfg,
            ModelBackend::Cli(_) => panic!("expected HTTP backend"),
        };
        assert_eq!(cfg.base_url, "https://gw/v1");
        assert_eq!(cfg.model, "m1");
    }
}
