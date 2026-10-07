//! Capability providers: **one implementation of a capability**.
//!
//! ```text
//! Capability = WHAT medusa wants     (network.port_scan)
//! Provider   = HOW it can be done    (NmapProvider, NaabuProvider)
//! Executor   = how it actually runs  (ProcessExecutor, future: HTTP/MCP)
//! ```
//!
//! The LLM decides *what capability it needs* â€” never which binary,
//! never which flags. [`ProviderRegistry::select`] resolves a capability
//! to an appropriate healthy provider (priority-ordered, option-aware);
//! the selected provider translates the semantic request into its own
//! invocation. Argument translation is trusted runtime code driven by
//! declarative [`OptionBinding`] data â€” the model's options can only
//! map onto whitelisted flags with validated values.
//!
//! Adding a non-CLI provider later (browser, HTTP API, MCP) means
//! implementing [`CapabilityProvider`] and registering it; `AgentRuntime`
//! never changes.

use std::sync::Arc;
use std::time::Duration;

use crate::model::{EnvironmentState, ToolDefinition, ToolStatus};
use crate::registry::ToolRegistry;

use super::executor::{resolve_args, ProcessExecutor, ToolResult};
use super::model::{OptionSet, OptionValue};

/// The runtime's validated request: WHAT capability, on WHAT target, with
/// WHICH semantic options. This is the only execution-adjacent type the
/// model can influence, and only through the capability's declared schema.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityRequest {
    pub capability: String,
    pub target: String,
    pub options: OptionSet,
    pub reason: String,
}

impl CapabilityRequest {
    pub fn new(capability: &str, target: &str, reason: &str) -> Self {
        Self {
            capability: capability.to_string(),
            target: target.to_string(),
            options: OptionSet::new(),
            reason: reason.to_string(),
        }
    }
}

/// Errors at the capability-resolution / provider-selection boundary.
/// Deliberately distinct from execution failures (timeouts, exit codes)
/// and from policy rejections (scope, risk, arguments) so the model can
/// choose a different path when appropriate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// No provider implements this capability at all (honest registry gap).
    NoProviderRegistered { capability: String },
    /// Providers exist but none is installed + healthy.
    NoProviderAvailable {
        capability: String,
        known_providers: Vec<String>,
    },
    /// Healthy providers exist but none supports the requested option.
    OptionUnsupported {
        capability: String,
        option: String,
        available_providers: Vec<String>,
    },
}

impl ProviderError {
    /// Stable prefix the runtime/tests can match on.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoProviderRegistered { .. } => "no_provider_registered",
            Self::NoProviderAvailable { .. } => "no_provider_available",
            Self::OptionUnsupported { .. } => "option_unsupported",
        }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProviderRegistered { capability } => {
                write!(f, "no provider supports `{capability}` yet")
            }
            Self::NoProviderAvailable {
                capability,
                known_providers,
            } => {
                if known_providers.is_empty() {
                    write!(f, "no healthy provider for `{capability}`")
                } else {
                    write!(
                        f,
                        "no healthy provider for `{capability}` (known providers, all unavailable: {})",
                        known_providers.join(", ")
                    )
                }
            }
            Self::OptionUnsupported {
                capability,
                option,
                available_providers,
            } => {
                write!(
                    f,
                    "option `{option}` is not supported by any available provider of `{capability}` ({}); retry without it or use a different capability",
                    available_providers.join(", ")
                )
            }
        }
    }
}

/// Everything a provider needs to run. Carries the executor (process
/// today; future providers may ignore it) and the environment snapshot
/// (executable paths, health). Providers must not mutate either.
pub struct ExecutionContext<'a> {
    pub executor: &'a dyn ProcessExecutor,
    pub env: &'a EnvironmentState,
}

/// One implementation of a capability. Concrete today: [`ProcessProvider`]
/// (CLI tools). Future: browser, HTTP API, MCP â€” same trait, same runtime.
pub trait CapabilityProvider: Send + Sync {
    /// Stable provider id (== tool id for CLI providers), e.g. "nmap".
    fn id(&self) -> &str;
    /// Capabilities this provider implements.
    fn capabilities(&self) -> &[String];
    /// 0-100, higher wins during selection (preserves existing behavior).
    fn priority(&self) -> u8;
    /// Does this provider bind the semantic `option` for `capability`?
    fn supports_option(&self, capability: &str, option: &str) -> bool;
    /// Installed + healthy in this environment?
    fn is_available(&self, env: &EnvironmentState) -> bool;
    /// Translate the semantic request into this provider's invocation and
    /// run it through the executor. Trusted runtime code: the model never
    /// constructs argv.
    fn execute(&self, request: &CapabilityRequest, ctx: &ExecutionContext) -> ToolResult;
}

/// Tools that operate on local filesystem paths (or local images) and
/// cannot act on URLs or remote hosts. Guarded at the provider boundary:
/// a URL aimed at these tools fails instantly with actionable feedback
/// instead of a tool crash, three retries and 20+ wasted seconds.
const FS_ONLY_TOOLS: &[&str] = &["semgrep", "trivy", "syft", "grype", "gitleaks", "codeql"];

/// Does `target` look remote (URL / host:port / bare domain) rather than
/// a local path? Local paths that exist always pass; Windows drive
/// letters and any path separators pass; anything URL-shaped or
/// host-shaped is rejected for filesystem tools.
fn fs_target_reject_reason(tool_id: &str, target: &str) -> Option<String> {
    let t = target.trim();
    if t.is_empty() || std::path::Path::new(t).exists() {
        return None; // a real local path (or empty — let the tool complain)
    }
    let has_scheme = t.contains("://") || t.starts_with("http:") || t.starts_with("https:");
    let host_port = !t.contains('/') && !t.contains('\\') && t.matches(':').count() == 1 && {
        let port = t.rsplit(':').next().unwrap_or("");
        !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
    };
    let domainish = !t.contains('/')
        && !t.contains('\\')
        && !t.contains(' ')
        && t.matches('.').count() >= 1
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':');
    if has_scheme || host_port || domainish {
        Some(format!(
            "`{tool_id}` scans local filesystem paths, not remote targets — `{t}` looks like a URL/host. Use a web capability (http.request, http.probe) for remote content, or point `{tool_id}` at a local source directory"
        ))
    } else {
        None
    }
}

/// CLI-process provider backed by a [`ToolDefinition`]: argv template +
/// semantic option bindings. The registry data (executable candidates,
/// install info, priority) is reused as-is â€” this is the provider-oriented
/// view over the existing tool registry, not a rewrite of it.
pub struct ProcessProvider {
    def: ToolDefinition,
    timeout: Duration,
}

impl ProcessProvider {
    pub fn new(def: ToolDefinition) -> Self {
        Self {
            def,
            timeout: Duration::from_secs(300),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Semantic option â†’ provider argv translation. Only options with a
    /// declared binding can appear here (policy already rejected unknown
    /// options against the capability schema); a missing binding is a
    /// hard error, never a passthrough â€” no model input ever reaches the
    /// process invocation unbound.
    fn translate(&self, request: &CapabilityRequest) -> Result<Vec<String>, String> {
        let mut args = resolve_args(&self.def.default_args, &request.target);
        // Capability-constant flags: bindings with an empty option name
        // (e.g. nmap `-O` for network.os_detection) append whenever the
        // action's capability matches. The model can never supply an
        // empty option name, so these cannot collide with model input.
        for b in &self.def.option_bindings {
            if b.option.is_empty() && b.capability == request.capability {
                args.push(b.flag.clone());
            }
        }
        for (name, value) in &request.options {
            let binding = self
                .def
                .option_bindings
                .iter()
                .find(|b| b.capability == request.capability && b.option == *name)
                .ok_or_else(|| {
                    format!(
                        "provider `{}` does not support option `{name}` for `{}`",
                        self.def.id, request.capability
                    )
                })?;
            let rendered = match value {
                OptionValue::Str(s) => {
                    if binding.value_map.is_empty() {
                        s.clone()
                    } else {
                        binding
                            .value_map
                            .iter()
                            .find(|(k, _)| k == s)
                            .map(|(_, v)| v.clone())
                            .ok_or_else(|| {
                                format!(
                                    "provider `{}` cannot map value `{s}` for option `{name}`",
                                    self.def.id
                                )
                            })?
                    }
                }
                OptionValue::Num(n) => format_option_number(*n),
                OptionValue::Bool(b) => b.to_string(),
            };
            if binding.joined {
                args.push(format!("{}{}", binding.flag, rendered));
            } else {
                args.push(binding.flag.clone());
                args.push(rendered);
            }
        }
        Ok(args)
    }
}

fn format_option_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

impl CapabilityProvider for ProcessProvider {
    fn id(&self) -> &str {
        &self.def.id
    }

    fn capabilities(&self) -> &[String] {
        &self.def.capabilities
    }

    fn priority(&self) -> u8 {
        self.def.priority
    }

    fn supports_option(&self, capability: &str, option: &str) -> bool {
        self.def
            .option_bindings
            .iter()
            .any(|b| b.capability == capability && b.option == option)
    }

    fn is_available(&self, env: &EnvironmentState) -> bool {
        // A provider whose argv has no `{target}` slot cannot execute
        // anything meaningful for a request. Worse, bare invocation of
        // tools like zap (GUI) or rizin (REPL) hangs until the executor
        // timeout. Treat such tools as unavailable providers until real
        // argv — or a sidecar binary — exists for them.
        if !self.def.default_args.iter().any(|a| a.contains("{target}")) {
            return false;
        }
        env.tools
            .get(&self.def.id)
            .is_some_and(|s| s.installed && s.healthy)
    }

    fn execute(&self, request: &CapabilityRequest, ctx: &ExecutionContext) -> ToolResult {
        // Defense in depth: selection checked availability, but re-verify
        // at the execution boundary so a stale environment cannot spawn
        // an uninstalled executable.
        let status: &ToolStatus = match ctx.env.tools.get(&self.def.id) {
            Some(s) if s.installed && s.healthy => s,
            _ => {
                return ToolResult::error(
                    &self.def.id,
                    &request.capability,
                    &request.target,
                    format!("provider `{}` is not installed or not healthy", self.def.id),
                );
            }
        };
        // Target-kind guard: filesystem-only tools reject URL/host targets
        // before any process is spawned. Non-retryable — the same request
        // would fail identically.
        if FS_ONLY_TOOLS.contains(&self.def.id.as_str()) {
            if let Some(reason) = fs_target_reject_reason(&self.def.id, &request.target) {
                return ToolResult::error_non_retryable(
                    &self.def.id,
                    &request.capability,
                    &request.target,
                    reason,
                );
            }
        }
        let exe = match &status.executable_path {
            Some(p) => p.clone(),
            None => {
                return ToolResult::error(
                    &self.def.id,
                    &request.capability,
                    &request.target,
                    format!("no executable path resolved for `{}`", self.def.id),
                );
            }
        };
        let args = match self.translate(request) {
            Ok(a) => a,
            Err(e) => {
                return ToolResult::error(&self.def.id, &request.capability, &request.target, e);
            }
        };
        let out = ctx.executor.run(&exe, &args, self.timeout);
        ToolResult {
            tool_id: self.def.id.clone(),
            capability: request.capability.clone(),
            target: request.target.clone(),
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
            timed_out: out.timed_out,
            error: out.error,
        }
    }
}

/// The provider allow-list. Built from the tool registry; unregistered
/// executables can never become providers no matter what exists on PATH.
/// Selection order: capability support â†’ availability â†’ option support â†’
/// priority (descending). The LLM never calls this.
#[derive(Clone, Default)]
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn CapabilityProvider>>,
}

impl ProviderRegistry {
    pub fn from_tools(tools: &ToolRegistry) -> Self {
        Self {
            providers: tools
                .all()
                .iter()
                // Internal (builtin) tools have their own provider type,
                // registered by the runtime — never a CLI ProcessProvider.
                .filter(|t| !t.builtin)
                .map(|t| Arc::new(ProcessProvider::new(t.clone())) as Arc<dyn CapabilityProvider>)
                .collect(),
        }
    }

    pub fn register(&mut self, provider: Arc<dyn CapabilityProvider>) {
        self.providers.push(provider);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn CapabilityProvider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }

    pub fn all(&self) -> &[Arc<dyn CapabilityProvider>] {
        &self.providers
    }

    /// Resolve a capability to the best healthy provider for this request.
    /// `options` participates in selection: a provider that cannot honor
    /// a requested semantic option is skipped (capability-specific
    /// suitability), so `network.port_scan` + `intensity` prefers nmap
    /// while bare `network.port_scan` may fall back to naabu.
    pub fn select(
        &self,
        capability: &str,
        options: &OptionSet,
        env: &EnvironmentState,
    ) -> Result<Arc<dyn CapabilityProvider>, ProviderError> {
        let supporting: Vec<&Arc<dyn CapabilityProvider>> = self
            .providers
            .iter()
            .filter(|p| p.capabilities().iter().any(|c| c == capability))
            .collect();
        if supporting.is_empty() {
            return Err(ProviderError::NoProviderRegistered {
                capability: capability.to_string(),
            });
        }
        let available: Vec<&Arc<dyn CapabilityProvider>> = supporting
            .iter()
            .copied()
            .filter(|p| p.is_available(env))
            .collect();
        if available.is_empty() {
            return Err(ProviderError::NoProviderAvailable {
                capability: capability.to_string(),
                known_providers: supporting.iter().map(|p| p.id().to_string()).collect(),
            });
        }
        let usable: Vec<&Arc<dyn CapabilityProvider>> = available
            .iter()
            .copied()
            .filter(|p| {
                options
                    .iter()
                    .all(|(k, _)| p.supports_option(capability, k))
            })
            .collect();
        if usable.is_empty() {
            let option = options
                .keys()
                .find(|k| !available.iter().any(|p| p.supports_option(capability, k)))
                .cloned()
                .unwrap_or_default();
            return Err(ProviderError::OptionUnsupported {
                capability: capability.to_string(),
                option,
                available_providers: available.iter().map(|p| p.id().to_string()).collect(),
            });
        }
        // Priority descending; first max wins for determinism.
        let mut ranked = usable;
        ranked.sort_by_key(|p| std::cmp::Reverse(p.priority()));
        Ok(ranked[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ToolStatus;
    use crate::registry::{CapabilityRegistry, ToolRegistry};
    use std::collections::HashMap;

    use super::super::executor::RecordingExecutor;

    fn state_with(installed: &[&str]) -> EnvironmentState {
        let tools = ToolRegistry::builtin();
        let mut s = EnvironmentState::empty();
        s.tools = tools
            .all()
            .iter()
            .map(|t| {
                let up = installed.contains(&t.id.as_str());
                (
                    t.id.clone(),
                    ToolStatus {
                        tool_id: t.id.clone(),
                        installed: up,
                        executable_path: up.then(|| format!("/bin/{}", t.id)),
                        version: up.then(|| "1.0".into()),
                        platform: "linux".into(),
                        arch: "x64".into(),
                        healthy: up,
                        adapter_available: false,
                        capabilities: if up { t.capabilities.clone() } else { vec![] },
                        missing_dependencies: vec![],
                        diagnostic: String::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        s
    }

    fn registry() -> ProviderRegistry {
        ProviderRegistry::from_tools(&ToolRegistry::builtin())
    }

    #[test]
    fn fs_only_tools_reject_url_targets_without_spawning() {
        use super::super::executor::RecordingExecutor;
        let tools = ToolRegistry::builtin();
        let env = state_with(&["semgrep"]);
        let def = tools.get("semgrep").unwrap().clone();
        let provider = ProcessProvider::new(def);
        let request = CapabilityRequest::new(
            "source.secret_detection",
            "http://127.0.0.1:3000",
            "scan the served bundles",
        );
        let rec = RecordingExecutor::succeeding();
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        assert!(!result.success());
        assert!(result.is_non_retryable(), "error: {:?}", result.error);
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("local filesystem"),
            "error: {:?}",
            result.error
        );
        assert!(rec.calls.lock().unwrap().is_empty(), "no process may spawn");
    }

    #[test]
    fn fs_only_tools_allow_real_local_paths() {
        use super::super::executor::RecordingExecutor;
        let tools = ToolRegistry::builtin();
        let env = state_with(&["semgrep"]);
        let def = tools.get("semgrep").unwrap().clone();
        let provider = ProcessProvider::new(def);
        let request = CapabilityRequest::new(
            "source.secret_detection",
            "C:\\src\\project",
            "scan the repo",
        );
        let rec = RecordingExecutor::succeeding();
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        // No guard rejection: the run proceeds (and succeeds via the stub).
        assert!(result.success(), "error: {:?}", result.error);
        assert_eq!(rec.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn capability_constant_flags_are_appended() {
        // network.os_detection carries no model options, but nmap has a
        // constant binding: any os_detection request must include -O.
        let tools = ToolRegistry::builtin();
        let env = state_with(&["nmap"]);
        let def = tools.get("nmap").unwrap().clone();
        let provider = ProcessProvider::new(def);
        let request = CapabilityRequest::new("network.os_detection", "10.0.0.1", "fingerprint");
        let rec = RecordingExecutor::succeeding();
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        assert!(result.success(), "{:?}", result.error);
        let calls = rec.calls.lock().unwrap();
        assert!(
            calls[0].1.contains(&"-O".to_string()),
            "argv: {:?}",
            calls[0].1
        );
        // And it must NOT leak into other capabilities.
        let request = CapabilityRequest::new("network.port_scan", "10.0.0.1", "ports");
        let rec2 = RecordingExecutor::succeeding();
        let ctx2 = ExecutionContext {
            executor: &rec2,
            env: &env,
        };
        let result = provider.execute(&request, &ctx2);
        assert!(result.success());
        let calls2 = rec2.calls.lock().unwrap();
        assert!(
            !calls2[0].1.contains(&"-O".to_string()),
            "argv: {:?}",
            calls2[0].1
        );
    }

    #[test]
    fn resolves_capability_to_highest_priority_provider() {
        let env = state_with(&["nmap", "naabu"]);
        let pick = registry()
            .select("network.port_scan", &OptionSet::new(), &env)
            .unwrap();
        assert_eq!(pick.id(), "nmap"); // priority 100 beats naabu 70
    }

    #[test]
    fn falls_back_to_second_provider_when_primary_unavailable() {
        // nmap absent, naabu installed â†’ network.port_scan still available.
        let env = state_with(&["naabu"]);
        let pick = registry()
            .select("network.port_scan", &OptionSet::new(), &env)
            .unwrap();
        assert_eq!(pick.id(), "naabu");
    }

    #[test]
    fn no_healthy_provider_lists_known_providers() {
        let env = state_with(&[]);
        let err = registry()
            .select("network.port_scan", &OptionSet::new(), &env)
            .err()
            .unwrap();
        match err {
            ProviderError::NoProviderAvailable {
                known_providers, ..
            } => {
                assert!(known_providers.contains(&"nmap".to_string()));
                assert!(known_providers.contains(&"naabu".to_string()));
            }
            other => panic!("expected NoProviderAvailable, got {other:?}"),
        }
    }

    #[test]
    fn unregistered_capability_is_an_honest_gap() {
        let env = state_with(&["nmap"]);
        let err = registry()
            .select("made.up.capability", &OptionSet::new(), &env)
            .err()
            .unwrap();
        assert!(matches!(err, ProviderError::NoProviderRegistered { .. }));
    }

    #[test]
    fn option_support_participates_in_selection() {
        // `intensity` is bound on nmap but not naabu: with both installed
        // nmap wins; with only naabu the request is rejected as unsupported.
        let env = state_with(&["nmap", "naabu"]);
        let mut opts = OptionSet::new();
        opts.insert("intensity".into(), OptionValue::Str("normal".into()));
        let pick = registry().select("network.port_scan", &opts, &env).unwrap();
        assert_eq!(pick.id(), "nmap");

        let env_naabu_only = state_with(&["naabu"]);
        let err = registry()
            .select("network.port_scan", &opts, &env_naabu_only)
            .err()
            .unwrap();
        match err {
            ProviderError::OptionUnsupported {
                option,
                available_providers,
                ..
            } => {
                assert_eq!(option, "intensity");
                assert_eq!(available_providers, vec!["naabu".to_string()]);
            }
            other => panic!("expected OptionUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn selection_ignores_extra_model_fields_such_as_provider() {
        // There is no code path where a model-supplied "provider" field can
        // influence selection: select() only reads capability + validated
        // options. A request whose capability maps to nmap resolves to nmap
        // regardless of any other content the model produced.
        let env = state_with(&["nmap", "naabu"]);
        let pick = registry()
            .select("network.port_scan", &OptionSet::new(), &env)
            .unwrap();
        assert_eq!(pick.id(), "nmap");
    }

    #[test]
    fn provider_translate_builds_nmap_argv_from_semantic_options() {
        use crate::agent::executor::RecordingExecutor;

        let tools = ToolRegistry::builtin();
        let caps = CapabilityRegistry::builtin();
        let env = state_with(&["nmap"]);
        let def = tools.get("nmap").unwrap().clone();
        let provider = ProcessProvider::new(def);

        let mut opts = OptionSet::new();
        opts.insert("ports".into(), OptionValue::Str("80,443".into()));
        opts.insert("intensity".into(), OptionValue::Str("fast".into()));
        let request = CapabilityRequest {
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            options: opts,
            reason: "test".into(),
        };

        let rec = RecordingExecutor::succeeding();
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        assert!(result.success(), "{:?}", result.error);

        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (exe, argv) = &calls[0];
        assert!(exe.ends_with("nmap"));
        // Template args + bound options (BTreeMap iteration order:
        // alphabetical by option name — argv order is irrelevant to the
        // tool, and deterministic for tests):
        assert_eq!(
            argv,
            &vec![
                "-sV".to_string(),
                "-oX".to_string(),
                "-".to_string(),
                "10.0.0.1".to_string(),
                "-T4".to_string(), // "fast" mapped through the value table
                "-p".to_string(),
                "80,443".to_string(),
            ]
        );
        let _ = caps;
    }

    #[test]
    fn provider_translate_rejects_unbound_option_never_passthrough() {
        // Even if an option bypassed schema validation somehow, the
        // provider refuses to translate it â€” no passthrough to argv.
        let tools = ToolRegistry::builtin();
        let env = state_with(&["nmap"]);
        let def = tools.get("nmap").unwrap().clone();
        let provider = ProcessProvider::new(def);

        let mut opts = OptionSet::new();
        opts.insert("flags".into(), OptionValue::Str("--privileged".to_string()));
        let request = CapabilityRequest {
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            options: opts,
            reason: "test".into(),
        };
        let rec = RecordingExecutor::succeeding();
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        assert!(!result.success());
        assert!(
            result.error.unwrap().contains("does not support option"),
            "must refuse unbound option"
        );
        assert!(rec.calls.lock().unwrap().is_empty(), "nothing may run");
    }

    #[test]
    fn provider_execute_fails_closed_when_not_installed() {
        let tools = ToolRegistry::builtin();
        let env = state_with(&[]); // nothing installed
        let def = tools.get("nmap").unwrap().clone();
        let provider = ProcessProvider::new(def);
        let request = CapabilityRequest::new("network.port_scan", "10.0.0.1", "r");
        let rec = RecordingExecutor::succeeding();
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        assert!(!result.success());
        assert!(result.error.unwrap().contains("not installed"));
        assert!(rec.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn raw_evidence_is_preserved_on_the_result() {
        // stdout/stderr/exit code survive untranslated on the result even
        // though parsers will later distill them into observations.
        let tools = ToolRegistry::builtin();
        let env = state_with(&["nmap"]);
        let def = tools.get("nmap").unwrap().clone();
        let provider = ProcessProvider::new(def);
        let request = CapabilityRequest::new("network.port_scan", "10.0.0.1", "r");
        let rec = RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: crate::agent::executor::ProcessOutput {
                exit_code: 0,
                stdout: "<nmaprun>raw xml</nmaprun>".into(),
                stderr: "warning: something".into(),
                timed_out: false,
                error: None,
            },
        };
        let ctx = ExecutionContext {
            executor: &rec,
            env: &env,
        };
        let result = provider.execute(&request, &ctx);
        assert_eq!(result.stdout, "<nmaprun>raw xml</nmaprun>");
        assert_eq!(result.stderr, "warning: something");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.tool_id, "nmap");
        assert_eq!(result.capability, "network.port_scan");
    }
}
