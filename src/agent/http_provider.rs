//! Internal HTTP request provider (`medusa-http`): the built-in
//! implementation behind the `http.request`, `api.auth_testing` and
//! `api.bola_testing` capabilities. There is no external executable —
//! the provider performs the request itself via ureq (already the
//! model-transport HTTP client) and synthesizes JSON evidence that the
//! parsers turn into observations.
//!
//! This closes the action-space gap for business-logic verification:
//! the model could always *decide* to test a login bypass or an IDOR
//! primitive, but previously had no capability that could issue a
//! crafted raw request — only whole-tool invocations with fixed argv.

use std::time::Duration;

use super::executor::ToolResult;
use super::model::OptionValue;
use super::provider::{CapabilityProvider, CapabilityRequest, ExecutionContext};

pub const HTTP_CAPABILITIES: [&str; 3] = ["http.request", "api.auth_testing", "api.bola_testing"];

/// Body snippets are capped so a huge response cannot blow up the
/// context budget; full evidence stays in the raw result.
/// Raw response body retained in the tool's evidence JSON. http.request
/// is a payload-verification tool: the model reads the rendered body to
/// confirm/reject a finding (SSTI, SQLi, IDOR), so this must be generous —
/// not a tiny head snippet that hides the proof mid-page.
const BODY_SNIPPET_CHARS: usize = 8_000;

pub struct HttpRequestProvider {
    timeout: Duration,
}

impl Default for HttpRequestProvider {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }
}

impl HttpRequestProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// "host:port/path" → "http://host:port/path"; already-schemed targets
    /// pass through. Also repairs mangled backslashes (the model has been
    /// seen emitting `http:\127.0.0.1:3000`), so a borderline target still
    /// reaches the server instead of failing an encoding check.
    fn normalize_url(target: &str) -> String {
        let mut t = target.trim().to_string();
        if t.is_empty() {
            return t;
        }
        // Collapse mangled schemes: `http:\host` and `http:\\host`.
        // Handle the double-backslash before the single so `\\` doesn't
        // turn into `/\`.
        t = t
            .replace("http:\\\\", "http://")
            .replace("https:\\\\", "https://")
            .replace("http:\\", "http://")
            .replace("https:\\", "https://");
        if t.starts_with("http://") || t.starts_with("https://") {
            t
        } else {
            format!("http://{t}")
        }
    }
}

fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .filter_map(|h| {
            let (name, value) = h.split_once(':')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.trim().to_string()))
        })
        .collect()
}

impl CapabilityProvider for HttpRequestProvider {
    fn id(&self) -> &str {
        "medusa-http"
    }

    fn capabilities(&self) -> &[String] {
        // Static slice stored as String allocations once per call site is
        // wasteful; a thread-local keeps the trait signature (borrowed
        // slice) without per-call allocation.
        static CAPS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| HTTP_CAPABILITIES.iter().map(|s| s.to_string()).collect())
    }

    fn priority(&self) -> u8 {
        40 // real scanners win for their own jobs; this is the fallback
    }

    fn supports_option(&self, _capability: &str, option: &str) -> bool {
        matches!(option, "method" | "headers" | "body" | "follow_redirects")
    }

    fn is_available(&self, _env: &crate::model::EnvironmentState) -> bool {
        true // built into medusa
    }

    fn execute(&self, request: &CapabilityRequest, _ctx: &ExecutionContext) -> ToolResult {
        let url = Self::normalize_url(&request.target);
        let mut method = "GET".to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body: Option<String> = None;
        let mut follow = true;
        for (name, value) in &request.options {
            match (name.as_str(), value) {
                ("method", OptionValue::Str(m)) => method = m.to_uppercase(),
                ("headers", OptionValue::Str(h)) => headers = parse_headers(h),
                ("body", OptionValue::Str(b)) => body = Some(b.clone()),
                ("follow_redirects", OptionValue::Bool(b)) => follow = *b,
                _ => {}
            }
        }
        // A body without an explicit method means POST.
        if body.is_some() && !request.options.contains_key("method") {
            method = "POST".to_string();
        }

        // ureq 2.x: redirect policy lives on the Agent, so pick the agent
        // matching the requested redirect behavior.
        let agent = if follow {
            ureq::AgentBuilder::new().timeout(self.timeout).build()
        } else {
            ureq::AgentBuilder::new()
                .timeout(self.timeout)
                .redirects(0)
                .build()
        };
        let mut req = agent.request(&method, &url);
        for (name, value) in &headers {
            req = req.set(name, value);
        }
        let response = match body {
            Some(b) => req.send_string(&b),
            None => req.call(),
        };

        match response {
            Ok(resp) => {
                let status = resp.status();
                let content_type = resp.content_type().to_string();
                let body_text = resp
                    .into_string()
                    .unwrap_or_default()
                    .chars()
                    .take(BODY_SNIPPET_CHARS)
                    .collect::<String>();
                let snippet: String = body_text.chars().take(800).collect();
                let evidence = serde_json::json!({
                    "url": url,
                    "method": method,
                    "status": status,
                    "content_type": content_type,
                    "body_length": body_text.len(),
                    "body_snippet": snippet,
                });
                ToolResult {
                    tool_id: "medusa-http".into(),
                    capability: request.capability.clone(),
                    target: request.target.clone(),
                    exit_code: 0,
                    stdout: serde_json::to_string(&evidence).unwrap_or_default(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                }
            }
            Err(ureq::Error::Status(code, resp)) => {
                // Non-2xx/3xx is a valid security observation, not a failure.
                let content_type = resp.content_type().to_string();
                let body_text = resp.into_string().unwrap_or_default();
                let snippet: String = body_text.chars().take(800).collect();
                let evidence = serde_json::json!({
                    "url": url,
                    "method": method,
                    "status": code,
                    "content_type": content_type,
                    "body_length": body_text.len(),
                    "body_snippet": snippet,
                });
                ToolResult {
                    tool_id: "medusa-http".into(),
                    capability: request.capability.clone(),
                    target: request.target.clone(),
                    exit_code: 0,
                    stdout: serde_json::to_string(&evidence).unwrap_or_default(),
                    stderr: String::new(),
                    timed_out: false,
                    error: None,
                }
            }
            Err(e) => {
                // Deterministic input errors (bad URL, bad header) must
                // not burn the automatic retries — identical input fails
                // identically. Mark them non-retryable so the loop
                // reports the failure to the model immediately.
                let deterministic = matches!(
                    &e,
                    ureq::Error::Transport(t)
                        if matches!(
                            t.kind(),
                            ureq::ErrorKind::InvalidUrl
                                | ureq::ErrorKind::UnknownScheme
                                | ureq::ErrorKind::BadHeader
                        )
                );
                let msg = format!("request to {url} failed: {e}");
                if deterministic {
                    ToolResult::error_non_retryable(
                        "medusa-http",
                        &request.capability,
                        &request.target,
                        msg,
                    )
                } else {
                    ToolResult::error(
                        "medusa-http",
                        &request.capability,
                        &request.target,
                        msg,
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::executor::StubExecutor;
    use crate::agent::model::OptionSet;
    use crate::agent::provider::ExecutionContext;

    fn run(target: &str, opts: OptionSet) -> ToolResult {
        let p = HttpRequestProvider::new().with_timeout(Duration::from_secs(10));
        let request = CapabilityRequest {
            capability: "api.auth_testing".into(),
            target: target.into(),
            options: opts,
            reason: "live test".into(),
        };
        let stub = StubExecutor::new();
        let env = crate::model::EnvironmentState::empty();
        let ctx = ExecutionContext {
            executor: &stub,
            env: &env,
        };
        p.execute(&request, &ctx)
    }

    #[test]
    fn malformed_url_is_non_retryable() {
        // A deterministic input error (bad URL) must be marked
        // non-retryable so the loop reports it immediately instead of
        // burning three identical retries — which is what disabled
        // api.auth_testing for the session.
        let r = run(":::bad url:::", OptionSet::new());
        assert!(!r.success());
        assert!(r.is_non_retryable(), "error should be non-retryable: {r:?}");
    }

    #[test]
    #[ignore = "live: needs a local HTTP server on 127.0.0.1:3000"]
    fn live_post_and_get_against_juice_shop() {
        let r = run(
            "http://127.0.0.1:3000/rest/admin/application-version",
            OptionSet::new(),
        );
        assert!(
            r.success(),
            "GET failed: error={:?} stdout={}",
            r.error,
            &r.stdout.chars().take(300).collect::<String>()
        );
        println!(
            "GET stdout: {}",
            &r.stdout.chars().take(300).collect::<String>()
        );

        // GET the ROOT (the exact shape the failing assessment used).
        let r = run("http://127.0.0.1:3000", OptionSet::new());
        assert!(
            r.success(),
            "GET root failed: error={:?} stdout={}",
            r.error,
            &r.stdout.chars().take(300).collect::<String>()
        );
        println!(
            "GET root: {}",
            &r.stdout.chars().take(200).collect::<String>()
        );

        // POST + JSON headers + body shape (auth testing)
        let mut opts = OptionSet::new();
        opts.insert(
            "headers".into(),
            OptionValue::Str("Content-Type: application/json".into()),
        );
        opts.insert(
            "body".into(),
            OptionValue::Str(r#"{"email":"x@y.z","password":"x"}"#.into()),
        );
        let r = run("http://127.0.0.1:3000/rest/user/login", opts);
        assert!(
            r.success(),
            "POST failed: error={:?} stdout={}",
            r.error,
            &r.stdout.chars().take(300).collect::<String>()
        );
        // 401 for bad creds is a valid observation, not a failure.
        assert!(
            r.stdout.contains("\"status\":401"),
            "stdout: {}",
            &r.stdout.chars().take(300).collect::<String>()
        );
        println!(
            "POST stdout: {}",
            &r.stdout.chars().take(300).collect::<String>()
        );

        // POST to the ROOT with the same options (auth-testing shape aimed
        // at the base URL, as the model did in the failing run).
        let mut opts = OptionSet::new();
        opts.insert("method".into(), OptionValue::Str("POST".into()));
        opts.insert(
            "headers".into(),
            OptionValue::Str("Content-Type: application/json".into()),
        );
        opts.insert(
            "body".into(),
            OptionValue::Str(r#"{"email":"x@y.z","password":"x"}"#.into()),
        );
        let r = run("http://127.0.0.1:3000", opts);
        println!(
            "POST root: success={} error={:?} stdout={}",
            r.success(),
            r.error,
            &r.stdout.chars().take(200).collect::<String>()
        );

        // follow_redirects=false shape.
        let mut opts = OptionSet::new();
        opts.insert("follow_redirects".into(), OptionValue::Bool(false));
        let r = run("http://127.0.0.1:3000", opts);
        println!(
            "no-redirect GET root: success={} error={:?}",
            r.success(),
            r.error
        );
    }

    #[test]
    #[ignore = "live: error-shape probes against a live server"]
    fn live_error_shapes_are_reported_not_panicked() {
        // No-scheme host:port target.
        let r = run("127.0.0.1:3000/rest/products/search", OptionSet::new());
        assert!(r.success(), "no-scheme failed: {:?}", r.error);
        // Bad header line must not break the request.
        let mut opts = OptionSet::new();
        opts.insert("headers".into(), OptionValue::Str("garbage".into()));
        let r = run("http://127.0.0.1:3000/", opts);
        assert!(r.success(), "bad-header failed: {:?}", r.error);
        // Method with trailing space — must not corrupt the request.
        let mut opts = OptionSet::new();
        opts.insert("method".into(), OptionValue::Str("get ".into()));
        let r = run("http://127.0.0.1:3000/", opts);
        println!("spacey method: success={} error={:?}", r.success(), r.error);
    }

    #[test]
    fn option_set_contains_works_for_btree_maps() {
        let mut opts = OptionSet::new();
        opts.insert("method".into(), OptionValue::Str("POST".into()));
        assert!(opts.contains_key("method"));
        assert!(!opts.contains_key("body"));
    }

    #[test]
    fn url_normalization_adds_scheme() {
        assert_eq!(
            HttpRequestProvider::normalize_url("127.0.0.1:3000/rest/user/login"),
            "http://127.0.0.1:3000/rest/user/login"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url("https://example.com/x"),
            "https://example.com/x"
        );
    }

    #[test]
    fn url_normalization_repairs_mangled_backslashes() {
        assert_eq!(
            HttpRequestProvider::normalize_url(r"http:\127.0.0.1:3000"),
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url(r"http:\\127.0.0.1:3000"),
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url(r"https:\example.com"),
            "https://example.com"
        );
        assert_eq!(
            HttpRequestProvider::normalize_url(r"http:\127.0.0.1:3000/rest/user/login"),
            "http://127.0.0.1:3000/rest/user/login"
        );
    }

    #[test]
    fn header_parsing_splits_pairs() {
        let hs = parse_headers("Content-Type: application/json; X-Test: 1");
        assert_eq!(hs.len(), 2);
        assert_eq!(hs[0], ("Content-Type".into(), "application/json".into()));
        assert!(parse_headers("garbage").is_empty());
        assert!(parse_headers("").is_empty());
    }

    #[test]
    fn provider_identity_and_availability() {
        let p = HttpRequestProvider::new();
        assert_eq!(p.id(), "medusa-http");
        assert!(p
            .capabilities()
            .iter()
            .all(|c| HTTP_CAPABILITIES.contains(&c.as_str())));
        assert!(p.is_available(&crate::model::EnvironmentState::empty()));
        assert!(p.supports_option("http.request", "method"));
        assert!(!p.supports_option("http.request", "bogus"));
    }
}
