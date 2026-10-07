//! Internal web-research provider (`medusa-research`): lets the model
//! fetch and read web content — documentation, code, web scraping —
//! to validate findings, research CVEs, and understand targets.
//!
//! Design:
//! * **Read-only**: this capability only fetches and extracts text. It
//!   can never launch an attack tool at a researched target. The executor
//!   it drives is scoped to fetching; anything requiring exploitation is
//!   a separate, policy-gated capability.
//! * **URL-driven**: the model names a URL (a GitHub repo, a docs root,
//!   any page) that the provider fetches and extracts. Search is NOT
//!   part of this capability — the model searches via the direct
//!   `web_search` decision (see `agent::web_search`) and reads the hits
//!   here.
//! * **Open access by operator choice**: research may read any URL. This
//!   is intentional and explicit — research reads, it does not attack.
//!
//! Fetch+extract is built in via ureq (already the model-transport HTTP
//! client).

use std::time::Duration;

use super::executor::ToolResult;
use super::provider::{CapabilityProvider, CapabilityRequest, ExecutionContext};

pub const RESEARCH_CAPABILITIES: [&str; 1] = ["web.research"];

/// Cap on extracted text carried into evidence (chars). Research feeds the
/// model's `recent_evidence`, which already caps per-entry.
const EXTRACT_CHARS: usize = 12_000;
/// Cap on an individual fetched page body before extraction.
const FETCH_CAP_BYTES: usize = 2 * 1024 * 1024;
/// Default fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

pub struct ResearchProvider {
    timeout: Duration,
}

impl Default for ResearchProvider {
    fn default() -> Self {
        Self { timeout: FETCH_TIMEOUT }
    }
}

impl ResearchProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Extract readable text from HTML: drop scripts/styles/tags, collapse
/// whitespace, prefer headers and code blocks. Good enough for research
/// without pulling in a full HTML engine.
fn html_to_text(html: &str) -> String {
    // Guard against pathological inputs.
    let html: String = html.chars().take(FETCH_CAP_BYTES).collect();
    // Drop script/style blocks entirely.
    let without_scripts = strip_blocks(&html, &["script", "style", "noscript", "svg", "head"]);
    let mut out = String::with_capacity(without_scripts.len());
    // Inline text replacing tags with separators so words don't jam.
    let mut in_tag = false;
    let mut skip_tag = String::new();
    for ch in without_scripts.chars() {
        if in_tag {
            if ch == '>' {
                in_tag = false;
                // code/pre/br produce a newline so neighboring text separates.
                if matches!(
                    skip_tag.as_str(),
                    "p" | "div"
                        | "br"
                        | "li"
                        | "h1"
                        | "h2"
                        | "h3"
                        | "h4"
                        | "pre"
                        | "code"
                        | "tr"
                        | "section"
                        | "article"
                ) {
                    out.push('\n');
                }
                skip_tag = String::new();
            } else if !ch.is_whitespace() {
                skip_tag.push(ch);
            }
            continue;
        }
        if ch == '<' {
            in_tag = true;
            skip_tag = String::new();
            continue;
        }
        out.push(ch);
    }
    // Collapse runs of whitespace.
    let mut result = String::with_capacity(out.len());
    let mut ws = true;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !ws {
                result.push(' ');
            }
            ws = true;
        } else {
            result.push(ch);
            ws = false;
        }
    }
    result
        .chars()
        .take(EXTRACT_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Replace `script`/`style` blocks (with their inner text) with a space,
/// so their content doesn't leak into the readable extract.
fn strip_blocks(html: &str, tags: &[&str]) -> String {
    let mut out = String::with_capacity(html.len());
    let lower = html.to_lowercase();
    let mut i = 0usize;
    while i < html.len() {
        // Find next "<tag".
        let mut consumed = false;
        for tag in tags {
            let open = format!("<{tag}");
            let close = format!("</{tag}>");
            if lower[i..].starts_with(&open) {
                if let Some(c) = lower[i..].find(&close) {
                    i += c + close.len();
                    out.push(' ');
                    consumed = true;
                    break;
                }
            }
        }
        if consumed {
            continue;
        }
        // fall through copying chars
        let ch = html[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn fetch_text(url: &str, timeout: Duration) -> Result<ToolResult, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent("Medusa/0.1 (security-research; contact local-operator)")
        .build();
    let resp = agent.get(url).call().map_err(|e| format!("fetch failed: {e}"))?;
    let status = resp.status();
    let content_type = resp.content_type().to_string();
    let mut body = Vec::with_capacity(64 * 1024);
    use std::io::Read;
    let mut reader = resp.into_reader().take(FETCH_CAP_BYTES as u64);
    reader.read_to_end(&mut body).map_err(|e| format!("read failed: {e}"))?;
    let body_str = String::from_utf8_lossy(&body);
    let is_html = content_type.contains("html");
    let text = if is_html { html_to_text(&body_str) } else { body_str.trim().chars().take(EXTRACT_CHARS).collect::<String>() };
    let evidence = serde_json::json!({
        "url": url,
        "status": status,
        "content_type": content_type,
        "extracted_chars": text.len(),
        "text": text,
    });
    let tool_id = "medusa-research".to_string();
    let target = url.to_string();
    let cap = "web.research".to_string();
    let stdout = serde_json::to_string(&evidence).unwrap_or_default();
    Ok(ToolResult {
        tool_id,
        capability: cap,
        target,
        exit_code: 0,
        stdout,
        stderr: String::new(),
        timed_out: false,
        error: None,
    })
}

impl CapabilityProvider for ResearchProvider {
    fn id(&self) -> &str {
        "medusa-research"
    }

    fn capabilities(&self) -> &[String] {
        static CAPS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| RESEARCH_CAPABILITIES.iter().map(|s| s.to_string()).collect())
    }

    fn priority(&self) -> u8 {
        30
    }

    fn supports_option(&self, _capability: &str, option: &str) -> bool {
        matches!(option, "selector")
    }

    fn is_available(&self, _env: &crate::model::EnvironmentState) -> bool {
        true // built-in, no external executable
    }

    fn execute(&self, request: &CapabilityRequest, _ctx: &ExecutionContext) -> ToolResult {
        // The request target is the URL to read. `selector` is accepted
        // but not yet used (kept so the schema is forward-compatible) —
        // extraction is whole-page for now.
        let target = request.target.trim();

        if target.is_empty() {
            ToolResult::error_non_retryable(
                "medusa-research",
                &request.capability,
                "",
                "web.research requires a target URL".into(),
            )
        } else {
            match fetch_text(target, self.timeout) {
                Ok(res) => res,
                Err(e) => ToolResult::error_non_retryable(
                    "medusa-research",
                    &request.capability,
                    &request.target,
                    e,
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_extraction_drops_tags_and_scripts() {
        let html = "<html><head><title>t</title></head><body><script>alert(1)</script><h1>Heading</h1><p>Hello <b>world</b></p><pre>code();</pre></body></html>";
        let text = html_to_text(html);
        assert!(text.contains("Heading"));
        assert!(text.contains("Hello world"));
        assert!(text.contains("code();"));
        assert!(!text.contains("alert(1)"));
        assert!(!text.contains("<h1>"));
    }

    #[test]
    fn empty_target_is_non_retryable() {
        let p = ResearchProvider::new();
        let req = CapabilityRequest {
            capability: "web.research".into(),
            target: "".into(),
            options: super::super::model::OptionSet::new(),
            reason: "r".into(),
        };
        let stub = super::super::executor::StubExecutor::new();
        let env = crate::model::EnvironmentState::empty();
        let ctx = ExecutionContext { executor: &stub, env: &env };
        let r = p.execute(&req, &ctx);
        assert!(r.is_non_retryable());
    }
}