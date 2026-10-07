//! Direct LLM web-search tool (`web_search` decision). This is NOT a
//! capability: it bypasses the capability/policy/provider machinery the
//! same way `reply`, `narrate`, and `hypothesis` do — the model calls it
//! directly with a free-text query, and the runtime executes it here.
//!
//! Engine: DuckDuckGo's HTML endpoint (`html.duckduckgo.com/html/?q=`).
//! No API key, no signup, no rate-limit account. Results are distilled
//! from the server-rendered HTML (title + real URL + snippet); the
//! redirect-wrapped `uddg` links are unwrapped and percent-decoded.

use std::time::Duration;

/// One distilled search result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// Query the web and return up to 10 results. Engine cascade, first
/// winner serves:
/// 1. **SearXNG** (self-hosted aggregator, default `http://localhost:8888`,
///    override with `MEDUSA_SEARXNG_URL`) — unlimited, rotates dozens of
///    upstream engines, no keys.
/// 2. **DuckDuckGo** plain HTTP (`html.duckduckgo.com`) — zero-config,
///    but rate-limits aggressive clients with a bot challenge.
/// 3. **Browser fallback** (headless Chromium via Playwright) — for when
///    plain HTTP is challenged.
pub fn search(query: &str, timeout: Duration) -> Result<Vec<WebResult>, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err("empty search query".into());
    }
    if query.chars().count() > 400 {
        return Err("search query too long (max 400 chars)".into());
    }
    let mut errors: Vec<String> = Vec::new();
    // 1. SearXNG — retry once: upstream engines can transiently time out
    //    together (observed with the default 3s engine timeout), and a
    //    cold query often succeeds on the second attempt.
    match search_searxng(query, timeout) {
        Ok(results) if !results.is_empty() => return Ok(results),
        first => {
            std::thread::sleep(Duration::from_millis(1500));
            match search_searxng(query, timeout) {
                Ok(results) if !results.is_empty() => return Ok(results),
                _ => {
                    let msg = match first {
                        Ok(_) => "searxng returned no results (after retry)".to_string(),
                        Err(e) => format!("searxng: {e} (after retry)"),
                    };
                    errors.push(msg);
                }
            }
        }
    }
    // 2. DuckDuckGo plain HTTP
    match search_ddg_http(query, timeout) {
        Ok(results) if !results.is_empty() => return Ok(results),
        Ok(_) => errors.push("duckduckgo returned no results".into()),
        Err(e) => errors.push(format!("duckduckgo: {e}")),
    }
    // 3. Browser fallback
    match search_browser(query) {
        Ok(results) if !results.is_empty() => return Ok(results),
        Ok(_) => errors.push("browser search returned no results".into()),
        Err(e) => errors.push(format!("browser fallback: {e}")),
    }
    Err(errors.join("; "))
}

/// SearXNG instance base URL: env override, else the local default.
fn searxng_base() -> String {
    std::env::var("MEDUSA_SEARXNG_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "http://localhost:8888".to_string())
        .trim_end_matches('/')
        .to_string()
}

/// SearXNG path: `/search?q=...&format=json`.
fn search_searxng(query: &str, timeout: Duration) -> Result<Vec<WebResult>, String> {
    let url = format!(
        "{}/search?q={}&format=json",
        searxng_base(),
        encode_query(query)
    );
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(true)
        .timeout(timeout)
        .build();
    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| format!("request failed: {e}"))?;
    let body: String = resp
        .into_string()
        .map_err(|e| format!("read failed: {e}"))?;
    parse_searxng_json(&body)
}

/// SearXNG JSON: `{"results": [{"url", "title", "content", ...}]}`.
fn parse_searxng_json(body: &str) -> Result<Vec<WebResult>, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("bad json: {e}"))?;
    let mut out = Vec::new();
    if let Some(arr) = v.get("results").and_then(|r| r.as_array()) {
        for r in arr {
            let title = r.get("title").and_then(|x| x.as_str()).unwrap_or("");
            let url = r.get("url").and_then(|x| x.as_str()).unwrap_or("");
            let snippet = r
                .get("content")
                .or_else(|| r.get("snippet"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if !url.is_empty() && !title.is_empty() {
                out.push(WebResult {
                    title: title.to_string(),
                    url: url.to_string(),
                    snippet: snippet.to_string(),
                });
            }
            if out.len() >= 10 {
                break;
            }
        }
    }
    Ok(out)
}

/// DuckDuckGo plain-HTTP path.
fn search_ddg_http(query: &str, timeout: Duration) -> Result<Vec<WebResult>, String> {
    let url = format!(
        "https://html.duckduckgo.com/html/?q={}",
        encode_query(query)
    );
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(true)
        .timeout(timeout)
        .build();
    let resp = agent
        .get(&url)
        .set(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        )
        .set("Accept", "text/html")
        .set("Accept-Language", "en-US,en;q=0.9")
        .call()
        .map_err(|e| format!("duckduckgo request failed: {e}"))?;
    let status = resp.status();
    let mut body = String::new();
    // Cap the read: the html page is ~30-100KB; anything huge is abnormal.
    if let Ok(s) = resp.into_string() {
        body = s.chars().take(500_000).collect();
    }
    let results = parse_ddg_html(&body, 10);
    if results.is_empty()
        && (status == 202 || (!body.contains("result__a") && !body.contains("result-link")))
    {
        // Distinguish "no hits" from "engine blocked/changed markup".
        return Err(format!(
            "duckduckgo served status {status} with no parseable results ({} bytes) — likely the bot challenge",
            body.len()
        ));
    }
    Ok(results)
}

/// Browser fallback: run the embedded web-search.mjs sidecar under node.
/// The sidecar prints one JSON object with the results.
fn search_browser(query: &str) -> Result<Vec<WebResult>, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err("empty query".into());
    }
    let Some(script) = crate::infra::scripts::ensure_script("web-search.mjs") else {
        return Err("web-search.mjs sidecar unavailable".into());
    };
    let Some(node) = crate::core::resolver::resolve_executable(
        &["node".to_string()],
        &[],
    ) else {
        return Err("node not found on PATH (needed for the browser fallback)".into());
    };
    let args = vec![
        script.to_string_lossy().into_owned(),
        "--query".to_string(),
        query.to_string(),
    ];
    let out = super::executor::spawn_with_timeout(
        &node.to_string_lossy(),
        &args,
        Duration::from_secs(60),
    );
    if out.timed_out {
        return Err("browser search timed out after 60s".into());
    }
    if let Some(e) = out.error {
        return Err(format!("failed to run browser search: {e}"));
    }
    if out.exit_code != 0 {
        let msg = if !out.stderr.trim().is_empty() {
            out.stderr
        } else {
            out.stdout
        };
        let trimmed: String = msg.chars().take(200).collect();
        return Err(format!("browser search exited {}: {trimmed}", out.exit_code));
    }
    // One JSON object on stdout.
    let stdout = out.stdout.trim();
    let start = stdout.find('{').ok_or("browser search printed no JSON")?;
    let end = stdout.rfind('}').ok_or("browser search printed no JSON")?;
    let v: serde_json::Value = serde_json::from_str(&stdout[start..=end])
        .map_err(|e| format!("browser search JSON parse: {e}"))?;
    let mut results = Vec::new();
    if let Some(arr) = v.get("results").and_then(|r| r.as_array()) {
        for r in arr {
            let title = r.get("title").and_then(|x| x.as_str()).unwrap_or("");
            let url = r.get("url").and_then(|x| x.as_str()).unwrap_or("");
            let snippet = r.get("snippet").and_then(|x| x.as_str()).unwrap_or("");
            if !url.is_empty() && !title.is_empty() {
                results.push(WebResult {
                    title: title.to_string(),
                    url: url.to_string(),
                    snippet: snippet.to_string(),
                });
            }
        }
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// HTML distillation — hand-rolled against the known endpoint markup:
//   <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=ENCODED&amp;rut=...">Title</a>
//   <a class="result__snippet" ...>snippet …</a>   (or td.result-snippet on Lite)
// ---------------------------------------------------------------------------

/// Extract result links + snippets from a DuckDuckGo HTML page.
pub fn parse_ddg_html(html: &str, max: usize) -> Vec<WebResult> {
    let links = extract_anchors_by_class(html, "result__a");
    let snippets = extract_text_by_class(html, &["result__snippet", "result-snippet"]);
    links
        .into_iter()
        .enumerate()
        .take(max)
        .map(|(i, (href, title))| WebResult {
            title: clean_text(&title),
            url: unwrap_ddg_redirect(&href),
            snippet: snippets
                .get(i)
                .map(|s| clean_text(s))
                .unwrap_or_default(),
        })
        .filter(|r| !r.url.is_empty() && !r.title.is_empty())
        .collect()
}

/// All `<a ... class="<class>" ... href="...">text</a>` anchors, in order.
fn extract_anchors_by_class(html: &str, class: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(pos) = rest.find(class) {
        // The class attribute sits inside an opening <a ...> tag; find its
        // start, then the tag's end.
        let Some(tag_start) = rest[..pos].rfind('<') else {
            rest = &rest[pos + class.len()..];
            continue;
        };
        let Some(tag_end) = rest[pos..].find('>') else {
            break;
        };
        let tag_end = pos + tag_end;
        let tag = &rest[tag_start..tag_end];
        // Only accept anchors actually tagged with this class.
        let is_anchor = tag.starts_with("<a");
        let has_class = tag.contains(&format!("class=\"{class}\""))
            || tag.contains(&format!("class='{class}'"));
        if is_anchor && has_class {
            let href = attr_value(tag, "href").unwrap_or_default();
            let after = &rest[tag_end + 1..];
            let text = strip_tags(&after[..find_close(after)]);
            if !href.is_empty() {
                out.push((href, text));
            }
        }
        rest = &rest[tag_end + 1..];
    }
    out
}

/// Text content of elements carrying any of `classes` (snippet blocks):
/// takes the text between the opening tag and its closing tag, stripping
/// nested markup.
fn extract_text_by_class(html: &str, classes: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(pos) = rest.find("class=\"") {
        let open_q = pos + 6; // the '"' right after `class=`
        let Some(rel) = rest[open_q + 1..].find('"') else {
            break;
        };
        let attr_end = open_q + 1 + rel; // the closing quote
        let class_name = &rest[open_q + 1..attr_end];
        let advance = attr_end + 1;
        if classes.contains(&class_name) {
            if let Some(tag_start) = rest[..pos].rfind('<') {
                if rest[tag_start..].starts_with('<') {
                    if let Some(gt) = rest[attr_end..].find('>') {
                        let tag_close = attr_end + gt;
                        let after = &rest[tag_close + 1..];
                        out.push(strip_tags(&after[..find_close(after)]));
                    }
                }
            }
        }
        rest = &rest[advance..];
    }
    out
}

/// Position of the first `</a>` or `</td>` close after `from` (whichever
/// comes first), bounded so a malformed page cannot slice the whole file.
fn find_close(from: &str) -> usize {
    let a = from.find("</a>").unwrap_or(usize::MAX);
    let td = from.find("</td>").unwrap_or(usize::MAX);
    let div = from.find("</div>").unwrap_or(usize::MAX);
    a.min(td).min(div).min(from.len())
}

fn attr_value(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

/// Strip nested tags and collapse whitespace.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

fn clean_text(s: &str) -> String {
    let unescaped = unescape_entities(s);
    let collapsed: String = unescaped
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed.trim().to_string()
}

/// `//duckduckgo.com/l/?uddg=<percent-encoded>&amp;rut=...` → real URL.
fn unwrap_ddg_redirect(href: &str) -> String {
    let h = unescape_entities(href);
    let Some(pos) = h.find("uddg=") else {
        // Direct links pass through unchanged.
        return if h.starts_with("//") {
            format!("https:{}", h)
        } else {
            h
        };
    };
    let rest = &h[pos + "uddg=".len()..];
    let encoded = rest.split('&').next().unwrap_or(rest);
    percent_decode(encoded)
}

// ---------------------------------------------------------------------------
// Encoding helpers (no external crate)
// ---------------------------------------------------------------------------

/// Form-encode a query string (spaces → `+`).
fn encode_query(q: &str) -> String {
    let mut out = String::with_capacity(q.len() * 2);
    for b in q.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode `%XX` sequences; `+` is preserved (URLs legitimately contain it).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The handful of entities DuckDuckGo emits in titles/snippets.
fn unescape_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&#x2F;", "/")
        .replace("&nbsp;", " ")
        .replace("&hellip;", "…")
        .replace("&ndash;", "–")
        .replace("&mdash;", "—")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Structure captured from a live html.duckduckgo.com response.
    const FIXTURE: &str = r#"
<div class="links_main links_deep result__body">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.rs%2Fpercent%2Dencoding%2Flatest%2Fpercent_encoding%2F&amp;rut=36f04744">percent_encoding - Rust - Docs.rs</a>
  </h2>
  <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.rs%2Fpercent%2Dencoding%2Flatest%2Fpercent_encoding%2F&amp;rut=36f04744">Percent-encoding &amp; URL encoding for Rust strings</a>
</div>
<div class="links_main links_deep result__body">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fen%2Ewikipedia%2Eorg%2Fwiki%2FPercent%2Dencoding&amp;rut=abc123">Percent-encoding - Wikipedia</a>
  </h2>
  <a class="result__snippet" href="//r">URLs can only contain ASCII; encoding &lt;safe&gt; chars</a>
</div>
<div class="links_main links_deep result__body">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="https://example.com/direct">Direct link &mdash; no redirect</a>
  </h2>
</div>
"#;

    #[test]
    fn parses_titles_urls_and_snippets() {
        let results = parse_ddg_html(FIXTURE, 10);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].title, "percent_encoding - Rust - Docs.rs");
        assert_eq!(
            results[0].url,
            "https://docs.rs/percent-encoding/latest/percent_encoding/"
        );
        assert_eq!(results[0].snippet, "Percent-encoding & URL encoding for Rust strings");
        assert_eq!(results[1].url, "https://en.wikipedia.org/wiki/Percent-encoding");
        assert_eq!(results[1].snippet, "URLs can only contain ASCII; encoding <safe> chars");
        // Direct (non-redirect) links pass through.
        assert_eq!(results[2].url, "https://example.com/direct");
        assert_eq!(results[2].title, "Direct link — no redirect");
    }

    #[test]
    fn max_results_is_respected() {
        assert_eq!(parse_ddg_html(FIXTURE, 1).len(), 1);
    }

    #[test]
    fn garbage_yields_nothing() {
        assert!(parse_ddg_html("", 10).is_empty());
        assert!(parse_ddg_html("<html><body>nothing here</body></html>", 10).is_empty());
    }

    #[test]
    fn query_encoding_round_trips() {
        assert_eq!(encode_query("a b&c=d"), "a+b%26c%3Dd");
        assert_eq!(encode_query("100%"), "100%25");
        // uddg decode: '+' is preserved, %XX decoded.
        assert_eq!(percent_decode("a+b%26c%3Dd"), "a+b&c=d");
    }

    #[test]
    fn percent_decode_handles_urls() {
        assert_eq!(
            percent_decode("https%3A%2F%2Fdocs.rs%2Fpercent%2Dencoding"),
            "https://docs.rs/percent-encoding"
        );
        // Invalid hex passes through untouched.
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn empty_query_is_rejected_without_network() {
        assert!(search("", Duration::from_secs(5)).is_err());
        assert!(search("   ", Duration::from_secs(5)).is_err());
    }

    #[test]
    fn searxng_json_parses_results_and_caps_them() {
        let body = r#"{"query":"x","results":[
            {"url":"https://a.example/1","title":"A one","content":"snip a","engine":"google"},
            {"url":"https://b.example/2","title":"B two","engine":"bing"},
            {"url":"","title":"no url dropped"},
            {"url":"https://c.example/3","title":"","content":"no title dropped"}
        ]}"#;
        let rs = parse_searxng_json(body).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].url, "https://a.example/1");
        assert_eq!(rs[0].snippet, "snip a");
        assert_eq!(rs[1].snippet, "");
        let many: Vec<(String, String)> = (0..30)
            .map(|i| (format!("https://x.example/{i}"), format!("T{i}")))
            .collect();
        let big = serde_json::json!({ "results": many.iter().map(|(u, t)| serde_json::json!({"url": u, "title": t})).collect::<Vec<_>>() });
        assert_eq!(parse_searxng_json(&big.to_string()).unwrap().len(), 10);
    }

    #[test]
    fn searxng_bad_json_is_an_error() {
        assert!(parse_searxng_json("not json").is_err());
        assert!(parse_searxng_json("{}").unwrap().is_empty());
    }

    /// Live (ignored): real DuckDuckGo query.
    /// `cargo test live_web_search -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_web_search() {
        let results = search("owasp juice shop documentation", Duration::from_secs(20)).unwrap();
        assert!(!results.is_empty());
        for r in results.iter().take(3) {
            println!("{} — {} | {}", r.title, r.url, r.snippet);
        }
        assert!(results.iter().all(|r| r.url.starts_with("http")));
    }
}
