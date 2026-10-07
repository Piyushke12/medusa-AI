//! Execution policy: every `Execute` decision is validated BEFORE anything
//! runs — and before a provider is even selected. The LLM is never
//! authoritative about whether an action is allowed.
//!
//! Validation order (deliberate — scope must not be checkable only after
//! provider resolution):
//!
//! ```text
//! 1. capability exists          (CapabilityRegistry)
//! 2. arguments valid            (capability's OptionSpec schema)
//! 3. target within scope        (ScopePolicy — discovered assets are
//!                                NOT automatically in scope)
//! 4. risk gate                  (Destructive tests need explicit approval)
//! ```
//!
//! Only then does the runtime ask the [`crate::agent::ProviderRegistry`]
//! to select a provider. Provider selection cannot cause an out-of-scope
//! target to execute because scope was already enforced.

use std::sync::Arc;

use crate::model::CapabilityDefinition;
use crate::registry::CapabilityRegistry;

use super::model::{OptionSet, OptionValue};
use super::provider::CapabilityRequest;

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyError {
    UnknownCapability(String),
    /// Arguments failed the capability's semantic schema (unknown option,
    /// wrong type, out-of-range value, invalid enum member).
    InvalidArguments {
        capability: String,
        details: String,
    },
    /// The requested target is not part of the assessment scope.
    /// Distinct from provider errors: the capability may be perfectly
    /// available — the target is simply not allowed.
    OutOfScope {
        target: String,
        scope: String,
    },
    HighRiskRequiresApproval {
        capability: String,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCapability(c) => write!(f, "unknown capability `{c}`"),
            Self::InvalidArguments {
                capability,
                details,
            } => write!(f, "invalid arguments for `{capability}`: {details}"),
            Self::OutOfScope { target, scope } => write!(
                f,
                "target `{target}` is outside assessment scope (`{scope}`); discovered assets are not automatically in scope — note it as an observation or hypothesis instead"
            ),
              Self::HighRiskRequiresApproval { capability } => {
                  write!(f, "high-risk capability `{capability}` requires explicit approval (Destructive). Enable opt-in mode for authorized labs/CTFs.")
              }
        }
    }
}

/// Scope enforcement. User-mentioned targets define the scope; assets
/// *discovered during* the investigation (a shared-IP vhost, a linked
/// domain, a subdomain of someone else) do NOT automatically become
/// active-assessment targets.
///
/// Rules (host-based, scheme/port/path-insensitive):
/// * exact host match is in scope
/// * subdomains of a scoped host are in scope (`www.` of the scoped
///   host, and the apex when the user scoped `www.`)
/// * everything else is out of scope
///
/// Sessions may hold several granted roots (the user mentioned several
/// targets); `None` = unrestricted (headless/unit-test use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePolicy {
    scope: Option<Vec<String>>,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self::unrestricted()
    }
}

impl ScopePolicy {
    pub fn unrestricted() -> Self {
        Self { scope: None }
    }

    /// Nothing in scope — every execute is rejected until the user
    /// grants a target. Safest default for interactive sessions.
    pub fn empty() -> Self {
        Self {
            scope: Some(Vec::new()),
        }
    }

    pub fn new(session_target: &str) -> Self {
        Self {
            scope: Some(vec![host_of(session_target)]),
        }
    }

    /// Grant an additional root (idempotent). Only call sites that parse
    /// user input may invoke this — never the model. Returns true when
    /// the root was newly added.
    pub fn grant(&mut self, target: &str) -> bool {
        if let Some(roots) = self.scope.as_mut() {
            let host = host_of(target);
            if !host.is_empty() && !roots.contains(&host) {
                roots.push(host);
                return true;
            }
        }
        false
    }

    /// The granted roots (empty when unrestricted, which reports `*`).
    pub fn roots(&self) -> Vec<String> {
        match &self.scope {
            None => vec!["*".to_string()],
            Some(roots) => roots.clone(),
        }
    }

    /// Owned display form (multi-root aware).
    pub fn scope_target(&self) -> String {
        match &self.scope {
            None => "*".to_string(),
            Some(roots) => roots.join(", "),
        }
    }

    pub fn is_in_scope(&self, requested: &str) -> bool {
        match &self.scope {
            None => true,
            Some(roots) => {
                let req = host_of(requested);
                !req.is_empty() && roots.iter().any(|scope| host_matches(scope, &req))
            }
        }
    }
}

/// Extract the comparable host from a target string: strips scheme,
/// userinfo, port, path, query, fragment; lowercases; trims trailing dot.
pub fn host_of(target: &str) -> String {
    let t = target.trim();
    let t = t.split_once("://").map(|(_, rest)| rest).unwrap_or(t);
    let t = t.split(['/', '?', '#']).next().unwrap_or("");
    let t = t.rsplit('@').next().unwrap_or("");
    let h = if t.starts_with('[') {
        // IPv6 literal: [::1]:8080 → ::1
        t.split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
            .to_string()
    } else {
        t.split(':').next().unwrap_or("").to_string()
    };
    h.trim_end_matches('.').to_ascii_lowercase()
}

fn host_matches(scope_host: &str, req_host: &str) -> bool {
    // Loopback equivalence: localhost, 127.0.0.1 and ::1 are the same
    // machine, so a grant in one form covers the others. The model often
    // normalizes between them; that must not break execution.
    if is_loopback(scope_host) && is_loopback(req_host) {
        return true;
    }
    // Normalize: scoping www.example.com treats example.com as the root -
    // "www." is a naming convention, not a security boundary. The whole
    // registered domain's subdomains stay in scope; other domains do not.
    let root = scope_host.strip_prefix("www.").unwrap_or(scope_host);
    if req_host == root || req_host == scope_host {
        return true;
    }
    req_host.ends_with(&format!(".{root}"))
}

/// All names for the loopback interface.
fn is_loopback(h: &str) -> bool {
    h == "localhost" || h == "127.0.0.1" || h == "::1"
}

/// Pre-execution validation: registry facts, argument schema, scope, and
/// risk. Deliberately strict — a rejection is fed back to the model as
/// `last_error` so it can self-correct.
#[derive(Debug, Clone)]
pub struct ExecutionPolicy {
    /// Opt-in for authorized labs/CTFs to allow Destructive tests (e.g. RCE chain validation).
    /// Shared via Arc so TUI approval dialog can flip it while runtime is sleeping between retries.
    pub allow_destructive: Arc<std::sync::atomic::AtomicBool>,
    /// What this investigation may actively touch.
    pub scope: ScopePolicy,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            allow_destructive: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            scope: ScopePolicy::unrestricted(),
        }
    }
}

impl ExecutionPolicy {
    /// Derive the policy for one investigation: same risk gate, scope
    /// pinned to the investigation's declared target.
    pub fn for_target(&self, session_target: &str) -> Self {
        Self {
            allow_destructive: Arc::clone(&self.allow_destructive),
            scope: ScopePolicy::new(session_target),
        }
    }

    /// Grant an additional scope root (sessions parse user messages and
    /// call this; the model never can). Returns true when newly added.
    pub fn grant_scope(&mut self, target: &str) -> bool {
        self.scope.grant(target)
    }

    /// The granted scope roots.
    pub fn scope_roots(&self) -> Vec<String> {
        self.scope.roots()
    }

    /// Session policy: same risk gate, scope starting empty — every
    /// execute is rejected until a user-mentioned target is granted.
    pub fn for_session(&self) -> Self {
        Self {
            allow_destructive: Arc::clone(&self.allow_destructive),
            scope: ScopePolicy::empty(),
        }
    }

    /// Validate a capability request before provider selection.
    /// Checks (in order): capability exists, arguments match the
    /// capability's schema, target is in scope, risk gate passes.
    pub fn validate(
        &self,
        request: &CapabilityRequest,
        caps: &CapabilityRegistry,
    ) -> Result<(), PolicyError> {
        let Some(def) = caps.get(&request.capability) else {
            return Err(PolicyError::UnknownCapability(request.capability.clone()));
        };
        if let Err(details) = validate_options(def, &request.options) {
            return Err(PolicyError::InvalidArguments {
                capability: request.capability.clone(),
                details,
            });
        }
        if !self.scope.is_in_scope(&request.target) {
            return Err(PolicyError::OutOfScope {
                target: request.target.clone(),
                scope: self.scope.scope_target(),
            });
        }
        // Strong policy boundary for RCE/exploitation: Destructive
        // capabilities (exploit validation, OOB payload testing) must
        // not be reachable by LLM decision alone. The classification
        // lives on the capability itself; bypass via tool argument
        // spoofing is impossible because the LLM only requests
        // capability + semantic options, never binary or flags.
        if !self
            .allow_destructive
            .load(std::sync::atomic::Ordering::SeqCst)
            && def.risk == crate::model::RiskLevel::Destructive
        {
            return Err(PolicyError::HighRiskRequiresApproval {
                capability: request.capability.clone(),
            });
        }
        Ok(())
    }
}

/// Validate semantic options against the capability's schema. Unknown
/// options, wrong types, out-of-range numbers, and invalid enum members
/// are rejected — raw flags/commands can never pass through because they
/// are not declared options.
pub fn validate_options(def: &CapabilityDefinition, options: &OptionSet) -> Result<(), String> {
    for (name, value) in options {
        let Some(spec) = def.options.iter().find(|o| o.name == *name) else {
            let allowed: Vec<String> = def.options.iter().map(|o| o.name.clone()).collect();
            let allowed_str = if allowed.is_empty() {
                "this capability takes no options".to_string()
            } else {
                format!("allowed: {}", allowed.join(", "))
            };
            return Err(format!("unknown option `{name}` ({allowed_str})"));
        };
        let type_error = |expected: &str| {
            format!(
                "option `{name}` must be {expected}, got {}",
                value.kind_name()
            )
        };
        match &spec.kind {
            crate::model::OptionKind::Str => {
                if !matches!(value, OptionValue::Str(_)) {
                    return Err(type_error("a string"));
                }
            }
            crate::model::OptionKind::Bool => {
                if !matches!(value, OptionValue::Bool(_)) {
                    return Err(type_error("a boolean"));
                }
            }
            crate::model::OptionKind::Number { min, max } => {
                let OptionValue::Num(n) = value else {
                    return Err(type_error("a number"));
                };
                if let Some(min) = min {
                    if *n < *min {
                        return Err(format!("option `{name}` must be >= {min}, got {n}"));
                    }
                }
                if let Some(max) = max {
                    if *n > *max {
                        return Err(format!("option `{name}` must be <= {max}, got {n}"));
                    }
                }
            }
            crate::model::OptionKind::Enum { values } => {
                let OptionValue::Str(s) = value else {
                    return Err(type_error(&format!("one of: {}", values.join("|"))));
                };
                if !values.contains(s) {
                    return Err(format!(
                        "option `{name}` must be one of: {} (got \"{s}\")",
                        values.join("|")
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> CapabilityRegistry {
        CapabilityRegistry::builtin()
    }

    fn request(capability: &str, target: &str) -> CapabilityRequest {
        CapabilityRequest::new(capability, target, "test")
    }

    #[test]
    fn rejects_unknown_capability() {
        let err = ExecutionPolicy::default()
            .validate(&request("nope.nope", "10.0.0.1"), &caps())
            .unwrap_err();
        assert!(matches!(err, PolicyError::UnknownCapability(_)));
    }

    #[test]
    fn rejects_unknown_option() {
        let mut r = request("network.port_scan", "10.0.0.1");
        r.options
            .insert("flags".into(), OptionValue::Str("-O".into()));
        let err = ExecutionPolicy::default()
            .validate(&r, &caps())
            .unwrap_err();
        match err {
            PolicyError::InvalidArguments { details, .. } => {
                assert!(details.contains("unknown option `flags`"), "{details}");
            }
            other => panic!("expected InvalidArguments, got {other:?}"),
        }
    }

    #[test]
    fn rejects_command_smuggling_through_options() {
        // "command" / "flags" / "argv" are not declared options anywhere.
        for smuggle in ["command", "flags", "argv", "shell", "exec"] {
            let mut r = request("network.port_scan", "10.0.0.1");
            r.options
                .insert(smuggle.into(), OptionValue::Str("nmap -sS".into()));
            let err = ExecutionPolicy::default()
                .validate(&r, &caps())
                .unwrap_err();
            assert!(
                matches!(err, PolicyError::InvalidArguments { .. }),
                "{smuggle} must be rejected: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_wrong_option_type() {
        let mut r = request("http.crawl", "http://example.com");
        r.options
            .insert("depth".into(), OptionValue::Str("three".into()));
        let err = ExecutionPolicy::default()
            .validate(&r, &caps())
            .unwrap_err();
        assert!(matches!(err, PolicyError::InvalidArguments { .. }));
    }

    #[test]
    fn rejects_out_of_range_number() {
        let mut r = request("http.crawl", "http://example.com");
        r.options.insert("depth".into(), OptionValue::Num(99.0));
        let err = ExecutionPolicy::default()
            .validate(&r, &caps())
            .unwrap_err();
        match err {
            PolicyError::InvalidArguments { details, .. } => {
                assert!(details.contains("<= 10"), "{details}");
            }
            other => panic!("expected InvalidArguments, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_enum_member() {
        let mut r = request("network.port_scan", "10.0.0.1");
        r.options
            .insert("intensity".into(), OptionValue::Str("ludicrous".into()));
        let err = ExecutionPolicy::default()
            .validate(&r, &caps())
            .unwrap_err();
        match err {
            PolicyError::InvalidArguments { details, .. } => {
                assert!(details.contains("slow|normal|fast"), "{details}");
            }
            other => panic!("expected InvalidArguments, got {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_options() {
        let mut r = request("network.port_scan", "10.0.0.1");
        r.options
            .insert("ports".into(), OptionValue::Str("80,443".into()));
        r.options
            .insert("intensity".into(), OptionValue::Str("normal".into()));
        let mut r2 = request("http.crawl", "http://example.com");
        r2.options.insert("depth".into(), OptionValue::Num(3.0));
        assert!(ExecutionPolicy::default().validate(&r, &caps()).is_ok());
        assert!(ExecutionPolicy::default().validate(&r2, &caps()).is_ok());
    }

    #[test]
    fn scope_allows_exact_host_subdomains_and_paths() {
        let policy = ExecutionPolicy::default().for_target("www.itsecgames.com");
        for ok in [
            "www.itsecgames.com",
            "http://www.itsecgames.com/",
            "https://www.itsecgames.com/bWAPP/",
            "http://www.itsecgames.com:8080/login",
            "itsecgames.com", // apex of a www-scoped target
            "api.itsecgames.com",
            "deep.sub.itsecgames.com",
        ] {
            assert!(policy.scope.is_in_scope(ok), "{ok} must be in scope");
        }
    }

    #[test]
    fn scope_rejects_discovered_assets_like_the_shared_ip_vhost() {
        // The itsecgames/mmebvba case: a co-hosted site discovered during
        // the assessment must NOT become an active target by itself.
        let policy = ExecutionPolicy::default().for_target("www.itsecgames.com");
        for bad in [
            "mmebvba.com",
            "http://mmebvba.com/",
            "www.mmebvba.com",
            "itsecgames.com.evil.net", // suffix trick
            "notitsecgames.com",       // partial-name overlap
        ] {
            assert!(!policy.scope.is_in_scope(bad), "{bad} must be out of scope");
        }
    }

    #[test]
    fn scope_rejects_other_ips_when_scoped_to_an_ip() {
        let policy = ExecutionPolicy::default().for_target("10.0.0.1");
        assert!(policy.scope.is_in_scope("10.0.0.1"));
        assert!(policy.scope.is_in_scope("http://10.0.0.1:8080/x"));
        assert!(!policy.scope.is_in_scope("10.0.0.2"));
    }

    #[test]
    fn out_of_scope_is_a_distinct_rejection() {
        let policy = ExecutionPolicy::default().for_target("www.itsecgames.com");
        let err = policy
            .validate(&request("http.probe", "http://mmebvba.com/"), &caps())
            .unwrap_err();
        match &err {
            PolicyError::OutOfScope { target, scope } => {
                assert_eq!(target, "http://mmebvba.com/");
                assert_eq!(scope, "www.itsecgames.com");
            }
            other => panic!("expected OutOfScope, got {other:?}"),
        }
        // The message must be clearly different from provider errors.
        let msg = err.to_string();
        assert!(msg.contains("outside assessment scope"), "{msg}");
    }

    #[test]
    fn high_risk_requires_approval_and_is_bypass_proof() {
        // web.oob_testing is part of Destructive web.rce_chain_validation.
        let r = request("web.oob_testing", "10.0.0.1");
        let err = ExecutionPolicy::default()
            .validate(&r, &caps())
            .unwrap_err();
        assert!(matches!(err, PolicyError::HighRiskRequiresApproval { .. }));
        // Approval cannot be smuggled through options either.
        let mut r2 = request("web.oob_testing", "10.0.0.1");
        r2.options
            .insert("approved".into(), OptionValue::Bool(true));
        let err2 = ExecutionPolicy::default()
            .validate(&r2, &caps())
            .unwrap_err();
        assert!(
            matches!(err2, PolicyError::InvalidArguments { .. }),
            "option smuggle must fail before the risk gate: {err2:?}"
        );
        // Opt-in mode allows the capability itself.
        let allow = ExecutionPolicy {
            allow_destructive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            scope: ScopePolicy::unrestricted(),
        };
        assert!(allow.validate(&r, &caps()).is_ok());
    }

    #[test]
    fn host_of_strips_everything_but_the_host() {
        assert_eq!(
            host_of("http://User:pw@EXAMPLE.com:8080/a/b?x=1#f"),
            "example.com"
        );
        assert_eq!(host_of("https://10.0.0.1:443/"), "10.0.0.1");
        assert_eq!(host_of("example.com."), "example.com");
        assert_eq!(host_of("[::1]:8080/x"), "::1");
        assert_eq!(host_of("plainhost"), "plainhost");
    }
}
