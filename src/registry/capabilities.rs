//! Builtin capability definitions. A capability with zero registered provider
//! tools is an honest gap (e.g. cloud.*) — never invent providers.

use crate::model::{CapabilityDefinition, Importance as I, OptionKind, OptionSpec};

fn cap(id: &str, category: &str, description: &str, importance: I) -> CapabilityDefinition {
    CapabilityDefinition {
        id: id.to_string(),
        category: category.to_string(),
        description: description.to_string(),
        importance,
        min_providers_for_full: 1,
        requires_adapter: false,
        risk: crate::model::RiskLevel::Safe,
        options: Vec::new(),
    }
}

fn opt(name: &str, kind: OptionKind, description: &str) -> OptionSpec {
    OptionSpec {
        name: name.to_string(),
        kind,
        description: description.to_string(),
    }
}

fn ports_opt() -> OptionSpec {
    opt(
        "ports",
        OptionKind::Str,
        "Comma-separated port list or range, e.g. \"80,443\" or \"1-1000\".",
    )
}

fn intensity_opt() -> OptionSpec {
    opt(
        "intensity",
        OptionKind::Enum {
            values: vec!["slow".into(), "normal".into(), "fast".into()],
        },
        "Scan speed: slow (stealthy), normal, fast (loud).",
    )
}

fn with_options(mut c: CapabilityDefinition, options: Vec<OptionSpec>) -> CapabilityDefinition {
    c.options = options;
    c
}

pub fn builtin_capabilities() -> Vec<CapabilityDefinition> {
    vec![
        // Network
        cap(
            "network.host_discovery",
            "network",
            "Discover live hosts on a network.",
            I::High,
        ),
        with_options(
            cap(
                "network.port_scan",
                "network",
                "Enumerate open ports on a host.",
                I::High,
            ),
            vec![ports_opt(), intensity_opt()],
        ),
        with_options(
            cap(
                "network.service_detection",
                "network",
                "Identify services/versions on open ports.",
                I::High,
            ),
            vec![ports_opt()],
        ),
        cap(
            "network.os_detection",
            "network",
            "Fingerprint remote operating systems.",
            I::Medium,
        ),
        cap(
            "network.banner_grabbing",
            "network",
            "Grab service banners for identification.",
            I::Medium,
        ),
        // DNS / assets
        cap(
            "dns.enumeration",
            "dns",
            "Enumerate DNS records for a domain.",
            I::High,
        ),
        cap(
            "dns.resolution",
            "dns",
            "Resolve and validate large host lists.",
            I::Medium,
        ),
        cap(
            "subdomain.discovery",
            "dns",
            "Discover subdomains of a target.",
            I::High,
        ),
        cap(
            "asset.discovery",
            "dns",
            "Build an asset inventory for a target.",
            I::High,
        ),
        // HTTP / web discovery
        with_options(
            cap(
                "http.probe",
                "http",
                "Probe hosts for live HTTP(S) services.",
                I::High,
            ),
            vec![opt(
                "path",
                OptionKind::Str,
                "URL path to probe instead of the root, e.g. \"/login\".",
            )],
        ),
        with_options(
            cap(
                "http.crawl",
                "http",
                "Crawl a web app to map pages and endpoints.",
                I::High,
            ),
            vec![opt(
                "depth",
                OptionKind::Number {
                    min: Some(0.0),
                    max: Some(10.0),
                },
                "Maximum crawl depth (0-10).",
            )],
        ),
        cap(
            "http.endpoint_discovery",
            "http",
            "Discover hidden paths and endpoints.",
            I::High,
        ),
        cap(
            "http.parameter_discovery",
            "http",
            "Discover injectable parameters.",
            I::Medium,
        ),
        cap(
            "web.fuzzing",
            "http",
            "Fuzz web inputs for anomalies.",
            I::Medium,
        ),
        // Raw HTTP request issuing — the model's hands for business-logic
        // verification (login bypass, IDOR, auth checks). The target IS the
        // request URL; method/headers/body are semantic options.
        with_options(
            cap(
                "http.request",
                "http",
                "Issue a raw HTTP request to verify business-logic behavior (login bypass, IDOR, auth). Target = full URL.",
                I::High,
            ),
            vec![
                opt(
                    "method",
                    OptionKind::Enum {
                        values: vec![
                            "GET".into(),
                            "POST".into(),
                            "PUT".into(),
                            "PATCH".into(),
                            "DELETE".into(),
                            "HEAD".into(),
                            "OPTIONS".into(),
                        ],
                    },
                    "HTTP method (POST when `body` is given).",
                ),
                opt(
                    "headers",
                    OptionKind::Str,
                    "Request headers as \"Name: value\" pairs separated by \";\", e.g. \"Authorization: Bearer x; Content-Type: application/json\".",
                ),
                opt(
                    "body",
                    OptionKind::Str,
                    "Request body (form data, JSON, ...) — implies POST unless `method` is set.",
                ),
                opt(
                    "follow_redirects",
                    OptionKind::Bool,
                    "Follow 3xx redirects (default true).",
                ),
            ],
        ),
        // Web research — the model's read access to the internet: fetching
        // docs, GitHub code, or scraping pages to validate findings, look
        // up CVEs, or understand a target. READ-ONLY: it can never launch
        // an attack tool at a researched target. (Search is NOT here: the
        // model searches via the direct web_search tool.)
        with_options(
            cap(
                "web.research",
                "web",
                "Fetch and read web content (documentation, GitHub code, web pages) to research a topic, CVE, or target. Target = URL to read.",
                I::Medium,
            ),
            vec![opt(
                "selector",
                OptionKind::Str,
                "Reserved: target a specific element/selector. Whole-page extraction is used for now.",
            )],
        ),
        // Web security testing
        with_options(
            cap(
                "web.vulnerability_scan",
                "web",
                "Template/policy-based vuln scanning.",
                I::High,
            ),
            vec![opt(
                "severity",
                OptionKind::Enum {
                    values: vec![
                        "low".into(),
                        "medium".into(),
                        "high".into(),
                        "critical".into(),
                    ],
                },
                "Only report findings at or above this severity.",
            )],
        ),
        cap(
            "web.dynamic_testing",
            "web",
            "Interactive dynamic (DAST) testing.",
            I::High,
        ),
        cap(
            "web.interception",
            "web",
            "Intercept and modify live HTTP traffic.",
            I::Medium,
        ),
        with_options(
            cap(
                "web.injection_testing",
                "web",
                "Focused injection testing (SQLi etc.). Target the full endpoint URL (e.g. http://host/rest/user/login); supply `data` for POST parameters.",
                I::High,
            ),
            vec![
                opt(
                    "method",
                    OptionKind::Enum {
                        values: vec![
                            "GET".into(),
                            "POST".into(),
                            "PUT".into(),
                            "PATCH".into(),
                        ],
                    },
                    "HTTP method for the request under test (POST when `data` is given).",
                ),
                opt(
                    "data",
                    OptionKind::Str,
                    "Request body / POST parameters, e.g. \"email=a@b.c&password=x\".",
                ),
                opt(
                    "parameter",
                    OptionKind::Str,
                    "Restrict testing to this parameter name (e.g. \"email\").",
                ),
            ],
        ),
        // Traffic
        cap(
            "packet.capture",
            "traffic",
            "Capture raw network packets.",
            I::Medium,
        ),
        cap(
            "packet.analysis",
            "traffic",
            "Analyze captured packets.",
            I::Medium,
        ),
        cap(
            "protocol.analysis",
            "traffic",
            "Dissect protocol behavior.",
            I::Low,
        ),
        cap(
            "traffic.reconstruction",
            "traffic",
            "Reconstruct streams/files from captures.",
            I::Low,
        ),
        // Source
        cap(
            "source.static_analysis",
            "source",
            "Static analysis with security rules.",
            I::High,
        ),
        cap(
            "source.dataflow_analysis",
            "source",
            "Dataflow/taint analysis.",
            I::High,
        ),
        cap(
            "source.call_graph",
            "source",
            "Call-graph / reachability analysis.",
            I::Medium,
        ),
        cap(
            "source.secret_detection",
            "source",
            "Detect leaked secrets in code/history.",
            I::High,
        ),
        cap(
            "source.syntax_analysis",
            "source",
            "Parse/index source (baseline tooling).",
            I::Low,
        ),
        // Supply chain
        cap(
            "dependency.scan",
            "supply_chain",
            "Scan dependencies for known CVEs.",
            I::High,
        ),
        cap(
            "container.scan",
            "supply_chain",
            "Scan container images.",
            I::High,
        ),
        cap(
            "sbom.generate",
            "supply_chain",
            "Generate a software bill of materials.",
            I::Medium,
        ),
        cap(
            "vulnerability.lookup",
            "supply_chain",
            "Look up CVE/template metadata.",
            I::Medium,
        ),
        // Container / runtime
        cap(
            "container.security",
            "container",
            "Container image security scan (vulnerabilities, misconfigurations). Provider: trivy — target is an image reference (e.g. nginx:latest); needs the Docker daemon or registry access.",
            I::High,
        ),
        cap(
            "kubernetes.security",
            "container",
            "Kubernetes posture checks.",
            I::High,
        ),
        cap(
            "runtime.monitoring",
            "container",
            "Kernel/runtime threat monitoring. Provider: falco — Linux-only (kernel driver/eBPF), not possible on this device class.",
            I::Medium,
        ),
        cap(
            "configuration.audit",
            "container",
            "Benchmark/audit configuration.",
            I::Medium,
        ),
        // Binary
        cap(
            "binary.analysis",
            "binary",
            "Static binary analysis.",
            I::Medium,
        ),
        cap(
            "reverse.engineering",
            "binary",
            "Interactive reverse engineering.",
            I::Low,
        ),
        cap(
            "malware.analysis",
            "binary",
            "Malware triage and classification.",
            I::Low,
        ),
        cap(
            "capability.identification",
            "binary",
            "Identify binary capabilities (e.g. capa).",
            I::Low,
        ),
        // Cloud — prowler is the canonical provider; finer-grained checks
        // (per-service, per-provider) arrive with specialized providers later.
        cap(
            "cloud.posture_audit",
            "cloud",
            "Cloud posture/compliance audit (canonical provider: prowler).",
            I::High,
        ),
        cap(
            "cloud.asset_discovery",
            "cloud",
            "Enumerate cloud assets across providers.",
            I::High,
        ),
        cap(
            "cloud.iam_enumeration",
            "cloud",
            "Enumerate cloud identities, roles and policies.",
            I::High,
        ),
        cap(
            "cloud.storage_audit",
            "cloud",
            "Audit cloud storage exposure and encryption.",
            I::High,
        ),
        cap(
            "cloud.network_audit",
            "cloud",
            "Audit cloud network posture (SGs, exposure, flow).",
            I::Medium,
        ),
        cap(
            "cloud.entitlement_audit",
            "cloud",
            "Cloud entitlement/IAM audit. Provider: prowler (installed; execution adapter pending — its report goes to files, not stdout).",
            I::Medium,
        ),
        // External attack surface (uncover / asnmap / tlsx).
        cap(
            "external.exposed_host_discovery",
            "external",
            "Find exposed hosts via search-engine data.",
            I::High,
        ),
        cap(
            "external.asn_discovery",
            "external",
            "Map ASNs to IP ranges / org infrastructure.",
            I::Medium,
        ),
        cap(
            "external.tls_discovery",
            "external",
            "Discover certificates and TLS posture at scale.",
            I::Medium,
        ),
        // Out-of-band interaction testing (interactsh sidecar).
        with_options(
            cap(
                "web.oob_testing",
                "web",
                "Out-of-band detection (blind SSRF/XXE/callbacks). Workflow: action=start returns a unique callback URL — embed it in a payload, deliver it, then action=check lists interactions; action=stop cleans up.",
                I::Medium,
            ),
            vec![opt(
                "action",
                OptionKind::Enum {
                    values: vec!["start".into(), "check".into(), "stop".into()],
                },
                "Listener lifecycle: start (get callback URL), check (list interactions), stop (clean up).",
            )],
        ),
        // Browser — Playwright sidecar/worker, Chromium via Medusa Rust → BrowserProvider.
        // Initial capability is browser.network.observe (SPA API discovery); other browser.*
        // capabilities are provider-driven, not agent-loop changes.
        cap(
            "browser.network.observe",
            "browser",
            "Observe browser network events (XHR/fetch) to discover SPA APIs.",
            I::Medium,
        ),
        cap(
            "browser.dom.inspect",
            "browser",
            "Inspect DOM for forms and endpoints.",
            I::Low,
        ),
        cap(
            "browser.screenshot",
            "browser",
            "Capture browser screenshot for visual verification.",
            I::Low,
        ),
        // Identity — PingCastle (Windows-native AD security assessment).
        cap(
            "identity.enumeration",
            "identity",
            "Enumerate identities (users, groups, service accounts). Provider: PingCastle.",
            I::High,
        ),
        cap(
            "identity.privilege_analysis",
            "identity",
            "Excessive-privilege analysis. Provider: PingCastle.",
            I::High,
        ),
        cap(
            "identity.trust_analysis",
            "identity",
            "Trust-relationship analysis. Provider: PingCastle.",
            I::Medium,
        ),
        cap(
            "identity.attack_path_analysis",
            "identity",
            "Identity attack-path analysis. Provider: PingCastle.",
            I::Medium,
        ),
        // Database — discovery via nmap service detection; config/auth
        // audits via the mysql/psql clients; exposure via uncover.
        with_options(
            cap(
                "database.discovery",
                "database",
                "Discover database services (MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Elasticsearch). Provider: nmap.",
                I::Medium,
            ),
            vec![ports_opt()],
        ),
        with_options(
            cap(
                "database.config_audit",
                "database",
                "Database configuration audit (modes, logging, TLS, secure-transport settings). Providers: mysql, psql clients. Target = database host.",
                I::Medium,
            ),
            vec![
                opt("username", OptionKind::Str, "Database account name."),
                opt(
                    "password",
                    OptionKind::Str,
                    "Database account password (MySQL only; PostgreSQL uses ~/.pgpass).",
                ),
            ],
        ),
        with_options(
            cap(
                "database.auth_audit",
                "database",
                "Database authentication/authorization audit (accounts, hosts, auth plugins, grants, superuser roles). Providers: mysql, psql clients. Target = database host.",
                I::Medium,
            ),
            vec![
                opt("username", OptionKind::Str, "Database account name."),
                opt(
                    "password",
                    OptionKind::Str,
                    "Database account password (MySQL only; PostgreSQL uses ~/.pgpass).",
                ),
            ],
        ),
        cap(
            "database.exposed_detection",
            "database",
            "Detect internet-exposed databases via search-engine data (Shodan/Censys). Provider: uncover — needs API keys in its provider config. Target = domain to search.",
            I::High,
        ),
        // API — scanners contribute, but API authz/business-logic families
        // are tracked explicitly for the future reasoning engine.
        cap(
            "api.schema_discovery",
            "api",
            "Discover API schemas (REST/GraphQL/OpenAPI). No dedicated provider yet.",
            I::Medium,
        ),
        with_options(
            cap(
                "api.auth_testing",
                "api",
                "API authentication testing: verify auth mechanisms with raw requests (missing/weak/bypassed auth on endpoints). Target = the endpoint URL.",
                I::High,
            ),
            vec![
                opt(
                    "method",
                    OptionKind::Enum {
                        values: vec![
                            "GET".into(),
                            "POST".into(),
                            "PUT".into(),
                            "PATCH".into(),
                            "DELETE".into(),
                            "HEAD".into(),
                            "OPTIONS".into(),
                        ],
                    },
                    "HTTP method (POST when `body` is given).",
                ),
                opt(
                    "headers",
                    OptionKind::Str,
                    "Request headers as \"Name: value\" pairs separated by \";\". Omit Authorization to test missing-auth access.",
                ),
                opt(
                    "body",
                    OptionKind::Str,
                    "Request body (e.g. login JSON).",
                ),
            ],
        ),
        with_options(
            cap(
                "api.bola_testing",
                "api",
                "BOLA/IDOR testing: request another user's object by id and compare responses. Target = the object URL.",
                I::High,
            ),
            vec![
                opt(
                    "method",
                    OptionKind::Enum {
                        values: vec![
                            "GET".into(),
                            "POST".into(),
                            "PUT".into(),
                            "PATCH".into(),
                            "DELETE".into(),
                            "HEAD".into(),
                            "OPTIONS".into(),
                        ],
                    },
                    "HTTP method (default GET).",
                ),
                opt(
                    "headers",
                    OptionKind::Str,
                    "Request headers as \"Name: value\" pairs separated by \";\" (e.g. an Authorization token for the legit user).",
                ),
                opt(
                    "body",
                    OptionKind::Str,
                    "Request body when the object mutation needs one.",
                ),
            ],
        ),
        cap(
            "api.rate_limit_testing",
            "api",
            "Rate-limit / abuse testing. No dedicated provider yet.",
            I::Low,
        ),
    ]
    .into_iter()
    .map(|mut c| {
        // RCE-chain validation is the destructive-class methodology these
        // capabilities serve (OOB interaction / exploit validation) — the
        // risk gate keeps requiring explicit approval for them.
        if c.id == "web.vulnerability_scan" || c.id == "web.oob_testing" {
            c.risk = crate::model::RiskLevel::Destructive;
        }
        c
    })
    .collect()
}
