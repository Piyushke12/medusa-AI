//! Builtin tool definitions ââ‚¬” declarative data only.
//!
//! Installation policy (do not fabricate):
//! * `docs_url` is always an official homepage / official GitHub org repo.
//! * `brew`/`apt` package names equal the upstream project name; entries are
//!   marked `verified: true` only where the package name is the well-known
//!   upstream name. `winget` ids vary, so Windows entries are marked
//!   `verified: false` unless the id is the widely documented one (nmap),
//!   and the UI tells the user to `winget search` first.
//! * Nothing here is ever executed automatically.

use crate::model::{
    AdapterInfo, InstallKind, OptionBinding, Platform, PlatformInstall, ToolCategory,
    ToolDefinition,
};

fn adapter(id: &str, implemented: bool) -> Option<AdapterInfo> {
    Some(AdapterInfo {
        id: id.to_string(),
        implemented,
    })
}

/// Semantic option â†’ CLI flag binding (trusted translation data).
fn bind(
    capability: &str,
    option: &str,
    flag: &str,
    joined: bool,
    value_map: &[(&str, &str)],
) -> OptionBinding {
    OptionBinding {
        capability: capability.to_string(),
        option: option.to_string(),
        flag: flag.to_string(),
        joined,
        value_map: value_map
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

/// Capability-constant flag: an option binding with an EMPTY option name
/// that is appended whenever an action's capability matches — e.g. nmap
/// always gets `-O` for `network.os_detection`. Not model-controllable:
/// the schema never exposes an empty option name, so these bindings can
/// never collide with a model-supplied option.
fn bind_constant(capability: &str, flag: &str) -> OptionBinding {
    bind(capability, "", flag, false, &[])
}

fn pkg(
    manager: &str,
    package: &str,
    instructions: &str,
    verified: bool,
    docs_url: &str,
) -> PlatformInstall {
    PlatformInstall {
        kind: InstallKind::PackageManager,
        manager: Some(manager.to_string()),
        package: Some(package.to_string()),
        instructions: instructions.to_string(),
        verified,
        docs_url: docs_url.to_string(),
    }
}

fn docs(instructions: &str, docs_url: &str) -> PlatformInstall {
    PlatformInstall::docs_only(instructions, docs_url)
}

fn def(
    id: &str,
    name: &str,
    category: ToolCategory,
    description: &str,
    capabilities: &[&str],
    executables: &[&str],
    version_args: &[&str],
    docs_url: &str,
    adapter: Option<AdapterInfo>,
    priority: u8,
    default_args: &[&str],
) -> ToolDefinition {
    ToolDefinition {
        id: id.to_string(),
        name: name.to_string(),
        category,
        description: description.to_string(),
        capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
        executable_candidates: executables.iter().map(|s| s.to_string()).collect(),
        version_args: version_args.iter().map(|s| s.to_string()).collect(),
        health_args: None,
        extra_search_dirs: Vec::new(),
        dependencies: Vec::new(),
        platforms: vec![Platform::Windows, Platform::Macos, Platform::Linux],
        install_windows: None,
        install_macos: None,
        install_linux: None,
        docs_url: docs_url.to_string(),
        adapter,
        priority,
        required: false,
        builtin: false,
        default_args: default_args.iter().map(|s| s.to_string()).collect(),
        option_bindings: Vec::new(),
    }
}

/// All builtin tools. Ordered by category for stable startup display.
pub fn builtin_tools() -> Vec<ToolDefinition> {
    let mut v: Vec<ToolDefinition> = Vec::new();

    // ---- Network discovery ----
    let mut nmap = def(
        "nmap",
        "Nmap",
        ToolCategory::NetworkDiscovery,
        "Network discovery, port scanning and service/OS detection.",
        &[
            "network.host_discovery",
            "network.port_scan",
            "network.service_detection",
            "network.os_detection",
            "network.banner_grabbing",
            "database.discovery",
        ],
        &["nmap"],
        &["--version"],
        "https://nmap.org",
        adapter("nmap_xml", true),
        100,
        &["-sV", "-oX", "-", "{target}"],
    );
    nmap.extra_search_dirs = vec![
        "C:\\Program Files (x86)\\Nmap".into(),
        "C:\\Program Files\\Nmap".into(),
    ];
    // Semantic option translation: ports/intensity â†’ nmap flags, plus
    // capability-constant flags (OS fingerprinting, banner grabbing) that
    // apply whenever that capability is the one being executed.
    nmap.option_bindings = vec![
        bind("network.port_scan", "ports", "-p", false, &[]),
        bind(
            "network.port_scan",
            "intensity",
            "-T",
            true,
            &[("slow", "2"), ("normal", "3"), ("fast", "4")],
        ),
        bind("network.service_detection", "ports", "-p", false, &[]),
        bind("database.discovery", "ports", "-p", false, &[]),
        bind_constant("network.os_detection", "-O"),
        bind_constant("network.banner_grabbing", "--script=banner"),
    ];
    nmap.install_windows = Some(pkg(
        "winget",
        "Insecure.Nmap",
        "winget install Insecure.Nmap (verify with `winget search nmap` first)",
        true,
        "https://nmap.org/download.html",
    ));
    nmap.install_macos = Some(pkg(
        "brew",
        "nmap",
        "brew install nmap",
        true,
        "https://nmap.org/download.html",
    ));
    nmap.install_linux = Some(pkg(
        "apt",
        "nmap",
        "sudo apt install nmap",
        true,
        "https://nmap.org/download.html",
    ));
    v.push(nmap);

    let mut naabu = def(
        "naabu",
        "Naabu",
        ToolCategory::NetworkDiscovery,
        "Fast port scanner from ProjectDiscovery.",
        &["network.port_scan", "network.host_discovery"],
        &["naabu"],
        &["-version"],
        "https://github.com/projectdiscovery/naabu",
        adapter("naabu_json", true),
        70,
        &["-host", "{target}"],
    );
    naabu.install_macos = Some(pkg(
        "brew",
        "naabu",
        "brew install naabu",
        true,
        "https://github.com/projectdiscovery/naabu",
    ));
    naabu.install_linux = Some(docs("Install via the official release binary (Go toolchain also works: `go install`). See official README for the current release asset.", "https://github.com/projectdiscovery/naabu"));
    naabu.install_windows = Some(docs(
        "Download the official Windows release binary. See releases page.",
        "https://github.com/projectdiscovery/naabu/releases",
    ));
    // naabu binds `ports` but NOT `intensity` — requesting intensity makes
    // the resolver prefer nmap, or reject when only naabu is available.
    naabu.option_bindings = vec![bind("network.port_scan", "ports", "-p", false, &[])];
    v.push(naabu);

    // ---- DNS / asset ----
    let mut subfinder = def(
        "subfinder",
        "Subfinder",
        ToolCategory::DnsAsset,
        "Passive subdomain enumeration.",
        &["dns.enumeration", "subdomain.discovery", "asset.discovery"],
        &["subfinder"],
        &["-version"],
        "https://github.com/projectdiscovery/subfinder",
        adapter("subfinder_json", true),
        75,
        &["-d", "{target}"],
    );
    subfinder.install_macos = Some(pkg(
        "brew",
        "subfinder",
        "brew install subfinder",
        true,
        "https://github.com/projectdiscovery/subfinder",
    ));
    subfinder.install_linux = Some(pkg(
        "apt",
        "subfinder",
        "sudo apt install subfinder (or official release binary)",
        false,
        "https://github.com/projectdiscovery/subfinder",
    ));
    subfinder.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/subfinder/releases",
    ));
    v.push(subfinder);

    let mut dnsx = def(
        "dnsx",
        "dnsx",
        ToolCategory::DnsAsset,
        "Fast DNS resolver/validator.",
        &["dns.enumeration", "dns.resolution", "asset.discovery"],
        &["dnsx"],
        &["-version"],
        "https://github.com/projectdiscovery/dnsx",
        adapter("dnsx_json", true),
        70,
        // dnsx requires a wordlist with `-d` domain input — without `-w` it
        // fatals with "missing wordlist(w) flag required with domain(d) input".
        &["-d", "{target}", "-w", "wordlists/subdomains.txt"],
    );
    dnsx.install_macos = Some(pkg(
        "brew",
        "dnsx",
        "brew install dnsx",
        true,
        "https://github.com/projectdiscovery/dnsx",
    ));
    dnsx.install_linux = Some(docs(
        "Install via the official release binary. See README.",
        "https://github.com/projectdiscovery/dnsx",
    ));
    dnsx.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/dnsx/releases",
    ));
    v.push(dnsx);

    // ---- External attack surface ----
    // Canonical ProjectDiscovery mapping tools: uncover finds exposed hosts
    // via search engines, asnmap maps ASN -> IP ranges, tlsx probes TLS.
    let mut uncover = def(
        "uncover",
        "Uncover",
        ToolCategory::ExternalSurface,
        "Exposed-host discovery via search engines (Shodan/Censys/FOFA-style).",
        &["external.exposed_host_discovery", "asset.discovery"],
        &["uncover"],
        &["-version"],
        "https://github.com/projectdiscovery/uncover",
        adapter("uncover_json", true),
        72,
        &["-q", "{target}"],
    );
    uncover.install_macos = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/uncover",
    ));
    uncover.install_linux = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/uncover",
    ));
    uncover.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/uncover/releases",
    ));
    v.push(uncover);

    // Separate def from `uncover`: dedicated database-exposure query over
    // the same binary. The port filter targets common database services;
    // needs Shodan/Censys API keys in uncover's provider config.
    let uncover_db = def(
        "uncover-db",
        "Uncover (databases)",
        ToolCategory::ExternalSurface,
        "Internet-exposed database detection via search-engine data.",
        &["database.exposed_detection"],
        &["uncover"],
        &["-version"],
        "https://github.com/projectdiscovery/uncover",
        adapter("uncover_json", true),
        71,
        &[
            "-q",
            "domain:{target} AND port:1433,1521,3306,5432,6379,8545,9200,11211,27017",
        ],
    );
    v.push(uncover_db);

    let mut asnmap = def(
        "asnmap",
        "asnmap",
        ToolCategory::ExternalSurface,
        "ASN / IP / organizational infrastructure mapping.",
        &["external.asn_discovery", "asset.discovery"],
        &["asnmap"],
        &["-version"],
        "https://github.com/projectdiscovery/asnmap",
        adapter("asnmap_json", true),
        68,
        &["-d", "{target}"],
    );
    asnmap.install_macos = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/asnmap",
    ));
    asnmap.install_linux = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/asnmap",
    ));
    asnmap.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/asnmap/releases",
    ));
    v.push(asnmap);

    let mut tlsx = def(
        "tlsx",
        "tlsx",
        ToolCategory::ExternalSurface,
        "TLS certificate and configuration probing.",
        &["external.tls_discovery", "http.probe"],
        &["tlsx"],
        &["-version"],
        "https://github.com/projectdiscovery/tlsx",
        adapter("tlsx_json", true),
        68,
        &["-host", "{target}", "-json"],
    );
    tlsx.install_macos = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/tlsx",
    ));
    tlsx.install_linux = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/tlsx",
    ));
    tlsx.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/tlsx/releases",
    ));
    v.push(tlsx);

    // ---- HTTP / Web discovery ----
    let mut httpx = def(
        "httpx",
        "httpx",
        ToolCategory::HttpWebDiscovery,
        "Fast HTTP prober (status, title, tech detection).",
        &["http.probe", "http.endpoint_discovery"],
        &["httpx"],
        &["-version"],
        "https://github.com/projectdiscovery/httpx",
        adapter("httpx_json", true),
        80,
        &[
            "-u",
            "{target}",
            "-json",
            "-silent",
            "-follow-redirects",
            "-title",
            "-tech-detect",
        ],
    );
    httpx.install_macos = Some(pkg(
        "brew",
        "httpx",
        "brew install httpx",
        true,
        "https://github.com/projectdiscovery/httpx",
    ));
    httpx.install_linux = Some(docs(
        "Install via the official release binary. See README.",
        "https://github.com/projectdiscovery/httpx",
    ));
    httpx.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/httpx/releases",
    ));
    httpx.option_bindings = vec![bind("http.probe", "path", "-path", false, &[])];
    v.push(httpx);

    let mut katana = def(
        "katana",
        "Katana",
        ToolCategory::HttpWebDiscovery,
        "Crawler and spidering framework.",
        &[
            "http.crawl",
            "http.endpoint_discovery",
            "api.schema_discovery",
        ],
        &["katana"],
        &["-version"],
        "https://github.com/projectdiscovery/katana",
        adapter("katana_json", true),
        75,
        // -jc parses endpoints out of JavaScript bundles (SPAs hide their
        // API surface in main.js); -kf all also crawls robots.txt and
        // sitemap.xml. Default depth (3) satisfies -kf's minimum.
        &["-u", "{target}", "-jsonl", "-silent", "-jc", "-kf", "all"],
    );
    katana.install_macos = Some(pkg(
        "brew",
        "katana",
        "brew install katana",
        true,
        "https://github.com/projectdiscovery/katana",
    ));
    katana.install_linux = Some(docs(
        "Install via the official release binary.",
        "https://github.com/projectdiscovery/katana",
    ));
    katana.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/katana/releases",
    ));
    katana.option_bindings = vec![bind("http.crawl", "depth", "-d", false, &[])];
    v.push(katana);

    // BrowserProvider as first-class capability — same AgentRuntime, new provider via Playwright sidecar.
    // Medusa Rust â†’ `node <state_dir>/scripts/browser-observe.mjs --url {target} --json`
    // â†’ Playwright â†’ headless Chromium. The sidecar script is embedded in the
    // binary (`infra::scripts`) and written to the state dir on first use via
    // the `{script:...}` placeholder; `node` is the resolved executable and a
    // declared dependency. Requires the playwright npm package resolvable by
    // node (local or `npm root -g`) and `playwright install chromium`.
    let mut browser = def(
        "browser",
        "Browser",
        ToolCategory::HttpWebDiscovery,
        "Playwright sidecar for SPA network/DOM observation.",
        &[
            "browser.network.observe",
            "browser.dom.inspect",
            "browser.screenshot",
            "api.schema_discovery",
        ],
        &["node"],
        &["--version"],
        "https://playwright.dev",
        adapter("browser_json", true),
        60,
        &[
            "{script:browser-observe.mjs}",
            "--url",
            "{target}",
            "--json",
        ],
    );
    browser.dependencies = vec!["node".to_string()];
    browser.platforms = vec![Platform::Windows, Platform::Macos, Platform::Linux];
    v.push(browser);

    let mut ffuf = def(
        "ffuf",
        "ffuf",
        ToolCategory::HttpWebDiscovery,
        "Fast web fuzzer for endpoints and parameters.",
        &[
            "http.endpoint_discovery",
            "http.parameter_discovery",
            "web.fuzzing",
        ],
        &["ffuf"],
        &["-V"],
        "https://github.com/ffuf/ffuf",
        adapter("ffuf_plain", true),
        70,
        &[
            "-u",
            "{target}/FUZZ",
            "-w",
            "wordlists/common.txt",
            // -ac auto-calibrates: SPA fallbacks that return HTTP 200 with
            // identical bodies for every path (OWASP Juice Shop et al.) get
            // filtered as baseline noise instead of matching every word.
            "-ac",
            "-s",
        ],
    );
    ffuf.install_macos = Some(pkg(
        "brew",
        "ffuf",
        "brew install ffuf",
        true,
        "https://github.com/ffuf/ffuf",
    ));
    ffuf.install_linux = Some(pkg(
        "apt",
        "ffuf",
        "sudo apt install ffuf",
        true,
        "https://github.com/ffuf/ffuf",
    ));
    ffuf.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/ffuf/ffuf/releases",
    ));
    v.push(ffuf);

    // ---- Web security testing ----
    let mut nuclei = def(
        "nuclei",
        "Nuclei",
        ToolCategory::WebSecurity,
        "Template-based vulnerability scanner.",
        &["web.vulnerability_scan", "vulnerability.lookup"],
        &["nuclei"],
        &["-version"],
        "https://github.com/projectdiscovery/nuclei",
        adapter("nuclei_json", true),
        85,
        &["-target", "{target}", "-jsonl", "-silent"],
    );
    nuclei.install_macos = Some(pkg(
        "brew",
        "nuclei",
        "brew install nuclei",
        true,
        "https://github.com/projectdiscovery/nuclei",
    ));
    nuclei.install_linux = Some(pkg(
        "apt",
        "nuclei",
        "sudo apt install nuclei (or official release binary)",
        false,
        "https://github.com/projectdiscovery/nuclei",
    ));
    nuclei.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/nuclei/releases",
    ));
    nuclei.option_bindings = vec![bind(
        "web.vulnerability_scan",
        "severity",
        "-severity",
        false,
        &[],
    )];
    v.push(nuclei);

    let mut zap = def(
        "zap",
        "OWASP ZAP",
        ToolCategory::WebSecurity,
        "Dynamic application security testing proxy.",
        &[
            "web.vulnerability_scan",
            "web.dynamic_testing",
            "web.interception",
        ],
        &["zap", "zaproxy", "owasp-zap"],
        &["-version"],
        "https://www.zaproxy.org",
        adapter("zap_api", false),
        80,
        // -cmd forces headless cmdline mode (bare `zap` opens the GUI and
        // hangs the executor); quick-scan runs a baseline pass on the
        // target and exits.
        &["-cmd", "-quickurl", "{target}", "-quickprogress"],
    );
    zap.dependencies = vec!["java".to_string()];
    zap.install_macos = Some(pkg(
        "brew",
        "owasp-zap",
        "brew install --cask owasp-zap",
        true,
        "https://www.zaproxy.org/download/",
    ));
    zap.install_linux = Some(docs(
        "Use the official Docker image or installer. See download page.",
        "https://www.zaproxy.org/download/",
    ));
    zap.install_windows = Some(docs(
        "Download the official Windows installer.",
        "https://www.zaproxy.org/download/",
    ));
    v.push(zap);

    let mut sqlmap = def(
        "sqlmap",
        "sqlmap",
        ToolCategory::WebSecurity,
        "Automatic SQL injection testing.",
        &["web.injection_testing", "web.vulnerability_scan"],
        &["sqlmap", "sqlmap.py"],
        &["--version", "--non-interactive"],
        "https://sqlmap.org",
        adapter("sqlmap_plain", true),
        70,
        // Target must be the FULL endpoint URL (with path) — sqlmap cannot
        // test a bare origin ("no parameter(s) found"). POST bodies and
        // parameter pinning arrive via option bindings.
        &["-u", "{target}", "--batch", "--non-interactive"],
    );
    sqlmap.dependencies = vec!["python".to_string()];
    sqlmap.option_bindings = vec![
        bind("web.injection_testing", "method", "--method", false, &[]),
        bind("web.injection_testing", "data", "--data", false, &[]),
        bind("web.injection_testing", "parameter", "-p", false, &[]),
    ];
    sqlmap.install_macos = Some(pkg(
        "brew",
        "sqlmap",
        "brew install sqlmap",
        true,
        "https://sqlmap.org",
    ));
    sqlmap.install_linux = Some(pkg(
        "apt",
        "sqlmap",
        "sudo apt install sqlmap",
        true,
        "https://sqlmap.org",
    ));
    sqlmap.install_windows = Some(docs(
        "Download the official release zip (requires Python).",
        "https://sqlmap.org",
    ));
    v.push(sqlmap);

    let mut interactsh = def(
        "interactsh",
        "Interactsh",
        ToolCategory::WebSecurity,
        "Out-of-band interaction testing (blind SSRF, XXE, callbacks).",
        &["web.oob_testing", "web.vulnerability_scan"],
        // Sidecar pattern (like `browser`): the raw interactsh-client polls
        // forever and cannot run one-shot, so the embedded medusa-oob.mjs
        // manages a detached background client: action=start returns a
        // callback URL, action=check reports interactions, action=stop
        // cleans up. Requires `node` AND `interactsh-client` on PATH.
        &["node"],
        &["--version"],
        "https://github.com/projectdiscovery/interactsh",
        adapter("interactsh_json", true),
        62,
        &["{script:medusa-oob.mjs}", "--target", "{target}"],
    );
    interactsh.dependencies = vec!["node".to_string(), "interactsh-client".to_string()];
    interactsh.option_bindings = vec![bind("web.oob_testing", "action", "--action", false, &[])];
    interactsh.install_macos = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/interactsh",
    ));
    interactsh.install_linux = Some(docs(
        "Install via the official release binary or Go toolchain. See official README.",
        "https://github.com/projectdiscovery/interactsh",
    ));
    interactsh.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/projectdiscovery/interactsh/releases",
    ));
    v.push(interactsh);

    // ---- Traffic analysis ----
    let mut tshark = def(
        "tshark",
        "TShark (Wireshark)",
        ToolCategory::TrafficAnalysis,
        "CLI packet capture and analysis.",
        &[
            "packet.capture",
            "packet.analysis",
            "protocol.analysis",
            "traffic.reconstruction",
        ],
        &["tshark"],
        &["--version"],
        "https://www.wireshark.org",
        adapter("tshark_plain", true),
        75,
        // Read a capture file (target = .pcap/.pcapng path) instead of a
        // live capture: bare `tshark` blocks on the first interface.
        &["-r", "{target}"],
    );
    tshark.extra_search_dirs = vec!["C:\\Program Files\\Wireshark".into()];
    tshark.install_windows = Some(pkg("winget", "WiresharkFoundation.Wireshark", "winget install WiresharkFoundation.Wireshark (verify with `winget search wireshark` first)", false, "https://www.wireshark.org/download.html"));
    tshark.install_macos = Some(pkg(
        "brew",
        "wireshark",
        "brew install --cask wireshark",
        true,
        "https://www.wireshark.org/download.html",
    ));
    tshark.install_linux = Some(pkg(
        "apt",
        "tshark",
        "sudo apt install tshark",
        true,
        "https://www.wireshark.org/download.html",
    ));
    v.push(tshark);

    let mut tcpdump = def(
        "tcpdump",
        "tcpdump",
        ToolCategory::TrafficAnalysis,
        "CLI packet capture.",
        &["packet.capture", "packet.analysis"],
        &["tcpdump"],
        &["--version"],
        "https://www.tcpdump.org",
        adapter("tshark_plain", true),
        65,
        // Read a capture file like tshark; live capture (-i) needs an
        // interface choice and a stop condition the argv cannot express.
        &["-r", "{target}"],
    );
    tcpdump.platforms = vec![Platform::Macos, Platform::Linux];
    tcpdump.install_macos = Some(docs(
        "Preinstalled on macOS. Otherwise: `brew install tcpdump`.",
        "https://www.tcpdump.org",
    ));
    tcpdump.install_linux = Some(pkg(
        "apt",
        "tcpdump",
        "sudo apt install tcpdump",
        true,
        "https://www.tcpdump.org",
    ));
    tcpdump.install_windows = Some(docs(
        "Not natively available on Windows; use TShark or WinDump instead.",
        "https://www.tcpdump.org",
    ));
    v.push(tcpdump);

    // ---- Source analysis ----
    let mut semgrep = def(
        "semgrep",
        "Semgrep",
        ToolCategory::SourceAnalysis,
        "Static analysis with security rulesets.",
        &[
            "source.static_analysis",
            "source.secret_detection",
            "source.syntax_analysis",
        ],
        &["semgrep"],
        &["--version"],
        "https://semgrep.dev",
        adapter("semgrep_json", true),
        85,
        &["scan", "--json", "{target}"],
    );
    semgrep.dependencies = vec!["python".to_string()];
    semgrep.install_macos = Some(pkg(
        "brew",
        "semgrep",
        "brew install semgrep",
        true,
        "https://semgrep.dev/docs/getting-started/",
    ));
    semgrep.install_linux = Some(pkg(
        "pipx",
        "semgrep",
        "pipx install semgrep (see official docs)",
        false,
        "https://semgrep.dev/docs/getting-started/",
    ));
    semgrep.install_windows = Some(docs(
        "Install via pipx or Docker per official docs.",
        "https://semgrep.dev/docs/getting-started/",
    ));
    v.push(semgrep);

    let mut codeql = def(
        "codeql",
        "CodeQL",
        ToolCategory::SourceAnalysis,
        "Semantic code analysis / dataflow engine.",
        &[
            "source.static_analysis",
            "source.dataflow_analysis",
            "source.call_graph",
        ],
        &["codeql"],
        &["version"],
        "https://codeql.github.com",
        None,
        80,
        // No argv on purpose: CodeQL needs `database create` then
        // `database analyze` — a two-step workflow with a persistent
        // database directory that one {target} invocation cannot express.
        // The provider availability guard keeps it non-executable until a
        // workflow wrapper exists.
        &[],
    );
    codeql.dependencies = vec!["git".to_string()];
    codeql.install_macos = Some(pkg(
        "brew",
        "codeql",
        "brew install codeql",
        true,
        "https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/",
    ));
    codeql.install_linux = Some(docs(
        "Download the official CLI bundle (tar.gz).",
        "https://github.com/github/codeql-cli-binaries/releases",
    ));
    codeql.install_windows = Some(docs(
        "Download the official CLI bundle (zip).",
        "https://github.com/github/codeql-cli-binaries/releases",
    ));
    v.push(codeql);

    let mut gitleaks = def(
        "gitleaks",
        "Gitleaks",
        ToolCategory::SourceAnalysis,
        "Secret scanner for git repos.",
        &["source.secret_detection"],
        &["gitleaks"],
        &["version"],
        "https://github.com/gitleaks/gitleaks",
        adapter("gitleaks_json", true),
        70,
        &["detect", "--source", "{target}"],
    );
    gitleaks.install_macos = Some(pkg(
        "brew",
        "gitleaks",
        "brew install gitleaks",
        true,
        "https://github.com/gitleaks/gitleaks",
    ));
    gitleaks.install_linux = Some(docs(
        "Download the official release binary.",
        "https://github.com/gitleaks/gitleaks/releases",
    ));
    gitleaks.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/gitleaks/gitleaks/releases",
    ));
    v.push(gitleaks);

    let mut git = def(
        "git",
        "Git",
        ToolCategory::SourceAnalysis,
        "Baseline source-control tooling required by several analyzers.",
        &["source.syntax_analysis"],
        &["git"],
        &["--version"],
        "https://git-scm.com",
        None,
        90,
        &[],
    );
    git.required = true;
    git.install_windows = Some(pkg(
        "winget",
        "Git.Git",
        "winget install Git.Git (verify with `winget search git` first)",
        false,
        "https://git-scm.com/download/win",
    ));
    git.install_macos = Some(pkg(
        "brew",
        "git",
        "brew install git",
        true,
        "https://git-scm.com/download/mac",
    ));
    git.install_linux = Some(pkg(
        "apt",
        "git",
        "sudo apt install git",
        true,
        "https://git-scm.com/download/linux",
    ));
    v.push(git);

    // ---- Supply chain ----
    let mut trivy = def(
        "trivy",
        "Trivy",
        ToolCategory::SupplyChain,
        "Vulnerability/misconfig/secret scanner for deps, images and IaC.",
        &[
            "dependency.scan",
            "container.scan",
            "vulnerability.lookup",
            "configuration.audit",
        ],
        &["trivy"],
        &["--version"],
        "https://github.com/aquasecurity/trivy",
        adapter("trivy_json", true),
        85,
        &["fs", "--format", "json", "{target}"],
    );
    trivy.install_macos = Some(pkg(
        "brew",
        "trivy",
        "brew install trivy",
        true,
        "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
    ));
    trivy.install_linux = Some(pkg(
        "apt",
        "trivy",
        "See official docs: add AquaSecurity repo, then `apt install trivy`",
        false,
        "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
    ));
    trivy.install_windows = Some(docs(
        "Download the official Windows release (zip).",
        "https://github.com/aquasecurity/trivy/releases",
    ));
    v.push(trivy);

    // Separate def from `trivy` (filesystem mode): one binary, two
    // invocation shapes. container.security takes an image reference
    // (`nginx:latest`, `localhost:5000/app`) and needs the Docker daemon
    // (or a registry) — detection stays honest: absent daemon = failed run.
    let trivy_image = def(
        "trivy-image",
        "Trivy (container images)",
        ToolCategory::ContainerK8s,
        "Vulnerability/misconfig scan of container images.",
        &["container.security", "container.scan"],
        &["trivy"],
        &["--version"],
        "https://github.com/aquasecurity/trivy",
        adapter("trivy_json", true),
        80,
        &["image", "--format", "json", "{target}"],
    );
    v.push(trivy_image);

    let mut syft = def(
        "syft",
        "Syft",
        ToolCategory::SupplyChain,
        "SBOM generator for containers and filesystems.",
        &["sbom.generate", "dependency.scan"],
        &["syft"],
        &["version"],
        "https://github.com/anchore/syft",
        adapter("syft_json", true),
        70,
        &["{target}", "-o", "json"],
    );
    syft.install_macos = Some(pkg(
        "brew",
        "syft",
        "brew install syft",
        true,
        "https://github.com/anchore/syft",
    ));
    syft.install_linux = Some(docs(
        "Use the official install script or release binary per README.",
        "https://github.com/anchore/syft",
    ));
    syft.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/anchore/syft/releases",
    ));
    v.push(syft);

    let mut grype = def(
        "grype",
        "Grype",
        ToolCategory::SupplyChain,
        "Vulnerability scanner for SBOMs and images.",
        &["vulnerability.lookup", "dependency.scan"],
        &["grype"],
        &["version"],
        "https://github.com/anchore/grype",
        adapter("grype_json", true),
        70,
        // NOTE: grype treats a bare value as a container image reference and
        // attempts a registry pull (network hang until timeout). Local
        // filesystem targets need the `dir:` scheme.
        &["dir:{target}", "-o", "json"],
    );
    grype.install_macos = Some(pkg(
        "brew",
        "grype",
        "brew install grype",
        true,
        "https://github.com/anchore/grype",
    ));
    grype.install_linux = Some(docs(
        "Use the official install script or release binary per README.",
        "https://github.com/anchore/grype",
    ));
    grype.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/anchore/grype/releases",
    ));
    v.push(grype);

    // ---- Container / K8s ----
    let mut falco = def(
        "falco",
        "Falco",
        ToolCategory::ContainerK8s,
        "Runtime threat detection for containers/Kubernetes.",
        &["runtime.monitoring", "container.security"],
        &["falco"],
        &["--version"],
        "https://falco.org",
        adapter("falco_plain", true),
        65,
        &[],
    );
    falco.platforms = vec![Platform::Linux, Platform::Macos];
    falco.install_linux = Some(docs(
        "Install per official docs (apt repo / Helm chart).",
        "https://falco.org/docs/getting-started/installation/",
    ));
    falco.install_macos = Some(docs(
        "Falco is Linux-focused; on macOS use the official Docker image.",
        "https://falco.org/docs/getting-started/installation/",
    ));
    falco.install_windows = Some(docs(
        "Not supported on Windows; use WSL2 + Docker per official docs.",
        "https://falco.org/docs/getting-started/installation/",
    ));
    v.push(falco);

    let mut kubescape = def(
        "kubescape",
        "Kubescape",
        ToolCategory::ContainerK8s,
        "Kubernetes security posture scanning.",
        &["kubernetes.security", "configuration.audit"],
        &["kubescape"],
        &["version"],
        "https://github.com/kubescape/kubescape",
        adapter("kubescape_json", true),
        60,
        // scan framework all <target> — target is a manifest file, dir,
        // repo URL or cluster reference; JSON goes to stdout.
        &["scan", "framework", "all", "--format", "json", "{target}"],
    );
    kubescape.install_macos = Some(pkg(
        "brew",
        "kubescape",
        "brew install kubescape",
        true,
        "https://github.com/kubescape/kubescape",
    ));
    kubescape.install_linux = Some(docs(
        "Use the official install script per README.",
        "https://github.com/kubescape/kubescape",
    ));
    kubescape.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/kubescape/kubescape/releases",
    ));
    v.push(kubescape);

    let mut kubebench = def(
        "kube-bench",
        "kube-bench",
        ToolCategory::ContainerK8s,
        "CIS Kubernetes benchmark checks.",
        &["kubernetes.security", "configuration.audit"],
        &["kube-bench"],
        &["--version"],
        "https://github.com/aquasecurity/kube-bench",
        None,
        55,
        // No argv on purpose: kube-bench checks the local node/cluster
        // (no {target} semantics); JSON flags alone would run an
        // environment-dependent scan. Stays non-executable.
        &[],
    );
    kubebench.install_macos = Some(pkg(
        "brew",
        "kube-bench",
        "brew install kube-bench",
        true,
        "https://github.com/aquasecurity/kube-bench",
    ));
    kubebench.install_linux = Some(docs(
        "Download the official release binary.",
        "https://github.com/aquasecurity/kube-bench/releases",
    ));
    kubebench.install_windows = Some(docs(
        "Run via the official Docker image (needs cluster access).",
        "https://github.com/aquasecurity/kube-bench",
    ));
    v.push(kubebench);

    // ---- Binary / RE ----
    let mut ghidra = def(
        "ghidra",
        "Ghidra",
        ToolCategory::BinaryRe,
        "Software reverse-engineering suite.",
        &["binary.analysis", "reverse.engineering"],
        &["ghidra", "ghidraRun"],
        &["--version"],
        "https://ghidra-sre.org",
        None,
        60,
        // No argv on purpose: headless analysis needs the separate
        // analyzeHeadless launcher with a two-step project workflow
        // (create/import then analyze) that a single {target} invocation
        // cannot express. Bare `ghidra` opens the GUI — the provider
        // availability guard keeps this tool non-executable (and the
        // model untempted) until a real adapter lands.
        &[],
    );
    ghidra.dependencies = vec!["java".to_string()];
    ghidra.install_windows = Some(docs(
        "Download the official release zip (requires JDK per docs).",
        "https://ghidra-sre.org/installationguide.html",
    ));
    ghidra.install_macos = Some(docs(
        "Download the official release zip (requires JDK per docs).",
        "https://ghidra-sre.org/installationguide.html",
    ));
    ghidra.install_linux = Some(docs(
        "Download the official release zip (requires JDK per docs).",
        "https://ghidra-sre.org/installationguide.html",
    ));
    v.push(ghidra);

    let mut rizin = def(
        "rizin",
        "Rizin (radare2 family)",
        ToolCategory::BinaryRe,
        "CLI reverse-engineering framework.",
        &["binary.analysis", "reverse.engineering"],
        &["rizin", "radare2", "r2"],
        &["-v"],
        "https://rizin.re",
        adapter("rizin_plain", true),
        55,
        // -q -c runs a batch command and exits; bare `rizin` opens an
        // interactive REPL that hangs the executor until timeout.
        &["-q", "-c", "aaa;i", "{target}"],
    );
    rizin.install_macos = Some(pkg(
        "brew",
        "rizin",
        "brew install rizin",
        true,
        "https://rizin.re",
    ));
    rizin.install_linux = Some(pkg(
        "apt",
        "rizin",
        "sudo apt install rizin",
        true,
        "https://rizin.re",
    ));
    rizin.install_windows = Some(docs(
        "Download the official Windows release.",
        "https://github.com/rizinorg/rizin/releases",
    ));
    v.push(rizin);

    let mut capa = def(
        "capa",
        "capa",
        ToolCategory::BinaryRe,
        "Malware capability identification.",
        &["malware.analysis", "capability.identification"],
        &["capa"],
        &["--version"],
        "https://github.com/mandiant/capa",
        adapter("capa_json", true),
        50,
        &[],
    );
    capa.install_macos = Some(pkg(
        "brew",
        "capa",
        "brew install capa",
        true,
        "https://github.com/mandiant/capa",
    ));
    capa.install_linux = Some(docs(
        "Download the official Linux release binary.",
        "https://github.com/mandiant/capa/releases",
    ));
    capa.install_windows = Some(docs(
        "Download the official Windows release binary.",
        "https://github.com/mandiant/capa/releases",
    ));
    v.push(capa);

    // ---- Cloud security ----
    // Prowler is the canonical cloud provider: AWS, Azure, GCP, Kubernetes,
    // GitHub and M365 posture checks behind one capability family.
    // NOTE: prowler requires cloud credentials at runtime; the registry only
    // tracks installation, credential presence is a future doctor check.
    let mut prowler = def(
        "prowler",
        "Prowler",
        ToolCategory::Cloud,
        "Cloud security posture assessment (AWS/Azure/GCP/K8s/GitHub/M365).",
        &[
            "cloud.posture_audit",
            "cloud.asset_discovery",
            "cloud.iam_enumeration",
            "cloud.entitlement_audit",
            "cloud.storage_audit",
            "cloud.network_audit",
            "kubernetes.security",
        ],
        &["prowler"],
        &["--version"],
        "https://github.com/prowler-cloud/prowler",
        adapter("prowler_json", false),
        78,
        // No argv on purpose: prowler has no target positional (it audits
        // the ambient cloud account from credentials) and its JSON report
        // is written to ./output files, not stdout — the executor would
        // capture nothing parseable. Stays non-executable until an
        // adapter reads the report files.
        &[],
    );
    prowler.install_macos = Some(docs(
        "Install per the official docs (pip-based install). See docs.prowler.com.",
        "https://docs.prowler.com",
    ));
    prowler.install_linux = Some(docs(
        "Install per the official docs (pip-based install). See docs.prowler.com.",
        "https://docs.prowler.com",
    ));
    prowler.install_windows = Some(docs(
        "Run via the official Docker image or WSL per the official docs.",
        "https://docs.prowler.com",
    ));
    v.push(prowler);

    // ---- Database ----
    // mysql client: config/auth audit over a compact query set. Password
    // prompts cannot hang the executor (`.output()` closes stdin, so a
    // missing password fails fast); the model supplies credentials via the
    // capability's username/password options.
    let mut mysql = def(
        "mysql",
        "MySQL client",
        ToolCategory::Database,
        "MySQL/MariaDB client for configuration and authentication audits.",
        &["database.config_audit", "database.auth_audit"],
        &["mysql"],
        &["--version"],
        "https://dev.mysql.com/downloads/mysql/",
        // Plain TSV output; a structured adapter is future work — the raw
        // result set is still useful evidence for the model.
        adapter("mysql_plain", false),
        65,
        &[
            "--host",
            "{target}",
            "--batch",
            "--execute",
            "SELECT VERSION() AS version; SHOW VARIABLES WHERE Variable_name IN ('sql_mode','skip_networking','bind_address','general_log','require_secure_transport','have_ssl','log_output'); SELECT user,host,plugin,authentication_string='' AS empty_password FROM mysql.user; SHOW GRANTS;",
        ],
    );
    mysql.option_bindings = vec![
        bind("database.config_audit", "username", "--user", false, &[]),
        bind("database.config_audit", "password", "--password", true, &[]),
        bind("database.auth_audit", "username", "--user", false, &[]),
        bind("database.auth_audit", "password", "--password", true, &[]),
    ];
    mysql.install_windows = Some(pkg(
        "scoop",
        "mysql",
        "scoop install mysql",
        true,
        "https://dev.mysql.com/downloads/mysql/",
    ));
    mysql.install_macos = Some(pkg(
        "brew",
        "mysql-client",
        "brew install mysql-client",
        true,
        "https://dev.mysql.com/downloads/mysql/",
    ));
    mysql.install_linux = Some(pkg(
        "apt",
        "mysql-client",
        "sudo apt install mysql-client",
        true,
        "https://dev.mysql.com/downloads/mysql/",
    ));
    v.push(mysql);

    // psql client: same audit intent for PostgreSQL. `-w` never prompts
    // (a password-requiring server fails fast instead of hanging); supply
    // credentials via ~/.pgpass for password-auth servers.
    let mut psql = def(
        "psql",
        "PostgreSQL client (psql)",
        ToolCategory::Database,
        "PostgreSQL client for configuration and authentication audits.",
        &["database.config_audit", "database.auth_audit"],
        &["psql"],
        &["--version"],
        "https://www.postgresql.org/download/",
        adapter("mysql_plain", false),
        64,
        &[
            "--host",
            "{target}",
            "--no-psqlrc",
            "--no-password",
            "--no-align",
            "--command",
            "SELECT version(); SELECT name,setting FROM pg_settings WHERE name IN ('ssl','password_encryption','log_connections','log_disconnections','listen_addresses','row_security'); SELECT rolname,rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles;",
        ],
    );
    psql.option_bindings = vec![
        bind(
            "database.config_audit",
            "username",
            "--username",
            false,
            &[],
        ),
        bind("database.auth_audit", "username", "--username", false, &[]),
    ];
    psql.install_windows = Some(pkg(
        "scoop",
        "postgresql",
        "scoop install postgresql",
        true,
        "https://www.postgresql.org/download/",
    ));
    psql.install_macos = Some(pkg(
        "brew",
        "libpq",
        "brew install libpq",
        true,
        "https://www.postgresql.org/download/",
    ));
    psql.install_linux = Some(pkg(
        "apt",
        "postgresql-client",
        "sudo apt install postgresql-client",
        true,
        "https://www.postgresql.org/download/",
    ));
    v.push(psql);

    // ---- Identity ----
    // PingCastle: self-contained Windows-native AD security auditor. Its
    // healthcheck covers all four identity capabilities (enumeration,
    // privilege, trust, attack paths). Report files land in the process
    // cwd; the console stream is the evidence the agent sees. `--server`
    // takes a domain or DC hostname (must be reachable over LDAP).
    let pingcastle = def(
        "pingcastle",
        "PingCastle",
        ToolCategory::Identity,
        "Active Directory security assessment (users, privileges, trusts, attack paths).",
        &[
            "identity.enumeration",
            "identity.privilege_analysis",
            "identity.trust_analysis",
            "identity.attack_path_analysis",
        ],
        &["pingcastle", "PingCastle"],
        // --help exits -1; --generate-key is a fast, side-effect-free
        // invocation that exits 0 (required by the health probe).
        &["--generate-key"],
        "https://www.pingcastle.com",
        // Console output is a live progress log; a report-file adapter is
        // future work. Raw output remains evidence.
        adapter("pingcastle_plain", false),
        75,
        &["--healthcheck", "--server", "{target}"],
    );
    v.push(pingcastle);

    // ---- Internal providers ----
    // medusa-http: raw HTTP request issuing built into the agent. This is
    // what lets the model verify business-logic findings directly (login
    // bypass, IDOR/BOLA primitives, auth checks) without an external
    // scanner. `builtin: true` — discovery reports it available without a
    // PATH probe and the runtime swaps in the HttpRequestProvider instead
    // of a CLI ProcessProvider.
    let mut medusa_http = def(
        "medusa-http",
        "Medusa HTTP",
        ToolCategory::HttpWebDiscovery,
        "Built-in raw HTTP request provider (no external tool).",
        &["http.request", "api.auth_testing", "api.bola_testing"],
        &[], // no executable: built into medusa
        &[], // no version probe needed
        "https://github.com/piyus/medusa",
        adapter("http_json", true),
        40,
        &[],
    );
    medusa_http.builtin = true;
    v.push(medusa_http);

    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_capabilities_wellformed() {
        let tools = builtin_tools();
        assert!(!tools.is_empty());
        let mut ids = HashSet::new();
        for t in &tools {
            assert!(ids.insert(t.id.clone()), "duplicate tool id {}", t.id);
            assert!(
                t.builtin || !t.executable_candidates.is_empty(),
                "{} has no executables",
                t.id
            );
            for c in &t.capabilities {
                assert!(
                    c.contains('.'),
                    "capability {} of {} must be namespaced",
                    c,
                    t.id
                );
            }
            assert!(
                t.docs_url.starts_with("https://"),
                "{} docs must be https",
                t.id
            );
        }
    }

    #[test]
    fn new_capability_bindings_have_executable_providers() {
        let tools = builtin_tools();
        let expect = [
            ("container.security", "trivy-image"),
            ("database.discovery", "nmap"),
            ("database.config_audit", "mysql"),
            ("database.config_audit", "psql"),
            ("database.auth_audit", "mysql"),
            ("database.auth_audit", "psql"),
            ("database.exposed_detection", "uncover-db"),
            ("cloud.entitlement_audit", "prowler"),
            ("identity.enumeration", "pingcastle"),
            ("identity.privilege_analysis", "pingcastle"),
            ("identity.trust_analysis", "pingcastle"),
            ("identity.attack_path_analysis", "pingcastle"),
            ("web.oob_testing", "interactsh"),
        ];
        for (cap, tool) in expect {
            let def = tools
                .iter()
                .find(|t| t.id == tool)
                .unwrap_or_else(|| panic!("tool {tool} missing"));
            assert!(
                def.capabilities.iter().any(|c| c == cap),
                "{tool} does not bind {cap}"
            );
        }
    }

    #[test]
    fn executable_providers_carry_target_slots() {
        // Providers without a {target} slot are never selectable — every
        // new executable binding must express its invocation.
        let tools = builtin_tools();
        for id in ["trivy-image", "uncover-db", "mysql", "psql", "pingcastle"] {
            let def = tools.iter().find(|t| t.id == id).unwrap();
            assert!(
                def.default_args.iter().any(|a| a.contains("{target}")),
                "{id} argv has no {{target}} slot"
            );
        }
    }

    #[test]
    fn interactsh_is_a_node_sidecar_with_action_option() {
        let tools = builtin_tools();
        let def = tools.iter().find(|t| t.id == "interactsh").unwrap();
        assert_eq!(def.executable_candidates, vec!["node".to_string()]);
        assert!(def.default_args[0].starts_with("{script:medusa-oob.mjs}"));
        assert!(def
            .option_bindings
            .iter()
            .any(|b| b.capability == "web.oob_testing" && b.option == "action"));
        assert!(def.dependencies.contains(&"interactsh-client".to_string()));
    }

    #[test]
    fn falco_is_linux_only() {
        let tools = builtin_tools();
        let falco = tools.iter().find(|t| t.id == "falco").unwrap();
        assert!(falco.platforms.iter().all(|p| *p != Platform::Windows));
        assert!(!falco.supports_current_platform() || !cfg!(target_os = "windows"));
    }
}
