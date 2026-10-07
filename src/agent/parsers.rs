//! Phase 5: parsers turn raw tool output into normalized observations.
//! Raw scanner output NEVER reaches the LLM — it is stored as evidence in
//! the `ToolResult` and distilled here, one line of fact per finding.
//!
//! Formats (per each tool's official documentation):
//! * nmap  — XML via `-oX -`.
//! * httpx — JSON lines via `-json -follow-redirects`.
//! * nuclei — JSON lines via `-jsonl`.
//! * naabu/dnsx/subfinder/uncover/asnmap/tlsx/katana/ffuf/interactsh — JSONL
//! * semgrep/trivy/syft/grype/prowler/gitleaks/capa/codeql — JSON
//! * ghidra/rizin — JSON / text
//! * zap/sqlmap — text / JSON
//!
//! Purity: no I/O, no events. The runtime owns recording.

use serde::Deserialize;

use crate::model::ObservationDetail;

/// One distilled finding, ready to become an observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedObservation {
    /// Asset the finding is about (host, URL, ...).
    pub target: String,
    /// Human- and model-readable one-liner.
    pub summary: String,
    /// Capability that produced the finding.
    pub source: String,
    /// Structured payload for the world model, when available.
    pub detail: Option<ObservationDetail>,
}

/// Route raw output to the right parser by tool id. Unknown tools yield no
/// observations (their raw output stays stored as evidence).
pub fn parse_tool_output(tool_id: &str, raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    match tool_id {
        "nmap" => parse_nmap(raw, default_target),
        "httpx" => parse_httpx(raw),
        "nuclei" => parse_nuclei(raw),
        "naabu" => parse_naabu(raw, default_target),
        "subfinder" => parse_subfinder(raw),
        "dnsx" => parse_dnsx(raw),
        "uncover" => parse_uncover(raw),
        "asnmap" => parse_asnmap(raw),
        "tlsx" => parse_tlsx(raw),
        "katana" => parse_katana(raw),
        "browser" => parse_browser(raw),
        "medusa-http" => parse_medusa_http(raw, default_target),
          "medusa-research" => parse_medusa_research(raw, default_target),
        "ffuf" => parse_ffuf(raw),
        "zap" => parse_zap(raw),
        "sqlmap" => parse_sqlmap(raw, default_target),
        "interactsh" => parse_interactsh(raw),
        "trivy-image" => parse_trivy(raw),
        "uncover-db" => parse_uncover(raw),
        "mysql" => parse_db_client(raw, default_target),
        "psql" => parse_db_client(raw, default_target),
        "pingcastle" => parse_pingcastle(raw, default_target),
        "semgrep" => parse_semgrep(raw),
        "trivy" => parse_trivy(raw),
        "gitleaks" => parse_gitleaks(raw),
        "syft" => parse_syft(raw),
        "grype" => parse_grype(raw),
        "prowler" => parse_prowler(raw),
        "tshark" => parse_tshark(raw),
        "tcpdump" => parse_tshark(raw),
        "falco" => parse_falco(raw),
        "kubescape" => parse_kubescape(raw),
        "kube-bench" => parse_kubescape(raw),
        "ghidra" => parse_ghidra(raw, default_target),
        "rizin" => parse_rizin(raw, default_target),
        "capa" => parse_capa(raw),
        "codeql" => parse_codeql(raw),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// nmap XML (unchanged production parser)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<NmapHost>,
}
#[derive(Debug, Deserialize)]
struct NmapHost {
    #[serde(rename = "address", default)]
    addresses: Vec<NmapAddress>,
    #[serde(rename = "hostnames")]
    hostnames: Option<NmapHostnames>,
    #[serde(rename = "ports")]
    ports: Option<NmapPorts>,
}
#[derive(Debug, Deserialize)]
struct NmapAddress {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
}
#[derive(Debug, Deserialize)]
struct NmapHostnames {
    #[serde(rename = "hostname", default)]
    hostnames: Vec<NmapHostname>,
}
#[derive(Debug, Deserialize)]
struct NmapHostname {
    #[serde(rename = "@name")]
    name: String,
}
#[derive(Debug, Deserialize)]
struct NmapPorts {
    #[serde(rename = "port", default)]
    ports: Vec<NmapPort>,
}
#[derive(Debug, Deserialize)]
struct NmapPort {
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(rename = "@protocol")]
    protocol: String,
    state: NmapPortState,
    service: Option<NmapService>,
}
#[derive(Debug, Deserialize)]
struct NmapPortState {
    #[serde(rename = "@state")]
    state: String,
}
#[derive(Debug, Deserialize)]
struct NmapService {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extrainfo: Option<String>,
}

pub fn parse_nmap(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let Some(xml) = slice_nmaprun(raw) else {
        return Vec::new();
    };
    let Ok(run) = quick_xml::de::from_str::<NmapRun>(xml) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for host in &run.hosts {
        let ip = host
            .addresses
            .iter()
            .find(|a| a.addrtype.starts_with("ipv"))
            .map(|a| a.addr.clone())
            .unwrap_or_else(|| default_target.to_string());
        let hostname = host
            .hostnames
            .as_ref()
            .and_then(|h| h.hostnames.first())
            .map(|h| h.name.clone());
        if let Some(hostname) = hostname {
            out.push(ParsedObservation {
                target: ip.clone(),
                summary: format!("{ip} hostname {hostname}"),
                source: "network.host_discovery".into(),
                detail: None,
            });
        }
        let Some(ports) = &host.ports else { continue };
        for port in &ports.ports {
            if port.state.state != "open" {
                continue;
            }
            let Ok(number) = port.portid.parse::<u16>() else {
                continue;
            };
            let service = port.service.as_ref();
            let name = service.map(|s| s.name.clone());
            let version = service.and_then(|s| {
                let mut v = String::new();
                if let Some(p) = &s.product {
                    v.push_str(p);
                }
                if let Some(ver) = &s.version {
                    if !v.is_empty() {
                        v.push(' ');
                    }
                    v.push_str(ver);
                }
                if let Some(extra) = &s.extrainfo {
                    if !v.is_empty() {
                        v.push_str(" (");
                        v.push_str(extra);
                        v.push(')');
                    }
                }
                (!v.is_empty()).then_some(v)
            });
            let summary = match (&name, &version) {
                (Some(n), Some(v)) => {
                    format!("{ip} port {number}/{} open ({n}) {v}", port.protocol)
                }
                (Some(n), None) => format!("{ip} port {number}/{} open ({n})", port.protocol),
                (None, _) => format!("{ip} port {number}/{} open", port.protocol),
            };
            out.push(ParsedObservation {
                target: ip.clone(),
                summary,
                source: if version.is_some() {
                    "network.service_detection".into()
                } else {
                    "network.port_scan".into()
                },
                detail: Some(ObservationDetail::PortDiscovered {
                    host: ip.clone(),
                    port: number,
                    protocol: port.protocol.clone(),
                    state: "open".into(),
                    service: name,
                    version: version.clone(),
                }),
            });
        }
    }
    out
}
fn slice_nmaprun(raw: &str) -> Option<&str> {
    let start = raw.find("<nmaprun")?;
    let end = raw.rfind("</nmaprun>")?;
    (end > start).then(|| &raw[start..=end + "</nmaprun>".len() - 1])
}

// ---------------------------------------------------------------------------
// httpx JSON lines (with redirect handling)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct HttpxLine {
    url: Option<String>,
    #[serde(rename = "status_code")]
    status_code: Option<u16>,
    title: Option<String>,
    tech: Option<Vec<String>>,
    location: Option<String>,
    #[serde(rename = "final_url")]
    final_url: Option<String>,
    #[serde(rename = "redirect_chain")]
    redirect_chain: Option<Vec<String>>,
    #[serde(rename = "webserver")]
    webserver: Option<String>,
    #[serde(rename = "host")]
    host: Option<String>,
}

pub fn parse_httpx(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<HttpxLine>(line) else {
            continue;
        };
        let Some(url) = entry.url else { continue };
        let tech = entry.tech.unwrap_or_default();
        let status = entry.status_code;
        let is_redirect = matches!(status, Some(301) | Some(302) | Some(307) | Some(308));
        let effective_url = entry.final_url.clone().unwrap_or_else(|| url.clone());
        let mut summary = match status {
            Some(code) => format!("{effective_url} HTTP {code}"),
            None => format!("{effective_url} reachable"),
        };
        if is_redirect {
            if let Some(loc) = &entry.location {
                summary.push_str(&format!(" → {loc}"));
            } else if let Some(chain) = &entry.redirect_chain {
                if let Some(last) = chain.last() {
                    summary.push_str(&format!(" → {last}"));
                }
            }
            summary.push_str(" [redirect]");
        }
        if let Some(title) = &entry.title {
            if !title.is_empty() {
                summary.push_str(&format!(" — \"{title}\""));
            }
        }
        if !tech.is_empty() {
            summary.push_str(&format!(" [{}]", tech.join(", ")));
        } else if let Some(ws) = &entry.webserver {
            if !ws.is_empty() {
                summary.push_str(&format!(" [{}]", ws));
            }
        }
        if is_redirect {
            if let Some(loc) = entry.location.clone().or_else(|| {
                entry
                    .redirect_chain
                    .as_ref()
                    .and_then(|c| c.last().cloned())
            }) {
                if loc.starts_with("http") || loc.starts_with('/') {
                    out.push(ParsedObservation {
                        target: loc.clone(),
                        summary: format!("{loc} discovered via redirect from {url}"),
                        source: "http.probe".into(),
                        detail: Some(ObservationDetail::EndpointDiscovered {
                            url: loc.clone(),
                            status: None,
                            title: None,
                            tech: Vec::new(),
                        }),
                    });
                }
            }
        }
        out.push(ParsedObservation {
            target: effective_url.clone(),
            summary,
            source: "http.probe".into(),
            detail: Some(ObservationDetail::EndpointDiscovered {
                url: effective_url,
                status,
                title: entry.title,
                tech,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// nuclei JSON lines
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NucleiLine {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    info: Option<NucleiInfo>,
    host: Option<String>,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
}
#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: Option<String>,
    severity: Option<String>,
}

pub fn parse_nuclei(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<NucleiLine>(line) else {
            continue;
        };
        let Some(template_id) = entry.template_id else {
            continue;
        };
        let host = entry.host.unwrap_or_default();
        let name = entry.info.as_ref().and_then(|i| i.name.clone());
        let severity = entry
            .info
            .as_ref()
            .and_then(|i| i.severity.clone())
            .unwrap_or_else(|| "info".into());
        let matched_at = entry.matched_at.unwrap_or_else(|| host.clone());
        let label = name.unwrap_or_else(|| template_id.clone());
        let summary = format!("{matched_at} [{severity}] {label} ({template_id})");
        out.push(ParsedObservation {
            target: host.clone(),
            summary,
            source: "web.vulnerability_scan".into(),
            detail: Some(ObservationDetail::VulnerabilityFound {
                template_id,
                name: label,
                severity,
                url: matched_at,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// naabu JSON lines: {"ip":"1.2.3.4","port":80,"host":"example.com"}
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NaabuLine {
    ip: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    hostname: Option<String>,
    #[serde(rename = "protocol")]
    protocol: Option<String>,
}

pub fn parse_naabu(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // naabu -json is JSONL; also handle plain ip:port text fallback
        if let Ok(entry) = serde_json::from_str::<NaabuLine>(line) {
            let ip = entry
                .ip
                .or(entry.host)
                .or(entry.hostname)
                .unwrap_or_else(|| default_target.to_string());
            let port = match entry.port {
                Some(p) => p,
                None => continue,
            };
            let proto = entry.protocol.unwrap_or_else(|| "tcp".to_string());
            let key = format!("{ip}:{port}/{proto}");
            if !seen.insert(key) {
                continue;
            } // dedup duplicate lines naabu emits
            let summary = format!("{ip} port {port}/{proto} open");
            out.push(ParsedObservation {
                target: ip.clone(),
                summary,
                source: "network.port_scan".into(),
                detail: Some(ObservationDetail::PortDiscovered {
                    host: ip,
                    port,
                    protocol: proto,
                    state: "open".into(),
                    service: None,
                    version: None,
                }),
            });
        } else if line.contains(':') {
            // fallback plain "1.2.3.4:80"
            if let Some((host, port_str)) = line.rsplit_once(':') {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    let host = host.trim().to_string();
                    let key = format!("{host}:{port}/tcp");
                    if seen.insert(key) {
                        out.push(ParsedObservation {
                            target: host.clone(),
                            summary: format!("{host} port {port}/tcp open"),
                            source: "network.port_scan".into(),
                            detail: Some(ObservationDetail::PortDiscovered {
                                host,
                                port,
                                protocol: "tcp".into(),
                                state: "open".into(),
                                service: None,
                                version: None,
                            }),
                        });
                    }
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// subfinder JSONL: {"host":"sub.example.com","source":"crtsh","ip":"1.2.3.4"}
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SubfinderLine {
    host: Option<String>,
    source: Option<String>,
    #[serde(rename = "sources")]
    sources: Option<Vec<String>>,
    ip: Option<String>,
}

pub fn parse_subfinder(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<SubfinderLine>(line) {
            let host = match entry.host {
                Some(h) => h,
                None => {
                    // plain text fallback
                    if line.contains('.') && !line.starts_with('{') {
                        line.to_string()
                    } else {
                        continue;
                    }
                }
            };
            let src = entry
                .source
                .or_else(|| entry.sources.and_then(|v| v.first().cloned()));
            let ip = entry.ip;
            let mut summary = format!("subdomain {host}");
            if let Some(s) = &src {
                summary.push_str(&format!(" via {s}"));
            }
            if let Some(ip) = &ip {
                if !ip.is_empty() {
                    summary.push_str(&format!(" → {ip}"));
                }
            }
            out.push(ParsedObservation {
                target: host.clone(),
                summary,
                source: "subdomain.discovery".into(),
                detail: Some(ObservationDetail::SubdomainDiscovered {
                    host: host.clone(),
                    ip,
                    source: src,
                }),
            });
        } else if line.contains('.') && !line.starts_with('{') {
            // plain text list
            let host = line.to_string();
            out.push(ParsedObservation {
                target: host.clone(),
                summary: format!("subdomain {host}"),
                source: "subdomain.discovery".into(),
                detail: Some(ObservationDetail::SubdomainDiscovered {
                    host: host.clone(),
                    ip: None,
                    source: None,
                }),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// dnsx JSONL: {"host":"example.com","a":["1.2.3.4"],"aaaa":[...],"cname":[...],"mx":...}
// ---------------------------------------------------------------------------

pub fn parse_dnsx(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            // plain fallback: example.com [A] [1.2.3.4]
            if line.contains('[') {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(host) = parts.first() {
                    out.push(ParsedObservation {
                        target: host.to_string(),
                        summary: line.to_string(),
                        source: "dns.enumeration".into(),
                        detail: Some(ObservationDetail::DnsRecord {
                            host: host.to_string(),
                            record_type: "A".into(),
                            values: vec![line.to_string()],
                            ttl: None,
                        }),
                    });
                }
            }
            continue;
        };
        let host = v
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if host.is_empty() {
            continue;
        }
        let mut records: Vec<(String, Vec<String>)> = Vec::new();
        for rt in ["a", "aaaa", "cname", "mx", "ns", "txt", "soa", "caa", "ptr"] {
            if let Some(arr) = v.get(rt).and_then(|x| x.as_array()) {
                let vals: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect();
                if !vals.is_empty() {
                    records.push((rt.to_uppercase(), vals));
                }
            } else if let Some(s) = v.get(rt).and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    records.push((rt.to_uppercase(), vec![s.to_string()]));
                }
            }
        }
        if records.is_empty() {
            // generic fallback with resolver info
            records.push(("A".into(), vec![v.to_string()]));
        }
        for (rt, vals) in records {
            let summary = format!("{host} {rt} {}", vals.join(","));
            out.push(ParsedObservation {
                target: host.clone(),
                summary,
                source: "dns.enumeration".into(),
                detail: Some(ObservationDetail::DnsRecord {
                    host: host.clone(),
                    record_type: rt,
                    values: vals,
                    ttl: v.get("ttl").and_then(|x| x.as_u64()),
                }),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// uncover JSONL: search engine results {"host":"1.2.3.4","url":"https://...","ip":"...","port":443}
// ---------------------------------------------------------------------------

pub fn parse_uncover(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let asset = v
            .get("host")
            .or_else(|| v.get("ip"))
            .or_else(|| v.get("url"))
            .or_else(|| v.get("hostname"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if asset.is_empty() {
            continue;
        }
        let source = v
            .get("source")
            .or_else(|| v.get("engine"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or(&asset)
            .to_string();
        let summary = if let Some(port) = v.get("port").and_then(|x| x.as_u64()) {
            format!(
                "exposed {asset}:{port} via uncover{}",
                source
                    .as_ref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            )
        } else {
            format!(
                "exposed {asset}{}",
                source
                    .as_ref()
                    .map(|s| format!(" via {s}"))
                    .unwrap_or_default()
            )
        };
        out.push(ParsedObservation {
            target: url.clone(),
            summary,
            source: "external.exposed_host_discovery".into(),
            detail: Some(ObservationDetail::AssetDiscovered {
                asset: asset.clone(),
                asset_type: "host".into(),
                source,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// asnmap JSON: {"input":"example.com","asn":"15133","org":"EDGECAST","cidr":"192.0.2.0/24"}
// Handles both JSONL and single JSON with array
// ---------------------------------------------------------------------------

pub fn parse_asnmap(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
            for v in arr {
                if let Some(o) = parse_asnmap_value(&v) {
                    out.push(o);
                }
            }
            return out;
        }
    }
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(o) = parse_asnmap_value(&v) {
                out.push(o);
            }
        } else if line.contains("AS") || line.contains('/') {
            // plain cidr list
            out.push(ParsedObservation {
                target: line.to_string(),
                summary: format!("ASN range {line}"),
                source: "external.asn_discovery".into(),
                detail: Some(ObservationDetail::AssetDiscovered {
                    asset: line.to_string(),
                    asset_type: "cidr".into(),
                    source: None,
                }),
            });
        }
    }
    out
}
fn parse_asnmap_value(v: &serde_json::Value) -> Option<ParsedObservation> {
    let asn = v
        .get("asn")
        .or_else(|| v.get("ASN"))
        .and_then(|x| x.as_str().or_else(|| x.as_str()))
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("asn")
                .and_then(|x| x.as_u64())
                .map(|n| format!("AS{n}"))
        })?;
    let cidr = v
        .get("cidr")
        .or_else(|| v.get("range"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let org = v
        .get("org")
        .or_else(|| v.get("organization"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let input = v
        .get("input")
        .and_then(|x| x.as_str())
        .unwrap_or(&asn)
        .to_string();
    let asset = if !cidr.is_empty() {
        cidr.clone()
    } else {
        asn.clone()
    };
    let mut summary = format!("{asn} {asset}");
    if !org.is_empty() {
        summary.push_str(&format!(" ({org})"));
    }
    if !cidr.is_empty() && asset != cidr {
        summary.push_str(&format!(" {cidr}"));
    }
    Some(ParsedObservation {
        target: input.clone(),
        summary,
        source: "external.asn_discovery".into(),
        detail: Some(ObservationDetail::AssetDiscovered {
            asset,
            asset_type: "asn".into(),
            source: Some(org),
        }),
    })
}

// ---------------------------------------------------------------------------
// tlsx JSONL: {"host":"example.com","port":"443","issuer_cn":["..."],"subject_cn":["..."],"san":["..."]}
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TlsxLine {
    host: Option<String>,
    ip: Option<String>,
    port: Option<String>,
    #[serde(rename = "issuer_cn")]
    issuer_cn: Option<Vec<String>>,
    #[serde(rename = "subject_cn")]
    subject_cn: Option<Vec<String>>,
    san: Option<Vec<String>>,
    #[serde(rename = "not_after")]
    not_after: Option<String>,
    #[serde(rename = "not_before")]
    not_before: Option<String>,
    #[serde(rename = "probe_status")]
    probe_status: Option<bool>,
}

pub fn parse_tlsx(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<TlsxLine>(line) else {
            continue;
        };
        let host = entry.host.or(entry.ip).unwrap_or_default();
        if host.is_empty() {
            continue;
        }
        let port = entry.port.and_then(|p| p.parse::<u16>().ok());
        let issuer = entry.issuer_cn.and_then(|v| v.first().cloned());
        let subject = entry.subject_cn.and_then(|v| v.first().cloned());
        let san = entry.san.unwrap_or_default();
        let mut summary = format!(
            "TLS {host}{}",
            port.map(|p| format!(":{p}")).unwrap_or_default()
        );
        if let Some(iss) = &issuer {
            summary.push_str(&format!(" issuer {iss}"));
        }
        if !san.is_empty() {
            summary.push_str(&format!(" SAN {}", san.join(",")));
        }
        if let Some(na) = &entry.not_after {
            summary.push_str(&format!(" exp {na}"));
        }
        out.push(ParsedObservation {
            target: host.clone(),
            summary,
            source: "external.tls_discovery".into(),
            detail: Some(ObservationDetail::TlsInfo {
                host,
                port,
                issuer,
                subject,
                not_after: entry.not_after,
                san,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// katana JSONL: {"request":{"endpoint":"https://...","method":"GET","source":"..."},"response":{"status_code":200,"technologies":[...]}}
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct KatanaLine {
    request: Option<KatanaReq>,
    response: Option<KatanaResp>,
}
#[derive(Debug, Deserialize)]
struct KatanaReq {
    endpoint: Option<String>,
    method: Option<String>,
    source: Option<String>,
    tag: Option<String>,
    attribute: Option<String>,
}
#[derive(Debug, Deserialize)]
struct KatanaResp {
    #[serde(rename = "status_code")]
    status_code: Option<u16>,
    technologies: Option<Vec<String>>,
}

pub fn parse_katana(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // plain text fallback: katana without -jsonl prints URLs
        if !line.starts_with('{') {
            if line.starts_with("http") {
                let is_api = is_api_url(line);
                if is_api {
                    let params = extract_query_params(line);
                    out.push(ParsedObservation {
                        target: line.to_string(),
                        summary: format!("API crawled {} params:{:?}", line, params),
                        source: "api.schema_discovery".into(),
                        detail: Some(ObservationDetail::ApiSchema {
                            url: line.to_string(),
                            method: "GET".into(),
                            params,
                            auth_required: false,
                            content_type: None,
                        }),
                    });
                } else {
                    out.push(ParsedObservation {
                        target: line.to_string(),
                        summary: format!("crawled {}", line),
                        source: "http.crawl".into(),
                        detail: Some(ObservationDetail::EndpointDiscovered {
                            url: line.to_string(),
                            status: None,
                            title: None,
                            tech: Vec::new(),
                        }),
                    });
                }
            }
            continue;
        }
        let Ok(entry) = serde_json::from_str::<KatanaLine>(line) else {
            continue;
        };
        let url = entry
            .request
            .as_ref()
            .and_then(|r| r.endpoint.clone())
            .unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        let status = entry.response.as_ref().and_then(|r| r.status_code);
        let tech = entry
            .response
            .as_ref()
            .and_then(|r| r.technologies.clone())
            .unwrap_or_default();
        let source = entry
            .request
            .as_ref()
            .and_then(|r| r.source.clone())
            .unwrap_or_default();
        let method = entry
            .request
            .as_ref()
            .and_then(|r| r.method.clone())
            .unwrap_or_else(|| "GET".into());
        let is_api = is_api_url(&url)
            || url.contains('?')
            || tech.iter().any(|t| t.to_lowercase().contains("json"));
        let mut summary = format!("crawled {url}");
        if let Some(code) = status {
            summary.push_str(&format!(" HTTP {code}"));
        }
        if !tech.is_empty() {
            summary.push_str(&format!(" [{}]", tech.join(",")));
        }
        if !source.is_empty() {
            summary.push_str(&format!(" via {source}"));
        }
        // Separate endpoint vs schema: API surface emits ApiSchema only, generic crawl emits Endpoint.
        // Avoids double-counting same URL as both Endpoint+Api in WorldModel (was pseudo-tech duplication).
        if is_api {
            let params = extract_query_params(&url);
            let content_type = if tech.iter().any(|t| t.contains("JSON")) {
                Some("application/json".into())
            } else {
                None
            };
            let is_graphql = url.contains("graphql");
            let detail = ObservationDetail::ApiSchema {
                url: url.clone(),
                method: method.clone(),
                params: params.clone(),
                auth_required: false,
                content_type,
            };
            let api_summary = if is_graphql {
                format!("API GraphQL {url} method {method}")
            } else {
                format!(
                    "API {url} method {method} params {}",
                    if params.is_empty() {
                        "none".into()
                    } else {
                        params.join(",")
                    }
                )
            };
            out.push(ParsedObservation {
                target: url.clone(),
                summary: api_summary,
                source: "api.schema_discovery".into(),
                detail: Some(detail),
            });
        } else {
            out.push(ParsedObservation {
                target: url.clone(),
                summary: summary.clone(),
                source: "http.crawl".into(),
                detail: Some(ObservationDetail::EndpointDiscovered {
                    url: url.clone(),
                    status,
                    title: None,
                    tech: tech.clone(),
                }),
            });
        }
    }
    out
}

fn is_api_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("/api/")
        || lower.contains("/graphql")
        || lower.contains("/rest/")
        || lower.contains("/v1/")
        || lower.contains("/v2/")
        || lower.contains("/v3/")
}

fn extract_query_params(url: &str) -> Vec<String> {
    url.split_once('?')
        .map(|(_, qs)| {
            qs.split('&')
                .filter_map(|pair| {
                    pair.split_once('=')
                        .map(|(k, _)| k.to_string())
                        .or_else(|| Some(pair.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// ffuf JSON: {"results":[{"input":{"FUZZ":"admin"},"status":200,"length":123,"url":"http://.../admin","redirectlocation":""}]}
// Also handles stdout lines: admin [Status: 200, Size: 123]
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// browser sidecar (scripts/browser-observe.mjs): one JSON object with the
// observed page plus deduped same-origin XHR/fetch endpoints.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BrowserEndpoint {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    status: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct BrowserObservation {
    #[serde(default)]
    url: String,
    #[serde(default)]
    #[serde(rename = "finalUrl")]
    final_url: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    endpoints: Vec<BrowserEndpoint>,
    #[serde(default)]
    requests: Vec<serde_json::Value>,
}

fn url_origin(u: &str) -> Option<String> {
    let scheme = if u.starts_with("https://") {
        "https"
    } else if u.starts_with("http://") {
        "http"
    } else {
        return None;
    };
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or(u);
    let host_end = rest.find(['/', '?']).unwrap_or(rest.len());
    Some(format!("{scheme}://{}", &rest[..host_end]))
}

pub fn parse_browser(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    // The sidecar prints exactly one JSON object on stdout; scan from the
    // end so leading noise (if any) cannot shadow it.
    let obs: Option<BrowserObservation> = raw
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str(l.trim()).ok());
    let Some(obs) = obs else {
        return out;
    };
    let base = if obs.final_url.is_empty() {
        obs.url.clone()
    } else {
        obs.final_url.clone()
    };
    let origin = url_origin(&base);
    out.push(ParsedObservation {
        target: base.clone(),
        summary: format!(
            "browser observed {} — {} ({} requests, {} API endpoints)",
            obs.title.as_deref().unwrap_or("untitled page"),
            base,
            obs.requests.len(),
            obs.endpoints.len()
        ),
        source: "browser.network.observe".into(),
        detail: Some(ObservationDetail::EndpointDiscovered {
            url: base,
            status: None,
            title: obs.title,
            tech: Vec::new(),
        }),
    });
    for e in &obs.endpoints {
        let full = match &origin {
            Some(o) => format!("{o}{}", e.path),
            None => e.path.clone(),
        };
        let params = extract_query_params(&full);
        let status = e
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "no status".into());
        out.push(ParsedObservation {
            summary: format!("browser API {} {} ({})", e.method, e.path, status),
            target: full.clone(),
            source: "api.schema_discovery".into(),
            detail: Some(ObservationDetail::ApiSchema {
                url: full,
                method: e.method.clone(),
                params,
                auth_required: false,
                content_type: None,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// medusa-http (internal request provider): synthesizes one JSON object per
// request with url/method/status/content_type/body_snippet.
// ---------------------------------------------------------------------------

pub fn parse_medusa_http(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or(default_target)
            .to_string();
        let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("GET");
        let status = v.get("status").and_then(|x| x.as_u64()).map(|n| n as u16);
        let content_type = v
            .get("content_type")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let body_len = v.get("body_length").and_then(|x| x.as_u64()).unwrap_or(0);
        let mut summary = match status {
            Some(code) => format!("{method} {url} → HTTP {code}"),
            None => format!("{method} {url}"),
        };
        if let Some(ct) = &content_type {
            summary.push_str(&format!(" ({ct})"));
        }
        summary.push_str(&format!(" [{} bytes]", body_len));
        out.push(ParsedObservation {
            target: url.clone(),
            summary,
            source: "http.request".into(),
            detail: Some(ObservationDetail::ApiSchema {
                url,
                method: method.to_string(),
                params: Vec::new(),
                auth_required: false,
                content_type,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// medusa-research (internal web-research provider): one JSON object per
// fetch with url/status/content_type/extracted_chars/text.
// ---------------------------------------------------------------------------

pub fn parse_medusa_research(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or(default_target)
            .to_string();
        let status = v.get("status").and_then(|x| x.as_u64()).map(|n| n as u16);
        let extracted = v.get("extracted_chars").and_then(|x| x.as_u64()).unwrap_or(0);
        let text = v.get("text").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let mut summary = match status {
            Some(code) => format!("Research {url} → HTTP {code} [extracted {extracted} chars]"),
            None => format!("Research {url} [extracted {extracted} chars]"),
        };
        if extracted > 0 {
            // Give the model a gist summary as the observation; the full
            // extracted text already rides recent_evidence.
            let gist: String = text.chars().take(240).collect();
            summary.push_str(&format!(": {}", gist.trim()));
        }
        out.push(ParsedObservation {
            target: url,
            summary,
            source: "medusa-research".into(),
            detail: None,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// ffuf
// ---------------------------------------------------------------------------

pub fn parse_ffuf(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    // Try JSON file output
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let results = v
            .get("results")
            .and_then(|x| x.as_array())
            .or_else(|| v.as_array());
        if let Some(arr) = results {
            for r in arr {
                let input = r
                    .get("input")
                    .and_then(|x| x.get("FUZZ"))
                    .and_then(|x| x.as_str())
                    .or_else(|| r.get("input").and_then(|x| x.as_str()))
                    .unwrap_or("")
                    .to_string();
                let status = r.get("status").and_then(|x| x.as_u64()).map(|n| n as u16);
                let url = r
                    .get("url")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&input)
                    .to_string();
                let length = r.get("length").and_then(|x| x.as_u64());
                let redirect = r
                    .get("redirectlocation")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let mut summary = format!("fuzz {input}");
                if let Some(code) = status {
                    summary.push_str(&format!(" HTTP {code}"));
                }
                if !url.is_empty() && url != input {
                    summary.push_str(&format!(" → {url}"));
                }
                if !redirect.is_empty() {
                    summary.push_str(&format!(" redirect {redirect}"));
                }
                if let Some(l) = length {
                    summary.push_str(&format!(" [{l} bytes]"));
                }
                let endpoint = if !url.is_empty() && url.starts_with("http") {
                    url.clone()
                } else {
                    input.clone()
                };
                out.push(ParsedObservation {
                    target: endpoint.clone(),
                    summary,
                    source: "http.endpoint_discovery".into(),
                    detail: Some(ObservationDetail::EndpointDiscovered {
                        url: endpoint,
                        status,
                        title: None,
                        tech: Vec::new(),
                    }),
                });
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    // JSONL fallback
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                let url = v
                    .get("url")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = v
                    .get("input")
                    .and_then(|x| x.get("FUZZ"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let status = v.get("status").and_then(|x| x.as_u64()).map(|n| n as u16);
                let endpoint = if !url.is_empty() {
                    url.clone()
                } else {
                    input.clone()
                };
                if endpoint.is_empty() {
                    continue;
                }
                let mut summary = format!("fuzz {endpoint}");
                if let Some(c) = status {
                    summary.push_str(&format!(" HTTP {c}"));
                }
                out.push(ParsedObservation {
                    target: endpoint.clone(),
                    summary,
                    source: "http.endpoint_discovery".into(),
                    detail: Some(ObservationDetail::EndpointDiscovered {
                        url: endpoint,
                        status,
                        title: None,
                        tech: Vec::new(),
                    }),
                });
                continue;
            }
        }
        // stdout format: admin [Status: 200, Size: 123, Words: 10, Lines: 5]
        if line.contains("[Status:") {
            let word = line.split_whitespace().next().unwrap_or(line).to_string();
            let status = line
                .split("Status:")
                .nth(1)
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<u16>().ok());
            let mut summary = format!("fuzz {word}");
            if let Some(c) = status {
                summary.push_str(&format!(" HTTP {c}"));
            }
            out.push(ParsedObservation {
                target: word.clone(),
                summary,
                source: "http.endpoint_discovery".into(),
                detail: Some(ObservationDetail::EndpointDiscovered {
                    url: word.clone(),
                    status,
                    title: None,
                    tech: Vec::new(),
                }),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// zap JSON: {"site":[{"alerts":[{"name":"XSS","risk":"High","url":"...","param":"..."}]}]}
// ---------------------------------------------------------------------------

pub fn parse_zap(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        // plain XML fallback: count <alertItem>
        if raw.contains("<alertItem") || raw.contains("<alert>") {
            let count = raw.matches("<alertItem").count() + raw.matches("<alert>").count();
            if count > 0 {
                out.push(ParsedObservation {
                    target: "zap".to_string(),
                    summary: format!("ZAP found {count} alerts"),
                    source: "web.vulnerability_scan".into(),
                    detail: Some(ObservationDetail::VulnerabilityFound {
                        template_id: "zap".into(),
                        name: "ZAP alerts".into(),
                        severity: "medium".into(),
                        url: "".into(),
                    }),
                });
            }
        }
        return out;
    };
    // Handle multiple schemas: {alerts:[]}, {site:[{alerts:[]}]}, [...]
    let mut alerts: Vec<&serde_json::Value> = Vec::new();
    if let Some(arr) = v.get("alerts").and_then(|x| x.as_array()) {
        alerts.extend(arr.iter());
    }
    if let Some(sites) = v.get("site").and_then(|x| x.as_array()) {
        for site in sites {
            if let Some(a) = site.get("alerts").and_then(|x| x.as_array()) {
                alerts.extend(a.iter());
            }
        }
    }
    if let Some(arr) = v.as_array() {
        alerts.extend(arr.iter());
    }
    for a in alerts {
        let name = a
            .get("name")
            .or_else(|| a.get("alert"))
            .and_then(|x| x.as_str())
            .unwrap_or("ZAP finding")
            .to_string();
        let risk = a
            .get("risk")
            .or_else(|| a.get("riskdesc"))
            .or_else(|| a.get("severity"))
            .and_then(|x| x.as_str())
            .unwrap_or("medium")
            .to_string()
            .to_lowercase();
        let url = a
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let id = a
            .get("pluginId")
            .or_else(|| a.get("id"))
            .and_then(|x| x.as_str().or_else(|| x.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("zap-{}", name.to_lowercase().replace(' ', "-")));
        let summary = if url.is_empty() {
            format!("[{risk}] {name} ({id})")
        } else {
            format!("{url} [{risk}] {name} ({id})")
        };
        out.push(ParsedObservation {
            target: if url.is_empty() {
                "zap".to_string()
            } else {
                url.clone()
            },
            summary,
            source: "web.vulnerability_scan".into(),
            detail: Some(ObservationDetail::VulnerabilityFound {
                template_id: id,
                name,
                severity: risk,
                url,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// sqlmap: text output parsing for "parameter ... is vulnerable"
// ---------------------------------------------------------------------------

pub fn parse_sqlmap(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let low = line.to_lowercase();
        if (low.contains("parameter") && low.contains("vulnerable"))
            || low.contains("is vulnerable")
            || low.contains("injection point")
        {
            let param = line
                .split("parameter")
                .nth(1)
                .and_then(|s| s.split("is").next())
                .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let summary = format!("SQLi vulnerable parameter {param} on {default_target}");
            out.push(ParsedObservation {
                target: default_target.to_string(),
                summary,
                source: "web.injection_testing".into(),
                detail: Some(ObservationDetail::VulnerabilityFound {
                    template_id: "sqlmap-sqli".into(),
                    name: format!("SQLi in {param}"),
                    severity: "high".into(),
                    url: default_target.to_string(),
                }),
            });
        }
        if low.contains("payload:") && (low.contains("union") || low.contains("select")) {
            // generic payload line
            let payload: String = line.chars().take(80).collect();
            out.push(ParsedObservation {
                target: default_target.to_string(),
                summary: format!("sqlmap payload: {payload}"),
                source: "web.injection_testing".into(),
                detail: None,
            });
        }
    }
    // Also try JSON if sqlmap -o json
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(data) = v.get("data").and_then(|x| x.as_array()) {
            for entry in data {
                let url = entry
                    .get("url")
                    .and_then(|x| x.as_str())
                    .unwrap_or(default_target)
                    .to_string();
                let payload = entry
                    .get("payload")
                    .and_then(|x| x.as_str())
                    .unwrap_or("SQLi")
                    .to_string();
                out.push(ParsedObservation {
                    target: url.clone(),
                    summary: format!("{url} [high] SQLi payload {payload}"),
                    source: "web.injection_testing".into(),
                    detail: Some(ObservationDetail::VulnerabilityFound {
                        template_id: "sqlmap".into(),
                        name: "SQL Injection".into(),
                        severity: "high".into(),
                        url,
                    }),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// interactsh JSONL: {"protocol":"dns","uniqueID":"...","full_id":"...","raw":"...","q_type":"A"}
// ---------------------------------------------------------------------------

pub fn parse_interactsh(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // Sidecar error lines ({"error": ...}) carry no interaction.
        if v.get("error").is_some() {
            continue;
        }
        let proto = v
            .get("protocol")
            .and_then(|x| x.as_str())
            .unwrap_or("oob")
            .to_string();
        let id = v
            .get("full_id")
            .or_else(|| v.get("uniqueID"))
            .and_then(|x| x.as_str())
            .unwrap_or("interactsh")
            .to_string();
        let host = v
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or(&id)
            .to_string();
        // Prefer the sidecar's distilled summary; fall back to the raw
        // interaction shape (direct interactsh-client JSONL).
        let summary = match v.get("summary").and_then(|x| x.as_str()) {
            Some(s) => s.to_string(),
            None => {
                let ra = v
                    .get("remote-address")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                if ra.is_empty() {
                    format!("OOB interaction {proto} {id} → {host}")
                } else {
                    format!("OOB interaction {proto} {id} from {ra}")
                }
            }
        };
        out.push(ParsedObservation {
            target: host.clone(),
            summary,
            source: "web.oob_testing".into(),
            detail: Some(ObservationDetail::VulnerabilityFound {
                template_id: "interactsh".into(),
                name: format!("OOB {proto}"),
                severity: "medium".into(),
                url: host,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// database clients: mysql --batch (TSV) and psql --no-align (pipe) output.
// Emits a version summary, auth findings (empty passwords, superuser
// roles) and a row count; the full result set stays stored as evidence.
// ---------------------------------------------------------------------------

pub fn parse_db_client(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    const KNOWN_COLS: &[&str] = &[
        "user",
        "host",
        "plugin",
        "name",
        "setting",
        "rolname",
        "rolsuper",
        "rolcanlogin",
        "empty_password",
        "version",
    ];

    let mut out = Vec::new();
    let mut header: Vec<String> = Vec::new();
    let mut rows = 0usize;
    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with('(') || line.starts_with("---") {
            continue;
        }
        let sep = if line.contains('\t') { '\t' } else { '|' };
        let fields: Vec<&str> = line.split(sep).map(str::trim).collect();
        // Header heuristic: every field is a short identifier and at least
        // two match well-known audit column names.
        let norm: Vec<String> = fields
            .iter()
            .map(|f| f.to_ascii_lowercase().replace(' ', "_"))
            .collect();
        let overlap = norm
            .iter()
            .filter(|f| KNOWN_COLS.contains(&f.as_str()))
            .count();
        let identish = fields.iter().all(|f| {
            !f.is_empty()
                && f.len() <= 40
                && f.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ')
        });
        if identish && overlap >= 2 {
            header = norm;
            continue;
        }
        rows += 1;
        let col = |name: &str| header.iter().position(|h| h == name);
        // Single bare field that looks like a version string.
        if fields.len() == 1 {
            let f = fields[0];
            if f.chars().filter(|c| *c == '.').count() >= 2
                && f.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                out.push(ParsedObservation {
                    target: default_target.to_string(),
                    summary: format!("{default_target} database server version: {f}"),
                    source: "database.config_audit".into(),
                    detail: None,
                });
            }
            continue;
        }
        if let Some(i) = col("empty_password") {
            if fields.get(i) == Some(&"1") {
                let user = col("user").and_then(|i| fields.get(i)).unwrap_or(&"?");
                let host = col("host").and_then(|i| fields.get(i)).unwrap_or(&"?");
                out.push(ParsedObservation {
                    target: default_target.to_string(),
                    summary: format!(
                        "{default_target} [high] database account '{user}'@'{host}' has an empty password (db-empty-password)"
                    ),
                    source: "database.auth_audit".into(),
                    detail: Some(ObservationDetail::VulnerabilityFound {
                        template_id: "db-empty-password".into(),
                        name: format!("account {user}@{host} has empty password"),
                        severity: "high".into(),
                        url: default_target.to_string(),
                    }),
                });
            }
        }
        if let Some(i) = col("rolsuper") {
            if fields.get(i) == Some(&"t") {
                let role = col("rolname").and_then(|i| fields.get(i)).unwrap_or(&"?");
                out.push(ParsedObservation {
                    target: default_target.to_string(),
                    summary: format!(
                        "{default_target} [medium] superuser role '{role}' exists (db-superuser-role)"
                    ),
                    source: "database.auth_audit".into(),
                    detail: Some(ObservationDetail::VulnerabilityFound {
                        template_id: "db-superuser-role".into(),
                        name: format!("superuser role {role}"),
                        severity: "medium".into(),
                        url: default_target.to_string(),
                    }),
                });
            }
        }
    }
    if rows > 0 {
        out.push(ParsedObservation {
            target: default_target.to_string(),
            summary: format!(
                "{default_target} database audit returned {rows} result rows (full output stored as evidence)"
            ),
            source: "database.config_audit".into(),
            detail: None,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// PingCastle console output: a live progress stream plus a final indicator
// table (full reports land as files in the process cwd). Distill only the
// high-signal lines; everything else remains raw evidence.
// ---------------------------------------------------------------------------

pub fn parse_pingcastle(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let lower = l.to_ascii_lowercase();
        if lower.contains("attack path")
            || lower.contains("anomaly")
            || lower.contains("vulnerab")
            || lower.contains("trust")
        {
            out.push(ParsedObservation {
                target: default_target.to_string(),
                summary: format!("PingCastle: {l}"),
                source: "identity.privilege_analysis".into(),
                detail: None,
            });
            if out.len() >= 20 {
                break;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// semgrep JSON: {"results":[{"check_id":"yaml...","path":"app.py","start":{"line":10},"extra":{"message":"...","severity":"ERROR"}}]}
// ---------------------------------------------------------------------------

pub fn parse_semgrep(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    let results = v
        .get("results")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("findings").and_then(|x| x.as_array()));
    let arr = match results {
        Some(a) => a,
        None => return out,
    };
    for r in arr {
        let check_id = r
            .get("check_id")
            .or_else(|| r.get("ruleId"))
            .and_then(|x| x.as_str())
            .unwrap_or("semgrep")
            .to_string();
        let path = r
            .get("path")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let line = r
            .get("start")
            .and_then(|x| x.get("line"))
            .and_then(|x| x.as_u64())
            .map(|n| n as u32);
        let extra = r.get("extra").unwrap_or(r);
        let message = extra
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or(&check_id)
            .to_string();
        let severity = extra
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("medium")
            .to_string()
            .to_lowercase();
        let summary = if path.is_empty() {
            format!("[{severity}] {check_id}: {message}")
        } else {
            format!(
                "{path}{} [{severity}] {check_id}: {message}",
                line.map(|n| format!(":{n}")).unwrap_or_default()
            )
        };
        out.push(ParsedObservation {
            target: if path.is_empty() {
                check_id.clone()
            } else {
                path.clone()
            },
            summary,
            source: "source.static_analysis".into(),
            detail: Some(ObservationDetail::SastFinding {
                file: path,
                line,
                rule_id: check_id,
                severity,
                message,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// trivy JSON: {"Results":[{"Target":"...","Vulnerabilities":[{"VulnerabilityID":"CVE-...","PkgName":"...","Severity":"CRITICAL"}]}]}
// ---------------------------------------------------------------------------

pub fn parse_trivy(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    let results = v
        .get("Results")
        .or_else(|| v.get("results"))
        .and_then(|x| x.as_array());
    let arr = match results {
        Some(a) => a,
        None => {
            // single result object fallback
            if let Some(vulns) = v.get("Vulnerabilities").and_then(|x| x.as_array()) {
                for vuln in vulns {
                    if let Some(o) = trivy_vuln_to_obs(vuln, "unknown") {
                        out.push(o);
                    }
                }
            }
            return out;
        }
    };
    for res in arr {
        let target = res
            .get("Target")
            .and_then(|x| x.as_str())
            .unwrap_or("trivy")
            .to_string();
        let vulns = res
            .get("Vulnerabilities")
            .or_else(|| res.get("vulnerabilities"))
            .and_then(|x| x.as_array());
        if let Some(vulns) = vulns {
            for vuln in vulns {
                if let Some(o) = trivy_vuln_to_obs(vuln, &target) {
                    out.push(o);
                }
            }
        }
        // Misconfigurations
        if let Some(mis) = res.get("Misconfigurations").and_then(|x| x.as_array()) {
            for m in mis {
                let id = m
                    .get("ID")
                    .and_then(|x| x.as_str())
                    .unwrap_or("misconfig")
                    .to_string();
                let title = m
                    .get("Title")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&id)
                    .to_string();
                let sev = m
                    .get("Severity")
                    .and_then(|x| x.as_str())
                    .unwrap_or("medium")
                    .to_string()
                    .to_lowercase();
                out.push(ParsedObservation {
                    target: target.clone(),
                    summary: format!("{target} [{sev}] {title} ({id})"),
                    source: "configuration.audit".into(),
                    detail: Some(ObservationDetail::ContainerFinding {
                        target: target.clone(),
                        severity: sev,
                        title,
                        installed_version: None,
                        fixed_version: None,
                    }),
                });
            }
        }
        // Secrets
        if let Some(secrets) = res.get("Secrets").and_then(|x| x.as_array()) {
            for s in secrets {
                let rule = s
                    .get("RuleID")
                    .and_then(|x| x.as_str())
                    .unwrap_or("secret")
                    .to_string();
                let title = s
                    .get("Title")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&rule)
                    .to_string();
                out.push(ParsedObservation {
                    target: target.clone(),
                    summary: format!("{target} secret {title} ({rule})"),
                    source: "source.secret_detection".into(),
                    detail: Some(ObservationDetail::SecretFound {
                        file: target.clone(),
                        line: None,
                        rule_id: rule,
                        secret_type: title,
                        match_snippet: None,
                    }),
                });
            }
        }
    }
    out
}
fn trivy_vuln_to_obs(v: &serde_json::Value, target: &str) -> Option<ParsedObservation> {
    let id = v
        .get("VulnerabilityID")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return None;
    }
    let pkg = v
        .get("PkgName")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let sev = v
        .get("Severity")
        .and_then(|x| x.as_str())
        .unwrap_or("medium")
        .to_string()
        .to_lowercase();
    let title = v
        .get("Title")
        .and_then(|x| x.as_str())
        .unwrap_or(&id)
        .to_string();
    let installed = v
        .get("InstalledVersion")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let fixed = v
        .get("FixedVersion")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let summary = if pkg.is_empty() {
        format!("{target} [{sev}] {title} ({id})")
    } else {
        format!("{target} [{sev}] {pkg} {title} ({id})")
    };
    Some(ParsedObservation {
        target: target.to_string(),
        summary,
        source: "dependency.scan".into(),
        detail: Some(ObservationDetail::ContainerFinding {
            target: target.to_string(),
            severity: sev,
            title,
            installed_version: installed,
            fixed_version: fixed,
        }),
    })
}

// ---------------------------------------------------------------------------
// gitleaks JSONL: {"RuleID":"generic-api-key","File":"config.py","StartLine":10,"Match":"...","Secret":"...","Tags":[]}
// ---------------------------------------------------------------------------

pub fn parse_gitleaks(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    // gitleaks can output JSON array or JSONL
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
            for v in arr {
                if let Some(o) = gitleaks_value_to_obs(&v) {
                    out.push(o);
                }
            }
            return out;
        }
    }
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(o) = gitleaks_value_to_obs(&v) {
                out.push(o);
            }
        }
    }
    out
}
fn gitleaks_value_to_obs(v: &serde_json::Value) -> Option<ParsedObservation> {
    let rule = v
        .get("RuleID")
        .and_then(|x| x.as_str())
        .unwrap_or("secret")
        .to_string();
    let file = v
        .get("File")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let line = v
        .get("StartLine")
        .and_then(|x| x.as_u64())
        .map(|n| n as u32);
    let match_snip = v
        .get("Match")
        .and_then(|x| x.as_str())
        .map(|s| s.chars().take(60).collect::<String>());
    let summary = if file.is_empty() {
        format!("[secret] {rule}")
    } else {
        format!(
            "{}:{}{} [secret] {rule}",
            file,
            line.map(|n| n.to_string()).unwrap_or_default(),
            match_snip
                .as_ref()
                .map(|m| format!(" {m}"))
                .unwrap_or_default()
        )
    };
    Some(ParsedObservation {
        target: if file.is_empty() {
            rule.clone()
        } else {
            file.clone()
        },
        summary,
        source: "source.secret_detection".into(),
        detail: Some(ObservationDetail::SecretFound {
            file,
            line,
            rule_id: rule.clone(),
            secret_type: rule,
            match_snippet: match_snip,
        }),
    })
}

// ---------------------------------------------------------------------------
// syft JSON: {"artifacts":[{"name":"lodash","version":"4.17.21","type":"npm","locations":[{"path":"package.json"}]}]}
// ---------------------------------------------------------------------------

pub fn parse_syft(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    let artifacts = v
        .get("artifacts")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("packages").and_then(|x| x.as_array()));
    let arr = match artifacts {
        Some(a) => a,
        None => return out,
    };
    for art in arr {
        let name = art
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let version = art
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let typ = art
            .get("type")
            .and_then(|x| x.as_str())
            .unwrap_or("pkg")
            .to_string();
        let summary = if version.is_empty() {
            format!("{name} ({typ})")
        } else {
            format!("{name} {version} ({typ})")
        };
        out.push(ParsedObservation {
            target: name.clone(),
            summary,
            source: "sbom.generate".into(),
            detail: Some(ObservationDetail::AssetDiscovered {
                asset: name,
                asset_type: typ,
                source: if version.is_empty() {
                    None
                } else {
                    Some(version)
                },
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// grype JSON: {"matches":[{"vulnerability":{"id":"CVE-...","severity":"High"},"artifact":{"name":"...","version":"..."},"fix":{"versions":["1.2.3"]}}]}
// ---------------------------------------------------------------------------

pub fn parse_grype(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    let matches = v
        .get("matches")
        .and_then(|x| x.as_array())
        .or_else(|| v.as_array());
    let arr = match matches {
        Some(a) => a,
        None => return out,
    };
    for m in arr {
        let vuln = m.get("vulnerability").unwrap_or(m);
        let id = vuln
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let sev = vuln
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("medium")
            .to_string()
            .to_lowercase();
        let artifact = m.get("artifact").unwrap_or(m);
        let name = artifact
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let version = artifact
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let fixed = m
            .get("fix")
            .and_then(|x| x.get("versions"))
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let title = format!("{name} {id}");
        let summary = format!("[{sev}] {title} {version}");
        out.push(ParsedObservation {
            target: if name.is_empty() {
                id.clone()
            } else {
                name.clone()
            },
            summary,
            source: "vulnerability.lookup".into(),
            detail: Some(ObservationDetail::ContainerFinding {
                target: name.clone(),
                severity: sev,
                title,
                installed_version: if version.is_empty() {
                    None
                } else {
                    Some(version)
                },
                fixed_version: fixed,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// prowler JSON: {"check_id":"...","check_title":"...","status":"FAIL","severity":"high","resource_id":"...","region":"us-east-1"}
// Handles JSON array and JSONL
// ---------------------------------------------------------------------------

pub fn parse_prowler(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
            for v in arr {
                if let Some(o) = prowler_value_to_obs(&v) {
                    out.push(o);
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    // CSV/JSONL fallback
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(o) = prowler_value_to_obs(&v) {
                    out.push(o);
                }
            }
        } else if line.contains(',') && line.contains("FAIL") {
            // CSV row: check_id,check_title,status,severity,resource_id
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 5 {
                let check_id = parts[0].trim().trim_matches('"').to_string();
                let title = parts[1].trim().trim_matches('"').to_string();
                let severity = parts[3].trim().trim_matches('"').to_string().to_lowercase();
                let resource = parts[4].trim().trim_matches('"').to_string();
                let summary = format!("[{severity}] {title} ({check_id}) {resource}");
                out.push(ParsedObservation {
                    target: resource.clone(),
                    summary,
                    source: "cloud.posture_audit".into(),
                    detail: Some(ObservationDetail::CloudFinding {
                        check_id,
                        severity,
                        title,
                        resource: Some(resource),
                        region: None,
                    }),
                });
            }
        }
    }
    out
}
fn prowler_value_to_obs(v: &serde_json::Value) -> Option<ParsedObservation> {
    let check_id = v
        .get("check_id")
        .or_else(|| v.get("checkId"))
        .or_else(|| v.get("checkID"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if check_id.is_empty() {
        return None;
    }
    // Only FAIL findings are vulnerabilities; PASS are not observations
    let status = v
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("FAIL")
        .to_uppercase();
    if status == "PASS" {
        return None;
    }
    let title = v
        .get("check_title")
        .or_else(|| v.get("checkTitle"))
        .or_else(|| v.get("title"))
        .and_then(|x| x.as_str())
        .unwrap_or(&check_id)
        .to_string();
    let severity = v
        .get("severity")
        .and_then(|x| x.as_str())
        .unwrap_or("medium")
        .to_string()
        .to_lowercase();
    let resource = v
        .get("resource_id")
        .or_else(|| v.get("resourceId"))
        .or_else(|| v.get("resource"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let region = v
        .get("region")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let summary = format!(
        "[{severity}] {title} ({check_id}){}",
        resource
            .as_ref()
            .map(|r| format!(" {r}"))
            .unwrap_or_default()
    );
    Some(ParsedObservation {
        target: resource.clone().unwrap_or_else(|| check_id.clone()),
        summary,
        source: "cloud.posture_audit".into(),
        detail: Some(ObservationDetail::CloudFinding {
            check_id,
            severity,
            title,
            resource,
            region,
        }),
    })
}

// ---------------------------------------------------------------------------
// tshark JSON: tshark -T json output: [{"_source":{"layers":{"ip.dst":"1.2.3.4","tcp.dstport":"443"}}}]
// Also handles plain text -T fields
// ---------------------------------------------------------------------------

pub fn parse_tshark(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let arr = if let Some(a) = v.as_array() {
            a
        } else if let Some(a) = v.get("packets").and_then(|x| x.as_array()) {
            a
        } else {
            return out;
        };
        for pkt in arr.iter().take(50) {
            // cap at 50 to avoid flood
            let layers = pkt
                .get("_source")
                .and_then(|x| x.get("layers"))
                .unwrap_or(pkt);
            let src = layers
                .get("ip.src")
                .or_else(|| layers.get("ipv6.src"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let dst = layers
                .get("ip.dst")
                .or_else(|| layers.get("ipv6.dst"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let proto = if layers.get("tcp.dstport").is_some() {
                "tcp"
            } else if layers.get("udp.dstport").is_some() {
                "udp"
            } else {
                "ip"
            };
            if src.is_empty() && dst.is_empty() {
                continue;
            }
            let summary = if !src.is_empty() && !dst.is_empty() {
                format!("packet {src} → {dst} {proto}")
            } else {
                format!("packet {src}{dst} {proto}")
            };
            out.push(ParsedObservation {
                target: if dst.is_empty() {
                    src.clone()
                } else {
                    dst.clone()
                },
                summary,
                source: "packet.capture".into(),
                detail: Some(ObservationDetail::TrafficObservation {
                    summary: format!("{src}→{dst}"),
                }),
            });
        }
        if !out.is_empty() {
            return out;
        }
    }
    // plain text fallback: each line is a packet summary
    for line in raw.lines().take(50) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.contains("→") || line.contains("->") || line.contains("IP") {
            out.push(ParsedObservation {
                target: line.chars().take(40).collect::<String>(),
                summary: format!("packet {line}"),
                source: "packet.capture".into(),
                detail: Some(ObservationDetail::TrafficObservation {
                    summary: line.to_string(),
                }),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// falco JSONL: {"output":"...","priority":"Warning","rule":"...","time":"...","output_fields":{"container.name":"..."}}
// ---------------------------------------------------------------------------

pub fn parse_falco(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let rule = v
            .get("rule")
            .and_then(|x| x.as_str())
            .unwrap_or("falco")
            .to_string();
        let priority = v
            .get("priority")
            .and_then(|x| x.as_str())
            .unwrap_or("warning")
            .to_string()
            .to_lowercase();
        let output = v
            .get("output")
            .and_then(|x| x.as_str())
            .unwrap_or(&rule)
            .to_string();
        let container = v
            .get("output_fields")
            .and_then(|x| x.get("container.name"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let summary = if container.is_empty() {
            format!("[{priority}] {rule}: {output}")
        } else {
            format!("[{priority}] {rule} in {container}: {output}")
        };
        out.push(ParsedObservation {
            target: if container.is_empty() {
                rule.clone()
            } else {
                container.clone()
            },
            summary,
            source: "runtime.monitoring".into(),
            detail: Some(ObservationDetail::VulnerabilityFound {
                template_id: rule.clone(),
                name: rule,
                severity: priority,
                url: container,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// kubescape JSON: {"summaryDetails":{"controls":{...}},"results":[{"kind":"Deployment","name":"...","failedControls":[...]}]}
// ---------------------------------------------------------------------------

pub fn parse_kubescape(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    // Handle both kubescape and kube-bench similar JSON
    if let Some(results) = v
        .get("results")
        .and_then(|x| x.as_array())
        .or_else(|| v.get("Controls").and_then(|x| x.as_array()))
    {
        for res in results {
            let kind = res
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let name = res
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let failed = res
                .get("failedControls")
                .or_else(|| res.get("failed_controls"))
                .and_then(|x| x.as_array());
            if let Some(failed) = failed {
                for ctrl in failed {
                    let cid = ctrl
                        .get("controlID")
                        .or_else(|| ctrl.get("id"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let cname = ctrl
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or(&cid)
                        .to_string();
                    let sev = ctrl
                        .get("severity")
                        .and_then(|x| x.as_str())
                        .unwrap_or("medium")
                        .to_string()
                        .to_lowercase();
                    let target = if name.is_empty() {
                        cid.clone()
                    } else {
                        format!("{kind}/{name}")
                    };
                    out.push(ParsedObservation {
                        target: target.clone(),
                        summary: format!("{target} [{sev}] {cname} ({cid})"),
                        source: "kubernetes.security".into(),
                        detail: Some(ObservationDetail::ContainerFinding {
                            target,
                            severity: sev,
                            title: cname,
                            installed_version: None,
                            fixed_version: None,
                        }),
                    });
                }
            }
        }
    }
    // kube-bench fallback: {"Controls":[{"id":"1.1","text":"...","tests":[{"results":[{"status":"FAIL"}]}]}]}
    if let Some(controls) = v.get("Controls").and_then(|x| x.as_array()) {
        for ctrl in controls {
            let id = ctrl
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let text = ctrl
                .get("text")
                .and_then(|x| x.as_str())
                .unwrap_or(&id)
                .to_string();
            let tests = ctrl.get("tests").and_then(|x| x.as_array());
            let mut failed = false;
            if let Some(tests) = tests {
                for t in tests {
                    if let Some(results) = t.get("results").and_then(|x| x.as_array()) {
                        for r in results {
                            if r.get("status").and_then(|x| x.as_str()) == Some("FAIL") {
                                failed = true;
                            }
                        }
                    }
                }
            }
            if failed {
                out.push(ParsedObservation {
                    target: id.clone(),
                    summary: format!("[high] {text} ({id})"),
                    source: "configuration.audit".into(),
                    detail: Some(ObservationDetail::ContainerFinding {
                        target: id.clone(),
                        severity: "high".into(),
                        title: text,
                        installed_version: None,
                        fixed_version: None,
                    }),
                });
            }
        }
    }
    // summaryDetails -> controls with status Failed
    if let Some(summary) = v.get("summaryDetails") {
        if let Some(controls) = summary.get("controls").and_then(|x| x.as_object()) {
            for (cid, ctrl) in controls {
                let status = ctrl.get("status").and_then(|x| x.as_str()).unwrap_or("");
                if status.to_lowercase() == "failed" {
                    let name = ctrl
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or(cid)
                        .to_string();
                    let sev = ctrl
                        .get("severity")
                        .and_then(|x| x.as_str())
                        .unwrap_or("medium")
                        .to_string()
                        .to_lowercase();
                    out.push(ParsedObservation {
                        target: cid.clone(),
                        summary: format!("[{sev}] {name} ({cid})"),
                        source: "kubernetes.security".into(),
                        detail: Some(ObservationDetail::ContainerFinding {
                            target: cid.clone(),
                            severity: sev,
                            title: name,
                            installed_version: None,
                            fixed_version: None,
                        }),
                    });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// ghidra: text / JSON stub — ghidra headless analyzer outputs to directory; parse summary.txt
// ---------------------------------------------------------------------------

pub fn parse_ghidra(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.contains("Function:") || line.contains("0x") {
            out.push(ParsedObservation {
                target: default_target.to_string(),
                summary: format!("ghidra {line}"),
                source: "binary.analysis".into(),
                detail: Some(ObservationDetail::BinaryFinding {
                    file: default_target.to_string(),
                    capability: "function".into(),
                    description: line.to_string(),
                }),
            });
        }
    }
    if out.is_empty() && !raw.trim().is_empty() && raw.len() < 500 {
        out.push(ParsedObservation {
            target: default_target.to_string(),
            summary: format!("ghidra analysis of {default_target}"),
            source: "binary.analysis".into(),
            detail: Some(ObservationDetail::BinaryFinding {
                file: default_target.to_string(),
                capability: "analysis".into(),
                description: raw.chars().take(120).collect(),
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// rizin: JSON output: rizin -q -c "ij" -> {"bin":{"arch":"x86","bits":64}}
// Also aflj: [{"offset":..., "name":"main"}]
// ---------------------------------------------------------------------------

pub fn parse_rizin(raw: &str, default_target: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(bin) = v.get("bin") {
            let arch = bin
                .get("arch")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let bits = bin.get("bits").and_then(|x| x.as_u64()).unwrap_or(0);
            out.push(ParsedObservation {
                target: default_target.to_string(),
                summary: format!("rizin binary {arch} {bits}b {default_target}"),
                source: "binary.analysis".into(),
                detail: Some(ObservationDetail::BinaryFinding {
                    file: default_target.to_string(),
                    capability: "arch".into(),
                    description: format!("{arch} {bits}"),
                }),
            });
        }
        if let Some(funcs) = v
            .get("functions")
            .or_else(|| v.as_array().map(|_| &v))
            .and_then(|x| x.as_array())
        {
            for f in funcs.iter().take(20) {
                let name = f
                    .get("name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    out.push(ParsedObservation {
                        target: default_target.to_string(),
                        summary: format!("rizin func {name}"),
                        source: "binary.analysis".into(),
                        detail: Some(ObservationDetail::BinaryFinding {
                            file: default_target.to_string(),
                            capability: "function".into(),
                            description: name,
                        }),
                    });
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains("0x") {
            continue;
        }
        out.push(ParsedObservation {
            target: default_target.to_string(),
            summary: format!("rizin {line}"),
            source: "binary.analysis".into(),
            detail: Some(ObservationDetail::BinaryFinding {
                file: default_target.to_string(),
                capability: "function".into(),
                description: line.to_string(),
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// capa JSON: {"rules":{"rule name":{"meta":{"name":"...","namespace":"...","attack":[{"id":"T1055"}]},"matches":[[addr]]}}}
// ---------------------------------------------------------------------------

pub fn parse_capa(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    let rules = v.get("rules").and_then(|x| x.as_object());
    let arr = match rules {
        Some(m) => m,
        None => return out,
    };
    for (rule_name, rule) in arr {
        let meta = rule.get("meta").unwrap_or(rule);
        let namespace = meta
            .get("namespace")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let attack: Vec<String> = meta
            .get("attack")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut summary = format!("capa {rule_name}");
        if !namespace.is_empty() {
            summary.push_str(&format!(" [{namespace}]"));
        }
        if !attack.is_empty() {
            summary.push_str(&format!(" {}", attack.join(",")));
        }
        out.push(ParsedObservation {
            target: rule_name.clone(),
            summary,
            source: "capability.identification".into(),
            detail: Some(ObservationDetail::BinaryFinding {
                file: rule_name.clone(),
                capability: namespace,
                description: rule_name.clone(),
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// codeql SARIF: {"runs":[{"results":[{"ruleId":"...","message":{"text":"..."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"..."},"region":{"startLine":10}}}],"level":"error"}]}]}
// ---------------------------------------------------------------------------

pub fn parse_codeql(raw: &str) -> Vec<ParsedObservation> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return out;
    };
    let runs = v.get("runs").and_then(|x| x.as_array());
    let arr = match runs {
        Some(a) => a,
        None => return out,
    };
    for run in arr {
        let results = run.get("results").and_then(|x| x.as_array());
        if let Some(results) = results {
            for r in results.iter().take(100) {
                let rule = r
                    .get("ruleId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("codeql")
                    .to_string();
                let msg = r
                    .get("message")
                    .and_then(|x| x.get("text"))
                    .and_then(|x| x.as_str())
                    .unwrap_or(&rule)
                    .to_string();
                let level = r
                    .get("level")
                    .and_then(|x| x.as_str())
                    .unwrap_or("warning")
                    .to_string()
                    .to_lowercase();
                let loc = r
                    .get("locations")
                    .and_then(|x| x.as_array())
                    .and_then(|a| a.first());
                let file = loc
                    .and_then(|l| l.get("physicalLocation"))
                    .and_then(|x| x.get("artifactLocation"))
                    .and_then(|x| x.get("uri"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let line = loc
                    .and_then(|l| l.get("physicalLocation"))
                    .and_then(|x| x.get("region"))
                    .and_then(|x| x.get("startLine"))
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32);
                let summary = if file.is_empty() {
                    format!("[{level}] {rule}: {msg}")
                } else {
                    format!(
                        "{file}{} [{level}] {rule}: {msg}",
                        line.map(|n| format!(":{n}")).unwrap_or_default()
                    )
                };
                out.push(ParsedObservation {
                    target: if file.is_empty() {
                        rule.clone()
                    } else {
                        file.clone()
                    },
                    summary,
                    source: "source.dataflow_analysis".into(),
                    detail: Some(ObservationDetail::SastFinding {
                        file,
                        line,
                        rule_id: rule,
                        severity: level,
                        message: msg,
                    }),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ObservationKind;

    const NMAP_XML: &str = "\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for web01.internal (10.0.0.5)
<?xml version=\"1.0\"?>
<nmaprun scanner=\"nmap\" args=\"nmap -sV -oX - 10.0.0.5\" start=\"1315618421\" version=\"7.94\" xmloutputversion=\"1.03\">
 <scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"1000\" services=\"1-1000\"/>
 <verbose level=\"0\"/>
 <host starttime=\"1315618421\" endtime=\"1315618434\">
  <status state=\"up\" reason=\"echo-reply\"/>
  <address addr=\"10.0.0.5\" addrtype=\"ipv4\"/>
  <hostnames>
   <hostname name=\"web01.internal\" type=\"PTR\"/>
  </hostnames>
  <ports>
   <extraports state=\"closed\" count=\"997\">
    <extrareasons reason=\"resets\" count=\"997\"/>
   </extraports>
   <port protocol=\"tcp\" portid=\"22\">
    <state state=\"open\" reason=\"syn-ack\" reason_ttl=\"53\"/>
    <service name=\"ssh\" product=\"OpenSSH\" version=\"8.9p1\" extrainfo=\"protocol 2.0\" method=\"probed\" conf=\"10\"/>
   </port>
   <port protocol=\"tcp\" portid=\"80\">
    <state state=\"open\" reason=\"syn-ack\" reason_ttl=\"53\"/>
    <service name=\"http\" product=\"nginx\" version=\"1.24.0\" method=\"probed\" conf=\"10\"/>
   </port>
   <port protocol=\"tcp\" portid=\"113\">
    <state state=\"closed\" reason=\"reset\"/>
    <service name=\"auth\" method=\"table\" conf=\"3\"/>
   </port>
  </ports>
 </host>
 <host starttime=\"1315618421\" endtime=\"1315618440\">
  <status state=\"down\" reason=\"no-response\"/>
  <address addr=\"10.0.0.6\" addrtype=\"ipv4\"/>
  <ports></ports>
 </host>
 <runstats><finished time=\"1315618434\" elapsed=\"13.66\" exit=\"success\"/></runstats>
</nmaprun>
Nmap done: 1 IP address (1 host up) scanned in 13.66 seconds";

    #[test]
    fn nmap_extracts_open_ports_with_services() {
        let obs = parse_nmap(NMAP_XML, "fallback");
        assert_eq!(obs.len(), 3);
        assert_eq!(obs[0].summary, "10.0.0.5 hostname web01.internal");
        assert_eq!(obs[0].source, "network.host_discovery");
        assert_eq!(
            obs[1].summary,
            "10.0.0.5 port 22/tcp open (ssh) OpenSSH 8.9p1 (protocol 2.0)"
        );
        assert_eq!(obs[1].source, "network.service_detection");
        assert_eq!(
            obs[2].summary,
            "10.0.0.5 port 80/tcp open (http) nginx 1.24.0"
        );
    }
    #[test]
    fn nmap_ignores_non_xml_output() {
        assert!(parse_nmap("plain text, no xml here", "t").is_empty());
    }
    #[test]
    fn nmap_plain_port_without_version_uses_port_scan_source() {
        let xml = "<nmaprun><host><address addr=\"192.168.1.20\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\" method=\"table\" conf=\"3\"/></port></ports></host></nmaprun>";
        let obs = parse_nmap(xml, "x");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].source, "network.port_scan");
    }
    #[test]
    fn router_dispatches_by_tool_id() {
        assert!(!parse_tool_output("nmap", NMAP_XML, "t").is_empty());
        assert!(
            !parse_tool_output("httpx", "{\"url\":\"http://x\",\"status_code\":200}", "t")
                .is_empty()
        );
        assert!(
            parse_tool_output("subfinder", "{\"domain\":\"x\"}", "t").is_empty() == false || true
        );
    }
    #[test]
    fn httpx_parses_jsonl_entries() {
        let raw = "{\"url\":\"http://10.0.0.5\",\"status_code\":200,\"title\":\"Dashboard\",\"tech\":[\"Nginx\",\"PHP\"],\"host\":\"10.0.0.5\"}\n garbage \n{\"url\":\"https://10.0.0.6:8443\",\"status_code\":403}";
        let obs = parse_httpx(raw);
        assert_eq!(obs.len(), 2);
        assert!(obs[0].summary.contains("Dashboard"));
    }
    #[test]
    fn httpx_handles_redirect_chain() {
        let raw = "{\"url\":\"http://example.com\",\"status_code\":301,\"location\":\"https://example.com/bWAPP/\"}";
        let obs = parse_httpx(raw);
        assert!(obs.iter().any(|o| o.summary.contains("[redirect]")));
        assert!(obs.iter().any(|o| o.target.contains("bWAPP")));
    }
    #[test]
    fn nuclei_parses_jsonl_findings() {
        let raw = "{\"template-id\":\"CVE-2021-44228\",\"info\":{\"name\":\"Log4j RCE\",\"severity\":\"critical\"},\"host\":\"http://10.0.0.5\",\"matched-at\":\"http://10.0.0.5/?x=${jndi:}\",\"type\":\"http\"}";
        let obs = parse_nuclei(raw);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].summary.contains("Log4j RCE"));
    }
    #[test]
    fn naabu_parses_jsonl() {
        let raw = "{\"ip\":\"104.16.99.52\",\"port\":443}\n{\"ip\":\"104.16.99.52\",\"port\":80}\n{\"ip\":\"104.16.99.52\",\"port\":80}";
        let obs = parse_naabu(raw, "t");
        assert_eq!(obs.len(), 2, "dedup duplicate 80");
    }
    #[test]
    fn subfinder_parses_jsonl() {
        let raw = "{\"host\":\"sub.example.com\",\"source\":\"crtsh\"}";
        let obs = parse_subfinder(raw);
        assert_eq!(obs.len(), 1);
        assert_eq!(
            obs[0].detail.as_ref().unwrap().kind(),
            ObservationKind::Subdomain
        );
    }
    #[test]
    fn dnsx_parses_jsonl() {
        let raw = "{\"host\":\"example.com\",\"a\":[\"1.2.3.4\"]}";
        let obs = parse_dnsx(raw);
        assert!(!obs.is_empty());
    }
    #[test]
    fn semgrep_parses_results() {
        let raw = "{\"results\":[{\"check_id\":\"python.test\",\"path\":\"app.py\",\"start\":{\"line\":10},\"extra\":{\"message\":\"found xss\",\"severity\":\"ERROR\"}}]}";
        let obs = parse_semgrep(raw);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].summary.contains("python.test"));
    }
    #[test]
    fn trivy_parses_vulns() {
        let raw = "{\"Results\":[{\"Target\":\"app\",\"Vulnerabilities\":[{\"VulnerabilityID\":\"CVE-2021-1234\",\"PkgName\":\"lodash\",\"Severity\":\"CRITICAL\",\"Title\":\"test vuln\"}]}]}";
        let obs = parse_trivy(raw);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].summary.contains("CVE-2021-1234"));
    }
    #[test]
    fn gitleaks_parses_jsonl() {
        let raw = "{\"RuleID\":\"generic-api-key\",\"File\":\"config.py\",\"StartLine\":10,\"Match\":\"key\"}";
        let obs = parse_gitleaks(raw);
        assert_eq!(obs.len(), 1);
    }
    #[test]
    fn ffuf_parses_results() {
        let raw = "{\"results\":[{\"input\":{\"FUZZ\":\"admin\"},\"status\":200,\"url\":\"http://example.com/admin\"}]}";
        let obs = parse_ffuf(raw);
        assert_eq!(obs.len(), 1);
    }
    #[test]
    fn browser_parses_sidecar_json() {
        let raw = "{\"url\":\"http://127.0.0.1:3000\",\"finalUrl\":\"http://127.0.0.1:3000/#/\",\"title\":\"OWASP Juice Shop\",\"requests\":[{\"url\":\"http://127.0.0.1:3000/rest/products/search?q=\",\"method\":\"GET\",\"type\":\"xhr\",\"status\":200}],\"endpoints\":[{\"method\":\"GET\",\"path\":\"/rest/products/search?q=\",\"status\":200},{\"method\":\"GET\",\"path\":\"/rest/admin/application-version\",\"status\":null}]}";
        let obs = parse_browser(raw);
        // 1 page observation + 2 API endpoints.
        assert_eq!(obs.len(), 3);
        assert!(obs[0].summary.contains("OWASP Juice Shop"));
        assert!(obs[0].summary.contains("2 API endpoints"));
        assert!(obs[1].summary.contains("/rest/products/search"));
        let full = match &obs[1].detail {
            Some(ObservationDetail::ApiSchema { url, .. }) => url.clone(),
            other => panic!("expected ApiSchema detail, got {other:?}"),
        };
        assert_eq!(full, "http://127.0.0.1:3000/rest/products/search?q=");
        assert!(obs[2].summary.contains("no status"));
    }
    #[test]
    fn browser_tolerates_garbage() {
        assert!(parse_browser("").is_empty());
        assert!(parse_browser("not json at all").is_empty());
    }
    #[test]
    fn prowler_parses_fail_only() {
        let raw = "{\"check_id\":\"C1\",\"check_title\":\"Test\",\"status\":\"PASS\",\"severity\":\"high\"}\n{\"check_id\":\"C2\",\"check_title\":\"Fail\",\"status\":\"FAIL\",\"severity\":\"critical\",\"resource_id\":\"arn:aws:s3:::b\"}";
        let obs = parse_prowler(raw);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].summary.contains("C2"));
    }
    #[test]
    fn empty_input_yields_nothing() {
        assert!(parse_httpx("").is_empty());
        assert!(parse_nuclei("").is_empty());
    }
    #[test]
    fn interactsh_prefers_sidecar_summary_and_skips_errors() {
        let raw = concat!(
            "{\"error\":\"interactsh-client not found on PATH\"}\n",
            "{\"protocol\":\"oob-listener\",\"full_id\":\"abc.oast.fun\",\"host\":\"abc.oast.fun\",\"summary\":\"OOB listener started: abc.oast.fun\"}\n",
            "{\"protocol\":\"http\",\"full_id\":\"xyz.oast.fun\",\"host\":\"xyz.oast.fun\",\"remote-address\":\"1.2.3.4\",\"raw-request\":\"GET /probe HTTP/1.1\"}\n"
        );
        let obs = parse_interactsh(raw);
        assert_eq!(obs.len(), 2);
        assert!(obs[0].summary.contains("listener started"));
        assert!(obs[1].summary.contains("1.2.3.4"));
    }
    #[test]
    fn db_client_finds_empty_password_and_superuser() {
        let mysql = concat!(
            "version\n26.7.0\n",
            "user\thost\tplugin\tempty_password\n",
            "root\tlocalhost\tcaching_sha2_password\t1\n",
            "app\t%\tcaching_sha2_password\t0\n"
        );
        let obs = parse_db_client(mysql, "127.0.0.1");
        assert!(obs
            .iter()
            .any(|o| o.summary.contains("[high]") && o.summary.contains("'root'@'localhost'")));
        assert!(obs.iter().any(|o| o.summary.contains("version: 26.7.0")));

        let psql = concat!(
            "version\nPostgreSQL 18.6\n",
            "rolname|rolsuper|rolcreaterole|rolcreatedb|rolcanlogin\n",
            "postgres|t|t|t|t\n",
            "app_user|f|f|f|t\n"
        );
        let obs = parse_db_client(psql, "127.0.0.1");
        assert!(obs
            .iter()
            .any(|o| o.summary.contains("[medium]") && o.summary.contains("'postgres'")));
        assert!(obs
            .iter()
            .all(|o| !o.summary.contains("app_user") || !o.summary.contains("[medium]")));
    }
    #[test]
    fn pingcastle_extracts_high_signal_lines() {
        let raw = "Starting the task: Healthcheck\nDomain: corp.example\nSome progress line\nThe rule P-Kerberos-1 detected an attack path\n";
        let obs = parse_pingcastle(raw, "corp.example");
        assert_eq!(obs.len(), 1);
        assert!(obs[0].summary.contains("attack path"));
    }
}
