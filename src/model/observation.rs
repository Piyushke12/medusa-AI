//! Structured observation data shared by parsers (Phase 5), the world model
//! (Phase 3+) and the SecurityTestRegistry (Phase 7). Pure data — parsers
//! produce it, the world model interprets it.

/// Broad classification of an observation, used for test prerequisites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationKind {
    /// A port state/service finding on a host.
    Port,
    /// A reachable HTTP(S) endpoint.
    Endpoint,
    /// A matched vulnerability/template finding.
    Vulnerability,
    /// Discovered subdomain / DNS asset.
    Subdomain,
    /// DNS record.
    Dns,
    /// TLS/certificate observation.
    Tls,
    /// Secret / credential finding.
    Secret,
    /// Static analysis (SAST) finding.
    Sast,
    /// Container / SBOM / supply-chain finding.
    Container,
    /// Cloud posture finding.
    Cloud,
    /// Generic asset / host discovery.
    Asset,
    /// Traffic/packet observation.
    Traffic,
    /// Binary / RE finding.
    Binary,
    /// API schema discovery (OpenAPI/GraphQL/REST params).
    Api,
}

/// Structured payload a parser attaches to an observation. Plain strings and
/// numbers by design: parsers never depend on world-model types, the world
/// model converts to its typed enums when applying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationDetail {
    PortDiscovered {
        host: String,
        port: u16,
        protocol: String,
        state: String,
        service: Option<String>,
        version: Option<String>,
    },
    EndpointDiscovered {
        url: String,
        status: Option<u16>,
        title: Option<String>,
        tech: Vec<String>,
    },
    VulnerabilityFound {
        template_id: String,
        name: String,
        severity: String,
        url: String,
    },
    SubdomainDiscovered {
        host: String,
        ip: Option<String>,
        source: Option<String>,
    },
    DnsRecord {
        host: String,
        record_type: String,
        values: Vec<String>,
        ttl: Option<u64>,
    },
    TlsInfo {
        host: String,
        port: Option<u16>,
        issuer: Option<String>,
        subject: Option<String>,
        not_after: Option<String>,
        san: Vec<String>,
    },
    SecretFound {
        file: String,
        line: Option<u32>,
        rule_id: String,
        secret_type: String,
        match_snippet: Option<String>,
    },
    SastFinding {
        file: String,
        line: Option<u32>,
        rule_id: String,
        severity: String,
        message: String,
    },
    ContainerFinding {
        target: String,
        severity: String,
        title: String,
        installed_version: Option<String>,
        fixed_version: Option<String>,
    },
    CloudFinding {
        check_id: String,
        severity: String,
        title: String,
        resource: Option<String>,
        region: Option<String>,
    },
    AssetDiscovered {
        asset: String,
        asset_type: String,
        source: Option<String>,
    },
    TrafficObservation {
        summary: String,
    },
    BinaryFinding {
        file: String,
        capability: String,
        description: String,
    },
    ApiSchema {
        url: String,
        method: String,
        params: Vec<String>,
        auth_required: bool,
        content_type: Option<String>,
    },
}

impl ObservationDetail {
    pub fn kind(&self) -> ObservationKind {
        match self {
            Self::PortDiscovered { .. } => ObservationKind::Port,
            Self::EndpointDiscovered { .. } => ObservationKind::Endpoint,
            Self::VulnerabilityFound { .. } => ObservationKind::Vulnerability,
            Self::SubdomainDiscovered { .. } => ObservationKind::Subdomain,
            Self::DnsRecord { .. } => ObservationKind::Dns,
            Self::TlsInfo { .. } => ObservationKind::Tls,
            Self::SecretFound { .. } => ObservationKind::Secret,
            Self::SastFinding { .. } => ObservationKind::Sast,
            Self::ContainerFinding { .. } => ObservationKind::Container,
            Self::CloudFinding { .. } => ObservationKind::Cloud,
            Self::AssetDiscovered { .. } => ObservationKind::Asset,
            Self::TrafficObservation { .. } => ObservationKind::Traffic,
            Self::BinaryFinding { .. } => ObservationKind::Binary,
            Self::ApiSchema { .. } => ObservationKind::Api,
        }
    }
}
