//! Integration tests — run ONLY when explicitly enabled:
//! `MEDUSA_INTEGRATION=1 cargo test --test integration`
//! They may touch the real PATH and must never fail a normal `cargo test`.

use medusa_lib::core::discovery::ToolDiscoveryService;
use medusa_lib::infra::runner::RealCommandRunner;
use medusa_lib::registry::ToolRegistry;

fn enabled() -> bool {
    std::env::var("MEDUSA_INTEGRATION").as_deref() == Ok("1")
}

#[test]
fn real_path_scan_completes_without_panic() {
    if !enabled() {
        return;
    }
    let tools = ToolRegistry::builtin();
    let runner = RealCommandRunner;
    let svc = ToolDiscoveryService::new(&runner);
    let statuses = svc.discover_all(tools.all());
    assert_eq!(statuses.len(), tools.len());
    // Invariants that must hold on ANY machine:
    for (id, st) in &statuses {
        assert_eq!(&st.tool_id, id);
        if !st.installed {
            assert!(st.executable_path.is_none());
            assert!(st.capabilities.is_empty());
        }
    }
}

#[test]
fn real_doctor_renders() {
    if !enabled() {
        return;
    }
    use medusa_lib::core::discovery::derive_capabilities;
    use medusa_lib::model::EnvironmentState;
    use medusa_lib::registry::CapabilityRegistry;
    use std::collections::HashMap;

    let tools = ToolRegistry::builtin();
    let caps = CapabilityRegistry::builtin();
    let runner = RealCommandRunner;
    let svc = ToolDiscoveryService::new(&runner);
    let statuses = svc.discover_all(tools.all());
    let tools_by_id: HashMap<String, medusa_lib::model::ToolDefinition> = tools
        .all()
        .iter()
        .map(|t| (t.id.clone(), t.clone()))
        .collect();
    let state = EnvironmentState {
        schema_version: medusa_lib::model::state::STATE_SCHEMA_VERSION,
        last_scan_unix: 0,
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        tools: statuses,
        capabilities: derive_capabilities(&Default::default(), &tools_by_id, &caps),
    };
    let report = medusa_lib::doctor::diagnose(&runner, &state, tools.len());
    let text = medusa_lib::cli::render::render_doctor(&report);
    assert!(text.contains("medusa Doctor"));
    let _ = caps;
}

/// End-to-end: the FULL agent loop with REAL tool execution against a
/// controlled local target. A scripted model makes deterministic decisions
/// (nmap service detection → httpx probe → finish); everything else —
/// policy validation, process spawning, XML/JSONL parsing, world-model
/// updates, event emission — is the production path.
///
/// ```text
/// MEDUSA_INTEGRATION=1 cargo test --test integration e2e -- --nocapture
/// ```
#[test]
fn e2e_agent_loop_with_real_tools() {
    use medusa_lib::agent::{
        AgentEvent, AgentRuntime, Decision, FinishReason, StubProvider, Target,
    };
    use medusa_lib::core::discovery::scan_environment;
    use medusa_lib::registry::CapabilityRegistry;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    if !enabled() {
        return;
    }

    // A toy HTTP server on a nmap-top-1000 port. First bindable port wins;
    // if all are taken, whatever owns them still gets scanned.
    let port = {
        let mut bound: Option<u16> = None;
        for p in [8080u16, 8000, 8888, 3000] {
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", p)) {
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        let mut s = match stream {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let mut buf = [0u8; 2048];
                        let _ = s.read(&mut buf);
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello medusa",
                        );
                    }
                });
                bound = Some(p);
                break;
            }
        }
        match bound {
            Some(p) => p,
            None => {
                eprintln!("e2e: no bindable top-1000 port, skipping");
                return;
            }
        }
    };
    eprintln!("e2e: toy HTTP server on 127.0.0.1:{port}");

    // Fresh, real environment scan (bypasses the cache).
    let tools = ToolRegistry::builtin();
    let caps = CapabilityRegistry::builtin();
    let runner = RealCommandRunner;
    let state = scan_environment(&tools, &caps, &runner);

    let have = |id: &str| {
        state
            .tools
            .get(id)
            .map(|s| s.installed && s.healthy)
            .unwrap_or(false)
    };
    if !(have("nmap") && have("httpx")) {
        eprintln!(
            "e2e: nmap + httpx required, skipping (nmap={} httpx={})",
            have("nmap"),
            have("httpx")
        );
        return;
    }

    // Deterministic decisions, real execution.
    let model = StubProvider::new(vec![
        Decision::Execute {
            capability: "network.service_detection".into(),
            target: "127.0.0.1".into(),
            options: Default::default(),
            reason: "map the local attack surface".into(),
        },
        Decision::Execute {
            capability: "http.probe".into(),
            target: format!("http://127.0.0.1:{port}"),
            options: Default::default(),
            reason: "probe the discovered web port".into(),
        },
        Decision::Finish {
            reason: "e2e complete".into(),
        },
    ]);
    let rt = AgentRuntime::new(Box::new(model), &tools, &caps, &state);

    let events = RefCell::new(Vec::new());
    let res = rt.investigate_with(Target::new("127.0.0.1"), &mut |ev| {
        events.borrow_mut().push(ev)
    });
    let events = events.into_inner();

    // The loop completed by decision, not by error.
    assert!(
        matches!(res.finish_reason, FinishReason::ModelFinished(_)),
        "unexpected finish: {:?}",
        res.finish_reason
    );

    // Both tools executed through the real process path.
    assert_eq!(res.tool_results.len(), 2, "both steps must execute");
    let nmap_res = &res.tool_results[0];
    assert!(nmap_res.success(), "nmap run failed: {:?}", nmap_res.error);
    assert_eq!(nmap_res.tool_id, "nmap");
    let httpx_res = &res.tool_results[1];
    assert_eq!(httpx_res.tool_id, "httpx");
    assert!(
        httpx_res.success(),
        "httpx run failed: {:?}",
        httpx_res.error
    );

    // Phase 5 chain: real nmap XML was parsed into observations…
    let observations: Vec<String> = events
        .iter()
        .filter_map(|ev| match ev {
            AgentEvent::ObservationAdded { summary } => Some(summary.clone()),
            _ => None,
        })
        .collect();
    assert!(
        observations
            .iter()
            .any(|o| o.contains(&format!("port {port}"))),
        "nmap must observe the toy server's port, got: {observations:?}"
    );
    // …and real httpx JSON was parsed into an endpoint observation.
    assert!(
        observations
            .iter()
            .any(|o| o.contains("HTTP 200") && o.contains("127.0.0.1")),
        "httpx must observe the HTTP 200 endpoint, got: {observations:?}"
    );

    // The full event chain fired in order.
    use AgentEvent as Ev;
    assert!(events.iter().any(|e| matches!(e, Ev::ToolStarted { .. })));
    assert!(events
        .iter()
        .any(|e| matches!(e, Ev::ToolExecuted { success: true, .. })));

    eprintln!(
        "e2e ok: {} observations, {} planned actions",
        observations.len(),
        res.planned_actions.len()
    );
}
