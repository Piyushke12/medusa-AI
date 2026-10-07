//! Scratch probe: run the internal HttpRequestProvider against live and
//! dead endpoints to verify behavior outside the agent loop.
//! `cargo run --example http_probe`

use medusa_lib::agent::http_provider::HttpRequestProvider;
use medusa_lib::agent::model::{OptionSet, OptionValue};
use medusa_lib::agent::provider::{CapabilityProvider, CapabilityRequest, ExecutionContext};
use medusa_lib::agent::StubExecutor;
use medusa_lib::model::EnvironmentState;

fn main() {
    let p = HttpRequestProvider::new();
    let exec = StubExecutor::new();
    let env = EnvironmentState::empty();
    let ctx = ExecutionContext {
        executor: &exec,
        env: &env,
    };

    let cases: Vec<(&str, &str, Vec<(&str, &str)>)> = vec![
        ("GET live server", "http://127.0.0.1:8123/", vec![]),
        ("GET live 404", "http://127.0.0.1:8123/nope", vec![]),
        (
            "POST with body",
            "http://127.0.0.1:8123/submit",
            vec![("body", "email=a@b.c&password=x")],
        ),
        (
            "POST with headers+method",
            "http://127.0.0.1:8123/api",
            vec![
                ("method", "POST"),
                ("headers", "Content-Type: application/json; X-Test: 1"),
                ("body", "{\"a\":1}"),
            ],
        ),
        ("dead port", "http://127.0.0.1:9999/", vec![]),
        ("no scheme", "127.0.0.1:8123/", vec![]),
    ];

    for (name, target, opts) in cases {
        let mut options = OptionSet::new();
        for (k, v) in opts {
            options.insert(k.to_string(), OptionValue::Str(v.to_string()));
        }
        let req = CapabilityRequest {
            capability: "http.request".into(),
            target: target.into(),
            options,
            reason: name.into(),
        };
        let result = p.execute(&req, &ctx);
        println!("--- {name} (target={target}) ---");
        println!("exit={} success={}", result.exit_code, result.success());
        if let Some(e) = &result.error {
            println!("error: {e}");
        }
        if !result.stdout.is_empty() {
            let head: String = result.stdout.chars().take(200).collect();
            println!("stdout: {head}");
        }
    }
}
