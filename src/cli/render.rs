//! Terminal rendering: startup screen, tables, coverage bars, doctor output.
//! Windows-safe: plain UTF-8 glyphs (✓ ✗ ! █ ░) that render in Windows
//! Terminal / VS Code; width-aware with an 80-column fallback.

use std::collections::HashMap;

use crate::core::coverage::CategoryCoverage;
use crate::doctor::{DoctorIssue, DoctorReport};
use crate::install::InstallRecommendation;
use crate::model::{EnvironmentState, ToolCategory};
use crate::registry::ToolRegistry;

fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&w| w >= 40 && w <= 240)
        .unwrap_or(80)
}

pub fn bar(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn status_line(installed: bool, name: &str, version: Option<&str>, width: usize) -> String {
    let mark = if installed { "✓" } else { "✗" };
    let ver = version.unwrap_or("not installed");
    let mut line = format!("  {mark} {name:<15} {ver}");
    if line.len() > width {
        line.truncate(width);
    }
    line
}

/// Startup environment check, grouped by tool category.
pub fn render_startup(state: &EnvironmentState, tools: &ToolRegistry) -> String {
    let mut out = String::new();
    out.push_str("medusa Environment Check\n\nDetecting security capabilities...\n");
    let width = term_width();

    let mut by_cat: HashMap<ToolCategory, Vec<&crate::model::ToolDefinition>> = HashMap::new();
    for t in tools.all() {
        by_cat.entry(t.category).or_default().push(t);
    }
    for cat in ToolCategory::all() {
        let Some(list) = by_cat.get(cat) else {
            continue;
        };
        out.push_str(&format!("\n{}\n", cat.display_name()));
        let mut sorted = list.clone();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for t in sorted {
            let st = state.tools.get(&t.id);
            let (installed, ver) = match st {
                Some(s) if s.installed => (true, s.version.as_deref()),
                _ => (false, None),
            };
            out.push_str(&status_line(installed, &t.id, ver, width));
            out.push('\n');
        }
    }
    out
}

pub fn render_category_coverage(rows: &[CategoryCoverage]) -> String {
    let mut out = String::from("\nAssessment capability coverage\n\n");
    for r in rows {
        out.push_str(&format!(
            "  {:<22} {} {:>5.1}%\n",
            r.category,
            bar(r.pct, 10),
            r.pct
        ));
    }
    out
}

pub fn render_startup_summary(state: &EnvironmentState, missing_recommended: usize) -> String {
    format!(
        "\n{} tools available\n{} recommended tools missing\n\nRun /tools for details.\nRun /install <tool> for installation instructions.\nRun /doctor for a detailed environment diagnosis.\n",
        state.installed_tool_count(),
        missing_recommended
    )
}

pub fn render_tools_table(
    state: &EnvironmentState,
    tools: &ToolRegistry,
    filter: Option<ToolCategory>,
) -> String {
    let mut out = String::from("Tools\n\n");
    for t in tools
        .all()
        .iter()
        .filter(|t| filter.is_none_or(|c| t.category == c))
    {
        let st = state.tools.get(&t.id);
        let (mark, detail) = match st {
            Some(s) if s.installed => (
                "✓",
                format!(
                    "{} | {} | caps:{} | {}",
                    s.version.as_deref().unwrap_or("unknown version"),
                    s.executable_path.as_deref().unwrap_or("?"),
                    s.capabilities.len(),
                    s.diagnostic
                ),
            ),
            _ => ("✗", "not installed".to_string()),
        };
        out.push_str(&format!("{mark} {:<12} {:<18} {detail}\n", t.id, t.name));
    }
    out
}

pub fn render_tool_detail(
    state: &EnvironmentState,
    tools: &ToolRegistry,
    id: &str,
) -> Result<String, String> {
    let def = tools
        .get(id)
        .ok_or_else(|| format!("unknown tool `{id}`. Run /tools to list known tools."))?;
    let mut out = format!("{} ({})\n{}\n\n", def.name, def.id, def.description);
    out.push_str(&format!("Category: {}\n", def.category.display_name()));
    out.push_str("Provides:\n");
    for c in &def.capabilities {
        out.push_str(&format!("  • {c}\n"));
    }
    match state.tools.get(&def.id) {
        Some(s) if s.installed => {
            out.push_str(&format!(
                "\nStatus: installed ({})\nPath: {}\nHealth: {}\nAdapter: {}\nDiagnosis: {}\n",
                s.version.as_deref().unwrap_or("unknown"),
                s.executable_path.as_deref().unwrap_or("?"),
                if s.healthy { "healthy" } else { "UNHEALTHY" },
                if s.adapter_available {
                    "available"
                } else {
                    "not available"
                },
                s.diagnostic
            ));
            if !s.missing_dependencies.is_empty() {
                out.push_str(&format!(
                    "Missing deps: {}\n",
                    s.missing_dependencies.join(", ")
                ));
            }
        }
        _ => {
            out.push_str(&format!(
                "\nStatus: NOT INSTALLED\nDocs: {}\nRun `/install {}` for guidance.\n",
                def.docs_url, def.id
            ));
        }
    }
    Ok(out)
}

pub fn render_capabilities(state: &EnvironmentState) -> String {
    let mut out = String::from("Capabilities\n\n");
    let mut rows: Vec<_> = state.capabilities.iter().collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    for s in rows {
        let mark = match s.status {
            crate::model::CapabilityStatus::Covered => "✓",
            crate::model::CapabilityStatus::Partial => "~",
            crate::model::CapabilityStatus::NotAvailable => "✗",
        };
        out.push_str(&format!(
            "{mark} {:<30} {:<13} providers: {}\n",
            s.id,
            s.status.as_str(),
            if s.providers_available.is_empty() {
                "—".to_string()
            } else {
                s.providers_available.join(", ")
            }
        ));
    }
    out
}

pub fn render_capability_detail(
    state: &EnvironmentState,
    tools: &ToolRegistry,
    cap_id: &str,
) -> Result<String, String> {
    let snap = state
        .capabilities
        .iter()
        .find(|s| s.id == cap_id)
        .ok_or_else(|| format!("unknown capability `{cap_id}`. Run /capabilities to list."))?;
    let mut out = format!("{}\nStatus: {}\n\n", snap.id, snap.status.as_str());
    out.push_str("Available providers:\n");
    for p in tools.providers_of(cap_id) {
        let ver = state
            .tools
            .get(&p.id)
            .and_then(|s| s.version.clone())
            .unwrap_or_default();
        let up = state
            .tools
            .get(&p.id)
            .is_some_and(|s| s.installed && s.healthy);
        out.push_str(&format!(
            "  {} {:<12} {}\n",
            if up { "✓" } else { "✗" },
            p.id,
            if up { ver } else { "missing".to_string() }
        ));
    }
    Ok(out)
}

pub fn render_coverage(eval: &crate::model::ProfileEvaluation) -> String {
    let mut out = format!(
        "Profile `{}` — {:.1}% capability coverage\n",
        eval.profile_id, eval.coverage_pct
    );
    let section = |title: &str, items: &[String], o: &mut String| {
        o.push_str(&format!("\n{title}\n"));
        if items.is_empty() {
            o.push_str("  (none)\n");
        } else {
            for i in items {
                o.push_str(&format!("  {i}\n"));
            }
        }
    };
    section("HIGH — missing", &eval.missing_high, &mut out);
    section("MEDIUM — missing", &eval.missing_medium, &mut out);
    section("LOW — missing", &eval.missing_low, &mut out);
    out.push_str("\nRecommended tools\n");
    if eval.recommended_tools.is_empty() {
        out.push_str("  (environment covers this profile)\n");
    } else {
        for t in &eval.recommended_tools {
            out.push_str(&format!("  {t}\n"));
        }
    }
    out
}

pub fn render_doctor(r: &DoctorReport) -> String {
    let mut out = String::from("medusa Doctor\n");
    out.push_str(&format!(
        "\nPlatform\n  {} {}\n",
        r.platform.os, r.platform.arch
    ));
    out.push_str(&format!(
        "  PATH entries: {} | elevated: {}\n",
        r.platform.path_entries,
        if r.platform.elevated {
            "yes (approx.)"
        } else {
            "no (approx.)"
        }
    ));
    out.push_str("\nRuntime dependencies\n");
    for (name, ver) in &r.platform.runtimes {
        match ver {
            Some(v) => out.push_str(&format!("  ✓ {name} {v}\n")),
            None => out.push_str(&format!("  ✗ {name} (not on PATH)\n")),
        }
    }
    out.push_str(&format!(
        "  {} Docker {}\n",
        if r.platform.has_docker { "✓" } else { "✗" },
        if r.platform.has_docker {
            "detected"
        } else {
            "not detected"
        }
    ));
    out.push_str(&format!(
        "  {} WSL {}\n",
        if r.platform.has_wsl { "✓" } else { "✗" },
        if r.platform.has_wsl {
            "detected"
        } else {
            "not detected"
        }
    ));
    out.push_str(&format!(
        "  {} network egress {}\n",
        if r.platform.network_ok { "✓" } else { "✗" },
        if r.platform.network_ok {
            "ok"
        } else {
            "probe failed"
        }
    ));
    out.push_str(&format!(
        "\nSecurity capabilities\n  {}/{} capabilities covered | {}/{} tools installed\n",
        r.capabilities_covered, r.capabilities_total, r.tools_installed, r.tools_total
    ));
    out.push_str(&format!(
        "  {} packet capture\n",
        if r.packet_capture_ok { "✓" } else { "✗" }
    ));
    if !r.platform.package_managers.is_empty() {
        out.push_str(&format!(
            "\nPackage managers: {}\n",
            r.platform.package_managers.join(", ")
        ));
    }
    out.push_str("\nIssues\n");
    if r.issues.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for i in &r.issues {
            out.push_str(&format!(
                "  {} {}\n    why: {}\n    fix: {}\n",
                severity_mark(i.severity),
                i.message,
                issue_why(i),
                issue_fix(i)
            ));
        }
    }
    out
}

fn severity_mark(s: char) -> &'static str {
    match s {
        'x' => "✗",
        _ => "!",
    }
}

fn issue_why(i: &DoctorIssue) -> &str {
    &i.why_it_matters
}

fn issue_fix(i: &DoctorIssue) -> &str {
    &i.remediation
}

pub fn render_install(rec: &InstallRecommendation) -> String {
    let mut out = format!(
        "{} is not installed or needs attention.\n\nProvides:\n",
        rec.tool_name
    );
    for p in &rec.provides {
        out.push_str(&format!("  • {p}\n"));
    }
    out.push_str("\nRecommended installation methods:\n");
    for plat in &rec.per_platform {
        out.push_str(&format!("\n  {}:\n", platform_name(plat.platform)));
        for line in &plat.lines {
            out.push_str(&format!("    {line}\n"));
        }
        out.push_str(&format!("    Docs: {}\n", plat.docs_url));
    }
    out.push_str(&format!(
        "\nDocumentation:\n  {}\n\nRun `/install {}` to see this again. medusa never installs tools automatically.\n",
        rec.docs_url, rec.tool_id
    ));
    out
}

fn platform_name(p: crate::model::Platform) -> &'static str {
    match p {
        crate::model::Platform::Windows => "Windows",
        crate::model::Platform::Macos => "macOS",
        crate::model::Platform::Linux => "Linux",
    }
}

pub const HELP: &str = "Commands:\n  /tools [category]      list tools (optional category filter)\n  /tool <name>           show one tool\n  /capabilities [id]     list capabilities or show providers of one\n  /coverage [profile]    profile coverage (default: high_coverage)\n  /doctor                environment diagnosis\n  /install [tool]        installation guidance (no arg = missing tools)\n  /refresh-tools         force rediscovery\n  /profiles              list assessment profiles\n  /assess <target>       run an agentic investigation\n  /tui <target>          fullscreen investigation UI\n  /help                  this help\n  /exit                  quit\n";
