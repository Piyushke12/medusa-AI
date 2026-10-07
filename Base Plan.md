Build Phase 0 of `medusa`: a production-grade **Security Tool Discovery, Capability Registry, and Environment Doctor**.

This is the first subsystem of the security assessment agent.

The goal is NOT simply to check whether executables exist.

The goal is to understand the user's security-assessment environment and determine:

1. Which security tools are installed.
2. Which versions are installed.
3. Which tools are actually executable.
4. Which capabilities are provided by each tool.
5. Which dependencies/configuration are missing.
6. Which important assessment capabilities currently have no available tool.
7. Which tools are recommended for a high-coverage security assessment.
8. How the user can install missing tools.
9. Whether the installed tool can be used by medusa through its adapter.
10. Whether multiple tools provide overlapping capabilities.

The system must be extensible because the final agent will support a very large security-tool ecosystem.

---

# 1. User experience

Running:

```
medusa
```

for the first time should perform an environment assessment before entering the normal interactive agent.

Example:

```
medusa Environment Check

Detecting security capabilities...

Network Recon
  ✓ nmap              7.96
  ✓ naabu             2.x
  ✓ dnsx              1.x
  ✗ masscan            not installed

HTTP / Web
  ✓ httpx             1.x
  ✓ nuclei            3.x
  ✓ katana            1.x
  ✓ ffuf              2.x
  ✗ sqlmap             not installed
  ✗ OWASP ZAP          not installed

Traffic Analysis
  ✓ tshark
  ✓ tcpdump
  ✗ mitmproxy

Source Analysis
  ✓ semgrep
  ✓ git
  ✗ codeql
  ✗ gitleaks

Container / Runtime
  ✓ docker
  ✗ trivy
  ✗ falco

...

Assessment capability coverage

  Network discovery       ██████████ 100%
  Service enumeration     ██████████ 100%
  Web enumeration         ████████░░  80%
  Web vulnerability       ██████░░░░  60%
  Source analysis         █████░░░░░  50%
  Runtime analysis        ███░░░░░░░  30%

14 tools available
8 recommended tools missing

Run /tools for details.
Run /install <tool> for installation instructions.
Run /doctor for a detailed environment diagnosis.
```

Then continue into:

```
medusa >
```

Do NOT make missing tools a fatal error.

The agent must work with partial capability.

---

# 2. Interactive commands

Add these slash commands:

```
/tools
/tools <category>
/tool <name>
/capabilities
/coverage
/doctor
/install
/install <tool>
/refresh-tools
```

Examples:

```
/tools

/tools network

/tool nmap

/capabilities

/coverage

/doctor

/install nuclei

/refresh-tools
```

These commands must be deterministic and must NOT require the LLM.

---

# 3. Tool Registry

Create a declarative Tool Registry.

Do NOT hard-code tool detection logic throughout the CLI.

Conceptually:

```
ToolDefinition

    id
    name
    category
    description
    capabilities
    executable_candidates
    version_command
    health_check
    dependencies
    platforms
    installation_methods
    adapter
    priority
    optional/required status
```

Example:

```
id: nmap

name: Nmap

category:
    network_recon

capabilities:
    - network.host_discovery
    - network.port_scan
    - network.service_detection
    - network.os_detection

executable_candidates:
    - nmap

version_command:
    - nmap
    - --version

platforms:
    - windows
    - linux
    - macos

installation:
    windows:
        package_manager: winget
        package: Insecure.Nmap

    macos:
        package_manager: brew
        package: nmap

    linux:
        package_manager: apt
        package: nmap
```

The exact package-manager/package identifiers must be verified before being added.

Do not invent installation commands.

---

# 4. Separate Tool from Capability

This is extremely important.

A tool is NOT the same thing as a capability.

For example:

```
Nmap
   ├── network.host_discovery
   ├── network.port_scan
   ├── network.service_detection
   └── network.os_detection
```

Another tool may provide:

```
network.port_scan
```

Therefore the architecture should support:

```
Capability
     ↑
     │
┌────┴─────┐
│          │
```

Nmap       Naabu

The agent should reason about:

```
network.port_scan
```

rather than:

```
use nmap
```

This allows the agent to select the best available implementation later.

---

# 5. Tool detection

Implement a generic detection engine.

For each ToolDefinition:

1. Determine whether executable is available.
2. Search PATH.
3. Support platform-specific executable locations where necessary.
4. Execute version command.
5. Capture stdout/stderr.
6. Parse version.
7. Check exit code.
8. Run optional health check.
9. Determine installation status.
10. Determine adapter availability.
11. Determine capability availability.

Represent the result with something similar to:

```
ToolStatus

    tool_id
    installed
    executable_path
    version
    platform
    architecture
    healthy
    adapter_available
    capabilities
    missing_dependencies
    diagnostic_message
```

Do not assume that:

```
executable exists == tool is usable
```

---

# 6. Cross-platform support

The CLI must be designed for:

```
Windows
macOS
Linux
```

Do not write Unix-only shell detection.

Use Rust's process APIs and PATH resolution properly.

The system should understand platform-specific installation mechanisms.

Examples may include:

```
winget
brew
apt
pacman
cargo
pipx
npm
official binary releases
```

But installation should initially be informational/recommendational.

DO NOT automatically install security tools.

The user must explicitly request installation.

---

# 7. Installation recommendations

When a tool is missing:

```
✗ nuclei
```

show:

```
Nuclei is not installed.

Provides:
  • vulnerability scanning
  • template-based security testing

Recommended installation methods:

  Windows:
    <verified command/instructions>

  macOS:
    <verified command/instructions>

  Linux:
    <verified command/instructions>

Documentation:
  <official documentation URL>

Run:

  /install nuclei
```

for detailed instructions.

IMPORTANT:

Only use verified official installation sources.

Do not fabricate package names, URLs, commands, or installation procedures.

The CLI should clearly distinguish:

```
Official package manager
Official binary release
Official documentation
```

Do not automatically execute installation commands.

---

# 8. Tool categories

Design the registry around assessment capabilities rather than arbitrary tool lists.

Start with these categories:

## Network discovery

Potential tools:

```
nmap
naabu
masscan
rustscan
```

Capabilities:

```
network.host_discovery
network.port_scan
network.service_detection
network.os_detection
network.banner_grabbing
```

## DNS / asset discovery

Potential tools:

```
subfinder
dnsx
amass
```

Capabilities:

```
dns.enumeration
dns.resolution
subdomain.discovery
asset.discovery
```

## HTTP / Web discovery

Potential tools:

```
httpx
katana
ffuf
gobuster
```

Capabilities:

```
http.probe
http.crawl
http.endpoint_discovery
http.parameter_discovery
web.fuzzing
```

## Web security testing

Potential tools:

```
nuclei
OWASP ZAP
sqlmap
mitmproxy
```

Capabilities:

```
web.vulnerability_scan
web.dynamic_testing
web.interception
web.injection_testing
```

## Network traffic analysis

Potential tools:

```
tshark
Wireshark
tcpdump
mitmproxy
```

Capabilities:

```
packet.capture
packet.analysis
protocol.analysis
traffic.reconstruction
```

## Source-code analysis

Potential tools:

```
Semgrep
CodeQL
tree-sitter
Gitleaks
```

Capabilities:

```
source.static_analysis
source.dataflow_analysis
source.call_graph
source.secret_detection
source.syntax_analysis
```

## Dependency / supply-chain

Potential tools:

```
Trivy
Syft
Grype
```

Capabilities:

```
dependency.scan
container.scan
sbom.generate
vulnerability.lookup
```

## Container / Kubernetes

Potential tools:

```
Trivy
Falco
Kubescape
kube-bench
```

Capabilities:

```
container.security
kubernetes.security
runtime.monitoring
configuration.audit
```

## Binary / reverse engineering

Potential tools:

```
Ghidra
radare2 / Rizin
capa
```

Capabilities:

```
binary.analysis
reverse.engineering
malware.analysis
capability.identification
```

## Cloud security

Potential tools should be added through a declarative registry later.

Do not pretend that every category has complete coverage.

---

# 9. Tool alternatives

The registry must support alternative providers.

Example:

```
capability:
    network.port_scan

providers:

    nmap
    naabu
    masscan
    rustscan
```

Then:

```
/capabilities network.port_scan
```

could display:

```
network.port_scan

Available providers:
  ✓ nmap 7.96
  ✓ naabu 2.x
  ✗ masscan
  ✗ rustscan
```

Later the AgentRuntime can choose between providers based on:

* target
* required information
* speed
* accuracy
* platform
* privileges
* previous observations
* cost

Do not implement sophisticated provider selection yet.

Establish the abstraction.

---

# 10. Capability coverage

Create a capability model.

Example:

```
CapabilityDefinition

    id
    category
    description
    importance
    providers
    prerequisites
```

Then calculate:

```
available capability
unavailable capability
partially available capability
```

Example:

```
network.port_scan
   COVERED
   providers: nmap, naabu

web.dynamic_testing
   PARTIAL
   providers: nuclei

web.browser_interaction
   NOT_AVAILABLE
```

The important distinction:

A tool being installed does NOT necessarily mean the capability is fully covered.

---

# 11. Assessment profiles

Create assessment profiles.

At minimum:

```
baseline
high_coverage
web_application
network
source_code
cloud
container
full
```

The user can eventually run:

```
medusa profile high_coverage
```

The profile defines which capabilities are recommended.

For example:

```
high_coverage
```

requires/recommends capabilities across:

```
network
dns
http
web
source
dependency
container
runtime
traffic
binary
cloud
```

The exact coverage matrix should be represented declaratively.

Do not encode it into the agent prompt.

---

# 12. Security assessment should NOT blindly require every tool

This is important.

Do not tell the user:

```
"Install all 50 tools."
```

Instead explain:

```
"Your environment currently has 72% capability coverage
 for the selected assessment profile."
```

Then show:

```
Missing capabilities

HIGH
  web.dynamic_testing
  source.dataflow_analysis

MEDIUM
  runtime.monitoring
  packet.capture

LOW
  binary.reverse_engineering
```

And:

```
Recommended tools

  OWASP ZAP
  CodeQL
  Falco
  Ghidra
```

The user can decide what to install.

---

# 13. Environment Doctor

Implement:

```
/doctor
```

which diagnoses:

```
OS
architecture
PATH
privileges
Docker
WSL
Python
Node
Java
Go
Rust
network access
packet-capture support
container runtime
available package managers
```

Example:

```
medusa Doctor

Platform
  ✓ Windows 11 x64

Runtime dependencies
  ✓ Python 3.13
  ✓ Node 22
  ✓ Go 1.24
  ✓ Rust 1.89
  ✓ Docker
  ✓ WSL2

Security capabilities
  ✓ Network scanning
  ✓ HTTP probing
  ✗ Packet capture
  ✓ Source analysis

Issues
  ! Npcap not detected
  ! CodeQL unavailable
  ! Trivy unavailable
```

The doctor should explain why a dependency matters.

---

# 14. Persistent environment state

Do not scan every executable on every command.

Implement:

```
ToolDiscoveryService
```

with cached results.

Store:

```
last_scan
tool statuses
versions
executable paths
capability state
```

But provide:

```
/refresh-tools
```

to force rediscovery.

The agent can also automatically refresh when:

* configuration changes
* a tool execution fails because executable disappeared
* user installs a tool
* version changes are detected

---

# 15. Do NOT let the LLM perform discovery

This entire subsystem must be deterministic.

Bad:

```
LLM:
  "Let's check whether nmap is installed."
```

Good:

```
medusa startup
    ↓
ToolDiscoveryService
    ↓
ToolRegistry
    ↓
EnvironmentState
    ↓
Agent receives:

    Available capabilities:
        network.port_scan
        network.service_detection
        ...

    Missing capabilities:
        web.dynamic_testing
        source.dataflow_analysis
        ...
```

The LLM should consume the resulting structured state, not perform environment discovery itself.

---

# 16. Future agent integration

Design the output so the future agent can receive something like:

```
EnvironmentCapabilities {

    available: [
        network.host_discovery,
        network.port_scan,
        network.service_detection,
        http.probe,
        http.crawl
    ],

    unavailable: [
        runtime.kernel_monitoring,
        source.dataflow_analysis
    ],

    providers: {
        network.port_scan: [
            nmap,
            naabu
        ]
    }
}
```

This becomes part of the Agent Context.

The LLM can then reason:

```
"I need service enumeration.
 Nmap is available.
 Use network.service_detection."
```

It should NOT need to know whether Nmap was found at:

```
C:\Program Files\Nmap\nmap.exe
```

or:

```
/usr/bin/nmap
```

That belongs to the Tool Runtime.

---

# 17. Architecture

Implement the following boundaries:

```
CLI
  ↓
ToolDiscoveryService
  ↓
ToolRegistry
  ↓
CapabilityRegistry
  ↓
EnvironmentState
```

Later:

```
EnvironmentState
      ↓
AgentRuntime
      ↓
ContextManager
      ↓
    LLM
      ↓
  ToolCall
      ↓
ToolRuntime
      ↓
ToolAdapter
      ↓
  Actual tool
```

Do NOT couple these components.

---

# 18. Tests

Write comprehensive tests.

Test:

* executable discovery
* PATH resolution
* Windows paths
* macOS paths
* Linux paths
* version parsing
* failed version commands
* unavailable executables
* unhealthy tools
* missing dependencies
* capability mapping
* alternative providers
* coverage calculation
* profile calculation
* cache behavior
* refresh behavior
* installation recommendation generation

Create fake/mock ToolDefinitions for tests.

Do not require Nmap or other real security tools to be installed to run the unit test suite.

Create integration tests that run only when explicitly enabled.

---

# 19. CLI output

Make the output polished but don't spend excessive time on visual effects.

Prioritize:

* clear status
* useful grouping
* machine-readable internal state
* deterministic output
* good error messages
* terminal width handling
* Windows compatibility

Later we will build the full interactive agent UI around this foundation.

---

# 20. Important architectural constraint

This subsystem is NOT a one-time "dependency checker".

It is the foundation of the future security agent's:

```
Capability Model
```

The final system should be able to answer:

```
"What can I test on this machine?"

"What can't I test?"

"Which tool can perform this investigation?"

"Do I have multiple providers?"

"Which capability gaps affect this assessment?"

"Why is this vulnerability class currently not testable?"
```

Therefore design this as a permanent subsystem, not a setup script.

---

# Deliverables

After implementation, provide:

1. Repository structure.
2. Tool registry design.
3. Capability registry design.
4. Environment state schema.
5. Detection flow.
6. Example output.
7. Slash-command list.
8. Tests written.
9. How to run the CLI.
10. How to add a new tool without modifying the discovery engine.
11. How to add a new capability without modifying the agent.
12. What should be implemented in the next phase.

Do not move on to autonomous vulnerability testing yet.

The only goal of this phase is to build a robust, extensible **Security Tool + Capability Discovery subsystem** that the future agent can trust.

---

# Phase 1+: The Agentic Part — One Generic Investigation Loop

Status:
- Phase 0 complete and verified: 30 tools, 61 capabilities, 8 profiles, doctor, deterministic CLI.
- Phase 1 complete: `src/agent/` — AgentRuntime, ModelProvider (stub + OpenAI-compatible), Decision, ExecutionPolicy, loop, cancellation. 36+ tests.
- Phase 1.5 complete: `AgentEvent` stream (`src/agent/events.rs`); runtime emits via `investigate_with(&mut FnMut)`; headless `investigate()` unchanged.
- Phase 1.6 complete: rich inline CLI (`src/cli/assess.rs`, `/assess <target>`) on console+indicatif. Full-screen ratatui UI deferred until after execution debugging needs it.
- Phase 1.7 complete: fullscreen TUI (`src/cli/tui.rs`, `/tui <target>`) on ratatui+crossterm — worker-thread runtime, mpsc event feed, header/feed/hypotheses/actions layout, q/Esc quit, Ctrl+C cancel, ↑↓ scroll, auto-quit for piped runs. Verified live with real provider.
- Phase 1.8 complete: chat-first rewrite — `medusa` boots into an opencode-themed fullscreen chat (borderless stream, `┃` user cards, `▣` agent labels, spinner, black `#0a0a0a` background, ↑/↓ prompt history, PgUp/PgDn scroll, Enter-lag fixed by moving LLM routing off the UI thread, `with_handle` enables true Ctrl+C cancellation). Legacy REPL removed.
- Phase 2 complete: `src/agent/context.rs` — `ContextManager` owns investigation memory (observations, hypotheses, actions, last_error) and builds every `ContextView` through budgeted, recency-filtered selection: char-approximated `TokenBudget` (24k default ≈ 6k tokens), 40/30/30 split across observations/hypotheses/actions, newest-wins per category with chronological presentation and `[... N older elided ...]` markers, duplicate-observation collapse, never-elided essentials (target, step, capabilities, last error). `ContextView` gains `observations`; runtime records into the manager; `InvestigationResult` shape unchanged. Ready for Phase 4/5 parsers to feed `add_observation`.
- Phase 3 complete: `src/agent/world.rs` — in-memory `WorldModel` asset graph: `Host` (ip, hostname, ports), `Port` (number, protocol, state, service), `Service` (name, version), `Endpoint` (url, host, port, path, technologies), `Technology` (name, version, category), `WorldObservation`, `WorldHypothesis` (with `supporting: Vec<ObservationId>` links), `Finding` (severity, evidence), `Evidence` (observation link). Typed IDs (`ObservationId`, `HypothesisId`, `FindingId`). Mutation + query methods on `WorldModel`: add_host, add_port, add_service, add_endpoint, add_technology, add_observation (dedup by summary), add_hypothesis, link_observation_to_hypothesis (dedup), add_finding, get_host, get_observation, get_hypothesis, get_finding, observations_for(target), observation_as_context(id) bridge. 22 unit tests. Runtime creates `WorldModel` in `investigate_with`; observations will feed both stores when Phase 5 parsers land. 79/79 tests pass.
- Phase 4 complete: `src/agent/executor.rs` — `ToolProvider` trait, `LocalProcessProvider` (spawns `std::process::Command` with timeout via dedicated thread + `mpsc`), `ToolResult` (exit_code, stdout, stderr, timed_out, error, success()), `StubProvider` (test injection). `ToolDefinition` gains `default_args: Vec<String>` with `{target}` placeholder; all 25 builtin tools updated with invocation defaults (nmap `-sV`, httpx `-target {target}`, ffuf `-u {target} -mc 200,301,302,403`, nuclei `-target {target}`, semgrep `scan --json {target}`, trivy `fs --format json {target}`, etc.). Runtime Execute branch now runs the tool end-to-end: validate → `ToolStarted` → `LocalProcessProvider::execute` → `ToolFinished` → `ToolExecuted` → record action + store result. `InvestigationResult` gains `tool_results: Vec<ToolResult>`. `AgentEvent::ToolExecuted` added with exit_code/success/timed_out. CLI/TUI renderers updated. 11 executor tests. 90/90 tests pass.
- Phase 5 complete: `src/agent/parsers.rs` + `src/model/observation.rs` — structured observations. nmap parsed from XML (`-oX -`, per official nmap docs recommendation; quick-xml + serde wire structs with `@attr` renames and `#[serde(default)]` Vecs, robust `<nmaprun>` slicing), httpx/nuclei from JSON lines. `ObservationDetail::{PortDiscovered, EndpointDiscovered, VulnerabilityFound}` + `ObservationKind` shared model types. `WorldModel::apply_detail` mutates the asset graph (host/port/service, endpoint merge-by-url, findings with evidence links + dedup). Runtime: ToolResult → `parse_tool_output` router → observations into BOTH stores + `apply_detail` + hypothesis auto-linking by target + `ObservationAdded` events; execution failures feed `last_error` for self-correction. default_args fixed to machine-readable formats (nmap `["-sV","-oX","-","{target}"]` — also fixed the missing `{target}` bug; httpx `-json -silent`; nuclei `-jsonl -silent`). `AgentRuntime::with_executor` enables fixture-based end-to-end tests. `InvestigationResult` gains `findings: Vec<Finding>`. 15 parser + 5 world-detail tests.
- Phase 6 complete: `src/agent/hypothesis.rs` — `Confidence` (Low/Medium/High, ordered, degrades unknowns to Low), evidence-count scoring (0→Low, 1–2→Medium, 3+→High), `Unknown { description, asset, resolving_capability }`, `derive_unknowns(&WorldModel)`: empty world → surface-enumeration unknown; open port w/o service → service detection; web service w/o endpoint → http.probe; probed endpoint → vuln scan; endpoint w/o tech → tech detection; closed ports yield nothing. `WorldHypothesis` gains `target` + `HypothesisStatus` (Created→Supported auto-transition on first link; Validated/Refuted settable). `ContextView.unknowns` (10% budget share, newest-wins) surfaced to the LLM; system prompt teaches the field. 10 hypothesis tests.
- Phase 7 complete: `src/registry/security_tests.rs` — `SecurityTestDefinition { id, name, description, prerequisites, produces, evidence_required, validation_strategy, risk_level, capabilities }`, `Prerequisite::{Capability, Observation(ObservationKind)}`, `RiskLevel::{Safe, Intrusive, Destructive}`. 12 builtin methodology entries covering the network→HTTP→vulnerability chain (port sweep, service enum, OS fingerprint, subdomain enum, http probe, tech detect, TLS check, crawl, directory fuzz, param discovery, vuln scan, secret scan). `SecurityTestRegistry` container mirrors ToolRegistry. 4 registry tests.
- Phase 8 complete: `src/agent/planner.rs` — `suggest(world, tests, state, executed) -> Vec<Suggestion>`: capability gate, prerequisite gate (Capability→env availability; Observation→world asset presence), priority = 50 base +25 resolves-open-unknown +10 bootstrap +15 safe −30 already-run, clamp 0–100, sorted desc; Destructive tests never suggested. `is_complete(world, state, executed)`: false until something executed; true when every unknown's resolver was executed or is unavailable. `ContextView.suggested_investigations` (10% budget share, ranked order preserved, trailing omission marker). Runtime wires the planner before each `model.decide()` via owned `tests` registry (`with_tests()` builder). 9 planner tests. Full-loop test proves: nmap XML → parsed observation → world host/port → probe unknown derived → planner suggestion → all visible in the model's next ContextView. 133/133 tests pass, zero warnings.
- Post-phases, TUI architecture rewrite (opencode parity): the fullscreen alternate-screen TUI is replaced by an **inline viewport** TUI (`Viewport::Inline(3)`). Messages print ONCE into the terminal's real scrollback via `Terminal::insert_before` (Buffer-level `Widget::render` with a 2-col margin inset); only a 3-row live area (status/spinner · input · footer) redraws. Why: the old alternate-screen mode redrew the entire window every spinner tick, which destroyed native click-drag text selection (selection anchored to app-owned canvas → "copies the whole terminal window"). Inline printing makes selection stable on real scrollback text, the conversation survives app exit, and terminal-native scrollback replaces PgUp/PgDn. User/error cards gain a 2-column gap between the `┃` border and text (`CARD_GAP`). Message log bounded at 1000 with a printed-cursor that follows trims. No mouse capture (never enabled). 134/134 unit tests.
- Post-phases, tooling + E2E verified: installed nuclei 3.11.1, gitleaks 8.30.1, trivy 0.74.0, ffuf 2.3.0 (scoop main) and httpx 1.12.0 (official GitHub release → scoop shims; the shadowing Python httpx demo CLI renamed to httpx-python.exe — Python library unaffected). E2E integration test (`MEDUSA_INTEGRATION=1 cargo test --test integration e2e`): toy HTTP server on a nmap-top-1000 port → scripted decisions → REAL process execution — `nmap -sV -oX -` XML parsed to observations (port observed), `httpx -u … -json -silent` JSONL parsed to an HTTP 200 endpoint observation, full event chain asserted. Passed live in 27.8s. 137/137 tests, zero warnings.
- TUI UX pass 2 (claude-code parity): (1) every printed row carries the theme background via a full-width `Block` bg rendered inside `insert_before`; (2) startup geometry — `Viewport::Inline` anchors at the CURSOR row (ratatui semantics), so the cursor is placed so the INPUT lands mid-screen (`centered_anchor` math: input = viewport row 1 at `rows/2`, welcome height accounted, clamped), the screen regions outside the centered cluster are covered by static theme-bg rows painted directly (`paint_bg_rows`, plain terminal text — selection-safe), and `insert_before` pushes the viewport down to the bottom as messages accumulate; (3) `↑`/`↓` now open/scroll a transcript BROWSER — a temporary alternate-screen overlay rendering the bounded message log with offset-from-bottom scrolling (`open_browse`/`close_browse`/`draw_browse`, printing paused while open, printed-cursor catches up on close) — because an app cannot scroll the terminal's native scrollback viewport; prompt history moved to `Ctrl+P`/`Ctrl+N` (readline bindings); mouse wheel remains native scrollback. 140/140 tests, zero warnings.

## Core decision: one loop, not N agents

Do NOT build `NetworkAgent`, `WebAgent`, `CloudAgent`, etc. with separate loops.
That path ends in `WebAgent → APIAgent → AuthAgent → SSRFAgent → ...` and painful coordination.

Instead:

- **One loop** — `AgentRuntime` (identical for every assessment).
- **Many test definitions** — `SecurityTestRegistry` (per-domain methodology).
- The loop never knows whether it is doing network, web, cloud, or binary testing.
  It only asks: *"Given what I currently know, what is the most useful safe next action?"*

The per-user question "deterministic loop per scan type vs generalised loop" is resolved:
**one generalised deterministic loop; scan-type specifics live in test definitions and tool parsers, never in the loop.**

## The loop

```
Target
  ↓
Investigation Planner
  ↓
Select next action
  ↓
Policy / Scope Validator
  ↓
Execute tool (via capability → provider, never raw shell)
  ↓
Parser / Normalizer
  ↓
Observation
  ↓
┌───────────────┴───────────────┐
↓                               ↓
World Model                 Hypotheses
│                               │
└───────────────┬───────────────┘
                ↓
         Context Manager
                ↓
               LLM
                ↓
        Next Tool / Finish
```

## LLM never touches the shell

Forbidden:

```
LLM → "run nmap -sV ..." → shell
```

Required:

```
LLM → structured action { capability, target, reason }
      → Capability Resolver → Provider (nmap ✓ / naabu ✗) → validated execution
```

Example decision:

```json
{
  "action": "execute_capability",
  "capability": "network.service_detection",
  "target": "10.0.0.10",
  "reason": "Ports 22 and 8080 are exposed and service identity is unknown"
}
```

## Observations, not raw output

Never feed raw scanner output to the LLM. Pipeline: `Tool → raw evidence (stored as artifact) → Parser → normalized Observation → world model`. The LLM receives structured observations (e.g. `PortDiscovered`, `ServiceIdentified`), keeping context tight.

## Unknowns drive the loop

```
Observation → what do we know? → what is uncertain? → hypotheses →
highest-value unknown → safe test → evidence → update hypothesis → repeat
```

This is what separates the agent from "run all scanners and summarize."

## Build order

- **Phase 1 — AgentRuntime**: `AgentRuntime`, `ModelProvider` trait, `Decision::{Execute, CreateHypothesis, Finish}`, the loop, cancellation.
- **Phase 2 — ContextManager**: token budgeting, relevance filtering, observation selection.
- **Phase 3 — Security world model** (in-memory behind an abstraction; no graph DB yet): Target, Asset, Host, Port, Service, Endpoint, Technology, Observation, Hypothesis, Finding, Evidence.
- **Phase 4 — Tool execution**: connect existing `ToolRegistry` → provider selection → `ToolCall` → `ToolResult`, behind the scope/risk policy validator.
- **Phase 5 — Structured observations**: parsers for 2–3 tools first — **nmap, httpx, nuclei** (demonstrates network → HTTP → vulnerability chaining).
- **Phase 6 — Hypothesis engine**: Hypothesis, Evidence, Unknown, Confidence, test selection.
- **Phase 7 — SecurityTestRegistry**: real methodology entries (`prerequisites`, `produces`, `evidence_required`, `validation_strategy`, `risk_level`).
- **Phase 8 — Investigation planner**: "what should I investigate next?" instead of just "what tool next?".

## Model backend

`ModelProvider` is a trait. First implementation: OpenAI-compatible HTTP provider configured by environment (user supplies their own endpoint):

```
MEDUSA_MODEL_BASE_URL   (OpenAI-compatible base URL)
MEDUSA_MODEL_API_KEY    (key)
MEDUSA_MODEL_NAME       (model id, e.g. gpt-4o-mini or local equivalent)
```

No keys in code or config files. A stub/deterministic provider exists for tests so the suite never needs network or a key.

## Target end-state architecture

```
                         USER
                           │
                           ▼
                    ┌─────────────┐
                    │   CLI/UI    │
                    └──────┬──────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │   Agent Runtime    │
                 │ Investigation Loop │
                 └─────────┬─────────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
       ContextManager   TestRegistry   Policy
            │              │
            └───────┬──────┘
                    ▼
                   LLM
                    │
                    ▼
             Structured Decision
                    │
                    ▼
             Capability Resolver
                    │
                    ▼
              Tool Provider
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
        Nmap      HTTPx      Nuclei
          │         │          │
          └─────────┼──────────┘
                    ▼
               Raw Evidence
                    │
                    ▼
              Parser/Normalizer
                    │
                    ▼
                Observation
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
      World Model          Hypotheses
          │                    │
          └─────────┬──────────┘
                    ▼
             Context Manager → LLM → ...
```

## Guiding principle

Don't build 15 security agents. Build **one investigation engine + many security capabilities/tests** — moving Medusa from "run all scanners and summarize" to "understand the target, model the attack surface, identify unknowns, choose targeted tests, correlate evidence, validate hypotheses, produce defensible findings."

No further tool-list expansion before the core loop exists (per reviewer; Phase 0 registry is sufficient foundation).

## TUI UX pass 3 � opencode parity + research round

Research (opencode Go/bubbletea source, Pi harness, Anthropic compaction + context-window docs, Codex CLI architecture):
- opencode keybinds (source of truth): `history_previous: up`, `history_next: down`, `messages_page_up: pageup`, `input_move_up/down: up/down`; home screen = vertically-centered logo + Prompt with rotating placeholders + bottom footer; DialogAlert for errors; prompt history in JSONL (cap 50, dedupe, self-heal).
- Pi (earendil): minimal harness; AGENTS.md instructions; extensions inject/filter history per turn; context_checkpoint/timeline/compact tools; footer shows context usage/tokens; transient errors retried =5�.
- Claude Code: full-history accumulation with server-side compaction at ~83.5% (summary replaces old context, skills re-injected capped); /compact manual; subagents get fresh windows.
- Codex: turn-based loop over Responses API; transcript persisted + resume; subagents own context; hierarchical AGENTS.md kept under ~150 lines; thin ratatui TUI client; "100% context left" header meter.

Fixes applied:
- Model failure now surfaces the actual error: `FinishReason::TooManyModelErrors { count, last_error }` + `InvestigationResult.model_error`; `Ev::Error` carries the message; completion + assess summary print it; centered dialog overlay (opencode DialogAlert parity) with ack guard so dismissing sticks.
- Landing transparency fixed: full-screen static paint `[0, rows)` at startup + eager `print_landing` after terminal creation (old code deferred landing into first message, leaving gaps when the log started empty).
- Keybinds: ?/? prompt history (browse-aware), PgUp/PgDn transcript browser, Ctrl+P/N retained.
- Prompt history persists to `%APPDATA%\medusa\prompt-history.jsonl` (cap 50, dedupe, load at startup).
- 138 unit + 3 integration tests pass, zero warnings.
- Startup panic fix: `landing_lines` emitted 5 rows (extra blank + 4-row logo) vs `LANDING_LINES=4` geometry � dropped the duplicate blank, added `landing_height_matches_geometry_constant` regression test. 139 unit + 3 integration, zero warnings.
