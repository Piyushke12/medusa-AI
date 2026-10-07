//! medusa: Security Tool Discovery (Phase 0) + Agentic Investigation (Phase 1+).
//!
//! Layered architecture (dependencies point one way):
//!
//! ```text
//! cli  -> agent -> core -> model
//!   \        ^        ^
//!    \       |        |
//!     -> infra (implements core traits)   doctor, install, registry
//! ```
//!
//! * `model`    — pure data types, serializable, no I/O.
//! * `registry` — declarative builtin data + extensible containers. No detection logic.
//! * `core`     — deterministic business logic (discovery, coverage). No I/O except via traits.
//! * `agent`    — generic investigation loop (Phase 1): runtime, model providers,
//!                policy validation. No per-scan-type loops.
//! * `infra`    — side effects: process execution, filesystem, OS probes.
//! * `doctor`   — environment diagnosis aggregating state + platform probes.
//! * `install`  — installation recommendations (informational only, never executes).
//! * `cli`      — presentation: rendering + slash-command dispatch. No business logic.

pub mod agent;
pub mod cli;
pub mod core;
pub mod doctor;
pub mod infra;
pub mod install;
pub mod model;
pub mod registry;
