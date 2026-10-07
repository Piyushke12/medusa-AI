//! Deterministic business logic. Pure functions + the discovery service.
//! No direct I/O: process/filesystem access goes through small traits so tests
//! can inject fakes and no real security tool is ever required.

pub mod coverage;
pub mod discovery;
pub mod resolver;
pub mod version;

pub use coverage::{evaluate_profile, CategoryCoverage};
pub use discovery::{
    scan_environment, CommandOutput, CommandRunner, NullRunner, ToolDiscoveryService,
};
pub use resolver::resolve_executable;
pub use version::parse_version;
