//! Pure data types for tools, capabilities, profiles and persisted state.
//! No I/O, no process execution, no business logic.

pub mod capability;
pub mod observation;
pub mod profile;
pub mod state;
pub mod tool;

pub use capability::{
    CapabilityDefinition, CapabilitySnapshot, CapabilityStatus, Importance, OptionKind, OptionSpec,
    RiskLevel,
};
pub use observation::{ObservationDetail, ObservationKind};
pub use profile::{AssessmentProfile, ProfileEvaluation, ProfileRequirement};
pub use state::EnvironmentState;
pub use tool::{
    AdapterInfo, InstallKind, OptionBinding, Platform, PlatformInstall, ToolCategory,
    ToolDefinition, ToolStatus,
};
