//! Side effects: process execution, on-disk cache/state, OS/platform probes,
//! persistent config file. `infra` implements the traits defined in `core`;
//! it holds no business logic.

pub mod cache;
pub mod config;
pub mod platform;
pub mod runner;
pub mod scripts;
pub mod sessions;

pub use cache::{cache_path, load_state, save_state, state_is_fresh};
pub use config::{
    active_provider_id, config_location_help, config_path, list_provider_choices, load_file_config,
    resolve_model_config, resolve_selection, set_provider_in_config, set_provider_in_value,
    ProviderSummary,
};
pub use platform::{collect_platform_info, PlatformInfo};
pub use runner::RealCommandRunner;
pub use sessions::{
    list_sessions, load_session, SessionRecord, SessionSummary, SessionWriter, TimedRecord,
};
