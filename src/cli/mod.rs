//! Presentation layer: rendering + deterministic slash-command dispatch.
//! The CLI never performs detection or coverage math; it only formats data
//! produced by `core`/`doctor`/`install`.

pub mod assess;
pub mod commands;
pub mod render;
pub mod theme;
pub mod tui;

pub use commands::{dispatch, Command, Ctx, Signal};
