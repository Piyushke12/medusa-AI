//! The `opencode` theme, copied from `opencode.json` in the opencode repo
//! (dark variant). https://github.com/anomalyco/opencode
//!
//! Signature traits: near-black `#0a0a0a` background, panel `#141414` for
//! user-message cards, warm peach `#fab283` primary, muted gray text.

use ratatui::style::Color;

/// Page background. darkStep1 `#0a0a0a`.
pub const BG: Color = Color::Rgb(10, 10, 10);
/// User-message card background. darkStep2 `#141414`.
pub const PANEL: Color = Color::Rgb(20, 20, 20);
/// Hover/higher element background. darkStep3 `#1e1e1e`.
pub const ELEMENT: Color = Color::Rgb(30, 30, 30);
/// The opencode peach. darkStep9 `#fab283`.
pub const PRIMARY: Color = Color::Rgb(250, 178, 131);
/// Blue. `#5c9cf5`.
pub const SECONDARY: Color = Color::Rgb(92, 156, 245);
/// Purple. `#9d7cd8`.
pub const ACCENT: Color = Color::Rgb(157, 124, 216);
/// Red. `#e06c75`.
pub const ERROR: Color = Color::Rgb(224, 108, 117);
/// Orange. `#f5a742`.
pub const WARNING: Color = Color::Rgb(245, 167, 66);
/// Green. `#7fd88f`.
pub const SUCCESS: Color = Color::Rgb(127, 216, 143);
/// Cyan. `#56b6c2`.
pub const INFO: Color = Color::Rgb(86, 182, 194);
/// Primary text. darkStep12 `#eeeeee`.
pub const TEXT: Color = Color::Rgb(238, 238, 238);
/// Dimmed text. darkStep11 `#808080`.
pub const TEXT_MUTED: Color = Color::Rgb(128, 128, 128);
/// Border. darkStep7 `#484848`.
pub const BORDER: Color = Color::Rgb(72, 72, 72);
/// Focused border. darkStep8 `#606060`.
pub const BORDER_ACTIVE: Color = Color::Rgb(96, 96, 96);
