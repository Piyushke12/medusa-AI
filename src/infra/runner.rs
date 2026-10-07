//! Real process execution via `std::process::Command` only.
//! No shell (`sh -c` / `cmd /C`) is ever used: the executable path is resolved
//! by `core::resolver` and invoked directly with an argv list, which is
//! correct on Windows, macOS and Linux.

use std::path::Path;
use std::process::Command;

use crate::core::discovery::{CommandOutput, CommandRunner};

/// Production command runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, exe: &Path, args: &[String]) -> Result<CommandOutput, String> {
        let output = Command::new(exe)
            .args(args)
            .output()
            .map_err(|e| format!("failed to execute {}: {e}", exe.display()))?;
        let exit_code = output.status.code().unwrap_or(-1);
        Ok(CommandOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Probe whether `exe` resolves on PATH (cheap existence check for doctor /
/// dependency checks without running anything).
pub fn exe_exists(name: &str) -> Option<String> {
    crate::core::resolver::resolve_executable(&[name.to_string()], &[])
        .map(|p| p.to_string_lossy().into_owned())
}
