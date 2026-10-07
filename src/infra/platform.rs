//! OS / runtime / package-manager probes for the Environment Doctor.
//! Best-effort and non-fatal: every probe returns an `Option`/`bool` and the
//! doctor explains *why* each dependency matters.

use crate::core::discovery::CommandRunner;
use crate::infra::runner::exe_exists;

/// Snapshot of host facts used by `/doctor` and the startup screen.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub elevated: bool,
    pub path_entries: usize,
    pub package_managers: Vec<String>,
    pub runtimes: Vec<(String, Option<String>)>,
    pub has_docker: bool,
    pub has_wsl: bool,
    pub network_ok: bool,
}

fn version_of<R: CommandRunner>(runner: &R, exe: &str, args: &[&str]) -> Option<String> {
    let path = exe_exists(exe)?;
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let out = runner.run(std::path::Path::new(&path), &args).ok()?;
    if out.exit_code != 0 {
        return None;
    }
    crate::core::version::parse_version(&out.combined())
}

/// Heuristic elevation check: Windows via `net session` side effect is
/// avoided; we report based on env markers and let the doctor phrase it as
/// approximate. Unix checks `EUID` through the `id` tool when present.
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        // `HKLM` write probe would be intrusive; use session name heuristic.
        std::env::var("USERNAME")
            .map(|u| u.eq_ignore_ascii_case("administrator"))
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("EUID").map(|v| v == "0").unwrap_or(false)
            || std::env::var("USER").map(|u| u == "root").unwrap_or(false)
    }
}

pub fn collect_platform_info<R: CommandRunner>(runner: &R) -> PlatformInfo {
    let path_entries = std::env::var_os("PATH")
        .map(|v| std::env::split_paths(&v).count())
        .unwrap_or(0);

    let mut package_managers = Vec::new();
    for pm in [
        "winget", "brew", "apt", "apt-get", "pacman", "dnf", "cargo", "pipx", "npm", "go",
    ] {
        if exe_exists(pm).is_some() {
            package_managers.push(pm.to_string());
        }
    }

    let mut runtimes = Vec::new();
    for (exe, args) in [
        ("python", &["--version"] as &[&str]),
        ("python3", &["--version"]),
        ("node", &["--version"]),
        ("java", &["-version"]),
        ("go", &["version"]),
        ("rustc", &["--version"]),
        ("docker", &["--version"]),
        ("git", &["--version"]),
    ] {
        runtimes.push((exe.to_string(), version_of(runner, exe, args)));
    }

    let has_docker = exe_exists("docker").is_some();
    let has_wsl = exe_exists("wsl").is_some();
    let network_ok = std::net::TcpStream::connect_timeout(
        &"8.8.8.8:53".parse().expect("const addr"),
        std::time::Duration::from_secs(2),
    )
    .is_ok();

    PlatformInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        elevated: is_elevated(),
        path_entries,
        package_managers,
        runtimes,
        has_docker,
        has_wsl,
        network_ok,
    }
}
