//! Executable resolution: PATH search + platform-specific extra dirs.
//! Cross-platform by construction: no shell, no `which`/`where` subprocess.
//! The pure [`resolve_in_dirs`] takes an `exists` predicate so unit tests can
//! simulate Windows/macOS/Linux layouts without touching the real filesystem.

use std::path::{Path, PathBuf};

/// Candidate file names for `name` on this platform
/// (appends `.exe`/`.bat`/`.cmd` on Windows).
pub fn candidate_file_names(name: &str) -> Vec<String> {
    windows_candidate_file_names(name, cfg!(windows))
}

/// Same as [`candidate_file_names`] with an explicit platform flag so tests
/// and cross-platform resolution can probe Windows layouts on any host.
pub fn windows_candidate_file_names(name: &str, is_windows: bool) -> Vec<String> {
    if is_windows {
        if name.contains('.') {
            vec![name.to_string()]
        } else {
            vec![
                format!("{name}.exe"),
                format!("{name}.bat"),
                format!("{name}.cmd"),
                name.to_string(),
            ]
        }
    } else {
        vec![name.to_string()]
    }
}

/// Pure resolution over explicit dir lists. `is_windows` controls extension
/// probing so tests can cover Windows paths on any host.
pub fn resolve_in_dirs(
    candidates: &[String],
    path_dirs: &[PathBuf],
    extra_dirs: &[PathBuf],
    is_windows: bool,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let mut names: Vec<String> = Vec::new();
    for c in candidates {
        names.extend(windows_candidate_file_names(c, is_windows));
    }
    for dir in path_dirs.iter().chain(extra_dirs.iter()) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        for n in &names {
            let p = dir.join(n);
            if exists(&p) {
                return Some(p);
            }
        }
    }
    None
}

/// Resolve `candidates` against the real PATH + `extra_dirs`.
pub fn resolve_executable(candidates: &[String], extra_dirs: &[String]) -> Option<PathBuf> {
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    let extra: Vec<PathBuf> = extra_dirs.iter().map(PathBuf::from).collect();
    let is_windows = cfg!(windows);
    resolve_in_dirs(candidates, &path_dirs, &extra, is_windows, &|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn fake_fs(files: &[&str]) -> (Vec<PathBuf>, impl Fn(&Path) -> bool) {
        let set: HashSet<String> = files.iter().map(|s| s.to_string()).collect();
        let dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/extra")];
        let exists = move |p: &Path| set.contains(&p.to_string_lossy().replace('\\', "/"));
        (dirs, exists)
    }

    #[test]
    fn finds_candidate_on_path() {
        let (dirs, exists) = fake_fs(&["/usr/bin/nmap"]);
        let got = resolve_in_dirs(&["nmap".into()], &dirs[..1], &[], false, &exists);
        assert_eq!(got, Some(PathBuf::from("/usr/bin/nmap")));
    }

    #[test]
    fn falls_back_to_extra_dirs() {
        let (dirs, exists) = fake_fs(&["/extra/nmap"]);
        let got = resolve_in_dirs(&["nmap".into()], &dirs[..1], &dirs[1..], false, &exists);
        assert_eq!(got, Some(PathBuf::from("/extra/nmap")));
    }

    #[test]
    fn windows_probes_exe_extension() {
        let (_dirs, exists) = fake_fs(&["C:/Tools/nmap.exe"]);
        let got = resolve_in_dirs(
            &["nmap".into()],
            &[PathBuf::from("C:/Tools")],
            &[],
            true,
            &exists,
        );
        assert_eq!(got, Some(PathBuf::from("C:/Tools/nmap.exe")));
    }

    #[test]
    fn missing_executable_returns_none() {
        let (dirs, exists) = fake_fs(&[]);
        assert_eq!(
            resolve_in_dirs(&["nope".into()], &dirs, &[], false, &exists),
            None
        );
    }

    #[test]
    fn respects_candidate_preference_order() {
        let (_d, exists) = fake_fs(&["/usr/bin/zaproxy"]);
        let got = resolve_in_dirs(
            &["zap".into(), "zaproxy".into()],
            &[PathBuf::from("/usr/bin")],
            &[],
            false,
            &exists,
        );
        // "zap" itself is missing; second candidate matches.
        assert_eq!(got, Some(PathBuf::from("/usr/bin/zaproxy")));
    }
}
