//! Version parsing: first `major.minor[.patch...]` token in combined output.
//! Hand-rolled scanner (no regex dependency); deterministic and total.

/// Extract the first version-like token (e.g. `7.96`, `2.3.1`, `v1.6.0`).
/// Returns the numeric part without a leading `v`.
pub fn parse_version(haystack: &str) -> Option<String> {
    let bytes = haystack.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Token may start with digit, or 'v'/'V' followed by digit.
        let start_digit = bytes[i].is_ascii_digit()
            || ((bytes[i] == b'v' || bytes[i] == b'V')
                && i + 1 < bytes.len()
                && bytes[i + 1].is_ascii_digit());
        if !start_digit {
            i += 1;
            continue;
        }
        let mut j = if bytes[i] == b'v' || bytes[i] == b'V' {
            i + 1
        } else {
            i
        };
        // major
        let major_start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if major_start == j {
            i += 1;
            continue;
        }
        // Require at least one `.minor`.
        if j >= bytes.len() || bytes[j] != b'.' {
            i = j;
            continue;
        }
        // Consume `.digits` groups.
        let mut k = j;
        let mut groups = 0;
        while k < bytes.len() && bytes[k] == b'.' {
            let mut d = k + 1;
            while d < bytes.len() && bytes[d].is_ascii_digit() {
                d += 1;
            }
            if d == k + 1 {
                break; // trailing dot, stop
            }
            groups += 1;
            k = d;
        }
        if groups == 0 {
            i = j + 1;
            continue;
        }
        let token_start = if bytes[i] == b'v' || bytes[i] == b'V' {
            i + 1
        } else {
            i
        };
        // Guard: reject tokens preceded by a digit or '.' (e.g. middle of hash).
        if token_start > 0
            && (bytes[token_start - 1].is_ascii_digit() || bytes[token_start - 1] == b'.')
        {
            i = k.max(i + 1);
            continue;
        }
        return Some(haystack[token_start..k].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_version_outputs() {
        assert_eq!(
            parse_version("Nmap version 7.96 ( https://nmap.org )"),
            Some("7.96".into())
        );
        assert_eq!(parse_version("v1.6.0"), Some("1.6.0".into()));
        assert_eq!(
            parse_version("nuclei version 3.3.9 (2024-01-01)"),
            Some("3.3.9".into())
        );
        assert_eq!(parse_version("ffuf v2.1.0"), Some("2.1.0".into()));
    }

    #[test]
    fn prefers_first_token_and_reads_stderr_style() {
        assert_eq!(
            parse_version("Wireshark 4.2.6 (TShark)."),
            Some("4.2.6".into())
        );
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version("version 3"), None); // bare major is not a version
    }

    #[test]
    fn handles_version_command_failures_gracefully() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("error: command not found"), None);
    }
}
