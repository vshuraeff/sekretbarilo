use std::path::Path;

struct ScanTarget {
    path: &'static str,
    start_marker: Option<&'static str>,
    end_marker: Option<&'static str>,
}

const HOOK_PATH_TARGETS: &[ScanTarget] = &[
    ScanTarget {
        path: "src/agent/redact.rs",
        start_marker: None,
        end_marker: Some("#[cfg(test)]"),
    },
    ScanTarget {
        path: "src/agent/mod.rs",
        start_marker: None,
        end_marker: Some("#[cfg(test)]"),
    },
    ScanTarget {
        path: "src/config/mod.rs",
        start_marker: None,
        end_marker: Some("#[cfg(test)]"),
    },
    ScanTarget {
        path: "src/agent/codex.rs",
        start_marker: Some("pub fn run_check_codex() -> i32 {"),
        end_marker: Some("#[cfg(test)]"),
    },
];

#[test]
fn invariant_i6_no_panicking_print_macros_on_hook_path() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    for target in HOOK_PATH_TARGETS {
        let path = manifest_dir.join(target.path);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read source {}: {error}", target.path));
        let start = target.start_marker.map_or(0, |marker| {
            source.find(marker).unwrap_or_else(|| {
                panic!(
                    "start marker {marker:?} not found in hook-path source {}",
                    target.path
                )
            })
        });
        let end = target.end_marker.map_or(source.len(), |marker| {
            source[start..]
                .find(marker)
                .map(|offset| start + offset)
                .unwrap_or_else(|| {
                    panic!(
                        "end marker {marker:?} not found after the scan start in hook-path source {}",
                        target.path
                    )
                })
        });
        let window = &source[start..end];

        for pattern in ["eprintln!", "println!", "print!"] {
            assert!(
                !window.contains(pattern),
                "hook-path source {} contains panicking print macro {pattern}",
                target.path
            );
        }
    }
}
