use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::diff::check_env_files;
use sekretbarilo::diff::parser::{DiffFile, parse_diff};
use sekretbarilo::scanner::engine::scan;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::path::{Path, PathBuf};

fn framed(lf: &str) -> Vec<u8> {
    lf.replace('\n', "\r\n").into_bytes()
}

#[derive(Debug, PartialEq, Eq)]
struct FileSignature {
    path: String,
    is_new: bool,
    is_deleted: bool,
    is_renamed: bool,
    is_binary: bool,
    added_lines: Vec<(usize, Vec<u8>)>,
}

fn files_signature(files: &[DiffFile]) -> Vec<FileSignature> {
    files
        .iter()
        .map(|file| FileSignature {
            path: file.path.clone(),
            is_new: file.is_new,
            is_deleted: file.is_deleted,
            is_renamed: file.is_renamed,
            is_binary: file.is_binary,
            added_lines: file
                .added_lines
                .iter()
                .map(|line| (line.line_number, line.content.clone()))
                .collect(),
        })
        .collect()
}

fn findings(files: &[DiffFile]) -> Vec<(String, usize, String, Vec<u8>)> {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    findings_with(files, &scanner, &allowlist)
}

fn findings_with(
    files: &[DiffFile],
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> Vec<(String, usize, String, Vec<u8>)> {
    let mut found: Vec<_> = scan(files, scanner, allowlist)
        .into_iter()
        .map(|finding| {
            assert!(!finding.matched_value.contains(&b'\r'));
            (
                finding.file,
                finding.line,
                finding.rule_id,
                finding.matched_value,
            )
        })
        .collect();
    found.sort();
    found
}

const GENERATOR_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn next(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    *state = (*state).wrapping_mul(0x2545_F491_4F6C_DD1D);
    *state
}

fn hex(length: usize) -> String {
    let mut state = GENERATOR_SEED;
    (0..length)
        .map(|_| char::from_digit((next(&mut state) >> 60) as u32, 16).unwrap())
        .collect()
}

fn sequence(length: usize) -> String {
    (0..length)
        .map(|index| {
            let byte = if index % 5 == 0 {
                b'0' + (index % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + ((index * 7) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

fn base64_body(length: usize) -> String {
    let mut state = GENERATOR_SEED ^ 0x5555_5555_5555_5555;
    let mut value: String = (0..length - 1)
        .map(|_| char::from(B64_ALPHABET[(next(&mut state) >> 58) as usize]))
        .collect();
    value.push('=');
    value
}

fn expand_shape(line: &str) -> String {
    let raw = hex(32);
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &raw[0..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..32]
    );
    let mut expanded = line.to_owned();
    for (name, value) in [
        ("S32", sequence(32)),
        ("S36", sequence(36)),
        ("S40", sequence(40)),
        ("HEX32", raw),
        ("HEX40", hex(40)),
        ("HEX64", hex(64)),
        ("B64_44", base64_body(44)),
        ("UUID", uuid),
    ] {
        expanded = expanded.replace(&format!("{{{name}}}"), &value);
    }
    expanded
}

fn fixture_files(kind: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(kind);
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "txt"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "empty fixture directory: {}",
        dir.display()
    );
    paths
}

fn is_fixture_shape(line: &str) -> bool {
    !line.trim().is_empty() && line != "#" && !line.starts_with("# ") && !line.starts_with("#\t")
}

fn token(seed: usize) -> String {
    (0..32)
        .map(|index| {
            let byte = if index % 5 == 0 {
                b'0' + ((index + seed) % 10) as u8
            } else {
                let base = if index % 2 == 0 { b'A' } else { b'a' };
                base + ((index * 7 + seed) % 26) as u8
            };
            char::from(byte)
        })
        .collect()
}

#[test]
fn full_crlf_framing_matches_lf_for_metadata_and_hunks() {
    let lf = "diff --git a/src/new.rs b/src/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/src/new.rs\n@@ -0,0 +3,2 @@\n+let first = 1;\n+let second = 2;\n@@ -10 +20,2 @@\n old\n+let third = 3;\n+let fourth = 4;\ndiff --git a/removed.rs b/removed.rs\ndeleted file mode 100644\n--- a/removed.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\ndiff --git a/old name.go b/src/new name.go\nrename from old name.go\nrename to src/new name.go\n--- a/old name.go\n+++ b/src/new name.go\n@@ -4 +4 @@\n-old\n+new\ndiff --git a/image.png b/image.png\nBinary files /dev/null and b/image.png differ\ndiff --git a/data.bin b/data.bin\nnew file mode 100644\nGIT binary patch\nliteral 12\nabc\n";
    let lf_files = parse_diff(lf.as_bytes());
    let crlf_files = parse_diff(&framed(lf));
    assert_eq!(files_signature(&crlf_files), files_signature(&lf_files));
    assert_eq!(lf_files.len(), 5);
    assert_eq!(lf_files[0].path, "src/new.rs");
    assert!(lf_files[0].is_new);
    assert_eq!(
        lf_files[0]
            .added_lines
            .iter()
            .map(|line| line.line_number)
            .collect::<Vec<_>>(),
        [3, 4, 21, 22]
    );
    assert!(lf_files[1].is_deleted);
    assert!(lf_files[2].is_renamed);
    assert_eq!(lf_files[2].path, "src/new name.go");
    assert!(lf_files[3].is_binary);
    assert!(lf_files[4].is_binary);
    assert!(lf_files[4].is_new);
    assert_eq!(findings(&crlf_files), findings(&lf_files));
}

#[test]
fn generated_source_and_text_shapes_have_lf_crlf_scan_parity() {
    let paths = ["src/example.rs", "src/example.go", "data/shapes.txt"];
    let mut positive_cases = 0;
    for (index, path) in paths.iter().enumerate() {
        for seed in 0..6 {
            let value = token(index * 10 + seed);
            let line = match seed % 3 {
                0 => format!("api_key = \"{value}\""),
                1 => format!("client_secret = \"{value}\""),
                _ => format!("password = \"{value}\""),
            };
            let lf = format!(
                "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{line}\n"
            );
            let expected = parse_diff(lf.as_bytes());
            let actual = parse_diff(&framed(&lf));
            assert_eq!(
                files_signature(&actual),
                files_signature(&expected),
                "{path}: {seed}"
            );
            let lf_found = findings(&expected);
            let crlf_found = findings(&actual);
            assert_eq!(crlf_found, lf_found, "{path}: {seed}");
            assert!(
                crlf_found.iter().any(|(_, line, _, matched)| {
                    *line == 1
                        && matched
                            .windows(value.len())
                            .any(|part| part == value.as_bytes())
                }),
                "missing generated value for {path}: {seed}"
            );
            positive_cases += 1;
        }
        for benign in [
            "api_key = \"changeme\"",
            "password = \"********\"",
            "Authorization: Bearer ${ACME_API_TOKEN}",
        ] {
            let lf = format!(
                "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{benign}\n"
            );
            let expected = parse_diff(lf.as_bytes());
            let actual = parse_diff(&framed(&lf));
            assert_eq!(files_signature(&actual), files_signature(&expected));
            assert_eq!(findings(&actual), findings(&expected));
            assert!(findings(&actual).is_empty(), "benign {path}: {benign}");
        }
    }
    assert_eq!(positive_cases, 18);
}

#[test]
fn path_exemptions_and_no_newline_markers_match() {
    let value = token(99);
    let lf = format!(
        "diff --git a/.env.local b/.env.local\nnew file mode 100644\n--- /dev/null\n+++ b/.env.local\n@@ -0,0 +1 @@\n+api_key = \"{value}\"\n\\ No newline at end of file\ndiff --git a/vendor/generated.rs b/vendor/generated.rs\nnew file mode 100644\n--- /dev/null\n+++ b/vendor/generated.rs\n@@ -0,0 +1 @@\n+api_key = \"{value}\"\n"
    );
    let lf_files = parse_diff(lf.as_bytes());
    let crlf_files = parse_diff(&framed(&lf));
    assert_eq!(files_signature(&crlf_files), files_signature(&lf_files));
    assert_eq!(check_env_files(&lf_files).blocked_files, [".env.local"]);
    assert_eq!(check_env_files(&crlf_files).blocked_files, [".env.local"]);
    assert_eq!(findings(&crlf_files), findings(&lf_files));
    assert!(
        findings(&crlf_files)
            .iter()
            .all(|finding| finding.0 != "vendor/generated.rs")
    );
}

#[test]
fn test_path_tier_three_skip_matches_lf() {
    let value = token(3);
    let lf = format!(
        "diff --git a/tests/example.rs b/tests/example.rs\nnew file mode 100644\n--- /dev/null\n+++ b/tests/example.rs\n@@ -0,0 +1 @@\n+let k = \"{value}\";\ndiff --git a/src/example.rs b/src/example.rs\nnew file mode 100644\n--- /dev/null\n+++ b/src/example.rs\n@@ -0,0 +1 @@\n+let k = \"{value}\";\n"
    );
    let lf_found = findings(&parse_diff(lf.as_bytes()));
    let crlf_found = findings(&parse_diff(&framed(&lf)));
    assert_eq!(crlf_found, lf_found);
    assert!(crlf_found.iter().any(|finding| {
        finding.0 == "src/example.rs" && finding.2 == "generic-high-entropy-value"
    }));
    assert!(!crlf_found.iter().any(|finding| {
        finding.0 == "tests/example.rs" && finding.2 == "generic-high-entropy-value"
    }));
}

#[test]
fn lf_framing_keeps_source_cr_bytes_without_candidate_cr() {
    let value = token(17);
    let lf = format!(
        "diff --git a/src/example.go b/src/example.go\n--- a/src/example.go\n+++ b/src/example.go\n@@ -0,0 +5 @@\n+api_key = \"{value}\"\n\\ No newline at end of file\n"
    );
    let git_source_crlf = lf.replace(
        &format!("+api_key = \"{value}\"\n"),
        &format!("+api_key = \"{value}\"\r\n"),
    );
    let source = parse_diff(git_source_crlf.as_bytes());
    assert_eq!(source[0].path, "src/example.go");
    assert_eq!(source[0].added_lines[0].line_number, 5);
    assert_eq!(source[0].added_lines[0].content.last(), Some(&b'\r'));
    assert_eq!(findings(&source), findings(&parse_diff(lf.as_bytes())));

    let full_crlf_with_source_cr = framed(&git_source_crlf);
    let nested = parse_diff(&full_crlf_with_source_cr);
    assert_eq!(nested[0].added_lines[0].content.last(), Some(&b'\r'));
    assert_eq!(findings(&nested), findings(&source));
}

#[test]
fn fixture_corpus_has_lf_crlf_transport_parity() {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let allowlist = build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    let mut traced_allowlist = build_allowlist(&ProjectConfig::default(), &rules).unwrap();
    traced_allowlist.trace_exemptions = true;
    let mut shape_count = 0;
    let mut detected_count = 0;
    let mut traced_count = 0;

    for kind in ["true_positives", "false_positives"] {
        for path in fixture_files(kind) {
            let text = std::fs::read_to_string(&path).unwrap();
            for (index, line) in text.lines().enumerate() {
                if !is_fixture_shape(line) {
                    continue;
                }
                let shape = if kind == "true_positives" {
                    line.split_once('\t')
                        .unwrap_or_else(|| {
                            panic!("missing rule id: {}:{}", path.display(), index + 1)
                        })
                        .1
                } else {
                    line
                };
                let expanded = expand_shape(shape);
                let lf = format!(
                    "diff --git a/corpus/shapes.txt b/corpus/shapes.txt\nnew file mode 100644\n--- /dev/null\n+++ b/corpus/shapes.txt\n@@ -0,0 +1 @@\n+{expanded}\n"
                );
                let lf_files = parse_diff(lf.as_bytes());
                let crlf_files = parse_diff(&framed(&lf));
                let label = format!("{}:{}", path.display(), index + 1);
                assert_eq!(
                    files_signature(&crlf_files),
                    files_signature(&lf_files),
                    "{label}"
                );
                assert_eq!(crlf_files[0].path, "corpus/shapes.txt", "{label}");
                assert_eq!(crlf_files[0].added_lines[0].line_number, 1, "{label}");

                let lf_found = findings_with(&lf_files, &scanner, &allowlist);
                let crlf_found = findings_with(&crlf_files, &scanner, &allowlist);
                assert_eq!(crlf_found, lf_found, "findings: {label}");
                detected_count += lf_found.len();

                let lf_traced = findings_with(&lf_files, &scanner, &traced_allowlist);
                let crlf_traced = findings_with(&crlf_files, &scanner, &traced_allowlist);
                assert_eq!(crlf_traced, lf_traced, "exemption trace: {label}");
                traced_count += lf_traced
                    .iter()
                    .filter(|found| found.2.starts_with("exempt:"))
                    .count();
                shape_count += 1;
            }
        }
    }

    assert!(
        shape_count >= 100,
        "only {shape_count} fixture shapes transported"
    );
    assert!(
        detected_count >= 20,
        "only {detected_count} candidates detected"
    );
    assert!(traced_count > 0, "no exemption traces exercised");
}
