//! redact-claude surface: credential-named `NAME=value` assignments printed in process argv
//! output (`pgrep -fl`, `ps`), with built-in defaults only. an assignment embedded mid-line among
//! other `KEY=value` pairs, paths and flags must be masked exactly like one at line start, and a
//! stray or phrase-opening quote byte earlier on the line must not hide it. opaque values are
//! generated here, never stored.

use std::sync::LazyLock;

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist};
use sekretbarilo::scanner::engine::redact_text;
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    compile_rules(&load_default_rules().expect("default rules load"))
        .expect("default rules compile")
});

static ALLOWLIST: LazyLock<CompiledAllowlist> = LazyLock::new(|| {
    let rules = load_default_rules().expect("default rules load");
    build_allowlist(&ProjectConfig::default(), &rules).expect("default allowlist")
});

const HEX: &[u8] = b"0123456789abcdef";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BENIGN: &str = "LANG=en_US.UTF-8 TERM=xterm-256color PATH=/usr/bin:/bin HOME=/home/u";

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn draw(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| char::from(alphabet[(self.next_u64() % alphabet.len() as u64) as usize]))
            .collect()
    }
}

/// mixed-case values are redrawn until they clear the entropy gate on their own, so the tests
/// exercise position rather than threshold luck.
fn high_entropy_alnum(generator: &mut SplitMix64, len: usize) -> String {
    loop {
        let value = generator.draw(ALNUM, len);
        if shannon_entropy(value.as_bytes()) >= 4.0 {
            return value;
        }
    }
}

/// credential-named variables with values in their services' realistic shapes: hex api keys,
/// alphanumeric api keys, and a 30-character app token.
fn shapes() -> Vec<(&'static str, String)> {
    let mut generator = SplitMix64(0x5eed_a26f_0000_0001);
    vec![
        ("VAST_AI_API_KEY", generator.draw(HEX, 64)),
        ("ZEROENTROPY_API_KEY", generator.draw(HEX, 32)),
        (
            "ZEROENTROPY_API_KEY",
            high_entropy_alnum(&mut generator, 32),
        ),
        (
            "ZEROENTROPY_API_KEY",
            high_entropy_alnum(&mut generator, 64),
        ),
        ("PUSHOVER_APP_TOKEN", high_entropy_alnum(&mut generator, 30)),
    ]
}

fn redact(text: &str) -> String {
    redact_text(text, &SCANNER, &ALLOWLIST)
}

/// every value replaced by the marker and nothing else touched.
fn expected(line: &str, values: &[&str]) -> String {
    values.iter().fold(line.to_owned(), |text, value| {
        text.replace(value, "[REDACTED]")
    })
}

fn assert_masked_exactly(line: &str, values: &[&str], context: &str) {
    let redacted = redact(line);
    for value in values {
        assert!(
            !redacted.contains(value),
            "{context}: a {}-byte value survived redaction",
            value.len()
        );
    }
    assert_eq!(
        redacted,
        expected(line, values),
        "{context}: redaction touched bytes outside the values"
    );
}

/// the positions a process listing prints an assignment in, from line start to deep inside argv.
fn positions(name: &str, value: &str) -> Vec<(&'static str, String)> {
    vec![
        ("alone", format!("{name}={value}")),
        ("export", format!("export {name}={value}")),
        (
            "env argv",
            format!(
                "41234 /usr/bin/env {BENIGN} {name}={value} /usr/local/bin/bundle exec jekyll serve --port 4000"
            ),
        ),
        (
            "shell wrapper argv",
            format!(
                "41234 /bin/zsh -c -l source /home/u/.cache/snapshot.sh && eval 'cd /home/u/site && {name}={value} bundle exec jekyll serve' < /dev/null"
            ),
        ),
        (
            "single-quoted value in argv",
            format!("41234 /bin/sh -c {name}='{value}' {BENIGN} jekyll serve"),
        ),
        (
            "double-quoted value in argv",
            format!("41234 /bin/sh -c {name}=\"{value}\" {BENIGN} jekyll serve"),
        ),
    ]
}

#[test]
fn credential_assignment_is_masked_alone_and_embedded_in_argv() {
    for (name, value) in shapes() {
        for (position, line) in positions(name, &value) {
            assert_masked_exactly(&line, &[&value], &format!("{name} ({position})"));
        }
    }
}

#[test]
fn quote_byte_earlier_on_the_line_does_not_hide_the_assignment() {
    for (name, value) in shapes() {
        let value = value.as_str();
        for (position, line) in [
            // an unquoted value carrying a quote byte pairs with the next assignment's quote.
            (
                "stray double quote",
                format!(
                    "41234 /usr/bin/ruby PS1=\"%n@%m {name}={value} PROMPT=\"%# \" jekyll serve"
                ),
            ),
            // a quoted phrase is not a value; the assignments inside it still are.
            (
                "single-quoted phrase",
                format!(
                    "41234 /usr/bin/ruby JEKYLL_ARGS='--trace {name}={value} --verbose' jekyll serve"
                ),
            ),
            (
                "double-quoted phrase",
                format!("41234 /bin/sh -c \"cd /home/u/site && {name}={value} jekyll serve\""),
            ),
        ] {
            assert_masked_exactly(&line, &[value], &format!("{name} ({position})"));
        }
    }
}

#[test]
fn every_credential_on_one_argv_line_is_masked() {
    let shapes = shapes();
    let assignments: Vec<String> = shapes
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    let line = format!(
        "41234 /usr/bin/env {BENIGN} {} /usr/local/bin/bundle exec jekyll serve --livereload",
        assignments.join(" ")
    );
    let values: Vec<&str> = shapes.iter().map(|(_, value)| value.as_str()).collect();
    assert_masked_exactly(&line, &values, "all shapes on one line");
}

#[test]
fn assignment_after_kilobytes_of_benign_pairs_is_masked() {
    let padding: Vec<String> = (0..200)
        .map(|index| format!("ACME_SETTING_{index}=value-{index}"))
        .collect();
    let padding = padding.join(" ");
    assert!(padding.len() > 4096);
    for (name, value) in shapes() {
        let line = format!("41234 /usr/bin/env {padding} {name}={value} {padding} jekyll serve");
        assert_masked_exactly(
            &line,
            &[&value],
            &format!("{name} (after {} bytes)", padding.len()),
        );
    }
}

#[test]
fn benign_argv_lines_are_unchanged() {
    for line in [
        format!(
            "41234 /usr/bin/env {BENIGN} /usr/local/bin/ruby -w /home/u/site/vendor/bundle/bin/jekyll serve --port 4000 --livereload"
        ),
        format!("41234 /bin/zsh -c -l source /home/u/.cache/snapshot.sh && eval 'cd /home/u/site && {BENIGN} bundle exec jekyll serve' < /dev/null"),
        // quoted phrases are rescanned for assignments; ordinary ones must still pass through.
        "41234 /bin/zsh -c PS1=\"%n@%m %1~ %# \" LESS='-R --mouse' EDITOR=vim jekyll serve --config _config.yml,_config.dev.yml".to_owned(),
        "41234 /usr/bin/ruby JEKYLL_ARGS='--trace --baseurl=/docs --port=4000' jekyll serve".to_owned(),
    ] {
        assert_eq!(redact(&line), line, "benign argv line was modified");
    }
}
