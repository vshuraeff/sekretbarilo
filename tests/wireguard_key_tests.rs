//! `wireguard-key-assignment`: a WireGuard or AmneziaWG preshared or private key under its key
//! name, detected with the default configuration (heuristic rule off) on the text surface of the
//! agent hooks and on the diff surface of the pre-commit scan. every key is generated here, so the
//! repository never stores one.

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{ProjectConfig, build_allowlist, load_rules_with_config};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{redact_text, scan, scan_text};
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules};

const RULE: &str = "wireguard-key-assignment";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn defaults() -> (CompiledScanner, CompiledAllowlist, f64) {
    let config = ProjectConfig::default();
    let rules = load_rules_with_config(&config).unwrap();
    let threshold = rules
        .iter()
        .find(|rule| rule.id == RULE)
        .and_then(|rule| rule.entropy_threshold)
        .unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    (compile_rules(&rules).unwrap(), allowlist, threshold)
}

/// the base64 form of 32 random bytes, as `wg genkey`, `wg genpsk` and `openssl rand -base64 32`
/// print it: 42 free symbols, a 43rd whose two low bits are zero, and one `=`.
fn wg_key(state: &mut u64) -> String {
    let mut next = || {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    };
    let mut key: String = (0..42)
        .map(|_| char::from(B64[(next() >> 58) as usize]))
        .collect();
    key.push(char::from(B64[((next() >> 60) as usize) * 4]));
    key.push('=');
    key
}

fn key(seed: u64) -> String {
    wg_key(&mut (seed | 1))
}

fn diff_file(text: &str) -> DiffFile {
    diff_file_at("group_vars/vpn.yml", text)
}

fn diff_file_at(path: &str, text: &str) -> DiffFile {
    DiffFile {
        path: path.to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: text
            .lines()
            .enumerate()
            .map(|(index, line)| AddedLine {
                line_number: index + 1,
                content: line.as_bytes().to_vec(),
            })
            .collect(),
    }
}

/// every key in `text` is a finding of the rule with exactly its range on the text surface and
/// its bytes on the diff surface, and redaction replaces the keys and nothing else.
fn assert_masked(text: &str, keys: &[&str]) {
    let (scanner, allowlist, _) = defaults();
    let found = scan_text(text, &scanner, &allowlist);
    let mut expected = text.to_string();
    for key in keys {
        let start = text.find(key).unwrap();
        assert!(
            found
                .iter()
                .any(|matched| matched.rule_id == RULE
                    && matched.range == (start..start + key.len())),
            "{RULE} missed the key in {text:?}: {found:?}"
        );
        expected = expected.replace(key, "[REDACTED]");
    }
    assert_eq!(redact_text(text, &scanner, &allowlist), expected);
    let findings = scan(&[diff_file(text)], &scanner, &allowlist);
    for key in keys {
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == RULE && finding.matched_value == key.as_bytes()),
            "diff scan missed the key in {text:?}"
        );
    }
}

/// no rule reports anything under the default configuration, on either surface.
fn assert_clear(text: &str) {
    let (scanner, allowlist, _) = defaults();
    let found = scan_text(text, &scanner, &allowlist);
    assert!(
        found.is_empty(),
        "unexpected finding in {text:?}: {found:?}"
    );
    let findings = scan(&[diff_file(text)], &scanner, &allowlist);
    assert!(
        findings.is_empty(),
        "unexpected diff finding in {text:?}: {:?}",
        findings
            .iter()
            .map(|finding| &finding.rule_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn key_names_and_value_forms_are_detected_and_only_the_value_is_masked() {
    let key = key(0x5EED_0001);
    for template in [
        // ansible failed-task output, the json of a loop item
        r#"failed: [h] (item=awg0) => {"mode": "server", "psk": "{K}", "nat": false}"#,
        // the same json encoded once more inside a json string, and twice
        r#"{"msg": "{\"mode\": \"server\", \"psk\": \"{K}\", \"nat\": false}"}"#,
        r#"{"msg": "{\"stdout\": \"{\\\"psk\\\": \\\"{K}\\\"}\"}"}"#,
        // json-printed command output: a line break is the `\n` escape before a lowercase name
        r#"{"stdout": "[wireguard]\nprivate-key={K}\n"}"#,
        r#"{"stdout": "[wireguard-peer.x]\npreshared-key={K}\n"}"#,
        r#"{"stdout": "x\npsk: {K}"}"#,
        r#"{"stdout": "x\nprivate_key: {K}"}"#,
        r#"{"stdout": "x\r\npsk: {K}"}"#,
        r#"{"stdout": "\tpsk = {K}"}"#,
        // a failed result that quotes a template expression on the same line
        r#"failed: [h] (item=awg0) => {"psk": "{K}", "msg": "with_items:\n - {{ foo }}"}"#,
        r#"{"preshared_key": "{K}"}"#,
        r#"{"private_key": "{K}"}"#,
        r#"{"privateKey":"{K}"}"#,
        "{'psk': '{K}', 'nat': False}",
        "  psk: {K}",
        "- psk: {K}",
        r#"private_key: "{K}""#,
        "private_key: '{K}'",
        "PresharedKey = {K}",
        "PrivateKey = {K}",
        "PrivateKey={K}",
        "  preshared key: {K}",
        "  private key: {K}",
        "preshared-key = {K}",
        "presharedkey={K}",
        "PRIVATE-KEY: {K}",
        "privatekey={K}",
        "PSK:{K}",
        "sops_amneziawg_awg0_psk: {K}",
        r#"wireguard_private_key: "{K}""#,
        "AWG_PRESHARED_KEY={K}",
        "export WG_PRIVATE_KEY={K}",
        r#"peerPresharedKey: "{K}""#,
        "interfacePrivateKey = {K}",
        "_psk={K}",
        r#"peer_psk := "{K}""#,
        r#"cfg['private_key'] = '{K}'"#,
        "wg set wg0 --psk={K} peer",
        "psk={K},nat=false",
        "psk: {K} # rotated",
        "psk: {K}\r",
    ] {
        assert_masked(&template.replace("{K}", &key), &[&key]);
    }
}

#[test]
fn several_keys_in_one_text_are_each_masked() {
    let first = key(0x5EED_0002);
    let second = key(0x5EED_0003);
    assert_masked(
        &format!(
            "[Interface]\nPrivateKey = {first}\nListenPort = 51820\n\n[Peer]\nPresharedKey = {second}\n"
        ),
        &[&first, &second],
    );
    assert_masked(
        &format!("psk={first},private_key={second}"),
        &[&first, &second],
    );
    assert_masked(
        &format!(r#"{{"psk": "{first}", "private_key": "{second}"}}"#),
        &[&first, &second],
    );
    // json-printed output: the boundary byte after an unquoted key is the `\` of the escape that
    // leads the next name
    for template in [
        r#"{"stdout": "x\npsk: {A}\npsk: {B}"}"#,
        r#"{"stdout": "x\nprivate_key: {A}\npsk: {B}"}"#,
        r#"{"stdout": "[wireguard]\nprivate-key={A}\npreshared-key={B}\n"}"#,
        r#"{"stdout":"psk={A}\npsk={B}"}"#,
        r#"{"stdout":"psk={A}\tpsk={B}\r\npsk={A}"}"#,
    ] {
        assert_masked(
            &template.replace("{A}", &first).replace("{B}", &second),
            &[&first, &second],
        );
    }
}

#[test]
fn public_keys_hidden_values_references_and_other_names_stay_clear() {
    let key = key(0x5EED_0004);
    for template in [
        "PublicKey = {K}",
        "public_key: {K}",
        r#"peer_public_key: "{K}""#,
        r#""publicKey": "{K}""#,
        "peerPublicKey: {K}",
        "WGPublicKey = {K}",
        "checksum: {K}",
        "psk_file: {K}",
        "private_key_path = {K}",
        "pskfile={K}",
        "xpsk = {K}",
        "mypsk: {K}",
        r#"{"stdout": "x\npsk_file: {K}"}"#,
        r#"{"stdout": "x\nmypsk: {K}"}"#,
        r#"{"stdout": "x\npublic_key: {K}"}"#,
    ] {
        assert_clear(&template.replace("{K}", &key));
    }
    for line in [
        "  preshared key: (hidden)",
        "  private key: (hidden)",
        "psk_file: /etc/x.psk",
        r#"private_key_path: "/etc/wireguard/x.key""#,
        r#"private_key: "{{ sops_x }}""#,
        "psk: !vault |",
        "psk: ${WG_PSK}",
    ] {
        assert_clear(line);
    }
}

#[test]
fn values_off_the_exact_key_shape_stay_clear() {
    let (scanner, allowlist, _) = defaults();
    let key = key(0x5EED_0005);
    let body = &key[..43];
    for value in [
        // one symbol short, one symbol long, no padding, double padding, padding inside a run
        format!("{}=", &body[..42]),
        format!("{body}A="),
        body.to_string(),
        format!("{body}A"),
        format!("{}==", &body[..42]),
        format!("{key}A"),
        format!("{key}="),
        format!("{key}/x"),
        format!("A{key}"),
        format!("{}-{}=", &body[..20], &body[21..]),
    ] {
        for form in [
            "psk: VALUE",
            r#"psk: "VALUE""#,
            "psk: 'VALUE'",
            "PresharedKey = VALUE",
        ] {
            let text = form.replace("VALUE", &value);
            assert!(
                !scan_text(&text, &scanner, &allowlist)
                    .iter()
                    .any(|matched| matched.rule_id == RULE),
                "{text:?}"
            );
        }
    }
}

#[test]
fn single_symbol_placeholders_stay_clear() {
    for symbol in ['A', 'a', '0', '/'] {
        let placeholder = format!("{}=", symbol.to_string().repeat(43));
        for form in [
            "PresharedKey = VALUE",
            r#"{"psk": "VALUE"}"#,
            "private_key: 'VALUE'",
        ] {
            assert_clear(&form.replace("VALUE", &placeholder));
        }
    }
}

/// the threshold claim: no random key falls below it, while a placeholder of one or two symbols
/// does. the recall claim: every generated key is a finding, on the text surface and in a
/// documentation file of a diff, including the keys that hold a built-in stopword (a run of three
/// `x`, a delimited `/test+`) or measure below the threshold a documentation file would raise.
#[test]
fn every_random_key_clears_the_entropy_threshold_and_is_detected() {
    let (scanner, allowlist, threshold) = defaults();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut lowest = f64::MAX;
    for _ in 0..200_000 {
        lowest = lowest.min(shannon_entropy(wg_key(&mut state).as_bytes()));
    }
    assert!(
        lowest >= threshold + 0.5,
        "lowest key entropy {lowest} is too close to the {threshold} threshold"
    );
    let two_symbols = format!("{}=", "AB".repeat(21) + "A");
    assert!(shannon_entropy(two_symbols.as_bytes()) < threshold);

    let doc_threshold = threshold + allowlist.doc_entropy_bonus();
    let keys: Vec<String> = (0..10_000).map(|_| wg_key(&mut state)).collect();
    let mut with_legacy_x_run = 0;
    let mut below_doc_threshold = 0;
    for key in &keys {
        with_legacy_x_run += usize::from(allowlist.is_placeholder_pattern(key.as_bytes()));
        below_doc_threshold += usize::from(shannon_entropy(key.as_bytes()) < doc_threshold);
        let text = format!(r#"{{"psk": "{key}"}}"#);
        assert!(
            scan_text(&text, &scanner, &allowlist)
                .iter()
                .any(|matched| matched.rule_id == RULE),
            "missed a random key"
        );
    }
    // the seed covers embedded x/X runs and values below the old documentation margin.
    assert!(with_legacy_x_run > 0 && below_doc_threshold > 0);

    let doc: String = keys.iter().map(|key| format!("psk: {key}\n")).collect();
    let findings = scan(&[diff_file_at("docs/vpn.md", &doc)], &scanner, &allowlist);
    let found: std::collections::HashSet<&[u8]> = findings
        .iter()
        .filter(|finding| finding.rule_id == RULE)
        .map(|finding| finding.matched_value.as_slice())
        .collect();
    assert!(
        keys.iter().all(|key| found.contains(key.as_bytes())),
        "missed a random key in a documentation file"
    );
}

/// a name led by an acronym (`WGPrivateKey`, `AWGPsk`) is read like any camel name; an all-caps
/// run into `PSK` therefore is too, while a lowercase run into `psk` and a public key are not.
#[test]
fn acronym_prefixed_camel_names_are_read() {
    let (scanner, allowlist, _) = defaults();
    let key = key(0x5EED_0006);
    let found = |template: &str| {
        scan_text(&template.replace("{K}", &key), &scanner, &allowlist)
            .iter()
            .any(|matched| matched.rule_id == RULE)
    };
    let unread: Vec<_> = [
        "WGPrivateKey = {K}",
        "AWGPsk: {K}",
        "wgPSK={K}",
        "AWGPresharedKey: \"{K}\"",
        "peerPresharedKey: {K}",
        "WGPSK={K}",
    ]
    .into_iter()
    .filter(|template| !found(template))
    .collect();
    assert!(unread.is_empty(), "not read: {unread:?}");
    for template in [
        "mypsk: {K}",
        "xpsk = {K}",
        "pskfile={K}",
        "PublicKey = {K}",
        "peerPublicKey: {K}",
        "WGPublicKey = {K}",
        "WGPskFile = {K}",
    ] {
        assert!(!found(template), "{template} read");
    }
}

/// the built-in word stopwords do not apply to the rule, a user's own stopword does, as a plain
/// substring of the key.
#[test]
fn a_user_stopword_suppresses_the_rule_as_a_substring() {
    let key = key(0x5EED_0007);
    let text = format!(r#"{{"psk": "{key}"}}"#);
    let mut config = ProjectConfig::default();
    config.allowlist.stopwords = vec![key[8..20].to_lowercase()];
    let rules = load_rules_with_config(&config).unwrap();
    let allowlist = build_allowlist(&config, &rules).unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let reported = |allowlist: &CompiledAllowlist| {
        scan_text(&text, &scanner, allowlist)
            .iter()
            .any(|matched| matched.rule_id == RULE)
    };
    assert!(
        !reported(&allowlist),
        "a user stopword did not suppress the key"
    );
    assert!(
        reported(&defaults().1),
        "the key is not a finding without the stopword"
    );
}
