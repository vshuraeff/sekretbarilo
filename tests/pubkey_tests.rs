// integration tests for public key recognition and false positive prevention

use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::config::{self, ProjectConfig, SettingsConfig};
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine;
use sekretbarilo::scanner::rules::{self, compile_rules};

fn default_allowlist() -> CompiledAllowlist {
    CompiledAllowlist::default_allowlist().unwrap()
}

fn detect_pubkeys_allowlist() -> CompiledAllowlist {
    CompiledAllowlist::new(&[], &[], None, &[], true).unwrap()
}

fn make_file(path: &str, lines: Vec<(usize, &[u8])>) -> DiffFile {
    DiffFile {
        path: path.to_string(),
        is_new: false,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        added_lines: lines
            .into_iter()
            .map(|(num, content)| AddedLine {
                line_number: num,
                content: content.to_vec(),
            })
            .collect(),
    }
}

fn default_scanner() -> sekretbarilo::scanner::rules::CompiledScanner {
    let rules = rules::load_default_rules().unwrap();
    compile_rules(&rules).unwrap()
}

// -- PEM public key block suppression --

#[test]
fn pem_public_key_block_not_flagged() {
    let scanner = default_scanner();
    let al = default_allowlist();

    // base64 body contains "EAA" which triggers facebook-access-token, and high-entropy
    // content that triggers generic-api-key. should be suppressed inside public key block.
    let file = make_file(
        "config/pubkey.pem",
        vec![
            (1, b"-----BEGIN PUBLIC KEY-----"),
            (2, b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
            (3, b"sK5yEAAmj3TyBqMZ0qs3O5EAA0VdV8a6NzC5Y4Y+zP2H"),
            (4, b"qR8n+8V4bDeujfI3jMDZGKy+8fWw3J+nJQKj8EEhPfVt"),
            (5, b"-----END PUBLIC KEY-----"),
        ],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "PEM public key block should not produce findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn rsa_public_key_block_not_flagged() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        "keys/id_rsa.pub",
        vec![
            (1, b"-----BEGIN RSA PUBLIC KEY-----"),
            (2, b"MIIBCgKCAQEA4E0YOZ/sMVBzZAGkzU5wHf2HrFHG3qPz"),
            (3, b"-----END RSA PUBLIC KEY-----"),
        ],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "RSA public key block should not produce findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// -- PGP public key block suppression --

#[test]
fn pgp_public_key_block_not_flagged() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        "gpg/pubkey.asc",
        vec![
            (1, b"-----BEGIN PGP PUBLIC KEY BLOCK-----"),
            (2, b"mQENBGXYz8kBCAC7U+EAAkG8m9TRp+uD5BJ7qP9G"),
            (3, b"=wN8f"),
            (4, b"-----END PGP PUBLIC KEY BLOCK-----"),
        ],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "PGP public key block should not produce findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// -- OpenSSH public key suppression --

#[test]
fn openssh_rsa_public_key_not_flagged() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        "authorized_keys",
        vec![(
            1,
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3FUn9G2Xe6EAAmq/gT5R8K+Pw user@host",
        )],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "OpenSSH RSA public key should not produce findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn openssh_ed25519_public_key_not_flagged() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        ".ssh/authorized_keys",
        vec![(
            1,
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcK5y3EAAqr9T+wP user@host",
        )],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "OpenSSH ed25519 public key should not produce findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn openssh_ecdsa_public_key_not_flagged() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        ".ssh/id_ecdsa.pub",
        vec![(
            1,
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY user@host",
        )],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "OpenSSH ECDSA public key should not produce findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// -- private keys MUST still be detected --

#[test]
fn pem_private_key_still_detected() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        "secrets/key.pem",
        vec![
            (1, b"-----BEGIN RSA PRIVATE KEY-----"),
            (2, b"MIIEpAIBAAKCAQEA4E0YOZ/sMVBzZAGkzU5wHf2HrFHG"),
            (3, b"-----END RSA PRIVATE KEY-----"),
        ],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.iter().any(|f| f.rule_id == "pem-private-key"),
        "private key should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn pgp_private_key_still_detected() {
    let scanner = default_scanner();
    let al = default_allowlist();

    let file = make_file(
        "secrets/pgp.asc",
        vec![
            (1, b"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            (2, b"lQOYBGXYz8kBCAC7U+W5q2k"),
            (3, b"-----END PGP PRIVATE KEY BLOCK-----"),
        ],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "pgp-private-key-block"),
        "PGP private key block should be detected, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// -- detect_public_keys = true: public keys ARE flagged --

#[test]
fn pem_public_key_detected_when_enabled() {
    let scanner = default_scanner();
    let al = detect_pubkeys_allowlist();

    let file = make_file(
        "config/pubkey.pem",
        vec![
            (1, b"-----BEGIN PUBLIC KEY-----"),
            (2, b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
            (3, b"-----END PUBLIC KEY-----"),
        ],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.iter().any(|f| f.rule_id == "pem-public-key"),
        "public key should be detected when detect_public_keys=true, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn openssh_public_key_detected_when_enabled() {
    let scanner = default_scanner();
    let al = detect_pubkeys_allowlist();

    let file = make_file(
        "authorized_keys",
        vec![(
            1,
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3FUn9G2Xe6EAAmq/gT5R8K+Pw user@host",
        )],
    );

    let findings = engine::scan(&[file], &scanner, &al);
    assert!(
        findings.iter().any(|f| f.rule_id == "openssh-public-key"),
        "OpenSSH public key should be detected when detect_public_keys=true, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// -- config parsing --

#[test]
fn config_detect_public_keys_parsing() {
    let toml = r#"
[settings]
detect_public_keys = true
"#;
    let config: ProjectConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.settings.detect_public_keys, Some(true));
}

#[test]
fn config_detect_public_keys_default_is_none() {
    let toml = "[settings]\n";
    let config: ProjectConfig = toml::from_str(toml).unwrap();
    assert!(config.settings.detect_public_keys.is_none());
}

#[test]
fn config_detect_public_keys_merge_overlay_wins() {
    use sekretbarilo::config::merge::merge_two;

    let base = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: None,
            detect_public_keys: Some(false),
        },
        ..Default::default()
    };
    let overlay = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: None,
            detect_public_keys: Some(true),
        },
        ..Default::default()
    };
    let merged = merge_two(base, overlay);
    assert_eq!(merged.settings.detect_public_keys, Some(true));
}

#[test]
fn config_detect_public_keys_base_preserved_when_overlay_none() {
    use sekretbarilo::config::merge::merge_two;

    let base = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: None,
            detect_public_keys: Some(true),
        },
        ..Default::default()
    };
    let overlay = ProjectConfig::default();
    let merged = merge_two(base, overlay);
    assert_eq!(merged.settings.detect_public_keys, Some(true));
}

// -- build_allowlist passes detect_public_keys --

#[test]
fn build_allowlist_detect_public_keys_false_by_default() {
    let config = ProjectConfig::default();
    let al = config::build_allowlist(&config, &[]).unwrap();
    assert!(!al.detect_public_keys);
}

#[test]
fn build_allowlist_detect_public_keys_true_when_set() {
    let config = ProjectConfig {
        settings: SettingsConfig {
            entropy_threshold: None,
            detect_public_keys: Some(true),
        },
        ..Default::default()
    };
    let al = config::build_allowlist(&config, &[]).unwrap();
    assert!(al.detect_public_keys);
}
