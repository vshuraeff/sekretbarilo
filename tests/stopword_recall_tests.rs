use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::scan;
use sekretbarilo::scanner::entropy::passes_entropy_check;
use sekretbarilo::scanner::rules::{CompiledScanner, Rule, compile_rules, load_default_rules};
use std::sync::LazyLock;

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
const HEX: &[u8] = b"0123456789abcdef";
type Case = (
    &'static str,
    &'static str,
    &'static str,
    &'static [u8],
    usize,
);

const CASES: &[Case] = &[
    (
        "aws-secret-access-key",
        "AWS_SECRET_ACCESS_KEY=\"",
        "\"",
        BASE64,
        40,
    ),
    (
        "infisical-client-id",
        "INFISICAL_CLIENT_ID=\"",
        "\"",
        URL,
        20,
    ),
    ("generic-secret-assignment", "SECRET=\"", "\"", BASE64, 32),
    ("http-bearer-token", "Authorization Bearer ", "", URL, 24),
    ("cloudflare-api-key", "cloudflare_api_key=\"", "\"", HEX, 37),
    ("datadog-api-key", "datadog_api_key=\"", "\"", HEX, 32),
    ("heroku-api-key", "heroku_api_key=\"", "\"", HEX, 32),
    (
        "wireguard-key-assignment",
        "PrivateKey=\"",
        "\"",
        BASE64,
        44,
    ),
    ("generic-api-key", "API_KEY=\"", "\"", BASE64, 32),
    ("discord-bot-token", "discord_token=\"", "\"", URL, 53),
    ("telegram-bot-token", "telegram_token=\"", "\"", URL, 46),
    ("mailchimp-api-key", "", "", HEX, 32),
    ("facebook-access-token", "", "", BASE62, 24),
    ("dropbox-api-token", "", "", URL, 100),
    ("launchdarkly-sdk-key", "", "", HEX, 32),
    ("azure-ad-client-secret", "client_secret=\"", "\"", URL, 34),
    (
        "azure-devops-pat",
        "azure_pat=\"",
        "\"",
        b"0123456789abcdefghijklmnopqrstuvwxyz",
        52,
    ),
    (
        "alibaba-secret-key",
        "alibaba_secret_key=\"",
        "\"",
        BASE62,
        30,
    ),
    (
        "mssql-connection-string",
        "Server=database.invalid;Password=",
        ";",
        BASE62,
        24,
    ),
    (
        "pagerduty-api-key",
        "pagerduty_api_key=\"",
        "\"",
        BASE64,
        24,
    ),
    ("circleci-api-token", "circleci_api_token=\"", "\"", HEX, 40),
    ("vercel-api-token", "vercel_api_token=\"", "\"", BASE62, 24),
    ("netlify-access-token", "netlify_token=\"", "\"", URL, 40),
    (
        "atlassian-api-token",
        "atlassian_api_token=\"",
        "\"",
        BASE62,
        24,
    ),
    (
        "twitter-bearer-token",
        "twitter_bearer_token=\"",
        "\"",
        BASE62,
        50,
    ),
    ("okta-api-token", "okta_api_token=\"", "\"", URL, 30),
    ("algolia-api-key", "algolia_api_key=\"", "\"", HEX, 32),
    ("elastic-api-key", "elastic_api_key=\"", "\"", URL, 30),
    ("splunk-hec-token", "splunk_hec_token=\"", "\"", HEX, 32),
    (
        "postmark-server-token",
        "postmark_server_token=\"",
        "\"",
        HEX,
        32,
    ),
    (
        "gitlab-deploy-token",
        "gitlab_deploy_token=\"",
        "\"",
        URL,
        24,
    ),
    ("cohere-api-key", "cohere_api_key=\"", "\"", BASE62, 40),
    ("generic-token-assignment", "TOKEN=\"", "\"", BASE64, 32),
];

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| load_default_rules().unwrap());

struct Random(u64);

impl Random {
    fn string(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                let index = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % alphabet.len() as u64;
                char::from(alphabet[index as usize])
            })
            .collect()
    }
}

fn rule(id: &str) -> Rule {
    RULES.iter().find(|rule| rule.id == id).unwrap().clone()
}

fn setup(rule: &Rule, stopwords: &[String]) -> (CompiledScanner, CompiledAllowlist) {
    let per_rule = vec![(
        rule.id.clone(),
        rule.allowlist.regexes.clone(),
        rule.allowlist.paths.clone(),
    )];
    (
        compile_rules(std::slice::from_ref(rule)).unwrap(),
        CompiledAllowlist::new(&[], stopwords, None, &per_rule, false).unwrap(),
    )
}

fn detects(
    line: &str,
    path: &str,
    scanner: &CompiledScanner,
    allowlist: &CompiledAllowlist,
) -> bool {
    let file = DiffFile {
        path: path.to_owned(),
        is_new: true,
        is_deleted: false,
        is_renamed: false,
        is_binary: false,
        context: None,
        added_lines: vec![AddedLine {
            line_number: 1,
            content: line.as_bytes().to_vec(),
        }],
    };
    !scan(&[file], scanner, allowlist).is_empty()
}

fn value(case: &Case, random: &mut Random, alphabet: &[u8]) -> String {
    match case.0 {
        "heroku-api-key"
        | "launchdarkly-sdk-key"
        | "splunk-hec-token"
        | "postmark-server-token" => {
            let mut value = random.string(alphabet, 32);
            value.replace_range(12..13, "4");
            value.replace_range(16..17, "8");
            for at in [20, 16, 12, 8] {
                value.insert(at, '-');
            }
            if case.0 == "launchdarkly-sdk-key" {
                format!("sdk-{value}")
            } else {
                value
            }
        }
        "wireguard-key-assignment" => format!(
            "{}{}=",
            random.string(alphabet, 42),
            random.string(b"AEIMQUYcgkosw048", 1)
        ),
        "discord-bot-token" => format!(
            "{}.{}.{}",
            random.string(b"0123456789", 18),
            random.string(alphabet, 6),
            random.string(alphabet, 27)
        ),
        "telegram-bot-token" => format!(
            "{}:{}",
            random.string(b"0123456789", 10),
            random.string(alphabet, 35)
        ),
        "mailchimp-api-key" => format!("{}-us1", random.string(alphabet, 32)),
        "facebook-access-token" => format!("EAA{}", random.string(alphabet, case.4)),
        "dropbox-api-token" => format!("sl.{}", random.string(alphabet, case.4)),
        _ => random.string(alphabet, case.4),
    }
}

#[test]
fn embedded_stopwords_in_opaque_values_are_detected_and_user_stopwords_still_apply() {
    let mut random = Random(0x6a09_e667_f3bc_c909);
    for case in CASES {
        // select by generated format so reverting a rule flag cannot remove its coverage.
        if case.3 == HEX || case.0 == "mssql-connection-string" {
            continue;
        }
        let rule = rule(case.0);
        assert_eq!(
            rule.builtin_stopwords,
            (case.0 == "wireguard-key-assignment").then_some(false),
            "unexpected built-in stopword override for {}",
            case.0
        );
        let (scanner, allowlist) = setup(&rule, &[]);
        let mut markers = vec![("xxx", "xXx")];
        if case.3 == BASE64 {
            markers.push(("/test+", "TeSt"));
        }
        if case.0.starts_with("generic-") {
            markers.push((".fake/", "FaKe"));
        }
        for (marker, user_word) in markers {
            let (_, user_allowlist) = setup(&rule, &[user_word.to_owned()]);
            for _ in 0..12 {
                let mut value = value(case, &mut random, case.3);
                let at = value.len() - marker.len() - 3;
                value.replace_range(at - 1..at, "q");
                value.replace_range(at..at + marker.len(), marker);
                value.replace_range(at + marker.len()..at + marker.len() + 1, "z");
                let line = format!("{}{value}{}", case.1, case.2);
                assert!(
                    !allowlist.contains_stopword(value.as_bytes()),
                    "accidental stopword still rejected for {}",
                    case.0
                );
                assert!(
                    detects(&line, "sample.txt", &scanner, &allowlist),
                    "opaque witness not detected for {}",
                    case.0
                );
                assert!(
                    !detects(&line, "sample.txt", &scanner, &user_allowlist),
                    "user stopword ignored for {}",
                    case.0
                );
            }
        }
    }
}

#[test]
fn credential_anchors_keep_the_same_entropy_gate_on_documentation_paths() {
    let mut random = Random(0xbb67_ae85_84ca_a73b);
    for case in CASES {
        let mut rule = rule(case.0);
        let (scanner, allowlist) = setup(&rule, &[]);
        let threshold = rule.entropy_threshold.unwrap();
        let alphabet = &case.3[..case.3.len().min(if threshold < 3.5 {
            12
        } else if threshold < 4.0 {
            20
        } else {
            64
        })];
        let witness = (0..4096)
            .find_map(|_| {
                let value = value(case, &mut random, alphabet);
                let line = format!("{}{value}{}", case.1, case.2);
                (passes_entropy_check(value.as_bytes(), threshold)
                    && !passes_entropy_check(
                        value.as_bytes(),
                        threshold + allowlist.doc_entropy_bonus(),
                    )
                    && detects(&line, "sample.txt", &scanner, &allowlist))
                .then_some(line)
            })
            .unwrap_or_else(|| panic!("no documentation entropy witness for {}", case.0));
        for path in ["docs/sample.md", "sample.rst", "README"] {
            assert!(
                detects(&witness, path, &scanner, &allowlist),
                "documentation witness lost for {}",
                case.0
            );
        }
        rule.doc_entropy_bonus = Some(true);
        let (legacy, _) = setup(&rule, &[]);
        assert!(
            !detects(&witness, "docs/sample.md", &legacy, &allowlist),
            "legacy documentation control did not reject {}",
            case.0
        );
    }
}

#[test]
fn whole_placeholders_stay_clean_under_token_and_password_rules() {
    let mut random = Random(0x3c6e_f372_fe94_f82b);
    for case in CASES {
        let (scanner, allowlist) = setup(&rule(case.0), &[]);
        let repeated = if case.3 == HEX {
            b"a".as_slice()
        } else {
            b"x".as_slice()
        };
        let placeholder = value(case, &mut random, repeated);
        let line = format!("{}{placeholder}{}", case.1, case.2);
        assert!(
            !detects(&line, "docs/sample.md", &scanner, &allowlist),
            "repeated placeholder reported for {}",
            case.0
        );
    }
    for id in [
        "generic-secret-assignment",
        "generic-api-key",
        "generic-token-assignment",
        "generic-password-assignment",
    ] {
        let (scanner, allowlist) = setup(&rule(id), &[]);
        let key = match id {
            "generic-api-key" => "API_KEY",
            "generic-token-assignment" => "TOKEN",
            "generic-password-assignment" => "PASSWORD",
            _ => "SECRET",
        };
        for placeholder in ["xxxx", "xxxxxxxxxxxxxxxx", "your-api-key-here", "changeme"] {
            for path in ["sample.txt", "docs/sample.md"] {
                let line = format!("{key}=\"{placeholder}\"");
                assert!(
                    !detects(&line, path, &scanner, &allowlist),
                    "whole placeholder reported for {id}"
                );
            }
        }
    }
}

#[test]
fn generated_placeholder_families_cover_every_builtin_word() {
    let words = [
        "example",
        "test",
        "sample",
        "placeholder",
        "dummy",
        "changeme",
        "fake",
        "mock",
        "todo",
        "fixme",
        "xxx",
        "lorem",
        "default",
        "replace_me",
        "insert_here",
        "your_",
        "my_",
        "your-",
        "my-",
        "<your",
    ];
    let mut random = Random(0x510e_527f_ade6_82d1);
    for (id, key) in [
        ("generic-api-key", "API_KEY"),
        ("generic-token-assignment", "TOKEN"),
        ("generic-secret-assignment", "SECRET"),
    ] {
        let mut rule = rule(id);
        let (scanner, allowlist) = setup(&rule, &[]);
        rule.builtin_stopwords = Some(false);
        let (without_builtin, _) = setup(&rule, &[]);
        for word in words {
            let mut eligible = 0;
            let mut reported = 0;
            for _ in 0..128 {
                let placeholder = format!("{word}_credential_{}", random.string(BASE62, 32));
                let line = format!("{key}=\"{placeholder}\"");
                eligible += usize::from(detects(&line, "config.py", &without_builtin, &allowlist));
                for path in ["config.py", "README.md"] {
                    reported += usize::from(detects(&line, path, &scanner, &allowlist));
                }
            }
            assert!(
                eligible > 0,
                "no otherwise-eligible placeholder for {id}/{word}"
            );
            assert_eq!(reported, 0, "placeholder family reported for {id}/{word}");
            eprintln!(
                "placeholder rule={id} word={word} N=128 otherwise_eligible={eligible} reported_on_two_paths={reported}"
            );
        }
    }
}

#[test]
fn reported_documentation_placeholder_shapes_remain_clean() {
    let mut random = Random(0x9b05_688c_2b3e_6c1f);
    for (id, key, prefix, alphabet, length) in [
        ("generic-api-key", "API_KEY", "sample_api_key_", BASE62, 16),
        (
            "generic-token-assignment",
            "TOKEN",
            "your_token_goes_here_",
            BASE62,
            8,
        ),
        (
            "generic-secret-assignment",
            "client_secret",
            "test-client-secret-",
            HEX,
            12,
        ),
        (
            "generic-secret-assignment",
            "SECRET",
            "dummy-secret-value-for-docs-",
            b"0123456789",
            4,
        ),
    ] {
        let mut rule = rule(id);
        let (scanner, allowlist) = setup(&rule, &[]);
        rule.builtin_stopwords = Some(false);
        let (without_builtin, _) = setup(&rule, &[]);
        let mut eligible = 0;
        let mut reported = 0;
        for _ in 0..256 {
            let placeholder = format!("{prefix}{}", random.string(alphabet, length));
            let line = format!("{key}=\"{placeholder}\"");
            eligible += usize::from(detects(&line, "config.py", &without_builtin, &allowlist));
            for path in ["config.py", "README.md"] {
                reported += usize::from(detects(&line, path, &scanner, &allowlist));
            }
        }
        assert!(
            eligible > 0,
            "no otherwise-eligible reported shape for {key}"
        );
        assert_eq!(reported, 0, "reported placeholder regression for {key}");
        eprintln!(
            "documented-placeholder key={key} N=256 otherwise_eligible={eligible} reported_on_two_paths={reported}"
        );
    }
}

#[test]
fn user_and_signature_placeholder_contracts_keep_their_legacy_boundaries() {
    let default = CompiledAllowlist::default_allowlist().unwrap();
    let user_x = CompiledAllowlist::new(&[], &["xXx".to_owned()], None, &[], false).unwrap();
    let user_word = CompiledAllowlist::new(&[], &["TeSt".to_owned()], None, &[], false).unwrap();
    let mut random = Random(0x1f83_d9ab_fb41_bd6b);
    let mut embedded = random.string(BASE62, 40);
    embedded.replace_range(18..21, "xxx");
    assert!(!default.contains_stopword(embedded.as_bytes()));
    assert!(user_x.contains_stopword(embedded.as_bytes()));
    assert!(default.is_placeholder_pattern(embedded.as_bytes()));
    let delimited = format!(
        "{}/test+{}",
        random.string(BASE62, 16),
        random.string(BASE62, 16)
    );
    assert!(!default.contains_stopword(delimited.as_bytes()));
    assert!(user_word.contains_stopword(delimited.as_bytes()));
    assert!(user_word.contains_user_stopword(delimited.as_bytes()));

    let (scanner, allowlist) = setup(&rule("generic-api-key"), &[]);
    for marker in ["_test_", "-fake-", "_xxx_"] {
        let value = format!(
            "{}{marker}{}",
            random.string(URL, 20),
            random.string(URL, 20)
        );
        assert!(allowlist.contains_stopword(value.as_bytes()));
        assert!(!detects(
            &format!("API_KEY=\"{value}\""),
            "config.py",
            &scanner,
            &allowlist
        ));
    }
}

#[test]
fn custom_rules_keep_builtin_defaults_with_the_narrower_placeholder_policy() {
    let mut custom = rule("generic-api-key");
    custom.id = "custom-stopword-policy".to_owned();
    custom.builtin_stopwords = None;
    custom.doc_entropy_bonus = None;
    let (scanner, allowlist) = setup(&custom, &[]);
    assert!(scanner.rules[0].builtin_stopwords);
    assert!(scanner.rules[0].doc_entropy_bonus);
    let mut random = Random(0x5be0_cd19_137e_2179);
    let mut opaque = random.string(BASE62, 40);
    opaque.replace_range(18..21, "xxx");
    assert!(detects(
        &format!("API_KEY=\"{opaque}\""),
        "config.py",
        &scanner,
        &allowlist
    ));
    let placeholder = format!("sample_api_key_{}", random.string(BASE62, 32));
    assert!(!detects(
        &format!("API_KEY=\"{placeholder}\""),
        "config.py",
        &scanner,
        &allowlist
    ));
}

#[test]
fn non_base64_punctuation_still_delimits_builtin_placeholder_words() {
    let shapes: [(&str, &str, usize); 7] = [
        ("[example-token-", "]", 12),
        ("test:", "", 16),
        ("(sample-api-key-", ")", 12),
        ("test@", "", 16),
        ("mock,", "", 16),
        ("*placeholder*", "", 12),
        ("#dummy#", "", 16),
    ];
    let mut random = Random(0x428a_2f98_d728_ae22);
    for (id, key) in [
        ("generic-api-key", "API_KEY"),
        ("generic-token-assignment", "TOKEN"),
        ("generic-secret-assignment", "SECRET"),
    ] {
        let mut rule = rule(id);
        let (scanner, allowlist) = setup(&rule, &[]);
        rule.builtin_stopwords = Some(false);
        let (without_builtin, _) = setup(&rule, &[]);
        for (prefix, suffix, length) in shapes {
            let mut eligible = 0;
            let mut reported = 0;
            for _ in 0..64 {
                let placeholder = format!("{prefix}{}{suffix}", random.string(BASE62, length));
                let line = format!("{key}=\"{placeholder}\"");
                eligible += usize::from(detects(&line, "config.py", &without_builtin, &allowlist));
                for path in ["config.py", "README.md"] {
                    reported += usize::from(detects(&line, path, &scanner, &allowlist));
                }
            }
            assert!(
                eligible > 0,
                "no otherwise-eligible placeholder for {id}/{prefix}"
            );
            assert_eq!(
                reported, 0,
                "punctuation placeholder reported for {id}/{prefix}"
            );
        }
    }
}

fn encode_basic(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let word = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0] {
            encoded.push(
                if (shift == 6 && chunk.len() < 2) || (shift == 0 && chunk.len() < 3) {
                    '='
                } else {
                    char::from(BASE64[((word >> shift) & 63) as usize])
                },
            );
        }
    }
    encoded
}

#[test]
fn genuine_basic_credentials_keep_path_parity_including_password_colons() {
    let mut random = Random(0xa54f_f53a_5f1d_36f1);
    let mut rule = rule("http-basic-auth");
    let (scanner, allowlist) = setup(&rule, &[]);
    rule.doc_entropy_bonus = Some(true);
    let (legacy, _) = setup(&rule, &[]);
    let mut total_gaps = 0;
    for (name, alphabet) in [
        ("letters", b"ab".as_slice()),
        ("punctuation-colons", b":!?@#$%&+"),
        ("mixed", BASE62),
    ] {
        let mut normal = 0;
        let mut gaps = 0;
        for sample in 0..1000 {
            let username = random.string(b"abc", 4 + sample % 7);
            let password = random.string(alphabet, 12 + sample % 9);
            let encoded = encode_basic(format!("{username}:{password}").as_bytes());
            let line = format!("Authorization Basic {encoded}");
            if detects(&line, "sample.txt", &scanner, &allowlist) {
                normal += 1;
                assert!(
                    detects(&line, "docs/sample.md", &scanner, &allowlist),
                    "genuine Basic credential lost on documentation path in {name}"
                );
                gaps += usize::from(!detects(&line, "docs/sample.md", &legacy, &allowlist));
            }
        }
        assert!(
            normal > 0,
            "no eligible genuine Basic credentials in {name}"
        );
        eprintln!(
            "genuine Basic family={name} N=1000 normal={normal} legacy_doc_loss={gaps} new_doc_loss=0"
        );
        total_gaps += gaps;
    }
    assert!(
        total_gaps > 0,
        "no genuine Basic documentation-bonus loss witnessed"
    );
}
