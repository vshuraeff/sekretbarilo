use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::scan;
use sekretbarilo::scanner::entropy::passes_entropy_check;
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};
use std::collections::BTreeSet;
use std::time::Instant;

const SEED: u64 = 0x6a09_e667_f3bc_c909;
const SAMPLES: usize = 20_000;
const BATCH: usize = 1_000;
const HEX: &[u8] = b"0123456789abcdef";
const BASE36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const AZURE: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~._-";
const TWITTER: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz%";

struct Random(u64);

impl Random {
    fn index(&mut self, length: usize) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % length as u64) as usize
    }

    fn string(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(alphabet[self.index(alphabet.len())]))
            .collect()
    }

    fn uuid(&mut self) -> String {
        let mut value = self.string(HEX, 32);
        value.replace_range(12..13, "4");
        value.replace_range(16..17, &self.string(b"89ab", 1));
        for at in [20, 16, 12, 8] {
            value.insert(at, '-');
        }
        value
    }
}

struct Profile<'a> {
    name: &'a str,
    alphabet: &'a [u8],
    length: usize,
}

fn profiles(id: &str) -> Vec<Profile<'static>> {
    let (name, alphabet, length) = match id {
        "aws-secret-access-key" => ("base64", BASE64, 40),
        "infisical-client-id" | "http-bearer-token" | "gitlab-deploy-token" => {
            ("base64url", BASE64URL, 20)
        }
        "http-basic-auth" => ("base64-syntax", BASE64, 32),
        "cloudflare-api-key" => ("hex", HEX, 37),
        "datadog-api-key" | "algolia-api-key" | "mailchimp-api-key" => ("hex", HEX, 32),
        "circleci-api-token" => ("hex", HEX, 40),
        "heroku-api-key"
        | "launchdarkly-sdk-key"
        | "splunk-hec-token"
        | "postmark-server-token" => ("uuid-v4", HEX, 36),
        "wireguard-key-assignment" => ("base64-32-bytes", BASE64, 44),
        "discord-bot-token" => ("discord-shape", BASE64URL, 53),
        "telegram-bot-token" => ("telegram-shape", BASE64URL, 46),
        "facebook-access-token" => ("base62", BASE62, 20),
        "dropbox-api-token" => ("base64url", BASE64URL, 100),
        "azure-ad-client-secret" => ("azure-alphabet", AZURE, 34),
        "azure-devops-pat" => ("base36", BASE36, 52),
        "alibaba-secret-key" => ("base62", BASE62, 30),
        "mssql-connection-string" => ("base62", BASE62, 16),
        "pagerduty-api-key" => ("base64", BASE64, 20),
        "vercel-api-token" | "atlassian-api-token" => ("base62", BASE62, 24),
        "netlify-access-token" => ("base64url", BASE64URL, 40),
        "twitter-bearer-token" => ("twitter-alphabet", TWITTER, 50),
        "okta-api-token" | "elastic-api-key" => ("base64url", BASE64URL, 30),
        "cohere-api-key" => ("base62", BASE62, 40),
        "generic-secret-assignment"
        | "generic-api-key"
        | "generic-token-assignment"
        | "generic-high-entropy-value" => {
            let mut profiles: Vec<_> = [16, 20, 32, 40, 64]
                .into_iter()
                .map(|length| Profile {
                    name: "base64",
                    alphabet: BASE64,
                    length,
                })
                .collect();
            for (name, alphabet) in [("base64url", BASE64URL), ("base62", BASE62), ("hex", HEX)] {
                profiles.push(Profile {
                    name,
                    alphabet,
                    length: 32,
                });
            }
            return profiles;
        }
        _ => panic!("missing measurement profile for {id}"),
    };
    vec![Profile {
        name,
        alphabet,
        length,
    }]
}

fn generate(id: &str, profile: &Profile<'_>, random: &mut Random) -> (String, String) {
    let value = match profile.name {
        "uuid-v4" => random.uuid(),
        "base64-32-bytes" => format!(
            "{}{}=",
            random.string(BASE64, 42),
            random.string(b"AEIMQUYcgkosw048", 1)
        ),
        "discord-shape" => format!(
            "{}.{}.{}",
            random.string(b"0123456789", 18),
            random.string(BASE64URL, 6),
            random.string(BASE64URL, 27)
        ),
        "telegram-shape" => format!(
            "{}:{}",
            random.string(b"0123456789", 10),
            random.string(BASE64URL, 35)
        ),
        _ => random.string(profile.alphabet, profile.length),
    };
    let (prefix, suffix) = match id {
        "aws-secret-access-key" => ("AWS_SECRET_ACCESS_KEY=\"", "\""),
        "infisical-client-id" => ("INFISICAL_CLIENT_ID=\"", "\""),
        "generic-secret-assignment" => ("SECRET=\"", "\""),
        "http-bearer-token" => ("Authorization Bearer ", ""),
        "http-basic-auth" => ("Authorization Basic ", ""),
        "cloudflare-api-key" => ("cloudflare_api_key=\"", "\""),
        "datadog-api-key" => ("datadog_api_key=\"", "\""),
        "heroku-api-key" => ("heroku_api_key=\"", "\""),
        "wireguard-key-assignment" => ("PrivateKey=\"", "\""),
        "generic-high-entropy-value" => ("VALUE=\"", "\""),
        "generic-api-key" => ("API_KEY=\"", "\""),
        "discord-bot-token" => ("discord_token=\"", "\""),
        "telegram-bot-token" => ("telegram_token=\"", "\""),
        "mailchimp-api-key" => ("", "-us1"),
        "facebook-access-token" => ("EAA", ""),
        "dropbox-api-token" => ("sl.", ""),
        "launchdarkly-sdk-key" => ("sdk-", ""),
        "azure-ad-client-secret" => ("client_secret=\"", "\""),
        "azure-devops-pat" => ("azure_pat=\"", "\""),
        "alibaba-secret-key" => ("alibaba_secret_key=\"", "\""),
        "mssql-connection-string" => ("Server=database.invalid;Password=", ";"),
        "pagerduty-api-key" => ("pagerduty_api_key=\"", "\""),
        "circleci-api-token" => ("circleci_api_token=\"", "\""),
        "vercel-api-token" => ("vercel_api_token=\"", "\""),
        "netlify-access-token" => ("netlify_token=\"", "\""),
        "atlassian-api-token" => ("atlassian_api_token=\"", "\""),
        "twitter-bearer-token" => ("twitter_bearer_token=\"", "\""),
        "okta-api-token" => ("okta_api_token=\"", "\""),
        "algolia-api-key" => ("algolia_api_key=\"", "\""),
        "elastic-api-key" => ("elastic_api_key=\"", "\""),
        "splunk-hec-token" => ("splunk_hec_token=\"", "\""),
        "postmark-server-token" => ("postmark_server_token=\"", "\""),
        "gitlab-deploy-token" => ("gitlab_deploy_token=\"", "\""),
        "cohere-api-key" => ("cohere_api_key=\"", "\""),
        "generic-token-assignment" => ("TOKEN=\"", "\""),
        _ => unreachable!("missing line form for {id}"),
    };
    let line = format!("{prefix}{value}{suffix}");
    let captured = match id {
        "mailchimp-api-key"
        | "facebook-access-token"
        | "dropbox-api-token"
        | "launchdarkly-sdk-key" => line.clone(),
        _ => value,
    };
    (line, captured)
}

fn rate(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        "n/a".to_owned()
    } else {
        format!("{:.4}%", 100.0 * numerator as f64 / denominator as f64)
    }
}

#[test]
#[ignore = "explicit seeded measurement: scans over a million generated lines, aggregate output only"]
fn measure_builtin_stopword_and_documentation_losses() {
    let started = Instant::now();
    let rules = load_default_rules().unwrap();
    let mut measured = BTreeSet::new();
    eprintln!("seed={SEED:#x}; xorshift64-star; samples={SAMPLES}; batch={BATCH}");
    eprintln!(
        "raw doc loss is conditional on raw base entropy acceptance; sequential doc loss additionally excludes built-in stopwords"
    );
    eprintln!(
        "scanner probes isolate one built-in rule, forced on, default allowlist, measurements.txt versus docs/measurements.md"
    );
    eprintln!(
        "|rule|profile|length|threshold|default on|N|raw stop/N|raw E|raw doc/E|after stop E|sequential doc/E|scanner normal/N|scanner doc loss/normal|"
    );
    for rule in rules.iter().filter(|rule| rule.entropy_threshold.is_some()) {
        measured.insert(rule.id.as_str());
        let scanner = compile_rules(std::slice::from_ref(rule)).unwrap();
        let compiled = &scanner.rules[0];
        let per_rule = vec![(
            rule.id.clone(),
            rule.allowlist.regexes.clone(),
            rule.allowlist.paths.clone(),
        )];
        let allowlist = CompiledAllowlist::new(&[], &[], None, &per_rule, false).unwrap();
        let threshold = rule.entropy_threshold.unwrap();
        for profile in profiles(&rule.id) {
            // restarting the stream makes equal alphabet/length profiles directly comparable.
            let mut random = Random(SEED);
            let mut stop = 0;
            let mut eligible = 0;
            let mut doc_loss = 0;
            let mut sequential_eligible = 0;
            let mut sequential_loss = 0;
            let mut normal = 0;
            let mut scanner_doc_loss = 0;
            for _ in 0..SAMPLES / BATCH {
                let mut file = DiffFile {
                    path: "measurements.txt".to_owned(),
                    is_new: true,
                    is_deleted: false,
                    is_renamed: false,
                    is_binary: false,
                    added_lines: Vec::with_capacity(BATCH),
                    context: None,
                };
                for sample in 0..BATCH {
                    let (line, value) = generate(&rule.id, &profile, &mut random);
                    let captures = compiled.regex.captures(line.as_bytes()).unwrap_or_else(|| {
                        panic!("generator does not match rule {} sample {sample}", rule.id)
                    });
                    let captured = captures
                        .get(compiled.secret_group)
                        .or_else(|| {
                            compiled
                                .secret_groups
                                .iter()
                                .find_map(|&group| captures.get(group))
                        })
                        .expect("generated value has a capture");
                    assert!(
                        captured.as_bytes() == value.as_bytes(),
                        "capture differs for rule {} sample {sample}",
                        rule.id
                    );
                    let stopped = allowlist.contains_stopword(value.as_bytes());
                    let base = passes_entropy_check(value.as_bytes(), threshold);
                    let doc = passes_entropy_check(
                        value.as_bytes(),
                        threshold + allowlist.doc_entropy_bonus(),
                    );
                    stop += usize::from(stopped);
                    eligible += usize::from(base);
                    doc_loss += usize::from(base && !doc);
                    sequential_eligible += usize::from(base && !stopped);
                    sequential_loss += usize::from(base && !stopped && !doc);
                    file.added_lines.push(AddedLine {
                        line_number: sample + 1,
                        content: line.into_bytes(),
                    });
                }
                let found = scan(std::slice::from_ref(&file), &scanner, &allowlist);
                let normal_lines: BTreeSet<_> = found.iter().map(|finding| finding.line).collect();
                assert!(
                    normal_lines.len() == found.len(),
                    "multiple findings per generated line for {}",
                    rule.id
                );
                normal += normal_lines.len();
                file.path = "docs/measurements.md".to_owned();
                let doc_lines: BTreeSet<_> = scan(&[file], &scanner, &allowlist)
                    .iter()
                    .map(|finding| finding.line)
                    .collect();
                assert!(
                    doc_lines.is_subset(&normal_lines),
                    "documentation gained findings for {}",
                    rule.id
                );
                scanner_doc_loss += normal_lines.difference(&doc_lines).count();
            }
            eprintln!(
                "|{}|{}|{}|{threshold:.1}|{}|{SAMPLES}|{stop}/{}|{eligible}|{doc_loss}/{}|{sequential_eligible}|{sequential_loss}/{}|{normal}/{}|{scanner_doc_loss}/{}|",
                rule.id,
                profile.name,
                profile.length,
                rule.resolved_class().enabled_by_default(),
                rate(stop, SAMPLES),
                rate(doc_loss, eligible),
                rate(sequential_loss, sequential_eligible),
                rate(normal, SAMPLES),
                rate(scanner_doc_loss, normal)
            );
        }
    }
    eprintln!(
        "measured entropy rules={}; elapsed={:.3}s",
        measured.len(),
        started.elapsed().as_secs_f64()
    );
}
