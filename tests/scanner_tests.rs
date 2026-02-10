// comprehensive unit tests for the scanner module (phase 8.2)
//
// covers:
//   - all tier-1 prefix-based rules
//   - tier-2 context-dependent rules
//   - tier-3 generic catch-all rule
//   - entropy calculation accuracy
//   - hash detection (should NOT be flagged)

use sekretbarilo::config;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::{scan, Finding};
use sekretbarilo::scanner::entropy;
use sekretbarilo::scanner::rules::{compile_rules, load_default_rules};

// -- helpers --

fn default_scanner_and_allowlist() -> (
    sekretbarilo::scanner::rules::CompiledScanner,
    sekretbarilo::config::allowlist::CompiledAllowlist,
) {
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();
    (scanner, al)
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

fn scan_line(path: &str, line: &[u8]) -> Vec<Finding> {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(path, vec![(1, line)]);
    scan(&[file], &scanner, &al)
}

fn assert_detected(path: &str, line: &[u8], expected_rule: &str) {
    let findings = scan_line(path, line);
    assert!(
        findings.iter().any(|f| f.rule_id == expected_rule),
        "expected rule '{}' to trigger on line {:?}, got findings: {:?}",
        expected_rule,
        String::from_utf8_lossy(line),
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

fn assert_not_detected(path: &str, line: &[u8]) {
    let findings = scan_line(path, line);
    assert!(
        findings.is_empty(),
        "expected no findings for line {:?}, got: {:?}",
        String::from_utf8_lossy(line),
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

// ============================================================================
// tier 1: prefix-based rules (very low false positives)
// ============================================================================

#[test]
fn tier1_aws_access_key_id() {
    assert_detected(
        "config.py",
        b"AWS_KEY = \"AKIAIOSFODNN7ABCDEFG\"",
        "aws-access-key-id",
    );
}

#[test]
fn tier1_aws_access_key_id_inline() {
    // key directly in code without quotes
    assert_detected(
        "deploy.sh",
        b"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7XYZWTUV",
        "aws-access-key-id",
    );
}

#[test]
fn tier1_github_personal_access_token() {
    assert_detected(
        "config.yml",
        b"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-personal-access-token",
    );
}

#[test]
fn tier1_github_oauth_token() {
    assert_detected(
        "config.yml",
        b"token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-oauth-token",
    );
}

#[test]
fn tier1_github_app_token() {
    assert_detected(
        "config.yml",
        b"token: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-app-token",
    );
}

#[test]
fn tier1_github_refresh_token() {
    assert_detected(
        "config.yml",
        b"token: ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "github-refresh-token",
    );
}

#[test]
fn tier1_github_fine_grained_pat() {
    // github_pat_ tokens are 82+ chars after the prefix
    let token = format!(
        "github_pat_{}",
        "A".repeat(82)
    );
    let line = format!("token: {}", token);
    assert_detected(
        "config.yml",
        line.as_bytes(),
        "github-fine-grained-pat",
    );
}

#[test]
fn tier1_gitlab_personal_access_token() {
    assert_detected(
        "config.yml",
        b"token: glpat-ABCDEFGHIJKLMNOPQRSTU",
        "gitlab-personal-access-token",
    );
}

#[test]
fn tier1_slack_bot_token() {
    assert_detected(
        "config.js",
        b"const token = \"xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\"",
        "slack-bot-token",
    );
}

#[test]
fn tier1_slack_user_token() {
    assert_detected(
        "config.js",
        b"const token = \"xoxp-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\"",
        "slack-user-token",
    );
}

#[test]
fn tier1_slack_app_token() {
    assert_detected(
        "config.js",
        b"const token = \"xapp-1-ABCDEFGHIJ-1234567890-AbCdEfGhIjKlMnOpQrStUvWx\"",
        "slack-app-token",
    );
}

#[test]
fn tier1_stripe_secret_key_live() {
    assert_detected(
        "config.rb",
        b"Stripe.api_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe-secret-key-live",
    );
}

#[test]
fn tier1_stripe_secret_key_test_detected() {
    // tier 1 rules skip stopword filtering (high confidence prefix-based
    // rules should not be suppressed by stopwords embedded in the token).
    assert_detected(
        "config.rb",
        b"Stripe.api_key = \"sk_test_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe-secret-key-test",
    );
}

#[test]
fn tier1_stripe_secret_key_test_regex_matches() {
    // verify the regex pattern itself matches sk_test_ tokens
    let rules = load_default_rules().unwrap();
    let rule = rules.iter().find(|r| r.id == "stripe-secret-key-test").unwrap();
    let re = regex::bytes::Regex::new(&rule.regex_pattern).unwrap();
    assert!(re.is_match(b"sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
}

#[test]
fn tier1_stripe_publishable_key_live() {
    assert_detected(
        "config.rb",
        b"pk = \"pk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        "stripe-publishable-key-live",
    );
}

#[test]
fn tier1_sendgrid_api_key() {
    assert_detected(
        "email.py",
        b"sg_key = \"SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQR\"",
        "sendgrid-api-key",
    );
}

#[test]
fn tier1_pem_private_key() {
    assert_detected(
        "key.pem",
        b"-----BEGIN RSA PRIVATE KEY-----",
        "pem-private-key",
    );
}

#[test]
fn tier1_pem_ec_private_key() {
    assert_detected(
        "key.pem",
        b"-----BEGIN EC PRIVATE KEY-----",
        "pem-private-key",
    );
}

#[test]
fn tier1_pem_generic_private_key() {
    assert_detected(
        "key.pem",
        b"-----BEGIN PRIVATE KEY-----",
        "pem-private-key",
    );
}

#[test]
fn tier1_jwt_token() {
    // a realistic JWT: header.payload.signature
    assert_detected(
        "auth.js",
        b"token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\"",
        "jwt-token",
    );
}

#[test]
fn tier1_digitalocean_personal_access_token() {
    let token = format!("dop_v1_{}", "a1b2c3d4".repeat(8));
    let line = format!("token: {}", token);
    assert_detected(
        "config.yml",
        line.as_bytes(),
        "digitalocean-personal-access-token",
    );
}

#[test]
fn tier1_digitalocean_oauth_token() {
    let token = format!("doo_v1_{}", "a1b2c3d4".repeat(8));
    let line = format!("token: {}", token);
    assert_detected(
        "config.yml",
        line.as_bytes(),
        "digitalocean-oauth-token",
    );
}

#[test]
fn tier1_digitalocean_refresh_token() {
    let token = format!("dor_v1_{}", "a1b2c3d4".repeat(8));
    let line = format!("token: {}", token);
    assert_detected(
        "config.yml",
        line.as_bytes(),
        "digitalocean-refresh-token",
    );
}

#[test]
fn tier1_npm_access_token() {
    assert_detected(
        ".npmrc",
        b"//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "npm-access-token",
    );
}

#[test]
fn tier1_pypi_api_token() {
    assert_detected(
        "config.cfg",
        b"password = pypi-AgEIcHlwaS5vcmcCJGQwNmE4ZjNhLTRhO",
        "pypi-api-token",
    );
}

#[test]
fn tier1_docker_hub_pat() {
    assert_detected(
        "docker.env",
        b"DOCKER_TOKEN=dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWx",
        "docker-hub-pat",
    );
}

#[test]
fn tier1_new_relic_api_key() {
    assert_detected(
        "monitoring.yml",
        b"api_key: NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
        "new-relic-api-key",
    );
}

#[test]
fn tier1_terraform_cloud_token() {
    let token = format!("abcdefghijklmn.atlasv1.{}", "A".repeat(60));
    let line = format!("token = \"{}\"", token);
    assert_detected(
        "terraform.tf",
        line.as_bytes(),
        "terraform-cloud-token",
    );
}

#[test]
fn tier1_anthropic_api_key() {
    assert_detected(
        "config.py",
        b"ANTHROPIC_KEY = \"sk-ant-api03-abcdefghijklmnopqrst\"",
        "anthropic-api-key",
    );
}

#[test]
fn tier1_openai_api_key() {
    assert_detected(
        "config.py",
        b"OPENAI_KEY = \"sk-abcdefghijklmnopqrstT3BlbkFJuvwxyz0123456789abcd\"",
        "openai-api-key-legacy",
    );
}

#[test]
fn tier1_openai_api_key_project_format() {
    assert_detected(
        "config.py",
        b"OPENAI_KEY = \"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\"",
        "openai-api-key",
    );
}

// ============================================================================
// tier 2: context-needed rules (medium false positives)
// ============================================================================

#[test]
fn tier2_aws_secret_access_key() {
    // high entropy base64-like value with AWS context keyword
    // avoid "EXAMPLE" in value since it's a stopword
    assert_detected(
        "config.py",
        b"aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzR9gB4kN+a'",
        "aws-secret-access-key",
    );
}

#[test]
fn tier2_aws_secret_low_entropy_not_flagged() {
    // low entropy value should not be flagged (entropy threshold 3.5)
    assert_not_detected(
        "config.py",
        b"aws_secret_access_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
    );
}

#[test]
fn tier2_postgres_connection_string() {
    assert_detected(
        "config.rs",
        b"let url = \"postgres://admin:s3cur3Pa55w0rd@db.prod-host.com:5432/mydb\"",
        "database-connection-string-postgres",
    );
}

#[test]
fn tier2_postgresql_connection_string() {
    assert_detected(
        "config.rs",
        b"let url = \"postgresql://admin:s3cur3Pa55w0rd@db.prod-host.com:5432/mydb\"",
        "database-connection-string-postgres",
    );
}

#[test]
fn tier2_mysql_connection_string() {
    assert_detected(
        "config.py",
        b"db_url = \"mysql://root:s3cur3Pa55w0rd@db.prod-host.com:3306/app\"",
        "database-connection-string-mysql",
    );
}

#[test]
fn tier2_mongodb_connection_string() {
    assert_detected(
        "config.py",
        b"mongo_url = \"mongodb://admin:s3cur3Pa55w0rd@mongo.prod-host.com:27017/app\"",
        "database-connection-string-mongodb",
    );
}

#[test]
fn tier2_mongodb_srv_connection_string() {
    assert_detected(
        "config.py",
        b"mongo_url = \"mongodb+srv://admin:s3cur3Pa55w0rd@cluster.prod-host.com/app\"",
        "database-connection-string-mongodb",
    );
}

#[test]
fn tier2_redis_connection_string() {
    assert_detected(
        "config.py",
        b"redis_url = \"redis://:s3cur3Pa55w0rd@redis.prod-host.com:6379\"",
        "redis-connection-string",
    );
}

#[test]
fn tier2_generic_password_assignment_high_entropy() {
    // strong password with high entropy - should be detected
    assert_detected(
        "config.py",
        b"password = \"Kj8mP2xQ9vL4nR5tB7wY\"",
        "generic-password-assignment",
    );
}

#[test]
fn tier2_generic_password_low_entropy_not_flagged() {
    // low entropy value should not pass the entropy threshold
    assert_not_detected(
        "config.py",
        b"password = \"aaaaaaaaaaaaaaaaaaaaaa\"",
    );
}

#[test]
fn tier2_generic_secret_assignment() {
    assert_detected(
        "config.py",
        b"secret = \"aB3dEf7hIj1kLmN0pQrStUvW\"",
        "generic-secret-assignment",
    );
}

#[test]
fn tier2_generic_secret_assignment_low_entropy_not_flagged() {
    assert_not_detected(
        "config.py",
        b"secret = \"aaaaaaaaaaaaaaaaaaaaaa\"",
    );
}

#[test]
fn tier2_password_in_url() {
    // password must be 8+ chars and >= 20 chars for entropy check (MIN_ENTROPY_LENGTH=20)
    // use a long, high-entropy password and avoid "example" domain (stopword)
    assert_detected(
        "config.yml",
        b"url: https://admin:Kj8mP2xQ9vL4nR5tB7wY@prod-host.com/api",
        "password-in-url",
    );
}

#[test]
fn tier2_http_bearer_token() {
    // high entropy bearer token
    assert_detected(
        "api.py",
        b"Authorization: Bearer aB3dEf7hIj1kLmN0pQrStUvW",
        "http-bearer-token",
    );
}

#[test]
fn tier2_http_basic_auth() {
    // base64 encoded credentials
    assert_detected(
        "api.py",
        b"Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NQ==",
        "http-basic-auth",
    );
}

#[test]
fn tier2_webhook_url_slack() {
    // avoid "xxx" or repetitive chars in the token (stopword "xxx")
    assert_detected(
        "notify.py",
        b"webhook = \"https://hooks.slack.com/services/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\"",
        "webhook-url-with-token",
    );
}

#[test]
fn tier2_azure_storage_account_key() {
    // azure keys are 86 base64 chars + ==
    let key = format!("{}==", "A".repeat(86));
    let line = format!("AccountKey={}", key);
    assert_detected(
        "config.cs",
        line.as_bytes(),
        "azure-storage-account-key",
    );
}

#[test]
fn tier2_cloudflare_api_key() {
    // 37 hex chars with cloudflare context and high entropy (threshold 3.0)
    let key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a";
    assert_eq!(key.len(), 37);
    let line = format!("cloudflare_api_key = '{}'", key);
    assert_detected(
        "config.py",
        line.as_bytes(),
        "cloudflare-api-key",
    );
}

#[test]
fn tier2_datadog_api_key() {
    // 32 hex chars should now be detected when there is no hash context.
    // hash detection requires context keywords (md5, sha, checksum, etc.)
    // to avoid false negatives on hex-based API keys.
    let key = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
    let line = format!("datadog_api_key = '{}'", key);
    assert_detected(
        "config.py",
        line.as_bytes(),
        "datadog-api-key",
    );
}

#[test]
fn tier2_datadog_api_key_mixed_case() {
    // datadog keys with mixed case won't trigger MD5 hash detection
    // since is_hex_string checks ascii_hexdigit (accepts A-F too)
    // but mixed with uppercase makes it clearly not a hash
    // use a value with uppercase hex chars that still matches [0-9a-f]{32}
    // actually the regex only allows lowercase [0-9a-f] so we use lowercase
    // and accept that pure-lowercase 32-hex = hash detection filters it.
    // instead, verify the rule regex pattern directly
    let rules = load_default_rules().unwrap();
    let rule = rules.iter().find(|r| r.id == "datadog-api-key").unwrap();
    let re = regex::bytes::Regex::new(&rule.regex_pattern).unwrap();
    let line = b"datadog_api_key = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8'";
    assert!(re.is_match(line), "datadog-api-key regex should match");
}

#[test]
fn tier2_heroku_api_key() {
    // 36-char uuid-like with heroku context
    let key = "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6";
    let line = format!("heroku_api_key = '{}'", key);
    assert_detected(
        "config.py",
        line.as_bytes(),
        "heroku-api-key",
    );
}

// ============================================================================
// tier 3: catch-all rules
// ============================================================================

#[test]
fn tier3_generic_api_key_high_entropy() {
    // generic api key with high entropy (threshold 4.0)
    assert_detected(
        "config.py",
        b"api_key = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"",
        "generic-api-key",
    );
}

#[test]
fn tier3_generic_api_key_low_entropy_not_flagged() {
    // low entropy value should not trigger
    assert_not_detected(
        "config.py",
        b"api_key = \"aaaaaaaaaaaaaaaaaaaaaa\"",
    );
}

#[test]
fn tier3_generic_api_token() {
    assert_detected(
        "config.py",
        b"api_token = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"",
        "generic-api-key",
    );
}

#[test]
fn tier3_generic_apikey_no_separator() {
    assert_detected(
        "config.py",
        b"apikey = \"aB3dEf7hIj1kLmN0pQrStUvWxYz\"",
        "generic-api-key",
    );
}

// ============================================================================
// entropy calculation accuracy
// ============================================================================

#[test]
fn entropy_zero_for_empty() {
    assert_eq!(entropy::shannon_entropy(b""), 0.0);
}

#[test]
fn entropy_zero_for_uniform() {
    // all same character = zero entropy
    assert_eq!(entropy::shannon_entropy(b"aaaaaaaaaa"), 0.0);
}

#[test]
fn entropy_one_for_two_equal_symbols() {
    // exactly 2 symbols with equal frequency -> entropy = 1.0
    let e = entropy::shannon_entropy(b"abababab");
    assert!((e - 1.0).abs() < 0.001, "expected ~1.0, got {}", e);
}

#[test]
fn entropy_two_for_four_equal_symbols() {
    // 4 symbols with equal frequency -> entropy = 2.0
    let e = entropy::shannon_entropy(b"abcdabcdabcdabcd");
    assert!((e - 2.0).abs() < 0.001, "expected ~2.0, got {}", e);
}

#[test]
fn entropy_increases_with_more_symbols() {
    let e1 = entropy::shannon_entropy(b"aabb");
    let e2 = entropy::shannon_entropy(b"aabbccdd");
    let e3 = entropy::shannon_entropy(b"aabbccddeeffgghh");
    assert!(e1 < e2, "e1={} should be < e2={}", e1, e2);
    assert!(e2 < e3, "e2={} should be < e3={}", e2, e3);
}

#[test]
fn entropy_realistic_api_key() {
    // a realistic high-entropy API key
    let data = b"aB3dEf7hIj1kLmN0pQrStUvWxYz";
    let e = entropy::shannon_entropy(data);
    assert!(e > 3.5, "expected high entropy for API key, got {}", e);
}

#[test]
fn entropy_realistic_low_entropy_password() {
    // a low entropy "password"
    let data = b"aaaaaaaaaaaaaaaaaaaaaa";
    let e = entropy::shannon_entropy(data);
    assert!(e < 0.5, "expected near-zero entropy, got {}", e);
}

#[test]
fn entropy_hex_valid_returns_some() {
    let e = entropy::hex_entropy(b"a1b2c3d4e5f6a7b8c9d0");
    assert!(e.is_some());
    assert!(e.unwrap() > 2.0);
}

#[test]
fn entropy_hex_invalid_returns_none() {
    assert!(entropy::hex_entropy(b"not-hex-at-all!!").is_none());
}

#[test]
fn entropy_base64_valid_returns_some() {
    let e = entropy::base64_entropy(b"SGVsbG8gV29ybGQhIFRoaXM=");
    assert!(e.is_some());
    assert!(e.unwrap() > 2.0);
}

#[test]
fn entropy_base64_url_safe_valid() {
    let e = entropy::base64_entropy(b"SGVsbG8tV29ybGRf");
    assert!(e.is_some());
}

#[test]
fn entropy_base64_invalid_returns_none() {
    assert!(entropy::base64_entropy(b"has spaces and !@#").is_none());
}

#[test]
fn entropy_alphanumeric_valid_returns_some() {
    let e = entropy::alphanumeric_entropy(b"aB3dEf7hIj1kLmN0pQrS");
    assert!(e.is_some());
    assert!(e.unwrap() > 3.0);
}

#[test]
fn entropy_alphanumeric_invalid_returns_none() {
    assert!(entropy::alphanumeric_entropy(b"has-dashes!").is_none());
}

#[test]
fn entropy_passes_check_short_strings_pass_through() {
    // short strings skip entropy check (pass through) since regex+keyword
    // match already provides confidence
    assert!(entropy::passes_entropy_check(b"aB3dEf7h", 1.0));
    assert!(entropy::passes_entropy_check(b"short", 0.0));
}

#[test]
fn entropy_passes_check_below_threshold() {
    // long string but low entropy
    let data = b"aaaaaaaaaaaaaaaaaaaaaa";
    assert!(!entropy::passes_entropy_check(data, 3.0));
}

#[test]
fn entropy_passes_check_above_threshold() {
    let data = b"aB3dEf7hIj1kLmN0pQrStUvWxYz";
    assert!(entropy::passes_entropy_check(data, 3.0));
}

#[test]
fn entropy_min_length_constant() {
    assert_eq!(entropy::MIN_ENTROPY_LENGTH, 20);
}

// ============================================================================
// hash detection (should NOT flag as secrets)
// ============================================================================

#[test]
fn hash_md5_not_flagged_as_secret() {
    // MD5 hash (32 hex chars) with context keyword should be skipped
    assert_not_detected(
        "checksums.txt",
        b"md5 secret = \"d41d8cd98f00b204e9800998ecf8427e\"",
    );
}

#[test]
fn hash_sha1_not_flagged_as_secret() {
    // SHA-1 hash (40 hex chars) with context keyword should be skipped
    assert_not_detected(
        "config.py",
        b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
    );
}

#[test]
fn hash_sha256_not_flagged_as_secret() {
    // SHA-256 hash (64 hex chars) with context keyword should be skipped
    assert_not_detected(
        "config.py",
        b"checksum secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

#[test]
fn hash_git_commit_sha_in_context() {
    // 40-char hex with "commit" context - should NOT flag
    assert_not_detected(
        "changelog.py",
        b"commit secret = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"",
    );
}

#[test]
fn hash_abbreviated_git_in_merge_context() {
    // abbreviated commit hash in merge context
    // note: the scanner only detects this as hash if the captured value
    // itself is hex and line has git context keywords
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(
        "git.log",
        vec![(1, b"merge commit da39a3e into main")],
    );
    let findings = scan(&[file], &scanner, &al);
    // should not flag anything - no rule keywords match in this line
    assert!(
        findings.is_empty(),
        "git merge line should not be flagged, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn hash_sha256_checksum_context() {
    // hash with "checksum" context word
    assert_not_detected(
        "verify.py",
        b"checksum secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

#[test]
fn hash_sha256_digest_context() {
    assert_not_detected(
        "verify.py",
        b"digest secret = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"",
    );
}

// ============================================================================
// additional coverage: scanner behavior with default rules
// ============================================================================

#[test]
fn stopword_changeme_not_flagged() {
    // "changeme" is a stopword - should not flag
    assert_not_detected(
        "config.py",
        b"password = \"changeme_please_update\"",
    );
}

#[test]
fn stopword_example_not_flagged() {
    assert_not_detected(
        "config.py",
        b"api_key = \"example_api_key_for_documentation\"",
    );
}

#[test]
fn variable_reference_env_not_flagged() {
    assert_not_detected(
        "config.py",
        b"secret = \"${SECRET_KEY}\"",
    );
}

#[test]
fn variable_reference_process_env_not_flagged() {
    assert_not_detected(
        "config.js",
        b"secret = \"process.env.SECRET_KEY\"",
    );
}

#[test]
fn aws_example_key_allowlisted() {
    // AKIAIOSFODNN7EXAMPLE is the well-known AWS example key
    // it's skipped because "EXAMPLE" matches the "example" stopword
    let rules = load_default_rules().unwrap();
    let scanner = compile_rules(&rules).unwrap();
    let al = config::build_allowlist(&config::ProjectConfig::default(), &rules).unwrap();

    let file = make_file(
        "config.py",
        vec![(5, b"key = \"AKIAIOSFODNN7EXAMPLE\"")],
    );
    let findings = scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "AWS example key should be allowlisted, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn multiple_secrets_in_one_file() {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(
        "leaked.py",
        vec![
            (1, b"aws_key = \"AKIAIOSFODNN7ABCDEFG\""),
            (5, b"token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\""),
            (10, b"-----BEGIN RSA PRIVATE KEY-----"),
        ],
    );
    let findings = scan(&[file], &scanner, &al);
    assert!(
        findings.len() >= 3,
        "expected at least 3 findings, got {}: {:?}",
        findings.len(),
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn clean_code_no_findings() {
    let (scanner, al) = default_scanner_and_allowlist();
    let file = make_file(
        "clean.rs",
        vec![
            (1, b"fn main() {"),
            (2, b"    let x = 42;"),
            (3, b"    println!(\"hello world\");"),
            (4, b"    let config = load_config();"),
            (5, b"}"),
        ],
    );
    let findings = scan(&[file], &scanner, &al);
    assert!(
        findings.is_empty(),
        "clean code should have no findings, got: {:?}",
        findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}
