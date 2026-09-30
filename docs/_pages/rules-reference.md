---
layout: default
title: Rules Reference
nav_order: 6
---

# Rules Reference

sekretbarilo ships **113 built-in rule definitions**, with **109 active by default**
in 0.9.0. Each rule belongs to one rule class; the tables below give the class
for every listed rule. Classes describe detection evidence, not a precision rank.

| Rule class | Rules | Default | Evidence |
|------------|-------|---------|----------|
| `signature` | 75 (including 3 public-key rules) | Enabled; public keys additionally require `detect_public_keys` | Credential format, marker, or provider-specific structure |
| `contextual` | 37 | Enabled | Credential-naming key, authentication header, or credential-bearing URL |
| `heuristic` | 1 | Disabled | Generic value shape and entropy without credential-specific context |

Use `[settings.rule_classes]` for class switches and `[settings.rules]` for
individual rule switches. Rule-id switches win over class switches after
per-key configuration merging. See [Configuration]({{ '/configuration/' | relative_url }}).

## Provider-specific Rules

Most provider formats are signature rules; rules requiring a named assignment
are contextual. The class is explicit in each row. Some signature rules also use
entropy thresholds; class membership does not change their existing filters.

### Cloud Providers

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `aws-access-key-id` | AWS access key ID | `AKIA` + 16 chars | `signature` |
| `gcp-api-key` | GCP API key | `AIza` + 35 chars | `signature` |
| `gcp-oauth-client-secret` | GCP OAuth client secret | `GOCSPX-` + 28 chars | `signature` |
| `alibaba-access-key-id` | Alibaba Cloud access key ID | `LTAI` + 12-20 chars | `signature` |
| `digitalocean-personal-access-token` | DigitalOcean PAT | `dop_v1_` + 64 hex | `signature` |
| `digitalocean-oauth-token` | DigitalOcean OAuth token | `doo_v1_` + 64 hex | `signature` |
| `digitalocean-refresh-token` | DigitalOcean refresh token | `dor_v1_` + 64 hex | `signature` |

### Source Control

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `github-personal-access-token` | GitHub PAT | `ghp_` + 36+ chars | `signature` |
| `github-oauth-token` | GitHub OAuth token | `gho_` + 36+ chars | `signature` |
| `github-app-token` | GitHub app token | `ghs_` + 36+ chars | `signature` |
| `github-refresh-token` | GitHub refresh token | `ghr_` + 36+ chars | `signature` |
| `github-fine-grained-pat` | GitHub fine-grained PAT | `github_pat_` + 82+ chars | `signature` |
| `gitlab-personal-access-token` | GitLab PAT | `glpat-` + 20+ chars | `signature` |
| `gitlab-pipeline-trigger-token` | GitLab pipeline trigger | `glptt-` + 20+ chars | `signature` |
| `gitlab-runner-registration-token` | GitLab runner registration | `glrt-` + 20+ chars | `signature` |
| `gitlab-ci-job-token` | GitLab CI job token | `glcbt-` + 20+ chars | `signature` |

### Communication

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `slack-bot-token` | Slack bot token | `xoxb-` + 24+ chars | `signature` |
| `slack-user-token` | Slack user token | `xoxp-` + 24+ chars | `signature` |
| `slack-app-token` | Slack app token | `xapp-` + 24+ chars | `signature` |
| `discord-webhook-url` | Discord webhook URL | `discord.com/api/webhooks/...` | `signature` |

### Payment

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `stripe-secret-key-live` | Stripe live secret key | `sk_live_` + 24+ chars | `signature` |
| `stripe-secret-key-test` | Stripe test secret key | `sk_test_` + 24+ chars | `signature` |
| `stripe-publishable-key-live` | Stripe live publishable key | `pk_live_` + 24+ chars | `signature` |
| `stripe-restricted-key-live` | Stripe live restricted key | `rk_live_` + 24+ chars | `signature` |
| `stripe-restricted-key-test` | Stripe test restricted key | `rk_test_` + 24+ chars | `signature` |
| `square-access-token` | Square access token | `sq0atp-` + 22+ chars | `signature` |
| `square-oauth-secret` | Square OAuth secret | `sq0csp-` + 40+ chars | `signature` |

### AI / ML

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `anthropic-api-key` | Anthropic API key | `sk-ant-` + 20+ chars | `signature` |
| `openai-api-key` | OpenAI API key (project) | `sk-proj-` + 20+ chars; payload entropy at least 3.0 bits/byte | `signature` |
| `openai-api-key-legacy` | OpenAI API key (legacy) | `sk-...T3BlbkFJ...` | `signature` |
| `huggingface-access-token` | HuggingFace token | `hf_` + 34+ chars | `signature` |
| `replicate-api-token` | Replicate API token | `r8_` + 38+ chars | `signature` |

### Email / Messaging

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `sendgrid-api-key` | SendGrid API key | `SG.` + base64 segments | `signature` |
| `mailgun-private-api-token` | Mailgun private API token | `key-` + 32 hex | `signature` |
| `mailchimp-api-key` | Mailchimp API key | 32 hex + `-us` + digits | `signature` |
| `sendinblue-api-key` | Brevo (Sendinblue) API key | `xkeysib-` + 64 hex | `signature` |

### CI / CD

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `buildkite-api-token` | Buildkite API token | `bkua_` + 40 hex | `signature` |
| `terraform-cloud-token` | Terraform Cloud token | 14 chars + `.atlasv1.` + 60+ chars | `signature` |

### Monitoring / Observability

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `new-relic-api-key` | New Relic API key | `NRAK-` + 27 chars | `signature` |
| `grafana-cloud-api-token` | Grafana Cloud API token | `glc_` + 32+ chars | `signature` |
| `grafana-service-account-token` | Grafana service account token | `glsa_` + 32+ chars | `signature` |
| `sentry-auth-token` | Sentry auth token | `sntrys_` + 36+ chars | `signature` |
| `sentry-dsn` | Sentry DSN URL | `https://...ingest.sentry.io/...` | `signature` |
| `dynatrace-api-token` | Dynatrace API token | `dt0c01.` + 24+64 chars | `signature` |

### Database

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `database-connection-string-postgres` | PostgreSQL connection string | `postgres://` or `postgresql://` | `contextual` |
| `database-connection-string-mysql` | MySQL connection string | `mysql://` | `contextual` |
| `database-connection-string-mongodb` | MongoDB connection string | `mongodb://` or `mongodb+srv://` | `contextual` |
| `redis-connection-string` | Redis connection string | `redis://` | `contextual` |
| `planetscale-password` | PlanetScale password | `pscale_pw_` + 30+ chars | `signature` |
| `planetscale-api-token` | PlanetScale API token | `pscale_tkn_` + 30+ chars | `signature` |

### Package Registries

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `npm-access-token` | npm access token | `npm_` + 36+ chars | `signature` |
| `pypi-api-token` | PyPI API token | `pypi-` + 16+ chars | `signature` |
| `docker-hub-pat` | Docker Hub PAT | `dckr_pat_` + 24+ chars | `signature` |
| `rubygems-api-key` | RubyGems API key | `rubygems_` + 48 hex | `signature` |
| `nuget-api-key` | NuGet API key | `oy2` + 43 chars | `signature` |

### Crypto / Secrets Management

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `pem-private-key` | PEM private key block | `-----BEGIN...PRIVATE KEY-----` | `signature` |
| `pgp-private-key-block` | PGP private key block | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | `signature` |
| `jwt-token` | JWT token | `eyJ...eyJ...` (3 base64 segments) | `signature` |
| `age-secret-key` | age encryption secret key | `AGE-SECRET-KEY-1` + 58 chars (uppercase bech32 only; a lowercase `age-secret-key-1...` value can be caught by `generic-high-entropy-value` only when that rule is enabled) | `signature` |
| `hashicorp-vault-service-token` | Vault service token | `hvs.` + 24+ chars | `signature` |
| `hashicorp-vault-batch-token` | Vault batch token | `hvb.` + 24+ chars | `signature` |

### Cloud Infrastructure

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `fly-io-api-token` | Fly.io API token | `fo1_` + 40+ chars | `signature` |
| `pulumi-access-token` | Pulumi access token | `pul-` + 40 hex | `signature` |

### SaaS

| Rule ID | Description | Prefix | Class |
|---------|-------------|--------|-------|
| `linear-api-key` | Linear API key | `lin_api_` + 40+ chars | `signature` |
| `shopify-access-token-admin` | Shopify admin token | `shpat_` + 32 hex | `signature` |
| `shopify-access-token-custom-app` | Shopify custom app token | `shpca_` + 32 hex | `signature` |
| `shopify-access-token-private-app` | Shopify private app token | `shppa_` + 32 hex | `signature` |
| `sourcegraph-access-token` | Sourcegraph access token | `sgp_` + 40+ hex | `signature` |
| `figma-personal-access-token` | Figma PAT | `figd_` + 40+ chars | `signature` |
| `mapbox-api-token` | Mapbox API token | `pk.` + base64 segments | `signature` |
| `dropbox-api-token` | Dropbox API token | `sl.` + 100+ chars | `signature` |
| `launchdarkly-sdk-key` | LaunchDarkly SDK key | `sdk-` + UUID | `signature` |
| `notion-api-token` | Notion API token | `ntn_` + 40+ chars | `signature` |
| `databricks-api-token` | Databricks API token | `dapi` + 32 hex | `signature` |
| `facebook-access-token` | Facebook access token | `EAA` + 20+ chars | `signature` |

---

## Context-based Rules

Most rules here are contextual; recognizable URL formats can be signature rules.
The class is explicit in each row.

These rules require keyword context and apply additional validation (entropy thresholds and/or password strength heuristics).

### Cloud & Infrastructure

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `aws-secret-access-key` | `aws_secret`, `secret_access_key` | 3.5 | `contextual` |
| `azure-storage-account-key` | `accountkey` | — | `contextual` |
| `azure-ad-client-secret` | `azure`, `client_secret` | 3.5 | `contextual` |
| `azure-devops-pat` | `azure`, `devops` | 3.5 | `contextual` |
| `alibaba-secret-key` | `alibaba`, `aliyun` | 3.5 | `contextual` |
| `cloudflare-api-key` | `cloudflare`, `cf_api` | 3.0 | `contextual` |
| `heroku-api-key` | `heroku` | 3.0 | `contextual` |

### Communication

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `discord-bot-token` | `discord`, `bot` | 3.0 | `contextual` |
| `telegram-bot-token` | `telegram`, `bot` | 3.0 | `contextual` |
| `twilio-api-key` | `twilio` | — | `contextual` |
| `webhook-url-with-token` | `hooks.slack.com` | — | `signature` |

### Databases

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `mssql-connection-string` | `server`, `data source`, `password` | 3.0 | `contextual` |
| `airtable-api-key` | `airtable` | — | `contextual` |

### Monitoring / Observability

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `datadog-api-key` | `datadog`, `dd_api` | 3.0 | `contextual` |
| `elastic-api-key` | `elastic` | 3.5 | `contextual` |
| `splunk-hec-token` | `splunk` | 3.0 | `contextual` |
| `pagerduty-api-key` | `pagerduty` | 3.0 | `contextual` |

### CI / CD & DevOps

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `circleci-api-token` | `circleci` | 3.0 | `contextual` |
| `vercel-api-token` | `vercel` | 3.5 | `contextual` |
| `netlify-access-token` | `netlify` | 3.5 | `contextual` |
| `gitlab-deploy-token` | `gitlab`, `deploy_token` | 3.0 | `contextual` |

### Identity & Auth

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `okta-api-token` | `okta` | 3.0 | `contextual` |
| `atlassian-api-token` | `atlassian`, `jira` | 3.5 | `contextual` |
| `twitter-bearer-token` | `twitter`, `bearer` | 3.5 | `contextual` |
| `http-bearer-token` | `bearer`, `authorization` | 3.5 | `contextual` |
| `http-basic-auth` | `basic`, `authorization` | 3.0 | `contextual` |

### Email

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `postmark-server-token` | `postmark` | 3.0 | `contextual` |

### AI / ML

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `cohere-api-key` | `cohere` | 3.5 | `contextual` |

### Search

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `algolia-api-key` | `algolia` | 3.0 | `contextual` |

### Generic Patterns

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `generic-password-assignment` | `password`, `passwd`, `pwd` | strength heuristic | `contextual` |
| `generic-secret-assignment` | `secret`, `secret_key`, `api_secret` | 3.5 | `contextual` |
| `password-in-url` | `://` | strength heuristic | `contextual` |

`generic-secret-assignment` reads quoted values and unquoted `NAME=value` / `name: value` assignments the same way as the [generic credential assignments](#generic-credential-assignments) below.

Password rules (`generic-password-assignment`, `password-in-url`) only flag strong passwords: 8+ chars, mixed case, digits.

Every prefix-anchored rule starts at a token boundary. The byte before the prefix must not be an ASCII word byte, unless it ends one of these:
- a source-code string escape (`\n`, `\x20`, `\u000a` and the like);
- a percent escape of url-encoded text (`%3D`);
- an ANSI color or erase sequence of terminal output (`ESC[0m`, `ESC[38;5;186m`, `ESC[38:2::255:0:0m`, the `ESC[K` that `grep --color` writes).

So a prefix buried inside a longer alphanumeric run, such as `EAA` inside a base64 key body, is not a finding.

`generic-password-assignment` detects `password`, `passwd`, and `pwd` assignments with `=` or `:`, including names such as `DB_PASSWORD` and quoted mapping keys. Values can be double-quoted, single-quoted, backtick-quoted, or unquoted. Quoted captures preserve internal spaces, opposite quote characters, and escaped quotes. Unquoted captures stop at whitespace or syntax delimiters such as commas, semicolons, brackets, and parentheses; escaped whitespace and delimiters are included. Quote passwords containing literal delimiters. Masking replaces the complete captured value while retaining its surrounding quotes and adjacent fields.

Since 0.9.0 the strength gate trades some recall for fewer label and prose findings, by design:
- a value of three or more whitespace-separated words is prose and never a password, however strong;
- below the strength threshold, a value that contains `pass` or `pwd` after leet folding is read as a field label;
- below the strength threshold, a dictionary word followed only by digits and trailing `!?.*#` is a weak stem.

Such values are not reported under this rule, and there is no fallback for them. `generic-high-entropy-value` takes neither values with whitespace nor values under 20 bytes, so a passphrase rejected as prose and a short label or stem value reach no other rule.

All forms retain the same rule ID and its value allowlists and password-strength filters. Shell variables, supported template expressions, and weak or placeholder passwords remain excluded. This is pattern detection rather than a parser for every configuration language.

Raw single-quoted and backtick strings can be ambiguous with languages that interpret backslash escapes. When a backslash precedes a possible closing quote and another matching quote follows, detection conservatively includes the longer interpretation. This can mask adjacent text in raw-string formats. Multiline quoting and mixed shell quoting are not parsed as password assignments.

---

### Generic credential assignments

These named-key rules also have `class = "contextual"` and remain enabled by default.

| Rule ID | Keywords | Entropy | Class |
|---------|----------|---------|-------|
| `generic-api-key` | `api_key`, `apikey`, `api-key`, `api_token`, `apitoken`, `api-token` | 4.0 | `contextual` |
| `generic-token-assignment` | `token` | 4.0 | `contextual` |

`generic-api-key`, `generic-token-assignment` and `generic-secret-assignment` (listed under Generic Patterns) read two value forms, both after `=` or `:`:

- A quoted value, `'…'` or `"…"`, after a key anywhere on the line that ends in one of the rule's names: `api_key`, `api-key`, `apikey`, `api_token`, `api-token`, `apitoken`; `auth_token`, `access_token`, `secret_token`; `secret`, `secret_key`, `api_secret`. Its pattern is unchanged from earlier releases; the hex measure below applies to it as well.
- An unquoted value under a credential name, wherever an assignment can start on the line. `NAME=value`, with optional spaces or tabs around `=`, is read at line start and after a space or tab, a `;`, `&`, `|` or `(`. That covers `export API_KEY=…`, `env API_KEY=… cmd`, `sudo API_KEY=… cmd`, `docker run -e API_KEY=… img`, `cmd; API_KEY=…`, `make && TOKEN=…`, a Compose list item `  - API_KEY=…` and several assignments on one line. The YAML form `name: value`, with at least one space or tab after the colon, is read only at the start of a logical line or after a YAML `- `, as in `  token: …` and `  - api_key: …`.

  The name, case-insensitive and optionally led by `_`, is one of the rule's key words or a longer name that ends in one. The key words are `api_key` and `api_token` for `generic-api-key`; `token`, `auth_token`, `access_token`, `secret_token` and `github_token` for `generic-token-assignment`; `secret`, `secret_key`, `api_secret` and `client_secret` for `generic-secret-assignment`. Their words may be joined by `-`, `_` or nothing (`API_KEY`, `api-key`, `apikey`). A longer name reaches the key word through snake or kebab words (`HF_TOKEN`, `NPM_TOKEN`, `AWS_SESSION_TOKEN`, `DJANGO_SECRET_KEY`, `STRIPE_API_KEY`, `x-api-key`) or a camel hump (`openaiApiKey`, `jwtSecret`, `githubToken`). A name that continues past the key word (`MY_TOKENIZER`, `token_count`, `api_key_file`, `secret_name`) or glues it to a lowercase word (`xapi_key`, `mytoken`) is not read. A name after `.` (`self.token = …`, `x.API_KEY=…`) is a member rather than an assignment, and one after `-` is a flag (`--token=…`), so neither is read.

The unquoted value is the whole run of printable ASCII up to whitespace or the end of the line, so a trailing `# comment` is not part of it. Trailing punctuation belongs to the run (`API_KEY=…;` in `export API_KEY=…; ./run`), and masking replaces the whole run. A quote, backtick or `(` anywhere in the run means the assignment is not read in this form at all, rather than reporting the part before it: `api_key=get_key()` and `SECRET_KEY=$(cat f)` are not findings. A value starting with `=` is a comparison (`token == other`), not a value. The minimum lengths (8 bytes for `generic-secret-assignment`, 16 for the other two), the entropy thresholds, stopwords, hash context and variable references (`${API_KEY}`) apply to both forms. An exact-length hex value (32, 40 or 64 digits, optionally `0x`) is measured by its hex symbols instead of the 4.0-bit gate, which its sixteen symbols cannot reach. The value must have a hex-symbol entropy of at least 2.0 bits, as under the heuristic rule's hex policy, and a digest with hash context on its line, such as `checksum`, stays clear.

The unquoted form also skips a filesystem path (`SECRET_KEY=/run/secrets/key`), a path rooted at a variable reference (`$HOME/.config/app/api_token`), and a value that reads as code or words: a member chain or index (`settings.SECRET_KEY`, `text[token_start`), a type (`SecretStr`), or a name built from words (`ingress-tls-secret`). Every letter-and-digit piece of such a value must read as words or be a number. The value needs at least two letter words, or one word when it is shorter than 16 bytes (`existingSecret: postgresql`, `- secret: required`), and no run of short groups. It is never skipped when it could be a token standing alone: 20 bytes or more, at or over the rule's entropy threshold, and at least 80% distinct bytes with letter case folded.

The `&` start also reads a query parameter after the first in a URL (`…?a=1&token=…`), and the reported value then runs to the end of the URL word; `?token=…` is not read. A value without one of these names, bare or under an unrelated name, is covered only by the opt-in heuristic rule. So are a quoted JSON value (`"api_key": "…"`), a Makefile `:=`, a Dockerfile `ENV NAME value`, and an assignment after `=` or `,` (`--from-literal=token=…`, `--set a=1,token=…`) or inside quotes (`-e "API_KEY=…"`). The same holds for a dotted property name (`app.github.token=…`) and a name the key word does not end (`SECRET_KEY_BASE`). A random value made only of lowercase or only of uppercase letters that reads as words can be skipped as a word value. Measured on random two-piece values, that is about a quarter of those of 16 to 19 bytes. Of the longer ones it is a few percent under the 4.0-bit rules and up to about a fifth at 20 to 25 bytes under the 3.5-bit `generic-secret-assignment`. A secret shorter than 16 bytes that is one word, alone or with one short number, is skipped the same way.

## Heuristic Rules

| Rule ID | Class | Default | Entropy |
|---------|-------|---------|---------|
| `generic-high-entropy-value` | `heuristic` | Disabled | 4.0 |

To enable keywordless detection, set `[settings.rules]` with
`"generic-high-entropy-value" = true`, or `[settings.rule_classes]` with
`heuristic = true`. Without this opt-in, prefix-less random tokens may go
unreported, including in Claude tool-output redaction. The exemption layer,
source posture and test-path settings below do not enable the rule.

When enabled, `generic-high-entropy-value` detects a complete single-line ASCII token value when the captured value is at least 20 bytes and its raw, case-sensitive byte Shannon entropy is at least 4.0 bits per byte. It scores only the captured value, excluding the variable or key name, delimiter, and surrounding quotes; it does not normalize case or adjust for charset size. Whitespace-containing values and complete variable references are not candidates.

Supported assignment forms are NAME=VALUE, export NAME=VALUE, NAME: VALUE, name = "VALUE", name = 'VALUE', and JSON "name": "VALUE", including multiple fields on one line. A quoted value may carry a string prefix (Python `r b u f t`, C/C++ `L u U u8` and the `R` raw forms), and a Swift raw string `#"VALUE"#` counts as quoted; in a source file the value is the body without the prefix or delimiters, while an environment-style line keeps the whole shell word, and on a Python file an f-string or t-string whose holes are expressions of names is judged piece by piece around its `{…}` holes. An unquoted value ends at whitespace, at trailing `, ; ) ] } > &` and before a shell `&&` followed by a command. The name before a `::` scope separator, a POSIX class name such as `[:space:]` and the letter of a backslash escape such as `\n:` are not assignment names. A standalone otherwise-bare alphanumeric, base64, or base64url token line also qualifies, including normal trailing base64 padding and optional surrounding single or double quotes and horizontal whitespace.

The variable or key name is irrelevant: there are no exemptions for PATH, MANPATH, LS_COLORS, TERM_SESSION_ID, DB_TOKEN, or similar names. This intentional broadness can flag harmless high-entropy data such as base64 blobs and lockfile-style checksums. A UUID under a `*_CLIENT_ID`-style key gets no special-case exemption either: like any other value it is judged only by this rule's generic entropy gate, and a UUID's hex alphabet normally keeps it under the 4.0 threshold, which happens to match the OAuth convention that a client id is the public half of the pair, not a secret. To suppress a specific false positive, add a matching value to [allowlist].stopwords, or preferably add a [[allowlist.rules]] entry for generic-high-entropy-value with regexes matched against the captured value. For known-safe assignment names, its per-rule `keys` allowlist provides case-sensitive whole-key matching without weakening other rules.

This rule bypasses the built-in default stopword list, surrounding-line hash/checksum suppression, and documentation-file entropy bonus used by other rules. Explicit user-configured `[allowlist].stopwords` still apply as case-insensitive plain substrings of the captured value, not word-boundary matches. A per-rule `[[allowlist.rules]]` value regex for `generic-high-entropy-value` is narrower and more precise; anchor it to an exact known-safe value instead of using a broad pattern. Path allowlists, public-key suppression, and a higher global `[settings]` entropy-threshold override still apply normally; the override is a floor that can raise, never lower, this rule's 4.0 threshold.

---

## Gated Rules: Public Key Detection

These 3 rules have `class = "signature"` and are **disabled by default** by the separate public-key gate. Enable them with `detect_public_keys = true` in config or `--detect-public-keys` on the CLI.

| Rule ID | Description | Matches | Class |
|---------|-------------|---------|-------|
| `pem-public-key` | PEM public key header | `-----BEGIN PUBLIC KEY-----`, `-----BEGIN RSA PUBLIC KEY-----`, etc. | `signature` |
| `pgp-public-key-block` | PGP public key block header | `-----BEGIN PGP PUBLIC KEY BLOCK-----` | `signature` |
| `openssh-public-key` | OpenSSH public key | `ssh-rsa AAAA...`, `ssh-ed25519 AAAA...`, `ecdsa-sha2-nistp256 AAAA...`, etc. | `signature` |

when disabled (default), sekretbarilo also suppresses false positives from base64 content inside multi-line PEM/PGP public key blocks (e.g., base64 lines that might trigger token rules like `facebook-access-token`).

**enabling public key detection:**

```toml
# .sekretbarilo.toml
[settings]
detect_public_keys = true
```

A class or rule switch set to `false` still disables the corresponding rule.

Or via CLI:

```sh
sekretbarilo scan --detect-public-keys
sekretbarilo audit --detect-public-keys
```

---

## False Positive Reduction

1. **Entropy thresholds** — rules with entropy thresholds filter low-randomness strings; doc files get +1.0 bonus (the bonus does not apply to `generic-high-entropy-value`)
2. **Stopwords** — `example`, `test`, `placeholder`, `changeme`, `fake`, `mock`, `dummy`, etc. (`generic-high-entropy-value` uses only explicit user-configured stopwords)
3. **Hash detection** — SHA-1, SHA-256, MD5, git commit hashes (`generic-high-entropy-value` bypasses this suppression)
4. **Variable references** — `${VAR}`, `process.env.VAR`, `os.environ["VAR"]`, etc.
5. **Template handling** — Jinja2/Helm/Mustache/Handlebars {% raw %}`{{ }}`{% endraw %}, GitHub Actions {% raw %}`${{ }}`{% endraw %}, ERB `<%= %>`, Terraform `${var.}`, etc. (`generic-high-entropy-value` bypasses this suppression)
6. **Public key suppression** — PEM, PGP, and OpenSSH public key blocks are suppressed by default (prevents base64 content from triggering token rules)
7. **Password strength** — only flags strong passwords (8+ chars, mixed case, digits); also applied to connection string passwords
8. **Path allowlists** — binary, generated, lock files, vendor dirs auto-skipped

---

## Custom Rules

Add project-specific rules in `.sekretbarilo.toml`:

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = "(MYCO_[A-Z0-9]{32})"
secret_group = 1
keywords = ["myco_"]
entropy_threshold = 3.5

[rules.allowlist]
regexes = ["test_token_.*"]
paths = ["test/.*"]
```

### Required fields

- `id` — unique identifier (lowercase with hyphens)
- `description` — human-readable description
- `regex` — pattern with capture group for the secret
- `secret_group` — which capture group contains the secret (usually 1)
- `keywords` — case-insensitive keywords for aho-corasick pre-filtering

### Optional fields

- `class` — `signature`, `contextual`, or `heuristic`. Omitted on a built-in replacement, it inherits the built-in class; on a new custom id, it defaults to `contextual`.

- `secret_groups` — alternative capture group indices, checked in order if `secret_group` did not participate. Defaults to `[]`. If no configured group participates, the full match is used. Overrides replace the complete rule, including this list.
- `entropy_threshold` — minimum Shannon entropy (typical: 3.0–4.0)
- `allowlist.regexes` — value patterns to skip
- `allowlist.paths` — file path patterns to skip

### Override or disable built-in rules

Override a definition with a `[[rules]]` entry carrying the same `id`. Toggle it
without replacing its regex through a boolean switch:

```toml
[settings.rules]
"generic-api-key" = false
"generic-high-entropy-value" = true
```

The rule-id switch overrides its class switch. It does not bypass filters or
the independent public-key gate. Unknown class names and rule ids are errors.

### Configuration hierarchy

Rules merge in this order (later overrides earlier):

1. Built-in defaults (113 definitions, 109 enabled by default)
2. System config (`/etc/sekretbarilo.toml`)
3. User config (`~/.config/sekretbarilo.toml`)
4. Project config (`.sekretbarilo.toml`)
5. CLI overrides (`--config`, `--no-defaults`, etc.)

Same `id` replaces the earlier definition; unique `id`s are appended.

---

## Next Steps

- **[Configuration Guide]({{ '/configuration/' | relative_url }})** — allowlists, stopwords, output formats
- **[CLI Reference]({{ '/cli-reference/' | relative_url }})** — command options
- **[Agent Hooks]({{ '/agent-hooks/' | relative_url }})** — AI agent integration
