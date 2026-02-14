---
layout: default
title: Rules Reference
nav_order: 6
---

# Rules Reference

sekretbarilo ships **109 built-in detection rules** organized into three precision tiers.

## Three-Tier Detection System

### Tier 1: Prefix-Based (75 rules)

Match distinctive, service-specific prefixes (e.g., `AKIA`, `ghp_`, `sk-ant-`). No keyword context needed. Very low false positive rate. Stopword filtering only checks for placeholder patterns like `XXXX...`.

### Tier 2: Context-Aware (32 rules)

Require keyword context (e.g., `password=`, `postgres://`) and/or entropy thresholds. Full stopword filtering. Password rules use strength heuristics instead of entropy.

### Tier 3: Catch-All (2 rules)

Generic patterns with the highest entropy threshold (4.0). Broad keyword matching (`api_key`, `auth_token`, etc.).

---

## Tier 1: Prefix-Based Rules

### Cloud Providers

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `aws-access-key-id` | AWS access key ID | `AKIA` + 16 chars |
| `gcp-api-key` | GCP API key | `AIza` + 35 chars |
| `gcp-oauth-client-secret` | GCP OAuth client secret | `GOCSPX-` + 28 chars |
| `alibaba-access-key-id` | Alibaba Cloud access key ID | `LTAI` + 12-20 chars |
| `digitalocean-personal-access-token` | DigitalOcean PAT | `dop_v1_` + 64 hex |
| `digitalocean-oauth-token` | DigitalOcean OAuth token | `doo_v1_` + 64 hex |
| `digitalocean-refresh-token` | DigitalOcean refresh token | `dor_v1_` + 64 hex |

### Source Control

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `github-personal-access-token` | GitHub PAT | `ghp_` + 36+ chars |
| `github-oauth-token` | GitHub OAuth token | `gho_` + 36+ chars |
| `github-app-token` | GitHub app token | `ghs_` + 36+ chars |
| `github-refresh-token` | GitHub refresh token | `ghr_` + 36+ chars |
| `github-fine-grained-pat` | GitHub fine-grained PAT | `github_pat_` + 82+ chars |
| `gitlab-personal-access-token` | GitLab PAT | `glpat-` + 20+ chars |
| `gitlab-pipeline-trigger-token` | GitLab pipeline trigger | `glptt-` + 20+ chars |
| `gitlab-runner-registration-token` | GitLab runner registration | `glrt-` + 20+ chars |
| `gitlab-ci-job-token` | GitLab CI job token | `glcbt-` + 20+ chars |

### Communication

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `slack-bot-token` | Slack bot token | `xoxb-` + 24+ chars |
| `slack-user-token` | Slack user token | `xoxp-` + 24+ chars |
| `slack-app-token` | Slack app token | `xapp-` + 24+ chars |
| `discord-webhook-url` | Discord webhook URL | `discord.com/api/webhooks/...` |

### Payment

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `stripe-secret-key-live` | Stripe live secret key | `sk_live_` + 24+ chars |
| `stripe-secret-key-test` | Stripe test secret key | `sk_test_` + 24+ chars |
| `stripe-publishable-key-live` | Stripe live publishable key | `pk_live_` + 24+ chars |
| `stripe-restricted-key-live` | Stripe live restricted key | `rk_live_` + 24+ chars |
| `stripe-restricted-key-test` | Stripe test restricted key | `rk_test_` + 24+ chars |
| `square-access-token` | Square access token | `sq0atp-` + 22+ chars |
| `square-oauth-secret` | Square OAuth secret | `sq0csp-` + 40+ chars |

### AI / ML

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `anthropic-api-key` | Anthropic API key | `sk-ant-` + 20+ chars |
| `openai-api-key` | OpenAI API key (project) | `sk-proj-` + 20+ chars |
| `openai-api-key-legacy` | OpenAI API key (legacy) | `sk-...T3BlbkFJ...` |
| `huggingface-access-token` | HuggingFace token | `hf_` + 34+ chars |
| `replicate-api-token` | Replicate API token | `r8_` + 38+ chars |

### Email / Messaging

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `sendgrid-api-key` | SendGrid API key | `SG.` + base64 segments |
| `mailgun-private-api-token` | Mailgun private API token | `key-` + 32 hex |
| `mailchimp-api-key` | Mailchimp API key | 32 hex + `-us` + digits |
| `sendinblue-api-key` | Brevo (Sendinblue) API key | `xkeysib-` + 64 hex |

### CI / CD

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `buildkite-api-token` | Buildkite API token | `bkua_` + 40 hex |
| `terraform-cloud-token` | Terraform Cloud token | 14 chars + `.atlasv1.` + 60+ chars |

### Monitoring / Observability

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `new-relic-api-key` | New Relic API key | `NRAK-` + 27 chars |
| `grafana-cloud-api-token` | Grafana Cloud API token | `glc_` + 32+ chars |
| `grafana-service-account-token` | Grafana service account token | `glsa_` + 32+ chars |
| `sentry-auth-token` | Sentry auth token | `sntrys_` + 36+ chars |
| `sentry-dsn` | Sentry DSN URL | `https://...ingest.sentry.io/...` |
| `dynatrace-api-token` | Dynatrace API token | `dt0c01.` + 24+64 chars |

### Database

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `database-connection-string-postgres` | PostgreSQL connection string | `postgres://` or `postgresql://` |
| `database-connection-string-mysql` | MySQL connection string | `mysql://` |
| `database-connection-string-mongodb` | MongoDB connection string | `mongodb://` or `mongodb+srv://` |
| `redis-connection-string` | Redis connection string | `redis://` |
| `planetscale-password` | PlanetScale password | `pscale_pw_` + 30+ chars |
| `planetscale-api-token` | PlanetScale API token | `pscale_tkn_` + 30+ chars |

### Package Registries

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `npm-access-token` | npm access token | `npm_` + 36+ chars |
| `pypi-api-token` | PyPI API token | `pypi-` + 16+ chars |
| `docker-hub-pat` | Docker Hub PAT | `dckr_pat_` + 24+ chars |
| `rubygems-api-key` | RubyGems API key | `rubygems_` + 48 hex |
| `nuget-api-key` | NuGet API key | `oy2` + 43 chars |

### Crypto / Secrets Management

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `pem-private-key` | PEM private key block | `-----BEGIN...PRIVATE KEY-----` |
| `pgp-private-key-block` | PGP private key block | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| `jwt-token` | JWT token | `eyJ...eyJ...` (3 base64 segments) |
| `age-secret-key` | age encryption secret key | `AGE-SECRET-KEY-1` + 58 chars |
| `hashicorp-vault-service-token` | Vault service token | `hvs.` + 24+ chars |
| `hashicorp-vault-batch-token` | Vault batch token | `hvb.` + 24+ chars |

### Cloud Infrastructure

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `fly-io-api-token` | Fly.io API token | `fo1_` + 40+ chars |
| `pulumi-access-token` | Pulumi access token | `pul-` + 40 hex |

### SaaS

| Rule ID | Description | Prefix |
|---------|-------------|--------|
| `linear-api-key` | Linear API key | `lin_api_` + 40+ chars |
| `shopify-access-token-admin` | Shopify admin token | `shpat_` + 32 hex |
| `shopify-access-token-custom-app` | Shopify custom app token | `shpca_` + 32 hex |
| `shopify-access-token-private-app` | Shopify private app token | `shppa_` + 32 hex |
| `sourcegraph-access-token` | Sourcegraph access token | `sgp_` + 40+ hex |
| `figma-personal-access-token` | Figma PAT | `figd_` + 40+ chars |
| `mapbox-api-token` | Mapbox API token | `pk.` + base64 segments |
| `dropbox-api-token` | Dropbox API token | `sl.` + 100+ chars |
| `launchdarkly-sdk-key` | LaunchDarkly SDK key | `sdk-` + UUID |
| `notion-api-token` | Notion API token | `ntn_` + 40+ chars |
| `databricks-api-token` | Databricks API token | `dapi` + 32 hex |
| `facebook-access-token` | Facebook access token | `EAA` + 20+ chars |

---

## Tier 2: Context-Aware Rules

These rules require keyword context and apply additional validation (entropy thresholds and/or password strength heuristics).

### Cloud & Infrastructure

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `aws-secret-access-key` | `aws_secret`, `secret_access_key` | 3.5 |
| `azure-storage-account-key` | `accountkey` | — |
| `azure-ad-client-secret` | `azure`, `client_secret` | 3.5 |
| `azure-devops-pat` | `azure`, `devops` | 3.5 |
| `alibaba-secret-key` | `alibaba`, `aliyun` | 3.5 |
| `cloudflare-api-key` | `cloudflare`, `cf_api` | 3.0 |
| `heroku-api-key` | `heroku` | 3.0 |

### Communication

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `discord-bot-token` | `discord`, `bot` | 3.0 |
| `telegram-bot-token` | `telegram`, `bot` | 3.0 |
| `twilio-api-key` | `twilio` | — |
| `webhook-url-with-token` | `hooks.slack.com` | — |

### Databases

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `mssql-connection-string` | `server`, `data source`, `password` | 3.0 |
| `airtable-api-key` | `airtable` | — |

### Monitoring / Observability

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `datadog-api-key` | `datadog`, `dd_api` | 3.0 |
| `elastic-api-key` | `elastic` | 3.5 |
| `splunk-hec-token` | `splunk` | 3.0 |
| `pagerduty-api-key` | `pagerduty` | 3.0 |

### CI / CD & DevOps

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `circleci-api-token` | `circleci` | 3.0 |
| `vercel-api-token` | `vercel` | 3.5 |
| `netlify-access-token` | `netlify` | 3.5 |
| `gitlab-deploy-token` | `gitlab`, `deploy_token` | 3.0 |

### Identity & Auth

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `okta-api-token` | `okta` | 3.0 |
| `atlassian-api-token` | `atlassian`, `jira` | 3.5 |
| `twitter-bearer-token` | `twitter`, `bearer` | 3.5 |
| `http-bearer-token` | `bearer`, `authorization` | 3.5 |
| `http-basic-auth` | `basic`, `authorization` | 3.0 |

### Email

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `postmark-server-token` | `postmark` | 3.0 |

### AI / ML

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `cohere-api-key` | `cohere` | 3.5 |

### Search

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `algolia-api-key` | `algolia` | 3.0 |

### Generic Patterns

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `generic-password-assignment` | `password`, `passwd`, `pwd` | strength heuristic |
| `generic-secret-assignment` | `secret`, `secret_key`, `api_secret` | 3.5 |
| `password-in-url` | `://` | strength heuristic |

Password rules (`generic-password-assignment`, `password-in-url`) only flag strong passwords: 8+ chars, mixed case, digits.

---

## Tier 3: Catch-All Rules

| Rule ID | Keywords | Entropy |
|---------|----------|---------|
| `generic-api-key` | `api_key`, `apikey`, `api-key`, `api_token`, `api-token` | 4.0 |
| `generic-token-assignment` | `auth_token`, `access_token`, `secret_token` | 4.0 |

---

## False Positive Reduction

1. **Entropy thresholds** — tier 2/3 rules filter low-randomness strings; doc files get +1.0 bonus
2. **Stopwords** — `example`, `test`, `placeholder`, `changeme`, `fake`, `mock`, `dummy`, etc.
3. **Hash detection** — SHA-1, SHA-256, MD5, git commit hashes
4. **Variable references** — `${VAR}`, `process.env.VAR`, `os.environ["VAR"]`, etc.
5. **Template handling** — Jinja2/Helm `{{ }}`, GitHub Actions `${{ }}`, ERB `<%= %>`, Terraform `${var.}`, etc.
6. **Password strength** — only flags strong passwords (8+ chars, mixed case, digits)
7. **Path allowlists** — binary, generated, lock files, vendor dirs auto-skipped

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

- `entropy_threshold` — minimum Shannon entropy (typical: 3.0–4.0)
- `allowlist.regexes` — value patterns to skip
- `allowlist.paths` — file path patterns to skip

### Override or disable built-in rules

Override by defining a rule with the same `id`. Disable with an unmatchable pattern:

```toml
[[rules]]
id = "generic-api-key"
description = "Disabled"
regex = "(?-u:^$a)"
secret_group = 1
keywords = ["__never_match__"]
```

### Configuration hierarchy

Rules merge in this order (later overrides earlier):

1. Built-in defaults (109 rules)
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
