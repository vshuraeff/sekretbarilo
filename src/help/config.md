# sekretbarilo configuration

Configuration is optional TOML. `sekretbarilo help rules` lists the effective
cwd inventory; `sekretbarilo help rules --defaults` ignores external config.
`help`, `help config`, and `help rules --defaults` work with broken config.
Help topics write stdout; errors write stderr and exit 2. Ordinary --help
continues to write stderr.

## Files and precedence

Lowest to highest priority:
1. /etc/sekretbarilo.toml
2. $XDG_CONFIG_HOME/sekretbarilo/sekretbarilo.toml, falling back to
   ~/.config/sekretbarilo/sekretbarilo.toml when XDG_CONFIG_HOME is unset,
   empty or relative (a relative value is invalid and ignored)
3. .sekretbarilo.toml in each directory from $HOME through the discovery start
   directory, inclusive (including ~/.sekretbarilo.toml)

Outside $HOME, only the start directory is checked in addition to system/user
config; its ancestors are not walked. Scan/audit normally start at the repo
root; help rules starts at cwd. Prefer a user config for personal policy or an
ancestor config for a group of projects. Hooks only honor an in-workspace
layer when it is git-tracked and unchanged against HEAD; otherwise they ignore
the entire layer. Scan/audit and help rules do not apply this hook trust filter.

For scan/audit, repeated --config PATH replaces discovery: only the named files
are loaded in argument order. Later scalars win; CLI scalar overrides win last.
--no-defaults selects only custom definitions, retaining built-in class
inheritance and validating switches against all known rule IDs.

Scalar values: nearest explicitly set value wins.
Lists: concatenate and deduplicate, except per-rule allowlist entries combine
by ID and append their patterns. A narrower entry cannot revoke an older one.
Rule definitions: replace a same-ID definition as a whole; new IDs append.
Switch maps: merge per key; nearer keys win without clearing other keys.
After merging, an explicit rule switch wins over its class, even when the class
switch came from a nearer layer.

Missing discovered files and empty files are skipped. Parse/type errors are
fatal; diagnostics report file and location without echoing config values.
A file that is not UTF-8 is a parse error; a discovered file that cannot be
read (permissions, I/O) is skipped with a warning. Explicit missing files,
unknown switch class/ID, invalid enabled-rule regexes, and invalid allowlists
are errors; an allowlist error names a fixed category, not the pattern. scan
validates config even when nothing is staged. Use doctor to diagnose effective
config. check-file and check-codex fail closed on a trusted layer that cannot
be read or parsed and ignore untrusted in-workspace layers without reading
them; redact-claude keeps its own fail-closed protocol.

## Settings

```toml
[settings]
entropy_threshold = 4.0
detect_public_keys = false
exemption_layer = true
source_posture = "literals"
heuristic_skip_test_paths = true

[settings.rule_classes]
signature = true
contextual = true
heuristic = false

[settings.rules]
"generic-high-entropy-value" = true
```

entropy_threshold is an optional global Shannon entropy floor (bits/byte).
It can raise a rule's existing threshold, but does not add entropy filtering
to a rule without one. Class selection does not change entropy or stopwords.
detect_public_keys defaults false: it independently gates pem-public-key,
pgp-public-key-block, and openssh-public-key. Enabling a rule cannot bypass it.
exemption_layer defaults true and enables heuristic candidate exemptions.
source_posture accepts "literals" or "all". When omitted it follows
exemption_layer: true means literals, false means all. Literals posture limits
generic-high-entropy-value in supported source files to recognized literals;
all posture also examines code-shaped candidates.
heuristic_skip_test_paths defaults true and skips test-shaped paths/recognized
Rust test regions for generic-high-entropy-value while exemption_layer is on.
tier3_skip_test_paths is its deprecated input alias. Both spellings in one
file are an error. These three heuristic settings do not affect detection
while generic-high-entropy-value is disabled.

Rule classes describe evidence: signature = recognizable credential format;
contextual = credential key, auth header or credential URL; heuristic = value
shape/entropy without named context. Signature/contextual default on; heuristic
defaults off. generic-high-entropy-value is the only built-in heuristic rule.
generic-api-key, generic-secret-assignment and generic-token-assignment are
contextual. Besides quoted values they read an unquoted value under a name that
is or ends in a credential key, wherever an assignment can start on a line
(API_KEY=..., HF_TOKEN=..., env DJANGO_SECRET_KEY=... cmd, cmd; API_KEY=...,
yaml token: ... at line start), so such env/yaml/shell values stay covered with
heuristic off; a value under any other name needs the heuristic rule. Boolean
entries under settings.rules use exact built-in or custom IDs. Unknown
classes/IDs fail.

## Allowlists

```toml
[allowlist]
paths = ['^generated/']
stopwords = ['known-safe-project-marker']

[[allowlist.rules]]
id = "aws-access-key-id"
regexes = ['^AKIAIOSFODNN7EXAMPLE$']
paths = []

[[allowlist.rules]]
id = "generic-high-entropy-value"
keys = ["TMPDIR", "SSH_AUTH_SOCK"]
```

paths and regexes are regular expressions, not globs. Global paths skip files;
per-rule paths skip that rule on matching files. Per-rule regexes match the
captured value, not the whole line. Anchor a known-safe literal with ^...$ and
escape regex metacharacters. Confirm the source is non-secret before adding it.
The AWS documentation placeholder above is already allowed by built-in rules.
Prefer an exact per-rule value exception over disabling a detector or broadly
excluding files. Built-in binary/vendor/lockfile skips remain active.

stopwords add to built-ins; ordinary word filtering applies to rules with an
entropy threshold, with separate password-specific checks. It is not a way to
allowlist every signature rule. Redaction ignores path exclusions and masks
supported text using the trusted layers' rules and value/key allowlists.

keys is supported only for generic-high-entropy-value. It matches the entire
case-sensitive assignment key: * matches any number of characters, ? one,
everything else is literal. Empty or wildcard-only patterns are errors.
Matching surrounding quotes are removed from assignment keys. Key allowlisting
does not disable other rules and can exempt any value under that key.
regexes, paths and keys default to empty lists. id is required.

## Custom rules

```toml
[[rules]]
id = "custom-internal-token"
description = "Internal service token"
regex = '(MYCO_[A-Z0-9]{32})'
secret_group = 1
keywords = ["myco_"]
class = "contextual"
entropy_threshold = 4.0
secret_groups = []

[rules.allowlist]
regexes = ['^MYCO_KNOWN_DOCUMENTATION_MARKER$']
paths = []
```

Signature rules can set `payload_group` to a payload capture, usually nested
inside `secret_group`.
`min_payload_entropy` then sets a Shannon entropy floor on that payload, and
`reject_hex_payload = true` rejects a payload made entirely of hex digits.
These guards require a valid, nonzero `payload_group`; invalid captures fail
rule compilation, including when a custom rule replaces a built-in rule ID.
The guards apply only to a match in which `payload_group` participates; a match
through a regex branch without that group is reported without them.

Required: id, description, regex, secret_group, keywords. keywords are lowercase
prefilter strings; an empty list disables the keyword prefilter for that rule.
secret_group selects the captured value. Optional secret_groups supplies
alternative capture indices in order; if none participates the full match is
used. entropy_threshold is optional. rules.allowlist has regexes and paths.
Omitted class inherits the embedded class for a built-in ID, otherwise defaults
to contextual. A same-ID custom definition replaces the built-in definition;
use settings.rules to switch a rule instead. There is no enabled definition
field. Literal TOML strings ('...') avoid doubling regex backslashes; in double
quoted strings write \\ for one backslash.

## Audit

```toml
[audit]
include_ignored = false
exclude_patterns = ['^build/']
include_patterns = ['\.rs$']
```

include_ignored includes gitignored files (default false). Pattern lists are
regular expressions; include_patterns overrides exclude_patterns for matching
paths. These settings affect audit only. CLI --include-ignored,
--exclude-pattern and --include-pattern provide the corresponding overrides.

## Common fixes

To opt in to prefixless high-entropy detection, put this in your user config:
```toml
[settings.rules]
"generic-high-entropy-value" = true
```
To enable all heuristic-class rules instead, use [settings.rule_classes] with
heuristic = true. Check for a more specific rule override if the class seems
ineffective. Run `sekretbarilo help rules` to inspect the resolved state and
`sekretbarilo doctor` for config diagnostics. Correct reported syntax/type
errors at the location shown; do not paste secrets into diagnostics or tickets.
