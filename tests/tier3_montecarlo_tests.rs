use sekretbarilo::config::allowlist::CompiledAllowlist;
use sekretbarilo::diff::parser::{AddedLine, DiffFile};
use sekretbarilo::scanner::engine::scan;
use sekretbarilo::scanner::entropy::shannon_entropy;
use sekretbarilo::scanner::rules::{CompiledScanner, compile_rules, load_default_rules};
use std::sync::LazyLock;
use std::time::Instant;

const SAMPLES: usize = 2000;
const LENGTHS: [usize; 5] = [20, 24, 32, 40, 64];
const HEX_LOWER: &[u8] = b"0123456789abcdef";
const HEX_UPPER: &[u8] = b"0123456789ABCDEF";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const UPPER_DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const DIGITS: &[u8] = b"0123456789";
const PREDICATES: [&str; 8] = [
    "file",
    "import",
    "markdown",
    "path",
    "pin",
    "url",
    "syntax",
    "wordshape",
];

static SCANNER: LazyLock<CompiledScanner> =
    LazyLock::new(|| compile_rules(&load_default_rules().unwrap()).unwrap());

struct Xorshift64Star {
    state: u64,
}

impl Xorshift64Star {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn index(&mut self, length: usize) -> usize {
        (self.next_u64() % length as u64) as usize
    }

    fn string(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(alphabet[self.index(alphabet.len())]))
            .collect()
    }
}

#[derive(Clone, Copy)]
enum FixedFormat {
    UuidDashed,
    UuidDashless,
    Github,
    Anthropic,
    Slack,
    Aws,
}

impl FixedFormat {
    fn name(self) -> &'static str {
        match self {
            Self::UuidDashed => "uuid-dashed",
            Self::UuidDashless => "uuid-dashless",
            Self::Github => "github",
            Self::Anthropic => "anthropic",
            Self::Slack => "slack",
            Self::Aws => "aws",
        }
    }

    fn length(self) -> usize {
        match self {
            Self::UuidDashed => 36,
            Self::UuidDashless => 32,
            Self::Github => 40,
            Self::Anthropic => 53,
            Self::Slack => 55,
            Self::Aws => 20,
        }
    }

    fn generate(self, rng: &mut Xorshift64Star) -> String {
        match self {
            Self::UuidDashed | Self::UuidDashless => {
                let mut value = String::with_capacity(self.length());
                for index in 0..32 {
                    if matches!(self, Self::UuidDashed) && [8, 12, 16, 20].contains(&index) {
                        value.push('-');
                    }
                    let byte = match index {
                        12 => b'4',
                        16 => b"89ab"[rng.index(4)],
                        _ => HEX_LOWER[rng.index(HEX_LOWER.len())],
                    };
                    value.push(char::from(byte));
                }
                value
            }
            Self::Github => format!("ghp_{}", rng.string(BASE62, 36)),
            Self::Anthropic => format!("sk-ant-api03-{}", rng.string(BASE64URL, 40)),
            Self::Slack => format!(
                "xoxb-{}-{}-{}",
                rng.string(DIGITS, 12),
                rng.string(DIGITS, 12),
                rng.string(BASE62, 24)
            ),
            Self::Aws => format!("AKIA{}", rng.string(UPPER_DIGITS, 16)),
        }
    }
}

#[derive(Clone, Copy)]
struct LineForm {
    name: &'static str,
    prefix: &'static str,
    suffix: &'static str,
}

impl LineForm {
    fn render(self, sample: &str) -> String {
        format!("{}{sample}{}", self.prefix, self.suffix)
    }

    fn is_call_literal(self) -> bool {
        matches!(
            self.name,
            "handler.process(\"S\")" | "let x = build(\"S\");"
        )
    }
}

const MAIN_FORMS: [LineForm; 10] = [
    LineForm {
        name: "KEY=S",
        prefix: "KEY=",
        suffix: "",
    },
    LineForm {
        name: "KEY=\"S\"",
        prefix: "KEY=\"",
        suffix: "\"",
    },
    LineForm {
        name: "bare",
        prefix: "",
        suffix: "",
    },
    LineForm {
        name: "let value = \"S\";",
        prefix: "let value = \"",
        suffix: "\";",
    },
    LineForm {
        name: "handler.process(S)",
        prefix: "handler.process(",
        suffix: ")",
    },
    LineForm {
        name: "handler.process(\"S\")",
        prefix: "handler.process(\"",
        suffix: "\")",
    },
    LineForm {
        name: "let x = build(\"S\");",
        prefix: "let x = build(\"",
        suffix: "\");",
    },
    LineForm {
        name: "https://host/?token=S",
        prefix: "https://host/?token=",
        suffix: "",
    },
    LineForm {
        name: "[link](https://host/S)",
        prefix: "[link](https://host/",
        suffix: ")",
    },
    LineForm {
        name: "uses: owner/repo@S",
        prefix: "uses: owner/repo@",
        suffix: "",
    },
];

const RECALL_FORMS: [LineForm; 3] = [
    LineForm {
        name: "API_KEY=S",
        prefix: "API_KEY=",
        suffix: "",
    },
    LineForm {
        name: "api_key: \"S\"",
        prefix: "api_key: \"",
        suffix: "\"",
    },
    LineForm {
        name: "PRIVATE_KEY=0xS",
        prefix: "PRIVATE_KEY=0x",
        suffix: "",
    },
];

// documented non-secret placeholders copied from the wordshape unit test.
const PASSPHRASES: [&str; 24] = [
    "MyVeryLongPassphraseForProduction",
    "correct-horse-battery-staple",
    "SuperSecretAdminPassword",
    "winter_meadow_sunrise_memory",
    "ReliableBackupRotationSchedule",
    "MountainRiverCedarForest",
    "orchard-lantern-morning-walk",
    "GentleNotebookCoffeeBreak",
    "archive_index_cleanup_plan",
    "secure-vault-rotation-checklist",
    "ProductReleaseValidationNotes",
    "telescope-garden-midnight-rain",
    "HelpfulAssistantDocumentReview",
    "network_backup_storage_policy",
    "CalendarMeetingReminderWorkflow",
    "copper-bridge-evening-window",
    "DocumentedMigrationSafetySteps",
    "morning_coffee_reading_journal",
    "PrivacyFocusedAccessControl",
    "library-catalog-search-index",
    "ServiceHealthMonitoringDashboard",
    "orange-violet-silver-garden",
    "ProjectPlanningSessionNotes",
    "friendly-neighbor-weekend-market",
];

#[derive(Default)]
struct Measurement {
    baseline_eligible: usize,
    base_detected: usize,
    layer_detected: usize,
    layer_misses: usize,
    predicate_misses: [usize; 8],
    predicate_samples: [Option<String>; 8],
    unattributed: usize,
    first_unattributed: Option<String>,
    first_layer_gap: Option<String>,
    call_url_cost: usize,
    call_wordshape_cost: usize,
    call_unattributed: usize,
}

struct ScannerPair {
    layer_on: CompiledAllowlist,
    layer_off: CompiledAllowlist,
}

impl ScannerPair {
    fn new() -> Self {
        let mut layer_on = CompiledAllowlist::default_allowlist().unwrap();
        layer_on.trace_exemptions = true;
        let mut layer_off = CompiledAllowlist::default_allowlist().unwrap();
        layer_off.exemption_layer = false;
        layer_off.trace_exemptions = false;
        Self {
            layer_on,
            layer_off,
        }
    }
}

fn masked(sample: &str) -> String {
    format!("{}..{}", &sample[..2], &sample[sample.len() - 2..])
}

impl Measurement {
    fn observe(&mut self, sample: &str, form: LineForm, scanners: &ScannerPair) {
        let file = DiffFile {
            path: "src/x.rs".to_string(),
            is_new: true,
            is_deleted: false,
            is_renamed: false,
            is_binary: false,
            added_lines: vec![AddedLine {
                line_number: 1,
                content: form.render(sample).into_bytes(),
            }],
        };
        let files = [file];
        let base_findings = scan(&files, &SCANNER, &scanners.layer_off);
        let findings = scan(&files, &SCANNER, &scanners.layer_on);
        // each single-line scan contains one sample; retain the brief's whole-line attribution.
        let base_detected = base_findings
            .iter()
            .any(|finding| !finding.rule_id.starts_with("exempt:"));
        let layer_detected = findings
            .iter()
            .any(|finding| !finding.rule_id.starts_with("exempt:"));
        self.baseline_eligible += 1;
        self.base_detected += usize::from(base_detected);
        self.layer_detected += usize::from(layer_detected);
        if !layer_detected {
            self.first_layer_gap.get_or_insert_with(|| masked(sample));
        }
        if form.is_call_literal() && !layer_detected {
            // call recall is new: costs must be counted even when the base has no candidate.
            let sample_trace = |name: &str| {
                findings.iter().any(|finding| {
                    finding.rule_id == name && finding.matched_value == sample.as_bytes()
                })
            };
            if sample_trace("exempt:url") {
                self.call_url_cost += 1;
            } else if sample_trace("exempt:wordshape") {
                self.call_wordshape_cost += 1;
            } else {
                self.call_unattributed += 1;
            }
        }
        if !base_detected || layer_detected {
            return;
        }
        self.layer_misses += 1;

        let mut fired = [false; PREDICATES.len()];
        for finding in &findings {
            if let Some(name) = finding.rule_id.strip_prefix("exempt:") {
                let index = PREDICATES
                    .iter()
                    .position(|&predicate| predicate == name)
                    .expect("trace emitted an unknown exemption predicate");
                fired[index] = true;
            }
        }
        for (index, present) in fired.iter().enumerate() {
            if *present {
                self.predicate_misses[index] += 1;
                self.predicate_samples[index].get_or_insert_with(|| masked(sample));
            }
        }
        if !fired.iter().any(|&present| present) {
            self.unattributed += 1;
            self.first_unattributed
                .get_or_insert_with(|| masked(sample));
        }
    }

    fn base_gaps(&self) -> usize {
        self.baseline_eligible - self.base_detected
    }
}

struct Row {
    group: &'static str,
    generator: &'static str,
    length: usize,
    form: LineForm,
    measurement: Measurement,
}

impl Row {
    fn new(group: &'static str, generator: &'static str, length: usize, form: LineForm) -> Self {
        Self {
            group,
            generator,
            length,
            form,
            measurement: Measurement::default(),
        }
    }

    fn identity(&self) -> String {
        format!(
            "{} / {} / length={} / {}",
            self.group, self.generator, self.length, self.form.name
        )
    }

    fn print(&self) {
        let m = &self.measurement;
        let [file, import, markdown, path, pin, url, syntax, wordshape] = m.predicate_misses;
        println!(
            "{:<7} {:<14} {:>4} {:<28} elig={:>5} base={:>5} layer={:>5} gap={:>4} miss={:>4} file={file:>4} import={import:>4} markdown={markdown:>4} path={path:>4} pin={pin:>4} url={url:>4} syntax={syntax:>4} wordshape={wordshape:>4} unattr={:>4}",
            self.group,
            self.generator,
            self.length,
            self.form.name,
            m.baseline_eligible,
            m.base_detected,
            m.layer_detected,
            m.base_gaps(),
            m.layer_misses,
            m.unattributed,
        );
        if self.form.is_call_literal() {
            println!(
                "call recall: {}: eligible={} base={} detected={} url_cost={} wordshape_cost={} unattr={}",
                self.identity(),
                m.baseline_eligible,
                m.base_detected,
                m.layer_detected,
                m.call_url_cost,
                m.call_wordshape_cost,
                m.call_unattributed,
            );
        }
    }

    fn call_recall_failure(&self) -> Option<String> {
        if !self.form.is_call_literal()
            || !matches!(
                self.generator,
                "base32" | "base36-lower" | "base58" | "base62" | "base64url"
            )
        {
            return None;
        }
        let m = &self.measurement;
        (m.layer_detected + m.call_url_cost + m.call_wordshape_cost != m.baseline_eligible
            || m.call_unattributed != 0)
            .then(|| format!(
                "{}: call recall detected={} url_cost={} wordshape_cost={} eligible={} unattr={}",
                self.identity(), m.layer_detected, m.call_url_cost, m.call_wordshape_cost,
                m.baseline_eligible, m.call_unattributed,
            ))
    }

    /// base64 and printable can carry url/expression-punctuation bytes inside the sample.
    /// their url/syntax misses are policy costs feeding decision g1, not predicate defects
    /// assertable here; every other predicate, wordshape, and unattributed keep normal bounds.
    fn is_structure_bearing(&self) -> bool {
        matches!(self.generator, "base64" | "printable")
    }

    fn safety_failures(&self) -> Vec<String> {
        let m = &self.measurement;
        let identity = self.identity();
        let mut failures = Vec::new();
        if m.unattributed != 0 {
            failures.push(format!(
                "{identity}: unattributed layer misses={}, allowed=0, masked sample={}",
                m.unattributed,
                m.first_unattributed.as_deref().unwrap_or("none")
            ));
        }
        for (index, predicate) in PREDICATES.iter().enumerate() {
            if self.is_structure_bearing() && matches!(*predicate, "url" | "syntax") {
                continue;
            }
            let count = m.predicate_misses[index];
            let allowed = if *predicate == "wordshape" {
                m.base_detected.div_ceil(1000)
            } else {
                0
            };
            if count > allowed {
                failures.push(format!(
                    "{identity}: {predicate} layer misses={count}, allowed={allowed}, masked sample={}",
                    m.predicate_samples[index].as_deref().unwrap_or("none")
                ));
            }
        }
        failures
    }

    fn recall_failure(&self) -> Option<String> {
        let m = &self.measurement;
        (m.layer_detected != SAMPLES).then(|| {
            format!(
                "{}: recall layer_detected={}, required={SAMPLES}, masked sample={}",
                self.identity(),
                m.layer_detected,
                m.first_layer_gap.as_deref().unwrap_or("none")
            )
        })
    }
}

fn measure_grid(
    name: &'static str,
    length: usize,
    mut generate: impl FnMut() -> String,
    scanners: &ScannerPair,
) -> Vec<Row> {
    let mut rows: Vec<_> = MAIN_FORMS
        .iter()
        .map(|&form| Row::new("grid", name, length, form))
        .collect();
    for _ in 0..SAMPLES {
        let sample = generate();
        assert_eq!(sample.len(), length, "generator length: {name}");
        if sample.len() < 20 || shannon_entropy(sample.as_bytes()) < 4.0 {
            continue;
        }
        for row in &mut rows {
            row.measurement.observe(&sample, row.form, scanners);
        }
    }
    rows
}

/// stopword samples have a literal prefix followed by 32 generated base62 bytes.
fn measure_stopwords(rng: &mut Xorshift64Star, scanners: &ScannerPair) -> Row {
    let prefixes = ["test", "example", "dummy"];
    let mut row = Row::new("cost", "stopword", 0, MAIN_FORMS[0]);
    for _ in 0..SAMPLES {
        let tail = rng.string(BASE62, 32);
        let prefix = prefixes[rng.index(prefixes.len())];
        let sample = format!("{prefix}{tail}");
        row.measurement.observe(&sample, row.form, scanners);
    }
    row
}

#[test]
fn tier3_montecarlo_zero_regression() {
    let started = Instant::now();
    println!("tier3 monte-carlo: N={SAMPLES} samples per cell; seed=0x9E3779B97F4A7C15");
    println!(
        "grid eligibility: sample length >= 20 and entropy >= 4.0; one sample reused across forms"
    );
    println!("recall and costs: ungated; elig counts all samples; length=0 means mixed lengths");
    println!(
        "base: exemption layer disabled; layer: default with tracing; miss: base caught, layer missed"
    );
    println!("gap: eligible minus base detected, report only");
    println!(
        "call recall: structure-free grid cells require detected + url/wordshape costs = eligible"
    );
    println!("stopword cost: prefix plus 32 base62 bytes, total length 36/37/39");
    let mut rng = Xorshift64Star::new(0x9E3779B97F4A7C15);
    let scanners = ScannerPair::new();

    let printable: Vec<u8> = (33..=126).collect();
    let alphabets: [(&str, &[u8]); 9] = [
        ("hex-lower", HEX_LOWER),
        ("hex-upper", HEX_UPPER),
        ("base32", BASE32),
        ("base36-lower", BASE36),
        ("base58", BASE58),
        ("base62", BASE62),
        ("base64", BASE64),
        ("base64url", BASE64URL),
        ("printable", &printable),
    ];
    let mut grid = Vec::new();
    for (name, alphabet) in alphabets {
        for length in LENGTHS {
            grid.extend(measure_grid(
                name,
                length,
                || rng.string(alphabet, length),
                &scanners,
            ));
        }
    }
    for format in [
        FixedFormat::UuidDashed,
        FixedFormat::UuidDashless,
        FixedFormat::Github,
        FixedFormat::Anthropic,
        FixedFormat::Slack,
        FixedFormat::Aws,
    ] {
        grid.extend(measure_grid(
            format.name(),
            format.length(),
            || format.generate(&mut rng),
            &scanners,
        ));
    }

    let mut recall = Vec::new();
    for (name, alphabet) in [("hex-lower", HEX_LOWER), ("hex-upper", HEX_UPPER)] {
        for length in [32, 40, 64] {
            let mut rows: Vec<_> = RECALL_FORMS
                .iter()
                .map(|&form| Row::new("recall", name, length, form))
                .collect();
            for _ in 0..SAMPLES {
                let sample = rng.string(alphabet, length);
                for row in &mut rows {
                    row.measurement.observe(&sample, row.form, &scanners);
                }
            }
            recall.extend(rows);
        }
    }

    let stopwords = measure_stopwords(&mut rng, &scanners);
    let mut passphrases = Row::new(
        "cost",
        "passphrase",
        0,
        LineForm {
            name: "token = \"P\"",
            prefix: "token = \"",
            suffix: "\"",
        },
    );
    for sample in PASSPHRASES {
        passphrases
            .measurement
            .observe(sample, passphrases.form, &scanners);
    }

    for row in grid.iter().chain(&recall).chain([&stopwords, &passphrases]) {
        row.print();
    }
    let mut largest_gaps: Vec<_> = grid
        .iter()
        .chain(&recall)
        .filter(|row| row.measurement.baseline_eligible >= 100)
        .collect();
    largest_gaps.sort_by_key(|row| std::cmp::Reverse(row.measurement.base_gaps()));
    println!("top 10 absolute base gaps: candidate recall improvements, report only");
    for row in largest_gaps.into_iter().take(10) {
        let m = &row.measurement;
        println!(
            "base gap: {}: eligible={}, base_detected={}, layer_detected={}, missed={}",
            row.identity(),
            m.baseline_eligible,
            m.base_detected,
            m.layer_detected,
            m.base_gaps()
        );
    }
    let failures: Vec<_> = grid
        .iter()
        .chain(&recall)
        .flat_map(Row::safety_failures)
        .chain(recall.iter().filter_map(Row::recall_failure))
        .chain(grid.iter().filter_map(Row::call_recall_failure))
        .collect();
    println!(
        "N={SAMPLES}; grid rows={}; recall rows={}; cost rows=2; elapsed={:.3}s",
        grid.len(),
        recall.len(),
        started.elapsed().as_secs_f64()
    );
    assert!(
        failures.is_empty(),
        "{} cell assertion failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
