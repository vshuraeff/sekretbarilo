// Each integration test imports this module as its own crate-local module, so a helper used by
// one test binary is dead code from another binary's perspective.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// get the path to the compiled binary
pub fn bin() -> String {
    env!("CARGO_BIN_EXE_sekretbarilo").to_string()
}

/// user-config fragment that turns the default-off heuristic rule back on.
pub const ENABLE_HEURISTIC: &str = "[settings.rules]\n\"generic-high-entropy-value\" = true\n";

pub struct IsolatedEnv {
    _root: tempfile::TempDir,
    home: PathBuf,
    codex_home: PathBuf,
    git_config_global: PathBuf,
}

impl IsolatedEnv {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("failed to create isolated environment");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("failed to create isolated HOME");
        let codex_home = root.path().join("codex-home");
        std::fs::create_dir_all(&codex_home).expect("failed to create isolated CODEX_HOME");
        let git_config_global = root.path().join(".fake-gitconfig");
        std::fs::write(&git_config_global, "").expect("failed to create isolated git config");

        Self {
            _root: root,
            home,
            codex_home,
            git_config_global,
        }
    }

    /// an isolated environment whose user config opts in to the heuristic rule
    /// `generic-high-entropy-value`, which is off by default.
    pub fn with_heuristic() -> Self {
        let env = Self::new();
        env.write_user_config("");
        env
    }

    /// write the user-layer config, always prefixed with the heuristic opt-in.
    pub fn write_user_config(&self, config: &str) {
        let dir = self.home.join(".config/sekretbarilo");
        std::fs::create_dir_all(&dir).expect("failed to create config directory");
        std::fs::write(
            dir.join("sekretbarilo.toml"),
            format!("{ENABLE_HEURISTIC}{config}"),
        )
        .expect("failed to write user config");
    }

    pub fn root(&self) -> &Path {
        self._root.path()
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    pub fn git_config_global(&self) -> &Path {
        &self.git_config_global
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(bin());
        command
            .env("HOME", &self.home)
            .env("CODEX_HOME", &self.codex_home)
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env_remove("CLAUDE_CONFIG_DIR");
        command
    }

    /// initialize a throwaway git repo at `<root>/repo` inside this environment, using this
    /// environment's isolated git config so the repo's identity never touches the developer's
    /// real global git config. Returns the repo path.
    pub fn git_repo(&self) -> PathBuf {
        let repo_path = self.root().join("repo");
        std::fs::create_dir_all(&repo_path).expect("failed to create isolated repo dir");

        Command::new("git")
            .args(["init"])
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .current_dir(&repo_path)
            .output()
            .expect("git init failed");
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .current_dir(&repo_path)
            .output()
            .expect("git config user.email failed");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .env("GIT_CONFIG_GLOBAL", &self.git_config_global)
            .current_dir(&repo_path)
            .output()
            .expect("git config user.name failed");

        repo_path
    }
}

/// create a temp git repo for pre-commit hook install tests.
/// isolates from user's global git config to prevent core.hooksPath leakage.
pub fn setup_git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // create an empty file to use as global git config, preventing leakage
    // from the user's actual global config (e.g. core.hooksPath)
    let fake_global = root.join(".fake-gitconfig");
    std::fs::write(&fake_global, "").unwrap();

    Command::new("git")
        .args(["init"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .expect("git init failed");

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .env("GIT_CONFIG_GLOBAL", &fake_global)
        .current_dir(root)
        .output()
        .unwrap();

    dir
}

/// get the path to the fake global gitconfig inside a test repo dir
pub fn fake_gitconfig(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join(".fake-gitconfig")
}

const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// standard padded base64 (rfc 4648 alphabet).
pub fn base64(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |word, (index, &byte)| {
                word | (u32::from(byte) << (16 - 8 * index))
            });
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(
                    BASE64_ALPHABET[((word >> (18 - 6 * index)) & 63) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// the inverse of `base64`, for round-trip checks of generated credentials.
pub fn base64_decode(encoded: &str) -> Vec<u8> {
    let sextets: Vec<u32> = encoded
        .trim_end_matches('=')
        .bytes()
        .map(|byte| {
            BASE64_ALPHABET
                .iter()
                .position(|&symbol| symbol == byte)
                .expect("base64 symbol") as u32
        })
        .collect();
    sextets
        .chunks(4)
        .flat_map(|group| {
            let word = group
                .iter()
                .enumerate()
                .fold(0_u32, |word, (index, &sextet)| {
                    word | (sextet << (18 - 6 * index))
                });
            word.to_be_bytes()[1..group.len()].to_vec()
        })
        .collect()
}

/// a seeded xorshift stream of indices below the bound it is called with, so a test never
/// stores a credential.
fn draws(seed: u64) -> impl FnMut(usize) -> usize {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    move |bound| {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as usize % bound
    }
}

/// `user:pass` drawn from `alphabet`.
pub fn generated_user_pass(seed: u64, alphabet: &[u8], user: usize, pass: usize) -> String {
    let mut draw = draws(seed);
    let mut word = |length: usize| -> String {
        (0..length)
            .map(|_| char::from(alphabet[draw(alphabet.len())]))
            .collect()
    };
    let user = word(user);
    format!("{user}:{}", word(pass))
}

/// a printable ascii `user:pass` and its base64, which is lowercase letters and slashes only.
/// it is built from three-byte groups of a printable byte, a colon and a printable byte, so the
/// user is one byte and the password holds further colons and punctuation (rfc 7617 gives
/// everything after the first colon to the password).
pub fn lowercase_slash_basic_credential(seed: u64, groups: usize) -> (String, String) {
    let printable = 0x20_u8..=0x7E;
    let candidates: Vec<[u8; 3]> = printable
        .clone()
        .flat_map(|first| printable.clone().map(move |last| [first, b':', last]))
        .filter(|group| {
            base64(group)
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'/')
        })
        .collect();
    let mut draw = draws(seed);
    let bytes: Vec<u8> = (0..groups)
        .flat_map(|_| candidates[draw(candidates.len())])
        .collect();
    let user_pass = String::from_utf8(bytes).expect("printable ascii");
    let encoded = base64(user_pass.as_bytes());
    (user_pass, encoded)
}

/// a utf-8 `user:pass` that mixes ascii with latin, cyrillic, greek and cjk letters (rfc 7617
/// `charset="UTF-8"`), and its base64.
pub fn utf8_basic_credential(seed: u64) -> (String, String) {
    const LETTERS: &[char] = &[
        'a', 'Z', '7', '-', 'ä', 'ö', 'ü', 'ß', 'é', 'ñ', 'ø', 'ж', 'щ', 'ю', 'я', 'π', 'λ', 'Ω',
        '€', '密', '码', '用', '户',
    ];
    let mut draw = draws(seed);
    let mut word =
        |length: usize| -> String { (0..length).map(|_| LETTERS[draw(LETTERS.len())]).collect() };
    let user = word(6);
    let user_pass = format!("{user}:{}", word(12));
    let encoded = base64(user_pass.as_bytes());
    (user_pass, encoded)
}

pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// a `user:pass` in a single-byte legacy charset (rfc 7617 leaves the default charset open) and
/// its base64: an ascii user, and a password that opens with a `lead` byte and mixes ascii
/// letters and digits with the charset's own letters (`letters`, all >= 0x80).
fn legacy_basic_credential(seed: u64, lead: &[u8], letters: &[u8]) -> (Vec<u8>, String) {
    let mut draw = draws(seed);
    let mut bytes: Vec<u8> = (0..6).map(|_| ALNUM[draw(ALNUM.len())]).collect();
    bytes.push(b':');
    bytes.push(lead[draw(lead.len())]);
    for _ in 0..14 {
        bytes.push(if draw(2) == 0 {
            ALNUM[draw(ALNUM.len())]
        } else {
            letters[draw(letters.len())]
        });
    }
    let encoded = base64(&bytes);
    (bytes, encoded)
}

/// an iso-8859-1 credential: the latin-1 letters 0xc0..=0xff (without the signs 0xd7, 0xf7).
pub fn iso_8859_1_basic_credential(seed: u64) -> (Vec<u8>, String) {
    let letters: Vec<u8> = (0xC0..=0xFF)
        .filter(|&byte| byte != 0xD7 && byte != 0xF7)
        .collect();
    legacy_basic_credential(seed, &letters, &letters)
}

/// the windows-1251 letters in 0x80..=0x9f, the c1 control range of iso-8859-1 (serbian and
/// macedonian letters such as `Љ`, `Ђ`, `џ`).
pub const WINDOWS_1251_C1_RANGE_LETTERS: &[u8] = &[
    0x80, 0x81, 0x83, 0x8A, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x9A, 0x9C, 0x9D, 0x9E, 0x9F,
];

/// a windows-1251 credential: the russian letters 0xc0..=0xff with `Ё` and `ё`, and the letters
/// of 0x80..=0x9f, one of which opens the password, so the bytes are never utf-8.
pub fn windows_1251_basic_credential(seed: u64) -> (Vec<u8>, String) {
    let letters: Vec<u8> = (0xC0..=0xFF)
        .chain([0xA8, 0xB8])
        .chain(WINDOWS_1251_C1_RANGE_LETTERS.iter().copied())
        .collect();
    legacy_basic_credential(seed, WINDOWS_1251_C1_RANGE_LETTERS, &letters)
}

/// the review's five legacy families, including bytes printable in windows-1251 that also
/// decode as a utf-8 c1 control. the ascii portions vary with the seed.
pub fn reviewed_basic_credentials(seed: u64) -> Vec<(&'static str, Vec<u8>, String)> {
    let ascii = generated_user_pass(seed, ALNUM, 10, 30);
    let (user, password) = ascii.split_once(':').expect("separator");
    [
        (
            "latin-1 username",
            [user.as_bytes(), &[0xE4], b":", password.as_bytes()].concat(),
        ),
        (
            "windows-1251 username",
            [user.as_bytes(), &[0xE6], b":", password.as_bytes()].concat(),
        ),
        (
            "latin-1 empty username",
            [b":".as_slice(), password.as_bytes(), &[0xE4]].concat(),
        ),
        (
            "windows-1251 empty username",
            [b":".as_slice(), password.as_bytes(), &[0xE6]].concat(),
        ),
        (
            "windows-1251 utf-8 collision",
            [ascii.as_bytes(), &[0xC2, 0x85]].concat(),
        ),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        let encoded = base64(&bytes);
        assert!(
            base64_decode(&encoded) == bytes,
            "{name}, seed {seed}: round trip"
        );
        assert!(
            !bytes.iter().any(u8::is_ascii_control),
            "{name}, seed {seed}"
        );
        // these are the exact single-byte mappings of ä, ж, and В… in the named charsets.
        if name.ends_with("collision") {
            assert!(
                std::str::from_utf8(&bytes)
                    .expect("utf-8 collision")
                    .contains('\u{85}')
            );
        } else {
            assert!(std::str::from_utf8(&bytes).is_err(), "{name}, seed {seed}");
        }
        (name, bytes, encoded)
    })
    .collect()
}

/// values that meet the basic rule's lexical gates but fail its decoded-byte or padding check.
pub fn generated_basic_noncredentials(seed: u64) -> Vec<(String, String)> {
    let ascii = generated_user_pass(seed, ALNUM, 10, 30);
    let families = std::iter::once(("ascii", ascii.as_bytes().to_vec())).chain(
        reviewed_basic_credentials(seed)
            .into_iter()
            .map(|(name, bytes, _)| (name, bytes)),
    );
    let mut cases = Vec::new();
    for (family, bytes) in families {
        for (name, control) in [
            ("no colon", None),
            ("tab", Some(b'\t')),
            ("nul", Some(0)),
            ("del", Some(0x7F)),
        ] {
            let mut malformed = bytes.clone();
            if let Some(control) = control {
                let last = malformed.last_mut().expect("password");
                *last = control;
            } else {
                malformed
                    .iter_mut()
                    .filter(|byte| **byte == b':')
                    .for_each(|byte| *byte = b'x');
            }
            let encoded = base64(&malformed);
            assert!(
                base64_decode(&encoded) == malformed,
                "{family}, {name}, seed {seed}: round trip"
            );
            cases.push((format!("{family}: {name}"), encoded));
        }
    }
    let padded = base64(ascii.as_bytes());
    cases.push((
        "incomplete padding".to_owned(),
        padded.trim_end_matches('=').to_owned() + "==",
    ));
    cases.push((
        "length one mod four".to_owned(),
        padded.trim_end_matches('=').to_owned() + "QQ",
    ));
    cases
}

/// the base64 value of an http basic credential with a mixed-case alphanumeric user and password.
pub fn generated_basic_credential(seed: u64) -> String {
    base64(generated_user_pass(seed, ALNUM, 10, 18).as_bytes())
}
