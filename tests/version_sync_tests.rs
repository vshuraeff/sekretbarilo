//! cargo repairs the root lockfile before any test runs, but nothing touches the tracked
//! `fuzz/Cargo.lock` on a version bump: it stayed at 0.13.0 through two releases.

use std::path::Path;

fn locked_version(lockfile: &Path) -> Option<String> {
    let text = std::fs::read_to_string(lockfile).unwrap();
    let lock: toml::Table = text.parse().unwrap();
    lock["package"]
        .as_array()?
        .iter()
        .find(|package| package["name"].as_str() == Some("sekretbarilo"))?["version"]
        .as_str()
        .map(str::to_owned)
}

#[test]
fn fuzz_lockfile_records_the_package_version() {
    let lockfile = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/Cargo.lock");
    assert_eq!(
        locked_version(&lockfile).as_deref(),
        Some(env!("CARGO_PKG_VERSION")),
        "fuzz/Cargo.lock is stale; refresh it with \
         `cargo update --manifest-path fuzz/Cargo.toml -p sekretbarilo --offline`"
    );
}
