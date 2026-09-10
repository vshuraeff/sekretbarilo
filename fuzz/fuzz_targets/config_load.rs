#![no_main]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use sekretbarilo::config::{
    load_project_config, load_project_config_from_paths, load_single_config,
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn temporary_config(data: &[u8]) -> Option<(PathBuf, PathBuf)> {
    for _ in 0..16 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "sekretbarilo-fuzz-config-{}-{id}",
            std::process::id()
        ));
        if fs::create_dir(&directory).is_err() {
            continue;
        }
        let path = directory.join(".sekretbarilo.toml");
        let created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(data));
        if created.is_ok() {
            return Some((directory, path));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&directory);
    }
    None
}

fuzz_target!(|data: &[u8]| {
    let Some((directory, path)) = temporary_config(data) else {
        return;
    };
    let _ = load_single_config(&path);
    let _ = load_project_config(Some(&directory));
    let _ = load_project_config_from_paths(&[path.clone()]);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir(&directory);
});
