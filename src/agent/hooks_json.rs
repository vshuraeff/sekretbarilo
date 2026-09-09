use std::io::Write as IoWrite;
use std::path::Path;

use crate::agent::claude::sekretbarilo_subcommand_executable;

/// result of hook installation
#[derive(Debug, PartialEq)]
pub enum HookInstallResult {
    Created,
    Updated,
    AlreadyInstalled,
}

impl HookInstallResult {
    pub fn describe(&self, agent_label: &str) -> String {
        match self {
            HookInstallResult::Created => {
                format!("created {} hook configuration", agent_label)
            }
            HookInstallResult::Updated => {
                format!("updated {} hook configuration", agent_label)
            }
            HookInstallResult::AlreadyInstalled => {
                format!("sekretbarilo already installed in {} hooks", agent_label)
            }
        }
    }
}

/// positions found while searching a hook event array
pub(crate) struct HookSearch {
    pub(crate) matching_group_index: Option<usize>,
    pub(crate) first_sekretbarilo_hook: Option<(usize, usize)>,
    pub(crate) exact_hook: Option<(usize, usize)>,
}

/// find a hook group and sekretbarilo handler without mutating the config.
pub(crate) fn find_hook(root: &serde_json::Value, matcher: &str, command: &str) -> HookSearch {
    find_hook_for_event_matching(root, "PreToolUse", matcher, command, |found_command| {
        sekretbarilo_subcommand_executable(found_command, "check-codex").is_some()
    })
}

/// preserve event-local indices used by codex's hook trust keys.
pub(crate) fn find_hook_for_event(
    root: &serde_json::Value,
    event: &str,
    matcher: &str,
    command: &str,
) -> HookSearch {
    find_hook_for_event_matching(root, event, matcher, command, |found_command| {
        found_command.contains("sekretbarilo")
    })
}

fn find_hook_for_event_matching(
    root: &serde_json::Value,
    event: &str,
    matcher: &str,
    command: &str,
    is_owned: impl Fn(&str) -> bool,
) -> HookSearch {
    let mut result = HookSearch {
        matching_group_index: None,
        first_sekretbarilo_hook: None,
        exact_hook: None,
    };

    let Some(entries) = root
        .get("hooks")
        .and_then(|hooks| hooks.get(event))
        .and_then(|entries| entries.as_array())
    else {
        return result;
    };

    for (group_index, group) in entries.iter().enumerate() {
        if group.get("matcher").and_then(|value| value.as_str()) != Some(matcher) {
            continue;
        }

        if result.matching_group_index.is_none() {
            result.matching_group_index = Some(group_index);
        }

        if let Some(hooks) = group.get("hooks").and_then(|value| value.as_array()) {
            for (hook_index, hook) in hooks.iter().enumerate() {
                if let Some(found_command) = hook.get("command").and_then(|value| value.as_str()) {
                    if found_command == command && result.exact_hook.is_none() {
                        result.exact_hook = Some((group_index, hook_index));
                    }
                    if is_owned(found_command) && result.first_sekretbarilo_hook.is_none() {
                        result.first_sekretbarilo_hook = Some((group_index, hook_index));
                    }
                }
            }
        }
    }

    result
}

/// write the JSON config back to disk with pretty printing.
/// uses atomic write (write to temp file, then rename) to prevent corruption.
pub(crate) fn write_config(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let content = serde_json::to_string_pretty(value)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;
    // use pid + timestamp for unique temp file name to avoid races
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "config".to_string()),
        pid,
        ts,
    );
    let tmp = path.with_file_name(tmp_name);
    // use exclusive create (O_CREAT | O_EXCL) to prevent symlink following and path collisions
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("failed to create {}: {}", tmp.display(), e))?;
    file.write_all((content + "\n").as_bytes()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to write {}: {}", tmp.display(), e)
    })?;
    file.sync_all().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to sync {}: {}", tmp.display(), e)
    })?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "failed to rename {} -> {}: {}",
            tmp.display(),
            path.display(),
            e
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_search_preserves_codex_trust_positions() {
        let config = serde_json::json!({"hooks": {
            "PreToolUse": [
                {"matcher": "Read", "hooks": [{"command": "echo unrelated"}]},
                {"matcher": "Bash", "hooks": [{"command": "echo first"}, {"command": "sekretbarilo check-codex --stdin-json"}]}
            ],
            "PostToolUse": [
                {"matcher": "Bash", "hooks": [{"command": "sekretbarilo redact-claude --stdin-json"}]}
            ]
        }});
        let original = config.clone();
        let codex = find_hook(&config, "Bash", "sekretbarilo check-codex --stdin-json");
        assert_eq!(codex.matching_group_index, Some(1));
        assert_eq!(codex.exact_hook, Some((1, 1)));
        let redact = find_hook_for_event(
            &config,
            "PostToolUse",
            "Bash",
            "sekretbarilo redact-claude --stdin-json",
        );
        assert_eq!(redact.matching_group_index, Some(0));
        assert_eq!(redact.exact_hook, Some((0, 0)));
        assert_eq!(config, original);
    }

    #[test]
    fn codex_search_ignores_foreign_sekretbarilo_mentions_and_subcommands() {
        let config = serde_json::json!({"hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [
                    {"command": "echo sekretbarilo check-codex --stdin-json"},
                    {"command": "sekretbarilo check-file --stdin-json"},
                    {"command": "sekretbarilo check-codex --stdin-json"}
                ]
            }]
        }});

        let result = find_hook(&config, "Bash", "sekretbarilo check-codex --stdin-json");
        assert_eq!(result.first_sekretbarilo_hook, Some((0, 2)));
        assert_eq!(result.exact_hook, Some((0, 2)));
    }
}
