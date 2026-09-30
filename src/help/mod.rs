use crate::config::{self, ProjectConfig};
use std::fmt::Write as _;
use std::io::Write as _;

pub fn run(args: &[String]) -> i32 {
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => Ok(
            "Help topics:\n  sekretbarilo help config\n  sekretbarilo help rules [--defaults]\n"
                .to_owned(),
        ),
        ["config"] => Ok(include_str!("config.md").to_owned()),
        ["rules"] => rules(false),
        ["rules", "--defaults"] => rules(true),
        _ => {
            Err("usage: sekretbarilo help config | sekretbarilo help rules [--defaults]".to_owned())
        }
    };
    match result {
        Ok(text) => match std::io::stdout().lock().write_all(text.as_bytes()) {
            Ok(()) => 0,
            Err(_) => 2,
        },
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "[ERROR] {error}\nsee: sekretbarilo help config"
            );
            2
        }
    }
}

fn rules(defaults: bool) -> Result<String, String> {
    let config = if defaults {
        ProjectConfig::default()
    } else {
        config::load_project_config(None)?
    };
    let enabled = config::load_rules_with_config(&config)?;
    crate::scanner::rules::compile_rules(&enabled)
        .map_err(|_| "invalid detection rule configuration".to_owned())?;
    config::build_allowlist(&config, &enabled)
        .map_err(|_| "invalid allowlist configuration".to_owned())?;
    let mut states = config::rule_states(&config)?;
    states.sort_by(|a, b| a.id.cmp(&b.id));
    let mut output = format!(
        "Rule inventory: {}\nid\tclass\tstate\treason\n",
        if defaults {
            "built-in defaults (external config ignored)"
        } else {
            "effective cwd configuration"
        }
    );
    for state in states {
        let (on, reason) = if state.public_key_gated {
            (false, "detect_public_keys gate")
        } else {
            (state.enabled, state.reason.as_str())
        };
        let _ = writeln!(
            output,
            "{}\t{}\t{}\t{}",
            crate::audit::history::sanitize_display(&state.id),
            state.class,
            if on { "enabled" } else { "disabled" },
            reason
        );
    }
    Ok(output)
}
