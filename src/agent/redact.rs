//! in-memory replacement of successful Claude tool output; never edits a file.

use std::io::{Read, Write};
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::config;
use crate::scanner::{engine::redact_text, rules::compile_rules};

const MAX_BYTES: usize = 10 * 1024 * 1024;
const STOP_REASON: &str = "sekretbarilo could not safely redact tool output; continuation stopped.";
const MINIMAL_STOP: &[u8] = b"{\"continue\":false,\"stopReason\":\"sekretbarilo could not safely redact tool output; continuation stopped.\"}\n";

/// a CLI error must use the PostToolUse stop protocol too, without echoing args.
pub fn redact_cli_error() -> i32 {
    emit(
        Some(MINIMAL_STOP.to_vec()),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

pub fn run_redact_claude() -> i32 {
    let output = process(&mut std::io::stdin());
    emit(output, &mut std::io::stdout(), &mut std::io::stderr())
}

fn emit(output: Option<Vec<u8>>, stdout: &mut impl Write, stderr: &mut impl Write) -> i32 {
    if let Some(output) = output
        && (stdout.write_all(&output).is_err() || stdout.flush().is_err())
    {
        // a closed output channel cannot carry a stop decision. never panic or
        // claim that exit 2 would remove the original result in Claude.
        let _ = writeln!(stderr, "{STOP_REASON}");
        return 1;
    }
    0
}

fn process(input: &mut impl Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let read_ok = input
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_ok();
    let mut payload = serde_json::from_slice::<Value>(&bytes).ok();
    if !read_ok || bytes.len() > MAX_BYTES {
        return Some(failure(payload.as_mut()));
    }
    let Some(payload) = payload.as_mut() else {
        return Some(MINIMAL_STOP.to_vec());
    };
    match evaluate(payload) {
        Ok(false) => None,
        Ok(true) => {
            let replacement = replacement(payload["tool_response"].take());
            match serialize_bounded(&replacement) {
                Ok(output) => Some(output),
                Err(()) => {
                    // restore the response so the stop result can erase all of
                    // its supported text, including text without any findings.
                    payload["tool_response"] =
                        replacement["hookSpecificOutput"]["updatedToolOutput"].clone();
                    Some(failure(Some(payload)))
                }
            }
        }
        Err(()) => Some(failure(Some(payload))),
    }
}

fn evaluate(payload: &mut Value) -> Result<bool, ()> {
    if payload.get("hook_event_name").and_then(Value::as_str) != Some("PostToolUse") {
        return Err(());
    }
    let tool = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .ok_or(())?
        .to_owned();
    if !matches!(tool.as_str(), "Bash" | "Read" | "Grep") {
        return Ok(false);
    }
    let base = match payload.get("cwd") {
        Some(Value::String(cwd)) if !cwd.is_empty() => PathBuf::from(cwd),
        None => std::env::current_dir().map_err(|_| ())?,
        _ => return Err(()),
    };
    if !base.is_absolute() || !base.is_dir() {
        return Err(());
    }
    let response = payload.get_mut("tool_response").ok_or(())?;
    // known non-text Read variants are outside this command's scope.
    if tool == "Read"
        && matches!(
            response.get("type").and_then(Value::as_str),
            Some("image" | "pdf" | "parts" | "notebook" | "file_unchanged")
        )
    {
        return Ok(false);
    }
    visit_text(&tool, response, &mut |text| text.to_owned())?;
    let project = super::codex::load_trusted_redact_config(&base).map_err(|_| ())?;
    let rules = config::load_rules_with_config(&project).map_err(|_| ())?;
    let allowlist = config::build_allowlist(&project, &rules).map_err(|_| ())?;
    let scanner = compile_rules(&rules).map_err(|_| ())?;
    visit_text(&tool, response, &mut |text| {
        redact_text(text, &scanner, &allowlist)
    })
}

fn replacement(response: Value) -> Value {
    json!({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": response}})
}

fn failure(payload: Option<&mut Value>) -> Vec<u8> {
    let mut stop = json!({"continue": false, "stopReason": STOP_REASON});
    if let Some(payload) = payload {
        let tool = payload
            .get("tool_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if let Some(response) = payload.get_mut("tool_response") {
            if matches!(tool.as_str(), "Bash" | "Read" | "Grep") {
                erase_supported(&tool, response);
            } else {
                for known_tool in ["Bash", "Read", "Grep"] {
                    erase_supported(known_tool, response);
                }
            }
            stop["hookSpecificOutput"] = replacement(response.take())["hookSpecificOutput"].take();
        }
    }
    serialize_bounded(&stop).unwrap_or_else(|()| MINIMAL_STOP.to_vec())
}

fn erase_text(text: &str) -> String {
    let mut masked = String::from("[REDACTED]");
    masked.extend(text.chars().filter(|c| matches!(c, '\r' | '\n')));
    masked
}

fn erase_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = erase_text(text),
        Value::Array(values) => values.iter_mut().for_each(erase_value),
        Value::Object(object) => object.values_mut().for_each(erase_value),
        _ => {}
    }
}

/// on failure even a malformed text container must not retain its raw strings.
fn erase_supported(tool: &str, response: &mut Value) {
    let Some(object) = response.as_object_mut() else {
        erase_value(response);
        return;
    };
    match tool {
        "Bash" => {
            for key in ["stdout", "stderr"] {
                if let Some(value) = object.get_mut(key) {
                    erase_value(value);
                }
            }
            for key in ["content", "structuredContent"] {
                if let Some(value) = object.get_mut(key) {
                    if let Some(blocks) = value.as_array_mut() {
                        for block in blocks {
                            if block.get("type").and_then(Value::as_str) == Some("text")
                                || block.get("text").is_some()
                            {
                                if let Some(text) = block.get_mut("text") {
                                    erase_value(text);
                                } else {
                                    erase_value(block);
                                }
                            } else if !block.is_object() {
                                erase_value(block);
                            }
                        }
                    } else {
                        erase_value(value);
                    }
                }
            }
        }
        "Read" => {
            if let Some(file) = object.get_mut("file") {
                if let Some(content) = file.get_mut("content") {
                    erase_value(content);
                } else if !file.is_object() {
                    erase_value(file);
                }
            }
        }
        "Grep" => {
            for key in ["content", "filenames", "lines", "matches"] {
                if let Some(value) = object.get_mut(key) {
                    erase_value(value);
                }
            }
        }
        _ => {}
    }
}

/// visit only output-bearing fields. unknown metadata is retained byte-for-value.
/// visit every available field even on schema errors, for best-effort erasure.
fn visit_text(
    tool: &str,
    response: &mut Value,
    transform: &mut impl FnMut(&str) -> String,
) -> Result<bool, ()> {
    let mut changed = false;
    let mut valid = true;
    let Some(object) = response.as_object_mut() else {
        transform_value(response, transform, &mut changed, &mut valid);
        return Err(());
    };
    match tool {
        "Bash" => {
            for key in ["stdout", "stderr"] {
                if let Some(value) = object.get_mut(key) {
                    transform_value(value, transform, &mut changed, &mut valid);
                } else {
                    valid = false;
                }
            }
            valid &= object.get("interrupted").is_some_and(Value::is_boolean);
            for key in ["content", "structuredContent"] {
                if let Some(value) = object.get_mut(key) {
                    transform_blocks(value, transform, &mut changed, &mut valid);
                }
            }
        }
        "Read" => {
            valid &= object.get("type").and_then(Value::as_str) == Some("text");
            match object
                .get_mut("file")
                .and_then(Value::as_object_mut)
                .and_then(|file| file.get_mut("content"))
            {
                Some(value) => transform_value(value, transform, &mut changed, &mut valid),
                None => valid = false,
            }
        }
        "Grep" => {
            if let Some(mode) = object.get("mode") {
                valid &= matches!(
                    mode.as_str(),
                    Some("content" | "count" | "files_with_matches")
                );
            }
            valid &= object.get("numFiles").is_some_and(Value::is_number);
            for key in ["content", "filenames", "lines", "matches"] {
                if let Some(value) = object.get_mut(key) {
                    transform_value(value, transform, &mut changed, &mut valid);
                } else if key == "filenames" {
                    valid = false;
                }
            }
        }
        _ => valid = false,
    }
    if valid { Ok(changed) } else { Err(()) }
}

fn transform_value(
    value: &mut Value,
    transform: &mut impl FnMut(&str) -> String,
    changed: &mut bool,
    valid: &mut bool,
) {
    match value {
        Value::String(text) => {
            let updated = transform(text);
            *changed |= *text != updated;
            *text = updated;
        }
        Value::Array(values) => {
            for value in values {
                if let Some(object) = value.as_object_mut() {
                    // alternate line-result objects retain paths and line numbers.
                    let mut found = false;
                    for key in ["text", "content", "line"] {
                        if let Some(text) = object.get_mut(key).filter(|v| !v.is_number()) {
                            found = true;
                            transform_value(text, transform, changed, valid);
                        }
                    }
                    *valid &= found;
                } else {
                    transform_value(value, transform, changed, valid);
                }
            }
        }
        Value::Object(object) => {
            // a drifted text field is invalid, but its available text must also
            // be erased when emitting the failure replacement.
            *valid = false;
            for value in object.values_mut() {
                transform_value(value, transform, changed, valid);
            }
        }
        _ => *valid = false,
    }
}

fn transform_blocks(
    value: &mut Value,
    transform: &mut impl FnMut(&str) -> String,
    changed: &mut bool,
    valid: &mut bool,
) {
    let Some(blocks) = value.as_array_mut() else {
        transform_value(value, transform, changed, valid);
        *valid = false;
        return;
    };
    for block in blocks {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(text) = block.get_mut("text") {
                transform_value(text, transform, changed, valid);
            } else {
                *valid = false;
            }
        } else if block.get("text").is_some() || !block.is_object() {
            *valid = false;
        }
    }
}

struct BoundedOutput(Vec<u8>);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("hook output limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded(value: &Value) -> Result<Vec<u8>, ()> {
    let mut output = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(|_| ())?;
    output.write_all(b"\n").map_err(|_| ())?;
    Ok(output.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn broken_output_channels_are_fallible() {
        assert_eq!(
            emit(Some(MINIMAL_STOP.to_vec()), &mut Broken, &mut Broken),
            1
        );
    }

    #[test]
    fn serialized_size_includes_envelope_and_newline() {
        assert!(serialize_bounded(&Value::String("x".repeat(MAX_BYTES))).is_err());
    }

    #[test]
    fn input_io_failure_stops() {
        struct FailedInput;
        impl Read for FailedInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::Other.into())
            }
        }
        assert_eq!(process(&mut FailedInput), Some(MINIMAL_STOP.to_vec()));
    }
}
