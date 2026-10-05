#![no_main]

use libfuzzer_sys::fuzz_target;
use sekretbarilo::agent::{CodexToolCall, parse_codex_payload, parse_hook_payload};
use serde_json::{Map, Value, json};

const MALFORMED_PREFIX: &str = "malformed Codex hook JSON: ";

// the codex parser sanitizes every serde message it quotes, and its own text is ascii
fn is_display_safe(reason: &str) -> bool {
    reason.chars().all(|c| {
        (c == '\t' || !c.is_control())
            && !matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{061C}'
                    | '\u{FEFF}'
            )
    })
}

fn check_claude(text: &str) {
    let parsed = parse_hook_payload(text);
    assert_eq!(parsed, parse_hook_payload(text));
    let (file_path, cwd) = match parsed {
        Ok(fields) => fields,
        Err(reason) => {
            assert!(!reason.is_empty());
            return;
        }
    };
    assert!(!file_path.is_empty());

    // the struct parse skips unknown fields without building them, so a generic parse may
    // reject what it accepted (an out-of-range number, a lone surrogate); serde's derived
    // structs also take positional arrays, so the named comparison reads objects only
    if let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(text) {
        assert_eq!(payload.get("cwd").and_then(Value::as_str), cwd.as_deref());
        if let Some(Value::Object(tool_input)) = payload.get("tool_input") {
            assert_eq!(
                tool_input.get("file_path").and_then(Value::as_str),
                Some(file_path.as_str())
            );
        }
    }

    let rebuilt = json!({"tool_input": {"file_path": file_path}, "cwd": cwd}).to_string();
    assert_eq!(parse_hook_payload(&rebuilt), Ok((file_path, cwd)));
}

fn check_codex_fields(
    payload: &Map<String, Value>,
    scanned: Option<(&str, &str, &str, Option<&str>)>,
) {
    let text = |name: &str| payload.get(name).and_then(Value::as_str);
    let (Some(event), Some(tool)) = (text("hook_event_name"), text("tool_name")) else {
        panic!("an accepted payload names its event and its tool");
    };
    assert!(payload.contains_key("tool_input"));
    match scanned {
        None => assert!(
            !(event == "PreToolUse" && matches!(tool, "apply_patch" | "Bash")
                || event == "PostToolUse" && tool == "Bash")
        ),
        Some((scanned_event, scanned_tool, scanned_text, cwd)) => {
            assert_eq!((event, tool), (scanned_event, scanned_tool));
            if scanned_event == "PostToolUse" {
                assert_eq!(text("tool_response"), Some(scanned_text));
            } else {
                assert_eq!(payload["tool_input"]["command"].as_str(), Some(scanned_text));
            }
            assert_eq!(text("cwd"), cwd);
        }
    }
}

fn check_codex(data: &[u8]) {
    let parsed = parse_codex_payload(data);
    assert_eq!(parsed, parse_codex_payload(data));

    // the parser reads the bytes as generic json before it applies the payload schema
    let value = serde_json::from_slice::<Value>(data);
    let call = match parsed {
        Ok(call) => call,
        Err(reason) => {
            assert!(!reason.is_empty());
            assert!(is_display_safe(&reason));
            assert_eq!(reason.starts_with(MALFORMED_PREFIX), value.is_err());
            return;
        }
    };
    let value = value.expect("an accepted payload is valid json");

    let scanned = match &call {
        CodexToolCall::Unscanned => None,
        CodexToolCall::ApplyPatch { command, cwd } => {
            Some(("PreToolUse", "apply_patch", command.as_str(), cwd.as_deref()))
        }
        CodexToolCall::Bash { command, cwd } => {
            Some(("PreToolUse", "Bash", command.as_str(), cwd.as_deref()))
        }
        CodexToolCall::BashOutput { output, cwd } => {
            Some(("PostToolUse", "Bash", output.as_str(), cwd.as_deref()))
        }
    };
    // serde's derived structs also take positional arrays; the named checks read objects
    if let Value::Object(payload) = &value {
        check_codex_fields(payload, scanned);
    }

    let Some((event, tool, text, cwd)) = scanned else {
        return;
    };
    let rebuilt = if event == "PostToolUse" {
        json!({
            "hook_event_name": event,
            "tool_name": tool,
            "tool_input": {},
            "tool_response": text,
            "cwd": cwd,
        })
    } else {
        json!({
            "hook_event_name": event,
            "tool_name": tool,
            "tool_input": {"command": text},
            "cwd": cwd,
        })
    };
    let rebuilt = serde_json::to_vec(&rebuilt).expect("a json value serializes");
    assert_eq!(parse_codex_payload(&rebuilt), Ok(call));
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        check_claude(text);
    }
    check_codex(data);
});
