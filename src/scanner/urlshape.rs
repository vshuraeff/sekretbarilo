// URL-shape recognition for exemption-layer filtering

// wired in the exemption-layer glue
#[allow(dead_code)]
/// returns whether a URL-shaped value has no credential-bearing component.
///
/// the git-position exception is a semantic exception to the general opaque-run cap.
/// a capability URL carrying a hex bearer token in a git-position path slot is not
/// detected by this rule. it is intended only for the generic-high-entropy-value
/// rule; callers decide which rules this result gates.
pub fn is_credential_free_url(value: &[u8]) -> bool {
    let rest = if let Some(rest) = value.strip_prefix(b"//") {
        rest
    } else {
        let Some(scheme_end) = scheme_end(value) else {
            return false;
        };
        let Some(rest) = value.get(scheme_end + 3..) else {
            return false;
        };
        rest
    };

    let authority_end = rest
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains(&b'@') || !host_labels_allowed(authority) {
        return false;
    }

    let path_and_more = &rest[authority_end..];
    let question = path_and_more.iter().position(|byte| *byte == b'?');
    let fragment = path_and_more.iter().position(|byte| *byte == b'#');
    let path_end = match (question, fragment) {
        (Some(question), Some(fragment)) => question.min(fragment),
        (Some(question), None) => question,
        (None, Some(fragment)) => fragment,
        (None, None) => path_and_more.len(),
    };

    if !path_segments_allowed(&path_and_more[..path_end]) {
        return false;
    }

    if let Some(question) = question.filter(|question| {
        fragment
            .map(|fragment| *question < fragment)
            .unwrap_or(true)
    }) {
        let query_end = fragment.unwrap_or(path_and_more.len());
        if !query_allowed(&path_and_more[question + 1..query_end]) {
            return false;
        }
    }

    if let Some(fragment) = fragment {
        return component_allowed(&path_and_more[fragment + 1..]);
    }

    true
}

/// returns whether a value has a url scheme or network-path prefix.
pub fn is_url_shaped(value: &[u8]) -> bool {
    value.starts_with(b"//") || scheme_end(value).is_some()
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// locates a credential-bearing span within a URL-shaped value.
pub fn unwrap_markdown_target(value: &[u8]) -> Option<std::ops::Range<usize>> {
    if value.starts_with(b"<") && value.ends_with(b">") && value.len() >= 2 {
        let target = &value[1..value.len() - 1];
        if !target.is_empty() && !contains_ascii_whitespace(target) && scheme_end(target).is_some()
        {
            return Some(1..value.len() - 1);
        }
        return None;
    }

    let label_start = match value.first() {
        Some(b'[') => 1,
        Some(b'!') if value.get(1) == Some(&b'[') => 2,
        _ => return None,
    };
    let label_end = value[label_start..]
        .iter()
        .position(|byte| *byte == b']')
        .map(|offset| label_start + offset)?;
    let target_start = label_end + 2;
    if value.get(label_end + 1) != Some(&b'(')
        || value.last() != Some(&b')')
        || target_start > value.len() - 1
    {
        return None;
    }

    let label = &value[label_start..label_end];
    let target = &value[target_start..value.len() - 1];
    if has_opaque_run(label) || contains_ascii_whitespace(target) {
        return None;
    }

    Some(target_start..value.len() - 1)
}

// wired in the exemption-layer glue
#[allow(dead_code)]
/// returns whether a key/value pair is a pinned action reference.
pub fn is_pinned_action_ref(key: Option<&[u8]>, value: &[u8]) -> bool {
    let Some(key) = key else {
        return false;
    };
    let key = strip_matching_quotes(key);
    if key != b"uses" {
        return false;
    }

    let Some(at) = value.iter().rposition(|byte| *byte == b'@') else {
        return false;
    };
    let reference = &value[..at];
    let digest = &value[at + 1..];

    if let Some(image) = reference.strip_prefix(b"docker://") {
        return !image.is_empty()
            && !contains_ascii_whitespace(image)
            && digest
                .strip_prefix(b"sha256:")
                .is_some_and(|hex| is_hex_run(hex, 64, 64));
    }

    !reference.is_empty()
        && reference.contains(&b'/')
        && reference
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'-'))
        && is_hex_run(digest, 40, 40)
}

fn scheme_end(value: &[u8]) -> Option<usize> {
    if !value.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }

    let mut end = 1;
    while value
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
    {
        end += 1;
    }

    value
        .get(end..end + 3)
        .filter(|prefix| *prefix == b"://")
        .map(|_| end)
}

fn contains_ascii_whitespace(value: &[u8]) -> bool {
    value.iter().any(u8::is_ascii_whitespace)
}

fn has_opaque_run(value: &[u8]) -> bool {
    let mut run_length = 0;
    for byte in value {
        if byte.is_ascii_whitespace() {
            run_length = 0;
        } else {
            run_length += 1;
            if run_length >= 20 {
                return true;
            }
        }
    }
    false
}

fn host_labels_allowed(authority: &[u8]) -> bool {
    let Some(last_dot) = authority.iter().rposition(|byte| *byte == b'.') else {
        return component_allowed(
            authority
                .split(|byte| *byte == b':')
                .next()
                .unwrap_or_default(),
        );
    };

    if !authority[..last_dot]
        .split(|byte| *byte == b'.')
        .all(component_allowed)
    {
        return false;
    }

    let final_label = authority[last_dot + 1..]
        .split(|byte| *byte == b':')
        .next()
        .unwrap_or_default();
    component_allowed(final_label)
}

fn path_segments_allowed(path: &[u8]) -> bool {
    let mut previous = None;
    for segment in path
        .split(|byte| *byte == b'/')
        .filter(|segment| !segment.is_empty())
    {
        let decoded = percent_decode(segment);
        if decoded.len() >= 20
            && !crate::scanner::wordshape::is_word_structured(&decoded)
            && !is_git_position(&decoded, previous)
        {
            return false;
        }
        previous = Some(segment);
    }
    true
}

fn query_allowed(query: &[u8]) -> bool {
    for pair in query.split(|byte| *byte == b'&') {
        let (key, value) = match pair.iter().position(|byte| *byte == b'=') {
            Some(equal) => (&pair[..equal], &pair[equal + 1..]),
            None => {
                if !component_allowed(pair) {
                    return false;
                }
                (pair, &[][..])
            }
        };
        if is_veto_key(&percent_decode(key)) || !component_allowed(key) || !component_allowed(value)
        {
            return false;
        }
    }
    true
}

fn is_veto_key(key: &[u8]) -> bool {
    const VETO_KEYS: &[&[u8]] = &[
        b"token",
        b"access_token",
        b"accesstoken",
        b"key",
        b"api_key",
        b"apikey",
        b"secret",
        b"sig",
        b"signature",
        b"password",
        b"passwd",
        b"pass",
        b"pwd",
        b"auth",
        b"authorization",
        b"x-amz-signature",
        b"x-amz-credential",
        b"x-amz-security-token",
        b"sv",
        b"st",
        b"se",
        b"sr",
        b"sp",
        b"sas",
        b"sas_token",
        b"private_token",
        b"client_secret",
        b"code",
    ];

    VETO_KEYS.iter().any(|candidate| {
        key.len() == candidate.len()
            && key
                .iter()
                .zip(*candidate)
                .all(|(byte, candidate)| byte.to_ascii_lowercase() == *candidate)
    })
}

fn component_allowed(value: &[u8]) -> bool {
    let decoded = percent_decode(value);
    decoded.len() < 20 || crate::scanner::wordshape::is_word_structured(&decoded)
}

fn is_git_position(segment: &[u8], previous: Option<&[u8]>) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    const GIT_POSITIONS: &[&[u8]] = &[
        b"compare", b"commit", b"commits", b"tree", b"blob", b"blame", b"raw",
    ];

    if GIT_POSITIONS.contains(&previous) && is_hex_run(segment, 7, 64) {
        return true;
    }
    if previous != b"compare" {
        return false;
    }

    split_hex_range(segment, b"...") || split_hex_range(segment, b"..")
}

fn split_hex_range(segment: &[u8], separator: &[u8]) -> bool {
    let Some(start) = segment
        .windows(separator.len())
        .position(|window| window == separator)
    else {
        return false;
    };
    let end = start + separator.len();
    is_hex_run(&segment[..start], 7, 64) && is_hex_run(&segment[end..], 7, 64)
}

fn is_hex_run(value: &[u8], min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.iter().all(u8::is_ascii_hexdigit)
}

fn percent_decode(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%'
            && let Some(byte) = value
                .get(index + 1..index + 3)
                .and_then(|digits| hex_byte(digits[0], digits[1]))
        {
            decoded.push(byte);
            index += 3;
            continue;
        }
        decoded.push(value[index]);
        index += 1;
    }
    decoded
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? << 4 | hex_digit(low)?)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn strip_matching_quotes(value: &[u8]) -> &[u8] {
    if value.len() >= 2 && matches!(value[0], b'\'' | b'"') && value[0] == value[value.len() - 1] {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distinct_token(len: usize) -> String {
        (b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .cycle()
            .take(len)
            .map(char::from)
            .collect()
    }

    fn hex_token(len: usize) -> String {
        (0..len)
            .map(|index| char::from_digit((index % 16) as u32, 16).unwrap())
            .collect()
    }

    #[test]
    fn credential_free_urls_accept_expected_shapes() {
        let hex = hex_token(40);

        for value in [
            "https://github.com/owner/repo/compare/v1.0.0...v1.1.0".to_owned(),
            format!("//github.com/owner/repo/compare/{hex}...{hex}"),
            "https://www.apache.org/licenses/LICENSE-2.0".to_owned(),
            "https://img.shields.io/badge/license-MIT.svg".to_owned(),
            "https://github.com/owner/repo/archive/refs/tags/v2026.09.zip".to_owned(),
            "https://vector.example.internal:9598/metrics?format=prometheus".to_owned(),
            format!("https://host/commit/{hex}"),
            format!("https://host/blob/{hex}/README.md"),
            "https://host/path?format=short".to_owned(),
            "https://host/path#about".to_owned(),
        ] {
            assert!(is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_reject_credentials_and_opaque_parts() {
        let opaque = distinct_token(24);
        let non_hex = distinct_token(40);
        let hex = hex_token(40);

        for value in [
            format!("https://user:{opaque}@host/"),
            format!("https://host/download/{opaque}"),
            format!("https://host/?token={opaque}"),
            format!("https://host/?x={opaque}"),
            "https://host/?key=abc123".to_owned(),
            format!("https://host/?%74oken={opaque}"),
            format!("https://host/#{opaque}"),
            format!("//host/{opaque}"),
            format!("https://{opaque}.ngrok.io/"),
            format!("https://host/blob/{non_hex}"),
            format!("https://host/x/{hex}"),
            format!("ftp://host/{opaque}"),
        ] {
            assert!(!is_credential_free_url(value.as_bytes()), "{value}");
        }
    }

    #[test]
    fn credential_free_urls_reject_key_only_opaque_query_values() {
        let opaque = distinct_token(32);
        assert!(!is_credential_free_url(
            format!("https://host/?{opaque}").as_bytes()
        ));
        assert!(is_credential_free_url(b"https://host/?v=sample"));
        assert!(is_credential_free_url(b"https://host/?debug"));
    }

    #[test]
    fn credential_free_urls_reject_opaque_query_keys_with_values() {
        let opaque = distinct_token(32);
        let encoded = opaque
            .bytes()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
        for key in [&opaque, &encoded] {
            assert!(!is_credential_free_url(
                format!("https://host/?{key}=1").as_bytes()
            ));
        }
    }

    #[test]
    fn credential_free_urls_preserve_query_key_and_value_policy() {
        let opaque = distinct_token(32);
        for key in ["page", "utm_source", "v", "redirect_uri"] {
            assert!(is_credential_free_url(
                format!("https://host/?{key}=sample").as_bytes()
            ));
            assert!(!is_credential_free_url(
                format!("https://host/?{key}={opaque}").as_bytes()
            ));
        }
        assert!(!is_credential_free_url(
            format!("https://host/path?token={opaque}").as_bytes()
        ));
    }

    #[test]
    fn unwraps_markdown_targets() {
        let link = b"[text](docs/plans/x.md)";
        let range = unwrap_markdown_target(link).unwrap();
        assert_eq!(&link[range], b"docs/plans/x.md");

        let image = b"![alt](/images/a.png)";
        let range = unwrap_markdown_target(image).unwrap();
        assert_eq!(&image[range], b"/images/a.png");

        let autolink = b"<https://example.com/a>";
        let range = unwrap_markdown_target(autolink).unwrap();
        assert_eq!(&autolink[range], b"https://example.com/a");
    }

    #[test]
    fn refuses_malformed_or_opaque_markdown_targets() {
        let opaque = distinct_token(20);
        let opaque_label = format!("[{opaque}](notes)");

        for value in [
            opaque_label.as_bytes(),
            b"[a](b) c",
            b"[a]",
            b"text](x)",
            b"[a](has space)",
            b"<not-a-url>",
        ] {
            assert!(unwrap_markdown_target(value).is_none());
        }
    }

    #[test]
    fn recognizes_pinned_action_references() {
        let sha1 = hex_token(40);
        let action = format!("actions/checkout@{sha1}");
        let sha256 = hex_token(64);
        let image = format!("docker://ghcr.io/org/img@sha256:{sha256}");

        assert!(is_pinned_action_ref(Some(b"uses"), action.as_bytes()));
        assert!(is_pinned_action_ref(Some(b"\"uses\""), action.as_bytes()));
        assert!(is_pinned_action_ref(Some(b"uses"), image.as_bytes()));
    }

    #[test]
    fn rejects_unpinned_or_wrong_action_references() {
        let opaque = distinct_token(24);
        let sha1 = hex_token(40);

        assert!(!is_pinned_action_ref(Some(b"uses"), b"actions/checkout@v4"));
        assert!(!is_pinned_action_ref(
            Some(b"uses"),
            format!("actions/checkout@{opaque}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            Some(b"use"),
            format!("actions/checkout@{sha1}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            Some(b"uses_ref"),
            format!("actions/checkout@{sha1}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            None,
            format!("actions/checkout@{sha1}").as_bytes()
        ));
        assert!(!is_pinned_action_ref(
            Some(b"uses"),
            format!("checkout@{sha1}").as_bytes()
        ));
    }
}
