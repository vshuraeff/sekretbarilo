// regular-expression structure recognition for exemption-layer filtering

#[derive(Clone, Copy)]
enum QuantifierAnchor {
    None,
    Class,
    Group,
    Escape,
}

struct ParsedClass {
    end: usize,
    counted: bool,
    max_plain_run: usize,
}

/// recognizes values whose byte structure is itself a regular-expression literal.
pub fn is_regex_shaped(value: &[u8]) -> bool {
    let mut kinds = [false; 4];
    let mut groups = Vec::new();
    let mut anchor = QuantifierAnchor::None;
    let mut plain_run = 0;
    let mut disqualified = false;
    let mut index = 0;

    while index < value.len() {
        if value[index] == b'['
            && let Some(class) = parse_class(value, index)
        {
            if class.counted {
                kinds[0] = true;
                plain_run = 0;
                anchor = QuantifierAnchor::Class;
            } else {
                disqualified |= class.max_plain_run >= 20;
                plain_run = 0;
                anchor = QuantifierAnchor::None;
            }
            index = class.end;
            continue;
        }

        if value[index] == b'{'
            && let Some(end) = quantifier_end(value, index)
            && matches!(
                anchor,
                QuantifierAnchor::Class | QuantifierAnchor::Group | QuantifierAnchor::Escape
            )
        {
            kinds[1] = true;
            plain_run = 0;
            anchor = QuantifierAnchor::None;
            index = end;
            continue;
        }

        if matches!(value[index], b'*' | b'+' | b'?')
            && matches!(
                anchor,
                QuantifierAnchor::Class | QuantifierAnchor::Group | QuantifierAnchor::Escape
            )
        {
            kinds[1] = true;
            plain_run = 0;
            anchor = QuantifierAnchor::None;
            index += 1;
            continue;
        }

        if value[index] == b'\\'
            && let Some(end) = escape_end(value, index)
        {
            kinds[2] = true;
            observe_plain(&value[index..end], &mut plain_run, &mut disqualified);
            anchor = QuantifierAnchor::Escape;
            index = end;
            continue;
        }

        match value[index] {
            b'(' => {
                kinds[3] |= is_group_opener(value, index);
                groups.push(());
                observe_plain(&value[index..index + 1], &mut plain_run, &mut disqualified);
                anchor = QuantifierAnchor::None;
            }
            b')' => {
                observe_plain(&value[index..index + 1], &mut plain_run, &mut disqualified);
                anchor = if groups.pop().is_some() {
                    QuantifierAnchor::Group
                } else {
                    QuantifierAnchor::None
                };
            }
            _ => {
                observe_plain(&value[index..index + 1], &mut plain_run, &mut disqualified);
                anchor = QuantifierAnchor::None;
            }
        }
        index += 1;
    }

    !disqualified && kinds[0] && kinds.into_iter().filter(|found| *found).count() >= 2
}

fn parse_class(value: &[u8], start: usize) -> Option<ParsedClass> {
    let mut index = start + 1;
    let mut negated = false;
    if value.get(index) == Some(&b'^') {
        negated = true;
        index += 1;
    }
    if value.get(index) == Some(&b']') {
        index += 1;
    }

    let mut has_range = false;
    let mut has_escape = false;
    let mut has_posix = false;
    let mut plain_run = 0;
    let mut max_plain_run = 0;
    while index < value.len() {
        let byte = value[index];
        if is_opaque_byte(byte) {
            plain_run += 1;
            max_plain_run = max_plain_run.max(plain_run);
        } else {
            plain_run = 0;
        }

        if byte == b'\\' {
            if index + 1 < value.len() {
                has_escape = true;
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if let Some(end) = posix_class_end(value, index) {
            has_posix = true;
            index = end;
            continue;
        }
        if byte == b']' {
            return Some(ParsedClass {
                end: index + 1,
                counted: negated || has_range || has_escape || has_posix,
                max_plain_run,
            });
        }
        if value
            .get(index + 1..index + 3)
            .is_some_and(|tail| tail[0] == b'-' && is_valid_range(byte, tail[1]))
        {
            has_range = true;
        }
        index += 1;
    }
    None
}

fn posix_class_end(value: &[u8], start: usize) -> Option<usize> {
    if value.get(start..start + 2) != Some(b"[:") {
        return None;
    }
    let mut index = start + 2;
    let name_start = index;
    while value.get(index).is_some_and(u8::is_ascii_alphabetic) {
        index += 1;
    }
    (index > name_start && value.get(index..index + 2) == Some(b":]")).then_some(index + 2)
}

fn is_valid_range(start: u8, end: u8) -> bool {
    start < end
        && matches!(
            (start, end),
            (b'0'..=b'9', b'0'..=b'9') | (b'a'..=b'z', b'a'..=b'z') | (b'A'..=b'Z', b'A'..=b'Z')
        )
}

fn quantifier_end(value: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    let digits_start = index;
    while value.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    if index == digits_start {
        return None;
    }
    if value.get(index) == Some(&b'}') {
        return Some(index + 1);
    }
    if value.get(index) != Some(&b',') {
        return None;
    }
    index += 1;
    while value.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    (value.get(index) == Some(&b'}')).then_some(index + 1)
}

fn escape_end(value: &[u8], start: usize) -> Option<usize> {
    let slashes = if value.get(start + 1) == Some(&b'\\') {
        2
    } else {
        1
    };
    let target = start + slashes;
    value
        .get(target)
        .filter(|byte| is_regex_escape(**byte))
        .map(|_| target + 1)
}

fn is_regex_escape(byte: u8) -> bool {
    matches!(
        byte,
        b'b' | b'B'
            | b'd'
            | b'D'
            | b'w'
            | b'W'
            | b's'
            | b'S'
            | b'.'
            | b'$'
            | b'^'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'|'
            | b'+'
            | b'*'
            | b'?'
            | b'/'
    )
}

fn is_group_opener(value: &[u8], start: usize) -> bool {
    if value.get(start..start + 3) == Some(b"(?:")
        || value.get(start..start + 4) == Some(b"(?P<")
        || value.get(start..start + 3) == Some(b"(?<")
        || value.get(start..start + 3) == Some(b"(?=")
        || value.get(start..start + 3) == Some(b"(?!")
    {
        return true;
    }
    if value.get(start..start + 2) != Some(b"(?") {
        return false;
    }
    let mut index = start + 2;
    while value
        .get(index)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'-')
    {
        index += 1;
    }
    index > start + 2 && matches!(value.get(index), Some(b')' | b':'))
}

fn observe_plain(bytes: &[u8], plain_run: &mut usize, disqualified: &mut bool) {
    for &byte in bytes {
        if is_opaque_byte(byte) {
            *plain_run += 1;
            *disqualified |= *plain_run >= 20;
        } else {
            *plain_run = 0;
        }
    }
}

fn is_opaque_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::is_regex_shaped;

    #[test]
    fn class_based_kind_pairs_are_regex_shaped() {
        for value in [b"[A-Z]{2,8}".as_slice(), br"[A-Z]\d", b"(?i:[a-z])"] {
            assert!(is_regex_shaped(value), "{value:?}");
        }
    }

    #[test]
    fn quantifiers_without_counted_classes_are_not_enough() {
        for value in [br"\d{2,4}".as_slice(), b"(?:segment){2}"] {
            assert!(!is_regex_shaped(value), "{value:?}");
        }
    }

    #[test]
    fn bracket_classes_honor_regex_edge_cases() {
        for value in [br"[^]]{1,2}".as_slice(), br"[\]]\d", br"[[:alpha:]]\d"] {
            assert!(is_regex_shaped(value), "{value:?}");
        }
    }

    #[test]
    fn one_kind_or_unanchored_quantifiers_are_not_enough() {
        for value in [
            b"[A-Z]".as_slice(),
            br"\d",
            b"(?i:plain)",
            b"[plain]+",
            b"literal{2,4}",
        ] {
            assert!(!is_regex_shaped(value), "{value:?}");
        }
    }

    #[test]
    fn opaque_runs_outside_counted_constructs_disqualify_the_value() {
        assert!(is_regex_shaped(b"[A-ZABCDEFGHIJKLMNOPQRSTUVWXYZ]{2}"));
        assert!(!is_regex_shaped(
            b"(?i)[A-Za-z]{2}prefix_Ab3D4e5F6g7H8i9J0kLmN"
        ));
    }

    #[test]
    fn false_positive_fixture_bodies_are_regex_shaped() {
        let mut checked = 0;
        for line in include_str!("../../tests/fixtures/false_positives/regex-literal.txt")
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with("# "))
        {
            let body = fixture_body(line);
            assert!(is_regex_shaped(body), "{line}");
            checked += 1;
        }
        assert!(checked >= 8, "checked only {checked} fixture bodies");
    }

    fn fixture_body(line: &str) -> &[u8] {
        let start = line
            .find("r\"")
            .map(|index| index + 2)
            .or_else(|| line.find('"').map(|index| index + 1))
            .expect("fixture line carries a quoted literal");
        let end = start
            + line[start..]
                .find('"')
                .expect("fixture line closes its quoted literal");
        &line.as_bytes()[start..end]
    }
}
