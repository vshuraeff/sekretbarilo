// the binary compiles scanner modules separately; engine integration is pending.
#![allow(dead_code)]

use std::ops::Range;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Language {
    Rust,
    Go,
    Python,
    JavaScript,
    C,
}

pub fn language_for_path(path: &str) -> Option<Language> {
    let segment = path.rsplit('/').next()?;
    let (_, extension) = segment.rsplit_once('.')?;
    // complete-source parsers select other languages separately from this streaming tracker.
    [(Language::Rust, &["rs"][..]), (Language::Go, &["go"][..])]
        .into_iter()
        .find_map(|(language, extensions)| {
            extensions
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
                .then_some(language)
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineLiterals {
    pub bodies: Vec<Range<usize>>,
    pub known: bool,
    pub test_span: Option<Range<usize>>,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Code,
    Unknown,
    CLineComment,
    Block(usize),
    Quoted {
        quote: u8,
        triple: bool,
        fstring: bool,
    },
    RustRaw(usize),
    GoRaw,
    CRaw {
        delimiter: [u8; 16],
        len: usize,
    },
    Template,
}

#[derive(Debug, Clone)]
enum RustTestPending {
    None,
    Hash {
        test: bool,
        inner: bool,
    },
    Attribute {
        test: bool,
        inner: bool,
        delimiters: Vec<u8>,
        tokens: Vec<Vec<u8>>,
    },
    Item {
        test: bool,
        header: Vec<Vec<u8>>,
    },
}

#[derive(Debug, Clone)]
struct State {
    mode: Mode,
    // each active template has zero braces in text, or positive depth in code.
    templates: [usize; 4],
    template_count: usize,
    expression: bool,
    rust_brace_depth: usize,
    rust_test_pending: RustTestPending,
    test_region: Option<usize>,
    rust_scope_eligible: Vec<bool>,
    rust_scope_fresh: Vec<bool>,
    rust_item_boundary: bool,
    rust_macro_delimiters: Vec<u8>,
}

impl State {
    fn new() -> Self {
        Self {
            mode: Mode::Code,
            templates: [0; 4],
            template_count: 0,
            expression: true,
            rust_brace_depth: 0,
            rust_test_pending: RustTestPending::None,
            test_region: None,
            rust_scope_eligible: vec![true],
            rust_scope_fresh: vec![true],
            rust_item_boundary: true,
            rust_macro_delimiters: Vec::new(),
        }
    }
}

fn cfg_attribute_implies_test(tokens: &[Vec<u8>]) -> bool {
    if tokens.first().is_none_or(|token| token != b"cfg")
        || tokens.get(1).is_none_or(|token| token != b"(")
    {
        return false;
    }
    let mut index = 2;
    let implied = cfg_expr_implies_test(tokens, &mut index, 0);
    implied == Some(true)
        && tokens.get(index).is_some_and(|token| token == b")")
        && index + 1 == tokens.len()
}

fn cfg_expr_implies_test(tokens: &[Vec<u8>], index: &mut usize, depth: usize) -> Option<bool> {
    if depth > 32 {
        return None;
    }
    let name = tokens.get(*index)?;
    *index += 1;
    if !rust_identifier(name) {
        return None;
    }
    if tokens.get(*index).is_some_and(|token| token == b"=") {
        *index += 1;
        if tokens.get(*index).is_none_or(|token| token != b"\"") {
            return None;
        }
        *index += 1;
        return Some(false);
    }
    if tokens.get(*index).is_none_or(|token| token != b"(") {
        return Some(name == b"test");
    }
    if !matches!(name.as_slice(), b"all" | b"any" | b"not") {
        return None;
    }
    *index += 1;
    let mut count = 0;
    let mut implied = name == b"any";
    loop {
        if tokens.get(*index).is_some_and(|token| token == b")") {
            *index += 1;
            return (name != b"not" || count == 1)
                .then_some(count > 0 && implied && name != b"not");
        }
        let child = cfg_expr_implies_test(tokens, index, depth + 1)?;
        count += 1;
        if name == b"all" {
            implied |= child;
        } else {
            implied &= child;
        }
        match tokens.get(*index).map(Vec::as_slice) {
            Some(b",") => {
                *index += 1;
                if tokens.get(*index).is_some_and(|token| token == b")") {
                    *index += 1;
                    return (name != b"not" || count == 1)
                        .then_some(count > 0 && implied && name != b"not");
                }
            }
            Some(b")") => {}
            _ => return None,
        }
    }
}

fn rust_body_header(header: &[Vec<u8>]) -> bool {
    let mut index = 0;
    if header.get(index).is_some_and(|token| token == b"pub") {
        index += 1;
        if header.get(index).is_some_and(|token| token == b"(") {
            let mut depth = 1;
            index += 1;
            while depth > 0 && index < header.len() {
                match header[index].as_slice() {
                    b"(" => depth += 1,
                    b")" => depth -= 1,
                    _ => {}
                }
                index += 1;
            }
            if depth != 0 {
                return false;
            }
        }
    }
    while header.get(index).is_some_and(|token| {
        matches!(
            token.as_slice(),
            b"async" | b"unsafe" | b"default" | b"const" | b"extern"
        )
    }) {
        let external = header[index] == b"extern";
        index += 1;
        if external && header.get(index).is_some_and(|token| token == b"\"") {
            index += 1;
        }
    }
    match header.get(index).map(Vec::as_slice) {
        Some(b"mod") => header.len() == index + 2 && rust_identifier(&header[index + 1]),
        Some(b"fn") => {
            if !header
                .get(index + 1)
                .is_some_and(|token| rust_identifier(token))
            {
                return false;
            }
            let mut paren = 0_usize;
            let mut angle = 0_usize;
            let mut bracket = 0_usize;
            let mut saw_params = false;
            for (position, token) in header[index + 2..].iter().enumerate() {
                match token.as_slice() {
                    b"(" => {
                        if paren == 0 && angle == 0 {
                            saw_params = true;
                        }
                        paren += 1;
                    }
                    b")" => {
                        if paren == 0 {
                            return false;
                        }
                        paren -= 1;
                    }
                    b"<" if paren == 0 => angle += 1,
                    b">" if paren == 0 => {
                        if angle == 0 {
                            let previous = position
                                .checked_sub(1)
                                .and_then(|i| header.get(index + 2 + i));
                            if !saw_params || previous.is_none_or(|part| part != b"-") {
                                return false;
                            }
                        } else {
                            angle -= 1;
                        }
                    }
                    b"[" => bracket += 1,
                    b"]" => {
                        if bracket == 0 {
                            return false;
                        }
                        bracket -= 1;
                    }
                    b"=" | b"!" | b"#" => return false,
                    _ => {}
                }
            }
            saw_params && paren == 0 && angle == 0 && bracket == 0
        }
        Some(b"impl") => {
            let rest = &header[index + 1..];
            let mut angle = 0_usize;
            let mut bracket = 0_usize;
            for token in rest {
                match token.as_slice() {
                    b"<" => angle += 1,
                    b">" => {
                        if angle == 0 {
                            return false;
                        }
                        angle -= 1;
                    }
                    b"[" => bracket += 1,
                    b"]" => {
                        if bracket == 0 {
                            return false;
                        }
                        bracket -= 1;
                    }
                    b"=" | b"!" | b"#" | b"{" | b"}" => return false,
                    _ => {}
                }
            }
            !rest.is_empty() && angle == 0 && bracket == 0
        }
        _ => false,
    }
}

fn rust_identifier(token: &[u8]) -> bool {
    token
        .first()
        .is_some_and(|&byte| identifier_start(byte) && byte != b'$')
        && token
            .iter()
            .all(|&byte| identifier_continue(byte) && byte != b'$')
}

fn go_tag_bodies(line: &[u8], body: Range<usize>) -> Option<Vec<Range<usize>>> {
    let tag = line.get(body.clone())?;
    let mut index = 0;
    let mut values = Vec::new();
    while index < tag.len() {
        while tag.get(index) == Some(&b' ') {
            index += 1;
        }
        if index == tag.len() {
            break;
        }
        let key_start = index;
        while tag
            .get(index)
            .is_some_and(|&byte| byte > b' ' && byte != 0x7f && !matches!(byte, b':' | b'"'))
        {
            index += 1;
        }
        if index == key_start || tag.get(index..index + 2) != Some(&b":\""[..]) {
            return None;
        }
        values.push(body.start + key_start..body.start + index);
        index += 2;
        let value_start = index;
        let mut item_start = index;
        let mut items = Vec::new();
        loop {
            match *tag.get(index)? {
                b'"' => break,
                b'\\' => index += go_tag_escape_width(tag.get(index..)?)?,
                b',' => {
                    if item_start < index {
                        items.push(body.start + item_start..body.start + index);
                    }
                    index += 1;
                    item_start = index;
                }
                byte if byte < b' ' || byte == 0x7f => return None,
                _ => index += 1,
            }
        }
        if value_start < index {
            values.push(body.start + value_start..body.start + index);
        }
        if item_start < index && item_start != value_start {
            items.push(body.start + item_start..body.start + index);
        }
        values.extend(items);
        index += 1;
        if index < tag.len() && tag[index] != b' ' {
            return None;
        }
    }
    (!values.is_empty()).then_some(values)
}

fn go_tag_escape_width(input: &[u8]) -> Option<usize> {
    let escape = *input.get(1)?;
    match escape {
        b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' | b'\\' | b'"' => Some(2),
        b'x' => input
            .get(2..4)
            .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))
            .map(|_| 4),
        b'u' | b'U' => {
            let digits = if escape == b'u' { 4 } else { 8 };
            let hex = input.get(2..2 + digits)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let scalar = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            char::from_u32(scalar).map(|_| 2 + digits)
        }
        b'0'..=b'7' => input
            .get(1..4)
            .filter(|digits| digits.iter().all(|byte| matches!(byte, b'0'..=b'7')))
            .filter(|digits| digits[0] <= b'3')
            .map(|_| 4),
        _ => None,
    }
}

fn rust_closer(opener: &[u8]) -> u8 {
    match opener {
        b"(" => b')',
        b"[" => b']',
        _ => b'}',
    }
}

#[derive(Debug, Clone)]
pub struct LiteralTracker {
    language: Language,
    state: State,
    previous_line: Option<usize>,
    known: bool,
}

impl LiteralTracker {
    pub fn new(language: Language) -> Self {
        Self {
            language,
            state: State::new(),
            previous_line: None,
            known: true,
        }
    }

    pub fn feed(&mut self, line: &[u8], line_number: usize) -> LineLiterals {
        let contiguous = match self.previous_line {
            Some(previous) => previous.checked_add(1) == Some(line_number),
            None => line_number == 1,
        };
        let recovery = !contiguous || !self.known;
        if recovery && !matches!(self.state.mode, Mode::Unknown) {
            self.state = State::new();
        }
        self.previous_line = Some(line_number);
        let mut bodies = Vec::new();
        let mut test_span = self.state.test_region.map(|_| 0..line.len());
        let result = self
            .state
            .lex(self.language, line, &mut bodies, &mut test_span);
        if result.is_err() {
            if !matches!(self.state.mode, Mode::Unknown) {
                self.state = State::new();
            }
            // failed recovery stays unknown; a broken known line restarts in code.
            self.known = !recovery && !matches!(self.state.mode, Mode::Unknown);
        } else {
            self.known = true;
        }
        let known = !recovery && result.is_ok();
        if !known {
            bodies.clear();
            test_span = None;
            self.state.rust_brace_depth = 0;
            self.state.rust_test_pending = RustTestPending::None;
            self.state.test_region = None;
            self.state.rust_scope_eligible = vec![true];
            self.state.rust_scope_fresh = vec![true];
            self.state.rust_item_boundary = true;
            self.state.rust_macro_delimiters.clear();
        }
        LineLiterals {
            bodies,
            known,
            test_span,
        }
    }

    pub fn is_known(&self) -> bool {
        self.known
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.language);
    }
}

impl State {
    fn lex(
        &mut self,
        language: Language,
        input: &[u8],
        bodies: &mut Vec<Range<usize>>,
        test_span: &mut Option<Range<usize>>,
    ) -> Result<(), ()> {
        let line = input
            .strip_suffix(b"\n")
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .unwrap_or(input);
        let mut index = 0;
        let mut body_start = 0;
        let splice = (language == Language::C)
            .then(|| line.iter().rposition(|b| !matches!(b, b' ' | b'\t')))
            .flatten()
            .filter(|&end| line[end] == b'\\');
        self.expression = true;
        loop {
            match self.mode {
                Mode::Unknown => return Err(()),
                Mode::CLineComment => {
                    if splice.is_none() {
                        self.mode = Mode::Code;
                    }
                    return Ok(());
                }
                Mode::Code => {
                    if index == line.len() {
                        return Ok(());
                    }
                    if splice == Some(index) {
                        // splicing can join tokens across physical lines.
                        self.mode = Mode::Unknown;
                        return Err(());
                    }
                    let start = index;
                    let comment =
                        line[start..].starts_with(b"//") || line[start..].starts_with(b"/*");
                    self.code(language, line, &mut index)?;
                    if language == Language::Rust && !comment && !line[start].is_ascii_whitespace()
                    {
                        self.rust_test_token(&line[start..index], start, input.len(), test_span)?;
                    }
                    body_start = index;
                }
                Mode::Block(mut depth) => {
                    while index < line.len() {
                        if line[index..].starts_with(b"*/") {
                            depth -= 1;
                            index += 2;
                            if depth == 0 {
                                self.mode = Mode::Code;
                                break;
                            }
                        } else if language == Language::Rust && line[index..].starts_with(b"/*") {
                            depth = depth.checked_add(1).ok_or(())?;
                            index += 2;
                        } else {
                            index += 1;
                        }
                    }
                    if depth > 0 {
                        if splice.is_some() {
                            self.mode = Mode::Unknown;
                            return Err(());
                        }
                        self.mode = Mode::Block(depth);
                        return Ok(());
                    }
                }
                Mode::Quoted {
                    quote,
                    triple,
                    fstring,
                } => {
                    let width = if triple { 3 } else { 1 };
                    let mut continuation = false;
                    while index < line.len() {
                        if fstring && line[index] == b'{' {
                            if line.get(index + 1) == Some(&b'{') {
                                index += 2;
                                continue;
                            }
                            // replacement fields need a parser, including across lines.
                            self.mode = Mode::Unknown;
                            return Err(());
                        }
                        if line[index..].starts_with(&[quote; 3][..width]) {
                            bodies.push(body_start..index);
                            index += width;
                            self.mode = Mode::Code;
                            self.expression = false;
                            break;
                        }
                        if line[index] == b'\\' {
                            if splice == Some(index) {
                                continuation = true;
                                break;
                            }
                            if splice == Some(index + 1) {
                                // the remaining escape would consume the next line's byte.
                                self.mode = Mode::Unknown;
                                return Err(());
                            }
                            continuation = index + 1 == line.len();
                            index += if fstring && line.get(index + 1) == Some(&b'{') {
                                1
                            } else {
                                (line.len() - index).min(2)
                            };
                        } else {
                            index += 1;
                        }
                    }
                    if matches!(self.mode, Mode::Quoted { .. }) {
                        let may_continue = triple
                            || language == Language::Rust
                            || (continuation && matches!(language, Language::Python | Language::C));
                        if !may_continue {
                            return Err(());
                        }
                        let end = splice.filter(|_| continuation).unwrap_or(line.len());
                        bodies.push(body_start..end);
                        return Ok(());
                    }
                }
                Mode::RustRaw(hashes) => {
                    let mut closed = false;
                    while index < line.len() {
                        if line[index] == b'"' {
                            let end = index;
                            index += 1;
                            let mut matched = 0;
                            while matched < hashes && line.get(index) == Some(&b'#') {
                                matched += 1;
                                index += 1;
                            }
                            if matched == hashes {
                                bodies.push(body_start..end);
                                closed = true;
                                break;
                            }
                        } else {
                            index += 1;
                        }
                    }
                    if !closed {
                        bodies.push(body_start..line.len());
                        return Ok(());
                    }
                    self.mode = Mode::Code;
                    self.expression = false;
                }
                Mode::GoRaw | Mode::CRaw { .. } => {
                    let mut closed = false;
                    while index < line.len() {
                        let width = match self.mode {
                            Mode::GoRaw if line[index] == b'`' => 1,
                            Mode::CRaw { delimiter, len }
                                if line[index] == b')'
                                    && line[index + 1..].starts_with(&delimiter[..len])
                                    && line.get(index + 1 + len) == Some(&b'"') =>
                            {
                                len + 2
                            }
                            _ => 0,
                        };
                        if width > 0 {
                            let body = body_start..index;
                            if matches!(self.mode, Mode::GoRaw)
                                && body_start > 0
                                && line[body_start - 1] == b'`'
                            {
                                if let Some(tag_bodies) = go_tag_bodies(line, body.clone()) {
                                    bodies.extend(tag_bodies);
                                } else {
                                    bodies.push(body);
                                }
                            } else {
                                bodies.push(body);
                            }
                            index += width;
                            closed = true;
                            break;
                        }
                        index += 1;
                    }
                    if !closed {
                        bodies.push(body_start..line.len());
                        return Ok(());
                    }
                    self.mode = Mode::Code;
                    self.expression = false;
                }
                Mode::Template => {
                    while index < line.len() {
                        if line[index] == b'`' {
                            bodies.push(body_start..index);
                            index += 1;
                            self.template_count -= 1;
                            self.mode = Mode::Code;
                            self.expression = false;
                            break;
                        } else if line[index..].starts_with(b"${") {
                            bodies.push(body_start..index);
                            index += 2;
                            self.templates[self.template_count - 1] = 1;
                            self.mode = Mode::Code;
                            self.expression = true;
                            break;
                        } else if line[index] == b'\\' {
                            index += (line.len() - index).min(2);
                        } else {
                            index += 1;
                        }
                    }
                    if matches!(self.mode, Mode::Template) {
                        bodies.push(body_start..line.len());
                        return Ok(());
                    }
                }
            }
        }
    }

    fn rust_test_token(
        &mut self,
        token: &[u8],
        start: usize,
        line_len: usize,
        test_span: &mut Option<Range<usize>>,
    ) -> Result<(), ()> {
        use RustTestPending::{Attribute, Hash, Item, None};
        if !self.rust_macro_delimiters.is_empty() {
            match token {
                b"(" | b"[" | b"{" => {
                    if self.rust_macro_delimiters.len() >= 256 {
                        self.mode = Mode::Unknown;
                        return Err(());
                    }
                    self.rust_macro_delimiters.push(rust_closer(token));
                }
                b")" | b"]" | b"}" => {
                    if self.rust_macro_delimiters.pop() != Some(token[0]) {
                        self.mode = Mode::Unknown;
                        return Err(());
                    }
                    if self.rust_macro_delimiters.is_empty() {
                        self.rust_item_boundary = true;
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        if token == b"}" && !matches!(self.rust_test_pending, Attribute { .. }) {
            self.rust_brace_depth = self.rust_brace_depth.saturating_sub(1);
            self.rust_scope_eligible.pop();
            self.rust_scope_fresh.pop();
            if self.test_region == Some(self.rust_brace_depth) {
                self.test_region = Option::None;
                if let Some(span) = test_span {
                    span.end = start;
                }
            }
            self.rust_test_pending = None;
            self.rust_item_boundary = true;
            return Ok(());
        }
        let pending = std::mem::replace(&mut self.rust_test_pending, None);
        self.rust_test_pending = match pending {
            Hash { test, inner } if token == b"!" && !inner => Hash { test, inner: true },
            Hash { test, inner } if token == b"[" => Attribute {
                test,
                inner,
                delimiters: vec![b']'],
                tokens: Vec::new(),
            },
            Attribute {
                test,
                inner,
                mut delimiters,
                mut tokens,
            } => {
                if (delimiters.len() != 1 || token != b"]") && tokens.len() >= 512 {
                    self.mode = Mode::Unknown;
                    return Err(());
                }
                if matches!(token, b"[" | b"(" | b"{") {
                    tokens.push(token.to_vec());
                    delimiters.push(rust_closer(token));
                    Attribute {
                        test,
                        inner,
                        delimiters,
                        tokens,
                    }
                } else if matches!(token, b"]" | b")" | b"}") {
                    if delimiters.pop() != Some(token[0]) {
                        self.mode = Mode::Unknown;
                        return Err(());
                    }
                    if !delimiters.is_empty() {
                        tokens.push(token.to_vec());
                        Attribute {
                            test,
                            inner,
                            delimiters,
                            tokens,
                        }
                    } else {
                        let implied = cfg_attribute_implies_test(&tokens);
                        if inner {
                            if implied
                                && self.test_region.is_none()
                                && test_span.is_none()
                                && *self.rust_scope_eligible.last().unwrap_or(&false)
                                && *self.rust_scope_fresh.last().unwrap_or(&false)
                            {
                                let close_depth =
                                    self.rust_brace_depth.checked_sub(1).unwrap_or(usize::MAX);
                                self.test_region = Some(close_depth);
                                *test_span = Some(start + 1..line_len);
                            }
                            self.rust_item_boundary = true;
                            None
                        } else if test || implied {
                            self.rust_item_boundary = true;
                            Item {
                                test: true,
                                header: Vec::new(),
                            }
                        } else {
                            self.rust_item_boundary = true;
                            None
                        }
                    }
                } else {
                    tokens.push(token.to_vec());
                    Attribute {
                        test,
                        inner,
                        delimiters,
                        tokens,
                    }
                }
            }
            Item { test, header } if token == b"#" && header.is_empty() => {
                Hash { test, inner: false }
            }
            Item { test, header } if token == b"{" => {
                if let Some(fresh) = self.rust_scope_fresh.last_mut() {
                    *fresh = false;
                }
                if header.iter().any(|part| part == b"!") {
                    self.rust_macro_delimiters.push(b'}');
                    self.rust_item_boundary = false;
                    return Ok(());
                }
                let body =
                    *self.rust_scope_eligible.last().unwrap_or(&false) && rust_body_header(&header);
                if test && body && self.test_region.is_none() && test_span.is_none() {
                    self.test_region = Some(self.rust_brace_depth);
                    *test_span = Some(start + 1..line_len);
                }
                self.rust_scope_eligible.push(body);
                self.rust_scope_fresh.push(body);
                self.rust_brace_depth = self.rust_brace_depth.checked_add(1).ok_or(())?;
                self.rust_item_boundary = body;
                None
            }
            Item { mut header, .. } if token == b";" => {
                if let Some(fresh) = self.rust_scope_fresh.last_mut() {
                    *fresh = false;
                }
                self.rust_item_boundary = true;
                header.clear();
                None
            }
            Item { header, .. }
                if matches!(token, b"(" | b"[") && header.iter().any(|part| part == b"!") =>
            {
                self.rust_macro_delimiters.push(rust_closer(token));
                self.rust_item_boundary = false;
                None
            }
            Item { test, mut header } if header.len() < 512 => {
                if header.is_empty()
                    && let Some(fresh) = self.rust_scope_fresh.last_mut()
                {
                    *fresh = false;
                }
                header.push(token.to_vec());
                self.rust_item_boundary = false;
                Item { test, header }
            }
            _ if token == b"#"
                && self.rust_item_boundary
                && self.test_region.is_none()
                && *self.rust_scope_eligible.last().unwrap_or(&false) =>
            {
                Hash {
                    test: false,
                    inner: false,
                }
            }
            _ if token == b"{" => {
                if let Some(fresh) = self.rust_scope_fresh.last_mut() {
                    *fresh = false;
                }
                self.rust_scope_eligible.push(false);
                self.rust_scope_fresh.push(false);
                self.rust_brace_depth = self.rust_brace_depth.checked_add(1).ok_or(())?;
                self.rust_item_boundary = false;
                None
            }
            _ if token == b";" => {
                if let Some(fresh) = self.rust_scope_fresh.last_mut() {
                    *fresh = false;
                }
                self.rust_item_boundary = true;
                None
            }
            _ if self.rust_item_boundary && self.test_region.is_none() => {
                self.rust_item_boundary = false;
                if let Some(fresh) = self.rust_scope_fresh.last_mut() {
                    *fresh = false;
                }
                Item {
                    test: false,
                    header: vec![token.to_vec()],
                }
            }
            _ => {
                self.rust_item_boundary = false;
                None
            }
        };
        Ok(())
    }

    fn code(&mut self, language: Language, line: &[u8], index: &mut usize) -> Result<(), ()> {
        let rest = &line[*index..];
        let byte = rest[0];
        if byte.is_ascii_whitespace() {
            *index += 1;
            return Ok(());
        }
        if (language == Language::Python && byte == b'#')
            || (language != Language::Python && rest.starts_with(b"//"))
        {
            if language == Language::C {
                self.mode = Mode::CLineComment;
            }
            *index = line.len();
            return Ok(());
        }
        if language != Language::Python && rest.starts_with(b"/*") {
            self.mode = Mode::Block(1);
            *index += 2;
            return Ok(());
        }
        if language == Language::Rust
            && let Some((width, hashes)) = rust_raw(rest)
        {
            self.mode = Mode::RustRaw(hashes);
            *index += width;
            return Ok(());
        }
        if language == Language::C
            && let Some((width, delimiter, len)) = c_raw(rest)?
        {
            self.mode = Mode::CRaw { delimiter, len };
            *index += width;
            return Ok(());
        }
        if byte == b'\'' && matches!(language, Language::Rust | Language::Go | Language::C) {
            if let Some(width) = char_width(rest, language) {
                *index += width;
                self.expression = false;
                return Ok(());
            }
            // rust lifetimes and labels do not start strings.
            if language != Language::Rust || !rest.get(1).is_some_and(|&b| identifier_start(b)) {
                return Err(());
            }
            *index += 1;
            return Ok(());
        }
        if byte == b'"'
            || (byte == b'\'' && matches!(language, Language::Python | Language::JavaScript))
        {
            let triple = language == Language::Python && rest.starts_with(&[byte; 3]);
            self.mode = Mode::Quoted {
                quote: byte,
                triple,
                fstring: language == Language::Python
                    && line[..*index]
                        .rsplit(|&b| !identifier_continue(b))
                        .next()
                        .is_some_and(|prefix| {
                            prefix.eq_ignore_ascii_case(b"f")
                                || prefix.eq_ignore_ascii_case(b"fr")
                                || prefix.eq_ignore_ascii_case(b"rf")
                        }),
            };
            *index += if triple { 3 } else { 1 };
            return Ok(());
        }
        if byte == b'`' && language == Language::Go {
            self.mode = Mode::GoRaw;
            *index += 1;
            return Ok(());
        }
        if language == Language::JavaScript {
            if rest.starts_with(b"++") || rest.starts_with(b"--") {
                *index += 2;
                return Ok(());
            }
            if byte == b'!' && !self.expression && !rest.starts_with(b"!=") {
                *index += 1;
                return Ok(());
            }
            if byte == b'`' {
                if self.template_count == self.templates.len() {
                    return Err(());
                }
                self.templates[self.template_count] = 0;
                self.template_count += 1;
                self.mode = Mode::Template;
                *index += 1;
                return Ok(());
            }
            if byte == b'/' && self.expression {
                *index += regex_width(rest).ok_or(())?;
                self.expression = false;
                return Ok(());
            }
            if byte == b'/' {
                *index += 1;
                self.expression = true;
                return Ok(());
            }
            if self.template_count > 0 {
                let depth = &mut self.templates[self.template_count - 1];
                if byte == b'{' {
                    *depth = depth.checked_add(1).ok_or(())?;
                } else if byte == b'}' {
                    *depth -= 1;
                    if *depth == 0 {
                        self.mode = Mode::Template;
                    }
                }
            }
        }
        if identifier_start(byte) || byte.is_ascii_digit() {
            let start = *index;
            *index += 1;
            while line.get(*index).is_some_and(|&b| identifier_continue(b)) {
                *index += 1;
            }
            self.expression = matches!(
                &line[start..*index],
                b"return"
                    | b"typeof"
                    | b"instanceof"
                    | b"in"
                    | b"of"
                    | b"new"
                    | b"delete"
                    | b"void"
                    | b"throw"
                    | b"case"
                    | b"do"
                    | b"else"
            );
        } else {
            self.expression = b"(,=:[!&|?{};+-*%<>~^".contains(&byte);
            *index += 1;
        }
        Ok(())
    }
}

fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$' | 0x80..=0xff)
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

fn rust_raw(line: &[u8]) -> Option<(usize, usize)> {
    // mirrors calllit.rs: count opener hashes, then require the same closing count.
    let mut index = if line.starts_with(b"br") || line.starts_with(b"cr") {
        2
    } else if line.starts_with(b"r") {
        1
    } else {
        return None;
    };
    let start = index;
    while line.get(index) == Some(&b'#') {
        index += 1;
    }
    (line.get(index) == Some(&b'"')).then_some((index + 1, index - start))
}

type CRawOpener = (usize, [u8; 16], usize);

fn c_raw(line: &[u8]) -> Result<Option<CRawOpener>, ()> {
    let Some(prefix) = [b"R\"".as_slice(), b"u8R\"", b"LR\"", b"uR\"", b"UR\""]
        .into_iter()
        .find(|prefix| line.starts_with(prefix))
    else {
        return Ok(None);
    };
    let mut delimiter = [0; 16];
    let mut len = 0;
    let mut index = prefix.len();
    while let Some(&byte) = line.get(index) {
        if byte == b'(' {
            return Ok(Some((index + 1, delimiter, len)));
        }
        if len == delimiter.len() || byte.is_ascii_whitespace() || b")\\\"".contains(&byte) {
            return Err(());
        }
        delimiter[len] = byte;
        len += 1;
        index += 1;
    }
    Err(())
}

fn char_width(line: &[u8], language: Language) -> Option<usize> {
    let byte = *line.get(1)?;
    let end = if byte == b'\\' {
        match *line.get(2)? {
            b'x' => hex_escape_end(line, 3, 2)?,
            b'u' if language == Language::Rust => {
                if line.get(3) != Some(&b'{') {
                    return None;
                }
                let mut index = 4;
                let mut digits = 0;
                while let Some(&byte) = line.get(index) {
                    if byte == b'}' {
                        break;
                    }
                    if !byte.is_ascii_hexdigit() || digits == 6 {
                        return None;
                    }
                    digits += 1;
                    index += 1;
                }
                if digits == 0 || line.get(index) != Some(&b'}') {
                    return None;
                }
                index + 1
            }
            b'u' => hex_escape_end(line, 3, 4)?,
            b'U' => hex_escape_end(line, 3, 8)?,
            _ => 3,
        }
    } else if matches!(byte, b'\'' | b'\r' | b'\n') {
        return None;
    } else if byte.is_ascii() {
        2
    } else {
        let width = match byte {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return None,
        };
        std::str::from_utf8(line.get(1..1 + width)?).ok()?;
        1 + width
    };
    (line.get(end) == Some(&b'\'')).then_some(end + 1)
}

fn hex_escape_end(line: &[u8], start: usize, digits: usize) -> Option<usize> {
    line.get(start..start + digits)?
        .iter()
        .all(u8::is_ascii_hexdigit)
        .then_some(start + digits)
}

fn regex_width(line: &[u8]) -> Option<usize> {
    let mut index = 1;
    let mut class = false;
    while index < line.len() {
        match line[index] {
            b'\\' => index += (line.len() - index).min(2),
            b'[' => {
                class = true;
                index += 1;
            }
            b']' => {
                class = false;
                index += 1;
            }
            b'/' if !class => {
                index += 1;
                while line.get(index).is_some_and(|&b| identifier_continue(b)) {
                    index += 1;
                }
                return Some(index);
            }
            _ => index += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const LANGUAGES: [Language; 5] = [
        Language::Rust,
        Language::Go,
        Language::Python,
        Language::JavaScript,
        Language::C,
    ];

    fn token(seed: usize) -> String {
        (0..32)
            .map(|index| {
                let byte = if index % 5 == 0 {
                    b'0' + ((index + seed) % 10) as u8
                } else {
                    let base = if index % 2 == 0 { b'A' } else { b'a' };
                    base + ((index * 7 + seed) % 26) as u8
                };
                char::from(byte)
            })
            .collect()
    }

    fn check(tracker: &mut LiteralTracker, line: &[u8], number: usize, expected: &[&[u8]]) {
        let result = tracker.feed(line, number);
        assert!(result.known, "{line:?}: {result:?}");
        assert!(tracker.is_known());
        let mut end = 0;
        for range in &result.bodies {
            assert!(end <= range.start && range.start <= range.end && range.end <= line.len());
            end = range.end;
        }
        assert_eq!(
            result
                .bodies
                .iter()
                .map(|range| &line[range.clone()])
                .collect::<Vec<_>>(),
            expected,
            "{line:?}"
        );
    }

    #[test]
    fn literal_forms_and_comment_negatives() {
        let forms = [
            (Language::Rust, "\"", "\""),
            (Language::Rust, "b\"", "\""),
            (Language::Rust, "c\"", "\""),
            (Language::Rust, "r\"", "\""),
            (Language::Rust, "r#\"", "\"#"),
            (Language::Rust, "r##\"", "\"##"),
            (Language::Rust, "br\"", "\""),
            (Language::Rust, "br#\"", "\"#"),
            (Language::Rust, "cr\"", "\""),
            (Language::Rust, "cr#\"", "\"#"),
            (Language::Go, "\"", "\""),
            (Language::Go, "`", "`"),
            (Language::Python, "\"", "\""),
            (Language::Python, "'", "'"),
            (Language::Python, "\"\"\"", "\"\"\""),
            (Language::Python, "'''", "'''"),
            (Language::JavaScript, "\"", "\""),
            (Language::JavaScript, "'", "'"),
            (Language::JavaScript, "`", "`"),
            (Language::C, "\"", "\""),
            (Language::C, "R\"(", ")\""),
            (Language::C, "R\"tag(", ")tag\""),
            (Language::C, "u8R\"tag(", ")tag\""),
            (Language::C, "LR\"tag(", ")tag\""),
            (Language::C, "uR\"tag(", ")tag\""),
            (Language::C, "UR\"tag(", ")tag\""),
            (Language::C, "#include \"", "\""),
        ];
        for (seed, (language, opener, closer)) in forms.into_iter().enumerate() {
            let value = token(seed);
            let source = format!("{opener}{value}{closer}");
            let mut tracker = LiteralTracker::new(language);
            let result = tracker.feed(source.as_bytes(), 1);
            assert!(result.known, "{language:?}: {source}");
            assert_eq!(
                result.bodies,
                vec![opener.len()..opener.len() + value.len()]
            );
            assert_eq!(
                &source.as_bytes()[result.bodies[0].clone()],
                value.as_bytes()
            );
            let comment = if language == Language::Python {
                "#"
            } else {
                "//"
            };
            let negative = format!("{comment} {source}");
            check(&mut tracker, negative.as_bytes(), 2, &[]);
            check(
                &mut tracker,
                format!("identifier_{value}").as_bytes(),
                3,
                &[],
            );
        }
    }

    #[test]
    fn python_prefixes_and_empty_bodies() {
        let value = token(41);
        for first in ["", "r", "R", "b", "B", "u", "U", "f", "F"] {
            for second in ["", "r", "R", "b", "B", "u", "U", "f", "F"] {
                for quote in ["\"", "'", "\"\"\"", "'''"] {
                    let line = format!("{first}{second}{quote}{value}{quote}");
                    let mut tracker = LiteralTracker::new(Language::Python);
                    check(&mut tracker, line.as_bytes(), 1, &[value.as_bytes()]);
                    check(&mut tracker, format!("# {line}").as_bytes(), 2, &[]);
                }
            }
        }
        for language in LANGUAGES {
            check(&mut LiteralTracker::new(language), b"\"\"", 1, &[b""]);
        }
        for (language, line) in [
            (Language::Rust, b"r##\"\"##".as_slice()),
            (Language::Python, b"''''''"),
            (Language::Go, b"``"),
            (Language::JavaScript, b"``"),
            (Language::C, b"R\"()\""),
        ] {
            check(&mut LiteralTracker::new(language), line, 1, &[b""]);
        }
    }

    #[test]
    fn chars_runes_and_rust_lifetimes() {
        let value = token(73);
        for language in [Language::Rust, Language::Go, Language::C] {
            for character in [r#"'"'"#, r"'\''", r"'\x22'", "'é'", "'字'", "'x'"] {
                let line = format!("{character}; \"{value}\"");
                check(
                    &mut LiteralTracker::new(language),
                    line.as_bytes(),
                    1,
                    &[value.as_bytes()],
                );
            }
        }
        for (language, character) in [
            (Language::Rust, r"'\u{22}'"),
            (Language::Rust, r"b'\x22'"),
            (Language::Rust, "'a"),
            (Language::Rust, "'static"),
            (Language::Rust, "'label:"),
            (Language::Go, r"'\u0022'"),
            (Language::Go, r"'\U00000022'"),
            (Language::Go, r"'\q'"),
            (Language::C, r"'\u0022'"),
        ] {
            let line = format!("{character}; \"{value}\"");
            check(
                &mut LiteralTracker::new(language),
                line.as_bytes(),
                1,
                &[value.as_bytes()],
            );
        }
    }

    #[test]
    fn comments_and_nested_rust_blocks() {
        let value = token(5);
        for language in [
            Language::Rust,
            Language::Go,
            Language::JavaScript,
            Language::C,
        ] {
            let mut tracker = LiteralTracker::new(language);
            check(&mut tracker, b"/* \" ' `", 1, &[]);
            check(&mut tracker, value.as_bytes(), 2, &[]);
            check(&mut tracker, b"*/", 3, &[]);
            let line = format!("/* /* */ \"{value}\"");
            let expected = [value.as_bytes()];
            check(
                &mut tracker,
                line.as_bytes(),
                4,
                if language == Language::Rust {
                    &[]
                } else {
                    &expected
                },
            );
            if language == Language::Rust {
                check(&mut tracker, b"*/", 5, &[]);
            }
        }
        let mut rust = LiteralTracker::new(Language::Rust);
        check(&mut rust, b"/* outer /*", 1, &[]);
        check(
            &mut rust,
            format!("{value} */ still outer").as_bytes(),
            2,
            &[],
        );
        check(
            &mut rust,
            format!("*/ \"{value}\"").as_bytes(),
            3,
            &[value.as_bytes()],
        );
    }

    #[test]
    fn multiline_literal_ranges() {
        let value = token(17);
        for (language, opener, closer) in [
            (Language::Rust, "\"", "\""),
            (Language::Rust, "br##\"", "\"##"),
            (Language::Rust, "cr#\"", "\"#"),
            (Language::Go, "`", "`"),
            (Language::Python, "r\"\"\"", "\"\"\""),
            (Language::Python, "f'''", "'''"),
            (Language::C, "u8R\"end(", ")end\""),
            (Language::JavaScript, "`", "`"),
        ] {
            let mut tracker = LiteralTracker::new(language);
            check(
                &mut tracker,
                format!("{opener}open").as_bytes(),
                1,
                &[b"open"],
            );
            check(&mut tracker, value.as_bytes(), 2, &[value.as_bytes()]);
            check(
                &mut tracker,
                format!("close{closer}").as_bytes(),
                3,
                &[b"close"],
            );
            check(&mut tracker, b"code", 4, &[]);
        }
        let mut tracker = LiteralTracker::new(Language::Go);
        check(&mut tracker, b"`", 1, &[b""]);
        check(&mut tracker, b"", 2, &[b""]);
        check(&mut tracker, b"`", 3, &[b""]);
    }

    #[test]
    fn multiline_bodies_preserve_bare_carriage_returns() {
        for (language, opener, closer) in [
            (Language::Rust, b"r\"".as_slice(), b"\"".as_slice()),
            (Language::Go, b"`", b"`"),
            (Language::Python, b"'''", b"'''"),
            (Language::JavaScript, b"`", b"`"),
            (Language::C, b"R\"(", b")\""),
        ] {
            let mut tracker = LiteralTracker::new(language);
            check(&mut tracker, opener, 1, &[b""]);
            check(&mut tracker, b"x\r", 2, &[b"x\r"]);
            check(&mut tracker, closer, 3, &[b""]);
        }
    }

    #[test]
    fn continued_strings_and_escape_parity() {
        let value = token(11);
        for language in [Language::Rust, Language::Python, Language::C] {
            for terminator in ["", "\n", "\r\n"] {
                let mut tracker = LiteralTracker::new(language);
                check(
                    &mut tracker,
                    format!("\"open\\{terminator}").as_bytes(),
                    1,
                    &[if language == Language::C {
                        b"open"
                    } else {
                        b"open\\"
                    }],
                );
                check(
                    &mut tracker,
                    format!("{value}\\{terminator}").as_bytes(),
                    2,
                    &[
                        format!("{value}{}", if language == Language::C { "" } else { "\\" })
                            .as_bytes(),
                    ],
                );
                check(&mut tracker, b"\"", 3, &[b""]);
            }
        }
        for language in LANGUAGES {
            let mut tracker = LiteralTracker::new(language);
            check(&mut tracker, br#""a\"b\\""#, 1, &[br#"a\"b\\"#]);
        }
        for opener in ["r\"", "R\"", "fr\"", "r\"\"\"", "\"\"\""] {
            let triple = opener.ends_with("\"\"\"");
            let closer = if triple { "\"\"\"" } else { "\"" };
            let body = format!("{value}\\{closer}more");
            let line = format!("{opener}{body}{closer}");
            check(
                &mut LiteralTracker::new(Language::Python),
                line.as_bytes(),
                1,
                &[body.as_bytes()],
            );
        }
        check(
            &mut LiteralTracker::new(Language::Go),
            b"`a\\`",
            1,
            &[b"a\\"],
        );
    }

    #[test]
    fn raw_delimiter_matching() {
        let value = token(19);
        for hashes in [0, 1, 2, 16, 300] {
            let hashes = "#".repeat(hashes);
            let body = format!("{value}\\");
            let line = format!("r{hashes}\"{body}\"{hashes}");
            check(
                &mut LiteralTracker::new(Language::Rust),
                line.as_bytes(),
                1,
                &[body.as_bytes()],
            );
        }
        check(
            &mut LiteralTracker::new(Language::Rust),
            br###"r##"a"#b"##"###,
            1,
            &[br##"a"#b"##],
        );
        for delimiter in ["", "tag", "abcdefghijklmnop", "!@#$%^&*+-=;:<>?"] {
            let body = format!("{value})wrong\"\\");
            let line = format!("R\"{delimiter}({body}){delimiter}\"");
            check(
                &mut LiteralTracker::new(Language::C),
                line.as_bytes(),
                1,
                &[body.as_bytes()],
            );
        }
        for line in [
            b"R\"abcdefghijklmnopq(".as_slice(),
            b"R\"a b(",
            b"R\"a\\b(",
            b"R\"a)b(",
            b"R\"a\"b(",
            b"R\"missing",
        ] {
            assert!(!LiteralTracker::new(Language::C).feed(line, 1).known);
        }
    }

    #[test]
    fn javascript_regex_and_division_context() {
        let value = token(21);
        for prefix in [
            "",
            "  ",
            "x = ",
            "(",
            ",",
            "=",
            ":",
            "[",
            "!",
            "&",
            "|",
            "?",
            "{",
            "}",
            ";",
            "+",
            "-",
            "*",
            "%",
            "<",
            ">",
            "~",
            "^",
            "return ",
            "typeof ",
            "instanceof ",
            "in ",
            "of ",
            "new ",
            "delete ",
            "void ",
            "throw ",
            "case ",
            "do ",
            "else ",
            "return /* comment */ ",
        ] {
            let line = format!("{prefix}/a\"b\\/\\/c[/'`]/gi; \"{value}\"");
            check(
                &mut LiteralTracker::new(Language::JavaScript),
                line.as_bytes(),
                1,
                &[value.as_bytes()],
            );
        }
        for prefix in [
            "identifier",
            "returnValue",
            "1",
            ")",
            "]",
            "''",
            "``",
            "/x/",
        ] {
            let line = format!("{prefix} / 2; \"{value}\"");
            let expected = if matches!(prefix, "''" | "``") {
                vec![b"".as_slice(), value.as_bytes()]
            } else {
                vec![value.as_bytes()]
            };
            check(
                &mut LiteralTracker::new(Language::JavaScript),
                line.as_bytes(),
                1,
                &expected,
            );
        }
        for regex in ["/unclosed", "/[unclosed/", "/escape\\"] {
            let line = format!("\"{value}\"; {regex}");
            let result = LiteralTracker::new(Language::JavaScript).feed(line.as_bytes(), 1);
            assert!(!result.known);
            assert!(result.bodies.is_empty());
        }
    }

    #[test]
    fn javascript_postfix_division_preserves_following_literal_ranges() {
        let value = token(29);
        for operand in ["total", "call()", "items[0]"] {
            for operator in ["!", "++", "--"] {
                for division in ["/ count", "/count", "/= count"] {
                    let line = format!(
                        r#"{operand}{operator} {division}; const escaped = "\"/"; consume("{value}"); // ""#
                    );
                    let result = LiteralTracker::new(Language::JavaScript).feed(line.as_bytes(), 1);
                    let escaped = line.find(r#"\"/"#).unwrap();
                    let start = line.find(&value).unwrap();
                    assert!(result.known, "{line}");
                    assert_eq!(
                        result.bodies,
                        vec![escaped..escaped + 3, start..start + value.len()]
                    );
                }
            }
        }
        for expression in [
            "!/re/.test(x)",
            "++i / 2",
            "--i / 2",
            "i + ++j / 2",
            "i! / !/re/.test(x)",
            "i != /re/.test(x)",
        ] {
            let line = format!("{expression}; consume(\"{value}\");");
            check(
                &mut LiteralTracker::new(Language::JavaScript),
                line.as_bytes(),
                1,
                &[value.as_bytes()],
            );
        }
    }

    #[test]
    fn c_spliced_line_comments_do_not_open_block_comments() {
        let value = token(30);
        let literal = format!("const char *value = \"{value}\";");
        let start = literal.find(&value).unwrap();
        for terminator in ["", "\n", "\r\n"] {
            for trailing in ["", " ", "\t"] {
                for second in ["/* not actually code */", "/* still comment"] {
                    for continuations in [0, 1, 4] {
                        let mut tracker = LiteralTracker::new(Language::C);
                        check(
                            &mut tracker,
                            format!("// comment \\{trailing}{terminator}").as_bytes(),
                            1,
                            &[],
                        );
                        for number in 2..2 + continuations {
                            check(
                                &mut tracker,
                                format!("/* still comment \\{trailing}{terminator}").as_bytes(),
                                number,
                                &[],
                            );
                        }
                        check(
                            &mut tracker,
                            format!("{second}{terminator}").as_bytes(),
                            2 + continuations,
                            &[],
                        );
                        let result = tracker.feed(literal.as_bytes(), 3 + continuations);
                        assert!(result.known);
                        assert_eq!(result.bodies, vec![start..start + value.len()]);
                    }
                }
            }
        }
    }

    #[test]
    fn c_string_splices_preserve_ranges_or_invalidate_escape_ambiguity() {
        let value = token(31);
        for count in [1, 3] {
            let mut tracker = LiteralTracker::new(Language::C);
            let opening = format!("\"open{}\n", "\\".repeat(count));
            let result = tracker.feed(opening.as_bytes(), 1);
            assert!(result.known);
            assert_eq!(result.bodies, vec![1..opening.len() - 2]);
            let closing = format!("{value}\";");
            let result = tracker.feed(closing.as_bytes(), 2);
            assert!(result.known);
            assert_eq!(result.bodies, vec![0..value.len()]);
        }
        let mut tracker = LiteralTracker::new(Language::C);
        check(&mut tracker, b"\"open\\ \t\n", 1, &[b"open"]);
        check(
            &mut tracker,
            format!("{value}\"").as_bytes(),
            2,
            &[value.as_bytes()],
        );
        assert!(
            !LiteralTracker::new(Language::C)
                .feed(b"\"open\\\\\n", 1)
                .known
        );
    }

    #[test]
    fn c_split_comment_delimiters_stay_unknown_until_reset() {
        let value = token(32);
        for (first, second) in [
            ("/\\", "/ comment"),
            ("/\\ \t", "* comment"),
            ("/* comment *\\", "/"),
        ] {
            let mut tracker = LiteralTracker::new(Language::C);
            for (index, line) in [first, second, "/* still comment", &format!("\"{value}\"")]
                .iter()
                .enumerate()
            {
                let result = tracker.feed(line.as_bytes(), index + 1);
                assert!(!result.known, "{line}");
                assert!(result.bodies.is_empty());
                assert!(!tracker.is_known());
            }
            tracker.reset();
            check(
                &mut tracker,
                format!("\"{value}\"").as_bytes(),
                1,
                &[value.as_bytes()],
            );
        }
    }

    #[test]
    fn python_pep701_replacement_fields_are_unknown() {
        let value = token(33);
        for prefix in ["f", "F", "fr", "fR", "Fr", "FR", "rf", "rF", "Rf", "RF"] {
            for quote in ["\"", "'", "\"\"\"", "'''"] {
                let inner = &quote[..1];
                let line = format!("{prefix}{quote}{{tokens[{inner}{value}{inner}]}}{quote}");
                let mut tracker = LiteralTracker::new(Language::Python);
                let result = tracker.feed(line.as_bytes(), 1);
                assert!(!result.known, "{line}");
                assert!(result.bodies.is_empty());
                assert!(!tracker.feed(b"'''still in a replacement field", 2).known);
                assert!(!tracker.feed(b"unresolved", 3).known);
                tracker.reset();
                check(
                    &mut tracker,
                    format!("{prefix}{quote}{{{{{value}}}}}{quote}").as_bytes(),
                    1,
                    &[format!("{{{{{value}}}}}").as_bytes()],
                );
            }
        }
        for line in [r#"f"\{tokens["key"]}""#, r#"f"""text {""#] {
            assert!(
                !LiteralTracker::new(Language::Python)
                    .feed(line.as_bytes(), 1)
                    .known
            );
        }
        let mut tracker = LiteralTracker::new(Language::Python);
        check(&mut tracker, b"f\"\"\"opening", 1, &[b"opening"]);
        assert!(
            !tracker
                .feed(format!(r#"{{tokens["{value}"]}}"#).as_bytes(), 2)
                .known
        );
        assert!(!tracker.feed(b"still inside\"\"\"", 3).known);
        for prefix in ["", "r", "b", "u", "if", "elif"] {
            check(
                &mut LiteralTracker::new(Language::Python),
                format!("{prefix}\"{{{value}}}\"").as_bytes(),
                1,
                &[format!("{{{value}}}").as_bytes()],
            );
        }
    }

    #[test]
    fn javascript_nested_templates_and_interpolations() {
        let value = token(8);
        let line = format!("`a ${{ `b ${{x}}` }} c`; \"{value}\"");
        check(
            &mut LiteralTracker::new(Language::JavaScript),
            line.as_bytes(),
            1,
            &[b"a ", b"b ", b"", b" c", value.as_bytes()],
        );
        let mut tracker = LiteralTracker::new(Language::JavaScript);
        check(
            &mut tracker,
            b"`a ${ {field: /[}`]/, other: '}' /*",
            1,
            &[b"a ", b"}"],
        );
        check(
            &mut tracker,
            b"} ` */ } }b ${ `nested",
            2,
            &[b"b ", b"nested"],
        );
        check(
            &mut tracker,
            format!("{value}` }}c`").as_bytes(),
            3,
            &[value.as_bytes(), b"c"],
        );
        for depth in [4, 5] {
            let line = format!("{}x{}", "`${".repeat(depth), "}`".repeat(depth));
            let mut tracker = LiteralTracker::new(Language::JavaScript);
            let result = tracker.feed(line.as_bytes(), 1);
            assert_eq!(result.known, depth == 4);
            if depth == 5 {
                assert!(result.bodies.is_empty());
            } else {
                assert!(result.bodies.iter().all(|range| range.is_empty()));
            }
            check(
                &mut tracker,
                format!("\"{value}\"").as_bytes(),
                2,
                &[value.as_bytes()],
            );
        }
        check(
            &mut LiteralTracker::new(Language::JavaScript),
            br"`\${code}\`text`",
            1,
            &[br"\${code}\`text"],
        );
    }

    #[test]
    fn continuity_recovery_and_reset() {
        let value = token(39);
        let string = format!("\"{value}\"");
        let mut tracker = LiteralTracker::new(Language::Rust);
        assert!(tracker.is_known());
        check(&mut tracker, b"code", 1, &[]);
        let result = tracker.feed(string.as_bytes(), 5);
        assert_eq!(
            result,
            LineLiterals {
                bodies: vec![],
                known: false,
                test_span: None,
            }
        );
        assert!(tracker.is_known());
        check(&mut tracker, string.as_bytes(), 6, &[value.as_bytes()]);
        tracker.reset();
        assert!(tracker.is_known());
        assert!(!tracker.feed(b"/*", 20).known);
        check(&mut tracker, value.as_bytes(), 21, &[]);
        check(&mut tracker, b"*/", 22, &[]);
        tracker.reset();
        check(&mut tracker, string.as_bytes(), 1, &[value.as_bytes()]);
        assert!(!tracker.feed(b"r#\"open", 50).known);
        check(&mut tracker, value.as_bytes(), 51, &[value.as_bytes()]);
        check(&mut tracker, b"\"#", 52, &[b""]);
        assert!(!tracker.feed(b"code", usize::MAX).known);
        assert!(!tracker.feed(b"code", 0).known);
    }

    #[test]
    fn ambiguity_discards_bodies_and_recovers() {
        let value = token(6);
        for language in [
            Language::Go,
            Language::Python,
            Language::JavaScript,
            Language::C,
        ] {
            let mut tracker = LiteralTracker::new(language);
            let broken = format!("\"{value}\"; \"unterminated");
            let result = tracker.feed(broken.as_bytes(), 1);
            assert!(!result.known);
            assert!(result.bodies.is_empty());
            assert!(tracker.is_known());
            let string = format!("\"{value}\"");
            check(&mut tracker, string.as_bytes(), 2, &[value.as_bytes()]);
            assert!(!tracker.feed(broken.as_bytes(), 7).known);
            assert!(!tracker.is_known());
            assert!(!tracker.feed(broken.as_bytes(), 8).known);
            assert!(!tracker.is_known());
            assert!(!tracker.feed(string.as_bytes(), 9).known);
            assert!(tracker.is_known());
            check(&mut tracker, string.as_bytes(), 10, &[value.as_bytes()]);
        }
        for language in [Language::Python, Language::C] {
            assert!(!LiteralTracker::new(language).feed(b"\"two\\\\", 1).known);
        }
    }

    #[test]
    fn path_language_table() {
        for (language, extensions) in [(Language::Rust, "rs"), (Language::Go, "go")] {
            for extension in extensions.split_whitespace() {
                for prefix in ["foo.", "src/foo.", "."] {
                    assert_eq!(
                        language_for_path(&format!("{prefix}{extension}")),
                        Some(language)
                    );
                }
                assert_eq!(
                    language_for_path(&format!("foo.{}", extension.to_ascii_uppercase())),
                    Some(language)
                );
            }
        }
        for extension in [
            "py", "pyi", "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "c", "h", "cc",
            "cpp", "cxx", "hpp", "hxx",
        ] {
            for extension in [
                extension.to_owned(),
                extension.to_ascii_uppercase(),
                extension
                    .chars()
                    .enumerate()
                    .map(|(index, character)| {
                        if index % 2 == 0 {
                            character.to_ascii_uppercase()
                        } else {
                            character
                        }
                    })
                    .collect(),
            ] {
                assert_eq!(language_for_path(&format!("foo.{extension}")), None);
            }
        }
        for path in [
            "Makefile",
            "foo.unknown",
            "foo.d.ts",
            "src.rs/Makefile",
            "foo.rs/",
            "foo.",
            "",
            "src/",
        ] {
            assert_eq!(language_for_path(path), None);
        }
    }

    #[test]
    fn arbitrary_bytes_have_ordered_bounded_ranges() {
        for language in LANGUAGES {
            for byte in 0..=255 {
                let line = [b'\'', byte, b'\'', b';', b'"', byte, b'"'];
                let result = LiteralTracker::new(language).feed(&line, 1);
                let mut end = 0;
                for range in result.bodies {
                    assert!(
                        end <= range.start && range.start <= range.end && range.end <= line.len()
                    );
                    end = range.end;
                }
            }
        }
    }
}
