//! Strict JSON parsing and RFC 8785 (JCS) canonicalization.
//!
//! The parser is deliberately stricter than `serde_json`: it
//! rejects duplicate object keys outright (they cannot be repaired
//! by canonicalization, DESIGN F-01), lone UTF-16 surrogates in
//! `\u` escapes, unescaped control characters, and trailing
//! content. Numbers are stored as their canonical ECMAScript
//! serialization at parse time, so [`canonicalize`] is a pure
//! re-serialization and a manifest is well-formed exactly when
//! `canonicalize(bytes) == bytes`.

use std::collections::BTreeMap;
use std::fmt;

/// Maximum nesting depth the parser accepts.
pub const MAX_DEPTH: usize = 100;

/// A parsed JSON value with canonical number spellings.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Array(Vec<JsonValue>),
    Bool(bool),
    Null,
    /// Canonical ECMAScript spelling of the number.
    Number(String),
    Object(Vec<(String, JsonValue)>),
    String(String),
}

impl JsonValue {
    /// Looks up `key` in an object value.
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value as a string, when it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// The value as an object, when it is one.
    pub fn as_object(&self) -> Option<&Vec<(String, JsonValue)>> {
        match self {
            JsonValue::Object(entries) => Some(entries),
            _ => None,
        }
    }

    /// The value as an array, when it is one.
    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value as an `i64`, when it is an integer number.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => n.parse::<i64>().ok(),
            _ => None,
        }
    }

    /// The value as a boolean, when it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Why a byte string is not acceptable strict JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The same key appears twice in one object.
    DuplicateKey(String),
    /// Input ended mid-value.
    Eof,
    /// A `\u` escape names half of a surrogate pair.
    LoneSurrogate,
    /// A number cannot be represented canonically.
    NumberOutOfRange,
    /// Anything else, with the byte offset of the failure.
    Syntax { offset: usize, message: String },
    /// Content follows the top-level value.
    TrailingContent,
    /// Nesting exceeds [`MAX_DEPTH`].
    TooDeep,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::DuplicateKey(key) => write!(f, "duplicate object key: {key}"),
            ParseError::Eof => write!(f, "unexpected end of input"),
            ParseError::LoneSurrogate => write!(f, "lone UTF-16 surrogate in string escape"),
            ParseError::NumberOutOfRange => {
                write!(f, "number has no canonical finite representation")
            }
            ParseError::Syntax { offset, message } => {
                write!(f, "syntax error at byte {offset}: {message}")
            }
            ParseError::TrailingContent => write!(f, "trailing content after top-level value"),
            ParseError::TooDeep => write!(f, "nesting deeper than {MAX_DEPTH}"),
        }
    }
}

impl std::error::Error for ParseError {}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn syntax<T>(&self, message: &str) -> Result<T, ParseError> {
        Err(ParseError::Syntax {
            offset: self.pos,
            message: message.to_string(),
        })
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        self.skip_ws();
        match self.peek() {
            None => Err(ParseError::Eof),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(JsonValue::String(self.string()?)),
            Some(b't') => self.literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.literal("false", JsonValue::Bool(false)),
            Some(b'n') => self.literal("null", JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.syntax("unexpected byte"),
        }
    }

    fn literal(&mut self, text: &str, value: JsonValue) -> Result<JsonValue, ParseError> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            self.syntax("invalid literal")
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, ParseError> {
        self.pos += 1; // '{'
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return self.syntax("object key must be a string");
            }
            let key = self.string()?;
            if entries.iter().any(|(k, _)| *k == key) {
                return Err(ParseError::DuplicateKey(key));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return self.syntax("expected ':' after object key");
            }
            self.pos += 1;
            let val = self.value(depth + 1)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => return self.syntax("expected ',' or '}' in object"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, ParseError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            let item = self.value(depth + 1)?;
            items.push(item);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return self.syntax("expected ',' or ']' in array"),
            }
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        // Caller has peeked the opening quote.
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = match self.peek() {
                None => return Err(ParseError::Eof),
                Some(b) => b,
            };
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                0x00..=0x1F => return self.syntax("unescaped control character in string"),
                _ => {
                    // Consume one UTF-8 encoded character verbatim.
                    let rest = &self.bytes[self.pos..];
                    let s = match std::str::from_utf8(rest) {
                        Ok(s) => s,
                        Err(e) => {
                            let valid = e.valid_up_to();
                            if valid == 0 {
                                return self.syntax("invalid UTF-8 in string");
                            }
                            // Longest valid prefix; take its first char only.
                            let prefix = &rest[..valid];
                            let text =
                                std::str::from_utf8(prefix).map_err(|_| ParseError::Syntax {
                                    offset: self.pos,
                                    message: "invalid UTF-8 in string".to_string(),
                                })?;
                            let ch = text.chars().next().expect("nonempty prefix");
                            out.push(ch);
                            self.pos += ch.len_utf8();
                            continue;
                        }
                    };
                    let ch = s.chars().next().expect("nonempty input");
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let b = match self.peek() {
            None => return Err(ParseError::Eof),
            Some(b) => b,
        };
        self.pos += 1;
        match b {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000C}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let first = self.hex4()?;
                if (0xD800..=0xDBFF).contains(&first) {
                    // High surrogate: a low-surrogate escape must follow.
                    if self.peek() == Some(b'\\') && self.bytes.get(self.pos + 1) == Some(&b'u') {
                        self.pos += 2;
                        let second = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&second) {
                            return Err(ParseError::LoneSurrogate);
                        }
                        let cp = 0x10000u32
                            + (((first - 0xD800) as u32) << 10)
                            + ((second - 0xDC00) as u32);
                        out.push(char::from_u32(cp).ok_or(ParseError::LoneSurrogate)?);
                    } else {
                        return Err(ParseError::LoneSurrogate);
                    }
                } else if (0xDC00..=0xDFFF).contains(&first) {
                    return Err(ParseError::LoneSurrogate);
                } else {
                    out.push(char::from_u32(first as u32).ok_or(ParseError::LoneSurrogate)?);
                }
            }
            _ => return self.syntax("invalid escape"),
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u16, ParseError> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let b = match self.peek() {
                None => return Err(ParseError::Eof),
                Some(b) => b,
            };
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => return self.syntax("invalid hex digit in \\u escape"),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<JsonValue, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // Integer part: '0' or [1-9][0-9]*.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return self.syntax("invalid number"),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.syntax("digits required after decimal point");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.syntax("digits required in exponent");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .expect("number token is ASCII")
            .to_string();
        if !is_float {
            if let Ok(v) = raw.parse::<i64>() {
                return Ok(JsonValue::Number(v.to_string()));
            }
            if let Ok(v) = raw.parse::<u64>() {
                return Ok(JsonValue::Number(v.to_string()));
            }
            // Integer too large for u64: fall through to float rules,
            // which will almost surely reject it (precision loss must
            // never be canonicalized silently).
        }
        let value: f64 = raw.parse().map_err(|_| ParseError::NumberOutOfRange)?;
        if !value.is_finite() {
            return Err(ParseError::NumberOutOfRange);
        }
        Ok(JsonValue::Number(ecmascript_number(value)))
    }
}

/// Serializes an `f64` exactly as ECMAScript's `Number::toString`
/// (and therefore RFC 8785) requires.
fn ecmascript_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    // Rust's lower-exp format yields the shortest round-trip digit
    // string: "d.ddddde<exp>" or "de<exp>".
    let sci = format!("{:e}", magnitude);
    let (mantissa, exp10) = sci.split_once('e').expect("lower-exp has e");
    let exp: i32 = exp10.parse().expect("exponent parses");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    // value == 0.digits * 10^n  with n = exp + 1
    let n = exp + 1;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        // Exponential notation.
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
        }
        out.push_str(&e.to_string());
    }
    out
}

/// A string's UTF-16 code units, the RFC 8785 key ordering.
fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Writes the canonical form of a string value (with quotes).
fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Serializes a parsed value in canonical (RFC 8785) form.
pub fn serialize(value: &JsonValue) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &JsonValue) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => out.push_str(n),
        JsonValue::String(s) => write_string(out, s),
        JsonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        JsonValue::Object(entries) => {
            let mut sorted: Vec<&(String, JsonValue)> = entries.iter().collect();
            sorted.sort_by_key(|entry| utf16_units(&entry.0));
            out.push('{');
            for (i, (key, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, val);
            }
            out.push('}');
        }
    }
}

/// Parses strict JSON, rejecting anything canonicalization cannot
/// repair (duplicate keys, bad grammar, lone surrogates).
pub fn parse_strict(bytes: &[u8]) -> Result<JsonValue, ParseError> {
    let mut parser = Parser { bytes, pos: 0 };
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != bytes.len() {
        return Err(ParseError::TrailingContent);
    }
    Ok(value)
}

/// Canonicalizes raw JSON bytes: parse strictly, re-serialize.
/// Two inputs are the same JSON value iff their canonical bytes are
/// equal.
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    let value = parse_strict(bytes)?;
    Ok(serialize(&value).into_bytes())
}

/// Builds an object value from key/value pairs (order-insensitive;
/// serialization sorts).
pub fn object(pairs: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<Vec<_>>(),
    )
}

/// Reads a value as a sorted map for field extraction.
pub fn as_map(value: &JsonValue) -> Option<BTreeMap<&str, &JsonValue>> {
    match value {
        JsonValue::Object(entries) => Some(
            entries
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect::<BTreeMap<_, _>>(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(input: &str) -> String {
        String::from_utf8(canonicalize(input.as_bytes()).expect("canonicalizes")).expect("utf8")
    }

    #[test]
    fn sorts_keys() {
        assert_eq!(canon(r#"{"b":1,"a":2}"#), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(matches!(
            parse_strict(br#"{"a":1,"a":2}"#),
            Err(ParseError::DuplicateKey(_))
        ));
    }

    #[test]
    fn float_spellings_canonicalize() {
        assert_eq!(canon("1.0"), "1");
        assert_eq!(canon("1e2"), "100");
        assert_eq!(canon("-0"), "0");
        assert_eq!(canon("1.5e-7"), "1.5e-7");
        assert_eq!(canon("1e21"), "1e+21");
        assert_eq!(canon("0.1"), "0.1");
    }

    #[test]
    fn rejects_noncanonical_number_grammar() {
        assert!(parse_strict(b"01").is_err());
        assert!(parse_strict(b"+1").is_err());
        assert!(parse_strict(b".5").is_err());
        assert!(parse_strict(b"1.").is_err());
    }

    #[test]
    fn string_escapes_minimal() {
        assert_eq!(canon(r#""a\/b""#), r#""a/b""#);
        assert_eq!(canon(r#""é""#), "\"é\"");
        assert_eq!(canon(r#""\u0001""#), "\"\\u0001\"");
    }
}
