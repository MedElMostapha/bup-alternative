//! Rules that rewrite proxied messages automatically. A message no rule
//! changes is forwarded byte for byte.

use regex::bytes::{NoExpand, Regex};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::http::decode::{decompress, unframe, MAX_DECODED};
use crate::http::rewrite::line_name_is;
use crate::http::{find_head_end, parse_request_head, parse_response_head, Header};
use crate::intercept::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Replaces every copy of a header, or adds it if it is missing.
    SetHeader,
    RemoveHeader,
    ReplaceFirstLine,
    /// Works on one header line at a time; a line left empty is removed.
    ReplaceHeaders,
    /// Works on the decompressed body.
    ReplaceBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRule {
    pub enabled: bool,
    pub direction: Direction,
    pub kind: RuleKind,
    /// The header name, or the text to find.
    pub pattern: String,
    /// The header value, or what to put in place of a match.
    #[serde(default)]
    pub replacement: String,
    /// Whether `pattern` is a regex, which also enables `$1` in `replacement`.
    #[serde(default)]
    pub regex: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("Enter a header name.")]
    NoHeaderName,
    #[error("\"{0}\" is not a valid header name.")]
    BadHeaderName(String),
    #[error("A header value cannot contain line breaks.")]
    BadHeaderValue,
    #[error("Enter the text to find.")]
    NoPattern,
    #[error("Invalid regex: {0}")]
    BadPattern(String),
}

struct Matcher {
    regex: Regex,
    replacement: Vec<u8>,
    expand: bool,
}

impl Matcher {
    fn new(rule: &MatchRule) -> Result<Self, RuleError> {
        if rule.pattern.is_empty() {
            return Err(RuleError::NoPattern);
        }
        let source = if rule.regex { rule.pattern.clone() } else { regex::escape(&rule.pattern) };
        Ok(Self {
            regex: Regex::new(&source).map_err(|e| RuleError::BadPattern(e.to_string()))?,
            replacement: rule.replacement.clone().into_bytes(),
            expand: rule.regex,
        })
    }

    fn apply<'a>(&self, text: &'a [u8]) -> Cow<'a, [u8]> {
        if self.expand {
            self.regex.replace_all(text, self.replacement.as_slice())
        } else {
            self.regex.replace_all(text, NoExpand(&self.replacement))
        }
    }
}

enum Action {
    SetHeader { name: String, value: String },
    RemoveHeader(String),
    FirstLine(Matcher),
    Headers(Matcher),
    Body(Matcher),
}

fn checked_name(rule: &MatchRule) -> Result<String, RuleError> {
    let name = rule.pattern.trim();
    if name.is_empty() {
        return Err(RuleError::NoHeaderName);
    }
    let valid = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if !name.bytes().all(valid) {
        return Err(RuleError::BadHeaderName(name.to_string()));
    }
    Ok(name.to_string())
}

fn compile(rule: &MatchRule) -> Result<Action, RuleError> {
    Ok(match rule.kind {
        RuleKind::SetHeader => {
            if rule.replacement.contains(['\r', '\n']) {
                return Err(RuleError::BadHeaderValue);
            }
            Action::SetHeader {
                name: checked_name(rule)?,
                value: rule.replacement.trim().to_string(),
            }
        }
        RuleKind::RemoveHeader => Action::RemoveHeader(checked_name(rule)?),
        RuleKind::ReplaceFirstLine => Action::FirstLine(Matcher::new(rule)?),
        RuleKind::ReplaceHeaders => Action::Headers(Matcher::new(rule)?),
        RuleKind::ReplaceBody => Action::Body(Matcher::new(rule)?),
    })
}

#[derive(Clone, PartialEq, Eq)]
struct Head {
    first: Vec<u8>,
    headers: Vec<Vec<u8>>,
}

impl Head {
    fn parse(raw: &[u8]) -> Option<Self> {
        let mut lines = raw
            .split(|b| *b == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line).to_vec())
            .filter(|line| !line.is_empty());
        Some(Self {
            first: lines.next()?,
            headers: lines.collect(),
        })
    }

    fn render(&self) -> Vec<u8> {
        let mut out = self.first.clone();
        out.extend_from_slice(b"\r\n");
        for header in &self.headers {
            out.extend_from_slice(header);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    fn remove(&mut self, name: &str) {
        self.headers.retain(|line| !line_name_is(line, name));
    }

    fn set(&mut self, name: &str, value: &str) {
        let line = format!("{name}: {value}").into_bytes();
        match self.headers.iter().position(|h| line_name_is(h, name)) {
            Some(first) => {
                self.headers[first] = line.clone();
                let mut index = 0;
                self.headers.retain(|h| {
                    index += 1;
                    index - 1 == first || !line_name_is(h, name)
                });
            }
            None => self.headers.push(line),
        }
    }

    fn apply(&mut self, action: &Action) {
        match action {
            Action::SetHeader { name, value } => self.set(name, value),
            Action::RemoveHeader(name) => self.remove(name),
            Action::FirstLine(matcher) => self.first = matcher.apply(&self.first).into_owned(),
            Action::Headers(matcher) => {
                for line in &mut self.headers {
                    *line = matcher.apply(line).into_owned();
                }
                self.headers.retain(|line| !line.is_empty());
            }
            Action::Body(_) => {}
        }
    }
}

fn headers_of(direction: Direction, head: &[u8]) -> Option<Vec<Header>> {
    match direction {
        Direction::Request => parse_request_head(head).ok().map(|h| h.headers),
        Direction::Response => parse_response_head(head).ok().map(|h| h.headers),
    }
}

/// The body with the rules applied, unframed and decompressed, if they changed
/// it. A body that cannot be read in full is left alone rather than damaged.
fn rewrite_body(direction: Direction, head: &[u8], body: &[u8], matchers: &[&Matcher]) -> Option<Vec<u8>> {
    if matchers.is_empty() || body.is_empty() {
        return None;
    }
    let headers = headers_of(direction, head)?;
    let readable = decompress(&headers, &unframe(&headers, body))?;
    if readable.len() as u64 >= MAX_DECODED {
        return None;
    }
    let mut current = readable.clone();
    for matcher in matchers {
        if let Cow::Owned(next) = matcher.apply(&current) {
            current = next;
        }
    }
    (current != readable).then_some(current)
}

pub struct Rewritten {
    pub message: Vec<u8>,
    /// The body was replaced, so the head now describes its new length.
    pub body_changed: bool,
}

/// The rules as the user wrote them, and why each one cannot run, if it can't.
#[derive(Debug, Clone, Serialize)]
pub struct RulesView {
    pub rules: Vec<MatchRule>,
    pub errors: Vec<Option<String>>,
}

#[derive(Default)]
pub struct RuleSet {
    rules: Vec<MatchRule>,
    errors: Vec<Option<String>>,
    active: Vec<(Direction, Action)>,
}

impl RuleSet {
    pub fn new(rules: Vec<MatchRule>) -> Self {
        let mut errors = Vec::with_capacity(rules.len());
        let mut active = Vec::with_capacity(rules.len());
        for rule in &rules {
            match compile(rule) {
                Ok(action) => {
                    errors.push(None);
                    if rule.enabled {
                        active.push((rule.direction, action));
                    }
                }
                Err(e) => errors.push(Some(e.to_string())),
            }
        }
        Self { rules, errors, active }
    }

    pub fn rules(&self) -> &[MatchRule] {
        &self.rules
    }

    pub fn view(&self) -> RulesView {
        RulesView {
            rules: self.rules.clone(),
            errors: self.errors.clone(),
        }
    }

    pub fn rewrites_bodies(&self, direction: Direction) -> bool {
        self.active.iter().any(|(d, a)| *d == direction && matches!(a, Action::Body(_)))
    }

    /// Applies the rules in order, or returns `None` if nothing changed. With
    /// `body_complete` false, `message` may hold part of a body, which stays
    /// as it is.
    pub fn rewrite(&self, direction: Direction, message: &[u8], body_complete: bool) -> Option<Rewritten> {
        let actions: Vec<&Action> = self.active.iter().filter(|(d, _)| *d == direction).map(|(_, a)| a).collect();
        if actions.is_empty() {
            return None;
        }
        let end = find_head_end(message)?;
        let (raw_head, body) = message.split_at(end);
        let original = Head::parse(raw_head)?;
        let mut head = original.clone();
        actions.iter().for_each(|action| head.apply(action));

        let matchers: Vec<&Matcher> = actions
            .iter()
            .filter_map(|action| match action {
                Action::Body(matcher) => Some(matcher),
                _ => None,
            })
            .collect();
        let new_body = body_complete.then(|| rewrite_body(direction, raw_head, body, &matchers)).flatten();
        if let Some(new_body) = &new_body {
            head.remove("transfer-encoding");
            head.remove("content-encoding");
            head.set("Content-Length", &new_body.len().to_string());
        }
        if head == original && new_body.is_none() {
            return None;
        }
        let body_changed = new_body.is_some();
        let mut out = head.render();
        out.extend_from_slice(new_body.as_deref().unwrap_or(body));
        Some(Rewritten {
            message: out,
            body_changed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const REQUEST: &[u8] = b"GET /a HTTP/1.1\r\nHost: a.test\r\nUser-Agent: curl\r\n\r\n";

    fn rule(direction: Direction, kind: RuleKind, pattern: &str, replacement: &str) -> MatchRule {
        MatchRule {
            enabled: true,
            direction,
            kind,
            pattern: pattern.into(),
            replacement: replacement.into(),
            regex: false,
        }
    }

    fn request_rule(kind: RuleKind, pattern: &str, replacement: &str) -> MatchRule {
        rule(Direction::Request, kind, pattern, replacement)
    }

    fn rewrite_request(rules: Vec<MatchRule>, message: &[u8]) -> Option<Vec<u8>> {
        RuleSet::new(rules).rewrite(Direction::Request, message, true).map(|r| r.message)
    }

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn set_header_replaces_in_place_ignoring_case() {
        let out = rewrite_request(vec![request_rule(RuleKind::SetHeader, "user-agent", "Sluice")], REQUEST);
        assert_eq!(text(out.unwrap()), "GET /a HTTP/1.1\r\nHost: a.test\r\nuser-agent: Sluice\r\n\r\n");
    }

    #[test]
    fn set_header_adds_a_missing_header_and_collapses_copies() {
        let added = rewrite_request(vec![request_rule(RuleKind::SetHeader, "X-Test", "1")], REQUEST).unwrap();
        assert_eq!(text(added), "GET /a HTTP/1.1\r\nHost: a.test\r\nUser-Agent: curl\r\nX-Test: 1\r\n\r\n");

        let twice = b"GET / HTTP/1.1\r\nX-A: 1\r\nHost: a\r\nx-a: 2\r\n\r\n";
        let collapsed = rewrite_request(vec![request_rule(RuleKind::SetHeader, "X-A", "9")], twice).unwrap();
        assert_eq!(text(collapsed), "GET / HTTP/1.1\r\nX-A: 9\r\nHost: a\r\n\r\n");
    }

    #[test]
    fn remove_header_only_touches_that_name() {
        let out = rewrite_request(vec![request_rule(RuleKind::RemoveHeader, "user-agent", "")], REQUEST);
        assert_eq!(text(out.unwrap()), "GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n");
    }

    #[test]
    fn replace_rules_work_on_their_own_part() {
        let first = rewrite_request(vec![request_rule(RuleKind::ReplaceFirstLine, "/a", "/b")], REQUEST).unwrap();
        assert!(text(first).starts_with("GET /b HTTP/1.1\r\n"));
        let host = rewrite_request(vec![request_rule(RuleKind::ReplaceHeaders, "a.test", "b.test")], REQUEST).unwrap();
        assert!(text(host).contains("Host: b.test\r\n"));
        assert_eq!(rewrite_request(vec![request_rule(RuleKind::ReplaceFirstLine, "a.test", "x")], REQUEST).map(text), None);
    }

    #[test]
    fn a_header_line_emptied_by_a_regex_is_removed() {
        let mut remove = request_rule(RuleKind::ReplaceHeaders, "(?i)^user-agent:.*$", "");
        remove.regex = true;
        assert_eq!(text(rewrite_request(vec![remove], REQUEST).unwrap()), "GET /a HTTP/1.1\r\nHost: a.test\r\n\r\n");
    }

    #[test]
    fn regex_rules_expand_groups_but_literal_rules_do_not() {
        let mut groups = request_rule(RuleKind::ReplaceFirstLine, "/(a)", "/$1$1");
        groups.regex = true;
        assert!(text(rewrite_request(vec![groups], REQUEST).unwrap()).starts_with("GET /aa "));
        let literal = request_rule(RuleKind::ReplaceFirstLine, "/a", "/$1");
        assert!(text(rewrite_request(vec![literal], REQUEST).unwrap()).starts_with("GET /$1 "));
        let special = request_rule(RuleKind::ReplaceFirstLine, ".", "!");
        assert_eq!(rewrite_request(vec![special.clone()], b"GET /a HTTP/1.1\r\n\r\n").map(text).unwrap(), "GET /a HTTP/1!1\r\n\r\n");
    }

    #[test]
    fn rules_run_in_order_on_each_others_results() {
        let rules = vec![
            request_rule(RuleKind::ReplaceFirstLine, "/a", "/b"),
            request_rule(RuleKind::ReplaceFirstLine, "/b", "/c"),
        ];
        assert!(text(rewrite_request(rules, REQUEST).unwrap()).starts_with("GET /c "));
    }

    #[test]
    fn nothing_changed_means_no_rewrite() {
        let no_match = request_rule(RuleKind::ReplaceHeaders, "absent", "x");
        assert_eq!(rewrite_request(vec![no_match], REQUEST).map(text), None);
        let same = request_rule(RuleKind::SetHeader, "Host", "a.test");
        assert_eq!(rewrite_request(vec![same], REQUEST).map(text), None);
    }

    #[test]
    fn disabled_rules_and_the_other_direction_do_nothing() {
        let mut disabled = request_rule(RuleKind::SetHeader, "X-A", "1");
        disabled.enabled = false;
        assert_eq!(rewrite_request(vec![disabled], REQUEST).map(text), None);
        let other = rule(Direction::Response, RuleKind::SetHeader, "X-A", "1");
        assert_eq!(rewrite_request(vec![other], REQUEST).map(text), None);
    }

    #[test]
    fn invalid_rules_are_reported_and_skipped() {
        let mut bad_regex = request_rule(RuleKind::ReplaceBody, "(", "x");
        bad_regex.regex = true;
        let set = RuleSet::new(vec![
            bad_regex,
            request_rule(RuleKind::SetHeader, "bad name", "x"),
            request_rule(RuleKind::SetHeader, "", "x"),
            request_rule(RuleKind::SetHeader, "X-A", "a\r\nX-B: b"),
            request_rule(RuleKind::ReplaceFirstLine, "", "x"),
            request_rule(RuleKind::SetHeader, "X-Good", "1"),
        ]);
        let errors = set.view().errors;
        assert!(errors[0].as_deref().unwrap().starts_with("Invalid regex"));
        assert!(errors[1].as_deref().unwrap().contains("bad name"));
        assert_eq!(errors[2].as_deref(), Some("Enter a header name."));
        assert_eq!(errors[3].as_deref(), Some("A header value cannot contain line breaks."));
        assert_eq!(errors[4].as_deref(), Some("Enter the text to find."));
        assert_eq!(errors[5], None);
        assert!(text(set.rewrite(Direction::Request, REQUEST, true).unwrap().message).contains("X-Good: 1\r\n"));
    }

    #[test]
    fn a_changed_body_gets_the_right_length() {
        let message = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
        let out = RuleSet::new(vec![request_rule(RuleKind::ReplaceBody, "abc", "longer")])
            .rewrite(Direction::Request, message, true)
            .unwrap();
        assert!(out.body_changed);
        assert_eq!(text(out.message), "POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\nlonger");
    }

    #[test]
    fn a_header_rule_may_set_a_wrong_length_on_purpose() {
        let message = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
        let out = RuleSet::new(vec![request_rule(RuleKind::SetHeader, "Content-Length", "99")])
            .rewrite(Direction::Request, message, true)
            .unwrap();
        assert!(!out.body_changed);
        assert_eq!(text(out.message), "POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\nabc");
    }

    #[test]
    fn chunked_and_compressed_bodies_are_rewritten_as_plain_ones() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"hello world").unwrap();
        let compressed = encoder.finish().unwrap();
        let mut message = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", compressed.len()).into_bytes();
        message.extend(&compressed);
        let rules = RuleSet::new(vec![rule(Direction::Response, RuleKind::ReplaceBody, "world", "there")]);
        let out = rules.rewrite(Direction::Response, &message, true).unwrap();
        assert_eq!(text(out.message), "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello there");

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let out = rules.rewrite(Direction::Response, chunked, true).unwrap();
        assert_eq!(text(out.message), "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello there");
    }

    #[test]
    fn an_unchanged_compressed_body_keeps_its_exact_bytes() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let rules = RuleSet::new(vec![rule(Direction::Response, RuleKind::ReplaceBody, "absent", "x")]);
        assert!(rules.rewrite(Direction::Response, chunked, true).is_none());
    }

    #[test]
    fn unreadable_compression_is_left_alone() {
        let broken = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc";
        let rules = RuleSet::new(vec![rule(Direction::Response, RuleKind::ReplaceBody, "abc", "x")]);
        assert!(rules.rewrite(Direction::Response, broken, true).is_none());
    }

    #[test]
    fn a_partial_body_only_gets_head_rules() {
        let message = b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\nabc";
        let rules = RuleSet::new(vec![
            request_rule(RuleKind::ReplaceBody, "abc", "xyz"),
            request_rule(RuleKind::SetHeader, "X-A", "1"),
        ]);
        let out = rules.rewrite(Direction::Request, message, false).unwrap();
        assert!(!out.body_changed);
        assert_eq!(text(out.message), "POST / HTTP/1.1\r\nContent-Length: 99\r\nX-A: 1\r\n\r\nabc");
    }

    #[test]
    fn rule_fields_use_the_names_the_interface_sends() {
        let parsed: MatchRule = serde_json::from_value(serde_json::json!({
            "enabled": true, "direction": "response", "kind": "replace_body",
            "pattern": "a", "replacement": "b", "regex": true
        }))
        .unwrap();
        assert_eq!(parsed.kind, RuleKind::ReplaceBody);
        assert_eq!(parsed.direction, Direction::Response);
    }
}
