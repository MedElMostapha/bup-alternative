//! Lines up two messages and reports what differs, line by line and then word
//! by word inside the lines that changed.

use std::ops::Range;

use serde::Serialize;

use crate::http::find_head_end;
use crate::text::RawText;

/// Only this much of each side is compared, so the result stays usable.
const MAX_COMPARED: usize = 8 * 1024 * 1024;
/// Past these, the two sides are unrelated and a detailed answer costs too much.
const MAX_LINE_EDITS: usize = 2000;
const MAX_TOKEN_EDITS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Span {
    pub text: String,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Side {
    pub number: u32,
    pub spans: Vec<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Row {
    Same { a: Side, b: Side },
    Changed { a: Side, b: Side },
    Removed { a: Side },
    Added { b: Side },
    /// Identical lines left out of the result.
    Gap { lines: u32 },
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Comparison {
    pub rows: Vec<Row>,
    pub changed: u32,
    pub removed: u32,
    pub added: u32,
    /// Part of a side was over the limit and was not compared.
    pub clipped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Equal(usize, usize),
    Replace(Range<usize>, Range<usize>),
}

/// Index pairs of a longest common subsequence, by Myers' greedy search, or
/// `None` if the sides need more than `limit` edits.
fn common<T: PartialEq>(a: &[T], b: &[T], limit: usize) -> Option<Vec<(usize, usize)>> {
    let (n, m) = (a.len() as i32, b.len() as i32);
    let max = (n + m).min(limit as i32);
    let offset = max + 1;
    let mut furthest = vec![0i32; 2 * max as usize + 3];
    // Each entry is the part of `furthest` that round could have read.
    let mut trace: Vec<Vec<i32>> = Vec::new();
    let choose_down = |v: &dyn Fn(i32) -> i32, k: i32, d: i32| k == -d || (k != d && v(k - 1) < v(k + 1));
    for d in 0..=max {
        trace.push(furthest[(offset - d - 1) as usize..=(offset + d + 1) as usize].to_vec());
        for k in (-d..=d).step_by(2) {
            let read = |k: i32| furthest[(k + offset) as usize];
            let mut x = if choose_down(&read, k, d) { read(k + 1) } else { read(k - 1) + 1 };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            furthest[(k + offset) as usize] = x;
            if x >= n && y >= m {
                let (mut x, mut y) = (n, m);
                let mut pairs = Vec::new();
                for (d, snapshot) in trace.iter().enumerate().rev() {
                    let d = d as i32;
                    let read = |k: i32| snapshot[(k + d + 1) as usize];
                    let k = x - y;
                    let previous = if choose_down(&read, k, d) { k + 1 } else { k - 1 };
                    let (start_x, start_y) = (read(previous), read(previous) - previous);
                    while x > start_x && y > start_y {
                        x -= 1;
                        y -= 1;
                        pairs.push((x as usize, y as usize));
                    }
                    x = start_x;
                    y = start_y;
                }
                pairs.reverse();
                return Some(pairs);
            }
        }
    }
    None
}

/// The matching items in order, with what lies between them as replacements.
fn align<T: PartialEq>(a: &[T], b: &[T], limit: usize) -> Vec<Op> {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let end = (a.len() - suffix, b.len() - suffix);
    let mut ops: Vec<Op> = (0..prefix).map(|i| Op::Equal(i, i)).collect();
    let mut position = (prefix, prefix);
    for (i, j) in common(&a[prefix..end.0], &b[prefix..end.1], limit).unwrap_or_default() {
        let (i, j) = (i + prefix, j + prefix);
        if (i, j) != position {
            ops.push(Op::Replace(position.0..i, position.1..j));
        }
        ops.push(Op::Equal(i, j));
        position = (i + 1, j + 1);
    }
    if position != end {
        ops.push(Op::Replace(position.0..end.0, position.1..end.1));
    }
    ops.extend((0..suffix).map(|n| Op::Equal(end.0 + n, end.1 + n)));
    ops
}

/// Words stay whole so that a changed value reads as one change.
fn tokens(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut word_start = None;
    for (i, c) in line.char_indices() {
        if c.is_alphanumeric() {
            word_start.get_or_insert(i);
            continue;
        }
        if let Some(start) = word_start.take() {
            out.push(&line[start..i]);
        }
        out.push(&line[i..i + c.len_utf8()]);
    }
    if let Some(start) = word_start {
        out.push(&line[start..]);
    }
    out
}

fn push_span(spans: &mut Vec<Span>, text: &str, changed: bool) {
    match spans.last_mut() {
        Some(last) if last.changed == changed => last.text.push_str(text),
        _ => spans.push(Span {
            text: text.to_string(),
            changed,
        }),
    }
}

/// A line ending is only worth showing when it is the difference.
fn tidy_line_ending(mut spans: Vec<Span>) -> Vec<Span> {
    for span in &mut spans {
        if span.changed {
            span.text = span.text.replace('\r', "␍");
        } else {
            span.text.truncate(span.text.trim_end_matches('\r').len());
        }
    }
    spans.retain(|span| !span.text.is_empty());
    spans
}

fn inline_spans(a: &str, b: &str) -> (Vec<Span>, Vec<Span>) {
    let (from, to) = (tokens(a), tokens(b));
    let (mut left, mut right) = (Vec::new(), Vec::new());
    for op in align(&from, &to, MAX_TOKEN_EDITS) {
        match op {
            Op::Equal(i, j) => {
                push_span(&mut left, from[i], false);
                push_span(&mut right, to[j], false);
            }
            Op::Replace(removed, added) => {
                from[removed].iter().for_each(|t| push_span(&mut left, t, true));
                to[added].iter().for_each(|t| push_span(&mut right, t, true));
            }
        }
    }
    (tidy_line_ending(left), tidy_line_ending(right))
}

fn line_text(line: &[u8]) -> String {
    RawText::from_bytes(line).text
}

fn whole_line(number: usize, line: &[u8]) -> Side {
    let spans = vec![Span {
        text: line_text(line),
        changed: false,
    }];
    Side {
        number: number as u32 + 1,
        spans: tidy_line_ending(spans),
    }
}

fn lines(message: &[u8]) -> Vec<&[u8]> {
    message
        .split_inclusive(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
        .collect()
}

fn body_of(message: &[u8]) -> &[u8] {
    match find_head_end(message) {
        Some(end) if message.starts_with(b"HTTP/") => &message[end..],
        _ => message,
    }
}

/// `context` is how many identical lines to keep around each difference;
/// `None` keeps them all.
pub fn compare(a: &[u8], b: &[u8], body_only: bool, context: Option<usize>) -> Comparison {
    let (a, b) = if body_only { (body_of(a), body_of(b)) } else { (a, b) };
    let mut result = Comparison {
        clipped: a.len() > MAX_COMPARED || b.len() > MAX_COMPARED,
        ..Comparison::default()
    };
    let from = lines(&a[..a.len().min(MAX_COMPARED)]);
    let to = lines(&b[..b.len().min(MAX_COMPARED)]);
    let ops = align(&from, &to, MAX_LINE_EDITS);

    let mut keep = vec![context.is_none(); ops.len()];
    if let Some(context) = context {
        for (i, op) in ops.iter().enumerate() {
            if matches!(op, Op::Replace(..)) {
                keep[i.saturating_sub(context)..(i + context + 1).min(ops.len())].fill(true);
            }
        }
    }

    let mut hidden = 0;
    for (op, keep) in ops.into_iter().zip(keep) {
        if !keep {
            hidden += 1;
            continue;
        }
        if hidden > 0 {
            result.rows.push(Row::Gap { lines: hidden });
            hidden = 0;
        }
        match op {
            Op::Equal(i, j) => result.rows.push(Row::Same {
                a: whole_line(i, from[i]),
                b: whole_line(j, to[j]),
            }),
            Op::Replace(removed, added) => {
                let paired = removed.len().min(added.len());
                for n in 0..paired {
                    let (i, j) = (removed.start + n, added.start + n);
                    let (left, right) = inline_spans(&line_text(from[i]), &line_text(to[j]));
                    result.rows.push(Row::Changed {
                        a: Side {
                            number: i as u32 + 1,
                            spans: left,
                        },
                        b: Side {
                            number: j as u32 + 1,
                            spans: right,
                        },
                    });
                }
                let only_a = removed.start + paired..removed.end;
                let only_b = added.start + paired..added.end;
                result.rows.extend(only_a.map(|i| Row::Removed { a: whole_line(i, from[i]) }));
                result.rows.extend(only_b.map(|j| Row::Added { b: whole_line(j, to[j]) }));
                result.changed += paired as u32;
                result.removed += (removed.len() - paired) as u32;
                result.added += (added.len() - paired) as u32;
            }
        }
    }
    if hidden > 0 {
        result.rows.push(Row::Gap { lines: hidden });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(spans: &[Span]) -> String {
        spans.iter().map(|s| s.text.as_str()).collect()
    }

    fn changed(spans: &[Span]) -> Vec<&str> {
        spans.iter().filter(|s| s.changed).map(|s| s.text.as_str()).collect()
    }

    fn lcs_length(a: &[u8], b: &[u8]) -> usize {
        let mut table = vec![vec![0; b.len() + 1]; a.len() + 1];
        for i in 1..=a.len() {
            for j in 1..=b.len() {
                table[i][j] = if a[i - 1] == b[j - 1] {
                    table[i - 1][j - 1] + 1
                } else {
                    table[i - 1][j].max(table[i][j - 1])
                };
            }
        }
        table[a.len()][b.len()]
    }

    #[test]
    fn common_finds_a_longest_subsequence() {
        let mut seed = 12345u32;
        let mut next = |bound: u32| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (seed >> 16) % bound
        };
        for _ in 0..2000 {
            let (la, lb) = (next(14) as usize, next(14) as usize);
            let a: Vec<u8> = (0..la).map(|_| next(3) as u8).collect();
            let b: Vec<u8> = (0..lb).map(|_| next(3) as u8).collect();
            let pairs = common(&a, &b, 1000).unwrap();
            assert_eq!(pairs.len(), lcs_length(&a, &b), "{a:?} {b:?}");
            assert!(pairs.iter().all(|(i, j)| a[*i] == b[*j]), "{a:?} {b:?}");
            assert!(pairs.windows(2).all(|w| w[0].0 < w[1].0 && w[0].1 < w[1].1), "{a:?} {b:?}");
        }
    }

    #[test]
    fn common_gives_up_past_its_limit() {
        assert_eq!(common(b"abcd", b"wxyz", 3), None);
    }

    #[test]
    fn unrelated_sides_become_one_replacement() {
        assert_eq!(align(b"ab", b"xy", 1), [Op::Replace(0..2, 0..2)]);
    }

    #[test]
    fn identical_messages_have_no_differences() {
        let done = compare(b"one\r\ntwo\r\n", b"one\r\ntwo\r\n", false, Some(3));
        assert_eq!((done.changed, done.removed, done.added), (0, 0, 0));
        assert_eq!(done.rows, [Row::Gap { lines: 2 }]);
        assert_eq!(compare(b"one\ntwo\n", b"one\ntwo\n", false, None).rows.len(), 2);
    }

    #[test]
    fn a_changed_value_is_the_only_highlight() {
        let done = compare(b"HTTP/1.1 200 OK\r\nX-Id: abc123\r\n", b"HTTP/1.1 200 OK\r\nX-Id: def456\r\n", false, None);
        assert_eq!(done.changed, 1);
        let Row::Changed { a, b } = &done.rows[1] else { panic!("{:?}", done.rows) };
        assert_eq!((a.number, b.number), (2, 2));
        assert_eq!(changed(&a.spans), ["abc123"]);
        assert_eq!(changed(&b.spans), ["def456"]);
        assert_eq!(text(&a.spans), "X-Id: abc123");
    }

    #[test]
    fn insertions_keep_later_lines_aligned() {
        let done = compare(b"a\nc\n", b"a\nb\nc\n", false, None);
        assert_eq!((done.changed, done.removed, done.added), (0, 0, 1));
        let Row::Added { b } = &done.rows[1] else { panic!("{:?}", done.rows) };
        assert_eq!(b.number, 2);
        let Row::Same { a, b } = &done.rows[2] else { panic!("{:?}", done.rows) };
        assert_eq!((a.number, b.number), (2, 3));
    }

    #[test]
    fn removals_are_counted_and_replacements_pair_up() {
        let done = compare(b"a\nx\ny\nz\nb\n", b"a\nq\nb\n", false, None);
        assert_eq!((done.changed, done.removed, done.added), (1, 2, 0));
    }

    #[test]
    fn distant_identical_lines_collapse() {
        let mut a: Vec<String> = (0..20).map(|i| format!("line {i}")).collect();
        let joined = a.join("\n");
        a[10] = "different".into();
        let done = compare(joined.as_bytes(), a.join("\n").as_bytes(), false, Some(2));
        assert_eq!(done.changed, 1);
        assert_eq!(done.rows.first(), Some(&Row::Gap { lines: 8 }));
        assert_eq!(done.rows.last(), Some(&Row::Gap { lines: 7 }));
        assert_eq!(done.rows.len(), 7);
    }

    #[test]
    fn body_only_ignores_the_headers() {
        let a = b"HTTP/1.1 200 OK\r\nDate: Mon\r\n\r\nsame\n";
        let b = b"HTTP/1.1 200 OK\r\nDate: Tue\r\n\r\nsame\n";
        assert_eq!(compare(a, b, false, None).changed, 1);
        assert_eq!(compare(a, b, true, None).changed, 0);
    }

    #[test]
    fn pasted_text_that_is_not_http_is_kept_whole() {
        let done = compare(b"one\r\n\r\ntwo", b"one\r\n\r\nthree", true, None);
        assert_eq!(done.changed, 1);
        assert_eq!(done.rows.len(), 3);
    }

    #[test]
    fn a_line_ending_difference_is_visible() {
        let done = compare(b"same\r\n", b"same\n", false, None);
        let Row::Changed { a, b } = &done.rows[0] else { panic!("{:?}", done.rows) };
        assert_eq!(changed(&a.spans), ["␍"]);
        assert_eq!(text(&b.spans), "same");
    }

    #[test]
    fn binary_lines_compare_without_loss() {
        let done = compare(&[0xff, 0x01, b'\n'], &[0xfe, 0x01, b'\n'], false, None);
        assert_eq!(done.changed, 1);
    }

    #[test]
    fn empty_sides_are_all_additions() {
        let done = compare(b"", b"a\nb\n", false, None);
        assert_eq!((done.changed, done.removed, done.added), (0, 0, 2));
        assert!(compare(b"", b"", false, Some(3)).rows.is_empty());
    }

    #[test]
    fn rows_serialize_with_the_names_the_interface_expects() {
        let json = serde_json::to_value(Row::Gap { lines: 2 }).unwrap();
        assert_eq!(json, serde_json::json!({ "kind": "gap", "lines": 2 }));
    }
}
