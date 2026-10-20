//! Log redaction helpers (ARCHITECTURE §Logging).
//!
//! Three layers: `Redacted<T>` for values we hold, header helpers for request logging, and
//! [`scrub`], a last-line-of-defence text scrubber applied to every emitted log line.

use std::fmt;

/// Replacement text for anything secret.
pub const REDACTED: &str = "[REDACTED]";

/// Lower-case field/header names whose values must never reach a log line.
const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "set_cookie",
    "x-api-key",
    "x_api_key",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "totp",
    "totp_code",
    "otp",
    "csrf",
    "csrf_token",
    "session",
    "session_id",
    "secret",
    "token",
    "recovery_code",
    "recovery-code",
    "totp_key",
    "totp_secret",
    "sid",
    "nonce",
    "key",
];

/// Wrapper whose `Debug`/`Display` never reveal the inner value.
#[derive(Clone, Copy, Default)]
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// True if a header or field called `name` carries a secret (case-insensitive).
#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    SENSITIVE_KEYS.iter().any(|k| name.eq_ignore_ascii_case(k))
}

/// True if a structured field name matches the text scrubber's secret-name policy.
/// Also recognises suffixed names, dotted paths such as `request.sid`, and Rust raw identifiers.
#[must_use]
pub fn is_sensitive_field(name: &str) -> bool {
    let lower = name.strip_prefix("r#").unwrap_or(name).to_ascii_lowercase();
    is_sensitive_key(&lower)
        || lower.rsplit_once('.').is_some_and(|(_, component)| {
            is_sensitive_key(component.strip_prefix("r#").unwrap_or(component))
        })
}

/// Returns the value to log for header `name`: the real value, or [`REDACTED`] if sensitive.
#[must_use]
pub fn header_for_log<'a>(name: &str, value: &'a str) -> &'a str {
    if is_sensitive_name(name) {
        REDACTED
    } else {
        value
    }
}

/// Path without query string or fragment, for logging (queries may carry tokens).
#[must_use]
pub fn path_for_log(path_and_query: &str) -> &str {
    let end = path_and_query
        .find(['?', '#'])
        .unwrap_or(path_and_query.len());
    path_and_query.get(..end).unwrap_or_default()
}

/// Longest JSON key considered (bounds the look-ahead per quote, keeping `scrub` linear).
const MAX_KEY_LEN: usize = 64;
/// Shortest word starting with `nzbd_` treated as an API key (`nzbd_` + 43 base64url chars).
const API_KEY_MIN_LEN: usize = 24;

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// `word` (lower-case) is a sensitive key, or ends in one after a `_`/`-` boundary
/// (`user_password`, `x-csrf-token`); longer keys also match as plain suffixes.
fn is_sensitive_key(word: &str) -> bool {
    SENSITIVE_KEYS.iter().any(|k| {
        if word == *k {
            return true;
        }
        if !word.ends_with(k) {
            return false;
        }
        let Some(prev) = word
            .len()
            .checked_sub(k.len().saturating_add(1))
            .and_then(|i| word.as_bytes().get(i))
        else {
            return false;
        };
        k.len() >= 5 || matches!(prev, b'_' | b'-')
    })
}

/// End of a bare token: whitespace, quote, backslash, `&`, `,` or `;`.
fn token_end(b: &[u8], from: usize) -> usize {
    let mut e = from;
    while let Some(&c) = b.get(e) {
        if c.is_ascii_whitespace() || matches!(c, b'"' | b'\\' | b'&' | b',' | b';') {
            break;
        }
        e = e.saturating_add(1);
    }
    e
}

/// End (index of the closing quote, or `b.len()`) of a string whose body starts at `from`.
fn string_end(b: &[u8], from: usize) -> usize {
    let mut e = from;
    let mut escaped = false;
    while let Some(&c) = b.get(e) {
        if c == b'"' && !escaped {
            break;
        }
        escaped = c == b'\\' && !escaped;
        e = e.saturating_add(1);
    }
    e
}

fn skip_blanks(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t')) {
        i = i.saturating_add(1);
    }
    i
}

/// What to do at the current scan position.
enum Step {
    /// Replace `input[start..end]` with [`REDACTED`], resume at `next`.
    Redact {
        start: usize,
        end: usize,
        next: usize,
    },
    /// Nothing to redact; resume at the index.
    Skip(usize),
}

/// At a `"`: a JSON member `"key": value` with a sensitive key has its value redacted
/// (string, number, bool or null).
fn json_member(b: &[u8], lb: &[u8], lower: &str, i: usize) -> Step {
    let ks = i.saturating_add(1);
    let window_end = ks.saturating_add(MAX_KEY_LEN).min(lb.len());
    let Some(rel) = lb
        .get(ks..window_end)
        .and_then(|w| w.iter().position(|c| *c == b'"'))
    else {
        return Step::Skip(ks);
    };
    let kend = ks.saturating_add(rel);
    let p = skip_blanks(lb, kend.saturating_add(1));
    if lb.get(p) != Some(&b':') {
        return Step::Skip(ks); // a string value, not a key: scan its content as text
    }
    let key = lower.get(ks..kend).unwrap_or_default();
    if !is_sensitive_field(key) {
        return Step::Skip(kend.saturating_add(1));
    }
    let vs = skip_blanks(lb, p.saturating_add(1));
    if lb.get(vs) == Some(&b'"') {
        let start = vs.saturating_add(1);
        let end = string_end(b, start);
        let next = end.saturating_add(1).min(b.len());
        return Step::Redact { start, end, next };
    }
    let mut end = vs;
    while let Some(&c) = b.get(end) {
        if c.is_ascii_whitespace() || matches!(c, b',' | b'}' | b']') {
            break;
        }
        end = end.saturating_add(1);
    }
    if end == vs {
        return Step::Skip(vs);
    }
    Step::Redact {
        start: vs,
        end,
        next: end,
    }
}

/// At the start of a word `[i, j)`: `key=value`, `nzbd_...` API keys, `Bearer <token>`.
fn word_step(b: &[u8], lb: &[u8], lower: &str, i: usize, j: usize) -> Step {
    let word = lower.get(i..j).unwrap_or_default();
    if lb.get(j) == Some(&b'=') && is_sensitive_key(word) {
        let vs = j.saturating_add(1);
        if b.get(vs) == Some(&b'"') {
            let start = vs.saturating_add(1);
            let end = string_end(b, start);
            return Step::Redact {
                start,
                end,
                next: end.saturating_add(1).min(b.len()),
            };
        }
        let mut end = token_end(b, vs);
        if end == vs {
            return Step::Skip(vs);
        }
        // `authorization=Bearer abc`: the scheme is not the secret, the token after it is.
        if matches!(lower.get(vs..end), Some("bearer" | "basic")) && b.get(end) == Some(&b' ') {
            end = token_end(b, end.saturating_add(1));
        }
        return Step::Redact {
            start: vs,
            end,
            next: end,
        };
    }
    if word.starts_with("nzbd_") && word.len() >= API_KEY_MIN_LEN {
        return Step::Redact {
            start: i,
            end: j,
            next: j,
        };
    }
    if word == "bearer" && b.get(j) == Some(&b' ') {
        let start = j.saturating_add(1);
        let end = token_end(b, start);
        if end > start {
            return Step::Redact {
                start,
                end,
                next: end,
            };
        }
    }
    Step::Skip(j)
}

/// Replaces secrets in a log line with [`REDACTED`], in one linear pass.
///
/// Recognises, case-insensitively: JSON members with a sensitive key (`"password":"x"`,
/// `"totp_code":123456`), `key=value` text (also `key="quoted value"`), `Bearer <token>`, and
/// bare API keys of the form `nzbd_<base64url>` under any field name.
#[must_use]
pub fn scrub(input: &str) -> String {
    let b = input.as_bytes();
    let lower = input.to_ascii_lowercase(); // ASCII-only: byte offsets stay aligned with `input`
    let lb = lower.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut last = 0_usize;
    let mut i = 0_usize;
    while let Some(&c) = b.get(i) {
        let step = if c == b'"' {
            json_member(b, lb, &lower, i)
        } else if is_word_byte(c) {
            let mut j = i;
            while b.get(j).is_some_and(|x| is_word_byte(*x)) {
                j = j.saturating_add(1);
            }
            word_step(b, lb, &lower, i, j)
        } else {
            Step::Skip(i.saturating_add(1))
        };
        match step {
            Step::Redact { start, end, next } => {
                out.push_str(input.get(last..start).unwrap_or_default());
                out.push_str(REDACTED);
                last = end;
                i = next.max(i.saturating_add(1));
            }
            Step::Skip(next) => i = next.max(i.saturating_add(1)),
        }
    }
    out.push_str(input.get(last..).unwrap_or_default());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_wrapper_hides_value() {
        assert_eq!(
            format!("{:?} {}", Redacted("hunter2"), Redacted(7)),
            "[REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn headers_and_paths() {
        assert_eq!(header_for_log("Authorization", "Bearer x"), REDACTED);
        assert_eq!(header_for_log("X-Api-Key", "k"), REDACTED);
        assert_eq!(header_for_log("Accept", "text/html"), "text/html");
        assert_eq!(path_for_log("/login?next=/&token=abc"), "/login");
    }

    #[test]
    fn structured_field_names_follow_the_scrubber_policy() {
        for name in [
            "password",
            "PassWord",
            "user_password",
            "x-csrf-token",
            "r#key",
            "sid",
            "request.sid",
            "request.otp",
            "request.key",
            "request.csrf",
            "request.user_password",
            "request.r#key",
        ] {
            assert!(is_sensitive_field(name), "missed secret field {name}");
        }
        for name in [
            "message",
            "user",
            "status",
            "monkey",
            "public_key_id",
            "publicrequest.monkey",
            "request.public_key_id",
        ] {
            assert!(!is_sensitive_field(name), "masked public field {name}");
        }
    }

    #[test]
    fn scrub_json_recognises_dotted_sensitive_fields() {
        for name in [
            "r#key",
            "request.sid",
            "request.otp",
            "request.key",
            "request.csrf",
            "request.user_password",
            "request.r#key",
        ] {
            let input = format!(
                r#"{{"{name}":"secret head secret tail","publicrequest.monkey":"public words","request.public_key_id":"public id"}}"#
            );
            let expected = format!(
                r#"{{"{name}":"[REDACTED]","publicrequest.monkey":"public words","request.public_key_id":"public id"}}"#
            );
            assert_eq!(scrub(&input), expected);
        }
    }

    #[test]
    fn sec_033_scrub_numeric_bool_and_null_json_values() {
        let s = scrub(r#"{"totp_code":123456,"ok":true,"recovery_code": 99,"sid":null,"n":7}"#);
        assert_eq!(
            s,
            r#"{"totp_code":[REDACTED],"ok":true,"recovery_code": [REDACTED],"sid":[REDACTED],"n":7}"#
        );
    }

    #[test]
    fn sec_033_scrub_extended_keys_and_api_key_shape() {
        let key = format!("nzbd_{}", "A1b2-C3d4_".repeat(5));
        let s = scrub(&format!("created {key} for ui, other=nzbd_short"));
        assert!(!s.contains("A1b2"), "{s}");
        assert!(s.contains("other=nzbd_short"), "{s}");
        let s = scrub("totp_key=abc recovery_code=r-1234 sid=zz nonce=q Bearer tok123 ok");
        assert_eq!(
            s,
            "totp_key=[REDACTED] recovery_code=[REDACTED] sid=[REDACTED] nonce=[REDACTED] Bearer [REDACTED] ok"
        );
        let s = scrub(r#"Authorization=Bearer abc.def user_password="two words" x=1"#);
        assert_eq!(
            s,
            r#"Authorization=[REDACTED] user_password="[REDACTED]" x=1"#
        );
        // Secrets inside a JSON string value (nested key=value text) are still caught.
        let s = scrub(r#"{"msg":"login password=hunter2 failed"}"#);
        assert_eq!(s, r#"{"msg":"login password=[REDACTED] failed"}"#);
    }

    #[test]
    fn sec_033_scrub_is_linear_on_adversarial_input() {
        // 200k secret-key occurrences must finish promptly (old code was quadratic).
        let line = "password=x ".repeat(200_000);
        let t = std::time::Instant::now();
        let out = scrub(&line);
        // Very generous runaway ceiling: quadratic behaviour here would take minutes.
        assert!(t.elapsed() < std::time::Duration::from_secs(30));
        assert!(!out.contains("=x"));
        let quotes = "\"".repeat(200_000);
        let t = std::time::Instant::now();
        let _ = scrub(&quotes);
        // Very generous runaway ceiling: quadratic behaviour here would take minutes.
        assert!(t.elapsed() < std::time::Duration::from_secs(30));
    }

    #[test]
    fn scrub_json_and_kv() {
        let s = scrub(r#"{"msg":"x","password":"hu\"nter2","n":1,"Cookie":"a=b; c=d"}"#);
        assert!(!s.contains("hu"), "{s}");
        assert!(!s.contains("a=b"), "{s}");
        assert!(s.contains(r#""n":1"#));
        let s = scrub("login password=hunter2&user=bob csrf_token=zzz ok");
        assert_eq!(
            s,
            "login password=[REDACTED]&user=bob csrf_token=[REDACTED] ok"
        );
    }
}
