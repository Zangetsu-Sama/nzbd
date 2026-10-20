//! Structured JSON logging to stdout with a redacting writer.

use std::fmt;
use std::io::{self, Write};

use nzb_web::redact::{REDACTED, is_sensitive_field, scrub};
use tracing::field::{Field, Visit};
use tracing_subscriber::field::{RecordFields, VisitOutput};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::{DefaultVisitor, FormatFields, Writer};

/// Wraps a writer and scrubs secrets from every event before it is written.
///
/// `tracing`'s formatter hands the writer one complete line per event, so scrubbing per
/// `write` call sees whole JSON members. This is defence in depth on top of `Redacted<T>`.
pub struct ScrubWriter<W>(W);

impl<W: Write> Write for ScrubWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.0.write_all(scrub(&text).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// `MakeWriter` producing [`ScrubWriter`]s around another `MakeWriter`.
pub struct ScrubMakeWriter<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for ScrubMakeWriter<M> {
    type Writer = ScrubWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubWriter(self.0.make_writer())
    }
}

/// Redacts event and span values before formatting them or adding ANSI decorations.
struct ScrubFields;

impl<'writer> FormatFields<'writer> for ScrubFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        // A fresh writer has ANSI disabled. The surrounding event formatter keeps its colours,
        // while both initial span fields and later `Span::record` calls use this plain format.
        let mut plain = String::new();
        let mut visitor = ScrubVisitor(DefaultVisitor::new(Writer::new(&mut plain), true));
        fields.record(&mut visitor);
        visitor.0.finish()?;
        // Messages and public fields can themselves contain inline credentials.
        writer.write_str(&scrub(&plain))
    }
}

struct ScrubVisitor<'writer>(DefaultVisitor<'writer>);

impl Visit for ScrubVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if is_sensitive_field(field.name()) {
            self.0.record_str(field, REDACTED);
        } else {
            self.0.record_str(field, value);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if is_sensitive_field(field.name()) {
            self.0.record_str(field, REDACTED);
        } else {
            self.0.record_error(field, value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // Visit's numeric, boolean and byte methods delegate here too. Do not invoke a secret's
        // Debug/Display formatter: its output may include spaces, lists or arbitrary punctuation.
        if is_sensitive_field(field.name()) {
            self.0.record_str(field, REDACTED);
        } else {
            self.0.record_debug(field, value);
        }
    }
}

/// Environment variable choosing the log layout. Single underscore: not a `NZBD__section__key` override.
const FORMAT_ENV: &str = "NZBD_LOG_FORMAT";

/// Log layout. `Json` stays the default (machine-readable, what the production image and the e2e
/// checks parse); `Pretty` is for humans reading `docker compose logs` or `scripts/dev serve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One flattened JSON object per event.
    Json,
    /// Single-line, coloured (ANSI) text.
    Pretty,
}

impl Format {
    /// `pretty` (any case) selects [`Format::Pretty`]; anything else, or unset, is JSON.
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some(v) if v.eq_ignore_ascii_case("pretty") => Self::Pretty,
            _ => Self::Json,
        }
    }

    /// The layout requested by `NZBD_LOG_FORMAT`.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(FORMAT_ENV).ok().as_deref())
    }
}

/// Colour is on for the pretty layout unless the `NO_COLOR` convention (any non-empty value) asks otherwise.
fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

/// Builds the JSON subscriber: flattened events (`timestamp, level, target, message, ...`).
pub fn subscriber<M>(writer: M) -> impl tracing::Subscriber + Send + Sync
where
    M: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .with_env_filter(env_filter())
        .with_writer(ScrubMakeWriter(writer))
        .finish()
}

/// Builds the pretty subscriber: `time LEVEL target message key=value`, coloured when `ansi`.
/// Fields are redacted without ANSI escapes; [`ScrubMakeWriter`] also scrubs the finished line.
pub fn pretty_subscriber<M>(writer: M, ansi: bool) -> impl tracing::Subscriber + Send + Sync
where
    M: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .compact()
        .fmt_fields(ScrubFields)
        .with_target(true)
        .with_ansi(ansi)
        .with_env_filter(env_filter())
        .with_writer(ScrubMakeWriter(writer))
        .finish()
}

fn env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

/// Installs the global subscriber writing to stdout, in the layout `NZBD_LOG_FORMAT` asks for.
pub fn init() {
    // A second install attempt (tests) is harmless: ignore the error.
    let _ = match Format::from_env() {
        Format::Json => tracing::subscriber::set_global_default(subscriber(io::stdout)),
        Format::Pretty => {
            tracing::subscriber::set_global_default(pretty_subscriber(io::stdout, color_enabled()))
        }
    };
}

/// The startup banner, or `None` for the JSON layout (a banner would break line-per-event parsing).
pub fn banner(format: Format, version: &str, listen: &str) -> Option<String> {
    if format != Format::Pretty {
        return None;
    }
    let (cyan, magenta, dim, reset) = if color_enabled() {
        ("\x1b[1;36m", "\x1b[1;35m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "")
    };
    Some(format!(
        "{cyan}  _ __  ____| |__   __| |\n\
         {cyan} | '_ \\|_  /| '_ \\ / _` |\n\
         {magenta} | | | |/ / | |_) | (_| |\n\
         {magenta} |_| |_/___||_.__/ \\__,_|{reset}\n\
         {dim}  NZB indexer  |  v{version}  |  listening on {listen}  |  zero outbound{reset}\n"
    ))
}

/// Prints [`banner`] to stdout when `NZBD_LOG_FORMAT=pretty`.
pub fn print_banner(version: &str, listen: &str) {
    if let Some(b) = banner(Format::from_env(), version, listen) {
        println!("{b}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if let Ok(mut g) = self.0.lock() {
                g.extend_from_slice(b);
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    #[test]
    fn log_redaction_removes_secrets_from_output() {
        let buf = Buf::default();
        let sub = subscriber(buf.clone());
        tracing::subscriber::with_default(sub, || {
            tracing::info!(
                password = "hunter2-pw",
                authorization = "Bearer abc123tok",
                x_api_key = "plain-api-key",
                cookie = "__Host-sid=sessionsecret",
                csrf_token = "csrfsecret",
                totp_code = "123456",
                wrapped = %nzb_web::redact::Redacted("wrapped-secret"),
                "login attempt password=inline-pw user=alice"
            );
            tracing::info!(session = "sid-zzz", "plain event");
        });
        let out = String::from_utf8(buf.0.lock().map(|g| g.clone()).unwrap_or_default())
            .unwrap_or_default();
        for secret in [
            "hunter2-pw",
            "abc123tok",
            "sessionsecret",
            "csrfsecret",
            "123456",
            "wrapped-secret",
            "inline-pw",
            "sid-zzz",
        ] {
            assert!(!out.contains(secret), "leaked {secret}: {out}");
        }
        assert!(out.contains("alice"), "non-secret data kept: {out}");
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn pretty_format_is_opt_in_and_banner_is_pretty_only() {
        assert_eq!(Format::parse(None), Format::Json);
        assert_eq!(Format::parse(Some("json")), Format::Json);
        assert_eq!(Format::parse(Some("Pretty")), Format::Pretty);
        assert!(banner(Format::Json, "1.0.0", "0.0.0.0:8080").is_none());
        let b = banner(Format::Pretty, "1.0.0", "0.0.0.0:8080").unwrap_or_default();
        assert!(b.contains("v1.0.0") && b.contains("0.0.0.0:8080"));
    }

    #[test]
    fn pretty_output_is_redacted_too() {
        let buf = Buf::default();
        let sub = pretty_subscriber(buf.clone(), false);
        tracing::subscriber::with_default(sub, || {
            tracing::info!(password = "hunter2-pw", "login user=alice");
        });
        let out = String::from_utf8(buf.0.lock().map(|g| g.clone()).unwrap_or_default())
            .unwrap_or_default();
        assert!(!out.contains("hunter2-pw"), "leaked: {out}");
        assert!(out.contains("alice"));
    }

    #[test]
    fn pretty_ansi_output_redacts_event_and_span_fields() {
        let buf = Buf::default();
        let sub = pretty_subscriber(buf.clone(), true);
        tracing::subscriber::with_default(sub, || {
            let span = tracing::info_span!(
                "login",
                password = "AUDIT_FAKE_SPAN_PASSWORD",
                csrf_token = tracing::field::Empty,
                user = "alice"
            );
            let _entered = span.enter();
            tracing::info!(
                password = "AUDIT_FAKE_COLORED_PASSWORD",
                authorization = "Bearer AUDIT_FAKE_AUTHORIZATION",
                cookie = "__Host-sid=AUDIT_FAKE_COOKIE",
                x_api_key = "AUDIT_FAKE_API_KEY",
                totp_code = 987_654,
                user_password = "AUDIT_FAKE_PREFIXED_PASSWORD",
                sid = "AUDIT_FAKE_SID",
                nonce = "AUDIT_FAKE_NONCE",
                key = "AUDIT_FAKE_KEY",
                status = 200,
                "login password=AUDIT_FAKE_INLINE_PASSWORD"
            );
            span.record("csrf_token", "AUDIT_FAKE_RECORDED_CSRF");
            tracing::info!("recorded span fields");
        });
        let out = String::from_utf8(buf.0.lock().map(|g| g.clone()).unwrap_or_default())
            .unwrap_or_default();
        assert!(out.contains("\x1b["), "the regression requires ANSI output");
        assert!(!out.contains("AUDIT_FAKE_"), "leaked a secret: {out}");
        assert!(!out.contains("987654"), "leaked the numeric code: {out}");
        assert!(out.contains("password=\"[REDACTED]\""), "{out}");
        assert!(out.contains("csrf_token=\"[REDACTED]\""), "{out}");
        assert!(out.contains("alice") && out.contains("status=200"), "{out}");
        assert!(out.contains("recorded span fields"), "{out}");
    }

    #[test]
    fn sec_107_pretty_output_redacts_sensitive_values_before_formatting() {
        struct ObservedSecret(std::cell::Cell<usize>);

        impl std::fmt::Debug for ObservedSecret {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.set(self.0.get() + 1);
                f.write_str("AUDIT_SECRET_OBSERVED_HEAD AUDIT_SECRET_OBSERVED_TAIL")
            }
        }

        impl std::fmt::Display for ObservedSecret {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(self, f)
            }
        }

        for ansi in [false, true] {
            let buf = Buf::default();
            let secret = ObservedSecret(std::cell::Cell::new(0));
            let error = std::io::Error::other("AUDIT_SECRET_ERROR_HEAD AUDIT_SECRET_ERROR_TAIL");
            let dotted_secret = "AUDIT_SECRET_DOTTED_HEAD AUDIT_SECRET_DOTTED_TAIL";
            let sub = pretty_subscriber(buf.clone(), ansi);
            tracing::subscriber::with_default(sub, || {
                let span = tracing::info_span!(
                    "sensitive_fields",
                    password = %"AUDIT_SECRET_SPAN_HEAD AUDIT_SECRET_SPAN_TAIL",
                    token = ?["AUDIT_SECRET_SPAN_ONE", "AUDIT_SECRET_SPAN_TWO"],
                    csrf_token = tracing::field::Empty,
                    session = tracing::field::Empty,
                    user = "alice"
                );
                let _entered = span.enter();
                tracing::info!(
                    password = %"AUDIT_SECRET_DISPLAY_HEAD AUDIT_SECRET_DISPLAY_TAIL",
                    user_password = ?["AUDIT_SECRET_DEBUG_ONE", "AUDIT_SECRET_DEBUG_TWO"],
                    secret = &error as &(dyn std::error::Error + 'static),
                    key = %secret,
                    nonce = ?secret,
                    request.sid = %dotted_secret,
                    request.otp = %dotted_secret,
                    request.key = %dotted_secret,
                    request.csrf = %dotted_secret,
                    request.user_password = %dotted_secret,
                    publicrequest.monkey = %"public monkey words",
                    request.public_key_id = %"public key identifier",
                    details = %"public words",
                    items = ?["public-one", "public-two"],
                    status = 200,
                    "login password=AUDIT_SECRET_INLINE user=alice"
                );
                span.record(
                    "csrf_token",
                    tracing::field::debug([
                        "AUDIT_SECRET_RECORDED_ONE",
                        "AUDIT_SECRET_RECORDED_TWO",
                    ]),
                );
                span.record(
                    "session",
                    tracing::field::display(
                        "AUDIT_SECRET_RECORDED_HEAD AUDIT_SECRET_RECORDED_TAIL",
                    ),
                );
                tracing::info!("recorded complex fields");
            });
            let out = String::from_utf8(buf.0.lock().map(|g| g.clone()).unwrap_or_default())
                .unwrap_or_default();
            assert_eq!(secret.0.get(), 0, "secret formatter must never run");
            assert_eq!(out.contains("\x1b["), ansi, "{out}");
            assert!(!out.contains("AUDIT_SECRET_"), "leaked a secret: {out}");
            assert!(out.contains("csrf_token=\"[REDACTED]\""), "{out}");
            assert!(out.contains("session=\"[REDACTED]\""), "{out}");
            assert!(out.contains("alice") && out.contains("status=200"), "{out}");
            assert!(out.contains("public words"), "{out}");
            assert!(out.contains("public monkey words"), "{out}");
            assert!(out.contains("public key identifier"), "{out}");
            for name in ["sid", "otp", "key", "csrf", "user_password"] {
                assert!(
                    out.contains(&format!("request.{name}=\"[REDACTED]\"")),
                    "{out}"
                );
            }
            assert!(
                out.contains("public-one") && out.contains("public-two"),
                "{out}"
            );
            assert!(out.contains("recorded complex fields"), "{out}");
        }
    }

    #[test]
    fn sec_107_json_output_redacts_dotted_sensitive_fields() {
        let buf = Buf::default();
        let sub = subscriber(buf.clone());
        tracing::subscriber::with_default(sub, || {
            let secret = "AUDIT_JSON_SECRET_HEAD AUDIT_JSON_SECRET_TAIL";
            tracing::info!(
                request.sid = %secret,
                request.otp = ?["AUDIT_JSON_SECRET_ONE", "AUDIT_JSON_SECRET_TWO"],
                request.key = %secret,
                request.csrf = %secret,
                request.user_password = %secret,
                "request.r#key" = %secret,
                "r#key" = %secret,
                publicrequest.monkey = %"public monkey words",
                request.public_key_id = %"public key identifier",
                "public message"
            );
        });
        let out = String::from_utf8(buf.0.lock().map(|g| g.clone()).unwrap_or_default())
            .unwrap_or_default();
        assert!(
            !out.contains("AUDIT_JSON_SECRET_"),
            "leaked a secret: {out}"
        );
        for name in [
            "request.sid",
            "request.otp",
            "request.key",
            "request.csrf",
            "request.user_password",
            "request.r#key",
            "r#key",
        ] {
            assert!(out.contains(&format!(r#""{name}":"[REDACTED]""#)), "{out}");
        }
        assert!(out.contains("public monkey words"), "{out}");
        assert!(out.contains("public key identifier"), "{out}");
        assert!(out.contains("public message"), "{out}");
    }
}
