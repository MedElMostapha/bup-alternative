//! Passive checks over traffic that has already been recorded. Nothing in
//! this module sends a request.

use std::sync::LazyLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::http::decode::decode_body;
use crate::http::{find_head_end, parse_request_head, parse_response_head, RequestHead, ResponseHead};
use crate::model::{now_ms, Flow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: String,
    pub host: String,
    pub path: String,
    /// With `rule` and `host`, identifies a finding as already reported.
    pub dedupe: String,
    pub flow_id: u64,
    pub found_ms: i64,
}

/// What a rule reports; the scanner fills in where it was seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub detail: &'static str,
    pub evidence: String,
    /// Host-wide issues are reported once per host, others once per path.
    pub dedupe: Dedupe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dedupe {
    Host,
    Path,
    Key(String),
}

pub struct ScanContext<'a> {
    pub tls: bool,
    pub request: &'a RequestHead,
    pub response: &'a ResponseHead,
    /// The response body after removing transfer and content encodings.
    pub body: String,
}

impl ScanContext<'_> {
    fn mime(&self) -> String {
        self.response
            .header("content-type")
            .map(|v| String::from_utf8_lossy(v).to_ascii_lowercase())
            .unwrap_or_default()
    }

    fn is_html(&self) -> bool {
        self.mime().starts_with("text/html")
    }

    fn response_values(&self, name: &str) -> impl Iterator<Item = String> + '_ {
        let name = name.to_string();
        self.response
            .headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(&name))
            .map(|h| String::from_utf8_lossy(&h.value).into_owned())
    }

    fn response_text(&self, name: &str) -> Option<String> {
        self.response.header(name).map(|v| String::from_utf8_lossy(v).into_owned())
    }

    fn request_text(&self, name: &str) -> Option<String> {
        self.request.header(name).map(|v| String::from_utf8_lossy(v).into_owned())
    }
}

type Rule = fn(&ScanContext<'_>) -> Vec<Issue>;

const RULES: &[Rule] = &[
    missing_security_headers,
    cookie_flags,
    permissive_cors,
    version_disclosure,
    secrets_in_url,
    mixed_content,
    verbose_errors,
    directory_listing,
    jwt_alg_none,
];

pub fn scan(ctx: &ScanContext<'_>) -> Vec<Issue> {
    RULES.iter().flat_map(|rule| rule(ctx)).collect()
}

/// Runs every rule over a finished flow.
pub fn scan_flow(flow: &Flow) -> Vec<Finding> {
    let Some(raw_response) = flow.response.as_deref() else {
        return Vec::new();
    };
    let (Ok(request), Ok(response)) = (parse_request_head(&flow.request), parse_response_head(raw_response)) else {
        return Vec::new();
    };
    let start = find_head_end(raw_response).unwrap_or(raw_response.len());
    let decoded = decode_body(&response.headers, &raw_response[start..]);
    let ctx = ScanContext {
        tls: flow.target.tls,
        request: &request,
        response: &response,
        body: String::from_utf8_lossy(&decoded).into_owned(),
    };
    let path = request.target.split('?').next().unwrap_or("").to_string();
    scan(&ctx)
        .into_iter()
        .map(|issue| Finding {
            rule: issue.rule.to_string(),
            severity: issue.severity,
            title: issue.title,
            detail: issue.detail.to_string(),
            evidence: issue.evidence,
            host: flow.target.host.clone(),
            path: path.clone(),
            dedupe: match issue.dedupe {
                Dedupe::Host => String::new(),
                Dedupe::Path => path.clone(),
                Dedupe::Key(key) => key,
            },
            flow_id: flow.id,
            found_ms: now_ms(),
        })
        .collect()
}

fn missing_security_headers(ctx: &ScanContext<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut add = |rule, title: &str, detail, severity| {
        issues.push(Issue {
            rule,
            severity,
            title: title.to_string(),
            detail,
            evidence: format!("Response {} on {}", ctx.response.status, ctx.request.target),
            dedupe: Dedupe::Host,
        });
    };
    if ctx.tls && ctx.response.header("strict-transport-security").is_none() {
        add(
            "missing-hsts",
            "Strict-Transport-Security header is missing",
            "Without HSTS, a browser may reach this site over plain HTTP, where traffic can be read or changed.",
            Severity::Low,
        );
    }
    if !ctx.is_html() || !(200..300).contains(&ctx.response.status) {
        return issues;
    }
    let csp = ctx.response_text("content-security-policy");
    if csp.is_none() {
        add(
            "missing-csp",
            "Content-Security-Policy header is missing",
            "A content security policy limits the damage of cross-site scripting.",
            Severity::Low,
        );
    }
    if ctx.response.header("x-content-type-options").is_none() {
        add(
            "missing-content-type-options",
            "X-Content-Type-Options header is missing",
            "Setting this header to nosniff stops browsers guessing a different content type.",
            Severity::Low,
        );
    }
    let has_frame_ancestors = csp.is_some_and(|v| v.to_ascii_lowercase().contains("frame-ancestors"));
    if ctx.response.header("x-frame-options").is_none() && !has_frame_ancestors {
        add(
            "missing-frame-protection",
            "Page can be embedded in a frame by any site",
            "Without X-Frame-Options or a frame-ancestors policy, the page may be open to clickjacking.",
            Severity::Low,
        );
    }
    issues
}

fn cookie_flags(ctx: &ScanContext<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for cookie in ctx.response_values("set-cookie") {
        let mut parts = cookie.split(';');
        let name = parts.next().unwrap_or("").split('=').next().unwrap_or("").trim().to_string();
        let attributes: Vec<String> = parts
            .map(|p| p.split('=').next().unwrap_or("").trim().to_ascii_lowercase())
            .collect();
        let has = |flag: &str| attributes.iter().any(|a| a == flag);
        // Only the name is kept as evidence; the value may be a live session.
        let mut add = |rule, flag: &str, detail, severity| {
            issues.push(Issue {
                rule,
                severity,
                title: format!("Cookie {name} is missing {flag}"),
                detail,
                evidence: format!("Set-Cookie: {name}=…"),
                dedupe: Dedupe::Key(name.clone()),
            });
        };
        if ctx.tls && !has("secure") {
            add(
                "cookie-no-secure",
                "Secure",
                "Without Secure, the browser can send this cookie over unencrypted HTTP.",
                Severity::Low,
            );
        }
        if !has("httponly") {
            add(
                "cookie-no-httponly",
                "HttpOnly",
                "Without HttpOnly, scripts on the page can read this cookie.",
                Severity::Low,
            );
        }
        if !has("samesite") {
            add(
                "cookie-no-samesite",
                "SameSite",
                "Without an explicit SameSite value, protection against cross-site requests depends on browser defaults.",
                Severity::Info,
            );
        }
    }
    issues
}

fn permissive_cors(ctx: &ScanContext<'_>) -> Vec<Issue> {
    let Some(allowed) = ctx.response_text("access-control-allow-origin") else {
        return Vec::new();
    };
    let allowed = allowed.trim().to_string();
    let credentials = ctx
        .response_text("access-control-allow-credentials")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    let origin = ctx.request_text("origin");
    let (severity, title) = if allowed == "null" {
        (Severity::Medium, "CORS policy allows the null origin")
    } else if credentials && origin.as_deref().map(str::trim) == Some(allowed.as_str()) {
        (Severity::High, "CORS policy reflects the origin and allows credentials")
    } else if credentials && allowed == "*" {
        (Severity::Medium, "CORS policy combines a wildcard with credentials")
    } else {
        return Vec::new();
    };
    vec![Issue {
        rule: "permissive-cors",
        severity,
        title: title.to_string(),
        detail: "A permissive cross-origin policy can let other websites read responses from this site.",
        evidence: format!("Access-Control-Allow-Origin: {allowed}; credentials: {credentials}"),
        dedupe: Dedupe::Path,
    }]
}

fn version_disclosure(ctx: &ScanContext<'_>) -> Vec<Issue> {
    ["server", "x-powered-by", "x-aspnet-version"]
        .iter()
        .filter_map(|name| {
            let value = ctx.response_text(name)?;
            value.chars().any(|c| c.is_ascii_digit()).then(|| Issue {
                rule: "version-disclosure",
                severity: Severity::Info,
                title: format!("{name} header discloses a software version"),
                detail: "Version numbers help an attacker look up known vulnerabilities.",
                evidence: format!("{name}: {value}"),
                dedupe: Dedupe::Key((*name).to_string()),
            })
        })
        .collect()
}

static SECRET_PARAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(.*token|.*password|passwd|pwd|.*secret|api[_-]?key|session(id)?|jwt|auth)$").expect("valid regex")
});

fn secrets_in_url(ctx: &ScanContext<'_>) -> Vec<Issue> {
    let Some((_, query)) = ctx.request.target.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(name, value)| !value.is_empty() && SECRET_PARAM.is_match(name))
        .map(|(name, _)| Issue {
            rule: "secret-in-url",
            severity: Severity::Medium,
            title: format!("Parameter {name} may carry a secret in the URL"),
            detail: "URLs end up in browser history, server logs and Referer headers.",
            evidence: format!("?{name}=…"),
            dedupe: Dedupe::Key(name.to_string()),
        })
        .collect()
}

static MIXED_CONTENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<(script|iframe|img|link|embed|audio|video|source)\b[^>]*?\b(src|href)\s*=\s*["']?(http://[^"'\s>]+)"#)
        .expect("valid regex")
});

fn mixed_content(ctx: &ScanContext<'_>) -> Vec<Issue> {
    if !ctx.tls || !ctx.is_html() {
        return Vec::new();
    }
    let Some(found) = MIXED_CONTENT.captures(&ctx.body) else {
        return Vec::new();
    };
    let element = found[1].to_ascii_lowercase();
    let severity = if matches!(element.as_str(), "script" | "iframe" | "link") {
        Severity::Medium
    } else {
        Severity::Low
    };
    vec![Issue {
        rule: "mixed-content",
        severity,
        title: "HTTPS page loads a resource over HTTP".to_string(),
        detail: "A resource fetched over plain HTTP can be read or replaced by anyone on the network path.",
        evidence: format!("<{element}> {}", &found[3]),
        dedupe: Dedupe::Path,
    }]
}

static ERROR_SIGNATURES: LazyLock<Vec<(Regex, &'static str, Severity)>> = LazyLock::new(|| {
    [
        (r"Traceback \(most recent call last\)", "Python stack trace", Severity::Low),
        (r"at [\w.$]+\([\w$]+\.java:\d+\)", "Java stack trace", Severity::Low),
        (r"PHP (Fatal|Parse) error", "PHP error message", Severity::Low),
        (r"Server Error in '/[^']*' Application", "ASP.NET error page", Severity::Low),
        (r"SQLSTATE\[\w+\]", "SQL error message", Severity::Medium),
        (r"ORA-\d{5}", "Oracle database error", Severity::Medium),
        (r"You have an error in your SQL syntax", "MySQL error message", Severity::Medium),
    ]
    .into_iter()
    .map(|(pattern, name, severity)| (Regex::new(pattern).expect("valid regex"), name, severity))
    .collect()
});

fn verbose_errors(ctx: &ScanContext<'_>) -> Vec<Issue> {
    ERROR_SIGNATURES
        .iter()
        .filter_map(|(pattern, name, severity)| {
            let found = pattern.find(&ctx.body)?;
            Some(Issue {
                rule: "verbose-error",
                severity: *severity,
                title: format!("{name} in response"),
                detail: "Detailed errors can reveal code paths, queries and software versions.",
                evidence: found.as_str().chars().take(200).collect(),
                dedupe: Dedupe::Key(format!("{}:{name}", ctx.request.target.split('?').next().unwrap_or(""))),
            })
        })
        .collect()
}

static DIRECTORY_LISTING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<title>\s*(index of /|directory listing for /)").expect("valid regex"));

fn directory_listing(ctx: &ScanContext<'_>) -> Vec<Issue> {
    if !ctx.is_html() || ctx.response.status != 200 {
        return Vec::new();
    }
    let Some(found) = DIRECTORY_LISTING.find(&ctx.body) else {
        return Vec::new();
    };
    vec![Issue {
        rule: "directory-listing",
        severity: Severity::Low,
        title: "Directory listing is enabled".to_string(),
        detail: "A listing can expose files that were never meant to be linked.",
        evidence: found.as_str().to_string(),
        dedupe: Dedupe::Path,
    }]
}

static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").expect("valid regex"));

fn has_alg_none(token: &str) -> bool {
    let header = token.split('.').next().unwrap_or("");
    URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|json| json.get("alg")?.as_str().map(|a| a.eq_ignore_ascii_case("none")))
        .unwrap_or(false)
}

fn jwt_alg_none(ctx: &ScanContext<'_>) -> Vec<Issue> {
    let mut sources = vec![ctx.request_text("authorization"), ctx.request_text("cookie")];
    sources.extend(ctx.response_values("set-cookie").map(Some));
    let found = sources
        .iter()
        .flatten()
        .flat_map(|text| JWT.find_iter(text))
        .any(|m| has_alg_none(m.as_str()));
    if !found {
        return Vec::new();
    }
    vec![Issue {
        rule: "jwt-alg-none",
        severity: Severity::High,
        title: "JWT uses the none algorithm".to_string(),
        detail: "A token with no signature can be forged unless the server rejects it. Check that it does.",
        evidence: "JWT header has alg: none".to_string(),
        dedupe: Dedupe::Host,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Source, Target};

    fn flow(tls: bool, request: &str, response: &str) -> Flow {
        let target = Target {
            host: "a.test".into(),
            port: 443,
            tls,
        };
        let mut flow = Flow::new(1, Source::Proxy, target, request.as_bytes().to_vec());
        flow.response = Some(response.as_bytes().to_vec());
        flow
    }

    const GET: &str = "GET /page HTTP/1.1\r\nHost: a.test\r\n\r\n";

    fn rules(tls: bool, request: &str, response: &str) -> Vec<String> {
        scan_flow(&flow(tls, request, response)).into_iter().map(|f| f.rule).collect()
    }

    fn hardened(extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nStrict-Transport-Security: max-age=1\r\n\
             Content-Security-Policy: frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\n{extra}\r\n{body}"
        )
    }

    #[test]
    fn hardened_page_has_no_findings() {
        assert!(rules(true, GET, &hardened("", "<p>hello</p>")).is_empty());
    }

    #[test]
    fn plain_html_reports_missing_headers() {
        let found = rules(true, GET, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi");
        for rule in ["missing-hsts", "missing-csp", "missing-content-type-options", "missing-frame-protection"] {
            assert!(found.iter().any(|r| r == rule), "{rule} in {found:?}");
        }
    }

    #[test]
    fn hsts_is_not_expected_on_plain_http() {
        let found = rules(false, GET, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn cookie_flags_are_checked_and_value_is_withheld() {
        let response = hardened("Set-Cookie: sid=topsecret; Path=/\r\n", "");
        let findings = scan_flow(&flow(true, GET, &response));
        let found: Vec<_> = findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(found, ["cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"]);
        assert!(findings.iter().all(|f| !f.evidence.contains("topsecret")));
        assert!(rules(true, GET, &hardened("Set-Cookie: sid=x; Secure; HttpOnly; SameSite=Lax\r\n", "")).is_empty());
    }

    #[test]
    fn cors_reflection_with_credentials_is_high() {
        let request = "GET / HTTP/1.1\r\nOrigin: https://evil.test\r\n\r\n";
        let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.test\r\nAccess-Control-Allow-Credentials: true\r\n\r\n";
        let findings = scan_flow(&flow(false, request, response));
        assert_eq!(findings[0].rule, "permissive-cors");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn public_wildcard_cors_is_fine() {
        let response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
        assert!(rules(false, GET, response).is_empty());
    }

    #[test]
    fn version_numbers_are_flagged_but_bare_names_are_not() {
        assert_eq!(rules(false, GET, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n"), ["version-disclosure"]);
        assert!(rules(false, GET, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n").is_empty());
    }

    #[test]
    fn secrets_in_urls_are_flagged_without_the_value() {
        let request = "GET /x?page=1&access_token=abc123 HTTP/1.1\r\n\r\n";
        let findings = scan_flow(&flow(false, request, "HTTP/1.1 200 OK\r\n\r\n"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "secret-in-url");
        assert!(!findings[0].evidence.contains("abc123"));
    }

    #[test]
    fn mixed_content_needs_https_and_html() {
        let body = r#"<script src="http://cdn.test/a.js"></script>"#;
        assert_eq!(rules(true, GET, &hardened("", body)), ["mixed-content"]);
        assert!(rules(true, GET, &hardened("", r#"<a href="http://x.test">x</a>"#)).is_empty());
    }

    #[test]
    fn stack_traces_are_detected() {
        let response = "HTTP/1.1 500 X\r\n\r\nTraceback (most recent call last):\n  File";
        assert_eq!(rules(false, GET, response), ["verbose-error"]);
        assert!(rules(false, GET, "HTTP/1.1 500 X\r\n\r\nSomething went wrong").is_empty());
    }

    #[test]
    fn errors_inside_gzip_are_detected() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"ORA-00933: bad").unwrap();
        let mut raw = b"HTTP/1.1 500 X\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        raw.extend(encoder.finish().unwrap());
        let mut item = flow(false, GET, "");
        item.response = Some(raw);
        assert_eq!(scan_flow(&item)[0].rule, "verbose-error");
    }

    #[test]
    fn directory_listings_are_detected() {
        let body = "<html><title>Index of /files</title>";
        assert_eq!(rules(true, GET, &hardened("", body)), ["directory-listing"]);
    }

    #[test]
    fn unsigned_jwts_are_detected() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let request = format!("GET / HTTP/1.1\r\nAuthorization: Bearer {header}.e30.\r\n\r\n");
        assert_eq!(rules(false, &request, "HTTP/1.1 200 OK\r\n\r\n"), ["jwt-alg-none"]);
        let signed = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let request = format!("GET / HTTP/1.1\r\nAuthorization: Bearer {signed}.e30.c2ln\r\n\r\n");
        assert!(rules(false, &request, "HTTP/1.1 200 OK\r\n\r\n").is_empty());
    }

    #[test]
    fn incomplete_flows_are_skipped() {
        let mut item = flow(false, GET, "");
        item.response = None;
        assert!(scan_flow(&item).is_empty());
    }
}
