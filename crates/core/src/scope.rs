use serde::{Deserialize, Serialize};

use crate::http::rewrite::parse_authority;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Host pattern; `*` matches any run of characters.
    pub host: String,
    #[serde(default)]
    pub path_prefix: String,
}

impl ScopeRule {
    /// Reduces what people paste (`https://a.test/app`, `a.test:8443/`) to the
    /// host and path prefix that requests are matched against. A bare domain
    /// stays exact; subdomains need a `*.` pattern.
    fn normalized(&self) -> Self {
        let text = self.host.trim();
        let text = text.split_once("://").map_or(text, |(_, rest)| rest);
        let (authority, url_path) = text.split_at(text.find(['/', '?', '#']).unwrap_or(text.len()));
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        // More than one colon without brackets is an IPv6 address, not a port.
        let bare_ipv6 = authority.matches(':').count() > 1 && !authority.starts_with('[');
        let host = match parse_authority(authority, 0) {
            Some((host, _)) if !bare_ipv6 => host,
            _ => authority.to_string(),
        };
        let prefix = match self.path_prefix.trim() {
            "" => url_path.split(['?', '#']).next().unwrap_or(""),
            explicit => explicit,
        };
        let path_prefix = match prefix {
            "" | "/" => String::new(),
            path if path.starts_with('/') => path.to_string(),
            path => format!("/{path}"),
        };
        Self { host, path_prefix }
    }

    fn matches(&self, host: &str, path: &str) -> bool {
        glob_match(&self.host, host) && path.starts_with(&self.path_prefix)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub include: Vec<ScopeRule>,
    pub exclude: Vec<ScopeRule>,
}

impl Scope {
    /// The same rules in the form requests are matched against.
    pub fn normalized(&self) -> Self {
        let clean = |rules: &[ScopeRule]| {
            rules
                .iter()
                .map(ScopeRule::normalized)
                .filter(|rule| !rule.host.is_empty())
                .collect()
        };
        Self {
            include: clean(&self.include),
            exclude: clean(&self.exclude),
        }
    }

    /// Strict membership: an empty scope contains nothing. The fuzzer uses
    /// this so that it can only ever send to targets the user listed.
    pub fn contains(&self, host: &str, path: &str) -> bool {
        self.include.iter().any(|r| r.matches(host, path))
            && !self.exclude.iter().any(|r| r.matches(host, path))
    }

    /// Lenient membership for passive features, where an empty include list
    /// means the user has not narrowed anything down yet.
    pub fn allows(&self, host: &str, path: &str) -> bool {
        if self.include.is_empty() {
            !self.exclude.iter().any(|r| r.matches(host, path))
        } else {
            self.contains(host, path)
        }
    }
}

/// Case-insensitive glob supporting only `*`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    let parts: Vec<&str> = pattern.split('*').collect();
    let [first, middle @ .., last] = parts.as_slice() else {
        return text == pattern;
    };
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    for part in middle {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str, path_prefix: &str) -> ScopeRule {
        ScopeRule {
            host: host.into(),
            path_prefix: path_prefix.into(),
        }
    }

    #[test]
    fn globs() {
        assert!(glob_match("*.a.test", "x.A.test"));
        assert!(!glob_match("*.a.test", "a.test"));
        assert!(glob_match("a.test", "a.test"));
        assert!(!glob_match("a.test", "b.a.test"));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("ab*ab", "ab"));
    }

    #[test]
    fn empty_scope_is_strict_or_lenient() {
        let scope = Scope::default();
        assert!(!scope.contains("a.test", "/"));
        assert!(scope.allows("a.test", "/"));
    }

    #[test]
    fn pasted_urls_reduce_to_host_and_path() {
        for pasted in [
            "a.test",
            "a.test/",
            "  https://a.test  ",
            "https://a.test/",
            "HTTP://a.test/?x=1#top",
            "https://user:pw@a.test:8443/",
            "a.test:8443",
        ] {
            assert_eq!(rule(pasted, "").normalized(), rule("a.test", ""), "{pasted}");
        }
        assert_eq!(rule("https://*.a.test/", "").normalized(), rule("*.a.test", ""));
        assert_eq!(rule("https://a.test/app/?x=1", "").normalized(), rule("a.test", "/app/"));
        assert_eq!(rule("https://a.test/app", "/other").normalized(), rule("a.test", "/other"));
        assert_eq!(rule("a.test", "app").normalized(), rule("a.test", "/app"));
        assert_eq!(rule("a.test", "/").normalized(), rule("a.test", ""));
        assert_eq!(rule("[::1]:8080", "").normalized(), rule("::1", ""));
        assert_eq!(rule("::1", "").normalized(), rule("::1", ""));
    }

    #[test]
    fn a_bare_domain_does_not_widen_to_subdomains() {
        let scope = Scope {
            include: vec![rule("https://a.test/", "")],
            exclude: vec![rule("https://a.test/logout", "")],
        }
        .normalized();
        assert!(scope.contains("a.test", "/x"));
        assert!(!scope.contains("www.a.test", "/x"));
        assert!(!scope.contains("a.test", "/logout"));
    }

    #[test]
    fn rules_with_no_host_are_dropped() {
        let scope = Scope {
            include: vec![rule("https://", "")],
            exclude: vec![],
        };
        assert!(scope.normalized().include.is_empty());
    }

    #[test]
    fn exclude_beats_include() {
        let scope = Scope {
            include: vec![rule("a.test", "")],
            exclude: vec![rule("a.test", "/logout")],
        };
        assert!(scope.contains("a.test", "/x"));
        assert!(!scope.contains("a.test", "/logout"));
        assert!(!scope.allows("b.test", "/x"));
    }
}
