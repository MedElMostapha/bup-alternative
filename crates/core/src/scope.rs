use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Host pattern; `*` matches any run of characters.
    pub host: String,
    #[serde(default)]
    pub path_prefix: String,
}

impl ScopeRule {
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
