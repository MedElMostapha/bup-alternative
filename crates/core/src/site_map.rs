//! The site map: recorded proxy traffic arranged as a tree of hosts and paths.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Target;
use crate::scope::Scope;

/// Anything deeper stays in one node, so a hostile URL can't nest without limit.
const MAX_DEPTH: usize = 32;

/// Recorded requests that share a target, a request path and a status.
#[derive(Debug, Clone)]
pub struct SiteRow {
    pub target: Target,
    pub path: String,
    pub status: Option<u16>,
    pub requests: u64,
    pub latest_id: u64,
}

/// One node of the tree, for narrowing a flow list down to what is under it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitePlace {
    pub target: Target,
    /// Empty for a whole host.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteNode {
    pub name: String,
    pub path: String,
    /// Requests to this path and everything below it.
    pub requests: u64,
    /// The latest request to exactly this path, if there was one.
    pub flow_id: Option<u64>,
    pub status: Option<u16>,
    /// Whether this path or anything below it is in scope.
    pub in_scope: bool,
    pub children: Vec<SiteNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteTree {
    pub target: Target,
    pub root: SiteNode,
}

#[derive(Default)]
struct Branch {
    requests: u64,
    latest: Option<(u64, Option<u16>)>,
    in_scope: bool,
    children: BTreeMap<String, Branch>,
}

impl Branch {
    fn count(&mut self, row: &SiteRow, in_scope: bool) {
        self.requests += row.requests;
        self.in_scope |= in_scope;
    }

    fn into_node(self, name: String, path: String) -> SiteNode {
        let mut children: Vec<SiteNode> = self
            .children
            .into_iter()
            .map(|(child, branch)| {
                let child_path = format!("{path}/{child}");
                branch.into_node(child, child_path)
            })
            .collect();
        children.sort_by_cached_key(|node| node.name.to_lowercase());
        SiteNode {
            name,
            path,
            requests: self.requests,
            flow_id: self.latest.map(|(id, _)| id),
            status: self.latest.and_then(|(_, status)| status),
            in_scope: self.in_scope,
            children,
        }
    }
}

/// The folders and page a request target names. The query is not part of the
/// page, and `/a/` is the same place as `/a`.
fn segments(target: &str) -> Vec<&str> {
    let path = target.split(['?', '#']).next().unwrap_or("");
    let Some(path) = path.strip_prefix('/') else {
        return Vec::new();
    };
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() {
        return Vec::new();
    }
    path.splitn(MAX_DEPTH, '/').collect()
}

pub fn build(rows: Vec<SiteRow>, scope: &Scope) -> Vec<SiteTree> {
    let mut hosts: BTreeMap<(String, u16, bool), Branch> = BTreeMap::new();
    for row in &rows {
        let in_scope = scope.allows(&row.target.host, &row.path);
        let key = (row.target.host.clone(), row.target.port, row.target.tls);
        let mut branch = hosts.entry(key).or_default();
        branch.count(row, in_scope);
        for segment in segments(&row.path) {
            branch = branch.children.entry(segment.to_string()).or_default();
            branch.count(row, in_scope);
        }
        if branch.latest.is_none_or(|(id, _)| id < row.latest_id) {
            branch.latest = Some((row.latest_id, row.status));
        }
    }
    hosts
        .into_iter()
        .map(|((host, port, tls), branch)| SiteTree {
            target: Target { host, port, tls },
            root: branch.into_node(String::new(), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeRule;

    fn target(host: &str) -> Target {
        Target {
            host: host.into(),
            port: 443,
            tls: true,
        }
    }

    fn row(host: &str, path: &str, status: u16, latest_id: u64) -> SiteRow {
        SiteRow {
            target: target(host),
            path: path.into(),
            status: Some(status),
            requests: 1,
            latest_id,
        }
    }

    fn child<'a>(node: &'a SiteNode, name: &str) -> &'a SiteNode {
        node.children.iter().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn paths_become_folders_with_counts_all_the_way_up() {
        let trees = build(
            vec![row("a.test", "/v1/orders/5", 200, 1), row("a.test", "/v1/orders/6", 200, 2), row("a.test", "/v1/users", 200, 3)],
            &Scope::default(),
        );
        let root = &trees[0].root;
        assert_eq!(root.requests, 3);
        let v1 = child(root, "v1");
        assert_eq!((v1.path.as_str(), v1.requests), ("/v1", 3));
        let orders = child(v1, "orders");
        assert_eq!(orders.requests, 2);
        assert_eq!(child(orders, "6").path, "/v1/orders/6");
        assert_eq!(orders.flow_id, None, "nothing asked for the folder itself");
    }

    #[test]
    fn queries_and_trailing_slashes_are_the_same_page() {
        let trees = build(
            vec![row("a.test", "/p?x=1", 200, 1), row("a.test", "/p?x=2", 500, 2), row("a.test", "/p/", 404, 3)],
            &Scope::default(),
        );
        let root = &trees[0].root;
        assert_eq!(root.children.len(), 1);
        let page = child(root, "p");
        assert_eq!(page.requests, 3);
        assert_eq!((page.flow_id, page.status), (Some(3), Some(404)), "latest request wins");
    }

    #[test]
    fn the_host_root_is_its_own_page() {
        let trees = build(vec![row("a.test", "/", 200, 9), row("a.test", "/?x=1", 302, 4)], &Scope::default());
        let root = &trees[0].root;
        assert!(root.children.is_empty());
        assert_eq!((root.path.as_str(), root.flow_id, root.status), ("", Some(9), Some(200)));
    }

    #[test]
    fn hosts_are_kept_apart_by_port_and_scheme() {
        let mut plain = row("a.test", "/", 200, 1);
        plain.target = Target {
            host: "a.test".into(),
            port: 80,
            tls: false,
        };
        let trees = build(vec![row("b.test", "/", 200, 3), row("a.test", "/", 200, 2), plain], &Scope::default());
        let order: Vec<_> = trees.iter().map(|t| (t.target.host.as_str(), t.target.port)).collect();
        assert_eq!(order, [("a.test", 80), ("a.test", 443), ("b.test", 443)]);
    }

    #[test]
    fn children_sort_without_regard_to_case() {
        let trees = build(vec![row("a.test", "/b", 200, 1), row("a.test", "/C", 200, 2), row("a.test", "/A", 200, 3)], &Scope::default());
        let names: Vec<_> = trees[0].root.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["A", "b", "C"]);
    }

    #[test]
    fn a_folder_is_in_scope_if_anything_below_it_is() {
        let scope = Scope {
            include: vec![ScopeRule {
                host: "a.test".into(),
                path_prefix: "/app/in".into(),
            }],
            exclude: vec![],
        };
        let trees = build(vec![row("a.test", "/app/in", 200, 1), row("a.test", "/app/out", 200, 2), row("b.test", "/", 200, 3)], &scope);
        let app = child(&trees[0].root, "app");
        assert!(app.in_scope);
        assert!(child(app, "in").in_scope);
        assert!(!child(app, "out").in_scope);
        assert!(!trees[1].root.in_scope);
    }

    #[test]
    fn nesting_is_limited() {
        let deep = "/a".repeat(MAX_DEPTH * 3);
        let trees = build(vec![row("a.test", &deep, 200, 1)], &Scope::default());
        let (mut node, mut depth) = (&trees[0].root, 0);
        while let Some(next) = node.children.first() {
            node = next;
            depth += 1;
        }
        assert_eq!(depth, MAX_DEPTH);
        assert_eq!(node.path, deep, "the last node still names the whole path");
    }

    #[test]
    fn targets_that_are_not_paths_stay_on_the_host() {
        let trees = build(vec![row("a.test", "*", 200, 1)], &Scope::default());
        assert!(trees[0].root.children.is_empty());
        assert_eq!(trees[0].root.flow_id, Some(1));
    }
}
