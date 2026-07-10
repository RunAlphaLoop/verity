//! ReBAC client seam (SPEC §7a, roadmap task 10): SpiceDB over its HTTP
//! gateway.
//!
//! Client choice, recorded: there is no maintained official Rust client —
//! crates.io `authzed` is a 0.0.1 placeholder from 2021; `spicedb-rust` /
//! `spicedb-grpc` / `spicedb-client` are community crates, stale for 18+
//! months, and each drags a pinned tonic/prost/protoc stack into the build.
//! SpiceDB is never on the read hot path (SPEC §7b: zero live authz calls on
//! `recall`/`get`; we call it only at `open_scope`, on the admin group plane,
//! and for the restricted-class recheck), so gRPC throughput is not
//! load-bearing in v0.1. The HTTP gateway (`spicedb serve --http-enabled`,
//! port 8443) with the already-in-workspace `reqwest` is the smallest honest
//! client; this module is the thin seam SPEC §7a demands, so a later swap to
//! tonic is a local change.
//!
//! Tenancy: every SpiceDB object id is prefixed with the tenant uuid —
//! `group:<tenant>_<name>` / `user:<tenant>_<name>` — so relationship graphs
//! can never cross tenants even inside one shared SpiceDB. Principal names
//! (emails, group slugs) may contain characters outside SpiceDB's object-id
//! alphabet, so the name part is escaped: bytes outside `[A-Za-z0-9_-]`
//! become `=XX` (uppercase hex; `=` itself is `=3D`), which is injective and
//! stays inside SpiceDB's accepted charset (verified against authzed/spicedb).
//!
//! Schema (written at startup if absent):
//! ```text
//! definition user {}
//! definition group {
//!     relation member: user | group#member
//!     permission membership = member
//! }
//! ```
//! `membership` resolves nested groups transitively via `group#member`
//! subjects; `LookupResources(group#membership, subject)` therefore returns
//! the full transitive closure in one call.

use serde_json::{json, Value};
use verity_core::types::TenantId;

pub(crate) const SCHEMA: &str = "definition user {}\n\ndefinition group {\n\trelation member: user | group#member\n\tpermission membership = member\n}";

/// A parsed principal string: `user:<name>` or `group:<name>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrincipalKind {
    User,
    Group,
}

impl PrincipalKind {
    fn object_type(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }
}

/// Split `"user:alice@corp"` / `"group:sales"` into (kind, name). Anything
/// else is rejected — fail closed, never guess a namespace.
pub(crate) fn parse_principal(s: &str) -> Option<(PrincipalKind, &str)> {
    if let Some(name) = s.strip_prefix("user:") {
        if !name.is_empty() {
            return Some((PrincipalKind::User, name));
        }
    }
    if let Some(name) = s.strip_prefix("group:") {
        if !name.is_empty() {
            return Some((PrincipalKind::Group, name));
        }
    }
    None
}

/// Escape a principal name into SpiceDB's object-id alphabet. Injective:
/// `[A-Za-z0-9_-]` passes through, every other byte becomes `=XX`.
pub(crate) fn escape_id(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => out.push(b as char),
            other => out.push_str(&format!("={other:02X}")),
        }
    }
    out
}

/// Inverse of [`escape_id`]. Returns None on malformed escapes or invalid
/// UTF-8 (fail closed — a foreign object id resolves to nothing).
pub(crate) fn unescape_id(esc: &str) -> Option<String> {
    let bytes = esc.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Tenant-prefixed SpiceDB object id for a principal name.
fn object_id(tenant: TenantId, name: &str) -> String {
    format!("{tenant}_{}", escape_id(name))
}

/// Recover the principal name from a tenant-prefixed object id; None if the
/// id belongs to a different tenant or is malformed.
fn parse_object_id(tenant: TenantId, oid: &str) -> Option<String> {
    let rest = oid.strip_prefix(&format!("{tenant}_"))?;
    unescape_id(rest)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RebacError {
    #[error("spicedb transport error: {0}")]
    Transport(String),
    #[error("spicedb returned {status}: {body}")]
    Api { status: u16, body: String },
    #[error("spicedb response malformed: {0}")]
    Malformed(String),
}

type RebacResult<T> = std::result::Result<T, RebacError>;

/// SpiceDB client over the HTTP gateway. Present iff `VERITY_SPICEDB_URL` is
/// set; absent = ReBAC disabled (dev mode, caller-supplied principals).
pub(crate) struct Rebac {
    http: reqwest::Client,
    base: String,
    key: String,
}

impl Rebac {
    /// `VERITY_SPICEDB_URL` (e.g. `http://localhost:8443`) enables ReBAC;
    /// `VERITY_SPICEDB_KEY` is the preshared key (default `verity-dev-key`,
    /// matching deploy/docker-compose.yml, with a warning).
    pub(crate) fn from_env() -> Option<Self> {
        let base = std::env::var("VERITY_SPICEDB_URL").ok()?;
        let key = match std::env::var("VERITY_SPICEDB_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                tracing::warn!(
                    "VERITY_SPICEDB_KEY not set: using dev preshared key 'verity-dev-key'"
                );
                "verity-dev-key".to_string()
            }
        };
        Some(Self::new(&base, &key))
    }

    pub(crate) fn new(base: &str, key: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_string(),
            key: key.to_string(),
        }
    }

    /// POST a unary gateway call; returns the JSON body.
    async fn post(&self, path: &str, body: Value) -> RebacResult<Value> {
        let text = self.post_text(path, body).await?;
        serde_json::from_str(&text).map_err(|e| RebacError::Malformed(e.to_string()))
    }

    /// POST a (possibly server-streaming) gateway call; returns the `result`
    /// object of each NDJSON line. Any in-stream `error` line fails the call.
    async fn post_stream(&self, path: &str, body: Value) -> RebacResult<Vec<Value>> {
        let text = self.post_text(path, body).await?;
        let mut results = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: Value = serde_json::from_str(line)
                .map_err(|e| RebacError::Malformed(format!("bad stream line: {e}")))?;
            if let Some(err) = v.get("error") {
                return Err(RebacError::Api {
                    status: 200,
                    body: err.to_string(),
                });
            }
            match v.get("result") {
                Some(r) => results.push(r.clone()),
                None => return Err(RebacError::Malformed(format!("no result in line: {v}"))),
            }
        }
        Ok(results)
    }

    async fn post_text(&self, path: &str, body: Value) -> RebacResult<String> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.key)
            .json(&body)
            .send()
            .await
            .map_err(|e| RebacError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| RebacError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(RebacError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        Ok(text)
    }

    /// Startup: write the Verity schema if SpiceDB has none (or one missing
    /// our definitions). An unreachable/failing SpiceDB is a startup error —
    /// a deployment that configured ReBAC never runs without it (SPEC §7a).
    pub(crate) async fn ensure_schema(&self) -> RebacResult<()> {
        let existing = self.post("/v1/schema/read", json!({})).await;
        match existing {
            Ok(v) => {
                let text = v["schemaText"].as_str().unwrap_or_default();
                if text.contains("definition group") && text.contains("definition user") {
                    tracing::info!("spicedb schema present");
                    return Ok(());
                }
            }
            // "no schema written" surfaces as a NotFound-class API error;
            // transport errors must still fail startup.
            Err(RebacError::Api { .. }) => {}
            Err(e) => return Err(e),
        }
        self.post("/v1/schema/write", json!({ "schema": SCHEMA }))
            .await?;
        tracing::info!("spicedb schema written");
        Ok(())
    }

    fn membership_update(
        &self,
        op: &str,
        tenant: TenantId,
        group_name: &str,
        member_kind: PrincipalKind,
        member_name: &str,
    ) -> Value {
        let mut subject = json!({
            "object": {
                "objectType": member_kind.object_type(),
                "objectId": object_id(tenant, member_name),
            }
        });
        if member_kind == PrincipalKind::Group {
            // Nested groups join via their member set: `group#member`.
            subject["optionalRelation"] = json!("member");
        }
        json!({
            "updates": [{
                "operation": op,
                "relationship": {
                    "resource": { "objectType": "group", "objectId": object_id(tenant, group_name) },
                    "relation": "member",
                    "subject": subject,
                }
            }]
        })
    }

    /// Write (touch — idempotent) a membership tuple.
    pub(crate) async fn write_membership(
        &self,
        tenant: TenantId,
        group_name: &str,
        member_kind: PrincipalKind,
        member_name: &str,
    ) -> RebacResult<()> {
        let body = self.membership_update(
            "OPERATION_TOUCH",
            tenant,
            group_name,
            member_kind,
            member_name,
        );
        self.post("/v1/relationships/write", body).await?;
        Ok(())
    }

    /// Delete a membership tuple.
    pub(crate) async fn delete_membership(
        &self,
        tenant: TenantId,
        group_name: &str,
        member_kind: PrincipalKind,
        member_name: &str,
    ) -> RebacResult<()> {
        let body = self.membership_update(
            "OPERATION_DELETE",
            tenant,
            group_name,
            member_kind,
            member_name,
        );
        self.post("/v1/relationships/write", body).await?;
        Ok(())
    }

    /// Erasure support (SPEC §8b + task 28): delete every relationship whose
    /// SUBJECT is this user — in the Verity schema a `user` object never
    /// appears as a resource (it has no relations), so removing its subject
    /// tuples removes the user from the graph entirely. Called by the
    /// erasure handler BEFORE the storage purge (fail-closed ordering:
    /// a failure here aborts the erasure with 502 — tuples must never
    /// outlive the data they granted access to).
    pub(crate) async fn delete_subject_relationships(
        &self,
        tenant: TenantId,
        user_name: &str,
    ) -> RebacResult<()> {
        self.post(
            "/v1/relationships/delete",
            json!({
                "relationshipFilter": {
                    "resourceType": "group",
                    "optionalRelation": "member",
                    "optionalSubjectFilter": {
                        "subjectType": "user",
                        "optionalSubjectId": object_id(tenant, user_name),
                    }
                }
            }),
        )
        .await?;
        Ok(())
    }

    /// All groups the subject transitively has `membership` on, as
    /// `group:<name>` principal strings. Fully-consistent LookupResources.
    ///
    /// For a user subject this is the identity-resolution closure; for a
    /// `group#member` subject it is the group itself plus every ancestor —
    /// exactly the principal set lost when that group's members are removed.
    async fn membership_closure(
        &self,
        tenant: TenantId,
        subject_kind: PrincipalKind,
        subject_name: &str,
    ) -> RebacResult<Vec<String>> {
        let mut subject = json!({
            "object": {
                "objectType": subject_kind.object_type(),
                "objectId": object_id(tenant, subject_name),
            }
        });
        if subject_kind == PrincipalKind::Group {
            subject["optionalRelation"] = json!("member");
        }
        let results = self
            .post_stream(
                "/v1/permissions/resources",
                json!({
                    "consistency": { "fullyConsistent": true },
                    "resourceObjectType": "group",
                    "permission": "membership",
                    "subject": subject,
                }),
            )
            .await?;
        let mut groups = Vec::with_capacity(results.len());
        for r in results {
            let oid = r["resourceObjectId"]
                .as_str()
                .ok_or_else(|| RebacError::Malformed("missing resourceObjectId".into()))?;
            // Defense in depth: ids from other tenants (impossible by
            // construction) resolve to nothing rather than mis-filing.
            if let Some(name) = parse_object_id(tenant, oid) {
                groups.push(format!("group:{name}"));
            }
        }
        groups.sort();
        groups.dedup();
        Ok(groups)
    }

    /// Identity resolution for `open_scope`: the user's transitive group set.
    pub(crate) async fn user_groups(
        &self,
        tenant: TenantId,
        user_name: &str,
    ) -> RebacResult<Vec<String>> {
        self.membership_closure(tenant, PrincipalKind::User, user_name)
            .await
    }

    /// The group principals lost when members are removed from `group_name`:
    /// the group itself plus all transitive ancestors.
    pub(crate) async fn group_and_ancestors(
        &self,
        tenant: TenantId,
        group_name: &str,
    ) -> RebacResult<Vec<String>> {
        let mut set = self
            .membership_closure(tenant, PrincipalKind::Group, group_name)
            .await?;
        let own = format!("group:{group_name}");
        if !set.contains(&own) {
            set.push(own);
        }
        Ok(set)
    }

    /// All users transitively members of a group, as `user:<name>` principal
    /// strings (LookupSubjects). Used to record which member subtree a
    /// revocation covers.
    pub(crate) async fn group_users(
        &self,
        tenant: TenantId,
        group_name: &str,
    ) -> RebacResult<Vec<String>> {
        let results = self
            .post_stream(
                "/v1/permissions/subjects",
                json!({
                    "consistency": { "fullyConsistent": true },
                    "resource": { "objectType": "group", "objectId": object_id(tenant, group_name) },
                    "permission": "membership",
                    "subjectObjectType": "user",
                }),
            )
            .await?;
        let mut users = Vec::with_capacity(results.len());
        for r in results {
            let oid = r["subject"]["subjectObjectId"]
                .as_str()
                .or_else(|| r["subjectObjectId"].as_str())
                .ok_or_else(|| RebacError::Malformed("missing subjectObjectId".into()))?;
            if let Some(name) = parse_object_id(tenant, oid) {
                users.push(format!("user:{name}"));
            }
        }
        users.sort();
        users.dedup();
        Ok(users)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_parsing_is_strict() {
        assert_eq!(
            parse_principal("user:alice@corp.example"),
            Some((PrincipalKind::User, "alice@corp.example"))
        );
        assert_eq!(
            parse_principal("group:sales"),
            Some((PrincipalKind::Group, "sales"))
        );
        assert_eq!(parse_principal("user:"), None);
        assert_eq!(parse_principal("group:"), None);
        assert_eq!(parse_principal("robot:r2d2"), None);
        assert_eq!(parse_principal("alice@corp.example"), None);
    }

    #[test]
    fn escape_roundtrips_and_stays_in_alphabet() {
        for raw in [
            "alice@corp.example",
            "sales",
            "a=b=c",
            "space name",
            "uniçode-héllo",
            "trailing=",
            "=",
            "under_score-dash",
        ] {
            let esc = escape_id(raw);
            assert!(
                esc.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'='),
                "escaped {esc:?} leaves SpiceDB alphabet"
            );
            assert_eq!(unescape_id(&esc).as_deref(), Some(raw), "roundtrip {raw:?}");
        }
        // Injectivity at the classic collision points.
        assert_ne!(escape_id("a=40b"), escape_id("a@b"));
        // Malformed escapes fail closed.
        assert_eq!(unescape_id("=G1"), None);
        assert_eq!(unescape_id("abc="), None);
    }

    #[test]
    fn object_ids_are_tenant_prefixed_and_parse_back() {
        let t = uuid::Uuid::now_v7();
        let other = uuid::Uuid::now_v7();
        let oid = object_id(t, "alice@corp.example");
        assert!(oid.starts_with(&format!("{t}_")));
        assert_eq!(
            parse_object_id(t, &oid).as_deref(),
            Some("alice@corp.example")
        );
        // A foreign tenant's id resolves to nothing (fail closed).
        assert_eq!(parse_object_id(other, &oid), None);
    }

    /// Gated on VERITY_SPICEDB_URL (skips when absent, like VERITY_TEST_DSN):
    /// schema write is idempotent; nested membership resolves transitively;
    /// delete shrinks the closure.
    #[tokio::test]
    async fn spicedb_schema_and_transitive_membership() {
        let Some(rebac) = Rebac::from_env() else {
            eprintln!("VERITY_SPICEDB_URL not set; skipping");
            return;
        };
        rebac.ensure_schema().await.expect("schema");
        rebac.ensure_schema().await.expect("schema is idempotent");

        let tenant = uuid::Uuid::now_v7();
        // group:sales <- group:sales-west#member <- user:alice@corp.example
        rebac
            .write_membership(tenant, "sales", PrincipalKind::Group, "sales-west")
            .await
            .expect("nest group");
        rebac
            .write_membership(
                tenant,
                "sales-west",
                PrincipalKind::User,
                "alice@corp.example",
            )
            .await
            .expect("add user");

        let groups = rebac
            .user_groups(tenant, "alice@corp.example")
            .await
            .expect("resolve");
        assert_eq!(
            groups,
            vec!["group:sales".to_string(), "group:sales-west".to_string()],
            "transitive closure includes the outer group"
        );

        // The revocation set for sales-west is itself + its ancestor.
        let lost = rebac
            .group_and_ancestors(tenant, "sales-west")
            .await
            .expect("ancestors");
        assert_eq!(
            lost,
            vec!["group:sales".to_string(), "group:sales-west".to_string()]
        );

        // Member subtree of the outer group reaches the nested user.
        let users = rebac.group_users(tenant, "sales").await.expect("subjects");
        assert_eq!(users, vec!["user:alice@corp.example".to_string()]);

        // Another tenant sees nothing (tenant-prefixed object ids).
        let foreign = rebac
            .user_groups(uuid::Uuid::now_v7(), "alice@corp.example")
            .await
            .expect("foreign resolve");
        assert!(foreign.is_empty());

        // Delete the nested-group edge: alice keeps sales-west, loses sales.
        rebac
            .delete_membership(tenant, "sales", PrincipalKind::Group, "sales-west")
            .await
            .expect("delete");
        let groups = rebac
            .user_groups(tenant, "alice@corp.example")
            .await
            .expect("re-resolve");
        assert_eq!(groups, vec!["group:sales-west".to_string()]);

        // Erasure seam (task 28): deleting the subject's tuples empties the
        // closure — the user object is gone from the graph.
        rebac
            .delete_subject_relationships(tenant, "alice@corp.example")
            .await
            .expect("subject tuple delete");
        let groups = rebac
            .user_groups(tenant, "alice@corp.example")
            .await
            .expect("post-erasure resolve");
        assert!(
            groups.is_empty(),
            "subject tuples must be gone after erasure: {groups:?}"
        );
    }
}
