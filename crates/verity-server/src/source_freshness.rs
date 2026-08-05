//! Per-source freshness gate (HONESTY.md "Two different fail-closed
//! guarantees"): recall refuses hits whose SOURCE CONNECTOR has not
//! heartbeated within a staleness bound, instead of silently serving rows
//! whose ACLs are as stale as the stall is long.
//!
//! Mechanics mirror [`crate::revocation::RevocationPlane`]: one bounded query
//! per tenant per 5s, memoized in a moka cache, applied in-memory on the read
//! path — zero LLM calls, zero live ReBAC, no per-read DB round-trip beyond
//! the 5s-TTL refresh. The signal is `connector_status.updated_at` — the last
//! successful heartbeat instant (idle cycles beat too, see the Python sinks) —
//! NOT `last_event_at` (a quiet source with a live connector is fresh).
//!
//! The gate is OPT-IN and OFF by default (`VERITY_SOURCE_FRESHNESS_MAX_SECS`
//! unset — deliberate: dropping hits on heartbeat evidence is only honest once
//! the connectors actually beat on idle cycles, so the operator turns it on).
//! A request can also opt in per-call (`max_source_staleness_secs`); when both
//! are set the STRICTER (smaller) bound wins. Whether or not the gate is on,
//! every recall hit is annotated with its source's last heartbeat
//! (`source_synced_at`) so callers can judge freshness themselves.
//!
//! The verdict rule, fail-closed where it matters:
//!   * `agent`, `webhook:*`, `folder:*` — exempt (server-local write paths
//!     with no polling connector to stall; a heartbeat would be fiction).
//!   * heartbeat row within the bound — fresh, passes, annotated.
//!   * heartbeat row beyond the bound — stale, DROPPED.
//!   * no row and the source is a known chunk-writing connector
//!     ([`CONNECTOR_CHUNK_SOURCES`]) — DROPPED (cold-start rule: a
//!     never-heartbeated connector is indistinguishable from a stalled one).
//!   * no row and not in the registry — exempt (ad-hoc sources ingested via
//!     the direct document APIs have no connector to beat; fencing them would
//!     silently blank whole tenants).

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use verity_core::types::{RecallHit, TenantId};

use crate::{internal, HandlerResult};

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Every connector source that writes CHUNKS (the recall corpus): the
/// content/crm/support families of [`crate::connectors_admin::SOURCES`] plus
/// `sharepoint` (a real chunk-writing connector that has no console tile yet).
/// Directory connectors (`gdirectory`, `entra`) write principals, not chunks,
/// and the local `folder` aggregate heartbeats per-watch as `folder:<name>` —
/// none of them belong here. A unit test below guards this list against
/// registry drift.
pub(crate) const CONNECTOR_CHUNK_SOURCES: [&str; 9] = [
    "gdrive",
    "gmail",
    "hubspot",
    "salesforce",
    "notion",
    "intercom",
    "sharepoint",
    "slack",
    "zoom",
];

/// Per-tenant map: source → last heartbeat (`connector_status.updated_at`).
type SyncedMap = HashMap<String, DateTime<Utc>>;

pub(crate) struct SourceFreshnessPlane {
    /// Per-tenant heartbeat map, memoized 5s (same cadence + bound as the
    /// revocation tombstone cache: one indexed query per tenant per 5s).
    cache: moka::sync::Cache<TenantId, Arc<SyncedMap>>,
    /// Server-wide staleness bound (seconds). `None` = gate OFF (default).
    max_secs: Option<u64>,
}

impl SourceFreshnessPlane {
    pub(crate) fn new(max_secs: Option<u64>) -> Self {
        Self {
            cache: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(CACHE_TTL)
                .build(),
            max_secs,
        }
    }

    /// `VERITY_SOURCE_FRESHNESS_MAX_SECS`: unset (or set empty) = OFF —
    /// deliberate; see the module docs. A SET-but-unparseable value is a HARD
    /// startup error (main.rs convention for configured-but-unusable planes,
    /// e.g. SpiceDB and the media store): an operator who believes they turned
    /// the gate on must never silently run ungated.
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let raw = std::env::var("VERITY_SOURCE_FRESHNESS_MAX_SECS").ok();
        Ok(Self::new(parse_max_secs_env(raw.as_deref())?))
    }

    /// The bound this recall runs under: the stricter (smaller) of the
    /// caller's `max_source_staleness_secs` and the server env bound; `None`
    /// (gate off) only when NEITHER is set.
    pub(crate) fn effective_max_secs(&self, requested: Option<u64>) -> Option<u64> {
        match (requested, self.max_secs) {
            (Some(r), Some(e)) => Some(r.min(e)),
            (r, e) => r.or(e),
        }
    }

    /// The tenant's source → last-heartbeat map, memoized 5s. One bounded
    /// indexed query (`connector_status` is one row per (tenant, source)).
    pub(crate) async fn synced_map(
        &self,
        pool: &PgPool,
        tenant: TenantId,
    ) -> HandlerResult<Arc<SyncedMap>> {
        if let Some(hit) = self.cache.get(&tenant) {
            return Ok(hit);
        }
        let rows =
            sqlx::query("SELECT source, updated_at FROM connector_status WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_all(pool)
                .await
                .map_err(internal)?;
        let map: Arc<SyncedMap> = Arc::new(
            rows.iter()
                .map(|r| {
                    (
                        r.get::<String, _>("source"),
                        r.get::<DateTime<Utc>, _>("updated_at"),
                    )
                })
                .collect(),
        );
        self.cache.insert(tenant, Arc::clone(&map));
        Ok(map)
    }
}

/// Parse the raw `VERITY_SOURCE_FRESHNESS_MAX_SECS` value. Unset or empty =
/// gate off (`Ok(None)`); anything else must be a whole number of seconds or
/// startup is refused — never a silent fall-through to "off".
fn parse_max_secs_env(raw: Option<&str>) -> anyhow::Result<Option<u64>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) => v.parse::<u64>().map(Some).map_err(|e| {
            anyhow::anyhow!(
                "VERITY_SOURCE_FRESHNESS_MAX_SECS={v:?} is not a whole number of seconds ({e}); \
                 fix the value, or unset it to run with the freshness gate off"
            )
        }),
    }
}

/// The pure per-source verdict. See the module docs for the rule table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Not connector-owned (agent / webhook:* / folder:* / ad-hoc): passes,
    /// no timestamp to annotate.
    Exempt,
    /// Heartbeated within the bound: passes, annotated.
    Fresh(DateTime<Utc>),
    /// Heartbeated beyond the bound: dropped.
    Stale(DateTime<Utc>),
    /// Known chunk-writing connector with NO heartbeat row: dropped
    /// (cold-start rule — never-synced is indistinguishable from stalled).
    NeverSynced,
}

impl Verdict {
    pub(crate) fn passes(&self) -> bool {
        matches!(self, Verdict::Exempt | Verdict::Fresh(_))
    }
}

/// Classify one hit source against the tenant's heartbeat map. Pure: `now`
/// and the map are injected so tests need no clock or DB.
pub(crate) fn verdict(
    source: &str,
    synced_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    max_secs: u64,
) -> Verdict {
    if source == "agent" || source.starts_with("webhook:") || source.starts_with("folder:") {
        return Verdict::Exempt;
    }
    match synced_at {
        Some(at) if now.signed_duration_since(at).num_seconds() <= max_secs as i64 => {
            Verdict::Fresh(at)
        }
        Some(at) => Verdict::Stale(at),
        None if CONNECTOR_CHUNK_SOURCES.contains(&source) => Verdict::NeverSynced,
        None => Verdict::Exempt,
    }
}

/// What the recall handler applies after storage returns.
pub(crate) struct GateOutcome {
    pub(crate) hits: Vec<RecallHit>,
    /// Hits removed by the fence (NOT over-fetch truncation).
    pub(crate) dropped: usize,
    /// Distinct offending sources (stale or never-synced), sorted.
    pub(crate) stale_sources: Vec<String>,
}

/// Annotate every hit's `source_synced_at` from the heartbeat map
/// (UNCONDITIONALLY — gate on or off), then, when the gate is active
/// (`max_secs` set), drop hits whose verdict fails and truncate the survivors
/// to the caller's original `k` (the handler over-fetched).
pub(crate) fn annotate_and_gate(
    mut hits: Vec<RecallHit>,
    synced: &SyncedMap,
    max_secs: Option<u64>,
    now: DateTime<Utc>,
    k: usize,
) -> GateOutcome {
    for hit in &mut hits {
        hit.source_synced_at = synced.get(&hit.source).copied();
    }
    let Some(max) = max_secs else {
        return GateOutcome {
            hits,
            dropped: 0,
            stale_sources: Vec::new(),
        };
    };
    let mut stale_sources: Vec<String> = Vec::new();
    let before = hits.len();
    hits.retain(|hit| {
        if verdict(&hit.source, synced.get(&hit.source).copied(), now, max).passes() {
            true
        } else {
            if !stale_sources.contains(&hit.source) {
                stale_sources.push(hit.source.clone());
            }
            false
        }
    });
    let dropped = before - hits.len();
    hits.truncate(k);
    stale_sources.sort();
    GateOutcome {
        hits,
        dropped,
        stale_sources,
    }
}

/// `X-Verity-Source-Fence` header value: `dropped=<n>; stale=<sources>`.
///
/// Source names are sanitized to header-safe characters so the value ALWAYS
/// builds a valid HTTP header — a drop must never go unreported because a
/// source name carried a control byte, a non-ASCII character, or one of the
/// value's own `,` / `;` separators.
pub(crate) fn fence_header_value(dropped: usize, stale_sources: &[String]) -> String {
    let sanitized: Vec<String> = stale_sources
        .iter()
        .map(|s| sanitize_header_token(s))
        .collect();
    format!("dropped={dropped}; stale={}", sanitized.join(","))
}

/// Replace every character that is not visible ASCII — or that would collide
/// with the fence value's own `,` / `;` separators — with `_`.
fn sanitize_header_token(source: &str) -> String {
    source
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != ',' && c != ';' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use uuid::Uuid;
    use verity_core::types::{AclProvenance, TrustTier};

    fn hit(source: &str) -> RecallHit {
        RecallHit {
            chunk_id: Uuid::now_v7(),
            source: source.into(),
            source_synced_at: None,
            document_id: format!("doc-{source}"),
            seq: 0,
            content: "body".into(),
            score: 1.0,
            entity_tags: vec![],
            kind: "content".into(),
            support_tier: None,
            acl_provenance: AclProvenance::Mirrored,
            trust_tier: TrustTier::Observation,
            valid_from: Utc::now(),
            provenance: Uuid::nil(),
        }
    }

    // ---- drift guard ----

    /// Every console-registry connector that writes chunks (content/crm/
    /// support kinds) MUST be in CONNECTOR_CHUNK_SOURCES — adding a connector
    /// tile without teaching the gate would silently EXEMPT it from the
    /// cold-start rule (fail-open). Directory/local kinds must stay out.
    #[test]
    fn chunk_sources_track_the_connector_registry() {
        for spec in crate::connectors_admin::SOURCES.iter() {
            match spec.kind {
                "content" | "crm" | "support" => assert!(
                    CONNECTOR_CHUNK_SOURCES.contains(&spec.source),
                    "registry source {:?} (kind {:?}) missing from CONNECTOR_CHUNK_SOURCES — \
                     the freshness gate would fail OPEN for it",
                    spec.source,
                    spec.kind,
                ),
                "directory" | "local" => assert!(
                    !CONNECTOR_CHUNK_SOURCES.contains(&spec.source),
                    "registry source {:?} (kind {:?}) writes no chunks and must not be fenced",
                    spec.source,
                    spec.kind,
                ),
                other => panic!("unknown registry kind {other:?} — teach the freshness gate"),
            }
        }
    }

    // ---- hermetic verdict rules ----

    #[test]
    fn exempt_sources_pass_without_timestamps() {
        let now = Utc::now();
        assert_eq!(verdict("agent", None, now, 60), Verdict::Exempt);
        assert_eq!(verdict("webhook:crm", None, now, 60), Verdict::Exempt);
        assert_eq!(verdict("folder:notes", None, now, 60), Verdict::Exempt);
        // Exemption wins even over a (hypothetical) stale heartbeat row.
        assert_eq!(
            verdict("agent", Some(now - Duration::hours(2)), now, 60),
            Verdict::Exempt
        );
        // Ad-hoc sources outside the connector registry are exempt too.
        assert_eq!(verdict("my-custom-import", None, now, 60), Verdict::Exempt);
    }

    #[test]
    fn fresh_and_stale_split_on_the_bound() {
        let now = Utc::now();
        let fresh_at = now - Duration::seconds(30);
        let stale_at = now - Duration::seconds(301);
        assert_eq!(
            verdict("gdrive", Some(fresh_at), now, 300),
            Verdict::Fresh(fresh_at)
        );
        assert_eq!(
            verdict("gdrive", Some(stale_at), now, 300),
            Verdict::Stale(stale_at)
        );
        // A heartbeat row fences even a source OUTSIDE the registry.
        assert_eq!(
            verdict("entra", Some(stale_at), now, 300),
            Verdict::Stale(stale_at)
        );
    }

    #[test]
    fn never_synced_registry_connector_fails_closed() {
        let now = Utc::now();
        for source in CONNECTOR_CHUNK_SOURCES {
            assert_eq!(
                verdict(source, None, now, 300),
                Verdict::NeverSynced,
                "{source} without a heartbeat row must drop when the gate is on"
            );
        }
    }

    #[test]
    fn env_bound_unset_or_empty_is_off_but_garbage_refuses_startup() {
        assert_eq!(parse_max_secs_env(None).unwrap(), None);
        assert_eq!(parse_max_secs_env(Some("")).unwrap(), None);
        assert_eq!(parse_max_secs_env(Some("  ")).unwrap(), None);
        assert_eq!(parse_max_secs_env(Some("300")).unwrap(), Some(300));
        assert_eq!(parse_max_secs_env(Some(" 300 ")).unwrap(), Some(300));
        // A SET-but-unparseable bound must never silently disable the gate:
        // it is a hard config error (startup refuses).
        for garbage in ["5m", "-1", "3.5", "on", "1e3"] {
            let err = parse_max_secs_env(Some(garbage)).unwrap_err().to_string();
            assert!(
                err.contains("VERITY_SOURCE_FRESHNESS_MAX_SECS"),
                "error must name the env var: {err}"
            );
        }
    }

    #[test]
    fn fence_header_value_sanitizes_unsafe_source_names() {
        // A source name with control bytes / non-ASCII / the value's own
        // separators must still yield a valid, parseable header value — the
        // drop is NEVER silently unreported.
        let sources = vec![
            "gdrive".to_string(),
            "evil\r\nX-Injected: 1".to_string(),
            "naïve source;a,b".to_string(),
        ];
        let value = fence_header_value(3, &sources);
        assert_eq!(
            value,
            "dropped=3; stale=gdrive,evil__X-Injected:_1,na_ve_source_a_b"
        );
        assert!(
            value.parse::<axum::http::HeaderValue>().is_ok(),
            "sanitized fence value must always be header-safe"
        );
    }

    #[test]
    fn effective_bound_is_the_stricter_of_request_and_env() {
        let off = SourceFreshnessPlane::new(None);
        assert_eq!(off.effective_max_secs(None), None);
        assert_eq!(off.effective_max_secs(Some(60)), Some(60));
        let on = SourceFreshnessPlane::new(Some(300));
        assert_eq!(on.effective_max_secs(None), Some(300));
        assert_eq!(on.effective_max_secs(Some(60)), Some(60));
        assert_eq!(on.effective_max_secs(Some(900)), Some(300));
    }

    #[test]
    fn gate_off_annotates_but_never_drops() {
        let now = Utc::now();
        let stale_at = now - Duration::hours(3);
        let synced: SyncedMap = [("gdrive".to_string(), stale_at)].into();
        let out = annotate_and_gate(vec![hit("gdrive"), hit("agent")], &synced, None, now, 8);
        assert_eq!(out.hits.len(), 2);
        assert_eq!(out.dropped, 0);
        assert!(out.stale_sources.is_empty());
        assert_eq!(out.hits[0].source_synced_at, Some(stale_at), "annotated");
        assert_eq!(out.hits[1].source_synced_at, None);
    }

    #[test]
    fn gate_drops_dedupes_sources_and_truncates_to_k() {
        let now = Utc::now();
        let stale_at = now - Duration::hours(1);
        let fresh_at = now - Duration::seconds(5);
        let synced: SyncedMap = [
            ("gdrive".to_string(), stale_at),
            ("hubspot".to_string(), fresh_at),
        ]
        .into();
        let hits = vec![
            hit("gdrive"),
            hit("gmail"), // never-synced registry connector
            hit("gdrive"),
            hit("hubspot"),
            hit("agent"),
            hit("hubspot"),
        ];
        let out = annotate_and_gate(hits, &synced, Some(300), now, 2);
        assert_eq!(out.dropped, 3, "two stale gdrive + one never-synced gmail");
        assert_eq!(
            out.stale_sources,
            vec!["gdrive".to_string(), "gmail".to_string()]
        );
        assert_eq!(out.hits.len(), 2, "survivors truncated to k");
        assert!(out
            .hits
            .iter()
            .all(|h| h.source != "gdrive" && h.source != "gmail"));
        assert_eq!(
            fence_header_value(out.dropped, &out.stale_sources),
            "dropped=3; stale=gdrive,gmail"
        );
    }

    // ---- DSN-gated leak tests (VERITY_TEST_DSN; pattern of connectors.rs /
    // revocation.rs — real connector_status rows through the real loader) ----

    async fn test_pool() -> Option<(PgPool, TenantId)> {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return None;
        };
        use verity_core::adapter::StorageAdapter;
        let pg = verity_storage::PostgresAdapter::connect(&dsn)
            .await
            .expect("connect");
        pg.migrate().await.expect("migrate");
        let tenant = pg
            .create_tenant(&format!("freshness-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant");
        Some((pg.pool().clone(), tenant))
    }

    async fn beat(pool: &PgPool, tenant: TenantId, source: &str, age_secs: i64) {
        crate::connectors::record_heartbeat(
            pool,
            &crate::connectors::HeartbeatRequest {
                tenant_id: tenant,
                source: source.into(),
                cursor: None,
                items_synced: 0,
                last_event_at: None,
            },
        )
        .await
        .expect("heartbeat");
        // Age the row: updated_at is server-stamped now(), so rewind it.
        sqlx::query(
            "UPDATE connector_status SET updated_at = now() - make_interval(secs => $3)
             WHERE tenant_id = $1 AND source = $2",
        )
        .bind(tenant)
        .bind(source)
        .bind(age_secs as f64)
        .execute(pool)
        .await
        .expect("age heartbeat");
    }

    /// LEAK TEST: a source whose connector stalled (last heartbeat an hour
    /// ago) is DROPPED when the gate is on, and the drop is disclosed in the
    /// X-Verity-Source-Fence header value.
    #[tokio::test]
    async fn stalled_source_is_dropped_with_header() {
        let Some((pool, tenant)) = test_pool().await else {
            return;
        };
        beat(&pool, tenant, "gdrive", 3600).await;
        let plane = SourceFreshnessPlane::new(Some(300));
        let synced = plane.synced_map(&pool, tenant).await.expect("map");
        let out = annotate_and_gate(vec![hit("gdrive")], &synced, Some(300), Utc::now(), 8);
        assert!(out.hits.is_empty(), "stalled gdrive hit must not serve");
        assert_eq!(out.dropped, 1);
        assert_eq!(
            fence_header_value(out.dropped, &out.stale_sources),
            "dropped=1; stale=gdrive"
        );
    }

    /// agent + webhook:* chunks have no connector to stall: they pass the
    /// active gate, unannotated.
    #[tokio::test]
    async fn agent_and_webhook_hits_are_exempt() {
        let Some((pool, tenant)) = test_pool().await else {
            return;
        };
        let plane = SourceFreshnessPlane::new(Some(300));
        let synced = plane.synced_map(&pool, tenant).await.expect("map");
        let out = annotate_and_gate(
            vec![hit("agent"), hit("webhook:crm")],
            &synced,
            Some(300),
            Utc::now(),
            8,
        );
        assert_eq!(out.hits.len(), 2);
        assert_eq!(out.dropped, 0);
        assert!(out.hits.iter().all(|h| h.source_synced_at.is_none()));
    }

    /// COLD-START rule: a registry connector that has NEVER heartbeated is
    /// indistinguishable from a stalled one — its hits drop.
    #[tokio::test]
    async fn never_heartbeated_gdrive_is_dropped() {
        let Some((pool, tenant)) = test_pool().await else {
            return;
        };
        let plane = SourceFreshnessPlane::new(Some(300));
        let synced = plane.synced_map(&pool, tenant).await.expect("map");
        assert!(synced.get("gdrive").is_none(), "fresh tenant: no row");
        let out = annotate_and_gate(vec![hit("gdrive")], &synced, Some(300), Utc::now(), 8);
        assert!(out.hits.is_empty());
        assert_eq!(out.stale_sources, vec!["gdrive".to_string()]);
    }

    /// A freshly-heartbeated source passes the active gate WITH its
    /// synced-at annotation.
    #[tokio::test]
    async fn fresh_source_passes_annotated() {
        let Some((pool, tenant)) = test_pool().await else {
            return;
        };
        beat(&pool, tenant, "hubspot", 10).await;
        let plane = SourceFreshnessPlane::new(Some(300));
        let synced = plane.synced_map(&pool, tenant).await.expect("map");
        let out = annotate_and_gate(vec![hit("hubspot")], &synced, Some(300), Utc::now(), 8);
        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.dropped, 0);
        let at = out.hits[0].source_synced_at.expect("annotated");
        assert!(Utc::now().signed_duration_since(at).num_seconds() < 60);
    }

    /// CONTROL: gate off (no env, no request bound) — the stale hit still
    /// serves, but carries its honest (stale) synced-at annotation.
    #[tokio::test]
    async fn gate_off_serves_stale_hit_annotated() {
        let Some((pool, tenant)) = test_pool().await else {
            return;
        };
        beat(&pool, tenant, "gdrive", 3600).await;
        let plane = SourceFreshnessPlane::new(None);
        assert_eq!(plane.effective_max_secs(None), None, "gate off");
        let synced = plane.synced_map(&pool, tenant).await.expect("map");
        let out = annotate_and_gate(vec![hit("gdrive")], &synced, None, Utc::now(), 8);
        assert_eq!(out.hits.len(), 1, "gate off: nothing dropped");
        assert_eq!(out.dropped, 0);
        let at = out.hits[0].source_synced_at.expect("still annotated");
        assert!(
            Utc::now().signed_duration_since(at).num_seconds() >= 3000,
            "annotation discloses the staleness"
        );
    }
}
