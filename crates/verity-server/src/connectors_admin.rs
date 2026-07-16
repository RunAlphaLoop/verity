//! Connect-a-source read plane, Phase 1 (per-source readiness for the console).
//!
//! Two admin-gated GETs assemble ONE honest row per source family from what
//! the running server can truthfully observe: prereq probes (the exact checks
//! the workers' `SpawnError` preconditions use, probed without spawning),
//! worker-plane status in the same two authority tiers as `/v1/admin/planes`
//! (server-authoritative for owned children, "observed" for heartbeat-derived),
//! and the per-source `connector_status` heartbeat. Phase 1 ships ZERO
//! secret-handling and ZERO backfill triggering: there is no credential input,
//! no new POST, and every `backfill.available` is `false` with the honest
//! phase note in `hint`. CRM credential state is unknowable server-side (the
//! tokens live in the connector CLI's env on whatever machine runs it), so it
//! is reported `"untracked"`, never guessed.
//!
//! The registry / prereq-assembly / verdict layer is pure (probe results are
//! injected), so the honesty rules are pinned by hermetic unit tests below.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::{connectors, directory_worker, internal, AppState, HandlerResult};

// ---------------------------------------------------------------------------
// Source registry — the six source families Phase 1 lists.
// ---------------------------------------------------------------------------

/// One source family the console can (eventually) connect. `kind` is the
/// closed vocabulary {content, directory, crm, local} the panel groups by.
pub(crate) struct SourceSpec {
    pub(crate) source: &'static str,
    pub(crate) label: &'static str,
    pub(crate) kind: &'static str,
}

/// Fixed registry, alphabetical-ish by affinity: the zero-credential local
/// path first, then content, directory, CRM. `folder` is the aggregate of
/// every `folder:<name>` watch (the server IS that worker, in-process).
pub(crate) const SOURCES: [SourceSpec; 6] = [
    SourceSpec {
        source: "folder",
        label: "Local folders",
        kind: "local",
    },
    SourceSpec {
        source: "gdrive",
        label: "Google Drive",
        kind: "content",
    },
    SourceSpec {
        source: "gmail",
        label: "Gmail",
        kind: "content",
    },
    SourceSpec {
        source: "gdirectory",
        label: "Google Workspace directory",
        kind: "directory",
    },
    SourceSpec {
        source: "hubspot",
        label: "HubSpot",
        kind: "crm",
    },
    SourceSpec {
        source: "salesforce",
        label: "Salesforce",
        kind: "crm",
    },
];

/// Registry lookup for the per-source prereqs read. `None` = unknown source
/// (→ 404, fail closed — never a fabricated row).
pub(crate) fn source_spec(source: &str) -> Option<&'static SourceSpec> {
    SOURCES.iter().find(|s| s.source == source)
}

// ---------------------------------------------------------------------------
// Probe snapshot — everything the server can TRUTHFULLY observe, captured once
// per request so the pure assembly below is testable with injected values.
// ---------------------------------------------------------------------------

/// Server-observable prerequisite facts. Every field is an existence /
/// non-empty check — the server never reads credential contents (same posture
/// as the workers' spawn preconditions), so "present" never claims "valid".
pub(crate) struct ProbeSnapshot {
    /// `--repo` / `VERITY_REPO`, display form. `None` = the server can't find
    /// the ingest checkout at all.
    pub(crate) repo: Option<String>,
    /// `<repo>/ingest/.venv/bin/python` exists — the exact
    /// `SpawnError::NoVenv` precondition both workers check.
    pub(crate) venv: bool,
    /// `GOOGLE_APPLICATION_CREDENTIALS` is set on the SERVER. Directory plane
    /// only — gdrive/gmail read that var from their own CLI env, which the
    /// server cannot see (never cross-reported here).
    pub(crate) sa_key_configured: bool,
    /// ...and the file it points at exists on disk (path check only).
    pub(crate) sa_key_on_disk: bool,
    /// `VERITY_GDIRECTORY_SUBJECT` is set and non-empty.
    pub(crate) subject: bool,
}

impl ProbeSnapshot {
    /// Capture from live state. Reuses the workers' own non-attempting probes
    /// (`venv_exists` / `sa_key_ready` / `subject_ready`) so this read and a
    /// real spawn can never disagree about a precondition.
    fn capture(state: &AppState) -> Self {
        let repo = state.repo_root.as_deref();
        Self {
            repo: repo.map(|p| p.display().to_string()),
            venv: directory_worker::venv_exists(repo),
            sa_key_configured: state.directory.sa_key.is_some(),
            sa_key_on_disk: directory_worker::sa_key_ready(state.directory.sa_key.as_deref()),
            subject: directory_worker::subject_ready(state.directory.subject.as_deref()),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure assembly: prereqs, credential, worker verdict, backfill note, the row.
// ---------------------------------------------------------------------------

/// One prereq row: `hint` is the observation when ok, the exact copyable fix
/// when not (same wording as the planes `start_hint`s / `SpawnError`s).
fn probe(name: &str, ok: bool, hint: String) -> serde_json::Value {
    serde_json::json!({ "name": name, "ok": ok, "hint": hint })
}

/// The prereq probe list for one source — the same preconditions the workers'
/// `SpawnError` paths check, reported per-probe. `folder` has none (the watch
/// plane is Rust-native, in-process, zero-credential); the Python-CLI sources
/// need the ingest checkout + venv; gdirectory additionally needs the SA key
/// path and DWD subject on the SERVER. CRM credentials are deliberately NOT a
/// probe: they live in the connector CLI's env and are unobservable here.
pub(crate) fn prereqs_for(source: &str, p: &ProbeSnapshot) -> Vec<serde_json::Value> {
    let repo_probe = probe(
        "ingest_repo",
        p.repo.is_some(),
        match &p.repo {
            Some(repo) => format!("ingest checkout at {repo}"),
            None => "start the server with --repo <path> (or VERITY_REPO) so it can find \
                     ingest/.venv"
                .to_string(),
        },
    );
    let venv_probe = probe(
        "ingest_venv",
        p.venv,
        match (&p.repo, p.venv) {
            (Some(repo), true) => format!("{repo}/ingest/.venv/bin/python exists"),
            (Some(repo), false) => format!(
                "no ingest virtualenv at {repo}/ingest/.venv/bin/python — create it (cd ingest \
                 && python -m venv .venv && .venv/bin/pip install -e '.[gdrive]')"
            ),
            (None, _) => "needs the ingest repo first (--repo / VERITY_REPO)".to_string(),
        },
    );
    match source {
        // Rust-native, in-process, zero-credential — nothing external to probe.
        "folder" => vec![],
        "gdirectory" => {
            let sa_key_probe = probe(
                "google_sa_key",
                p.sa_key_on_disk,
                if p.sa_key_on_disk {
                    "service-account key path set and present on disk (contents never read — \
                     present does not mean valid)"
                        .to_string()
                } else if p.sa_key_configured {
                    "GOOGLE_APPLICATION_CREDENTIALS is set but no file exists at that path — \
                     fix the path on the server"
                        .to_string()
                } else {
                    "set GOOGLE_APPLICATION_CREDENTIALS on the server to your Workspace SA JSON \
                     (domain-wide delegation, scopes admin.directory.user.readonly + \
                     admin.directory.group.readonly)"
                        .to_string()
                },
            );
            let subject_probe = probe(
                "directory_subject",
                p.subject,
                if p.subject {
                    "VERITY_GDIRECTORY_SUBJECT is set".to_string()
                } else {
                    "set VERITY_GDIRECTORY_SUBJECT to a Workspace admin to impersonate".to_string()
                },
            );
            vec![repo_probe, venv_probe, sa_key_probe, subject_probe]
        }
        // gdrive/gmail/hubspot/salesforce run as external CLIs out of the
        // ingest checkout; their credentials live in THAT env — unprobeable.
        _ => vec![repo_probe, venv_probe],
    }
}

/// Truthfully-observable credential state. The server never guesses:
/// - `"not-required"` — folder watches are zero-credential;
/// - `"untracked"` — gdrive/gmail/hubspot/salesforce credentials live in the
///   connector CLI's env, invisible to the server;
/// - gdirectory is the one source whose credential the SERVER holds (a path):
///   `"unset"` / `"path-missing"` / `"path-configured"` — path-level only,
///   never a validity claim.
pub(crate) fn credential_for(source: &str, p: &ProbeSnapshot) -> &'static str {
    match source {
        "folder" => "not-required",
        "gdirectory" => {
            if !p.sa_key_configured {
                "unset"
            } else if p.sa_key_on_disk {
                "path-configured"
            } else {
                "path-missing"
            }
        }
        _ => "untracked",
    }
}

/// Whether an owned live directory child is authoritative FOR THIS tenant.
/// The worker is tenant-scoped (spawned with `--tenant-id`), so a live child
/// owned for a DIFFERENT tenant is no evidence about the queried one — it
/// must fall through to the heartbeat tier, never claim ("on", "server") for
/// a tenant nothing is syncing.
pub(crate) fn gdirectory_owned_for(
    owned: Option<&directory_worker::OwnedWorker>,
    tenant_id: Uuid,
) -> bool {
    owned.is_some_and(|w| w.tenant_id == tenant_id)
}

/// The two-tier worker verdict `(status, authority)` from injected
/// observations — same honest vocabulary as `/v1/admin/planes`:
/// - an owned live child is the ONE authoritative "on";
/// - a heartbeat within 2 minutes is `"unknown"` (recent activity does NOT
///   prove a worker is running now — it may have just finished, or be running
///   elsewhere), never a fabricated "on";
/// - an older heartbeat is `"off"` (observed);
/// - no heartbeat row at all is `"off"` with authority `"none"` — nothing has
///   ever been observed for this source.
pub(crate) fn worker_verdict(
    owned_live: bool,
    last_heartbeat: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> (&'static str, &'static str) {
    if owned_live {
        return ("on", "server");
    }
    match last_heartbeat {
        Some(t) if now - t < chrono::Duration::minutes(2) => ("unknown", "observed"),
        Some(_) => ("off", "observed"),
        None => ("off", "none"),
    }
}

/// Folder verdict: the server holds the OS watches in-process, so this is
/// fully authoritative — "on" iff at least one active watch is armed RIGHT NOW.
pub(crate) fn folder_worker_verdict(armed: usize) -> (&'static str, &'static str) {
    (if armed > 0 { "on" } else { "off" }, "server")
}

/// The honest Phase-1 backfill note. `available` is `false` for EVERY source —
/// there is no backfill trigger in this phase — and the hint says exactly why
/// per source, so the panel never renders a dead button or a vague "soon".
pub(crate) fn backfill_hint(source: &str) -> &'static str {
    match source {
        "folder" => {
            "not applicable — folder watches ingest synchronously when added and catch up \
             on server boot"
        }
        "gdirectory" => {
            "not applicable — directory sync reconciles the full directory on every pass"
        }
        "salesforce" => {
            "backfill — not wired yet (Phase 3); awaiting a Salesforce test org (the \
             connector is fixtures-only so far)"
        }
        _ => {
            "backfill — not wired yet (Phase 3); run the connector CLI \
             (ingest/verity_ingest/connectors) to backfill for now"
        }
    }
}

/// Assemble one connector row from the pure pieces. `prereqs_ok` is derived
/// from the SAME probe rows the response carries, so the summary flag and the
/// detail list can never disagree.
pub(crate) fn connector_row(
    spec: &SourceSpec,
    p: &ProbeSnapshot,
    worker: (&str, &str),
    last_heartbeat: Option<DateTime<Utc>>,
) -> serde_json::Value {
    let prereqs = prereqs_for(spec.source, p);
    let prereqs_ok = prereqs.iter().all(|q| q["ok"] == true);
    serde_json::json!({
        "source": spec.source,
        "label": spec.label,
        "kind": spec.kind,
        "credential": credential_for(spec.source, p),
        "worker": { "status": worker.0, "authority": worker.1 },
        "last_heartbeat": last_heartbeat,
        "backfill": { "available": false, "hint": backfill_hint(spec.source) },
        "prereqs_ok": prereqs_ok,
        "prereqs": prereqs,
    })
}

// ---------------------------------------------------------------------------
// Handlers.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct ListParams {
    tenant_id: Uuid,
}

/// GET /v1/admin/connectors?tenant_id= (admin): one row per source family with
/// prereq probes, worker verdict, last heartbeat, and the Phase-1 backfill
/// note. An unknown-but-well-formed tenant simply has no heartbeats/watches
/// (empty observations, like the sibling admin GETs); a malformed tenant_id is
/// a 400 at extraction — never a 500.
pub(crate) async fn list_connectors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let probes = ProbeSnapshot::capture(&state);

    // Heartbeats: one query (the exact rows GET /v1/admin/connector-status
    // serves), split per source. Folder watches heartbeat under
    // `folder:<name>`, so the aggregate folder row takes the newest of them.
    let rows = connectors::list_status_rows(state.pool(), q.tenant_id)
        .await
        .map_err(internal)?;
    let mut heartbeats: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut folder_hb: Option<DateTime<Utc>> = None;
    for row in &rows {
        let Some(source) = row["source"].as_str() else {
            continue;
        };
        let Ok(updated) = serde_json::from_value::<DateTime<Utc>>(row["updated_at"].clone()) else {
            continue;
        };
        if source.starts_with("folder:") {
            folder_hb = Some(folder_hb.map_or(updated, |t| t.max(updated)));
        } else {
            heartbeats.insert(source.to_string(), updated);
        }
    }

    // Folder plane: the server owns the OS watches, so count how many of this
    // tenant's ACTIVE watch rows are armed in-process right now.
    let active_ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM folder_watches WHERE tenant_id = $1 AND active")
            .bind(q.tenant_id)
            .fetch_all(state.pool())
            .await
            .map_err(internal)?;
    let armed_ids = state.folder_watchers.armed_ids().await;
    let armed = active_ids
        .iter()
        .filter(|id| armed_ids.contains(id))
        .count();

    // gdirectory: authoritative only when THIS server owns a live child FOR
    // THE QUERIED TENANT. Probe/reap discipline is shared with the planes
    // read (`owned_live`): a dead child is reaped and cleared, never reported
    // as a stale "on"; a live child spawned for a different tenant falls
    // through to the heartbeat tier for this one.
    let gdirectory_owned =
        gdirectory_owned_for(state.directory.owned_live().await.as_ref(), q.tenant_id);

    let now = Utc::now();
    let connectors_json: Vec<serde_json::Value> = SOURCES
        .iter()
        .map(|spec| {
            let (hb, verdict) = match spec.source {
                "folder" => (folder_hb, folder_worker_verdict(armed)),
                s => {
                    let hb = heartbeats.get(s).copied();
                    (
                        hb,
                        worker_verdict(s == "gdirectory" && gdirectory_owned, hb, now),
                    )
                }
            };
            connector_row(spec, &probes, verdict, hb)
        })
        .collect();

    Ok(Json(serde_json::json!({
        "connectors": connectors_json,
        "checked_at": now.to_rfc3339(),
    })))
}

/// GET /v1/admin/connectors/{source}/prereqs?tenant_id= (admin): the detailed
/// prereq probe list for ONE source — the same probes the workers' spawn
/// preconditions check, reported without attempting a spawn. Unknown source →
/// 404 naming the valid set (fail closed, never a fabricated row). The probes
/// are process-level, but tenant_id stays required for posture parity with
/// every sibling admin read.
pub(crate) async fn source_prereqs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(source): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<ListParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let _ = q.tenant_id;
    let Some(spec) = source_spec(&source) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!(
                "unknown source '{source}' — expected one of folder, gdrive, gmail, \
                 gdirectory, hubspot, salesforce"
            ),
        ));
    };
    let probes = ProbeSnapshot::capture(&state);
    let prereqs = prereqs_for(spec.source, &probes);
    let prereqs_ok = prereqs.iter().all(|p| p["ok"] == true);
    Ok(Json(serde_json::json!({
        "source": spec.source,
        "label": spec.label,
        "kind": spec.kind,
        "prereqs_ok": prereqs_ok,
        "prereqs": prereqs,
        "checked_at": Utc::now().to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Hermetic tests — the pure layer only (registry, credential, verdicts,
// prereq assembly from injected probe results). No DB, no FS, no spawns.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A server started bare: no --repo, no venv, no directory config.
    fn bare() -> ProbeSnapshot {
        ProbeSnapshot {
            repo: None,
            venv: false,
            sa_key_configured: false,
            sa_key_on_disk: false,
            subject: false,
        }
    }

    /// Every server-observable prereq present.
    fn full() -> ProbeSnapshot {
        ProbeSnapshot {
            repo: Some("/srv/verity".to_string()),
            venv: true,
            sa_key_configured: true,
            sa_key_on_disk: true,
            subject: true,
        }
    }

    #[test]
    fn registry_lists_the_six_sources_with_their_kinds() {
        let got: Vec<(&str, &str)> = SOURCES.iter().map(|s| (s.source, s.kind)).collect();
        assert_eq!(
            got,
            vec![
                ("folder", "local"),
                ("gdrive", "content"),
                ("gmail", "content"),
                ("gdirectory", "directory"),
                ("hubspot", "crm"),
                ("salesforce", "crm"),
            ]
        );
        assert_eq!(source_spec("hubspot").expect("known").label, "HubSpot");
        // Fail closed: an unknown source resolves to nothing, never a row.
        assert!(source_spec("notion").is_none());
        assert!(source_spec("folder:notes").is_none());
    }

    #[test]
    fn credential_is_never_guessed() {
        let p = bare();
        assert_eq!(credential_for("folder", &p), "not-required");
        // CRM + Drive/Gmail creds live in the connector CLI's env — the server
        // reports "untracked" regardless of any local state.
        for s in ["gdrive", "gmail", "hubspot", "salesforce"] {
            assert_eq!(credential_for(s, &p), "untracked");
            assert_eq!(credential_for(s, &full()), "untracked");
        }
        // gdirectory: the one path the server holds, reported path-level only.
        assert_eq!(credential_for("gdirectory", &bare()), "unset");
        assert_eq!(credential_for("gdirectory", &full()), "path-configured");
        let dangling = ProbeSnapshot {
            sa_key_configured: true,
            sa_key_on_disk: false,
            ..bare()
        };
        assert_eq!(credential_for("gdirectory", &dangling), "path-missing");
    }

    #[test]
    fn worker_verdict_never_fabricates_on_from_a_heartbeat() {
        let now = Utc::now();
        // Owned live child: the ONE authoritative "on".
        assert_eq!(worker_verdict(true, None, now), ("on", "server"));
        // Recent heartbeat proves recent activity, not a running worker.
        let recent = Some(now - chrono::Duration::seconds(30));
        assert_eq!(worker_verdict(false, recent, now), ("unknown", "observed"));
        // Stale heartbeat: off, but we did observe it once.
        let stale = Some(now - chrono::Duration::hours(3));
        assert_eq!(worker_verdict(false, stale, now), ("off", "observed"));
        // Never seen: nothing observed at all.
        assert_eq!(worker_verdict(false, None, now), ("off", "none"));
    }

    #[test]
    fn owned_worker_for_another_tenant_never_claims_on() {
        let now = Utc::now();
        let owned = directory_worker::OwnedWorker {
            pid: 4242,
            started_at: now,
            tenant_id: Uuid::now_v7(),
        };
        let other_tenant = Uuid::now_v7();
        // The child is live but tenant-scoped: only ITS tenant gets the one
        // authoritative "on"; any other tenant falls through to the heartbeat
        // tier — never a fabricated ("on", "server") for a tenant nothing syncs.
        assert!(gdirectory_owned_for(Some(&owned), owned.tenant_id));
        assert!(!gdirectory_owned_for(Some(&owned), other_tenant));
        assert!(!gdirectory_owned_for(None, other_tenant));
        assert_eq!(
            worker_verdict(
                gdirectory_owned_for(Some(&owned), owned.tenant_id),
                None,
                now
            ),
            ("on", "server")
        );
        assert_eq!(
            worker_verdict(gdirectory_owned_for(Some(&owned), other_tenant), None, now),
            ("off", "none")
        );
        let recent = Some(now - chrono::Duration::seconds(30));
        assert_eq!(
            worker_verdict(
                gdirectory_owned_for(Some(&owned), other_tenant),
                recent,
                now
            ),
            ("unknown", "observed")
        );
    }

    #[test]
    fn folder_verdict_is_server_authoritative() {
        assert_eq!(folder_worker_verdict(0), ("off", "server"));
        assert_eq!(folder_worker_verdict(2), ("on", "server"));
    }

    #[test]
    fn prereqs_folder_is_zero_prereq_ready() {
        // Rust-native and zero-credential even on a bare server: an empty
        // probe list, so `connector_row` derives prereqs_ok = true.
        assert!(prereqs_for("folder", &bare()).is_empty());
        let row = connector_row(&SOURCES[0], &bare(), ("off", "server"), None);
        assert_eq!(row["prereqs_ok"], true);
    }

    #[test]
    fn prereqs_bare_server_fails_with_the_exact_repo_fix() {
        let list = prereqs_for("gdrive", &bare());
        assert_eq!(list.len(), 2, "repo + venv, nothing else probeable");
        assert_eq!(list[0]["name"], "ingest_repo");
        assert_eq!(list[0]["ok"], false);
        assert!(list[0]["hint"]
            .as_str()
            .expect("hint")
            .contains("--repo <path> (or VERITY_REPO)"));
        assert_eq!(list[1]["name"], "ingest_venv");
        assert_eq!(list[1]["ok"], false);
    }

    #[test]
    fn prereqs_venv_hint_carries_the_exact_path_and_fix() {
        let p = ProbeSnapshot {
            repo: Some("/srv/verity".to_string()),
            venv: false,
            ..bare()
        };
        let list = prereqs_for("gmail", &p);
        assert_eq!(list[0]["ok"], true);
        assert_eq!(list[1]["ok"], false);
        let hint = list[1]["hint"].as_str().expect("hint");
        assert!(hint.contains("/srv/verity/ingest/.venv/bin/python"));
        assert!(hint.contains("python -m venv .venv"));
    }

    #[test]
    fn prereqs_gdirectory_probes_key_and_subject_separately() {
        let p = ProbeSnapshot {
            sa_key_configured: true,
            sa_key_on_disk: false,
            subject: false,
            ..full()
        };
        let list = prereqs_for("gdirectory", &p);
        let names: Vec<&str> = list.iter().map(|q| q["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                "ingest_repo",
                "ingest_venv",
                "google_sa_key",
                "directory_subject"
            ]
        );
        assert_eq!(list[2]["ok"], false);
        assert!(list[2]["hint"]
            .as_str()
            .expect("hint")
            .contains("no file exists at that path"));
        assert_eq!(list[3]["ok"], false);
        assert!(list[3]["hint"]
            .as_str()
            .expect("hint")
            .contains("VERITY_GDIRECTORY_SUBJECT"));

        // All present: every probe ok, and even then the key hint says
        // presence is not validity (the server never reads the key).
        let ok_list = prereqs_for("gdirectory", &full());
        assert!(ok_list.iter().all(|q| q["ok"] == true));
        assert!(ok_list[2]["hint"]
            .as_str()
            .expect("hint")
            .contains("present does not mean valid"));
    }

    #[test]
    fn crm_prereqs_never_include_a_credential_probe() {
        // HubSpot/Salesforce tokens are unknowable server-side; probing them
        // would be a fabricated claim either way.
        for s in ["hubspot", "salesforce"] {
            let names: Vec<String> = prereqs_for(s, &full())
                .iter()
                .map(|q| q["name"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(names, vec!["ingest_repo", "ingest_venv"]);
        }
    }

    #[test]
    fn row_shape_and_the_honest_backfill_notes() {
        let now = Utc::now();
        for spec in SOURCES.iter() {
            let row = connector_row(spec, &full(), ("off", "none"), None);
            // The full Phase-1 row contract, per source.
            for key in [
                "source",
                "label",
                "kind",
                "credential",
                "worker",
                "last_heartbeat",
                "backfill",
                "prereqs_ok",
                "prereqs",
            ] {
                assert!(row.get(key).is_some(), "{} missing {key}", spec.source);
            }
            // Phase 1 ships zero backfill triggering — never an available:true.
            assert_eq!(row["backfill"]["available"], false);
            assert!(!row["backfill"]["hint"].as_str().expect("hint").is_empty());
        }
        // Salesforce carries the honest awaiting-test-org note.
        let sf = connector_row(&SOURCES[5], &full(), ("off", "none"), None);
        assert!(sf["backfill"]["hint"]
            .as_str()
            .expect("hint")
            .contains("awaiting a Salesforce test org"));
        // Heartbeat round-trips as rfc3339, null when never seen.
        let hb = connector_row(&SOURCES[4], &full(), ("off", "observed"), Some(now));
        assert_eq!(
            serde_json::from_value::<DateTime<Utc>>(hb["last_heartbeat"].clone())
                .expect("timestamp")
                .timestamp_millis(),
            now.timestamp_millis()
        );
        assert!(
            connector_row(&SOURCES[4], &full(), ("off", "none"), None)["last_heartbeat"].is_null()
        );
    }

    #[test]
    fn prereqs_ok_derives_from_the_same_rows_the_response_carries() {
        // gdirectory on a bare server: every probe fails ⇒ prereqs_ok false.
        let row = connector_row(&SOURCES[3], &bare(), ("off", "none"), None);
        assert_eq!(row["prereqs_ok"], false);
        assert!(row["prereqs"]
            .as_array()
            .expect("list")
            .iter()
            .all(|q| q["ok"] == false));
        // ...and fully-provisioned: all ok ⇒ prereqs_ok true.
        let row = connector_row(&SOURCES[3], &full(), ("off", "none"), None);
        assert_eq!(row["prereqs_ok"], true);
    }
}
