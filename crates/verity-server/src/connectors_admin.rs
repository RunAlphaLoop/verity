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

use crate::{
    connectors, directory_worker, internal, AppState, HandlerResult, Secret, SecretIntakeAuth,
};
use verity_core::adapter::StorageAdapter;
use verity_core::types::{ConnectorCredentialKind, ConnectorCredentialStatus, StorageError};

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
// Phase-2 credential intake — the pure classification / validation / precedence
// layer. Everything here is a total function over injected values so the
// honesty rules (tier split, fail-closed empty visibility, env-vs-UI
// precedence, Google subject requirement) are pinned by hermetic tests below,
// with zero DB / FS / env access.
// ---------------------------------------------------------------------------

/// Which credential shape a source takes. `TierC` sources (HubSpot/Salesforce)
/// paste an encrypted-at-rest bearer + a REQUIRED visibility set; `Google`
/// sources register a SA-key PATH (+ subject for the impersonating ones).
/// `folder` is zero-credential and refuses secret intake entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialClass {
    /// hubspot / salesforce — a pasted bearer, encrypted under the tenant DEK.
    TierC,
    /// gdrive / gmail / gdirectory — a SA-key path; gmail/gdirectory also need
    /// a `subject` (domain-wide-delegation impersonation).
    Google { subject_required: bool },
    /// folder — no credential is ever stored (fail closed: secret intake 422s).
    None,
}

/// Classify a source for credential intake. `None` for the local watch plane,
/// and — fail closed — for any unknown source (never a fabricated tier).
pub(crate) fn credential_class(source: &str) -> CredentialClass {
    match source {
        "hubspot" | "salesforce" => CredentialClass::TierC,
        "gdrive" => CredentialClass::Google {
            subject_required: false,
        },
        "gmail" | "gdirectory" => CredentialClass::Google {
            subject_required: true,
        },
        _ => CredentialClass::None,
    }
}

/// The server env var(s) that already supply a credential for this source. If
/// ANY is set (non-empty) at request time, a UI store REFUSES (409) rather than
/// silently shadowing/overriding the operator's env-provided credential
/// (env-vs-UI precedence — never a silent double-source-of-truth). Returned as
/// a static slice so the handler can name the offending var in the 409.
pub(crate) fn env_precedence_vars(source: &str) -> &'static [&'static str] {
    match source {
        "hubspot" => &["HUBSPOT_SERVICE_KEY", "HUBSPOT_PRIVATE_APP_TOKEN"],
        "salesforce" => &["SF_CLIENT_ID", "SF_CLIENT_SECRET"],
        "gdrive" | "gmail" | "gdirectory" => &["GOOGLE_APPLICATION_CREDENTIALS"],
        _ => &[],
    }
}

/// The first env-precedence var that is actually set (non-empty) for this
/// source, if any. `lookup` is injected so this is testable without touching
/// process env. `Some(var)` => a UI store must 409 and name `var`.
pub(crate) fn env_precedence_hit<'a>(
    source: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<&'a str> {
    env_precedence_vars(source)
        .iter()
        .copied()
        .find(|var| lookup(var).is_some_and(|v| !v.trim().is_empty()))
}

/// Validated tier-C intake: a non-empty bearer and a non-empty visibility set.
/// The token stays inside `Secret` (never copied to a plain String here) and
/// `expose()` is the single read point the caller hands to the encryptor.
#[derive(Debug)]
pub(crate) struct TierCIntake {
    pub(crate) token: Secret,
    pub(crate) visibility: Vec<i32>,
}

/// The tier-C request body: `{ token: Secret, visibility: [int] }`. The token
/// is a `Secret` so it auto-redacts in Debug/Display and zeroizes on drop; it
/// is never logged, never echoed. `visibility` is REQUIRED (no `serde(default)`)
/// — a missing field is a 422 at deserialization, and an empty list is a 422 in
/// validation (fail closed: memory nobody can read is never a permissive
/// default at the credential boundary).
#[derive(Deserialize)]
pub(crate) struct TierCCredentialBody {
    pub(crate) token: Secret,
    pub(crate) visibility: Vec<i32>,
}

/// Validate a tier-C body: the pasted token must be non-empty (after trim) and
/// the visibility set must be non-empty. Returns the (422, message) fail-closed
/// error verbatim so the handler stays a thin wrapper. Never formats the token.
pub(crate) fn validate_tier_c(body: TierCCredentialBody) -> Result<TierCIntake, String> {
    if body.token.expose().trim().is_empty() {
        return Err("token must not be empty".to_string());
    }
    if body.visibility.is_empty() {
        return Err(
            "visibility must be a non-empty set of principal tokens (fail-closed: an empty \
             visibility would store a credential no reader can act under)"
                .to_string(),
        );
    }
    Ok(TierCIntake {
        token: body.token,
        visibility: body.visibility,
    })
}

/// The Google request body: `{ path: String, subject: Option<String> }`. No
/// `Secret` — a SA-key PATH is not itself a secret (the key file it names is,
/// and that never enters the server). `subject` is required for gmail/gdirectory
/// (domain-wide-delegation impersonation) and ignored for gdrive.
#[derive(Deserialize)]
pub(crate) struct GoogleCredentialBody {
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) subject: Option<String>,
}

/// A validated Google SA-key path (canonicalized) plus optional subject.
#[derive(Debug)]
pub(crate) struct GoogleIntake {
    /// The canonicalized, usable path string that gets stored.
    pub(crate) path: String,
    pub(crate) subject: Option<String>,
}

/// Validate a Google intake WITHOUT reading the key file's contents. Enforces:
/// non-empty path; `subject` present + non-empty when `subject_required`;
/// canonicalize + a coarse usable-or-not check via the injected `canonicalize`
/// probe (real handler passes `std::fs::canonicalize` composed with an
/// is-file check) — never an arbitrary-path exists oracle: the only signal
/// surfaced is "the path you gave is not a readable file", identical for a
/// missing path and a directory. On success returns the canonical path string.
pub(crate) fn validate_google(
    body: GoogleCredentialBody,
    subject_required: bool,
    canonicalize: impl Fn(&str) -> Option<String>,
) -> Result<GoogleIntake, String> {
    let raw = body.path.trim();
    if raw.is_empty() {
        return Err("path must not be empty".to_string());
    }
    let subject = match (subject_required, body.subject) {
        (true, Some(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        (true, _) => {
            return Err(
                "subject is required for this source (domain-wide-delegation impersonation \
                 subject — a Workspace admin address)"
                    .to_string(),
            )
        }
        (false, s) => s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
    };
    let Some(canonical) = canonicalize(raw) else {
        return Err(
            "path is not a readable service-account key file on the server (contents are \
             never read — this checks only that the path resolves to a readable file)"
                .to_string(),
        );
    };
    Ok(GoogleIntake {
        path: canonical,
        subject,
    })
}

/// The structural (NOT live-auth) SA-JSON check for the Google test probe. Given
/// the raw file bytes, `Ok(())` iff it parses as JSON with non-empty
/// `client_email` and `private_key` fields — honestly labeled by the caller as a
/// structural check, not proof the key authenticates. Never logs the bytes.
pub(crate) fn structural_sa_json_check(bytes: &[u8]) -> Result<(), String> {
    let json: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "service-account key file is not valid JSON".to_string())?;
    let has = |k: &str| {
        json.get(k)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    };
    if !has("client_email") {
        return Err("service-account key JSON is missing a non-empty client_email".to_string());
    }
    if !has("private_key") {
        return Err("service-account key JSON is missing a non-empty private_key".to_string());
    }
    Ok(())
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

/// The `credential` field of a connector row. When a credential is stored for
/// this (tenant, source) — Phase 2's new state — it reports `"tracked"` with the
/// non-secret `{ kind, fingerprint }` from `get_connector_credential_status`,
/// flipping the Phase-1 `"untracked"`. Otherwise it is the Phase-1 truthful
/// no-stored-credential state from `credential_for` (`not-required` / `unset` /
/// `path-missing` / `path-configured` / `untracked`). The secret is NEVER here.
pub(crate) fn credential_field(
    source: &str,
    p: &ProbeSnapshot,
    stored: Option<&ConnectorCredentialStatus>,
) -> serde_json::Value {
    match stored {
        Some(s) => serde_json::json!({
            "state": "tracked",
            "kind": s.kind.as_str(),
            "fingerprint": s.fingerprint,
            "updated_at": s.updated_at,
        }),
        None => serde_json::json!({ "state": credential_for(source, p) }),
    }
}

/// Assemble one connector row from the pure pieces. `prereqs_ok` is derived
/// from the SAME probe rows the response carries, so the summary flag and the
/// detail list can never disagree. `stored` flips `credential` from the Phase-1
/// observed state to the tracked `{ kind, fingerprint }` when Phase 2 holds one.
pub(crate) fn connector_row(
    spec: &SourceSpec,
    p: &ProbeSnapshot,
    worker: (&str, &str),
    last_heartbeat: Option<DateTime<Utc>>,
    stored: Option<&ConnectorCredentialStatus>,
) -> serde_json::Value {
    let prereqs = prereqs_for(spec.source, p);
    let prereqs_ok = prereqs.iter().all(|q| q["ok"] == true);
    serde_json::json!({
        "source": spec.source,
        "label": spec.label,
        "kind": spec.kind,
        "credential": credential_field(spec.source, p, stored),
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

    // Phase-2 credential state: the non-secret stored status per source, so a
    // source with a stored credential reports `tracked { kind, fingerprint }`
    // instead of the Phase-1 `untracked`. One status lookup per source; folder
    // is zero-credential and never stores one, so it is skipped.
    let mut stored: HashMap<&'static str, ConnectorCredentialStatus> = HashMap::new();
    for spec in SOURCES.iter().filter(|s| s.source != "folder") {
        if let Some(status) = state
            .storage
            .get_connector_credential_status(q.tenant_id, spec.source)
            .await
            .map_err(internal)?
        {
            stored.insert(spec.source, status);
        }
    }

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
            connector_row(spec, &probes, verdict, hb, stored.get(spec.source))
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
    // Phase-2: the stored credential status (never the secret) so this detail
    // read also flips `untracked` → `tracked { kind, fingerprint }`. folder is
    // zero-credential and never stores one.
    let stored = if spec.source == "folder" {
        None
    } else {
        state
            .storage
            .get_connector_credential_status(q.tenant_id, spec.source)
            .await
            .map_err(internal)?
    };
    Ok(Json(serde_json::json!({
        "source": spec.source,
        "label": spec.label,
        "kind": spec.kind,
        "credential": credential_field(spec.source, &probes, stored.as_ref()),
        "prereqs_ok": prereqs_ok,
        "prereqs": prereqs,
        "checked_at": Utc::now().to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Phase-2 secret-intake handlers — POST credential, POST credential/test,
// DELETE credential. All three are gated by `SecretIntakeAuth` (Origin/CSRF +
// bearer with NO dev-open branch): the extractor argument makes the gate
// compiler-enforced and it runs BEFORE the JSON body is read.
// ---------------------------------------------------------------------------

/// Map the storage layer's write errors to HTTP. The KEK-unset /
/// plaintext-provenance DEK hard-refusals surface as `InvalidInput` → 422
/// (fail closed, honest message); an unknown tenant → 404; a genuine DB fault →
/// 500. Never leaks a secret (the storage layer never formats one).
fn credential_status(e: StorageError) -> (StatusCode, String) {
    match e {
        StorageError::UnknownTenant(_) => (StatusCode::NOT_FOUND, e.to_string()),
        StorageError::InvalidInput(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        StorageError::Database(_) => internal(e),
    }
}

/// Canonicalize + coarse usable check for a Google SA-key path: `Some(canonical)`
/// iff the path resolves to a readable regular file, else `None`. Deliberately
/// NOT an arbitrary-path exists oracle — a missing path and a directory both
/// return `None` with the identical caller-side message; the key file's CONTENTS
/// are never read here.
fn canonicalize_readable_file(raw: &str) -> Option<String> {
    let canonical = std::fs::canonicalize(raw).ok()?;
    let meta = std::fs::metadata(&canonical).ok()?;
    if !meta.is_file() {
        return None;
    }
    // Confirm readability without reading contents into a lasting buffer.
    std::fs::File::open(&canonical).ok()?;
    Some(canonical.to_string_lossy().into_owned())
}

/// The one shared HTTP client for the tier-C live test probe (short timeout so a
/// hung upstream can't wedge the admin surface).
fn probe_http_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client construction cannot fail with these options")
    })
}

/// The request body of the credential POST, source-branched at the handler. A
/// tier-C body deserializes to `TierCCredentialBody` (token is a `Secret`); a
/// Google body to `GoogleCredentialBody`. We take the raw JSON and dispatch on
/// the source's class so ONE route serves both shapes.
///
/// POST /v1/admin/connectors/{source}/credential — store a credential for one
/// source. Gated by `SecretIntakeAuth` (401 when `VERITY_ADMIN_TOKEN` unset —
/// no dev exception — + Origin/CSRF). Returns ONLY `{ fingerprint, kind }`,
/// never the token. 409 when a server env var already provides this source's
/// credential (env-vs-UI precedence). 404 for an unknown source; 422 for a
/// zero-credential source (folder), an empty visibility set, a missing subject,
/// or a KEK-unset/plaintext-DEK refusal.
pub(crate) async fn store_credential(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(source): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<ListParams>,
    _auth: SecretIntakeAuth,
    Json(body): Json<serde_json::Value>,
) -> HandlerResult<Json<serde_json::Value>> {
    let Some(spec) = source_spec(&source) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!(
                "unknown source '{source}' — expected one of gdrive, gmail, gdirectory, \
                 hubspot, salesforce (folder is zero-credential)"
            ),
        ));
    };
    // Unknown tenant → clean 404 (UnknownTenant), never a raw foreign-key
    // violation surfacing as a 500 from the credential INSERT. This mirrors
    // every other admin write handler.
    state
        .storage
        .inner()
        .ensure_tenant(q.tenant_id)
        .await
        .map_err(credential_status)?;
    // ENV-VS-UI precedence: refuse (409) if the server already supplies this
    // source's credential via env — never silently shadow the operator's config.
    if let Some(var) = env_precedence_hit(spec.source, |k| std::env::var(k).ok()) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "{var} already provides the {source} credential on this server — refusing to \
                 store a UI credential that would shadow it; unset {var} first, or revoke the \
                 env credential, to manage it here"
            ),
        ));
    }

    let (fingerprint, kind) = match credential_class(spec.source) {
        CredentialClass::None => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{source} is zero-credential — nothing to store"),
            ));
        }
        CredentialClass::TierC => {
            let body: TierCCredentialBody = serde_json::from_value(body).map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("invalid tier-C credential body: {e}"),
                )
            })?;
            let intake =
                validate_tier_c(body).map_err(|msg| (StatusCode::UNPROCESSABLE_ENTITY, msg))?;
            // The visibility set is validated here (fail-closed: empty refused)
            // as a forward-compat gate, but Phase 2 does NOT persist or enforce
            // it — the contract wires spawn scoping in Phase 3, which will
            // collect visibility at spawn time. It is intentionally NOT stored:
            // there is no visibility column on connector_credentials yet, and
            // asserting a sharing scope was applied when nothing is persisted
            // would be a false enforcement claim. The bearer is exposed EXACTLY
            // once, here, to the encryptor — never logged, never formatted.
            let _ = &intake.visibility;
            let fingerprint = state
                .storage
                .store_connector_bearer(q.tenant_id, spec.source, intake.token.expose().as_bytes())
                .await
                .map_err(credential_status)?;
            (fingerprint, ConnectorCredentialKind::Bearer)
        }
        CredentialClass::Google { subject_required } => {
            let body: GoogleCredentialBody = serde_json::from_value(body).map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("invalid Google credential body: {e}"),
                )
            })?;
            let intake = validate_google(body, subject_required, canonicalize_readable_file)
                .map_err(|msg| (StatusCode::UNPROCESSABLE_ENTITY, msg))?;
            let _ = &intake.subject;
            let fingerprint = state
                .storage
                .store_connector_path(q.tenant_id, spec.source, &intake.path)
                .await
                .map_err(credential_status)?;
            (fingerprint, ConnectorCredentialKind::Path)
        }
    };

    // Append-only audit: actor = admin surface, source + fingerprint only, NEVER
    // the secret. Reuses the shared audit-insert path.
    crate::audit::spawn_credential_audit(
        &state,
        q.tenant_id,
        "credential.create",
        spec.source,
        &fingerprint,
    );

    Ok(Json(serde_json::json!({
        "fingerprint": fingerprint,
        "kind": kind.as_str(),
    })))
}

/// POST /v1/admin/connectors/{source}/credential/test — probe a source's
/// credential. Gated by `SecretIntakeAuth`. tier-C: materialize the stored
/// bearer (or accept a just-typed `token` in the body) and do a LIVE HTTP GET to
/// HubSpot `/crm/v3/owners`, surfacing 401/403 inline as `{ ok:false, detail }`.
/// Google: a STRUCTURAL SA-JSON check of the stored/typed path (client_email +
/// private_key present) — honestly labeled NOT a live-auth test. Never logs the
/// secret. `{ ok, detail, kind }` where `kind` is `"live"` or `"structural"`.
pub(crate) async fn test_credential(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(source): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<ListParams>,
    _auth: SecretIntakeAuth,
    body: Option<Json<serde_json::Value>>,
) -> HandlerResult<Json<serde_json::Value>> {
    let Some(spec) = source_spec(&source) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!(
                "unknown source '{source}' — expected one of gdrive, gmail, gdirectory, \
                 hubspot, salesforce (folder is zero-credential)"
            ),
        ));
    };
    let body = body.map(|Json(v)| v).unwrap_or(serde_json::Value::Null);

    match credential_class(spec.source) {
        CredentialClass::None => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{source} is zero-credential — nothing to test"),
        )),
        CredentialClass::TierC => {
            // The live probe hits ONE vendor's API, so it is only correct for
            // the source whose token that endpoint accepts. HubSpot is the only
            // wired live probe; salesforce is fixtures-only, so NEVER transmit a
            // Salesforce token to HubSpot's servers — return an honest
            // not-yet-supported response instead (no secret materialized, no
            // credential-misdirection leak to an unrelated third party).
            if spec.source != "hubspot" {
                return Ok(Json(serde_json::json!({
                    "ok": false,
                    "kind": "unsupported",
                    "detail": "no live credential test is wired for this source yet — the \
                               connector is fixtures-only, and the token is never sent to \
                               another vendor's API to probe it",
                })));
            }
            // Prefer a just-typed token (wrapped in Secret so it redacts); else
            // materialize the stored bearer. Nothing to test if neither exists.
            let typed: Option<Secret> = body
                .get("token")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| Secret::new(s.to_string()));
            let token_bytes: Vec<u8> = if let Some(typed) = &typed {
                typed.expose().as_bytes().to_vec()
            } else {
                match state
                    .storage
                    .materialize_connector_bearer(q.tenant_id, spec.source)
                    .await
                    .map_err(credential_status)?
                {
                    Some(b) => b,
                    None => {
                        return Ok(Json(serde_json::json!({
                            "ok": false,
                            "kind": "live",
                            "detail": "no stored bearer for this source and none supplied to test",
                        })))
                    }
                }
            };
            // The bearer is exposed ONLY as an Authorization header value here.
            let bearer = String::from_utf8_lossy(&token_bytes).into_owned();
            let resp = probe_http_client()
                .get("https://api.hubapi.com/crm/v3/owners")
                .bearer_auth(&bearer)
                .send()
                .await;
            let out = match resp {
                Ok(r) => {
                    let code = r.status().as_u16();
                    let ok = r.status().is_success();
                    let detail = match code {
                        401 => "HubSpot rejected the bearer (401 unauthorized)".to_string(),
                        403 => "HubSpot accepted the bearer but it lacks scope (403 forbidden)"
                            .to_string(),
                        c if (200..300).contains(&c) => {
                            "HubSpot accepted the bearer (owners endpoint reachable)".to_string()
                        }
                        c => format!("HubSpot returned HTTP {c}"),
                    };
                    serde_json::json!({ "ok": ok, "kind": "live", "status": code, "detail": detail })
                }
                Err(e) => serde_json::json!({
                    "ok": false,
                    "kind": "live",
                    // reqwest's Display never includes the bearer; still, keep it terse.
                    "detail": format!("could not reach HubSpot: {}", e),
                }),
            };
            Ok(Json(out))
        }
        CredentialClass::Google { .. } => {
            // Resolve the path to check: a just-typed `path` in the body, else
            // the stored path status. We only have the STATUS (fingerprint), not
            // the stored path plaintext, so a structural check requires a typed
            // path OR the server's configured SA key path for gdirectory.
            let typed_path = body
                .get("path")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string());
            let path = match typed_path {
                Some(p) => Some(p),
                None => {
                    // Fall back to the server-configured SA key path (the one
                    // source whose path the server itself holds).
                    state
                        .directory
                        .sa_key
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                }
            };
            let Some(path) = path else {
                return Ok(Json(serde_json::json!({
                    "ok": false,
                    "kind": "structural",
                    "detail": "no SA-key path supplied to test (pass {\"path\": ...}); the stored \
                               path plaintext is never echoed back to test against",
                })));
            };
            let Some(canonical) = canonicalize_readable_file(&path) else {
                return Ok(Json(serde_json::json!({
                    "ok": false,
                    "kind": "structural",
                    "detail": "path is not a readable file on the server",
                })));
            };
            let bytes = match std::fs::read(&canonical) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(Json(serde_json::json!({
                        "ok": false,
                        "kind": "structural",
                        "detail": "could not read the SA-key file",
                    })))
                }
            };
            let out = match structural_sa_json_check(&bytes) {
                Ok(()) => serde_json::json!({
                    "ok": true,
                    "kind": "structural",
                    "detail": "SA-key JSON is structurally valid (client_email + private_key \
                               present) — this is NOT a live-auth test",
                }),
                Err(msg) => {
                    serde_json::json!({ "ok": false, "kind": "structural", "detail": msg })
                }
            };
            Ok(Json(out))
        }
    }
}

/// DELETE /v1/admin/connectors/{source}/credential — revoke a stored credential.
/// Gated by `SecretIntakeAuth`. Deletes the (tenant, source) row (credentials are
/// operator config, not memory — a hard delete does not violate
/// invalidate-don't-delete). `{ revoked: bool }`; `revoked:false` is the honest
/// no-op when nothing was stored. Audited (`credential.revoke`) only when a row
/// was actually removed. 404 for an unknown source.
pub(crate) async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(source): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<ListParams>,
    _auth: SecretIntakeAuth,
) -> HandlerResult<Json<serde_json::Value>> {
    let Some(spec) = source_spec(&source) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!(
                "unknown source '{source}' — expected one of gdrive, gmail, gdirectory, \
                 hubspot, salesforce (folder is zero-credential)"
            ),
        ));
    };
    // Unknown tenant → clean 404, for parity with the store path (a revoke
    // against a nonexistent tenant is a 404, not a 500).
    state
        .storage
        .inner()
        .ensure_tenant(q.tenant_id)
        .await
        .map_err(credential_status)?;
    let revoked = state
        .storage
        .revoke_connector_credential(q.tenant_id, spec.source)
        .await
        .map_err(credential_status)?;
    if revoked {
        crate::audit::spawn_credential_audit(
            &state,
            q.tenant_id,
            "credential.revoke",
            spec.source,
            "revoked",
        );
    }
    Ok(Json(serde_json::json!({ "revoked": revoked })))
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
        let row = connector_row(&SOURCES[0], &bare(), ("off", "server"), None, None);
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
            let row = connector_row(spec, &full(), ("off", "none"), None, None);
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
        let sf = connector_row(&SOURCES[5], &full(), ("off", "none"), None, None);
        assert!(sf["backfill"]["hint"]
            .as_str()
            .expect("hint")
            .contains("awaiting a Salesforce test org"));
        // Heartbeat round-trips as rfc3339, null when never seen.
        let hb = connector_row(&SOURCES[4], &full(), ("off", "observed"), Some(now), None);
        assert_eq!(
            serde_json::from_value::<DateTime<Utc>>(hb["last_heartbeat"].clone())
                .expect("timestamp")
                .timestamp_millis(),
            now.timestamp_millis()
        );
        assert!(
            connector_row(&SOURCES[4], &full(), ("off", "none"), None, None)["last_heartbeat"]
                .is_null()
        );
    }

    #[test]
    fn prereqs_ok_derives_from_the_same_rows_the_response_carries() {
        // gdirectory on a bare server: every probe fails ⇒ prereqs_ok false.
        let row = connector_row(&SOURCES[3], &bare(), ("off", "none"), None, None);
        assert_eq!(row["prereqs_ok"], false);
        assert!(row["prereqs"]
            .as_array()
            .expect("list")
            .iter()
            .all(|q| q["ok"] == false));
        // ...and fully-provisioned: all ok ⇒ prereqs_ok true.
        let row = connector_row(&SOURCES[3], &full(), ("off", "none"), None, None);
        assert_eq!(row["prereqs_ok"], true);
    }

    // -----------------------------------------------------------------------
    // Phase-2 secret-intake: the pure classification / validation / precedence
    // layer, pinned without any DB / FS / env / HTTP.
    // -----------------------------------------------------------------------

    /// Deserialize a tier-C body from JSON exactly as the handler does — so the
    /// REQUIRED-field contract (a missing `visibility` is a deser error, not a
    /// silent default) is exercised through serde, and the token lands in Secret.
    fn tier_c_body(json: serde_json::Value) -> Result<TierCCredentialBody, String> {
        serde_json::from_value(json).map_err(|e| e.to_string())
    }

    #[test]
    fn credential_class_splits_tiers_and_fails_closed_on_unknown() {
        assert_eq!(credential_class("hubspot"), CredentialClass::TierC);
        assert_eq!(credential_class("salesforce"), CredentialClass::TierC);
        assert_eq!(
            credential_class("gdrive"),
            CredentialClass::Google {
                subject_required: false
            }
        );
        for s in ["gmail", "gdirectory"] {
            assert_eq!(
                credential_class(s),
                CredentialClass::Google {
                    subject_required: true
                }
            );
        }
        // folder + any unknown source classify as None (no secret intake).
        assert_eq!(credential_class("folder"), CredentialClass::None);
        assert_eq!(credential_class("notion"), CredentialClass::None);
    }

    #[test]
    fn env_precedence_hit_names_the_offending_var() {
        // No env → no hit; a UI store is allowed.
        assert_eq!(env_precedence_hit("hubspot", |_| None), None);
        // HUBSPOT_SERVICE_KEY set → 409 naming it.
        assert_eq!(
            env_precedence_hit("hubspot", |k| (k == "HUBSPOT_SERVICE_KEY")
                .then(|| "sk".to_string())),
            Some("HUBSPOT_SERVICE_KEY")
        );
        // The legacy token also trips it.
        assert_eq!(
            env_precedence_hit("hubspot", |k| (k == "HUBSPOT_PRIVATE_APP_TOKEN")
                .then(|| "t".to_string())),
            Some("HUBSPOT_PRIVATE_APP_TOKEN")
        );
        // An empty/whitespace env value is NOT a credential — no precedence hit.
        assert_eq!(
            env_precedence_hit("hubspot", |k| (k == "HUBSPOT_SERVICE_KEY")
                .then(|| "   ".to_string())),
            None
        );
        // Google sources are gated by GOOGLE_APPLICATION_CREDENTIALS.
        for s in ["gdrive", "gmail", "gdirectory"] {
            assert_eq!(
                env_precedence_hit(s, |k| (k == "GOOGLE_APPLICATION_CREDENTIALS")
                    .then(|| "/k.json".to_string())),
                Some("GOOGLE_APPLICATION_CREDENTIALS")
            );
        }
        // Salesforce OAuth client vars.
        assert_eq!(
            env_precedence_hit("salesforce", |k| (k == "SF_CLIENT_ID")
                .then(|| "id".to_string())),
            Some("SF_CLIENT_ID")
        );
        // folder has no env credential at all.
        assert_eq!(
            env_precedence_hit("folder", |_| Some("anything".to_string())),
            None
        );
    }

    #[test]
    fn tier_c_visibility_is_required_and_empty_fails_closed() {
        // Missing visibility entirely → deserialization error (REQUIRED field).
        assert!(tier_c_body(serde_json::json!({ "token": "sk-abc" })).is_err());
        // Empty visibility parses but validation refuses it (fail closed).
        let body = tier_c_body(serde_json::json!({ "token": "sk-abc", "visibility": [] }))
            .expect("parses");
        let err = validate_tier_c(body).expect_err("empty visibility must refuse");
        assert!(err.contains("non-empty"));
        // Empty token → refused too.
        let body =
            tier_c_body(serde_json::json!({ "token": "  ", "visibility": [7] })).expect("parses");
        assert!(validate_tier_c(body).is_err());
        // A well-formed body validates, preserving the visibility set; the token
        // is carried in Secret (redacts when formatted — never the raw value).
        let body = tier_c_body(serde_json::json!({ "token": "sk-abc", "visibility": [3, 9] }))
            .expect("parses");
        let intake = validate_tier_c(body).expect("valid");
        assert_eq!(intake.visibility, vec![3, 9]);
        assert_eq!(format!("{}", intake.token), "***");
        assert_eq!(format!("{:?}", intake.token), "Secret(***)");
        assert_eq!(intake.token.expose(), "sk-abc");
    }

    #[test]
    fn google_subject_required_only_for_gmail_and_directory() {
        // A canonicalize probe that always reports the path usable, so we test
        // ONLY the subject/path validation branches (no real FS).
        let ok_path = |p: &str| Some(format!("/canon{p}"));

        // gdrive: no subject required; a missing subject is fine.
        let intake = validate_google(
            GoogleCredentialBody {
                path: "/k.json".to_string(),
                subject: None,
            },
            false,
            ok_path,
        )
        .expect("gdrive needs no subject");
        assert_eq!(intake.path, "/canon/k.json");
        assert_eq!(intake.subject, None);

        // gmail/gdirectory: a missing (or blank) subject is a hard refuse.
        for subject in [None, Some("   ".to_string())] {
            let err = validate_google(
                GoogleCredentialBody {
                    path: "/k.json".to_string(),
                    subject,
                },
                true,
                ok_path,
            )
            .expect_err("subject required");
            assert!(err.contains("subject is required"));
        }
        // ...and present subject is trimmed and carried.
        let intake = validate_google(
            GoogleCredentialBody {
                path: "/k.json".to_string(),
                subject: Some("  admin@corp.com ".to_string()),
            },
            true,
            ok_path,
        )
        .expect("valid");
        assert_eq!(intake.subject.as_deref(), Some("admin@corp.com"));
    }

    #[test]
    fn google_path_check_is_not_an_arbitrary_exists_oracle() {
        // Empty path → refused before any FS probe.
        assert!(validate_google(
            GoogleCredentialBody {
                path: "   ".to_string(),
                subject: None,
            },
            false,
            |_| Some("x".to_string()),
        )
        .is_err());
        // An unusable path (probe returns None) → the identical coarse message,
        // whether it is missing, a directory, or unreadable — never disclosing
        // which. The message never claims the KEY is valid.
        let err = validate_google(
            GoogleCredentialBody {
                path: "/nope".to_string(),
                subject: None,
            },
            false,
            |_| None,
        )
        .expect_err("unusable path refused");
        assert!(err.contains("not a readable"));
        assert!(err.contains("never read"));
    }

    #[test]
    fn structural_sa_json_check_wants_client_email_and_private_key() {
        let good = br#"{"client_email":"svc@p.iam","private_key":"-----BEGIN-----"}"#;
        assert!(structural_sa_json_check(good).is_ok());
        // Not JSON at all.
        assert!(structural_sa_json_check(b"not json").is_err());
        // Missing / empty each required field.
        assert!(structural_sa_json_check(br#"{"private_key":"k"}"#).is_err());
        assert!(structural_sa_json_check(br#"{"client_email":"e","private_key":""}"#).is_err());
        assert!(
            structural_sa_json_check(br#"{"client_email":"","private_key":"k"}"#).is_err(),
            "empty client_email is not present"
        );
    }

    #[test]
    fn credential_field_flips_untracked_to_tracked_when_stored() {
        // No stored credential → the Phase-1 observed state under `state`.
        let f = credential_field("hubspot", &bare(), None);
        assert_eq!(f["state"], "untracked");
        // A stored credential → tracked { kind, fingerprint } (never a secret).
        let status = ConnectorCredentialStatus {
            kind: ConnectorCredentialKind::Bearer,
            fingerprint: "abcd1234".to_string(),
            updated_at: Utc::now(),
        };
        let f = credential_field("hubspot", &bare(), Some(&status));
        assert_eq!(f["state"], "tracked");
        assert_eq!(f["kind"], "bearer");
        assert_eq!(f["fingerprint"], "abcd1234");
        // And it appears in the assembled row, replacing the observed state.
        let row = connector_row(&SOURCES[4], &bare(), ("off", "none"), None, Some(&status));
        assert_eq!(row["credential"]["state"], "tracked");
        assert_eq!(row["credential"]["fingerprint"], "abcd1234");
    }
}
