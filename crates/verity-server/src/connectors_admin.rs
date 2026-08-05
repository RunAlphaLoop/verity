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
    connector_worker, connectors, directory_worker, internal, AppState, HandlerResult, Secret,
    SecretIntakeAuth,
};
use verity_core::adapter::StorageAdapter;
use verity_core::types::{
    ConnectorCredentialKind, ConnectorCredentialStatus, ConnectorPathCredential, StorageError,
    SyncSchedule,
};

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
pub(crate) const SOURCES: [SourceSpec; 9] = [
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
    SourceSpec {
        source: "notion",
        label: "Notion",
        kind: "content",
    },
    SourceSpec {
        source: "intercom",
        label: "Intercom",
        kind: "support",
    },
    SourceSpec {
        source: "zoom",
        label: "Zoom",
        kind: "content",
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
        "hubspot" | "salesforce" | "notion" | "intercom" => CredentialClass::TierC,
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
        "notion" => &["NOTION_TOKEN"],
        "intercom" => &["INTERCOM_ACCESS_TOKEN"],
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

/// The honest backfill note for a source that CANNOT be triggered — the same
/// phase/applicability wording the refused POST returns, so the row and the
/// trigger never disagree.
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
            "backfill not wired for salesforce yet — awaiting a Salesforce test org \
             (the connector is fixtures-only so far)"
        }
        // hubspot is backfillable and never reaches this hint (it has its own
        // bearer+visibility gating in backfill_field); this covers unknown sources.
        _ => "backfill not wired for this source",
    }
}

/// The `backfill` field of a connector row (Phase-3). `available: true` ONLY for
/// gdrive/gmail with a resolvable SA-key credential (a stored `path` row OR the
/// server env `GOOGLE_APPLICATION_CREDENTIALS`) — and, for gmail, a stored
/// subject (gmail aborts without one). Otherwise `available: false` with the
/// exact honest hint naming what is missing (or the phase note for non-content
/// sources). `env_sa_key` is whether the server env supplies the SA path.
pub(crate) fn backfill_field(
    source: &str,
    stored: Option<&ConnectorCredentialStatus>,
    env_sa_key: bool,
) -> serde_json::Value {
    if !connector_worker::is_backfillable(source) {
        return serde_json::json!({ "available": false, "hint": backfill_hint(source) });
    }
    // HubSpot (tier-C): a browser-triggered backfill needs a stored bearer WITH a
    // non-empty visibility policy (the connector's `--visibility` is resolved from
    // the store, fail-closed). `env_sa_key` is a Google concept and never gates
    // HubSpot; the env bearer alone can't be materialized to a --credential-file,
    // so `available` reflects the STORED bearer+visibility (the spawn path).
    if source == "hubspot" {
        let has_bearer = stored.is_some_and(|s| s.kind == ConnectorCredentialKind::Bearer);
        let has_visibility =
            stored.is_some_and(|s| s.visibility.as_ref().is_some_and(|v| !v.is_empty()));
        let (available, hint) = if has_bearer && has_visibility {
            (
                true,
                "ready — full-crawl backfill for hubspot can be triggered".to_string(),
            )
        } else {
            (
                false,
                "no hubspot bearer with a visibility policy yet — store a HubSpot credential \
                 with a visibility policy (POST /v1/admin/connectors/hubspot/credential \
                 {token, visibility}) to enable backfill"
                    .to_string(),
            )
        };
        return serde_json::json!({ "available": available, "hint": hint });
    }
    let stored_path = stored.is_some_and(|s| s.kind == ConnectorCredentialKind::Path);
    let (available, hint) = if !stored_path && !env_sa_key {
        (
            false,
            format!(
                "no {source} service-account key yet — store a Google credential for this \
                 source, or set GOOGLE_APPLICATION_CREDENTIALS on the server, to enable backfill"
            ),
        )
    } else if connector_worker::subject_required(source)
        && !stored.is_some_and(|s| s.subject.as_deref().is_some_and(|v| !v.trim().is_empty()))
    {
        // gmail: a path is present but there is no impersonation subject to run
        // under (a stored subject is the only source; env can't carry one).
        (
            false,
            format!(
                "{source} needs a stored impersonation subject — re-store the {source} \
                 credential with a subject (domain-wide delegation) to enable backfill"
            ),
        )
    } else {
        (
            true,
            format!("ready — full-crawl backfill for {source} can be triggered"),
        )
    };
    serde_json::json!({ "available": available, "hint": hint })
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
    schedule: Option<&SyncSchedule>,
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
        "backfill": backfill_field(spec.source, stored, p.sa_key_configured),
        "sync": sync_field(spec.source, schedule),
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

    // Phase-4 continuous-sync schedules: the durable per-source schedule state
    // (enabled/interval/last_run) for the sync toggle read-back. One lookup per
    // eligible source (gdrive/gmail/hubspot); the others have no schedule row.
    let mut schedules: HashMap<&'static str, SyncSchedule> = HashMap::new();
    for spec in SOURCES.iter().filter(|s| sync_eligible(s.source)) {
        if let Some(sched) = state
            .storage
            .get_sync_schedule(q.tenant_id, spec.source)
            .await
            .map_err(internal)?
        {
            schedules.insert(spec.source, sched);
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
            connector_row(
                spec,
                &probes,
                verdict,
                hb,
                stored.get(spec.source),
                schedules.get(spec.source),
            )
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
            // and, since Phase 4 (migration 0030), PERSISTED alongside the
            // bearer so a browser-triggered backfill spawn can resolve
            // `--visibility` from the store. It is a non-secret tier-C sharing
            // policy — stored in its own `visibility` column, echoed in status,
            // but NEVER fed into the fingerprint (which covers the secret bytes
            // only). The bearer is exposed EXACTLY once, here, to the encryptor
            // — never logged, never formatted.
            let fingerprint = state
                .storage
                .store_connector_bearer(
                    q.tenant_id,
                    spec.source,
                    intake.token.expose().as_bytes(),
                    &intake.visibility,
                )
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
            // Phase-3 carry-over: persist the non-secret DWD impersonation subject
            // (validated/trimmed by validate_google) so a browser-triggered
            // backfill spawn can resolve `--subject` from the store instead of
            // relying solely on a server env var.
            let fingerprint = state
                .storage
                .store_connector_path(
                    q.tenant_id,
                    spec.source,
                    &intake.path,
                    intake.subject.as_deref(),
                )
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
// Phase-3 backfill trigger — POST /v1/admin/connectors/{source}/backfill.
// admin.check-gated (NOT SecretIntakeAuth: there is no secret in the request —
// the SA-key path + subject are resolved SERVER-SIDE from the store or env).
// gdrive/gmail spawn a one-shot full crawl; every other source is a 422 with the
// honest phase/applicability note. The credential/precedence resolution is a
// PURE function (injected values) so its honesty rules are pinned hermetically.
// ---------------------------------------------------------------------------

use std::path::PathBuf;

/// The resolved spawn inputs for a gdrive/gmail backfill: the SA-key file PATH
/// (for `GOOGLE_APPLICATION_CREDENTIALS`) and the impersonation `subject` (for
/// `--subject`; `None` allowed for gdrive, required for gmail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedBackfill {
    pub(crate) sa_key_path: PathBuf,
    pub(crate) subject: Option<String>,
}

/// Why a backfill trigger is refused, each mapped to a fixed HTTP status by the
/// handler — never a 500. The message is the exact, copyable honest fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackfillReject {
    /// Source is not a Phase-3 backfillable content source (hubspot/salesforce
    /// not wired; folder/gdirectory not applicable). → 422.
    NotBackfillable(String),
    /// No SA-key path resolvable from the store or the server env. → 422.
    NoCredential(String),
    /// A path is present in BOTH the store and the server env — refuse rather
    /// than silently pick one (never a double source of truth). → 409.
    Ambiguous(String),
    /// gmail requires an impersonation subject and none is stored. → 422.
    SubjectMissing(String),
}

impl BackfillReject {
    /// The HTTP status this rejection maps to (409 for the ambiguous both-present
    /// case, 422 for every honest-precondition case). Never 500.
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            BackfillReject::Ambiguous(_) => StatusCode::CONFLICT,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
    pub(crate) fn message(self) -> String {
        match self {
            BackfillReject::NotBackfillable(m)
            | BackfillReject::NoCredential(m)
            | BackfillReject::Ambiguous(m)
            | BackfillReject::SubjectMissing(m) => m,
        }
    }
}

/// The honest phase/applicability note for a source that CANNOT be backfilled in
/// Phase 3. Matches the Phase-1 row hint intent so a refused trigger and the
/// panel row say the same thing.
fn not_backfillable_reason(source: &str) -> String {
    match source {
        "folder" => "backfill is not applicable to folder — local folder watches ingest \
                     synchronously when added and catch up on server boot"
            .to_string(),
        "gdirectory" => "backfill is not applicable to gdirectory — directory sync reconciles \
                         the full directory on every pass (run the directory plane instead)"
            .to_string(),
        "salesforce" => "backfill not wired for salesforce yet — awaiting a Salesforce test org \
                         (the connector is fixtures-only so far); run the connector CLI \
                         (ingest/verity_ingest/connectors) to backfill for now"
            .to_string(),
        other => format!("backfill not wired for {other} yet"),
    }
}

/// Resolve the SA-key path + subject for a gdrive/gmail backfill, PURE (no DB, no
/// FS, no env): all inputs are injected. Precedence rules (non-negotiable):
///   - source MUST be backfillable (gdrive/gmail) — else `NotBackfillable`;
///   - the path comes from the STORED credential OR the server env, but NOT both
///     (both present → `Ambiguous` 409; neither → `NoCredential` 422);
///   - the subject comes from the STORED config only; gmail requires it
///     (`SubjectMissing` 422 when absent). When the path came from env (no stored
///     row), gmail still needs a stored subject — env alone can't carry one, so
///     that path honestly 422s too.
pub(crate) fn resolve_backfill(
    source: &str,
    stored: Option<&ConnectorPathCredential>,
    env_sa_key: Option<&std::path::Path>,
) -> Result<ResolvedBackfill, BackfillReject> {
    if !connector_worker::is_backfillable(source) {
        return Err(BackfillReject::NotBackfillable(not_backfillable_reason(
            source,
        )));
    }
    let stored_path = stored.map(|c| c.path.as_str()).filter(|p| !p.is_empty());
    let env_path = env_sa_key.filter(|p| !p.as_os_str().is_empty());

    let sa_key_path = match (stored_path, env_path) {
        (Some(_), Some(_)) => {
            return Err(BackfillReject::Ambiguous(format!(
                "the {source} SA-key path is provided BOTH by a stored connector credential AND \
                 the server's GOOGLE_APPLICATION_CREDENTIALS env — refusing to guess which is \
                 authoritative; unset the env var or revoke the stored credential so exactly one \
                 remains, then retry"
            )));
        }
        (Some(p), None) => PathBuf::from(p),
        (None, Some(p)) => p.to_path_buf(),
        (None, None) => {
            return Err(BackfillReject::NoCredential(format!(
                "no {source} service-account key to back fill with — store a Google credential \
                 for this source (POST /v1/admin/connectors/{source}/credential) or set \
                 GOOGLE_APPLICATION_CREDENTIALS on the server, then retry"
            )));
        }
    };

    // Subject comes from the stored config only (env can't carry a per-source
    // subject). gmail hard-requires it (it aborts before any HTTP without one).
    let subject = stored
        .and_then(|c| c.subject.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if connector_worker::subject_required(source) && subject.is_none() {
        return Err(BackfillReject::SubjectMissing(format!(
            "{source} backfill needs a mailbox-owner impersonation subject (domain-wide \
             delegation) — store the {source} credential WITH a subject \
             (POST /v1/admin/connectors/{source}/credential {{path, subject}}); {source} aborts \
             before any HTTP without it"
        )));
    }

    Ok(ResolvedBackfill {
        sa_key_path,
        subject,
    })
}

/// POST /v1/admin/connectors/{source}/backfill?tenant_id= (admin): trigger a
/// one-shot full-crawl backfill for gdrive/gmail. admin.check-gated (NOT
/// SecretIntakeAuth — no secret in the request; the SA-key path + subject are
/// resolved server-side). Every non-backfillable source (folder/gdirectory not
/// applicable; hubspot/salesforce Phase 4) → 422 with the honest note. For
/// gdrive/gmail: resolve the path (store XOR env; both → 409) + subject (stored;
/// gmail requires it → 422), check ingest prereqs (repo/venv → 422), ensure the
/// tenant, MINT a run_id, and spawn the child. Returns
/// `{ run_id, source, tenant_id, state: "started", pid }`. Unknown source → 404,
/// unknown tenant → 404 (never a 500). An already-running (tenant,source) → 409;
/// the same source live under another tenant → 409 naming it.
pub(crate) async fn backfill_source(
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
                "unknown source '{source}' — expected one of folder, gdrive, gmail, gdirectory, \
                 hubspot, salesforce"
            ),
        ));
    };

    // Unknown tenant → clean 404, never a foreign-key 500 on the spawn/write.
    state
        .storage
        .inner()
        .ensure_tenant(q.tenant_id)
        .await
        .map_err(credential_status)?;

    // Non-backfillable sources (folder/gdirectory/salesforce) fail closed HERE
    // with the honest phase/applicability note, before any credential read.
    if !connector_worker::is_backfillable(spec.source) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            not_backfillable_reason(spec.source),
        ));
    }

    // Resolve the source-family identity: HubSpot (tier-C bearer + visibility)
    // takes a DIFFERENT shape from the Google SA-key path + subject.
    let identity = resolve_connector_identity(&state, q.tenant_id, spec.source).await?;

    // Mint the run_id SERVER-SIDE so the panel poll keys on THIS run.
    let run_id = Uuid::new_v4();
    let base_url = crate::worker_base_url(&state.listen);

    match state
        .connectors
        .start(
            state.pool().clone(),
            connector_worker::SpawnMode::Backfill,
            state.repo_root.as_deref(),
            &base_url,
            q.tenant_id,
            spec.source,
            state.admin_token.as_deref(),
            identity,
            run_id,
        )
        .await
    {
        Ok(pid) => Ok(Json(serde_json::json!({
            "run_id": run_id,
            "source": spec.source,
            "tenant_id": q.tenant_id,
            "state": "started",
            "pid": pid,
        }))),
        Err(e) => Err(spawn_error_status(e)),
    }
}

/// Resolve the source-family spawn identity for a gdrive/gmail/hubspot child —
/// the SHARED credential-precedence resolution used by BOTH the one-shot backfill
/// trigger and the continuous-sync `--once` scheduler (each cycle re-resolves the
/// CURRENT credential, so a rotation is picked up per cycle with no long-lived
/// bearer on disk). HubSpot (tier-C bearer + visibility) takes a DIFFERENT shape
/// from the Google SA-key path + subject; the fail-closed preconditions (a
/// resolvable credential; hubspot visibility; gmail subject) are identical either
/// way. Each precondition failure maps to a fixed HTTP status (422/409), never a
/// 500. The caller has already confirmed the source is spawnable.
pub(crate) async fn resolve_connector_identity(
    state: &AppState,
    tenant_id: Uuid,
    source: &str,
) -> Result<connector_worker::BackfillIdentity, (StatusCode, String)> {
    if connector_worker::is_single_bearer(source) {
        resolve_single_bearer_identity(state, tenant_id, source).await
    } else {
        // Google (gdrive/gmail): stored path (+ subject) XOR the server env SA key.
        let stored = state
            .storage
            .materialize_connector_path(tenant_id, source)
            .await
            .map_err(credential_status)?;
        let resolved =
            resolve_backfill(source, stored.as_ref(), state.connectors.sa_key.as_deref())
                .map_err(|r| (r.status(), r.clone().message()))?;
        Ok(connector_worker::BackfillIdentity::Google {
            sa_key_path: resolved.sa_key_path,
            subject: resolved.subject,
        })
    }
}

/// Resolve a single-bearer tier-C backfill identity (hubspot/notion/intercom):
/// the DECRYPTED bearer + the stored visibility policy, applying the fail-closed
/// preconditions in order.
///
/// - env-vs-store disambiguation: a server env credential (e.g.
///   `HUBSPOT_SERVICE_KEY` / `NOTION_TOKEN` / `INTERCOM_ACCESS_TOKEN`) AND a
///   stored bearer both present → 409 (never silently pick one — the same
///   precedence rule the credential store uses).
/// - a resolvable bearer: neither stored nor env → 422 with the exact fix.
/// - a stored non-empty visibility policy: tier-C requires a sharing scope, so
///   an absent/empty stored visibility → 422 (memory nobody can read is never a
///   permissive default).
///
/// It then materializes the bearer (decrypt-on-demand under the tenant DEK). The
/// bearer bytes are wrapped in `Zeroizing` so they scrub on drop; `spawn` writes
/// them to a 0600 `--credential-file` and unlinks it on child exit — the token
/// never touches argv/env/logs. EXCLUDES salesforce (multi-part OAuth, not a
/// single bearer — it never routes here).
async fn resolve_single_bearer_identity(
    state: &AppState,
    tenant_id: Uuid,
    source: &str,
) -> Result<connector_worker::BackfillIdentity, (StatusCode, String)> {
    let env_bearer_present = env_precedence_hit(source, |k| std::env::var(k).ok()).is_some();
    let env_vars = env_precedence_vars(source).join(" / ");

    // The non-secret stored status tells us kind + visibility WITHOUT decrypting.
    let status = state
        .storage
        .get_connector_credential_status(tenant_id, source)
        .await
        .map_err(credential_status)?;
    let stored_bearer_present = status
        .as_ref()
        .is_some_and(|s| s.kind == ConnectorCredentialKind::Bearer);

    // Env-vs-store precedence: refuse rather than guess which is authoritative.
    if env_bearer_present && stored_bearer_present {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "the {source} bearer is provided BOTH by a stored connector credential AND the \
                 server's {env_vars} env — refusing to guess which is authoritative; unset the \
                 env var or revoke the stored credential so exactly one remains, then retry"
            ),
        ));
    }
    if !env_bearer_present && !stored_bearer_present {
        let first_env_var = env_precedence_vars(source).first().copied().unwrap_or("");
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "no {source} bearer to back fill with — store a credential with a visibility \
                 policy first (POST /v1/admin/connectors/{source}/credential {{token, \
                 visibility}}), or set {first_env_var} on the server, then retry"
            ),
        ));
    }

    // A stored non-empty visibility policy is mandatory (tier-C fail-closed). An
    // env-only bearer has no stored visibility, so it honestly 422s here too —
    // the tier-C sharing scope must be stored alongside the credential.
    let visibility = status
        .as_ref()
        .and_then(|s| s.visibility.clone())
        .filter(|v| !v.is_empty())
        .ok_or((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "store a {source} credential with a visibility policy first — a tier-C backfill \
                 coarsens every record to the admin-assigned visibility, so an empty/absent \
                 policy would ingest memory no reader can act under (POST \
                 /v1/admin/connectors/{source}/credential {{token, visibility}})"
            ),
        ))?;

    // Decrypt-on-demand under the tenant DEK (inherits the KEK-unset fail-closed
    // refusal). None here would be a store/status race; fail closed, never spawn.
    let bearer = match state
        .storage
        .materialize_connector_bearer(tenant_id, source)
        .await
        .map_err(credential_status)?
    {
        Some(b) => b,
        None => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "no stored {source} bearer to materialize — store a credential with a \
                     visibility policy first"
                ),
            ))
        }
    };

    Ok(connector_worker::BackfillIdentity::SingleBearer {
        bearer: zeroize::Zeroizing::new(bearer),
        visibility,
    })
}

/// Map a `connector_worker::SpawnError` to a fixed HTTP status — NEVER a 500.
/// NoRepo/NoVenv → 422 (a fixable server-config precondition), NoConfig → 503
/// (the identity resolved by the pure layer but the FS check failed), Os → 503,
/// AlreadyRunning/SourceBusy → 409 with the busy identity named.
fn spawn_error_status(e: connector_worker::SpawnError) -> (StatusCode, String) {
    use connector_worker::SpawnError::*;
    match e {
        NoRepo => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "the server doesn't know its repo path — start it with --repo <path> or VERITY_REPO \
             so it can find ingest/.venv"
                .to_string(),
        ),
        NoVenv(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        NoConfig(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
        Os(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
        AlreadyRunning { pid } => (
            StatusCode::CONFLICT,
            format!("a backfill for this tenant + source is already running (pid {pid})"),
        ),
        SourceBusy { tenant, pid } => (
            StatusCode::CONFLICT,
            format!(
                "this source already has a live backfill under tenant {tenant} (pid {pid}) — a \
                 service-account key / rate budget is shared per source, so backfills are \
                 serialized per source across tenants; wait for it to finish, then retry"
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// Phase-4 continuous-sync toggle — POST /v1/admin/connectors/{source}/sync.
// admin.check-gated. Arms/disarms a per-(tenant, source) SCHEDULER that fires a
// short-lived `--once` poll cycle on an interval — NOT a persistent child. The
// schedule is durable in `sync_schedules` (migration 0033) + re-armed on boot.
// ---------------------------------------------------------------------------

/// The default poll interval (seconds) the toggle applies when the caller omits
/// `interval_secs`. 300s (5 min) — well above the 60s DB floor, a sane cadence
/// that never hammers a source API. The floor itself is
/// `verity_storage::SYNC_INTERVAL_FLOOR_SECS` (enforced by the DB CHECK + the
/// storage upsert, so a sub-floor value is a clean 422, never a silent clamp).
pub(crate) const SYNC_DEFAULT_INTERVAL_SECS: i32 = 300;

/// Whether a source is eligible for a native continuous-sync SCHEDULE. `gdrive` /
/// `gmail` / `hubspot` have a `--once` incremental poll + a persisted cursor.
/// `gdirectory` has its OWN continuous directory plane (mapped separately by the
/// toggle to the directory start/stop endpoints). `folder` (always-on in-process
/// watch) and `salesforce` (not wired) have no schedule.
fn sync_eligible(source: &str) -> bool {
    connector_worker::is_pollable(source)
}

#[derive(Deserialize)]
pub(crate) struct SyncToggleBody {
    tenant_id: Uuid,
    enabled: bool,
    /// Poll cadence in seconds. Floored at `SYNC_INTERVAL_FLOOR_SECS` (60);
    /// omitted → `SYNC_DEFAULT_INTERVAL_SECS` (300). A sub-floor value is a 422.
    #[serde(default)]
    interval_secs: Option<i32>,
}

/// POST /v1/admin/connectors/{source}/sync {tenant_id, enabled, interval_secs?}
/// (admin): arm/disarm continuous sync for (tenant, source).
///
/// - `gdirectory` maps to the existing directory plane (422 pointing at the
///   directory start/stop endpoints — a native schedule would duplicate the
///   directory_worker).
/// - `folder` / `salesforce` / unknown → 422 (no `--once` schedule).
/// - ENABLE (gdrive/gmail/hubspot): validate the SAME preconditions as backfill
///   (a resolvable credential; hubspot visibility; gmail subject) — a bad
///   precondition is a 422 BEFORE any durable write, so an unusable schedule is
///   never armed. Then floor the interval (>= 60, default 300), persist via
///   `upsert_sync_schedule`, arm the scheduler, and fire an immediate first
///   cycle. DOUBLE-POLL GUARD: if the env-configured knowledge/Temporal worker is
///   configured to poll this source, the toggle WARNS (a `warning` field) so an
///   operator never silently double-ingests.
/// - DISABLE: persist `enabled=false` (durable) + disarm the loop (an in-flight
///   cycle finishes). Idempotent — disabling an unarmed schedule is an honest
///   no-op that still persists the durable off-state.
///
/// Returns `{ source, enabled, interval_secs, next_run_at?, warning? }`.
pub(crate) async fn sync_source(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(source): axum::extract::Path<String>,
    Json(body): Json<SyncToggleBody>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let Some(spec) = source_spec(&source) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!(
                "unknown source '{source}' — expected one of folder, gdrive, gmail, gdirectory, \
                 hubspot, salesforce"
            ),
        ));
    };
    let source = spec.source; // 'static, validated

    // gdirectory has its own continuous directory plane — a native schedule would
    // duplicate directory_worker. Point the operator at the directory endpoints.
    if source == "gdirectory" {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "use directory sync for gdirectory — its continuous sync is the directory plane, not a \
             connector poll schedule; toggle it via POST /v1/admin/planes/directory/start and \
             /stop (the directory worker reconciles the full directory on every pass)"
                .to_string(),
        ));
    }
    // folder (always-on in-process) / salesforce (not wired) have no --once cycle.
    if !sync_eligible(source) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            match source {
                "folder" => "continuous sync is not applicable to folder — local folder watches \
                             ingest synchronously when added and catch up on server boot"
                    .to_string(),
                "salesforce" => "continuous sync is not wired for salesforce yet — the connector \
                                 is fixtures-only until a test org lands"
                    .to_string(),
                other => format!("continuous sync is not wired for {other}"),
            },
        ));
    }

    // Unknown tenant → clean 404 before any durable write.
    state
        .storage
        .inner()
        .ensure_tenant(body.tenant_id)
        .await
        .map_err(credential_status)?;

    // Hold the sync-plane admission lock across the whole persist→arm/disarm
    // critical section so two concurrent enable/disable requests for this key
    // can't interleave their durable upsert and their arm/disarm — otherwise a
    // late ENABLE's arm() could survive a DISABLE that already ran disarm(),
    // leaving a GHOST loop polling forever against a durable enabled=false. With
    // the lock, upsert + arm/disarm are atomic per request.
    let _admit = state.sync.admit().await;

    // DISABLE: persist the durable off-state + disarm the loop. Idempotent.
    if !body.enabled {
        // Persist enabled=false, preserving the stored interval (or the default if
        // none was ever stored). The interval is inert while disabled.
        let interval = state
            .storage
            .get_sync_schedule(body.tenant_id, source)
            .await
            .map_err(credential_status)?
            .map(|s| s.interval_secs)
            .unwrap_or(SYNC_DEFAULT_INTERVAL_SECS);
        state
            .storage
            .upsert_sync_schedule(body.tenant_id, source, interval, false)
            .await
            .map_err(credential_status)?;
        state.sync.disarm(body.tenant_id, source).await;
        return Ok(Json(serde_json::json!({
            "source": source,
            "enabled": false,
            "interval_secs": interval,
        })));
    }

    // ENABLE. Resolve + floor the interval FIRST (a sub-floor value must 422
    // before any spawn/precondition work).
    let interval = body.interval_secs.unwrap_or(SYNC_DEFAULT_INTERVAL_SECS);
    if interval < verity_storage::SYNC_INTERVAL_FLOOR_SECS {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "continuous-sync interval {interval}s is below the {}s floor — continuous sync \
                 must never hammer a source API / trip rate limits; use >= {}s (default {}s)",
                verity_storage::SYNC_INTERVAL_FLOOR_SECS,
                verity_storage::SYNC_INTERVAL_FLOOR_SECS,
                SYNC_DEFAULT_INTERVAL_SECS
            ),
        ));
    }

    // PRECONDITIONS: the SAME fail-closed credential checks as backfill (a
    // resolvable credential; hubspot visibility; gmail subject). Refuse to arm an
    // unusable schedule — a 422 here, BEFORE any durable write, so a bad toggle
    // never leaves a broken armed loop behind.
    resolve_connector_identity(&state, body.tenant_id, source).await?;

    // DOUBLE-POLL GUARD: the env-configured knowledge/Temporal connector-sync
    // worker (VERITY_CONNECTORS) is the OTHER continuous source poller. If it is
    // configured to poll this source, a native per-(tenant, source) schedule would
    // race the SAME cursor. Warn (there is no shared lock across the Rust process
    // and the Temporal worker, so this is a config exclusion, not a runtime mutex).
    let warning = double_poll_warning(source);

    // Persist the durable schedule (floored again in storage — belt + braces).
    let sched = state
        .storage
        .upsert_sync_schedule(body.tenant_id, source, interval, true)
        .await
        .map_err(credential_status)?;

    // Arm the scheduler loop, then fire an immediate first cycle (best-effort:
    // the loop's own first tick is one interval out, so the immediate cycle gives
    // instant feedback). The cycle is skip-if-running-safe.
    state
        .sync
        .arm(
            Arc::clone(&state),
            body.tenant_id,
            source,
            sched.interval_secs,
        )
        .await;
    let decision = crate::sync_scheduler::fire_cycle(&state, body.tenant_id, source).await;

    let next_run_at = Utc::now() + chrono::Duration::seconds(sched.interval_secs as i64);
    let mut out = serde_json::json!({
        "source": source,
        "enabled": true,
        "interval_secs": sched.interval_secs,
        "next_run_at": next_run_at,
        // Live in-memory confirmation the loop actually armed this process (the
        // durable enabled-flag is in sync_schedules; this is the runtime truth).
        "armed": state.sync.is_armed(body.tenant_id, source).await,
        "first_cycle": format!("{decision:?}"),
    });
    if let Some(w) = warning {
        out["warning"] = serde_json::Value::String(w);
    }
    Ok(Json(out))
}

/// The double-poll warning for a source if the env-configured knowledge/Temporal
/// connector-sync worker (`VERITY_CONNECTORS`, comma-separated) lists it. `None`
/// when the env is unset or does not name this source. A native schedule AND the
/// Temporal schedule polling the same source would advance the SAME cursor
/// concurrently — wasted double work + a cursor-rewind hazard. This is a config
/// exclusion (no shared cross-process lock), so we surface it, never silently
/// double-ingest.
fn double_poll_warning(source: &str) -> Option<String> {
    let connectors = std::env::var("VERITY_CONNECTORS").ok()?;
    // Normalize each token EXACTLY as the Python knowledge worker does
    // (orchestration/config.py::enabled_connectors — `token.strip().lower()`), so
    // `VERITY_CONNECTORS="HubSpot"` — which DOES arm the Python schedule — also
    // fires this warning. Our source ids are already lowercase, so a
    // case-sensitive compare would silently miss a capitalized env value and let
    // both pollers advance the same cursor with no warning.
    let listed = connectors
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .any(|c| c == source);
    listed.then(|| {
        format!(
            "the env-configured connector-sync worker (VERITY_CONNECTORS) already polls '{source}' \
             — running this native schedule AND that worker would advance the same cursor \
             concurrently (wasted double work + a cursor-rewind hazard). Remove '{source}' from \
             VERITY_CONNECTORS, or leave this schedule off, so exactly one poller owns the cursor."
        )
    })
}

/// The `sync` field of a connector row (Phase-4): the durable continuous-sync
/// state for the row's (tenant, source). Shape `{ enabled, interval_secs,
/// last_run_at, eligible, hint? }`. Only gdrive/gmail/hubspot have a native
/// schedule; gdirectory maps to the directory plane (reported `eligible:false`
/// with a hint pointing there); folder/salesforce are `eligible:false`. When a
/// schedule row exists it carries the persisted enabled/interval/last_run;
/// otherwise the honest not-yet-armed default.
pub(crate) fn sync_field(source: &str, schedule: Option<&SyncSchedule>) -> serde_json::Value {
    if source == "gdirectory" {
        return serde_json::json!({
            "enabled": false,
            "interval_secs": serde_json::Value::Null,
            "last_run_at": serde_json::Value::Null,
            "eligible": false,
            "hint": "continuous sync for gdirectory is the directory plane — toggle it via the \
                     directory worker start/stop, not a connector schedule",
        });
    }
    if !sync_eligible(source) {
        let hint = match source {
            "folder" => "not applicable — folder watches ingest synchronously and catch up on boot",
            "salesforce" => "continuous sync not wired for salesforce yet (fixtures-only)",
            _ => "continuous sync not wired for this source",
        };
        return serde_json::json!({
            "enabled": false,
            "interval_secs": serde_json::Value::Null,
            "last_run_at": serde_json::Value::Null,
            "eligible": false,
            "hint": hint,
        });
    }
    match schedule {
        Some(s) => serde_json::json!({
            "enabled": s.enabled,
            "interval_secs": s.interval_secs,
            "last_run_at": s.last_run_at,
            "eligible": true,
        }),
        None => serde_json::json!({
            "enabled": false,
            "interval_secs": serde_json::Value::Null,
            "last_run_at": serde_json::Value::Null,
            "eligible": true,
        }),
    }
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
    fn registry_lists_the_sources_with_their_kinds() {
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
                ("notion", "content"),
                ("intercom", "support"),
                ("zoom", "content"),
            ]
        );
        assert_eq!(source_spec("hubspot").expect("known").label, "HubSpot");
        assert_eq!(source_spec("notion").expect("known").label, "Notion");
        assert_eq!(source_spec("intercom").expect("known").label, "Intercom");
        // Fail closed: an unknown source resolves to nothing, never a row.
        assert!(source_spec("zendesk").is_none());
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
        let row = connector_row(&SOURCES[0], &bare(), ("off", "server"), None, None, None);
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
            let row = connector_row(spec, &full(), ("off", "none"), None, None, None);
            // The full row contract, per source.
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
            assert!(!row["backfill"]["hint"].as_str().expect("hint").is_empty());
        }
        // Phase-3: every NON-backfillable source stays available:false with the
        // honest phase/applicability note — no stored credential can flip them.
        for s in ["folder", "gdirectory", "hubspot", "salesforce"] {
            let spec = source_spec(s).unwrap();
            let row = connector_row(spec, &full(), ("off", "none"), None, None, None);
            assert_eq!(
                row["backfill"]["available"], false,
                "{s} must never be backfillable"
            );
        }
        // Salesforce carries the honest Phase-4 note.
        let sf = connector_row(&SOURCES[5], &full(), ("off", "none"), None, None, None);
        assert!(sf["backfill"]["hint"]
            .as_str()
            .expect("hint")
            .contains("awaiting a Salesforce test org"));
        // Heartbeat round-trips as rfc3339, null when never seen.
        let hb = connector_row(
            &SOURCES[4],
            &full(),
            ("off", "observed"),
            Some(now),
            None,
            None,
        );
        assert_eq!(
            serde_json::from_value::<DateTime<Utc>>(hb["last_heartbeat"].clone())
                .expect("timestamp")
                .timestamp_millis(),
            now.timestamp_millis()
        );
        assert!(
            connector_row(&SOURCES[4], &full(), ("off", "none"), None, None, None)
                ["last_heartbeat"]
                .is_null()
        );
    }

    #[test]
    fn prereqs_ok_derives_from_the_same_rows_the_response_carries() {
        // gdirectory on a bare server: every probe fails ⇒ prereqs_ok false.
        let row = connector_row(&SOURCES[3], &bare(), ("off", "none"), None, None, None);
        assert_eq!(row["prereqs_ok"], false);
        assert!(row["prereqs"]
            .as_array()
            .expect("list")
            .iter()
            .all(|q| q["ok"] == false));
        // ...and fully-provisioned: all ok ⇒ prereqs_ok true.
        let row = connector_row(&SOURCES[3], &full(), ("off", "none"), None, None, None);
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
        // Notion + Intercom are pasted-bearer tier-C sources like HubSpot.
        assert_eq!(credential_class("notion"), CredentialClass::TierC);
        assert_eq!(credential_class("intercom"), CredentialClass::TierC);
        // folder + any unknown source classify as None (no secret intake).
        assert_eq!(credential_class("folder"), CredentialClass::None);
        assert_eq!(credential_class("zendesk"), CredentialClass::None);
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
            subject: None,
            visibility: Some(vec![7]),
            updated_at: Utc::now(),
        };
        let f = credential_field("hubspot", &bare(), Some(&status));
        assert_eq!(f["state"], "tracked");
        assert_eq!(f["kind"], "bearer");
        assert_eq!(f["fingerprint"], "abcd1234");
        // And it appears in the assembled row, replacing the observed state.
        let row = connector_row(
            &SOURCES[4],
            &bare(),
            ("off", "none"),
            None,
            Some(&status),
            None,
        );
        assert_eq!(row["credential"]["state"], "tracked");
        assert_eq!(row["credential"]["fingerprint"], "abcd1234");
    }

    // ---- Phase-3 backfill: pure credential/subject precedence resolution ----

    use std::path::Path;

    fn stored_path(subject: Option<&str>) -> ConnectorPathCredential {
        ConnectorPathCredential {
            path: "/srv/sa.json".to_string(),
            subject: subject.map(str::to_string),
        }
    }

    fn path_status(subject: Option<&str>) -> ConnectorCredentialStatus {
        ConnectorCredentialStatus {
            kind: ConnectorCredentialKind::Path,
            fingerprint: "fp".to_string(),
            subject: subject.map(str::to_string),
            visibility: None,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn resolve_refuses_non_backfillable_sources() {
        // resolve_backfill is the GOOGLE (path/subject) resolver. hubspot is
        // backfillable but takes a DIFFERENT (bearer/visibility) path, resolved by
        // resolve_single_bearer_identity — never routed through here. These are the
        // sources with no browser-triggered backfill at all.
        for s in ["folder", "gdirectory", "salesforce", "bogus"] {
            let err = resolve_backfill(s, None, Some(Path::new("/srv/sa.json")))
                .err()
                .unwrap_or_else(|| panic!("{s} must not resolve"));
            assert!(matches!(err, BackfillReject::NotBackfillable(_)), "{s}");
            assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        // salesforce carries the honest fixtures-only note (hubspot no longer does
        // — it is wired).
        let msg = resolve_backfill("salesforce", None, None)
            .err()
            .unwrap()
            .message();
        assert!(msg.contains("test org"), "salesforce: {msg}");
        // hubspot is now backfillable, so the Google resolver does NOT refuse it as
        // non-backfillable (it would fail later for lacking a path, which is
        // irrelevant — the handler never calls this for hubspot).
        assert!(connector_worker::is_backfillable("hubspot"));
    }

    #[test]
    fn resolve_from_stored_path_only() {
        let cred = stored_path(None);
        let got = resolve_backfill("gdrive", Some(&cred), None).expect("gdrive ok");
        assert_eq!(got.sa_key_path, PathBuf::from("/srv/sa.json"));
        assert_eq!(got.subject, None);
    }

    #[test]
    fn resolve_from_env_only() {
        let got =
            resolve_backfill("gdrive", None, Some(Path::new("/env/sa.json"))).expect("gdrive ok");
        assert_eq!(got.sa_key_path, PathBuf::from("/env/sa.json"));
    }

    #[test]
    fn resolve_both_present_is_ambiguous_409() {
        let cred = stored_path(None);
        let err = resolve_backfill("gdrive", Some(&cred), Some(Path::new("/env/sa.json")))
            .err()
            .expect("both present must 409");
        assert!(matches!(err, BackfillReject::Ambiguous(_)));
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn resolve_neither_present_is_no_credential_422() {
        let err = resolve_backfill("gdrive", None, None)
            .err()
            .expect("neither present must 422");
        assert!(matches!(err, BackfillReject::NoCredential(_)));
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn gmail_requires_a_stored_subject() {
        // Path present (env), but gmail has no stored subject → 422.
        let err = resolve_backfill("gmail", None, Some(Path::new("/env/sa.json")))
            .err()
            .expect("gmail without subject must 422");
        assert!(matches!(err, BackfillReject::SubjectMissing(_)));
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);
        // A blank stored subject is treated as absent.
        let blank = stored_path(Some("   "));
        assert!(matches!(
            resolve_backfill("gmail", Some(&blank), None).err(),
            Some(BackfillReject::SubjectMissing(_))
        ));
        // With a real stored subject it resolves and the subject is trimmed.
        let cred = stored_path(Some("  mbox@corp.example  "));
        let got = resolve_backfill("gmail", Some(&cred), None).expect("gmail ok with subject");
        assert_eq!(got.subject.as_deref(), Some("mbox@corp.example"));
    }

    #[test]
    fn gdrive_subject_is_optional_but_carried_when_stored() {
        let cred = stored_path(Some("owner@corp.example"));
        let got = resolve_backfill("gdrive", Some(&cred), None).expect("gdrive ok");
        assert_eq!(got.subject.as_deref(), Some("owner@corp.example"));
    }

    // ---- backfill_field row note (available gating) ----------------------

    /// A bearer credential status with an optional visibility policy — the
    /// tier-C shape the HubSpot backfill_field arm gates on.
    fn bearer_status(visibility: Option<Vec<i32>>) -> ConnectorCredentialStatus {
        ConnectorCredentialStatus {
            kind: ConnectorCredentialKind::Bearer,
            fingerprint: "fp".to_string(),
            subject: None,
            visibility,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn backfill_field_available_only_with_a_resolvable_credential() {
        // With NO stored credential these are all unavailable (folder/gdirectory/
        // salesforce are never backfillable; hubspot needs a stored bearer).
        for s in ["folder", "gdirectory", "hubspot", "salesforce"] {
            let f = backfill_field(s, None, true);
            assert_eq!(f["available"], false, "{s}");
        }
        // hubspot: a stored bearer WITH a non-empty visibility policy → available;
        // a bearer with empty/absent visibility → NOT (tier-C fail-closed). The
        // env_sa_key flag is a Google concept and never gates hubspot.
        assert_eq!(
            backfill_field("hubspot", Some(&bearer_status(Some(vec![7, 9]))), false)["available"],
            true
        );
        assert_eq!(
            backfill_field("hubspot", Some(&bearer_status(Some(vec![]))), true)["available"],
            false
        );
        assert_eq!(
            backfill_field("hubspot", Some(&bearer_status(None)), true)["available"],
            false
        );
        // A path-kind row under hubspot (wrong shape) is not a usable bearer.
        assert_eq!(
            backfill_field("hubspot", Some(&path_status(None)), true)["available"],
            false
        );
        // gdrive: no credential anywhere → unavailable, honest hint.
        let f = backfill_field("gdrive", None, false);
        assert_eq!(f["available"], false);
        assert!(f["hint"].as_str().unwrap().contains("service-account"));
        // gdrive: env SA key set → available.
        assert_eq!(backfill_field("gdrive", None, true)["available"], true);
        // gdrive: stored path (no env) → available.
        let st = path_status(None);
        assert_eq!(
            backfill_field("gdrive", Some(&st), false)["available"],
            true
        );
        // gmail: path present but NO subject → unavailable (needs subject).
        assert_eq!(backfill_field("gmail", None, true)["available"], false);
        let st_no_subj = path_status(None);
        assert_eq!(
            backfill_field("gmail", Some(&st_no_subj), true)["available"],
            false
        );
        // gmail: stored path WITH subject → available.
        let st_subj = path_status(Some("mbox@corp.example"));
        assert_eq!(
            backfill_field("gmail", Some(&st_subj), false)["available"],
            true
        );
    }

    // ---- SpawnError → HTTP status mapping (never 500) --------------------

    #[test]
    fn spawn_error_maps_to_stable_statuses_never_500() {
        use connector_worker::SpawnError;
        assert_eq!(
            spawn_error_status(SpawnError::NoRepo).0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            spawn_error_status(SpawnError::NoVenv("x".into())).0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            spawn_error_status(SpawnError::NoConfig("x".into())).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            spawn_error_status(SpawnError::Os("x".into())).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            spawn_error_status(SpawnError::AlreadyRunning { pid: 7 }).0,
            StatusCode::CONFLICT
        );
        let busy = spawn_error_status(SpawnError::SourceBusy {
            tenant: Uuid::from_u128(42),
            pid: 9,
        });
        assert_eq!(busy.0, StatusCode::CONFLICT);
        // The 409 message names the busy tenant so the operator knows who to wait on.
        assert!(busy.1.contains(&Uuid::from_u128(42).to_string()));
    }

    // ---- run_id path: a fresh server-minted id per trigger --------------

    #[test]
    fn server_mints_a_fresh_run_id() {
        // The handler mints Uuid::new_v4() per call; two mints never collide, and
        // each is a valid UUID string the child reads from VERITY_BACKFILL_RUN_ID.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(a, b);
        assert_eq!(connector_worker::RUN_ID_ENV, "VERITY_BACKFILL_RUN_ID");
        assert!(Uuid::parse_str(&a.to_string()).is_ok());
    }

    // ---- Phase-4 continuous-sync toggle (pure layer) --------------------

    fn sched(source: &str, enabled: bool, interval: i32) -> SyncSchedule {
        SyncSchedule {
            tenant_id: Uuid::from_u128(1),
            source: source.to_string(),
            interval_secs: interval,
            enabled,
            last_run_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn sync_eligible_matches_pollable_sources_only() {
        assert!(sync_eligible("gdrive"));
        assert!(sync_eligible("gmail"));
        assert!(sync_eligible("hubspot"));
        // notion/intercom are now pollable → sync-eligible (single-bearer poll).
        assert!(sync_eligible("notion"));
        assert!(sync_eligible("intercom"));
        // gdirectory has its own plane; folder/salesforce have no --once cycle.
        // Salesforce stays INELIGIBLE — it never joined the pollable/bearer family.
        for s in ["gdirectory", "folder", "salesforce", "bogus"] {
            assert!(!sync_eligible(s), "{s} must not be sync-eligible");
        }
    }

    #[test]
    fn single_bearer_family_excludes_salesforce() {
        // The bearer resolver routes hubspot/notion/intercom; salesforce (multi-
        // part OAuth) must NEVER route into the single-bearer path.
        for s in ["hubspot", "notion", "intercom"] {
            assert!(connector_worker::is_single_bearer(s), "{s}");
        }
        for s in [
            "salesforce",
            "gdrive",
            "gmail",
            "gdirectory",
            "folder",
            "bogus",
        ] {
            assert!(!connector_worker::is_single_bearer(s), "{s}");
        }
    }

    #[test]
    fn sync_field_reports_schedule_state_for_eligible_sources() {
        // A stored, enabled schedule surfaces its enabled/interval/last_run.
        let s = sched("gdrive", true, 600);
        let f = sync_field("gdrive", Some(&s));
        assert_eq!(f["enabled"], true);
        assert_eq!(f["interval_secs"], 600);
        assert_eq!(f["eligible"], true);
        // No schedule yet → the honest not-armed default (eligible, but off/null).
        let f = sync_field("hubspot", None);
        assert_eq!(f["enabled"], false);
        assert_eq!(f["interval_secs"], serde_json::Value::Null);
        assert_eq!(f["eligible"], true);
    }

    #[test]
    fn sync_field_gdirectory_points_at_the_directory_plane() {
        let f = sync_field("gdirectory", None);
        assert_eq!(f["enabled"], false);
        assert_eq!(f["eligible"], false);
        assert!(f["hint"].as_str().unwrap().contains("directory plane"));
    }

    #[test]
    fn sync_field_ineligible_sources_are_off_with_hint() {
        for s in ["folder", "salesforce"] {
            let f = sync_field(s, None);
            assert_eq!(f["enabled"], false, "{s}");
            assert_eq!(f["eligible"], false, "{s}");
            assert!(f["hint"].is_string(), "{s} must carry an honest hint");
        }
    }

    #[test]
    fn interval_floor_is_below_the_default() {
        // The DB floor (60) must be <= the default the toggle applies (300), so
        // the default is always representable and a sub-floor value is rejectable.
        assert!(verity_storage::SYNC_INTERVAL_FLOOR_SECS <= SYNC_DEFAULT_INTERVAL_SECS);
        assert_eq!(verity_storage::SYNC_INTERVAL_FLOOR_SECS, 60);
        assert_eq!(SYNC_DEFAULT_INTERVAL_SECS, 300);
        // The handler's floor check: anything below the floor is a 422; the floor
        // itself and above pass. We assert the boundary the handler uses.
        assert!(59 < verity_storage::SYNC_INTERVAL_FLOOR_SECS);
        assert!(60 >= verity_storage::SYNC_INTERVAL_FLOOR_SECS);
    }

    #[test]
    fn double_poll_warning_fires_only_when_env_lists_the_source() {
        // Env unset → no warning.
        std::env::remove_var("VERITY_CONNECTORS");
        assert!(double_poll_warning("gdrive").is_none());
        // Env lists the source → a warning naming the source + the config fix.
        std::env::set_var("VERITY_CONNECTORS", "gdrive,gmail");
        let w = double_poll_warning("gdrive").expect("warning when listed");
        assert!(w.contains("gdrive"));
        assert!(w.contains("VERITY_CONNECTORS"));
        // A source NOT listed → no warning.
        assert!(double_poll_warning("hubspot").is_none());

        // CASE-INSENSITIVE: the Python knowledge worker lowercases each token
        // (config.py enabled_connectors → `token.strip().lower()`), so
        // `"HubSpot"`/`"GDrive"` DO arm the Temporal schedule. A case-sensitive
        // Rust guard would miss a capitalized env value and let both pollers
        // advance the same cursor silently — the warning MUST fire regardless of
        // case (kept in this one test since all mutate the shared env var).
        std::env::set_var("VERITY_CONNECTORS", "HubSpot, GDrive");
        assert!(double_poll_warning("hubspot")
            .expect("warning fires for capitalized env value")
            .contains("hubspot"));
        assert!(double_poll_warning("gdrive").is_some());
        std::env::remove_var("VERITY_CONNECTORS");
    }
}
