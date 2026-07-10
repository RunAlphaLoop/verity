//! The manifest runtime: one inbound JSON payload in → a deterministic set of
//! writes out, or a quarantine. No LLM, no eval, no network — a bounded
//! interpretation of the parsed manifest.
//!
//! Fail-closed rules (SPEC §5e.3 / §5e.6):
//! - no entity route claims the payload ⇒ quarantine ("unmatched routes →
//!   quarantine_preview");
//! - a declared mapping path (primary_key, valid_from, map.*, content,
//!   acl principals) missing or non-scalar ⇒ quarantine the WHOLE payload —
//!   never a partial or mis-filed write;
//! - acl_policy absent or mode quarantine ⇒ quarantine;
//! - `map` mode extracting zero principals ⇒ quarantine;
//! - payload deeper than the cap or output larger than the cap ⇒ quarantine.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};

use crate::limits;
use crate::path::{value_depth, Expr, Path};
use crate::predicate::Predicate;
use crate::schema::{AclMode, EntitySpec, IdentityNamespace, Manifest};

/// Injectable clock so `$now()` is deterministic under the conformance
/// harness (fixtures pin it to 2026-01-01T00:00:00Z).
#[derive(Debug, Clone, Copy)]
pub struct RuntimeOptions {
    pub now: DateTime<Utc>,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self { now: Utc::now() }
    }
}

impl RuntimeOptions {
    /// The fixed clock the conformance harness runs fixtures under.
    pub fn fixture_clock() -> Self {
        Self {
            now: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        }
    }
}

/// How the visibility of this payload's writes was determined. The server
/// maps this to principal tokens + an AclProvenance tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclEnvelope {
    /// `static` mode → admin-assigned provenance. `principals: None` means
    /// "use the binding webhook's mint-time visibility".
    Static { principals: Option<Vec<String>> },
    /// `map` mode → mirrored (Tier A) / approximated provenance. Principal
    /// strings are already namespaced (`user:…`, `<source>:…`, `group:…`).
    Mapped {
        principals: Vec<String>,
        approximated: bool,
    },
}

impl AclEnvelope {
    /// Canonical JSON — what fixtures assert against.
    pub fn to_json(&self, namespace: Option<IdentityNamespace>) -> Value {
        match self {
            AclEnvelope::Static { principals } => json!({
                "mode": "static",
                "acl_provenance": "admin-assigned",
                "principals": principals,
            }),
            AclEnvelope::Mapped {
                principals,
                approximated,
            } => json!({
                "mode": "map",
                "acl_provenance": if *approximated { "approximated" } else { "mirrored" },
                "identity_namespace": namespace.map(|n| match n {
                    IdentityNamespace::Email => "email",
                    IdentityNamespace::SourceNativeId => "source_native_id",
                    IdentityNamespace::VerityGroup => "verity_group",
                }),
                "principals": principals,
            }),
        }
    }
}

/// All writes derived from one matched entity block.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityWrites {
    pub entity_type: String,
    /// Deterministic primary key → idempotent duplicate absorption.
    pub entity_id: String,
    /// Bi-temporal event time for the fact upserts.
    pub valid_from: DateTime<Utc>,
    /// field → value, in declared (sorted) order.
    pub fields: Vec<(String, Value)>,
    /// Free-text chunk content, when the entity declares `content`.
    pub content: Option<String>,
}

impl EntityWrites {
    /// Canonical JSON for one write — the fixture `expect.facts` unit.
    pub fn to_json(&self) -> Value {
        let fields: serde_json::Map<String, Value> = self
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        json!({
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "valid_from": self.valid_from.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "fields": fields,
        })
    }
}

/// Runtime output for one payload.
#[derive(Debug, Clone, PartialEq)]
pub enum Applied {
    Writes {
        /// The L1 `source` partition — the manifest's source name.
        source: String,
        writes: Vec<EntityWrites>,
        /// One envelope covering every write from this payload (the policy is
        /// per-source, evaluated per-payload).
        acl: AclEnvelope,
    },
    Quarantine {
        reason: String,
    },
}

impl Applied {
    pub fn quarantine_reason(&self) -> Option<&str> {
        match self {
            Applied::Quarantine { reason } => Some(reason),
            Applied::Writes { .. } => None,
        }
    }
}

fn quarantine(reason: impl Into<String>) -> Applied {
    Applied::Quarantine {
        reason: reason.into(),
    }
}

/// Apply a validated manifest to one inbound payload.
pub fn apply(manifest: &Manifest, payload: &Value, opts: &RuntimeOptions) -> Applied {
    if value_depth(payload) > limits::MAX_PAYLOAD_DEPTH {
        return quarantine(format!(
            "payload nesting exceeds the {} level cap",
            limits::MAX_PAYLOAD_DEPTH
        ));
    }

    let mut writes = Vec::new();
    let mut output_bytes = 0usize;
    for entity in &manifest.entities {
        // Validated at parse; re-parse here keeps the runtime total.
        let Ok(when) = Predicate::parse(&entity.route.when) else {
            return quarantine(format!("entity {:?}: unparseable route", entity.r#type));
        };
        if !when.matches(payload) {
            continue;
        }
        match extract_entity(entity, payload, opts, &mut output_bytes) {
            Ok(w) => writes.push(w),
            Err(reason) => return quarantine(reason),
        }
    }
    if writes.is_empty() {
        return quarantine("no entity route matched the payload");
    }
    // The ACL gate stands between mapped writes and the index: no policy,
    // quarantine mode, or failed principal extraction ⇒ nothing indexes.
    let acl = match evaluate_acl(manifest, payload) {
        Ok(acl) => acl,
        Err(reason) => return quarantine(reason),
    };
    Applied::Writes {
        source: manifest.source.name.clone(),
        writes,
        acl,
    }
}

fn evaluate_acl(manifest: &Manifest, payload: &Value) -> Result<AclEnvelope, String> {
    let Some(policy) = &manifest.acl_policy else {
        return Err(
            "acl_policy absent — manifest can only quarantine until an admin adds one".to_string(),
        );
    };
    match policy.mode {
        AclMode::Quarantine => Err("acl_policy.mode is quarantine".to_string()),
        AclMode::Static => Ok(AclEnvelope::Static {
            principals: policy.static_visibility.clone(),
        }),
        AclMode::Map => {
            let expr = policy
                .principals
                .as_deref()
                .ok_or_else(|| "acl_policy.mode map without principals".to_string())?;
            let path = Path::parse(expr).map_err(|e| format!("acl principals path: {e}"))?;
            let namespace = policy
                .identity_namespace
                .ok_or_else(|| "acl_policy.mode map without identity_namespace".to_string())?;
            let hits = path.eval(payload);
            if hits.is_empty() {
                return Err(format!(
                    "acl principal extraction {expr:?} matched nothing — refusing to index"
                ));
            }
            if hits.len() > limits::MAX_PRINCIPALS {
                return Err(format!(
                    "acl principal extraction produced more than {} principals",
                    limits::MAX_PRINCIPALS
                ));
            }
            let mut principals = Vec::with_capacity(hits.len());
            for hit in hits {
                let raw = scalar_to_string(hit)
                    .ok_or_else(|| format!("acl principal at {expr:?} is not a scalar: {hit}"))?;
                principals.push(namespaced_principal(namespace, &manifest.source.name, &raw));
            }
            principals.sort();
            principals.dedup();
            Ok(AclEnvelope::Mapped {
                principals,
                approximated: policy.approximation,
            })
        }
    }
}

/// The principal-registry string an extracted id resolves under (documented
/// on `IdentityNamespace`).
pub fn namespaced_principal(namespace: IdentityNamespace, source_name: &str, raw: &str) -> String {
    match namespace {
        IdentityNamespace::Email => format!("user:{raw}"),
        IdentityNamespace::SourceNativeId => format!("{source_name}:{raw}"),
        IdentityNamespace::VerityGroup => format!("group:{raw}"),
    }
}

fn extract_entity(
    entity: &EntitySpec,
    payload: &Value,
    opts: &RuntimeOptions,
    output_bytes: &mut usize,
) -> Result<EntityWrites, String> {
    let t = &entity.r#type;
    let pk_path =
        Path::parse(&entity.primary_key).map_err(|e| format!("entity {t:?} primary_key: {e}"))?;
    let entity_id = pk_path
        .eval_scalar(payload)
        .and_then(scalar_to_string)
        .ok_or_else(|| {
            format!(
                "entity {t:?}: primary_key {:?} missing or non-scalar — quarantining, not mis-filing",
                entity.primary_key
            )
        })?;

    let valid_from = match &entity.valid_from {
        None => opts.now,
        Some(expr_text) => {
            let expr =
                Expr::parse(expr_text).map_err(|e| format!("entity {t:?} valid_from: {e}"))?;
            eval_timestamp(&expr, payload, opts).ok_or_else(|| {
                format!(
                    "entity {t:?}: valid_from {expr_text:?} missing or not a timestamp — \
                     quarantining, not mis-filing"
                )
            })?
        }
    };

    let mut fields = Vec::with_capacity(entity.map.len());
    for (field, expr_text) in &entity.map {
        let expr = Expr::parse(expr_text).map_err(|e| format!("entity {t:?} map.{field}: {e}"))?;
        let value = match expr {
            Expr::Now => json!(opts
                .now
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            Expr::Path(path) => path.eval_scalar(payload).cloned().ok_or_else(|| {
                format!(
                    "entity {t:?}: map.{field} path {expr_text:?} missing or non-scalar — \
                         quarantining, not mis-filing"
                )
            })?,
        };
        let size = value.to_string().len();
        if size > limits::MAX_VALUE_BYTES {
            return Err(format!(
                "entity {t:?}: map.{field} exceeds the {} byte value cap",
                limits::MAX_VALUE_BYTES
            ));
        }
        *output_bytes += size;
        if *output_bytes > limits::MAX_OUTPUT_BYTES {
            return Err(format!(
                "payload output exceeds the {} byte cap",
                limits::MAX_OUTPUT_BYTES
            ));
        }
        fields.push((field.clone(), value));
    }

    let content = match &entity.content {
        None => None,
        Some(expr_text) => {
            let path = Path::parse(expr_text).map_err(|e| format!("entity {t:?} content: {e}"))?;
            let value = path.eval_scalar(payload).ok_or_else(|| {
                format!(
                    "entity {t:?}: content path {expr_text:?} missing — quarantining, not mis-filing"
                )
            })?;
            let text = value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("entity {t:?}: content at {expr_text:?} is not text"))?;
            if text.len() > limits::MAX_VALUE_BYTES {
                return Err(format!(
                    "entity {t:?}: content exceeds the {} byte cap",
                    limits::MAX_VALUE_BYTES
                ));
            }
            *output_bytes += text.len();
            if *output_bytes > limits::MAX_OUTPUT_BYTES {
                return Err(format!(
                    "payload output exceeds the {} byte cap",
                    limits::MAX_OUTPUT_BYTES
                ));
            }
            Some(text)
        }
    };

    Ok(EntityWrites {
        entity_type: t.clone(),
        entity_id,
        valid_from,
        fields,
        content,
    })
}

fn eval_timestamp(expr: &Expr, payload: &Value, opts: &RuntimeOptions) -> Option<DateTime<Utc>> {
    match expr {
        Expr::Now => Some(opts.now),
        Expr::Path(path) => match path.eval_scalar(payload)? {
            Value::String(s) => DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc)),
            Value::Number(n) => {
                let ms = n.as_i64()?;
                Utc.timestamp_millis_opt(ms).single()
            }
            _ => None,
        },
    }
}

/// PK/principal values arrive as strings or numbers; ids are strings.
fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
manifest_version: 1
source:
  name: linear
  tier: B
entities:
  - type: issue
    route:
      when: "type = 'Issue' and action in ['create','update']"
    primary_key: "data.id"
    valid_from: "data.updatedAt"
    map:
      title: "data.title"
      state: "data.state.name"
      observed: "$now()"
acl_policy:
  mode: map
  identity_namespace: source_native_id
  principals: "data.team.id"
  approximation: true
  note: "Team membership approximates issue visibility."
"#;

    fn payload() -> Value {
        json!({
            "action": "update",
            "type": "Issue",
            "data": {
                "id": "iss_1",
                "title": "Fix the webhook",
                "updatedAt": "2026-07-01T12:00:00.000Z",
                "state": {"name": "In Progress"},
                "team": {"id": "team_9"}
            }
        })
    }

    #[test]
    fn maps_a_matched_payload() {
        let m = Manifest::from_yaml(MANIFEST).unwrap();
        let opts = RuntimeOptions::fixture_clock();
        let Applied::Writes {
            source,
            writes,
            acl,
        } = apply(&m, &payload(), &opts)
        else {
            panic!("expected writes");
        };
        assert_eq!(source, "linear");
        assert_eq!(writes.len(), 1);
        let w = &writes[0];
        assert_eq!(w.entity_id, "iss_1");
        assert_eq!(
            w.valid_from
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2026-07-01T12:00:00.000Z"
        );
        assert_eq!(
            w.fields,
            vec![
                ("observed".to_string(), json!("2026-01-01T00:00:00.000Z")),
                ("state".to_string(), json!("In Progress")),
                ("title".to_string(), json!("Fix the webhook")),
            ]
        );
        assert_eq!(
            acl,
            AclEnvelope::Mapped {
                principals: vec!["linear:team_9".into()],
                approximated: true,
            }
        );
    }

    #[test]
    fn unmatched_route_quarantines() {
        let m = Manifest::from_yaml(MANIFEST).unwrap();
        let out = apply(
            &m,
            &json!({"type": "Project", "action": "create"}),
            &RuntimeOptions::fixture_clock(),
        );
        assert!(out
            .quarantine_reason()
            .expect("quarantined")
            .contains("no entity route matched"));
    }

    #[test]
    fn missing_mapped_path_quarantines_not_misfiles() {
        let m = Manifest::from_yaml(MANIFEST).unwrap();
        let mut p = payload();
        p["data"].as_object_mut().unwrap().remove("title");
        let out = apply(&m, &p, &RuntimeOptions::fixture_clock());
        let reason = out.quarantine_reason().expect("quarantined");
        assert!(reason.contains("map.title"), "{reason}");
        // Missing pk and missing valid_from quarantine too.
        let mut p = payload();
        p["data"].as_object_mut().unwrap().remove("id");
        assert!(apply(&m, &p, &RuntimeOptions::fixture_clock())
            .quarantine_reason()
            .expect("quarantined")
            .contains("primary_key"));
        let mut p = payload();
        p["data"]["updatedAt"] = json!("not-a-date");
        assert!(apply(&m, &p, &RuntimeOptions::fixture_clock())
            .quarantine_reason()
            .expect("quarantined")
            .contains("valid_from"));
    }

    #[test]
    fn acl_failures_quarantine() {
        // Principal path missing from the payload.
        let m = Manifest::from_yaml(MANIFEST).unwrap();
        let mut p = payload();
        p["data"].as_object_mut().unwrap().remove("team");
        let out = apply(&m, &p, &RuntimeOptions::fixture_clock());
        assert!(out
            .quarantine_reason()
            .expect("quarantined")
            .contains("principal extraction"));

        // No acl_policy at all: parses, but the runtime fails closed.
        let no_acl = MANIFEST.split("acl_policy:").next().unwrap();
        let m = Manifest::from_yaml(no_acl).unwrap();
        assert!(apply(&m, &payload(), &RuntimeOptions::fixture_clock())
            .quarantine_reason()
            .expect("quarantined")
            .contains("acl_policy absent"));
    }

    #[test]
    fn map_mode_wildcard_principals() {
        let manifest = MANIFEST.replace("data.team.id", "data.subscribers[].id");
        let m = Manifest::from_yaml(&manifest).unwrap();
        let mut p = payload();
        p["data"]["subscribers"] = json!([{"id": "u2"}, {"id": "u1"}, {"id": "u2"}]);
        let Applied::Writes { acl, .. } = apply(&m, &p, &RuntimeOptions::fixture_clock()) else {
            panic!("expected writes");
        };
        assert_eq!(
            acl,
            AclEnvelope::Mapped {
                principals: vec!["linear:u1".into(), "linear:u2".into()],
                approximated: true,
            },
            "sorted + deduped"
        );
    }

    #[test]
    fn static_mode_and_deep_payloads() {
        let manifest = MANIFEST.replace(
            "acl_policy:\n  mode: map\n  identity_namespace: source_native_id\n  principals: \"data.team.id\"\n  approximation: true\n  note: \"Team membership approximates issue visibility.\"",
            "acl_policy:\n  mode: static\n  static_visibility: [\"group:eng\"]",
        ).replace("tier: B", "tier: C");
        let m = Manifest::from_yaml(&manifest).unwrap();
        let Applied::Writes { acl, .. } = apply(&m, &payload(), &RuntimeOptions::fixture_clock())
        else {
            panic!("expected writes");
        };
        assert_eq!(
            acl,
            AclEnvelope::Static {
                principals: Some(vec!["group:eng".into()])
            }
        );

        // Hostile nesting quarantines before any mapping runs.
        let m = Manifest::from_yaml(MANIFEST).unwrap();
        let mut deep = json!(1);
        for _ in 0..(limits::MAX_PAYLOAD_DEPTH + 2) {
            deep = json!([deep]);
        }
        assert!(apply(&m, &deep, &RuntimeOptions::fixture_clock())
            .quarantine_reason()
            .expect("quarantined")
            .contains("nesting"));
    }
}
