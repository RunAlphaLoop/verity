//! Debezium change-event envelope input (SPEC §5, push lane): first-class
//! CDC ingestion, so any database Debezium speaks to becomes a live memory
//! source. One envelope in → one L0 episode + deterministic L1 upserts out;
//! no LLM, no embedding for structured fields.
//!
//! Accepted shapes: the standard `{"schema": ..., "payload": {...}}` wrapper,
//! the bare payload object (ExtractNewRecordState-less pipelines vary), or a
//! JSON array of either for batching. The row's primary-key field is `pk`
//! (default "id") — Debezium's HTTP sink carries the key inside the row
//! image, not as a separate part.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use verity_core::{Confidentiality, PrincipalToken};

/// The visibility a change event resolved to at the SPEC §5e ACL choke point.
/// A Debezium envelope carries no native ACL, so visibility is materialized from
/// one of two explicit sources, in precedence order: (1) an inline `verity_acl`
/// block on the payload (envelope-declared), else (2) a static policy bound to
/// the connector at ingest time (`IngestParams`). When NEITHER resolves, the
/// fact is REFUSED — never indexed at a permissive tenant-wide default (fail
/// closed, non-negotiable). An empty token set is itself a refusal (a fact
/// nobody can read), never "visible to all".
#[derive(Debug, Clone)]
pub struct ResolvedAcl {
    pub visibility: Vec<PrincipalToken>,
    pub confidentiality: Confidentiality,
    /// How the tokens were obtained, for the fact's `acl_provenance` label and
    /// the audit trail. `Mirrored` = the envelope declared them; `AdminAssigned`
    /// = the connector-bound static policy supplied them.
    pub provenance: verity_core::AclProvenance,
}

/// A parsed change event, normalized from the Debezium envelope.
#[derive(Debug)]
pub struct ChangeEvent {
    /// "{connector}:{db}.{schema}.{table}" — the L1 `source` partition.
    pub source: String,
    pub entity_id: String,
    pub op: Op,
    /// Field → value from the row's `after` image (empty for deletes).
    pub fields: Vec<(String, Value)>,
    /// Event time: source ts_ms when present, else envelope ts_ms.
    pub occurred_at: DateTime<Utc>,
    /// The resolved visibility for every fact this event writes. `None` when the
    /// envelope declared no inline ACL AND the connector bound no static policy
    /// — the caller then REFUSES the upsert (fail closed). Always `None` for a
    /// Delete (a delete carries no new value to make visible).
    pub acl: Option<ResolvedAcl>,
    /// The raw payload, preserved verbatim for L0.
    pub raw: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// c = create, u = update, r = snapshot read — all deterministic upserts.
    Upsert,
    /// d = delete — retires the entity's current facts (SPEC §8c).
    Delete,
}

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("not a Debezium envelope: missing payload.op")]
    NotAnEnvelope,
    #[error("unsupported op {0:?}")]
    UnsupportedOp(String),
    #[error("missing row image for op")]
    MissingRowImage,
    #[error("primary key field {0:?} absent from row image")]
    MissingPk(String),
}

/// Parse one envelope (wrapped or bare payload) into a normalized event.
///
/// `bound_policy` is the static ACL policy the admin bound to this connector at
/// ingest time (`IngestParams`), used when the envelope declares no inline ACL.
/// `parse_envelope` resolves visibility HERE — the write-path choke point — so
/// no permissive default can slip past: an Upsert whose ACL resolves to nothing
/// yields `acl: None`, and the caller refuses it (SPEC §5e, fail closed).
pub fn parse_envelope(
    body: &Value,
    pk: &str,
    bound_policy: Option<&ResolvedAcl>,
) -> Result<ChangeEvent, IngestError> {
    // Standard envelope wraps the payload; SMT-flattened pipelines post it bare.
    let payload = match body.get("payload") {
        Some(p) if p.get("op").is_some() => p,
        _ if body.get("op").is_some() => body,
        _ => return Err(IngestError::NotAnEnvelope),
    };

    let op = match payload.get("op").and_then(Value::as_str) {
        Some("c") | Some("u") | Some("r") => Op::Upsert,
        Some("d") => Op::Delete,
        other => return Err(IngestError::UnsupportedOp(format!("{other:?}"))),
    };

    let source_meta = payload.get("source").unwrap_or(&Value::Null);
    let get = |k: &str| source_meta.get(k).and_then(Value::as_str).unwrap_or("");
    let mut source = format!(
        "{}:{}",
        non_empty(get("connector"), "debezium"),
        [get("db"), get("schema"), get("table")]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(".")
    );
    if source.ends_with(':') {
        source.push_str("unknown");
    }

    let image = match op {
        Op::Upsert => payload.get("after"),
        Op::Delete => payload.get("before").or_else(|| payload.get("after")),
    }
    .and_then(Value::as_object)
    .ok_or(IngestError::MissingRowImage)?;

    let entity_id = image
        .get(pk)
        .map(json_scalar_to_string)
        .ok_or_else(|| IngestError::MissingPk(pk.to_string()))?;

    let fields = match op {
        Op::Delete => Vec::new(),
        Op::Upsert => image
            .iter()
            .filter(|(k, _)| k.as_str() != pk)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };

    let ts_ms = source_meta
        .get("ts_ms")
        .or_else(|| payload.get("ts_ms"))
        .and_then(Value::as_i64);
    let occurred_at = ts_ms
        .and_then(|ms| Utc.timestamp_millis_opt(ms).single())
        .unwrap_or_else(Utc::now);

    // Resolve the ACL at the choke point. A delete carries no new value, so it
    // needs no visibility. For an upsert: an inline `verity_acl` block on the
    // payload (envelope-declared, provenance Mirrored) wins over the connector's
    // bound static policy (provenance AdminAssigned); neither present => None,
    // and the caller refuses the fact rather than defaulting it permissive.
    let acl = match op {
        Op::Delete => None,
        Op::Upsert => parse_inline_acl(payload).or_else(|| bound_policy.cloned()),
    };

    Ok(ChangeEvent {
        source,
        entity_id,
        op,
        fields,
        occurred_at,
        acl,
        raw: payload.clone(),
    })
}

/// Read an inline `verity_acl` extension block off the payload, when a pipeline
/// has been configured to carry source ACLs alongside the row image:
/// `"verity_acl": {"visibility": [3,7], "confidentiality": "confidential"}`.
/// Absent or malformed => `None` (fall back to the bound policy, then refuse) —
/// a malformed ACL is NEVER read as permissive.
fn parse_inline_acl(payload: &Value) -> Option<ResolvedAcl> {
    let block = payload.get("verity_acl")?.as_object()?;
    let visibility: Vec<PrincipalToken> = block
        .get("visibility")?
        .as_array()?
        .iter()
        .map(|v| v.as_i64().map(|n| n as PrincipalToken))
        .collect::<Option<Vec<_>>>()?;
    // Confidentiality defaults to the strictest sane class (Internal, matching
    // the connector plane) when the block omits it — never widened to Public.
    let confidentiality = match block.get("confidentiality") {
        None => Confidentiality::Internal,
        Some(v) => serde_json::from_value(v.clone()).ok()?,
    };
    Some(ResolvedAcl {
        visibility,
        confidentiality,
        provenance: verity_core::AclProvenance::Mirrored,
    })
}

fn non_empty<'a>(s: &'a str, fallback: &'a str) -> &'a str {
    if s.is_empty() {
        fallback
    } else {
        s
    }
}

/// PK values arrive as numbers or strings; L1 entity ids are strings.
fn json_scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wrapped_update() -> Value {
        json!({
            "schema": {"type": "struct"},
            "payload": {
                "before": {"id": 42, "amount": 50000, "stage": "negotiation"},
                "after": {"id": 42, "amount": 84000, "stage": "negotiation"},
                "source": {"connector": "postgresql", "db": "crm", "schema": "public",
                           "table": "opportunities", "ts_ms": 1751980800000i64},
                "op": "u",
                "ts_ms": 1751980801000i64
            }
        })
    }

    fn admin_policy() -> ResolvedAcl {
        ResolvedAcl {
            visibility: vec![100, 200],
            confidentiality: Confidentiality::Internal,
            provenance: verity_core::AclProvenance::AdminAssigned,
        }
    }

    #[test]
    fn parses_wrapped_update() {
        let ev = parse_envelope(&wrapped_update(), "id", None).unwrap();
        assert_eq!(ev.source, "postgresql:crm.public.opportunities");
        assert_eq!(ev.entity_id, "42");
        assert_eq!(ev.op, Op::Upsert);
        // pk excluded, both data fields present
        assert_eq!(ev.fields.len(), 2);
        assert!(ev
            .fields
            .iter()
            .any(|(k, v)| k == "amount" && *v == json!(84000)));
        // event time comes from source.ts_ms, not envelope ts_ms
        assert_eq!(ev.occurred_at.timestamp_millis(), 1751980800000);
    }

    #[test]
    fn parses_bare_payload_and_delete() {
        let bare = json!({
            "before": {"id": "deal-7", "amount": 1000},
            "after": null,
            "source": {"connector": "mysql", "db": "crm", "table": "deals", "ts_ms": 1000i64},
            "op": "d"
        });
        let ev = parse_envelope(&bare, "id", Some(&admin_policy())).unwrap();
        assert_eq!(ev.op, Op::Delete);
        // A delete carries no new value, so it resolves no ACL even when a
        // bound policy exists — retire-entity governs deletes, not visibility.
        assert!(ev.acl.is_none());
        assert_eq!(ev.entity_id, "deal-7");
        assert_eq!(ev.source, "mysql:crm.deals"); // no schema segment
        assert!(ev.fields.is_empty());
    }

    #[test]
    fn rejects_garbage_and_missing_pk() {
        assert!(matches!(
            parse_envelope(&json!({"hello": "world"}), "id", None),
            Err(IngestError::NotAnEnvelope)
        ));
        let no_pk = json!({
            "after": {"amount": 1},
            "source": {"table": "t"},
            "op": "c"
        });
        assert!(matches!(
            parse_envelope(&no_pk, "id", None),
            Err(IngestError::MissingPk(_))
        ));
    }

    #[test]
    fn upsert_without_any_acl_resolves_none() {
        // No inline block, no bound policy => acl None => the handler refuses
        // the fact (fail closed). This is the exact leak the write path closes:
        // absent ACL must never become a permissive tenant-wide default.
        let ev = parse_envelope(&wrapped_update(), "id", None).unwrap();
        assert!(ev.acl.is_none());
    }

    #[test]
    fn bound_policy_materializes_when_no_inline_block() {
        let ev = parse_envelope(&wrapped_update(), "id", Some(&admin_policy())).unwrap();
        let acl = ev.acl.expect("bound policy should materialize an ACL");
        assert_eq!(acl.visibility, vec![100, 200]);
        assert_eq!(acl.confidentiality, Confidentiality::Internal);
        assert_eq!(acl.provenance, verity_core::AclProvenance::AdminAssigned);
    }

    #[test]
    fn inline_acl_block_wins_over_bound_policy() {
        let mut env = wrapped_update();
        env["payload"]["verity_acl"] =
            json!({"visibility": [7, 9], "confidentiality": "confidential"});
        // Bound policy present, but the envelope declared its own ACL — the
        // declared (mirrored) ACL wins.
        let ev = parse_envelope(&env, "id", Some(&admin_policy())).unwrap();
        let acl = ev.acl.expect("inline ACL should materialize");
        assert_eq!(acl.visibility, vec![7, 9]);
        assert_eq!(acl.confidentiality, Confidentiality::Confidential);
        assert_eq!(acl.provenance, verity_core::AclProvenance::Mirrored);
    }

    #[test]
    fn malformed_inline_acl_is_not_permissive() {
        // A `verity_acl` block with a non-array visibility is malformed. It must
        // NOT be read as permissive — it falls through to the bound policy (here
        // absent), so the fact resolves to None and is refused.
        let mut env = wrapped_update();
        env["payload"]["verity_acl"] = json!({"visibility": "everyone"});
        let ev = parse_envelope(&env, "id", None).unwrap();
        assert!(ev.acl.is_none());
    }
}
