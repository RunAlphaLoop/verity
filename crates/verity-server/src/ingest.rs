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
pub fn parse_envelope(body: &Value, pk: &str) -> Result<ChangeEvent, IngestError> {
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

    Ok(ChangeEvent {
        source,
        entity_id,
        op,
        fields,
        occurred_at,
        raw: payload.clone(),
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

    #[test]
    fn parses_wrapped_update() {
        let ev = parse_envelope(&wrapped_update(), "id").unwrap();
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
        let ev = parse_envelope(&bare, "id").unwrap();
        assert_eq!(ev.op, Op::Delete);
        assert_eq!(ev.entity_id, "deal-7");
        assert_eq!(ev.source, "mysql:crm.deals"); // no schema segment
        assert!(ev.fields.is_empty());
    }

    #[test]
    fn rejects_garbage_and_missing_pk() {
        assert!(matches!(
            parse_envelope(&json!({"hello": "world"}), "id"),
            Err(IngestError::NotAnEnvelope)
        ));
        let no_pk = json!({
            "after": {"amount": 1},
            "source": {"table": "t"},
            "op": "c"
        });
        assert!(matches!(
            parse_envelope(&no_pk, "id"),
            Err(IngestError::MissingPk(_))
        ));
    }
}
