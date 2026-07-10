//! Purpose packs (roadmap task 7, SPEC §7 purpose binding): declarative
//! per-purpose ceilings applied at scope MINT time. A purpose can only ever
//! CLAMP what the caller asked for — the pack's `max_confidentiality` is
//! min'd with the requested one, never raised — and can require the scope to
//! be entity-bound. Unknown purposes are rejected (fail closed), absent
//! purposes keep current behavior.
//!
//! The pack is YAML, loaded from `VERITY_PURPOSE_PACK` when set; otherwise an
//! embedded default ships sensible ceilings for the common agent purposes.

use std::collections::HashMap;

use serde::Deserialize;

use verity_core::types::Confidentiality;

/// Embedded default pack: conservative ceilings per purpose. Deployments
/// override the whole pack via VERITY_PURPOSE_PACK.
const DEFAULT_PACK: &str = r#"
purposes:
  support_conversation:
    max_confidentiality: internal
    require_entity_scope: true
  sales_negotiation:
    max_confidentiality: confidential
    require_entity_scope: true
  marketing:
    max_confidentiality: public
    require_entity_scope: false
  analytics:
    max_confidentiality: internal
    require_entity_scope: false
  audit:
    max_confidentiality: restricted
    require_entity_scope: false
"#;

#[derive(Debug, Deserialize)]
struct RawPack {
    purposes: HashMap<String, RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    max_confidentiality: String,
    #[serde(default)]
    require_entity_scope: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PurposeRule {
    pub max_confidentiality: Confidentiality,
    pub require_entity_scope: bool,
}

#[derive(Debug)]
pub struct PurposePack {
    purposes: HashMap<String, PurposeRule>,
}

#[derive(Debug, thiserror::Error)]
pub enum PurposeError {
    #[error("invalid purpose pack YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("purpose {purpose:?}: unknown confidentiality {value:?} (expected public|internal|confidential|restricted)")]
    BadConfidentiality { purpose: String, value: String },
}

fn parse_confidentiality(s: &str) -> Option<Confidentiality> {
    match s.to_ascii_lowercase().as_str() {
        "public" => Some(Confidentiality::Public),
        "internal" => Some(Confidentiality::Internal),
        "confidential" => Some(Confidentiality::Confidential),
        "restricted" => Some(Confidentiality::Restricted),
        _ => None,
    }
}

impl PurposePack {
    pub fn parse(yaml: &str) -> Result<Self, PurposeError> {
        let raw: RawPack = serde_yaml_ng::from_str(yaml)?;
        let mut purposes = HashMap::with_capacity(raw.purposes.len());
        for (name, rule) in raw.purposes {
            let max_confidentiality =
                parse_confidentiality(&rule.max_confidentiality).ok_or_else(|| {
                    PurposeError::BadConfidentiality {
                        purpose: name.clone(),
                        value: rule.max_confidentiality.clone(),
                    }
                })?;
            purposes.insert(
                name,
                PurposeRule {
                    max_confidentiality,
                    require_entity_scope: rule.require_entity_scope,
                },
            );
        }
        Ok(Self { purposes })
    }

    /// Pack from `VERITY_PURPOSE_PACK` (path to YAML) or the embedded default.
    /// A set-but-broken pack is a startup error, never a silent fallback — a
    /// deployment that configured ceilings must not run without them.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("VERITY_PURPOSE_PACK") {
            Ok(path) => {
                let yaml = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("reading VERITY_PURPOSE_PACK {path:?}: {e}"))?;
                Ok(Self::parse(&yaml)?)
            }
            Err(_) => Ok(Self::parse(DEFAULT_PACK).expect("embedded default pack parses")),
        }
    }

    pub fn get(&self, purpose: &str) -> Option<&PurposeRule> {
        self.purposes.get(purpose)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pack_parses_with_expected_ceilings() {
        let pack = PurposePack::parse(DEFAULT_PACK).unwrap();
        let support = pack.get("support_conversation").unwrap();
        assert_eq!(support.max_confidentiality, Confidentiality::Internal);
        assert!(support.require_entity_scope);
        let sales = pack.get("sales_negotiation").unwrap();
        assert_eq!(sales.max_confidentiality, Confidentiality::Confidential);
        assert!(sales.require_entity_scope);
        let marketing = pack.get("marketing").unwrap();
        assert_eq!(marketing.max_confidentiality, Confidentiality::Public);
        assert!(!marketing.require_entity_scope);
        let audit = pack.get("audit").unwrap();
        assert_eq!(audit.max_confidentiality, Confidentiality::Restricted);
        assert!(!audit.require_entity_scope);
        assert!(pack.get("world_domination").is_none());
    }

    #[test]
    fn custom_pack_and_clamp_semantics() {
        let pack = PurposePack::parse("purposes:\n  triage:\n    max_confidentiality: Internal\n")
            .unwrap();
        let rule = pack.get("triage").unwrap();
        // Case-insensitive confidentiality, require_entity_scope defaults off.
        assert_eq!(rule.max_confidentiality, Confidentiality::Internal);
        assert!(!rule.require_entity_scope);
        // The clamp is a min: a purpose ceiling never RAISES the request.
        assert_eq!(
            rule.max_confidentiality.min(Confidentiality::Restricted),
            Confidentiality::Internal
        );
        assert_eq!(
            rule.max_confidentiality.min(Confidentiality::Public),
            Confidentiality::Public
        );
    }

    #[test]
    fn broken_packs_are_rejected() {
        assert!(matches!(
            PurposePack::parse("purposes:\n  x:\n    max_confidentiality: ultra\n"),
            Err(PurposeError::BadConfidentiality { .. })
        ));
        assert!(matches!(
            PurposePack::parse("not: a pack"),
            Err(PurposeError::Yaml(_))
        ));
    }
}
