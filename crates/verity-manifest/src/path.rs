//! The Verity dot-path subset (SPEC §5e.3 fallback dialect).
//!
//! Grammar:
//! ```text
//! expr    := "$now()" | path
//! path    := segment ("." segment)*
//! segment := key accessor*
//! key     := [A-Za-z0-9_$-]+
//! accessor:= "[" digits "]"      # index into an array
//!          | "[]"                # every element (flatten)
//! ```
//! Evaluation is a bounded, non-recursive walk: missing keys/indices yield
//! *no values* (never null-coercion), and `[]` fans out over arrays. Callers
//! decide whether zero values is an error (mapping: quarantine) or merely
//! false (routing predicates).

use serde_json::Value;

use crate::limits;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("expression exceeds {} chars", limits::MAX_EXPR_CHARS)]
    TooLong,
    #[error("path exceeds {} segments", limits::MAX_PATH_SEGMENTS)]
    TooDeep,
    #[error("empty path")]
    Empty,
    #[error("bad path syntax at {0:?}")]
    BadSyntax(String),
    #[error("array index exceeds {}", limits::MAX_ARRAY_INDEX)]
    IndexTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Accessor {
    Index(usize),
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    key: String,
    accessors: Vec<Accessor>,
}

/// A parsed dot-path. Parsing happens once at manifest validation; evaluation
/// never sees unparsed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    segments: Vec<Segment>,
    text: String,
}

/// A mapping expression: a dot-path or the `$now()` builtin (the only
/// function in the subset — no user-defined functions, no eval).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Now,
    Path(Path),
}

impl Expr {
    pub fn parse(s: &str) -> Result<Self, PathError> {
        let s = s.trim();
        if s == "$now()" {
            return Ok(Expr::Now);
        }
        Path::parse(s).map(Expr::Path)
    }

    pub fn as_text(&self) -> &str {
        match self {
            Expr::Now => "$now()",
            Expr::Path(p) => &p.text,
        }
    }
}

impl Path {
    pub fn parse(s: &str) -> Result<Self, PathError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(PathError::Empty);
        }
        if s.chars().count() > limits::MAX_EXPR_CHARS {
            return Err(PathError::TooLong);
        }
        let mut segments = Vec::new();
        for raw in s.split('.') {
            if segments.len() >= limits::MAX_PATH_SEGMENTS {
                return Err(PathError::TooDeep);
            }
            segments.push(parse_segment(raw)?);
        }
        Ok(Self {
            segments,
            text: s.to_string(),
        })
    }

    pub fn as_text(&self) -> &str {
        &self.text
    }

    /// Evaluate against a payload root. Missing keys and out-of-range indices
    /// produce no values; `[]` flattens arrays. Bounded by construction: the
    /// walk visits at most (values × segments) nodes, no recursion.
    pub fn eval<'a>(&self, root: &'a Value) -> Vec<&'a Value> {
        let mut current: Vec<&'a Value> = vec![root];
        for segment in &self.segments {
            let mut next = Vec::new();
            for value in current {
                let Some(child) = value.get(segment.key.as_str()) else {
                    continue;
                };
                let mut hits = vec![child];
                for accessor in &segment.accessors {
                    let mut widened = Vec::new();
                    for hit in hits {
                        match accessor {
                            Accessor::Index(i) => {
                                if let Some(v) = hit.get(*i) {
                                    widened.push(v);
                                }
                            }
                            Accessor::All => {
                                if let Some(items) = hit.as_array() {
                                    widened.extend(items.iter());
                                }
                            }
                        }
                    }
                    hits = widened;
                }
                next.extend(hits);
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }
        current
    }

    /// Exactly-one evaluation for scalar contexts (pk, valid_from, map
    /// values). Zero or multiple hits are both None — the caller fails closed.
    pub fn eval_scalar<'a>(&self, root: &'a Value) -> Option<&'a Value> {
        let hits = self.eval(root);
        match hits.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

fn parse_segment(raw: &str) -> Result<Segment, PathError> {
    let (key, mut rest) = match raw.find('[') {
        Some(i) => (&raw[..i], &raw[i..]),
        None => (raw, ""),
    };
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '-'))
    {
        return Err(PathError::BadSyntax(raw.to_string()));
    }
    let mut accessors = Vec::new();
    while !rest.is_empty() {
        let Some(stripped) = rest.strip_prefix('[') else {
            return Err(PathError::BadSyntax(raw.to_string()));
        };
        let Some(end) = stripped.find(']') else {
            return Err(PathError::BadSyntax(raw.to_string()));
        };
        let inside = &stripped[..end];
        if inside.is_empty() {
            accessors.push(Accessor::All);
        } else {
            let idx: usize = inside
                .parse()
                .map_err(|_| PathError::BadSyntax(raw.to_string()))?;
            if idx > limits::MAX_ARRAY_INDEX {
                return Err(PathError::IndexTooLarge);
            }
            accessors.push(Accessor::Index(idx));
        }
        rest = &stripped[end + 1..];
    }
    Ok(Segment {
        key: key.to_string(),
        accessors,
    })
}

/// Nesting depth of a JSON value, for the pre-evaluation payload cap.
pub fn value_depth(v: &Value) -> usize {
    // Iterative to keep hostile payloads from recursing the checker itself.
    let mut depth = 0usize;
    let mut stack = vec![(v, 1usize)];
    while let Some((value, d)) = stack.pop() {
        depth = depth.max(d);
        if d > limits::MAX_PAYLOAD_DEPTH {
            return d; // already over the cap, no need to finish
        }
        match value {
            Value::Array(items) => stack.extend(items.iter().map(|i| (i, d + 1))),
            Value::Object(map) => stack.extend(map.values().map(|i| (i, d + 1))),
            _ => {}
        }
    }
    depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_paths_and_indices() {
        let v = json!({"data": {"title": "T", "labels": [{"name": "bug"}, {"name": "p1"}]}});
        assert_eq!(
            Path::parse("data.title").unwrap().eval_scalar(&v),
            Some(&json!("T"))
        );
        assert_eq!(
            Path::parse("data.labels[1].name").unwrap().eval_scalar(&v),
            Some(&json!("p1"))
        );
        // Missing path: no values, not null.
        assert!(Path::parse("data.nope").unwrap().eval(&v).is_empty());
        assert!(Path::parse("data.labels[9].name")
            .unwrap()
            .eval(&v)
            .is_empty());
    }

    #[test]
    fn wildcard_flattens() {
        let v = json!({"team": {"members": [{"id": "u1"}, {"id": "u2"}]}});
        let hits = Path::parse("team.members[].id").unwrap().eval(&v);
        assert_eq!(hits, vec![&json!("u1"), &json!("u2")]);
        // Multi-hit is not a scalar.
        assert!(Path::parse("team.members[].id")
            .unwrap()
            .eval_scalar(&v)
            .is_none());
    }

    #[test]
    fn limits_and_syntax_are_enforced() {
        assert_eq!(Path::parse(""), Err(PathError::Empty));
        assert!(matches!(Path::parse("a..b"), Err(PathError::BadSyntax(_))));
        assert!(matches!(Path::parse("a[x]"), Err(PathError::BadSyntax(_))));
        assert!(matches!(Path::parse("a b"), Err(PathError::BadSyntax(_))));
        assert_eq!(Path::parse("a[99999999]"), Err(PathError::IndexTooLarge));
        let deep = vec!["k"; crate::limits::MAX_PATH_SEGMENTS + 1].join(".");
        assert_eq!(Path::parse(&deep), Err(PathError::TooDeep));
        let long = "a".repeat(crate::limits::MAX_EXPR_CHARS + 1);
        assert_eq!(Path::parse(&long), Err(PathError::TooLong));
    }

    #[test]
    fn now_builtin() {
        assert_eq!(Expr::parse(" $now() ").unwrap(), Expr::Now);
        assert!(matches!(Expr::parse("data.x").unwrap(), Expr::Path(_)));
        // $now with arguments or as a path is rejected.
        assert!(Expr::parse("$now(1)").is_err());
    }

    #[test]
    fn depth_check() {
        let mut v = json!(1);
        for _ in 0..70 {
            v = json!([v]);
        }
        assert!(value_depth(&v) > crate::limits::MAX_PAYLOAD_DEPTH);
        assert_eq!(value_depth(&json!({"a": {"b": 1}})), 3);
    }
}
