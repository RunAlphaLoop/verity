//! Route `when` predicates: simple comparisons and `in` over dot-paths,
//! joined by `and` (SPEC §5e.3 — the Debezium SMT routing idiom, no eval).
//!
//! Grammar:
//! ```text
//! when    := term ("and" term)*
//! term    := path ("=" | "!=") literal
//!          | path "in" "[" literal ("," literal)* "]"
//! literal := 'single-quoted string' | number | true | false | null
//! ```
//! A missing path makes the term false — routing never errors on absent
//! fields; a payload no route claims is quarantined by the runtime.

use serde_json::Value;

use crate::limits;
use crate::path::Path;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PredicateError {
    #[error("predicate exceeds {} chars", limits::MAX_EXPR_CHARS)]
    TooLong,
    #[error("empty predicate")]
    Empty,
    #[error("bad predicate syntax: {0}")]
    Bad(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

impl Literal {
    fn matches(&self, v: &Value) -> bool {
        match (self, v) {
            (Literal::Str(s), Value::String(vs)) => s == vs,
            (Literal::Num(n), Value::Number(vn)) => vn.as_f64() == Some(*n),
            (Literal::Bool(b), Value::Bool(vb)) => b == vb,
            (Literal::Null, Value::Null) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Op {
    Eq(Literal),
    Ne(Literal),
    In(Vec<Literal>),
}

#[derive(Debug, Clone, PartialEq)]
struct Term {
    path: Path,
    op: Op,
}

/// A parsed conjunction of terms.
#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    terms: Vec<Term>,
    text: String,
}

impl Predicate {
    pub fn parse(s: &str) -> Result<Self, PredicateError> {
        let text = s.trim().to_string();
        if text.is_empty() {
            return Err(PredicateError::Empty);
        }
        if text.chars().count() > limits::MAX_EXPR_CHARS {
            return Err(PredicateError::TooLong);
        }
        let tokens = tokenize(&text)?;
        let mut terms = Vec::new();
        let mut rest = tokens.as_slice();
        loop {
            let (term, remaining) = parse_term(rest)?;
            terms.push(term);
            match remaining {
                [] => break,
                [Token::And, tail @ ..] if !tail.is_empty() => rest = tail,
                _ => return Err(PredicateError::Bad("expected `and <term>`".into())),
            }
        }
        Ok(Self { terms, text })
    }

    pub fn as_text(&self) -> &str {
        &self.text
    }

    /// True iff every term matches. Missing paths are false, never errors.
    pub fn matches(&self, payload: &Value) -> bool {
        self.terms.iter().all(|t| {
            let Some(value) = t.path.eval_scalar(payload) else {
                // `!=` against an absent field is also false: routing claims
                // a payload only on evidence, never on absence.
                return false;
            };
            match &t.op {
                Op::Eq(lit) => lit.matches(value),
                Op::Ne(lit) => !lit.matches(value),
                Op::In(lits) => lits.iter().any(|l| l.matches(value)),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Path(String),
    Lit(Literal),
    Eq,
    Ne,
    In,
    And,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize(s: &str) -> Result<Vec<Token>, PredicateError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' => i += 1,
            '=' => {
                tokens.push(Token::Eq);
                i += 1;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Ne);
                i += 2;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '\'' => {
                let mut lit = String::new();
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('\'') => {
                            i += 1;
                            break;
                        }
                        Some(&ch) => {
                            lit.push(ch);
                            i += 1;
                        }
                        None => return Err(PredicateError::Bad("unterminated string".into())),
                    }
                }
                tokens.push(Token::Lit(Literal::Str(lit)));
            }
            _ => {
                // A bare word: number, keyword, bool/null literal, or a path.
                let start = i;
                while i < chars.len()
                    && !matches!(
                        chars[i],
                        ' ' | '\t' | '\n' | '=' | '!' | '[' | ']' | ',' | '\''
                    )
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                // Paths may carry `[n]`/`[]` accessors that the scanner above
                // split off; re-attach by scanning brackets when the next char
                // opens one and the word isn't a keyword.
                let token = match word.as_str() {
                    "and" => Token::And,
                    "in" => Token::In,
                    "true" => Token::Lit(Literal::Bool(true)),
                    "false" => Token::Lit(Literal::Bool(false)),
                    "null" => Token::Lit(Literal::Null),
                    _ => {
                        if let Ok(n) = word.parse::<f64>() {
                            Token::Lit(Literal::Num(n))
                        } else {
                            let mut path_text = word;
                            // Re-attach accessor brackets: "labels[0].name".
                            while chars.get(i) == Some(&'[') {
                                let close =
                                    chars[i..].iter().position(|&ch| ch == ']').ok_or_else(
                                        || PredicateError::Bad("unterminated index".into()),
                                    )?;
                                path_text.extend(&chars[i..=i + close]);
                                i += close + 1;
                                let start2 = i;
                                while i < chars.len()
                                    && !matches!(
                                        chars[i],
                                        ' ' | '\t' | '\n' | '=' | '!' | '[' | ']' | ',' | '\''
                                    )
                                {
                                    i += 1;
                                }
                                path_text.extend(&chars[start2..i]);
                            }
                            Token::Path(path_text)
                        }
                    }
                };
                tokens.push(token);
            }
        }
    }
    if tokens.is_empty() {
        return Err(PredicateError::Empty);
    }
    Ok(tokens)
}

fn parse_term(tokens: &[Token]) -> Result<(Term, &[Token]), PredicateError> {
    let [Token::Path(path_text), rest @ ..] = tokens else {
        return Err(PredicateError::Bad("expected a dot-path".into()));
    };
    let path =
        Path::parse(path_text).map_err(|e| PredicateError::Bad(format!("{path_text:?}: {e}")))?;
    match rest {
        [Token::Eq, Token::Lit(lit), tail @ ..] => Ok((
            Term {
                path,
                op: Op::Eq(lit.clone()),
            },
            tail,
        )),
        [Token::Ne, Token::Lit(lit), tail @ ..] => Ok((
            Term {
                path,
                op: Op::Ne(lit.clone()),
            },
            tail,
        )),
        [Token::In, Token::LBracket, tail @ ..] => {
            let mut lits = Vec::new();
            let mut rest = tail;
            loop {
                match rest {
                    [Token::Lit(lit), Token::Comma, tail @ ..] => {
                        lits.push(lit.clone());
                        rest = tail;
                    }
                    [Token::Lit(lit), Token::RBracket, tail @ ..] => {
                        lits.push(lit.clone());
                        return Ok((
                            Term {
                                path,
                                op: Op::In(lits),
                            },
                            tail,
                        ));
                    }
                    _ => return Err(PredicateError::Bad("bad `in [...]` list".into())),
                }
            }
        }
        _ => Err(PredicateError::Bad(
            "expected `= <lit>`, `!= <lit>`, or `in [...]`".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spec_example_predicate() {
        let p = Predicate::parse("type = 'Issue' and action in ['create','update']").unwrap();
        assert!(p.matches(&json!({"type": "Issue", "action": "create"})));
        assert!(p.matches(&json!({"type": "Issue", "action": "update"})));
        assert!(!p.matches(&json!({"type": "Issue", "action": "remove"})));
        assert!(!p.matches(&json!({"type": "Comment", "action": "create"})));
        // Absent fields never match — including for !=.
        assert!(!p.matches(&json!({"action": "create"})));
        let ne = Predicate::parse("type != 'Issue'").unwrap();
        assert!(!ne.matches(&json!({})));
        assert!(ne.matches(&json!({"type": "Comment"})));
    }

    #[test]
    fn numbers_bools_nulls_and_indexed_paths() {
        let p = Predicate::parse("data.priority = 2 and data.done = false").unwrap();
        assert!(p.matches(&json!({"data": {"priority": 2, "done": false}})));
        assert!(!p.matches(&json!({"data": {"priority": "2", "done": false}})));
        let p = Predicate::parse("data.labels[0].name = 'bug'").unwrap();
        assert!(p.matches(&json!({"data": {"labels": [{"name": "bug"}]}})));
        let p = Predicate::parse("data.parent = null").unwrap();
        assert!(p.matches(&json!({"data": {"parent": null}})));
        assert!(!p.matches(&json!({"data": {}})));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "type =",
            "type = 'Issue' and",
            "type ~ 'Issue'",
            "type in ['a'",
            "type = 'unterminated",
            "= 'Issue'",
            "a = 'x' or b = 'y'", // no `or` in the subset
        ] {
            assert!(Predicate::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
