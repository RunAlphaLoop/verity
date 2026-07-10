//! Fixture conformance harness — ships WITH the format, not after (SPEC
//! §5e.3). For each `fixtures[]` entry the runtime is applied to the input
//! payload under a pinned clock and the outputs are compared, as canonical
//! JSON, against the expected facts / chunks / ACL envelopes. Deterministic
//! pass/fail is what makes "LLM drafts, harness verifies, human approves"
//! honest.

use std::path::{Path as FsPath, PathBuf};

use serde_json::{json, Value};

use crate::runtime::{apply, Applied, RuntimeOptions};
use crate::schema::{Expect, Manifest, ManifestError};

/// One fixture's verdict. `failures` is empty iff `passed`.
#[derive(Debug)]
pub struct FixtureOutcome {
    pub input: String,
    pub passed: bool,
    pub failures: Vec<String>,
}

/// Run every fixture declared by the manifest at `manifest_path`. Fixture
/// paths resolve relative to the manifest file. Errors are reserved for
/// harness problems (unreadable files, invalid manifest); assertion failures
/// come back as `FixtureOutcome::failures`.
pub fn run_manifest_fixtures(manifest_path: &FsPath) -> Result<Vec<FixtureOutcome>, ManifestError> {
    let yaml = std::fs::read_to_string(manifest_path)
        .map_err(|e| ManifestError::Io(format!("{}: {e}", manifest_path.display())))?;
    let manifest = Manifest::from_yaml(&yaml)?;
    let base = manifest_path.parent().unwrap_or(FsPath::new("."));
    let opts = RuntimeOptions::fixture_clock();

    let mut outcomes = Vec::with_capacity(manifest.fixtures.len());
    for fixture in &manifest.fixtures {
        let payload = read_json(&resolve(base, &fixture.input)?)?;
        let applied = apply(&manifest, &payload, &opts);
        let failures = check_expectations(&manifest, base, &fixture.expect, &applied)?;
        outcomes.push(FixtureOutcome {
            input: fixture.input.clone(),
            passed: failures.is_empty(),
            failures,
        });
    }
    Ok(outcomes)
}

/// Canonical JSON views of a runtime outcome — the shapes fixtures assert.
pub fn actual_facts(applied: &Applied) -> Value {
    match applied {
        Applied::Writes { writes, .. } => {
            Value::Array(writes.iter().map(|w| w.to_json()).collect())
        }
        Applied::Quarantine { .. } => json!([]),
    }
}

pub fn actual_chunks(applied: &Applied) -> Value {
    match applied {
        Applied::Writes { writes, .. } => Value::Array(
            writes
                .iter()
                .filter_map(|w| {
                    w.content.as_ref().map(|content| {
                        json!({
                            "entity_type": w.entity_type,
                            "entity_id": w.entity_id,
                            "content": content,
                        })
                    })
                })
                .collect(),
        ),
        Applied::Quarantine { .. } => json!([]),
    }
}

pub fn actual_acl(manifest: &Manifest, applied: &Applied) -> Value {
    let namespace = manifest
        .acl_policy
        .as_ref()
        .and_then(|p| p.identity_namespace);
    match applied {
        Applied::Writes { acl, .. } => json!([acl.to_json(namespace)]),
        Applied::Quarantine { reason } => json!([{
            "mode": "quarantine",
            "acl_provenance": "quarantined",
            "reason": reason,
        }]),
    }
}

fn check_expectations(
    manifest: &Manifest,
    base: &FsPath,
    expect: &Expect,
    applied: &Applied,
) -> Result<Vec<String>, ManifestError> {
    let mut failures = Vec::new();

    match (expect.quarantined, applied) {
        (true, Applied::Writes { .. }) => {
            failures.push("expected quarantine, but the payload produced writes".into());
        }
        (false, Applied::Quarantine { reason }) => {
            failures.push(format!("unexpected quarantine: {reason}"));
        }
        (true, Applied::Quarantine { reason }) => {
            if let Some(needle) = &expect.reason_contains {
                if !reason.contains(needle.as_str()) {
                    failures.push(format!(
                        "quarantine reason {reason:?} does not contain {needle:?}"
                    ));
                }
            }
        }
        (false, Applied::Writes { .. }) => {}
    }

    let mut compare = |label: &str, expected_path: &Option<String>, actual: Value| {
        if let Some(p) = expected_path {
            match resolve(base, p).and_then(|p| read_json(&p)) {
                Ok(expected) => {
                    if expected != actual {
                        failures.push(format!(
                            "{label} mismatch:\n  expected: {expected}\n  actual:   {actual}"
                        ));
                    }
                }
                Err(e) => failures.push(format!("{label}: {e}")),
            }
        }
    };
    compare("facts", &expect.facts, actual_facts(applied));
    compare("chunks", &expect.chunks, actual_chunks(applied));
    compare(
        "acl_envelopes",
        &expect.acl_envelopes,
        actual_acl(manifest, applied),
    );
    Ok(failures)
}

/// Resolve a fixture-relative path, refusing escapes above the manifest dir
/// (fixtures ship next to the manifest; a manifest must not read `/etc`).
fn resolve(base: &FsPath, rel: &str) -> Result<PathBuf, ManifestError> {
    let p = FsPath::new(rel);
    if p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ManifestError::Io(format!(
            "fixture path {rel:?} must be relative to the manifest, without `..`"
        )));
    }
    Ok(base.join(p))
}

fn read_json(path: &FsPath) -> Result<Value, ManifestError> {
    let bytes =
        std::fs::read(path).map_err(|e| ManifestError::Io(format!("{}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ManifestError::Io(format!("{}: invalid JSON: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped example manifest must pass its own fixtures — the
    /// fixtures-ship-with-the-format guarantee, enforced in CI.
    #[test]
    fn shipped_linear_example_passes() {
        let path = FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/linear.yaml");
        let outcomes = run_manifest_fixtures(&path).expect("harness runs");
        assert!(!outcomes.is_empty(), "example declares fixtures");
        for o in &outcomes {
            assert!(o.passed, "{}: {:#?}", o.input, o.failures);
        }
    }

    #[test]
    fn fixture_paths_cannot_escape() {
        assert!(resolve(FsPath::new("/tmp"), "../etc/passwd").is_err());
        assert!(resolve(FsPath::new("/tmp"), "/etc/passwd").is_err());
        assert!(resolve(FsPath::new("/tmp"), "fixtures/x.json").is_ok());
    }
}
