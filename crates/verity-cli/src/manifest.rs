//! `verity-cli manifest …` — the community manifest registry front door
//! (SPEC §5e.3, task #48). A registry is a git repo of signed YAML files;
//! this reads a **local registry root** today (default `./registry`,
//! overridable via `--registry` / `VERITY_MANIFEST_REGISTRY`) and documents a
//! git/HTTP URL fetch as the next step.
//!
//! Trust chain, fail-closed at every hop:
//!   verify (sha256 + signature) → fixtures gate → human activation.
//! `fetch`/`install` refuse before touching a manifest that fails verify or
//! its own conformance fixtures — connectors-as-config with a test gate. The
//! server's human activation gate still applies after `install`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use verity_manifest::registry::{
    signing_key_from_env, verify_entry, RegistryEntry, RegistryIndex, RegistryTier, SignatureState,
    VerifyReport,
};
use verity_manifest::run_manifest_fixtures;

use crate::{ui, util, Ctx};

/// A registry source. v0 supports a local directory root; a git/HTTP URL is
/// the documented next hop (rejected with a clear message today).
struct Registry {
    root: PathBuf,
}

impl Registry {
    /// Resolve the registry root: `--registry` flag → `VERITY_MANIFEST_REGISTRY`
    /// env → `./registry` (relative to the current directory).
    fn resolve(explicit: Option<&str>) -> Result<Self> {
        let raw = explicit
            .map(str::to_string)
            .or_else(|| std::env::var("VERITY_MANIFEST_REGISTRY").ok())
            .unwrap_or_else(|| "./registry".to_string());

        if raw.starts_with("http://") || raw.starts_with("https://") || raw.starts_with("git@") {
            bail!(
                "remote registries are not fetched yet (v0 reads a local directory)\n  \
                 → clone the registry and point at the checkout: \
                 --registry /path/to/registry\n  \
                 (git/HTTP fetch is the documented next step — see registry/README.md)"
            );
        }
        let root = PathBuf::from(&raw);
        if !root.join("index.json").is_file() {
            bail!(
                "no registry at {} (expected {}/index.json)\n  \
                 → run from the verity checkout, or pass --registry <dir> / set \
                 VERITY_MANIFEST_REGISTRY",
                root.display(),
                root.display()
            );
        }
        Ok(Registry { root })
    }

    fn index(&self) -> Result<RegistryIndex> {
        let path = self.root.join("index.json");
        let bytes =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        RegistryIndex::from_json(&bytes).map_err(|e| anyhow!(e))
    }

    fn entry(&self, name: &str) -> Result<(RegistryIndex, RegistryEntry)> {
        let index = self.index()?;
        let entry = index.find(name).cloned().ok_or_else(|| {
            anyhow!("no manifest named {name:?} in the registry — `manifest list`")
        })?;
        Ok((index, entry))
    }

    /// Read the manifest bytes for an entry, refusing path escapes.
    fn manifest_bytes(&self, entry: &RegistryEntry) -> Result<Vec<u8>> {
        let path = self.safe_join(&entry.path)?;
        std::fs::read(&path).with_context(|| format!("cannot read manifest {}", path.display()))
    }

    /// Read the detached signature (hex), when the entry declares one.
    fn signature(&self, entry: &RegistryEntry) -> Result<Option<String>> {
        let Some(ref rel) = entry.signature_ref else {
            return Ok(None);
        };
        let path = self.safe_join(rel)?;
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read signature {}", path.display()))?;
        Ok(Some(raw.trim().to_string()))
    }

    /// Join a registry-relative path, refusing absolute paths and `..` escapes.
    fn safe_join(&self, rel: &str) -> Result<PathBuf> {
        let p = Path::new(rel);
        if p.is_absolute()
            || p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            bail!("registry path {rel:?} must be relative, without `..`");
        }
        Ok(self.root.join(p))
    }
}

// ---------- list ----------

pub fn list(registry: Option<&str>) -> Result<()> {
    let reg = Registry::resolve(registry)?;
    let index = reg.index()?;

    ui::banner(&format!(
        "manifest registry  ({} at {})",
        plural(index.entries.len(), "entry", "entries"),
        reg.root.display()
    ));
    println!();
    if index.entries.is_empty() {
        println!("  {}", ui::dim("(no entries yet)"));
        return Ok(());
    }
    for e in &index.entries {
        let tier = match e.tier {
            RegistryTier::Community => ui::cyan("[community]"),
            RegistryTier::Verified => ui::green("[verified]"),
        };
        println!("  {}  {}  {}", ui::bold(&e.name), ui::dim(&e.version), tier);
        println!("      {}", ui::truncate(&e.description, 96));
    }
    println!();
    println!(
        "  {}",
        ui::dim("verify one:  verity-cli manifest verify <name>")
    );
    Ok(())
}

// ---------- show ----------

pub fn show(name: &str, registry: Option<&str>) -> Result<()> {
    let reg = Registry::resolve(registry)?;
    let (_index, entry) = reg.entry(name)?;
    let bytes = reg.manifest_bytes(&entry)?;

    ui::banner(&format!("manifest \"{name}\""));
    println!();
    let kv =
        |label: &str, value: &str| println!("    {}  {value}", ui::dim(&format!("{label:<12}")));
    kv("version", &entry.version);
    kv("tier", entry.tier.as_str());
    kv("path", &entry.path);
    kv("sha256", &entry.sha256);
    kv(
        "signature",
        entry.signature_ref.as_deref().unwrap_or("(none)"),
    );
    println!();
    println!("  {}", ui::dim("─── manifest yaml ───"));
    println!();
    print!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

// ---------- verify ----------

/// Run the full verify (sha256 + signature) and print a clear pass/fail.
/// Returns the report so `fetch`/`install` can gate on it.
fn verify_report(reg: &Registry, entry: &RegistryEntry) -> Result<VerifyReport> {
    let bytes = reg.manifest_bytes(entry)?;
    let sig = reg.signature(entry)?;
    let key = signing_key_from_env();
    Ok(verify_entry(entry, &bytes, sig.as_deref(), key.as_deref()))
}

fn print_verify(entry: &RegistryEntry, report: &VerifyReport) {
    let mark = |ok: bool| {
        if ok {
            ui::green("✓")
        } else {
            ui::red("✗")
        }
    };
    println!(
        "    {} integrity   sha256 {}",
        mark(report.integrity_ok),
        if report.integrity_ok {
            ui::dim("matches index.json")
        } else {
            ui::red("MISMATCH — bytes differ from the catalog")
        }
    );
    let sig_ok = matches!(
        report.signature,
        SignatureState::Ok | SignatureState::NoneCommunity
    );
    println!(
        "    {} signature   {}",
        mark(sig_ok),
        report.signature.describe()
    );
    let _ = entry;
}

pub fn verify(name: &str, registry: Option<&str>) -> Result<()> {
    let reg = Registry::resolve(registry)?;
    let (_index, entry) = reg.entry(name)?;
    let report = verify_report(&reg, &entry)?;

    ui::banner(&format!("verify \"{name}\"  ({})", entry.tier.as_str()));
    println!();
    print_verify(&entry, &report);
    println!();
    if report.passed() {
        println!("  {} {}", ui::green("PASS"), ui::dim("verify succeeded"));
        Ok(())
    } else {
        bail!("verify FAILED for {name:?} — fetch/install will refuse (fail closed)");
    }
}

// ---------- fetch ----------

/// Verify → run fixtures → copy the manifest (and its fixtures) locally. Both
/// gates fail closed: a verify or fixture failure refuses the copy.
pub fn fetch(name: &str, out: Option<&Path>, registry: Option<&str>) -> Result<()> {
    let reg = Registry::resolve(registry)?;
    let (_index, entry) = reg.entry(name)?;

    ui::banner(&format!("fetch \"{name}\""));
    println!();

    // Gate 1: verify (sha256 + signature).
    let report = verify_report(&reg, &entry)?;
    print_verify(&entry, &report);
    if !report.passed() {
        bail!("refusing to fetch {name:?}: verify failed (fail closed)");
    }

    // Gate 2: conformance fixtures.
    let bytes = reg.manifest_bytes(&entry)?;
    run_fixtures_gate(&reg, &entry)?;

    // Both gates passed — copy the manifest locally.
    let out_dir = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(format!("./{name}")));
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("cannot create output dir {}", out_dir.display()))?;
    let dest = out_dir.join(format!("{name}.yaml"));
    std::fs::write(&dest, &bytes).with_context(|| format!("cannot write {}", dest.display()))?;
    copy_fixtures(&reg, &entry, &out_dir)?;

    println!();
    ui::step_ok(
        "fetched",
        &format!("{} (verified + fixtures pass)", dest.display()),
    );
    println!(
        "  {}",
        ui::dim(
            "upload it with `verity-cli manifest install`, or POST it yourself to /v1/manifests"
        )
    );
    Ok(())
}

// ---------- install ----------

/// Verify → run fixtures → POST to /v1/manifests (draft). Activation remains a
/// separate, human-gated admin action; this never activates.
pub async fn install(
    ctx: &Ctx,
    name: &str,
    tenant: &str,
    admin_token: &str,
    registry: Option<&str>,
) -> Result<()> {
    let reg = Registry::resolve(registry)?;
    let (_index, entry) = reg.entry(name)?;

    ui::banner(&format!("install \"{name}\""));
    println!();

    // Gate 1: verify.
    let report = verify_report(&reg, &entry)?;
    print_verify(&entry, &report);
    if !report.passed() {
        bail!("refusing to install {name:?}: verify failed (fail closed)");
    }

    // Gate 2: fixtures.
    run_fixtures_gate(&reg, &entry)?;

    // Upload as a draft. The server re-validates and stores; it does NOT
    // activate — activation is a separate human-gated admin call.
    let yaml =
        String::from_utf8(reg.manifest_bytes(&entry)?).context("manifest is not valid UTF-8")?;
    let req = ctx
        .http
        .post(format!("{}/v1/manifests", ctx.url))
        .bearer_auth(admin_token)
        .json(&serde_json::json!({ "tenant_id": tenant, "yaml": yaml }));
    let (status, body) = util::send(req, &ctx.url).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!("the server rejected the admin token (401) — check --admin-token");
    }
    let json = util::expect_json(
        status,
        &body,
        "fix the request and re-run `verity-cli manifest install`",
    )?;

    println!();
    ui::step_ok(
        "uploaded",
        &format!(
            "manifest_id={} status={}",
            json["manifest_id"].as_str().unwrap_or("?"),
            json["status"].as_str().unwrap_or("draft")
        ),
    );
    println!();
    println!(
        "  {}",
        ui::yellow("The human activation gate still applies.")
    );
    println!(
        "  {}",
        ui::dim(
            "This uploaded a DRAFT. An admin must review the acl_policy block and activate:\n  \
             → POST /v1/manifests/<id>/activate  {\"tenant_id\":…, \"approved_by\":\"you@org\"}"
        )
    );
    Ok(())
}

// ---------- fixtures gate ----------

/// Run the manifest's own conformance fixtures; refuse if any fail. This is
/// the connectors-as-config test gate. Fixtures are resolved relative to the
/// manifest file, so they must ship alongside it in the registry.
fn run_fixtures_gate(reg: &Registry, entry: &RegistryEntry) -> Result<()> {
    let manifest_path = reg.safe_join(&entry.path)?;
    let outcomes = run_manifest_fixtures(&manifest_path)
        .with_context(|| format!("cannot run fixtures for {}", entry.name))?;
    if outcomes.is_empty() {
        bail!(
            "refusing {name:?}: the manifest declares no fixtures — a manifest without a \
             conformance fixture cannot pass the test gate",
            name = entry.name
        );
    }
    let mut all_pass = true;
    for o in &outcomes {
        if o.passed {
            println!("    {} fixture    {}", ui::green("✓"), o.input);
        } else {
            all_pass = false;
            println!("    {} fixture    {}", ui::red("✗"), o.input);
            for f in &o.failures {
                println!("        {}", ui::red(f));
            }
        }
    }
    if !all_pass {
        bail!(
            "refusing {name:?}: conformance fixtures failed (connectors-as-config test gate)",
            name = entry.name
        );
    }
    Ok(())
}

/// Copy a manifest's fixtures (everything under `manifests/fixtures/`) next to
/// the fetched manifest so it stays self-verifying offline.
fn copy_fixtures(reg: &Registry, entry: &RegistryEntry, out_dir: &Path) -> Result<()> {
    let manifest_path = reg.safe_join(&entry.path)?;
    let src_fixtures = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("fixtures");
    if !src_fixtures.is_dir() {
        return Ok(());
    }
    let dest_fixtures = out_dir.join("fixtures");
    std::fs::create_dir_all(&dest_fixtures)?;
    for entry in std::fs::read_dir(&src_fixtures)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::copy(entry.path(), dest_fixtures.join(entry.file_name()))?;
        }
    }
    Ok(())
}

// ---------- helpers ----------

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute path to the repo's seeded `registry/` (two levels up from the
    /// crate: crates/verity-cli → repo root).
    fn seeded_registry() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../registry")
    }

    /// Copy the seeded registry into a fresh temp dir so tamper tests don't
    /// touch the checked-in files.
    fn temp_copy() -> PathBuf {
        let dst = std::env::temp_dir()
            .join(format!("verity-reg-test-{}", std::process::id()))
            .join(format!("{:?}", std::time::SystemTime::now()).replace([':', '.', ' '], "_"));
        copy_dir(&seeded_registry(), &dst);
        dst
    }

    fn copy_dir(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let to = dst.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_dir(&e.path(), &to);
            } else {
                std::fs::copy(e.path(), to).unwrap();
            }
        }
    }

    #[test]
    fn seeded_linear_entry_verifies() {
        let reg = Registry::resolve(Some(seeded_registry().to_str().unwrap())).unwrap();
        let (_idx, entry) = reg.entry("linear").unwrap();
        assert_eq!(entry.tier, RegistryTier::Community);
        let report = verify_report(&reg, &entry).unwrap();
        assert!(report.integrity_ok, "seeded sha256 must match");
        assert_eq!(report.signature, SignatureState::NoneCommunity);
        assert!(report.passed(), "seeded linear entry must verify");
    }

    #[test]
    fn seeded_linear_fixtures_pass() {
        let reg = Registry::resolve(Some(seeded_registry().to_str().unwrap())).unwrap();
        let (_idx, entry) = reg.entry("linear").unwrap();
        // The fixtures gate returns Ok iff every declared fixture passes.
        assert!(run_fixtures_gate(&reg, &entry).is_ok());
    }

    #[test]
    fn tampered_manifest_fails_verify_and_fetch_refuses() {
        let root = temp_copy();
        let manifest = root.join("manifests/linear.yaml");
        let mut bytes = std::fs::read_to_string(&manifest).unwrap();
        bytes.push_str("\n# tamper\n"); // one appended byte-run, sha256 now differs
        std::fs::write(&manifest, &bytes).unwrap();

        let reg = Registry::resolve(Some(root.to_str().unwrap())).unwrap();
        let (_idx, entry) = reg.entry("linear").unwrap();
        let report = verify_report(&reg, &entry).unwrap();
        assert!(!report.integrity_ok, "tampered bytes must fail integrity");
        assert!(!report.passed());

        // fetch must refuse and write nothing.
        let out = root.join("fetched-out");
        let err = fetch("linear", Some(&out), Some(root.to_str().unwrap()));
        assert!(err.is_err(), "fetch must refuse a tampered manifest");
        assert!(
            !out.join("linear.yaml").exists(),
            "no manifest may be written on a refused fetch (fail closed)"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn unknown_manifest_is_an_error() {
        let reg = Registry::resolve(Some(seeded_registry().to_str().unwrap())).unwrap();
        assert!(reg.entry("does-not-exist").is_err());
    }

    #[test]
    fn remote_registry_url_is_rejected_with_next_step() {
        match Registry::resolve(Some("https://example.com/registry")) {
            Ok(_) => panic!("remote URL must be rejected"),
            Err(e) => assert!(e.to_string().contains("not fetched yet")),
        }
    }
}
