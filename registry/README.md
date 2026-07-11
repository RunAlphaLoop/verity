# Verity community manifest registry

Source manifests (SPEC §5e.3) are **data, not code** — a system that can POST
JSON becomes a Verity source with a reviewable YAML file, no connector binary.
This directory is the community registry that SPEC §5e.3 sketched: *"a git repo
of signed YAML files at v0.1 (near-zero cost)."* Certification tiers,
moderation, and richer fetch machinery are deferred until ≥10 community
manifests exist — this is the minimal, honest first cut.

## Layout

```
registry/
  index.json                    # the catalog (see below)
  manifests/<name>.yaml         # one manifest per source
  manifests/fixtures/…          # conformance fixtures, resolved relative to the manifest
  signatures/<name>.sig         # detached signature (verified tier only)
  README.md                     # this file
```

### `index.json`

```json
{
  "registry_version": 1,
  "entries": [
    {
      "name": "linear",
      "version": "1",
      "description": "Linear issues + comments via webhook …",
      "tier": "community",
      "path": "manifests/linear.yaml",
      "sha256": "6e7ea06b…",
      "signature_ref": "signatures/linear.sig"   // present only when signed
    }
  ]
}
```

- `name` — the manifest's `source.name`; the catalog key and the CLI selector.
- `sha256` — lowercase hex sha256 of the manifest bytes at `path`. The
  **integrity anchor**: the CLI recomputes it before every fetch/install and
  refuses on mismatch.
- `signature_ref` — a detached signature file (see *Signing*). Optional for
  `community`, required for `verified`.

## Tiers

| tier | meaning | signature |
|---|---|---|
| `community` | **Self-attested.** Unsigned-by-us: the entry's integrity (sha256) is guaranteed, but Verity maintainers have not vouched for its ACL semantics. Anyone can contribute one. | optional (contributor-attested if present) |
| `verified` | **Maintainer-vouched.** Signed by a Verity maintainer key after review of the `acl_policy` block. | **required** |

`verified` is documented, not yet operated — no manifest ships as `verified`
until the maintainer key process below is real. This mirrors SPEC §5e.3:
certification machinery waits on real demand.

## Signing — the v0 story, stated honestly

Manifest-file signatures reuse verity-manifest's existing HMAC-SHA256 primitive
(the same one the webhook lane uses), signing the **manifest bytes**:

```
signatures/<name>.sig = hex( HMAC-SHA256( maintainer_key, manifest_bytes ) )
```

The maintainer key is resolved from the environment
(`VERITY_REGISTRY_SIGNING_KEY`), mirroring the `secret://` → `VERITY_SECRET_*`
convention. `verity-cli manifest verify <name>` checks integrity first, then the
signature.

**Why HMAC and not ed25519 (and the limit this buys):** we deliberately add
*zero* new supply-chain dependencies to a crate whose entire premise is "no
supply-chain code execution." HMAC is a **symmetric** MAC, so:

- **`sha256` in `index.json` is *integrity*, not authenticity.** It proves the
  bytes match the catalog — not who wrote them.
- **An HMAC signature proves the signer held the shared maintainer key** — it
  is authenticity *relative to that key*, not public-key non-repudiation.
  Because verify and sign use the same key, anyone who can verify can also
  forge. The key therefore stays maintainer-only and is **never shipped to
  clients that merely verify**.

The real `verified`-tier threat model wants a **public-key** signature (ed25519)
so verifiers hold only a public key and cannot forge. That is the documented
**next step**, gated — like the rest of the certification machinery — on ≥10
community manifests existing. Until then, `community` (integrity-guaranteed,
self-attested) is the honest tier, and `verified` is a schema slot with a real
but symmetric-key implementation behind it.

We do not build a CA. The maintainer public-key (eventually) or key location is
documented here; there is no key-issuance hierarchy.

## The install trust chain (fail-closed at every hop)

```
verify (sha256 + signature)  ──►  fixtures gate (conformance runner)  ──►  human activation
      │                                    │                                      │
  fetch/install REFUSE on            fetch/install REFUSE if any             POST /v1/manifests/{id}/activate
  integrity/signature failure        declared fixture fails                 still requires an admin approver;
  (fail closed)                      (connectors-as-config w/ a test gate)  the ACL block is reviewed by a human
```

`manifest install` uploads the verified, fixture-passing manifest as a **draft**
and stops. Activation — the point where ACL semantics go live — is always a
separate, human-gated admin action. The registry never lowers that bar.

## Contributing a manifest

1. Author `manifests/<name>.yaml` (see `../docs/manifests.md` for the format)
   and its fixtures under `manifests/fixtures/`. The `acl_policy` block is
   reviewed by a human — an LLM may draft everything else, never that block.
2. Confirm it passes its own fixtures:
   `cargo run -p verity-manifest --bin manifest-test -- registry/manifests/<name>.yaml`
3. Compute the sha256 (`shasum -a 256 registry/manifests/<name>.yaml`) and add
   an `index.json` entry with `tier: community`.
4. Open a PR. A maintainer reviews the manifest — especially the `acl_policy`
   block and the fixtures — before merge. Promotion to `verified` (a maintainer
   signature) is a separate, later step.

## Next steps (deferred, per SPEC §5e.3)

- ed25519 public-key signatures for the `verified` tier (verifiers hold only a
  public key).
- git/HTTP registry fetch (`--registry https://…` / a git URL); the CLI
  already reads a configurable registry root and documents this as the next hop.
- Certification tiers, moderation, and a curated index — once ≥10 manifests
  exist.
