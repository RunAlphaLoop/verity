#!/usr/bin/env python3
"""Seed a clean, synthetic demo tenant for recording the web console.

Unlike demo/two_agent_trust.py (which tears its space down), this leaves a
PERSISTENT tenant with a small, legible permission scenario so every console
panel — Memories, Playground, Scope Inspector, Permission graph — has something
real to show. All data is synthetic (Acme / alice-bob-carol-dave / Globex);
nothing here touches your real connected sources.

The scenario
------------
    all-staff ⊃ engineering ⊃ {alice, dave}
    all-staff ⊃ product     ⊃ {carol}
    sales               ⊃ {bob}          # sales is NOT under all-staff

So alice (engineering, under all-staff) sees the all-staff + engineering docs;
bob (sales only) sees just the sales doc. That contrast is the money shot for
the Scope Inspector and the Permission graph.

Run it
------
    # dev stack up (verity-cli dev); set VERITY_ADMIN_TOKEN if the server is gated
    python3 demo/seed_console.py
"""
import json
import os
import sys
import urllib.request

BASE = os.environ.get("VERITY_URL", "http://127.0.0.1:7717")
_ADMIN = os.environ.get("VERITY_ADMIN_TOKEN")


def http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"content-type": "application/json"}
    if _ADMIN:
        headers["authorization"] = f"Bearer {_ADMIN}"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


# group ⊃ member edges (directory / nested-group inheritance)
EDGES = [
    ("group:all-staff@acme.example", "group:engineering@acme.example"),
    ("group:all-staff@acme.example", "group:product@acme.example"),
    ("group:engineering@acme.example", "user:alice@acme.example"),
    ("group:engineering@acme.example", "user:dave@acme.example"),
    ("group:product@acme.example", "user:carol@acme.example"),
    ("group:sales@acme.example", "user:bob@acme.example"),
]

# document_id, content, group it is shared with
DOCS = [
    ("company-handbook",
     "The Acme company handbook: PTO policy, benefits, and the code of conduct.",
     "group:all-staff@acme.example"),
    ("eng-roadmap",
     "CONFIDENTIAL — the Q3 engineering roadmap: we are shipping the falcon-release-q3.",
     "group:all-staff@acme.example"),
    ("eng-oncall-runbook",
     "Engineering on-call runbook: paging policy, escalation ladder, and the incident bridge.",
     "group:engineering@acme.example"),
    ("sales-pipeline",
     "Sales pipeline — the Globex renewal is in negotiation at $61k annual; do not discount below $58k.",
     "group:sales@acme.example"),
]


def main():
    tenant = http("POST", "/v1/admin/tenants", {"name": "console-demo"})["tenant_id"]

    for group, member in EDGES:
        http("POST", "/v1/admin/groups", {"tenant_id": tenant, "group": group, "member": member})

    # One token per group we share docs with; visibility is a set of these tokens.
    share_groups = sorted({g for _, _, g in DOCS})
    tokens = http("POST", "/v1/admin/principals",
                  {"tenant_id": tenant, "principals": share_groups})["mappings"]

    for doc_id, content, group in DOCS:
        http("POST", "/v1/ingest/documents", {
            "tenant_id": tenant, "source": "demo", "document_id": doc_id,
            "content": content, "visibility": [tokens[group]], "acl_provenance": "mirrored"})

    url = f"{BASE}/ui?tenant={tenant}"
    print()
    print("  ✓ console demo tenant seeded (synthetic — safe to record)\n")
    print(f"    tenant  {tenant}")
    print(f"    console {url}\n")
    print("  Record this. Directory:")
    print("    all-staff ⊃ engineering ⊃ {alice, dave} · all-staff ⊃ product ⊃ {carol}")
    print("    sales ⊃ {bob}   (sales is NOT under all-staff)\n")
    print("  Suggested Scope Inspector / Permission-graph subjects:")
    print("    user:alice@acme.example  → sees handbook, roadmap, on-call runbook")
    print("    user:bob@acme.example    → sees only the sales pipeline (dark on the rest)\n")
    print("  Re-running makes a fresh tenant; this one persists until you delete it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
