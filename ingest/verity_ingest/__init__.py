"""Verity ingestion plane.

Connectors mirror systems of record into the Verity server (L0 episodes,
L1 fact writes, chunk upserts) over its REST API. Two lanes per SPEC.md §5:
a push lane (webhooks/CDC, seconds) and a truth lane (cursor polling + full
crawls) that reconciles dropped events, deletions, and permission drift.

Hard rules for every connector:
- ACLs ride the same pipeline as content; an item whose ACL cannot be mapped
  is quarantined, never indexed permissively.
- Structured records are deterministic L1 fact writes — no LLM in the write
  path for CRM rows.
- Every write carries provenance (source, source entity id, content hash).
"""

__version__ = "0.1.0"
