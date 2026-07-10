"""Temporal-backed durable orchestration for the ingest plane (SPEC.md §5).

SPEC §5: "the ingest plane is server-side, horizontally scalable, and runs on
durable execution … **Temporal is mandatory before the managed connector fleet
ships**." This package is that orchestration layer: it *wraps* the existing
connector classes (HubSpot, Salesforce, Google Drive) — it never modifies
them — and replaces the ad-hoc ``--once``-under-cron runners with durable
Temporal workflows.

Design (see module docstrings for detail):

- :mod:`.workflows` — ``ConnectorSyncWorkflow``: one long-lived workflow per
  connector; each iteration schedules one poll-cycle activity, carries the
  returned cursor in **workflow state** (not files), sleeps the configured
  interval, and continues-as-new so history stays bounded.
- :mod:`.activities` — ``run_connector_poll_cycle``: one truth-lane poll +
  sink delivery via the existing connector/sink classes; heartbeats while it
  works; returns the next cursor ONLY after delivery succeeded (at-least-once
  into deterministic keyed L1 upserts, exactly like the file-based runners).
- :mod:`.worker` — ``python -m verity_ingest.orchestration.worker``.
- :mod:`.schedules` — ``python -m verity_ingest.orchestration.schedules
  --apply``: create/update one Temporal Schedule per enabled connector.

Requires the ``orchestration`` extra: ``pip install 'verity-ingest[orchestration]'``.
"""
