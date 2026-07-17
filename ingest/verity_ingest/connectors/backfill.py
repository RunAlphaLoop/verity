"""Best-effort backfill progress reporter (task 49).

A *backfill* is the bounded, historical initial-sync a connector runs to catch a
cold source up before the change feed takes over (the §5a reconciliation crawl,
e.g. Drive ``files.list`` over every file). This reporter posts its progress to
``POST /v1/admin/backfill`` so the ``/ui`` backfill panel can show a per-source
progress bar, an ETA, and a terminal state.

Contract, identical to the connector heartbeat
(:mod:`verity_ingest.connectors` / migrations/0012): telemetry, never a ledger.
Every post is best-effort and swallows all failures — a failed progress post
must never fail (or replay) a sync that already delivered its rows. ``processed``
accumulates the deltas reported here and can undercount on a dropped post, never
over. The authoritative row count is the L0/L1 rows the ingest endpoints wrote.

One reporter instance == one run: the ``run_id`` is minted once (in the
orchestration, the same place the cursor lives) and threaded through every post,
so the server upserts a single ``backfill_run`` row.

Usage::

    rep = BackfillReporter(base_url, tenant_id, "gdrive", api_key=key)
    rep.start(total=None)                 # total=None when the source is uncountable
    for batch in batches:
        deliver(batch)
        rep.advance(len(batch), cursor=next_cursor)
    rep.finish()                          # or rep.fail("401 from source")
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

BACKFILL_PATH = "/v1/admin/backfill"


class BackfillReporter:
    """Posts backfill progress for a single run. Never raises."""

    def __init__(
        self,
        base_url: str,
        tenant_id: str,
        source: str,
        *,
        client: httpx.Client | None = None,
        api_key: str | None = None,
        run_id: str | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=30.0, headers=headers)
        self._base_url = base_url.rstrip("/")
        self._tenant_id = tenant_id
        self._source = source
        #: Stable per-run identity; the server keys the backfill_run row on it.
        self.run_id = run_id or str(uuid.uuid4())

    def _post(self, body: dict[str, Any]) -> None:
        body.update(
            {"run_id": self.run_id, "tenant_id": self._tenant_id, "source": self._source}
        )
        try:
            self._client.post(f"{self._base_url}{BACKFILL_PATH}", json=body)
        except Exception:  # noqa: BLE001 — telemetry only, never fail a sync
            pass

    def start(self, total: int | None = None, cursor: str | None = None) -> None:
        """Open the run as ``running``. ``total`` is the discovered/estimated
        window size, or ``None`` when the source can't be counted up front (the
        dashboard then shows an indeterminate bar, never a fake percentage)."""
        body: dict[str, Any] = {"state": "running", "processed_delta": 0}
        if total is not None:
            body["total"] = total
        if cursor is not None:
            body["cursor"] = cursor
        self._post(body)

    def advance(self, delta: int, cursor: str | None = None) -> None:
        """Report ``delta`` more items processed since the last post."""
        body: dict[str, Any] = {"processed_delta": max(0, int(delta))}
        if cursor is not None:
            body["cursor"] = cursor
        self._post(body)

    def finish(self, cursor: str | None = None, error: object | None = None) -> None:
        """Mark the run ``completed``. ``error`` is normally cleared on a clean
        finish, but a connector may pass a distinct non-fatal note (e.g. the
        HubSpot owners-scope ``degraded_acl`` signal) to record that the run
        succeeded with a caveat — the rows landed, but under a coarser ACL than a
        full mirror. The server keys ``state=degraded_acl`` off this note, so it
        is a run-level signal, never a silent success."""
        body: dict[str, Any] = {"state": "completed", "processed_delta": 0}
        if cursor is not None:
            body["cursor"] = cursor
        if error is not None:
            body["error"] = str(error)
        self._post(body)

    def fail(self, error: object, cursor: str | None = None) -> None:
        """Mark the run ``failed`` and record the operator-facing error."""
        body: dict[str, Any] = {
            "state": "failed",
            "processed_delta": 0,
            "error": str(error),
        }
        if cursor is not None:
            body["cursor"] = cursor
        self._post(body)
