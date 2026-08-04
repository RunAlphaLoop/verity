"""Backfill reporter + run_backfill wiring (task 49).

Two levels: the reusable :class:`BackfillReporter` primitive (best-effort POST
contract, never raises), and its end-to-end use driving the gdrive §5a
``full_crawl`` into a sink while reporting progress. No live API calls — the
crawl runs over the same recorded Drive fixtures as test_gdrive.py.
"""

from __future__ import annotations

import io
import json

import httpx
import pytest

from verity_ingest.connectors.backfill import BACKFILL_PATH, BackfillReporter
from verity_ingest.connectors.gdrive import (
    DryRunSink,
    GDriveConfig,
    GDriveConnector,
    StaticRegistry,
    run_backfill,
)

from test_gdrive import (  # reuse the recorded-fixture harness
    DOC_ID,
    PDF_ID,
    REGISTRY_MAP,
    TENANT,
    TXT_ID,
    FixtureTransport,
    _FILE_FIXTURES,
    _load,
)


class _CapturingClient:
    """Stands in for httpx.Client; records every POST body."""

    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []

    def post(self, url: str, json: dict) -> None:  # noqa: A002 - matches httpx signature
        self.posts.append((url, json))


class _RaisingClient:
    def post(self, url: str, json: dict) -> None:  # noqa: A002
        raise httpx.ConnectError("backfill endpoint unreachable")


# ---------------------------------------------------------------------------
# BackfillReporter: the best-effort POST contract
# ---------------------------------------------------------------------------


def _reporter() -> tuple[BackfillReporter, _CapturingClient]:
    client = _CapturingClient()
    rep = BackfillReporter(
        "http://verity.local", TENANT, "gdrive", client=client, run_id="run-1"
    )
    return rep, client


def test_reporter_threads_identity_and_lifecycle():
    rep, client = _reporter()
    rep.start(total=None, cursor="c0")
    rep.advance(40, cursor="c1")
    rep.advance(35)
    rep.finish(cursor="c2")

    paths = {url for url, _ in client.posts}
    assert paths == {f"http://verity.local{BACKFILL_PATH}"}
    bodies = [b for _, b in client.posts]
    # Every post carries the same run identity, tenant, and source.
    for b in bodies:
        assert b["run_id"] == "run-1"
        assert b["tenant_id"] == TENANT
        assert b["source"] == "gdrive"

    start, adv1, adv2, done = bodies
    # start: running, total omitted (None => indeterminate), cursor carried.
    assert start["state"] == "running" and "total" not in start
    assert start["processed_delta"] == 0 and start["cursor"] == "c0"
    # advances carry deltas; no state restated.
    assert adv1["processed_delta"] == 40 and adv1["cursor"] == "c1"
    assert "state" not in adv1
    assert adv2["processed_delta"] == 35 and "cursor" not in adv2
    # finish flips state; error absent (a completed run clears any error).
    assert done["state"] == "completed" and "error" not in done


def test_reporter_start_with_total_and_fail_records_error():
    rep, client = _reporter()
    rep.start(total=100)
    rep.fail("401 from source")
    start, failed = (b for _, b in client.posts)
    assert start["total"] == 100
    assert failed["state"] == "failed" and failed["error"] == "401 from source"


def test_reporter_clamps_negative_delta():
    rep, client = _reporter()
    rep.advance(-5)
    assert client.posts[0][1]["processed_delta"] == 0


def test_reporter_is_best_effort_and_never_raises():
    rep = BackfillReporter(
        "http://verity.local", TENANT, "gdrive", client=_RaisingClient(), run_id="r"
    )
    # None of these may propagate the client's ConnectError — a failed
    # telemetry post must never fail (or replay) a sync.
    rep.start(total=1)
    rep.advance(1)
    rep.finish()
    rep.fail("boom")


# ---------------------------------------------------------------------------
# run_backfill: driving full_crawl into a sink with progress reporting
# ---------------------------------------------------------------------------


class _CrawlTransport(FixtureTransport):
    """Adds a paged ``files.list`` over the three non-trashed fixture files so
    full_crawl has something to walk; per-file permissions/content still come
    from the inherited fixture handlers."""

    def get_json(self, path: str, params: dict) -> dict:
        if path == "files":  # bare list (files/{id}... keeps the slash)
            self.json_calls.append((path, dict(params)))
            if params.get("pageToken") == "p2":
                return {"files": [_load(_FILE_FIXTURES[PDF_ID])]}
            return {
                "files": [_load(_FILE_FIXTURES[DOC_ID]), _load(_FILE_FIXTURES[TXT_ID])],
                "nextPageToken": "p2",
            }
        return super().get_json(path, params)


def test_run_backfill_crawls_and_reports_progress(tmp_path):
    connector = GDriveConnector(_CrawlTransport(), GDriveConfig(tenant_id=TENANT))
    registry = StaticRegistry(REGISTRY_MAP)
    sink = DryRunSink(stream=io.StringIO())
    client = _CapturingClient()
    reporter = BackfillReporter(
        "http://verity.local", TENANT, "gdrive", client=client, run_id="bf"
    )
    state_file = tmp_path / "gdrive_cursor.json"

    # flush_every=1 so each delivery emits an advance we can count.
    delivered = run_backfill(connector, registry, sink, state_file, reporter, flush_every=1)

    # Three non-trashed files walked across two pages; the two mirrored ones
    # delivered. The anyone-shared PDF quarantines fail-closed: the documents
    # endpoint rejects quarantined bodies, so it is PARKED in the retraction
    # ledger — and with no retire transport on this DryRunSink it STAYS parked
    # (never silently dropped; the enforced drain is pinned in test_gdrive.py).
    assert delivered == 2
    assert [r["document_id"] for r in sink.requests] == [DOC_ID, TXT_ID]
    parked = json.loads((tmp_path / "gdrive_parked_retractions.json").read_text())
    assert [(e["document_id"], e["reason"]) for e in parked] == [(PDF_ID, "quarantined")]

    bodies = [b for _, b in client.posts]
    assert bodies[0]["state"] == "running"
    assert "total" not in bodies[0], "files.list is uncountable -> indeterminate"
    assert bodies[-1]["state"] == "completed"
    advanced = sum(b.get("processed_delta", 0) for b in bodies)
    assert advanced == delivered, "reported progress accounts for every delivery"


def test_run_backfill_reports_failure_then_reraises(tmp_path):
    class _BoomSink(DryRunSink):
        def deliver(self, request: dict) -> None:
            raise RuntimeError("sink exploded")

    connector = GDriveConnector(_CrawlTransport(), GDriveConfig(tenant_id=TENANT))
    registry = StaticRegistry(REGISTRY_MAP)
    client = _CapturingClient()
    reporter = BackfillReporter(
        "http://verity.local", TENANT, "gdrive", client=client, run_id="bf-fail"
    )

    with pytest.raises(RuntimeError, match="sink exploded"):
        run_backfill(
            connector,
            registry,
            _BoomSink(stream=io.StringIO()),
            tmp_path / "gdrive_cursor.json",
            reporter,
        )

    states = [b.get("state") for _, b in client.posts]
    assert states[0] == "running"
    assert states[-1] == "failed"
    assert client.posts[-1][1]["error"] == "sink exploded"
