"""Payload types shared between workflows and activities.

Stdlib-only on purpose: this module is imported inside the Temporal workflow
sandbox, so it must not pull in httpx, connectors, or anything with import
side effects.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The activities are referenced by name from the workflow (keeps the workflow
#: sandbox free of connector/httpx imports and lets tests register mocks).
POLL_CYCLE_ACTIVITY = "run_connector_poll_cycle"

#: Post-ingest hook: after a cycle delivers events, the workflow schedules this
#: activity (debounced — see :class:`ConnectorSyncInput`) to fire the tenant's
#: Tier-1 resolution run (POST /v1/admin/entity-resolution/run). It lives in the
#: worker/admin plane and never touches the read path.
RESOLVE_ACTIVITY = "trigger_entity_resolution"

#: Default debounce between post-ingest resolution runs for one connector chain.
#: A large backfill pages every ``interval_seconds`` for a long time; without a
#: floor that would fold on every page. 15 min is a conservative "fresh enough
#: for humans, cheap enough for a backfill" default; override per deployment via
#: ``VERITY_RESOLVE_DEBOUNCE`` (see :mod:`.config`).
DEFAULT_RESOLVE_DEBOUNCE_SECONDS = 900.0


@dataclass
class PollCycleInput:
    """One poll-cycle request: which connector, and the cursor to resume from
    (``None`` = the connector's own from-the-beginning semantics)."""

    connector: str
    cursor: str | None = None


@dataclass
class PollCycleResult:
    """One poll-cycle outcome. ``cursor`` is the checkpoint to carry forward —
    the activity returns it only after sink delivery succeeded, so a crash or
    delivery failure replays the window (at-least-once, safe on keyed L1
    upserts).

    ``tenant_id`` is the tenant the cycle just wrote into: the runner is the
    only layer that knows it (from env or the connector config), and the
    workflow needs it to fire the post-ingest resolution run. ``None`` when the
    runner could not determine a tenant (older/mock runners) — the workflow
    then skips the resolve hook rather than guessing.
    """

    cursor: str | None
    events_delivered: int = 0
    tenant_id: str | None = None


@dataclass
class ResolveInput:
    """One post-ingest resolution request: which tenant to resolve. The
    activity POSTs it to ``/v1/admin/entity-resolution/run`` (produce + fold)."""

    tenant_id: str


@dataclass
class ConnectorSyncInput:
    """ConnectorSyncWorkflow parameters.

    ``cursor`` is workflow state: it threads through continue-as-new and never
    touches the local ``.verity/*_cursor`` state files the ad-hoc runners use.
    ``max_cycles=None`` runs forever (the durable-scheduling posture);
    ``max_cycles=1`` is the ``--once`` equivalent for smoke tests.

    ``resolve_debounce_seconds`` rate-limits the post-ingest resolution hook:
    resolution fires at most once per this window across cycles.
    ``last_resolve_at_ms`` is durable debounce state — the workflow-clock time
    (ms since epoch, from ``workflow.now()``) of the last resolve it triggered;
    it threads through continue-as-new so a backfill paging for hours still
    folds on the debounce cadence, not per page. ``resolve_debounce_seconds <=
    0`` disables the hook entirely (resolution stays fully manual).
    """

    connector: str
    interval_seconds: float = 300.0
    cursor: str | None = None
    max_cycles: int | None = None
    resolve_debounce_seconds: float = DEFAULT_RESOLVE_DEBOUNCE_SECONDS
    last_resolve_at_ms: float | None = None
