"""Payload types shared between workflows and activities.

Stdlib-only on purpose: this module is imported inside the Temporal workflow
sandbox, so it must not pull in httpx, connectors, or anything with import
side effects.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The activity is referenced by name from the workflow (keeps the workflow
#: sandbox free of connector imports and lets tests register mocks).
POLL_CYCLE_ACTIVITY = "run_connector_poll_cycle"


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
    upserts)."""

    cursor: str | None
    events_delivered: int = 0


@dataclass
class ConnectorSyncInput:
    """ConnectorSyncWorkflow parameters.

    ``cursor`` is workflow state: it threads through continue-as-new and never
    touches the local ``.verity/*_cursor`` state files the ad-hoc runners use.
    ``max_cycles=None`` runs forever (the durable-scheduling posture);
    ``max_cycles=1`` is the ``--once`` equivalent for smoke tests.
    """

    connector: str
    interval_seconds: float = 300.0
    cursor: str | None = None
    max_cycles: int | None = None
