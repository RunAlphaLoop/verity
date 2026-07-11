"""Worker activities: the poll cycle, plus the post-ingest resolution hook.

Both are executed by the worker under Temporal's retry policy (owned by the
workflow). They heartbeat so a hung network call is detected by the heartbeat
timeout instead of hanging the schedule forever.

``run_connector_poll_cycle`` failure semantics:

- Config errors (missing visibility policy, unknown connector) are
  NON-retryable — retrying cannot fix an operator omission.
- Everything else (SaaS 5xx, sink connection refused, timeouts) raises
  normally and Temporal retries with exponential backoff, re-running the
  SAME cursor. The cursor advances only on a fully delivered cycle
  (at-least-once; see :mod:`.runners`).

``trigger_entity_resolution`` is the post-ingest hook: the facts are already
committed by the time it runs, so it is BEST-EFFORT. It retries a few times on
a transient server blip, but an exhausted retry does NOT fail the sync — the
next debounced hook (or the manual /run) will resolve the same idempotent
ledger. The run endpoint is deterministic + ``ON CONFLICT DO NOTHING``, so a
duplicate fire is a safe no-op.
"""

from __future__ import annotations

import os

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from verity_ingest.orchestration.runners import RunnerConfigError, get_runner
from verity_ingest.orchestration.shared import (
    PollCycleInput,
    PollCycleResult,
    ResolveInput,
)


@activity.defn(name="run_connector_poll_cycle")
async def run_connector_poll_cycle(input: PollCycleInput) -> PollCycleResult:
    try:
        runner = get_runner(input.connector)
    except RunnerConfigError as exc:
        raise ApplicationError(str(exc), non_retryable=True) from exc
    activity.heartbeat(f"{input.connector}: cycle starting")
    outcome = await runner.run_cycle(input.cursor, heartbeat=activity.heartbeat)
    return PollCycleResult(
        cursor=outcome.next_cursor,
        events_delivered=outcome.events_delivered,
        tenant_id=outcome.tenant_id,
    )


@activity.defn(name="trigger_entity_resolution")
async def trigger_entity_resolution(input: ResolveInput) -> int:
    """POST ``/v1/admin/entity-resolution/run`` for one tenant (produce + fold).

    Returns ``evidence_produced`` from the run report (telemetry only). Reads
    ``VERITY_URL`` and ``VERITY_ADMIN_TOKEN`` the same way the sinks do, so no
    new operator config is introduced. Raises on HTTP error so Temporal's retry
    policy can ride out a transient blip; the workflow caps the attempts and
    swallows a terminal failure (the hook is best-effort — see module docstring).
    """
    url = os.environ.get("VERITY_URL", "http://127.0.0.1:7717").rstrip("/")
    token = os.environ.get("VERITY_ADMIN_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    activity.heartbeat(f"resolving tenant={input.tenant_id}")
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{url}/v1/admin/entity-resolution/run",
            json={"tenant_id": input.tenant_id},
            headers=headers,
        )
        response.raise_for_status()
        report = response.json()
    return int(report.get("evidence_produced", 0))
