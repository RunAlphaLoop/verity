"""The one activity: run a single connector poll cycle.

Executed by the worker under Temporal's retry policy (owned by the workflow).
Heartbeats before polling and during delivery, so a hung SaaS call is
detected by the heartbeat timeout instead of hanging the schedule forever.

Failure semantics:

- Config errors (missing visibility policy, unknown connector) are
  NON-retryable — retrying cannot fix an operator omission.
- Everything else (SaaS 5xx, sink connection refused, timeouts) raises
  normally and Temporal retries with exponential backoff, re-running the
  SAME cursor. The cursor advances only on a fully delivered cycle
  (at-least-once; see :mod:`.runners`).
"""

from __future__ import annotations

from temporalio import activity
from temporalio.exceptions import ApplicationError

from verity_ingest.orchestration.runners import RunnerConfigError, get_runner
from verity_ingest.orchestration.shared import PollCycleInput, PollCycleResult


@activity.defn(name="run_connector_poll_cycle")
async def run_connector_poll_cycle(input: PollCycleInput) -> PollCycleResult:
    try:
        runner = get_runner(input.connector)
    except RunnerConfigError as exc:
        raise ApplicationError(str(exc), non_retryable=True) from exc
    activity.heartbeat(f"{input.connector}: cycle starting")
    outcome = await runner.run_cycle(input.cursor, heartbeat=activity.heartbeat)
    return PollCycleResult(cursor=outcome.next_cursor, events_delivered=outcome.events_delivered)
