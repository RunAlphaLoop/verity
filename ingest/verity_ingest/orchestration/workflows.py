"""ConnectorSyncWorkflow: the durable replacement for `--once` under cron.

One workflow instance per connector. Each iteration:

1. execute the poll-cycle activity (retries with exponential backoff — see
   ``RETRY_POLICY`` — heartbeat-timed so hangs are detected);
2. take the returned cursor into workflow state — the cursor lives HERE, in
   Temporal's event history, not in ``.verity/*_cursor`` files;
3. durable-sleep the configured interval;
4. ``continue_as_new`` with the cursor threaded into the next run's input,
   keeping event history bounded no matter how long the sync lives.

``max_cycles=1`` returns after the first cycle without sleeping — the
``--once`` equivalent for smoke tests and manual replays.

The activity is invoked BY NAME (:data:`~.shared.POLL_CYCLE_ACTIVITY`) so this
module never imports connector code into the workflow sandbox.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from verity_ingest.orchestration.shared import (
        POLL_CYCLE_ACTIVITY,
        ConnectorSyncInput,
        PollCycleInput,
        PollCycleResult,
    )

#: Exponential backoff on activity failure: 5s, 10s, 20s, ... capped at 5
#: minutes, unlimited attempts — a broken SaaS credential should page via
#: connector-status staleness, not silently drop the sync (Dust's lesson:
#: freshness pipelines are long-tail failure machines).
RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=5),
    maximum_attempts=0,  # unlimited; config errors are non-retryable at the source
)

#: One poll cycle may page through a large backfill window; heartbeats fire
#: per page/delivery, so a 2-minute heartbeat gap means "stuck", while the
#: overall cycle gets a generous half hour.
START_TO_CLOSE = timedelta(minutes=30)
HEARTBEAT_TIMEOUT = timedelta(minutes=2)


@workflow.defn
class ConnectorSyncWorkflow:
    @workflow.run
    async def run(self, input: ConnectorSyncInput) -> str | None:
        result = await workflow.execute_activity(
            POLL_CYCLE_ACTIVITY,
            PollCycleInput(connector=input.connector, cursor=input.cursor),
            result_type=PollCycleResult,
            start_to_close_timeout=START_TO_CLOSE,
            heartbeat_timeout=HEARTBEAT_TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
        cursor = result.cursor

        remaining = None if input.max_cycles is None else input.max_cycles - 1
        if remaining is not None and remaining <= 0:
            return cursor

        await workflow.sleep(input.interval_seconds)
        # NoReturn: raises ContinueAsNewError, starting a fresh run whose
        # input carries the cursor forward.
        workflow.continue_as_new(replace(input, cursor=cursor, max_cycles=remaining))
