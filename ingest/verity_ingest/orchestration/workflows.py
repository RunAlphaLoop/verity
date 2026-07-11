"""ConnectorSyncWorkflow: the durable replacement for `--once` under cron.

One workflow instance per connector. Each iteration:

1. execute the poll-cycle activity (retries with exponential backoff — see
   ``RETRY_POLICY`` — heartbeat-timed so hangs are detected);
2. take the returned cursor into workflow state — the cursor lives HERE, in
   Temporal's event history, not in ``.verity/*_cursor`` files;
3. POST-INGEST HOOK: if the cycle delivered events for a known tenant AND the
   debounce window has elapsed, fire the tenant's Tier-1 resolution run so
   ingested facts become resolved canonical entities without a manual API call.
   The debounce is deterministic workflow-clock state threaded through
   continue-as-new, so a large backfill folds on a cadence, not per page;
4. durable-sleep the configured interval;
5. ``continue_as_new`` with the cursor AND the debounce timestamp threaded into
   the next run's input, keeping event history bounded no matter how long the
   sync lives.

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
        RESOLVE_ACTIVITY,
        ConnectorSyncInput,
        PollCycleInput,
        PollCycleResult,
        ResolveInput,
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

#: The post-ingest resolution hook is BEST-EFFORT: the facts are already
#: committed, so a resolve failure must never fail the sync. A short bounded
#: retry rides out a transient server blip; a terminal failure is swallowed by
#: the workflow and the next debounced hook (or the manual /run) resolves the
#: same idempotent ledger. The run itself (produce + fold) is bounded.
RESOLVE_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)
RESOLVE_START_TO_CLOSE = timedelta(minutes=10)
RESOLVE_HEARTBEAT_TIMEOUT = timedelta(minutes=2)


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

        # Post-ingest hook: fire the tenant's resolution run, debounced.
        last_resolve_at_ms = await self._maybe_resolve(input, result)

        remaining = None if input.max_cycles is None else input.max_cycles - 1
        if remaining is not None and remaining <= 0:
            return cursor

        await workflow.sleep(input.interval_seconds)
        # NoReturn: raises ContinueAsNewError, starting a fresh run whose input
        # carries the cursor AND the debounce timestamp forward.
        workflow.continue_as_new(
            replace(
                input,
                cursor=cursor,
                max_cycles=remaining,
                last_resolve_at_ms=last_resolve_at_ms,
            )
        )

    async def _maybe_resolve(
        self, input: ConnectorSyncInput, result: PollCycleResult
    ) -> float | None:
        """Debounced post-ingest resolution. Returns the (possibly updated)
        ``last_resolve_at_ms`` to thread into continue-as-new.

        Fires ONLY when: the hook is enabled (``resolve_debounce_seconds > 0``),
        the cycle delivered events, the runner reported a tenant, and the
        debounce window has elapsed since the last resolve. Everything is driven
        by ``workflow.now()`` (deterministic, replay-safe) and durable input
        state, so a backfill paging for hours resolves on the debounce cadence
        rather than on every page.
        """
        if input.resolve_debounce_seconds <= 0:
            return input.last_resolve_at_ms  # hook disabled → resolution manual
        if result.events_delivered <= 0 or result.tenant_id is None:
            return input.last_resolve_at_ms  # nothing new / tenant unknown

        now_ms = workflow.now().timestamp() * 1000.0
        window_ms = input.resolve_debounce_seconds * 1000.0
        if (
            input.last_resolve_at_ms is not None
            and now_ms - input.last_resolve_at_ms < window_ms
        ):
            return input.last_resolve_at_ms  # still inside the debounce window

        try:
            await workflow.execute_activity(
                RESOLVE_ACTIVITY,
                ResolveInput(tenant_id=result.tenant_id),
                start_to_close_timeout=RESOLVE_START_TO_CLOSE,
                heartbeat_timeout=RESOLVE_HEARTBEAT_TIMEOUT,
                retry_policy=RESOLVE_RETRY_POLICY,
            )
        except Exception:  # noqa: BLE001
            # Best-effort: facts are committed, the ledger is idempotent. Swallow
            # so a resolve blip never breaks the sync loop; advance the debounce
            # clock anyway so a persistently-failing endpoint can't turn every
            # page of a backfill into a resolve attempt.
            workflow.logger.warning(
                "post-ingest resolution failed for tenant %s (connector %s); "
                "will retry on next debounced cycle",
                result.tenant_id,
                input.connector,
            )
        return now_ms
