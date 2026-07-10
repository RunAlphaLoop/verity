"""Temporal orchestration tests (SPEC.md §5: durable execution for the ingest
plane).

Everything runs on temporalio's testing framework — the time-skipping
``WorkflowEnvironment`` (a local test server; retry backoffs and the poll
interval are skipped, not slept) and ``ActivityEnvironment`` (no server at
all). Connector and sink seams are mocked through the
:data:`~verity_ingest.orchestration.runners.RUNNER_FACTORIES` registry; zero
live API calls, zero running Temporal cluster required.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest

pytest.importorskip("temporalio")

from temporalio import activity  # noqa: E402
from temporalio.client import (  # noqa: E402
    Schedule,
    ScheduleAlreadyRunningError,
    ScheduleOverlapPolicy,
)
from temporalio.exceptions import ApplicationError  # noqa: E402
from temporalio.testing import ActivityEnvironment, WorkflowEnvironment  # noqa: E402
from temporalio.worker import Worker  # noqa: E402

from verity_ingest.orchestration import config, runners, schedules  # noqa: E402
from verity_ingest.orchestration.activities import run_connector_poll_cycle  # noqa: E402
from verity_ingest.orchestration.runners import CycleOutcome  # noqa: E402
from verity_ingest.orchestration.shared import (  # noqa: E402
    POLL_CYCLE_ACTIVITY,
    ConnectorSyncInput,
    PollCycleInput,
    PollCycleResult,
)
from verity_ingest.orchestration.workflows import ConnectorSyncWorkflow  # noqa: E402


async def _execute(env: WorkflowEnvironment, activities: list, input: ConnectorSyncInput):
    """Run ConnectorSyncWorkflow to completion on a unique task queue with the
    given activity implementations; follows continue-as-new to the final run."""
    task_queue = f"tq-{uuid.uuid4()}"
    async with Worker(
        env.client,
        task_queue=task_queue,
        workflows=[ConnectorSyncWorkflow],
        activities=activities,
    ):
        return await env.client.execute_workflow(
            ConnectorSyncWorkflow.run,
            input,
            id=f"wf-{uuid.uuid4()}",
            task_queue=task_queue,
        )


# ---------------------------------------------------------------------------
# Workflow behavior (time-skipping environment)
# ---------------------------------------------------------------------------


def test_workflow_schedules_activity_and_returns_cursor() -> None:
    """One cycle: the workflow schedules the poll-cycle activity with the
    input cursor and completes with the cursor the activity returned."""
    calls: list[PollCycleInput] = []

    @activity.defn(name=POLL_CYCLE_ACTIVITY)
    async def mock_cycle(input: PollCycleInput) -> PollCycleResult:
        calls.append(input)
        return PollCycleResult(cursor="cursor-1", events_delivered=3)

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            result = await _execute(
                env,
                [mock_cycle],
                ConnectorSyncInput(connector="mock", interval_seconds=60.0, max_cycles=1),
            )
            assert result == "cursor-1"

    asyncio.run(scenario())
    assert [(c.connector, c.cursor) for c in calls] == [("mock", None)]


def test_cursor_threads_through_continue_as_new() -> None:
    """Two cycles: after the interval sleep the workflow continues-as-new and
    the SECOND run's activity receives the cursor the first cycle returned —
    the cursor is workflow state, not a file."""
    calls: list[str | None] = []

    @activity.defn(name=POLL_CYCLE_ACTIVITY)
    async def mock_cycle(input: PollCycleInput) -> PollCycleResult:
        calls.append(input.cursor)
        return PollCycleResult(cursor=f"cursor-{len(calls)}", events_delivered=1)

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            result = await _execute(
                env,
                [mock_cycle],
                ConnectorSyncInput(
                    connector="mock",
                    interval_seconds=3600.0,  # time-skipped, not slept
                    cursor="cursor-0",
                    max_cycles=2,
                ),
            )
            assert result == "cursor-2"

    asyncio.run(scenario())
    assert calls == ["cursor-0", "cursor-1"]


def test_activity_retried_with_backoff_on_transient_failure() -> None:
    """A transient connector failure fails the activity attempt; the retry
    policy (exponential backoff, time-skipped here) re-runs it and the cycle
    completes on the second attempt."""
    attempts: list[int] = []

    @activity.defn(name=POLL_CYCLE_ACTIVITY)
    async def flaky_cycle(input: PollCycleInput) -> PollCycleResult:
        attempts.append(activity.info().attempt)
        if len(attempts) == 1:
            raise RuntimeError("SaaS 503 (transient)")
        return PollCycleResult(cursor="cursor-after-retry", events_delivered=5)

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            result = await _execute(
                env,
                [flaky_cycle],
                ConnectorSyncInput(connector="mock", interval_seconds=60.0, max_cycles=1),
            )
            assert result == "cursor-after-retry"

    asyncio.run(scenario())
    assert attempts == [1, 2]


class FlakyDeliveryRunner:
    """Mock connector+sink seam: the poll 'succeeds' (a next cursor exists)
    but the first sink delivery fails — exactly the window where a cursor
    advance would lose data."""

    def __init__(self) -> None:
        self.cursors_seen: list[str | None] = []
        self.delivered = 0
        self._failed_once = False

    async def run_cycle(self, cursor: str | None, heartbeat) -> CycleOutcome:
        self.cursors_seen.append(cursor)
        heartbeat("polled 2 events")
        next_cursor = "cursor-new"  # what poll() produced
        if not self._failed_once:
            self._failed_once = True
            raise RuntimeError("sink delivery failed: connection refused")
        self.delivered += 2
        return CycleOutcome(next_cursor=next_cursor, events_delivered=2)


def test_cursor_not_advanced_past_failed_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    """At-least-once preserved end to end: through the REAL activity, a
    delivery failure means no cursor is returned, and the retry polls with
    the ORIGINAL cursor — never the one from the failed cycle."""
    runner = FlakyDeliveryRunner()
    monkeypatch.setitem(runners.RUNNER_FACTORIES, "mock-flaky", lambda: runner)

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_time_skipping() as env:
            result = await _execute(
                env,
                [run_connector_poll_cycle],
                ConnectorSyncInput(
                    connector="mock-flaky",
                    interval_seconds=60.0,
                    cursor="cursor-orig",
                    max_cycles=1,
                ),
            )
            assert result == "cursor-new"

    asyncio.run(scenario())
    # Attempt 1 and the retry both saw the pre-failure cursor.
    assert runner.cursors_seen == ["cursor-orig", "cursor-orig"]
    assert runner.delivered == 2


# ---------------------------------------------------------------------------
# Activity unit tests (ActivityEnvironment — no server)
# ---------------------------------------------------------------------------


class RecordingRunner:
    def __init__(self, next_cursor: str = "cursor-next", events: int = 4) -> None:
        self.outcome = CycleOutcome(next_cursor=next_cursor, events_delivered=events)
        self.cursors: list[str | None] = []

    async def run_cycle(self, cursor: str | None, heartbeat) -> CycleOutcome:
        self.cursors.append(cursor)
        heartbeat("working")
        return self.outcome


def test_activity_returns_cursor_and_heartbeats(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = RecordingRunner()
    monkeypatch.setitem(runners.RUNNER_FACTORIES, "mock", lambda: runner)
    env = ActivityEnvironment()
    beats: list[tuple] = []
    env.on_heartbeat = lambda *args: beats.append(args)

    result = asyncio.run(env.run(run_connector_poll_cycle, PollCycleInput("mock", "c0")))

    assert result == PollCycleResult(cursor="cursor-next", events_delivered=4)
    assert runner.cursors == ["c0"]
    assert len(beats) >= 2  # cycle-start + the runner's own progress heartbeat


def test_activity_unknown_connector_is_non_retryable() -> None:
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as excinfo:
        asyncio.run(env.run(run_connector_poll_cycle, PollCycleInput("no-such-connector")))
    assert excinfo.value.non_retryable is True


def test_activity_config_error_is_non_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing visibility policy is an operator omission, not a transient
    fault: surfacing it as non-retryable stops the backoff loop cold."""
    monkeypatch.delenv("HUBSPOT_VISIBILITY", raising=False)
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as excinfo:
        asyncio.run(env.run(run_connector_poll_cycle, PollCycleInput("hubspot")))
    assert excinfo.value.non_retryable is True
    assert "HUBSPOT_VISIBILITY" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Runner seam: fail-closed visibility parsing
# ---------------------------------------------------------------------------


def test_visibility_from_env_parses_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUBSPOT_VISIBILITY", "7, 12")
    assert runners._visibility_from_env("HUBSPOT_VISIBILITY") == [7, 12]
    monkeypatch.setenv("HUBSPOT_VISIBILITY", "")
    with pytest.raises(runners.RunnerConfigError):
        runners._visibility_from_env("HUBSPOT_VISIBILITY")
    monkeypatch.setenv("HUBSPOT_VISIBILITY", "1,zebra")
    with pytest.raises(runners.RunnerConfigError):
        runners._visibility_from_env("HUBSPOT_VISIBILITY")


# ---------------------------------------------------------------------------
# Schedules helper (duck-typed client; no server)
# ---------------------------------------------------------------------------


class FakeScheduleHandle:
    def __init__(self) -> None:
        self.updated: list[Schedule] = []

    async def update(self, updater) -> None:
        self.updated.append(updater(None).schedule)


class FakeScheduleClient:
    def __init__(self, existing: set[str] | None = None) -> None:
        self.existing = existing or set()
        self.created: dict[str, Schedule] = {}
        self.handles: dict[str, FakeScheduleHandle] = {}

    async def create_schedule(self, schedule_id: str, schedule: Schedule) -> None:
        if schedule_id in self.existing:
            raise ScheduleAlreadyRunningError()
        self.created[schedule_id] = schedule

    def get_schedule_handle(self, schedule_id: str) -> FakeScheduleHandle:
        return self.handles.setdefault(schedule_id, FakeScheduleHandle())


def test_apply_schedules_creates_per_enabled_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VERITY_SYNC_INTERVAL", "120")
    monkeypatch.setenv("VERITY_SYNC_INTERVAL_GDRIVE", "30")
    client = FakeScheduleClient()

    results = asyncio.run(schedules.apply_schedules(client, ["hubspot", "gdrive"]))

    assert results == {"hubspot": "created", "gdrive": "created"}
    hubspot = client.created["verity-sync-hubspot"]
    assert hubspot.spec.intervals[0].every == timedelta(seconds=120)
    assert hubspot.policy.overlap == ScheduleOverlapPolicy.SKIP
    assert hubspot.action.id == "connector-sync-hubspot"
    assert hubspot.action.args[0].connector == "hubspot"
    gdrive = client.created["verity-sync-gdrive"]
    assert gdrive.spec.intervals[0].every == timedelta(seconds=30)


def test_apply_schedules_updates_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERITY_SYNC_INTERVAL_HUBSPOT", "45")
    client = FakeScheduleClient(existing={"verity-sync-hubspot"})

    results = asyncio.run(schedules.apply_schedules(client, ["hubspot"]))

    assert results == {"hubspot": "updated"}
    (updated,) = client.handles["verity-sync-hubspot"].updated
    assert updated.spec.intervals[0].every == timedelta(seconds=45)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_enabled_connectors_parses_dedupes_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VERITY_CONNECTORS", raising=False)
    assert config.enabled_connectors() == []  # unset = nothing syncs
    monkeypatch.setenv("VERITY_CONNECTORS", " HubSpot, gdrive ,hubspot,")
    assert config.enabled_connectors() == ["hubspot", "gdrive"]


def test_interval_seconds_overrides_and_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VERITY_SYNC_INTERVAL", raising=False)
    monkeypatch.delenv("VERITY_SYNC_INTERVAL_HUBSPOT", raising=False)
    assert config.interval_seconds("hubspot") == config.DEFAULT_INTERVAL_SECONDS
    monkeypatch.setenv("VERITY_SYNC_INTERVAL", "600")
    assert config.interval_seconds("hubspot") == 600.0
    monkeypatch.setenv("VERITY_SYNC_INTERVAL_HUBSPOT", "60")
    assert config.interval_seconds("hubspot") == 60.0
    assert config.interval_seconds("gdrive") == 600.0
    monkeypatch.setenv("VERITY_SYNC_INTERVAL_HUBSPOT", "-5")
    with pytest.raises(RuntimeError):
        config.interval_seconds("hubspot")
