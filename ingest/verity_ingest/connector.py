"""Connector SDK: the interface every source connector implements.

Milestone A ships the interface and the bench/demo connector; HubSpot and
Google Drive land in Milestone C (SPEC.md §13).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator


class Lane(Enum):
    PUSH = "push"  # webhook/CDC-driven, seconds-level
    TRUTH = "truth"  # cursor polling + full crawl; reconciles drops, deletions, ACL drift


class TrustTier(Enum):
    AUTHORITATIVE = 1
    OBSERVATION = 2


@dataclass
class FactEvent:
    """A deterministic L1 write: one (source, entity, field) value change."""

    source: str
    entity_id: str
    field_name: str
    value: Any
    valid_from: datetime
    raw_payload: dict  # lands in L0 verbatim


@dataclass
class DocumentEvent:
    """An unstructured content change: becomes chunks after enrichment."""

    source: str
    document_id: str
    content: bytes
    mime_type: str
    version: str
    acl: "AclEnvelope"
    entity_tags: list[str] = field(default_factory=list)


@dataclass
class AclEnvelope:
    """Sharing metadata that rides with every content item.

    `resolvable` is False when the connector cannot faithfully map the source's
    sharing model — the item is then quarantined (fail closed), never indexed.
    """

    resolvable: bool
    principals: list[str] = field(default_factory=list)  # source-local principal ids
    groups: list[str] = field(default_factory=list)


class Connector(abc.ABC):
    """One source system. Implementations must be resumable: both lanes
    checkpoint through the cursor the server hands back."""

    name: str

    @abc.abstractmethod
    async def push_events(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """The push lane: consume webhooks/CDC. May be a no-op for poll-only sources."""

    @abc.abstractmethod
    async def poll(self, cursor: str | None) -> tuple[list[FactEvent | DocumentEvent], str]:
        """The truth lane: incremental poll from `cursor`, returns (events, next_cursor)."""

    @abc.abstractmethod
    async def full_crawl(self) -> AsyncIterator[FactEvent | DocumentEvent]:
        """Reconciliation crawl: content, deletions, and permission drift."""
