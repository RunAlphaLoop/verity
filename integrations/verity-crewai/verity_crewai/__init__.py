"""Verity StorageBackend for CrewAI — a great sink, never a loader
(SPEC §5e.4, §9c)."""

from ._client import VISIBILITY_TEACHING, VerityClient
from .storage import (
    FOREIGN_EMBEDDING_TEACHING,
    RECALL_WINDOW,
    RECORD_KIND,
    VerityStorage,
    in_scope,
    scope_tag,
)

__all__ = [
    "FOREIGN_EMBEDDING_TEACHING",
    "RECALL_WINDOW",
    "RECORD_KIND",
    "VISIBILITY_TEACHING",
    "VerityClient",
    "VerityStorage",
    "in_scope",
    "scope_tag",
]
