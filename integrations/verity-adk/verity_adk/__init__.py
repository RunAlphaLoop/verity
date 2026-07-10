"""Verity MemoryService for Google ADK — a great sink, never a loader
(SPEC §5e.4, §9c)."""

from ._client import VISIBILITY_TEACHING, VerityClient
from .memory_service import (
    MEMORY_KIND,
    UNKNOWN_SESSION_ID,
    VerityMemoryService,
    user_tag,
)

__all__ = [
    "MEMORY_KIND",
    "UNKNOWN_SESSION_ID",
    "VISIBILITY_TEACHING",
    "VerityClient",
    "VerityMemoryService",
    "user_tag",
]
