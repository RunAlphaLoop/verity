"""Source schema-drift detection (SPEC §5b).

Field-mapping conformance tests are static; production sources drift at runtime —
custom fields added/renamed, picklist values changed, objects deprecated. Silent
drift corrupts L1, and for an ACL-bearing field it is a SCOPE-LEAK vector (a
renamed sharing field, read as absent, could default permissive). This primitive
classifies a payload against a connector's REGISTERED schema so the ingest path
can divert drifted values to quarantine (stored in L0 with full fidelity,
excluded from L1/index) rather than guess a mapping — auto-mapping is off by
default because a silent wrong mapping is itself an L1 corruption.

Two dispositions:

- **Unknown fields** (present, not mapped, not known-noise): diverted to the
  schema-drift quarantine for an admin to map/ignore. They are NOT indexed — a
  brand-new field could be a new sharing field the connector does not yet read,
  so indexing the record while ignoring it would under-represent its ACL.
- **Missing mapped fields** (renamed/removed): the L1 field cannot be populated.
  When the missing field is ACL-bearing, the WHOLE record is fail-closed
  quarantined — never indexed on a visibility set we can no longer trust. This
  composes with the server's existing refusal of an absent/malformed
  ``verity_acl``; here it names WHICH field drifted so the admin can remap.

Presence-based (rename = missing ∪ unknown; removal = missing; addition =
unknown). Type-change detection is a declared-type follow-up; presence covers the
leak-relevant cases. Pure + transport-free — the ingest layer decides what to do
with a :class:`DriftReport` (quarantine, notify), this only classifies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class SourceSchema:
    """One connector's registered field schema.

    ``mapped_fields`` are the fields the connector maps into L1; ``acl_fields`` is
    the subset whose absence is a LEAK risk (visibility-bearing); ``ignored_fields``
    are known-noise (envelope/system keys) that are neither mapped nor drift.
    """

    source: str
    mapped_fields: frozenset[str]
    acl_fields: frozenset[str] = frozenset()
    ignored_fields: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DriftReport:
    source: str
    #: present but neither mapped nor ignored → divert to quarantine (admin maps).
    unknown_fields: dict[str, Any] = field(default_factory=dict)
    #: mapped/acl fields absent from the payload (renamed or removed).
    missing_mapped: frozenset[str] = frozenset()
    #: the ACL-bearing subset of ``missing_mapped`` — the leak-critical case.
    missing_acl: frozenset[str] = frozenset()

    @property
    def has_drift(self) -> bool:
        return bool(self.unknown_fields or self.missing_mapped)

    @property
    def quarantine_record(self) -> bool:
        """Fail closed: an ACL-bearing field vanished, so the record's visibility
        can no longer be trusted — quarantine the WHOLE record rather than index it
        on a partial/absent ACL. Unknown-only drift does NOT force this (the known
        fields are still trustworthy); those values ride the field-level quarantine."""
        return bool(self.missing_acl)


def detect_drift(payload: Mapping[str, Any], schema: SourceSchema) -> DriftReport:
    """Classify ``payload`` against ``schema``. Pure."""
    keys = set(payload)
    known = schema.mapped_fields | schema.acl_fields | schema.ignored_fields
    unknown = {k: payload[k] for k in sorted(keys - known)}
    expected = schema.mapped_fields | schema.acl_fields
    missing = expected - keys
    missing_acl = schema.acl_fields - keys
    return DriftReport(
        source=schema.source,
        unknown_fields=unknown,
        missing_mapped=frozenset(missing),
        missing_acl=frozenset(missing_acl),
    )
