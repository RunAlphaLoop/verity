"""Unit tests for the §5b schema-drift detection primitive."""

from __future__ import annotations

from verity_ingest.schema_drift import DriftReport, SourceSchema, detect_drift

SCHEMA = SourceSchema(
    source="salesforce",
    mapped_fields=frozenset({"Name", "Amount", "StageName"}),
    acl_fields=frozenset({"OwnerId"}),
    ignored_fields=frozenset({"attributes", "Id", "LastModifiedDate"}),
)


def test_no_drift_when_payload_matches_schema() -> None:
    payload = {
        "Id": "006", "Name": "Deal", "Amount": 1, "StageName": "Won",
        "OwnerId": "005", "attributes": {}, "LastModifiedDate": "t",
    }
    r = detect_drift(payload, SCHEMA)
    assert not r.has_drift
    assert not r.quarantine_record
    assert r.unknown_fields == {} and not r.missing_mapped


def test_unknown_field_is_drift_but_not_fail_closed() -> None:
    # A brand-new custom field → diverted to quarantine (admin maps), but the
    # record's KNOWN fields are still trustworthy, so it is NOT fail-closed.
    payload = {"Name": "Deal", "Amount": 1, "StageName": "Won", "OwnerId": "005",
               "Custom_Discount__c": 0.2}
    r = detect_drift(payload, SCHEMA)
    assert r.has_drift
    assert r.unknown_fields == {"Custom_Discount__c": 0.2}
    assert not r.quarantine_record  # unknown-only drift never forces fail-closed


def test_missing_non_acl_mapped_field_is_drift_not_fail_closed() -> None:
    payload = {"Name": "Deal", "StageName": "Won", "OwnerId": "005"}  # Amount removed
    r = detect_drift(payload, SCHEMA)
    assert "Amount" in r.missing_mapped
    assert r.has_drift
    assert not r.quarantine_record  # a content field vanishing is not a leak


def test_missing_acl_field_forces_fail_closed_quarantine() -> None:
    # The load-bearing rule: an ACL-bearing field vanished (renamed/removed) →
    # the record's visibility cannot be trusted → quarantine the whole record.
    payload = {"Name": "Deal", "Amount": 1, "StageName": "Won"}  # OwnerId gone
    r = detect_drift(payload, SCHEMA)
    assert r.missing_acl == frozenset({"OwnerId"})
    assert r.quarantine_record


def test_rename_shows_as_missing_plus_unknown() -> None:
    # A rename OwnerId -> Owner_Id__c is both a missing ACL field (fail closed)
    # AND an unknown field (surfaced for the admin to remap onto OwnerId).
    payload = {"Name": "Deal", "Amount": 1, "StageName": "Won", "Owner_Id__c": "005"}
    r = detect_drift(payload, SCHEMA)
    assert "OwnerId" in r.missing_acl
    assert "Owner_Id__c" in r.unknown_fields
    assert r.quarantine_record


def test_ignored_fields_never_count_as_drift() -> None:
    payload = {"Name": "D", "Amount": 1, "StageName": "W", "OwnerId": "005",
               "attributes": {"type": "Opportunity"}, "Id": "006", "LastModifiedDate": "t"}
    assert detect_drift(payload, SCHEMA) == DriftReport(source="salesforce")


def test_handle_webhook_survives_envelope_drift() -> None:
    # The wiring in HubSpot's handle_webhook: an unknown envelope key still maps
    # (logged), a MISSING required key (objectId drifted away) is skipped rather
    # than crashing with a KeyError — drift never takes down the whole batch.
    from verity_ingest.connectors.hubspot import HubSpotConnector

    base = {
        "subscriptionType": "contact.propertyChange",
        "propertyName": "email",
        "propertyValue": "a@b",
        "occurredAt": 1700000000000,
    }
    good = {**base, "objectId": 42}
    added = {**base, "objectId": 43, "NEW_hubspot_field_2027": "x"}  # unknown → logged, maps
    missing = {**base}  # objectId drifted away → skipped, no KeyError
    events = HubSpotConnector.handle_webhook([good, added, missing], [1])
    assert sorted(e.entity_id for e in events) == ["42", "43"]
