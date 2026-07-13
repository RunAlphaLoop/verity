"""Gmail connector conformance tests (SPEC.md §5: ACL-mapping conformance is
load-bearing and gates release).

All Gmail API payloads are canned fixtures authored inline from Google's
documented resource shapes (developers.google.com, Gmail API v1:
users.messages.list / users.messages.get / users.messages.attachments.get /
users.history.list / users.getProfile). No live API calls anywhere in this
file.

The two load-bearing decisions get the most scrutiny:
  * ``document_id`` = the RFC822 ``Message-ID`` (NOT the Gmail message id), so
    the same email in two mailboxes collapses to ONE memory; and
  * ACL = the mirrored participants (From + To + Cc) → ``user:<email>`` tokens.
"""

from __future__ import annotations

import base64
import io

import httpx
import pytest

from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.gmail import (
    DryRunSink,
    GmailConfig,
    GmailConnector,
    GmailDocumentEvent,
    StaticRegistry,
    build_document_request,
    map_participants,
    message_document_id,
    parse_valid_from,
    run_backfill,
)

TENANT = "t-acme"

# Registry that resolves the three internal participants but NOT the external
# addresses on the "no participant resolves" message.
REGISTRY_MAP = {
    "user:alice@corp.example": 101,
    "user:bob@corp.example": 202,
    "user:carol@corp.example": 303,
}

# The stable cross-mailbox dedup key: the SAME email appears as a different
# Gmail message id in the sender's Sent copy and the recipient's Inbox copy,
# but both carry this identical Message-ID header.
SHARED_MESSAGE_ID = "cafe123@mail.corp.example"

# Attachment raw bytes chosen so URL-safe and standard base64 DIFFER (the first
# triplet encodes to '+'/'/' under standard, '-'/'_' under URL-safe) — this is
# what makes the "re-encode standard" assertion meaningful rather than trivial.
ATTACH_RAW = bytes([0xFB, 0xEF, 0xBE, 0xFF])
ATTACH_DATA_URLSAFE = base64.urlsafe_b64encode(ATTACH_RAW).decode("ascii")


def _msg_inbox(msg_id: str = "m-inbox-1") -> dict:
    """A rich internal email with an attachment, as one recipient's Inbox copy."""
    return {
        "id": msg_id,
        "threadId": "t-1",
        "internalDate": "1783000000000",  # server-receipt time, NOT the Date header
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "Message-ID", "value": f"<{SHARED_MESSAGE_ID}>"},
                {"name": "From", "value": "Alice <alice@corp.example>"},
                {"name": "To", "value": "bob@corp.example"},
                {"name": "Cc", "value": "Carol <carol@corp.example>"},
                {"name": "Subject", "value": "Q3 planning"},
                # -0700 → the RFC3339 valid_from must land at 16:30:00Z.
                {"name": "Date", "value": "Wed, 08 Jul 2026 09:30:00 -0700"},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"Let's sync on Q3.").decode()},
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "agenda.pdf",
                    "body": {"attachmentId": "att-abc", "size": len(ATTACH_RAW)},
                },
            ],
        },
    }


def _msg_sent() -> dict:
    """The sender's Sent copy of the SAME email: different Gmail id, IDENTICAL
    Message-ID header (the whole point of decision #1)."""
    msg = _msg_inbox("m-sent-9")
    return msg


def _msg_noresolve() -> dict:
    """An email whose participants resolve to no token → quarantine."""
    return {
        "id": "m-noresolve",
        "threadId": "t-3",
        "internalDate": "1783000500000",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "Message-ID", "value": "<zzz999@ext.example>"},
                {"name": "From", "value": "ext@ext.example"},
                {"name": "To", "value": "ext2@ext.example"},
                {"name": "Subject", "value": "external thread"},
                {"name": "Date", "value": "Thu, 09 Jul 2026 12:00:00 +0000"},
            ],
            "body": {"data": base64.urlsafe_b64encode(b"outside the org").decode()},
        },
    }


class FixtureGmailTransport:
    """GmailTransport backed by canned dicts. ``m-boom`` raises on get_json to
    exercise per-message resilience."""

    def __init__(self, list_ids: list[str] | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._messages = {
            "m-inbox-1": _msg_inbox(),
            "m-sent-9": _msg_sent(),
            "m-noresolve": _msg_noresolve(),
        }
        # Default backfill listing: boom sits in the MIDDLE so we prove the
        # crawl survives it and still delivers the messages on either side.
        self._list_ids = list_ids or ["m-inbox-1", "m-boom", "m-noresolve"]

    def get_json(self, path: str, params: dict) -> dict:
        self.calls.append((path, dict(params)))
        if path == "profile":
            return {"emailAddress": "alice@corp.example", "historyId": "9876"}
        if path == "messages":
            return {"messages": [{"id": mid, "threadId": "t"} for mid in self._list_ids]}
        if path == "history":
            return {
                "history": [
                    {"id": "1", "messagesAdded": [{"message": {"id": "m-inbox-1"}}]},
                    # A duplicate messageAdded must not double-emit.
                    {"id": "2", "messagesAdded": [{"message": {"id": "m-inbox-1"}}]},
                ],
                "historyId": "9999",
            }
        parts = path.split("/")
        if len(parts) == 2 and parts[0] == "messages":
            mid = parts[1]
            if mid == "m-boom":
                raise httpx.ReadTimeout("boom: simulated transport failure")
            return self._messages[mid]
        if len(parts) == 4 and parts[0] == "messages" and parts[2] == "attachments":
            return {"size": len(ATTACH_RAW), "data": ATTACH_DATA_URLSAFE}
        raise AssertionError(f"unexpected Gmail call: GET {path} {params}")


def _connector(transport: FixtureGmailTransport | None = None) -> GmailConnector:
    return GmailConnector(
        transport or FixtureGmailTransport(),
        GmailConfig(tenant_id=TENANT, delegated_subject="alice@corp.example"),
    )


def _events(msg_id: str) -> list[GmailDocumentEvent]:
    return _connector()._events_for_message(msg_id)


def _delivered(
    transport: FixtureGmailTransport | None = None,
    registry: StaticRegistry | None = None,
) -> tuple[GmailConnector, list[dict]]:
    connector = _connector(transport)
    sink = DryRunSink(stream=io.StringIO())
    run_backfill(connector, registry or StaticRegistry(REGISTRY_MAP), sink)
    return connector, sink.requests


# ---------------------------------------------------------------------------
# Decision #1: Message-ID keying (the most important invariant)
# ---------------------------------------------------------------------------


def test_body_document_id_is_the_message_id_header_not_the_gmail_id():
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    # The Gmail API id is "m-inbox-1"; the memory key MUST be the Message-ID.
    assert body.document_id == SHARED_MESSAGE_ID
    assert body.document_id != "m-inbox-1"


def test_same_email_in_two_mailboxes_dedups_to_one_document_id():
    (inbox_body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    (sent_body,) = [e for e in _events("m-sent-9") if not e.is_attachment]
    # Different Gmail message ids, SAME Message-ID → SAME memory (ON CONFLICT
    # DO NOTHING collapses the two crawled copies into one).
    assert inbox_body.document_id == sent_body.document_id == SHARED_MESSAGE_ID


def test_message_id_helper_strips_angle_brackets():
    headers = [{"name": "Message-ID", "value": "  <abc@x.example>  "}]
    assert message_document_id(headers, "t-1", "1783000000000") == "abc@x.example"


def test_missing_message_id_falls_back_to_thread_and_internal_date():
    headers = [{"name": "From", "value": "a@x.example"}]
    assert (
        message_document_id(headers, "t-42", "1783000000000")
        == "gmail-thread:t-42:1783000000000"
    )


# ---------------------------------------------------------------------------
# Decision #2: participant ACL mirroring
# ---------------------------------------------------------------------------


def test_participants_from_to_cc_become_user_principals():
    envelope = map_participants(_msg_inbox()["payload"]["headers"])
    assert envelope == AclEnvelope(
        resolvable=True,
        principals=[
            "user:alice@corp.example",
            "user:bob@corp.example",
            "user:carol@corp.example",
        ],
        groups=[],
    )


def test_message_with_no_parseable_participants_quarantines():
    envelope = map_participants([{"name": "Subject", "value": "no addresses here"}])
    assert envelope == AclEnvelope(resolvable=False)


def test_body_mirrors_visibility_tokens_and_tags_participants():
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    request = build_document_request(body, StaticRegistry(REGISTRY_MAP), TENANT)
    assert request["visibility"] == [101, 202, 303]
    assert request["acl_provenance"] == "mirrored"
    # Participants are ALSO emitted as entity links (Verity resolves people by
    # email, Tier-1, from the structured From/To/Cc).
    assert request["entities"] == [
        "user:alice@corp.example",
        "user:bob@corp.example",
        "user:carol@corp.example",
    ]


def test_body_quarantines_when_no_participant_resolves():
    (body,) = [e for e in _events("m-noresolve") if not e.is_attachment]
    request = build_document_request(body, StaticRegistry(REGISTRY_MAP), TENANT)
    assert "visibility" not in request
    assert request["acl_provenance"] == "quarantined"


def test_partial_resolution_keeps_only_resolved_tokens():
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    # Only alice resolves; bob + carol confer nothing (fail-closed, §6b).
    request = build_document_request(
        body, StaticRegistry({"user:alice@corp.example": 101}), TENANT
    )
    assert request["visibility"] == [101]
    assert request["acl_provenance"] == "mirrored"


# ---------------------------------------------------------------------------
# Body content
# ---------------------------------------------------------------------------


def test_body_content_prepends_subject_and_carries_plain_text():
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    request = build_document_request(body, StaticRegistry(REGISTRY_MAP), TENANT)
    assert request["content"] == "Subject: Q3 planning\n\nLet's sync on Q3."


def test_html_only_body_is_tag_stripped():
    payload = {
        "mimeType": "text/html",
        "body": {
            "data": base64.urlsafe_b64encode(
                b"<html><body><p>Hello&nbsp;<b>world</b></p></body></html>"
            ).decode()
        },
    }
    from verity_ingest.connectors.gmail import extract_body

    assert extract_body(payload) == "Hello world"


# ---------------------------------------------------------------------------
# Attachments (URL-safe → standard base64, Message-ID-derived id)
# ---------------------------------------------------------------------------


def test_attachment_posts_as_standard_base64_with_message_id_derived_id():
    (attachment,) = [e for e in _events("m-inbox-1") if e.is_attachment]
    request = build_document_request(attachment, StaticRegistry(REGISTRY_MAP), TENANT)

    # Document id is derived from the Message-ID (so it dedups too), not the id.
    assert request["document_id"] == f"{SHARED_MESSAGE_ID}#att:att-abc"
    assert request["filename"] == "agenda.pdf"

    # Gmail handed us URL-safe base64; the endpoint must receive STANDARD.
    std = base64.b64encode(ATTACH_RAW).decode("ascii")
    assert ATTACH_DATA_URLSAFE != std  # sanity: these bytes actually differ
    assert request["content_base64"] == std
    assert base64.b64decode(request["content_base64"]) == ATTACH_RAW
    # Binary lane never doubles up a text "content" field.
    assert "content" not in request
    # Attachments inherit the parent email's mirrored visibility + tags.
    assert request["visibility"] == [101, 202, 303]
    assert request["acl_provenance"] == "mirrored"


# ---------------------------------------------------------------------------
# valid_from = the Date header, never the crawl time
# ---------------------------------------------------------------------------


def test_valid_from_is_the_date_header_not_now():
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    # Wed, 08 Jul 2026 09:30:00 -0700  ==  2026-07-08T16:30:00Z
    assert body.valid_from == "2026-07-08T16:30:00Z"
    # And decidedly NOT the internalDate (server receipt) or today's date.
    assert not body.valid_from.startswith("2026-07-12")


def test_valid_from_falls_back_to_internal_date_when_header_absent():
    headers = [{"name": "From", "value": "a@x.example"}]
    # 1783000000000 ms == 2026-07-02T13:46:40Z (server-receipt fallback)
    assert parse_valid_from(headers, "1783000000000") == "2026-07-02T13:46:40Z"


# ---------------------------------------------------------------------------
# Resilience: one bad message never aborts the crawl
# ---------------------------------------------------------------------------


def test_bad_message_is_skipped_and_the_rest_deliver():
    connector, requests = _delivered()
    # m-boom raised mid-crawl → skipped-and-counted; m-inbox-1 (body + its
    # attachment) still delivered; m-noresolve quarantined (not indexable).
    assert connector.skipped == 1
    delivered_ids = [r["document_id"] for r in requests]
    assert delivered_ids == [SHARED_MESSAGE_ID, f"{SHARED_MESSAGE_ID}#att:att-abc"]
    # The quarantined external message never reached the sink.
    assert all("ext.example" not in did for did in delivered_ids)


def test_backfill_returns_delivered_count():
    connector, requests = _delivered()
    assert len(requests) == 2  # one body + one attachment from the good message


# ---------------------------------------------------------------------------
# Full request-body shape (POST /v1/ingest/documents contract)
# ---------------------------------------------------------------------------


def test_body_request_shape_exact():
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    assert build_document_request(body, StaticRegistry(REGISTRY_MAP), TENANT) == {
        "tenant_id": TENANT,
        "source": "gmail",
        "document_id": SHARED_MESSAGE_ID,
        "content": "Subject: Q3 planning\n\nLet's sync on Q3.",
        "entities": [
            "user:alice@corp.example",
            "user:bob@corp.example",
            "user:carol@corp.example",
        ],
        "valid_from": "2026-07-08T16:30:00Z",
        "visibility": [101, 202, 303],
        "acl_provenance": "mirrored",
    }


# ---------------------------------------------------------------------------
# Poll lane: historyId cursor
# ---------------------------------------------------------------------------


def test_first_poll_reads_profile_history_id_and_emits_nothing():
    import asyncio

    connector = _connector()
    events, cursor = asyncio.run(connector.poll(None))
    assert events == []
    assert cursor == "9876"


def test_poll_emits_new_messages_and_advances_cursor():
    import asyncio

    connector = _connector()
    events, cursor = asyncio.run(connector.poll("9876"))
    # Two messagesAdded records reference the same id → deduped to one message
    # (body + attachment), and the cursor advances to the mailbox historyId.
    assert cursor == "9999"
    assert [e.document_id for e in events] == [
        SHARED_MESSAGE_ID,
        f"{SHARED_MESSAGE_ID}#att:att-abc",
    ]


def test_dry_run_sink_posts_nothing():
    connector, requests = _delivered()
    # DryRunSink only collects; the transport never saw a documents POST (it is
    # Gmail-only). This is implicit, but assert the sink captured bodies.
    assert requests and all("document_id" in r for r in requests)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
