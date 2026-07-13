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

import asyncio
import base64
import io
import json

import httpx
import pytest

from verity_ingest.connector import AclEnvelope
from verity_ingest.connectors.gmail import (
    DEBEZIUM_PATH,
    DryRunFactSink,
    DryRunSink,
    GmailConfig,
    GmailConnector,
    GmailDocumentEvent,
    StaticRegistry,
    VerityFactSink,
    _canonicalize_email,
    _CorrespondentStat,
    _is_person_display,
    _looks_like_list,
    _registrable_domain,
    build_document_request,
    build_org_envelope,
    build_person_envelope,
    deliver_facts,
    map_participants,
    message_document_id,
    parse_valid_from,
    run_backfill,
    select_org_facts,
    select_person_facts,
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


# ===========================================================================
# Fact lane: selective org/person entity facts (the anti-127-bots change).
#
# The document lane above emits participant tags + mirrored visibility on every
# body/attachment (unchanged). This second, ADDITIVE lane emits identity-keyed
# facts to POST /v1/ingest/debezium so entity RESOLUTION has something to fold:
# every external corporate DOMAIN → a singleton org canonical; ONLY real
# two-way human correspondents → a customer_contact person canonical. Bots,
# lists, no-reply and role mailboxes never become entities.
# ===========================================================================

# The mailbox owner for the fact-lane fixtures + their principal token.
FACT_OWNER = "me@myco.com"
FACT_OWNER_TOKEN = 501
FACT_REGISTRY = StaticRegistry({f"user:{FACT_OWNER}": FACT_OWNER_TOKEN})


def _fact_headers(**named: str) -> list[dict]:
    return [{"name": k.replace("_", "-"), "value": v} for k, v in named.items()]


def _fact_msg(mid: str, ms: str, **headers: str) -> dict:
    return {
        "id": mid,
        "threadId": f"th-{mid}",
        "internalDate": ms,
        "payload": {"mimeType": "text/plain", "headers": _fact_headers(**headers), "body": {}},
    }


# The §walk-through mixed batch: owner O=me@myco.com.
#   (1) "Stripe" <invoice+auto@stripe.com> → O
#   (2) O → "Jane Roe" <jane@supabase.io>
#   (3) "Jane Roe" <jane@supabase.io> → O
#   (4) notifications@github.com → O
#   (5) "Alice" <alice@gmail.com> → O
#   (6) "Bob" <bob@gmail.com> → O
_MIXED_BATCH = {
    "fm1": _fact_msg(
        "fm1", "1000",
        Message_ID="<fm1@x>", From="Stripe <invoice+auto@stripe.com>", To=FACT_OWNER,
        Subject="Invoice", Date="Wed, 08 Jul 2026 09:30:00 +0000",
    ),
    "fm2": _fact_msg(
        "fm2", "2000",
        Message_ID="<fm2@x>", From=FACT_OWNER, To="Jane Roe <jane@supabase.io>",
        Subject="Hi", Date="Wed, 08 Jul 2026 09:31:00 +0000",
    ),
    "fm3": _fact_msg(
        "fm3", "3000",
        Message_ID="<fm3@x>", From="Jane Roe <jane@supabase.io>", To=FACT_OWNER,
        Subject="Re: Hi", Date="Wed, 08 Jul 2026 09:32:00 +0000",
    ),
    "fm4": _fact_msg(
        "fm4", "4000",
        Message_ID="<fm4@x>", From="notifications@github.com", To=FACT_OWNER,
        Subject="[repo] CI", Date="Wed, 08 Jul 2026 09:33:00 +0000",
    ),
    "fm5": _fact_msg(
        "fm5", "5000",
        Message_ID="<fm5@x>", From="Alice <alice@gmail.com>", To=FACT_OWNER,
        Subject="hey", Date="Wed, 08 Jul 2026 09:34:00 +0000",
    ),
    "fm6": _fact_msg(
        "fm6", "6000",
        Message_ID="<fm6@x>", From="Bob <bob@gmail.com>", To=FACT_OWNER,
        Subject="yo", Date="Wed, 08 Jul 2026 09:35:00 +0000",
    ),
}


class FactBatchTransport:
    """A minimal transport that serves a dict of canned messages for a backfill.
    Records the documents-side calls so the fact lane can be tested end to end
    without any network."""

    def __init__(self, messages: dict[str, dict]) -> None:
        self._messages = messages

    def get_json(self, path: str, params: dict) -> dict:
        if path == "messages":
            return {"messages": [{"id": mid} for mid in self._messages]}
        parts = path.split("/")
        if len(parts) == 2 and parts[0] == "messages":
            return self._messages[parts[1]]
        raise AssertionError(f"unexpected call GET {path}")


def _fact_connector(messages: dict[str, dict], **cfg: object) -> GmailConnector:
    config = GmailConfig(tenant_id=TENANT, delegated_subject=FACT_OWNER, **cfg)
    return GmailConnector(FactBatchTransport(messages), config)


def _run_observe(messages: dict[str, dict], **cfg: object) -> GmailConnector:
    """Drive full_crawl so the fact accumulators fill exactly as in production."""
    connector = _fact_connector(messages, **cfg)

    async def _drain() -> None:
        async for _ in connector.full_crawl():
            pass

    asyncio.run(_drain())
    return connector


def _stat(inbound: bool, outbound: bool, names: set[str] | None = None, ms: int = 1):
    return _CorrespondentStat(
        inbound=inbound, outbound=outbound, display_names=names or set(), first_seen_ms=ms
    )


# ---- 1. denylist parity (mirror of canon.rs) ------------------------------


def test_canonicalize_email_denylist_parity():
    freemail = [
        "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
        "outlook.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
        "mac.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
        "zoho.com", "yandex.com", "pm.me",
    ]
    for dom in freemail:
        assert _canonicalize_email(f"jane@{dom}") is None, dom
    placeholder = [
        "example.com", "example.org", "example.net", "example.edu", "test.com",
        "none.com", "noemail.com", "no-reply.com", "noreply.com",
    ]
    for dom in placeholder:
        assert _canonicalize_email(f"jane@{dom}") is None, dom
    # localhost / invalid have no dot → rejected as malformed anyway.
    assert _canonicalize_email("jane@localhost") is None
    roles = [
        "info", "sales", "support", "admin", "noreply", "no-reply", "donotreply",
        "notifications", "newsletter", "mailer-daemon", "billing", "hi",
    ]
    for local in roles:
        assert _canonicalize_email(f"{local}@acme.com") is None, local
    # +tag still caught for a role local.
    assert _canonicalize_email("info+q3@acme.com") is None
    # malformed → None (fail closed).
    for bad in ["a@@b.com", "jane@", "@acme.com", "no-at-sign", "jane@no-dot"]:
        assert _canonicalize_email(bad) is None, bad
    # survivors canonicalize.
    assert _canonicalize_email("jane@acme.com") == "jane@acme.com"
    assert _canonicalize_email("  mailto:Bob@Acme.com ") == "bob@acme.com"
    assert _canonicalize_email("jane+news@acme.com") == "jane@acme.com"


# ---- 2. registrable domain ------------------------------------------------


def test_registrable_domain():
    assert _registrable_domain("www.acme.com") == "acme.com"
    assert _registrable_domain("mail.acme.co.uk") == "acme.co.uk"
    assert _registrable_domain("https://www.acme.com/contact?x=1") == "acme.com"
    assert _registrable_domain("host:8080".replace("host", "sub.acme.com")) == "acme.com"
    assert _registrable_domain("") is None
    assert _registrable_domain("localhost") is None  # single label


# ---- 3. person display quality gate ---------------------------------------


def test_is_person_display():
    assert _is_person_display("Jane Roe", "jane@acme.io") is True
    assert _is_person_display("", "jane@acme.io") is False
    assert _is_person_display("jane@acme.io", "jane@acme.io") is False
    assert _is_person_display("jane", "jane@acme.io") is False  # == local-part
    assert _is_person_display("GitHub", "notifications@github.com") is False  # single brand token
    assert _is_person_display("GitHub Notifications", "x@github.com") is False  # automation tail
    assert _is_person_display("Jane via Notion", "x@notion.so") is False  # byline
    assert _is_person_display("Support Team", "x@acme.io") is False  # role + tail


# ---- 4. list / ESP detection ----------------------------------------------


def test_looks_like_list():
    assert _looks_like_list("team@acme.io") is True
    assert _looks_like_list("notifications@acme.io") is True
    assert _looks_like_list("newsletter@acme.io") is True
    assert _looks_like_list("bounce@sendgrid.net") is True
    assert _looks_like_list("x@mailgun.org") is True
    assert _looks_like_list("jane@acme.io") is False


# ---- 5. two-way correspondence accumulator --------------------------------


def test_two_way_accumulator_from_full_crawl():
    conn = _run_observe(_MIXED_BATCH)
    # Jane is two-way: outbound from msg-2, inbound from msg-3.
    jane = conn._corr["jane@supabase.io"]
    assert jane.inbound and jane.outbound
    assert "Jane Roe" in jane.display_names
    # invoice@stripe.com is inbound-only (owner never wrote to it).
    inv = conn._corr["invoice@stripe.com"]
    assert inv.inbound and not inv.outbound
    # freemail strangers are NEVER accumulated → cannot ever weld.
    assert "alice@gmail.com" not in conn._corr
    assert "bob@gmail.com" not in conn._corr
    # notifications@github.com is a role local → never a person stat.
    assert not any(k.startswith("notifications@") for k in conn._corr)
    # the owner is never its own correspondent.
    assert FACT_OWNER not in conn._corr


# ---- 6. select_org_facts --------------------------------------------------


def test_select_org_facts_emits_clean_domains_only():
    conn = _run_observe(_MIXED_BATCH)
    orgs = select_org_facts(
        conn._org_domains, conn._org_first_seen, FACT_OWNER_TOKEN, owner_domain="myco.com"
    )
    ids = sorted(e["after"]["id"] for e in orgs)
    # stripe.com, github.com, supabase.io — role-local github sender STILL yields
    # its org. NO gmail.com (freemail). NO myco.com (owner's own domain).
    assert ids == ["github.com", "stripe.com", "supabase.io"]
    for e in orgs:
        assert e["after"]["kind"] == "organization"
        assert "email" not in e["after"]  # descriptive-only → singleton canonical
        assert e["verity_acl"]["visibility"] == [FACT_OWNER_TOKEN]


def test_select_org_facts_dedups_and_drops_denylisted():
    org_domains = {"stripe.com": "Stripe", "gmail.com": "Gmail", "example.com": "Example"}
    first = {"stripe.com": 1, "gmail.com": 2, "example.com": 3}
    orgs = select_org_facts(org_domains, first, FACT_OWNER_TOKEN)
    assert [e["after"]["id"] for e in orgs] == ["stripe.com"]


# ---- 7. select_person_facts (strict default) ------------------------------


def test_select_person_facts_strict_emits_two_way_human_only():
    conn = _run_observe(_MIXED_BATCH)
    persons = select_person_facts(conn._corr, FACT_OWNER_TOKEN, strict=True)
    assert [e["after"]["id"] for e in persons] == ["jane@supabase.io"]
    p = persons[0]
    assert p["after"]["email"] == "jane@supabase.io"  # BARE email → customer_contact producer
    assert p["after"]["correspondence"] == "two_way"
    assert p["after"]["name"] == "Jane Roe"
    assert p["after"]["domain"] == "supabase.io"
    assert p["source"] == {
        "connector": "gmail", "db": "contacts", "table": "person", "ts_ms": 2000,
    }
    assert p["verity_acl"]["visibility"] == [FACT_OWNER_TOKEN]
    # invoice@stripe.com is inbound-only under strict → NOT a person.
    assert not any(e["after"]["id"] == "invoice@stripe.com" for e in persons)


def test_two_way_bots_without_human_display_name_are_not_persons():
    """A two-way automation address the owner merely reply-all'd or CC'd a bot
    on must NOT become a PERSON fact. These evade _looks_like_list (novel
    local-part, non-ESP host) but have no real human display name, so the
    two-way branch's _is_person_display gate must drop them. Real two-way
    humans in the same batch still land — this is the 'NOT 127 bots' line."""
    corr = {
        # bots reaching two-way via reply-all / CC — no human name
        "ci_activity@noreply.github.com": _stat(True, True, {"GitHub CI"}),
        "tickets@zendesk-corp.io": _stat(True, True, set()),
        "jenkins@ci.internal-corp.com": _stat(True, True, {"Jenkins"}),
        "root@server.acme.com": _stat(True, True, set()),
        "list@discuss.corp.com": _stat(True, True, {"Discuss Updates"}),
        "reply@reply.intercom.io": _stat(True, True, {"Intercom"}),
        "automated-reports@bi.corp.com": _stat(True, True, {"BI Reports"}),
        # real two-way humans — must survive
        "jane@supabase.io": _stat(True, True, {"Jane Roe"}),
        "bob@acmecorp.com": _stat(True, True, {"Bob Smith"}),
    }
    persons = select_person_facts(corr, FACT_OWNER_TOKEN, strict=True)
    ids = sorted(e["after"]["id"] for e in persons)
    assert ids == ["bob@acmecorp.com", "jane@supabase.io"]
    # no automation address leaked in as a person
    for bot in (
        "ci_activity@noreply.github.com", "tickets@zendesk-corp.io",
        "jenkins@ci.internal-corp.com", "root@server.acme.com",
        "list@discuss.corp.com", "reply@reply.intercom.io",
        "automated-reports@bi.corp.com",
    ):
        assert not any(e["after"]["id"] == bot for e in persons), bot


# ---- 8. select_person_facts (--no-strict-people) --------------------------


def test_select_person_facts_relaxed_admits_named_inbound_business_human():
    corr = {
        "sarah@acme.io": _stat(inbound=True, outbound=False, names={"Sarah Chen"}),
        "dan@gmail.com": _stat(inbound=True, outbound=False, names={"Dan Stranger"}),
        "team@acme.io": _stat(inbound=True, outbound=False, names={"Acme Team"}),
    }
    relaxed = select_person_facts(corr, FACT_OWNER_TOKEN, strict=False)
    ids = sorted(e["after"]["id"] for e in relaxed)
    # named inbound business human admitted; named freemail human still dropped
    # (never accumulated in prod, and dropped here too); list address dropped.
    assert ids == ["sarah@acme.io"]
    assert relaxed[0]["after"]["correspondence"] == "inbound_named"
    # under STRICT the same single-direction contact is not admitted.
    assert select_person_facts(corr, FACT_OWNER_TOKEN, strict=True) == []


# ---- 9. envelope shape ----------------------------------------------------


def test_build_org_envelope_shape():
    env = build_org_envelope("stripe.com", "Stripe", FACT_OWNER_TOKEN, 1783000000000)
    assert env["op"] == "c"
    assert env["source"] == {
        "connector": "gmail", "db": "accounts", "table": "org", "ts_ms": 1783000000000,
    }
    assert env["after"] == {
        "id": "stripe.com", "domain": "stripe.com", "name": "Stripe", "kind": "organization",
    }
    assert env["verity_acl"] == {"visibility": [FACT_OWNER_TOKEN], "confidentiality": "internal"}
    # verity_acl is a TOP-LEVEL sibling, NOT inside after.
    assert "verity_acl" not in env["after"]


def test_build_person_envelope_shape():
    env = build_person_envelope(
        "jane@supabase.io", "Jane Roe", "supabase.io", "two_way", FACT_OWNER_TOKEN, 42
    )
    assert env["source"]["table"] == "person"
    assert env["after"]["id"] == "jane@supabase.io"
    assert env["after"]["email"] == "jane@supabase.io"  # bare email is the merge key
    assert env["after"]["correspondence"] == "two_way"
    assert "associatedcompanyid" not in env["after"] and "AccountId" not in env["after"]
    assert env["verity_acl"]["visibility"] == [FACT_OWNER_TOKEN]
    assert isinstance(env["verity_acl"]["visibility"][0], int)


# ---- 10. fail-closed: owner token unresolvable ----------------------------


def test_fail_closed_when_owner_token_missing():
    # builders return None.
    assert build_org_envelope("stripe.com", "Stripe", None, 1) is None
    assert build_person_envelope("j@acme.io", "J R", "acme.io", "two_way", None, 1) is None
    # selectors return empty.
    assert select_org_facts({"stripe.com": "Stripe"}, {"stripe.com": 1}, None) == []
    assert select_person_facts({"j@acme.io": _stat(True, True, {"J R"})}, None) == []
    # deliver_facts: a registry that resolves nothing → NO facts, sink untouched.
    conn = _run_observe(_MIXED_BATCH)
    sink = DryRunFactSink(stream=io.StringIO())
    empty_registry = StaticRegistry({})  # user:me@myco.com does NOT resolve
    orgs, persons = deliver_facts(conn, empty_registry, sink)
    assert (orgs, persons) == (0, 0)
    assert sink.envelopes == []


# ---- 11. VerityFactSink wire contract -------------------------------------


def test_verity_fact_sink_posts_array_to_debezium():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["params"] = dict(request.url.params)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"facts_ingested": 2, "facts_refused_no_acl": 0})

    client = httpx.Client(
        transport=httpx.MockTransport(handler), headers={"Authorization": "Bearer k"}
    )
    sink = VerityFactSink("http://verity.local", TENANT, client=client)
    env = build_org_envelope("stripe.com", "Stripe", FACT_OWNER_TOKEN, 1)
    sink.deliver([env], pk="id")

    assert captured["path"] == DEBEZIUM_PATH
    assert captured["params"] == {"tenant_id": TENANT, "pk": "id"}
    assert captured["auth"] == "Bearer k"
    assert isinstance(captured["body"], list) and len(captured["body"]) == 1
    # inline ACL supplies visibility — NO visibility= query param.
    assert "visibility" not in captured["params"]
    assert sink.refused == 0


def test_verity_fact_sink_skips_empty_batch():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("empty batch must not POST")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sink = VerityFactSink("http://verity.local", TENANT, client=client)
    sink.deliver([])  # no POST


# ---- 12. DryRunFactSink redaction -----------------------------------------


def test_dry_run_fact_sink_redacts_person_locals():
    buf = io.StringIO()
    sink = DryRunFactSink(stream=buf)
    person = build_person_envelope(
        "jane.roe@supabase.io", "Jane Roe", "supabase.io", "two_way", FACT_OWNER_TOKEN, 1
    )
    org = build_org_envelope("stripe.com", "Stripe", FACT_OWNER_TOKEN, 1)
    sink.deliver([org, person])
    out = buf.getvalue()
    # no full person address, no name, no token in the printed output.
    assert "jane.roe@supabase.io" not in out
    assert "jane.roe" not in out
    assert "Jane Roe" not in out
    assert str(FACT_OWNER_TOKEN) not in out
    # the redacted local + clear domain are present; org domain prints whole.
    assert "•••@supabase.io" in out
    assert "stripe.com" in out


# ---- 13. full mixed-batch integration (the §walk-through) -----------------


def test_mixed_batch_integration_three_orgs_one_person():
    conn = _run_observe(_MIXED_BATCH)
    sink = DryRunFactSink(stream=io.StringIO())
    orgs, persons = deliver_facts(conn, FACT_REGISTRY, sink)
    assert (orgs, persons) == (3, 1)
    org_env = [e for e in sink.envelopes if e["source"]["table"] == "org"]
    person_env = [e for e in sink.envelopes if e["source"]["table"] == "person"]
    assert sorted(e["after"]["id"] for e in org_env) == [
        "github.com", "stripe.com", "supabase.io",
    ]
    assert [e["after"]["id"] for e in person_env] == ["jane@supabase.io"]
    assert person_env[0]["after"]["correspondence"] == "two_way"
    # every envelope carries a non-empty int-array visibility (fail-visible).
    for e in sink.envelopes:
        vis = e["verity_acl"]["visibility"]
        assert isinstance(vis, list) and vis and all(isinstance(t, int) for t in vis)


def test_two_gmail_strangers_never_share_an_entity():
    conn = _run_observe(_MIXED_BATCH)
    persons = select_person_facts(conn._corr, FACT_OWNER_TOKEN, strict=False)
    ids = {e["after"]["id"] for e in persons}
    # neither freemail stranger is ever an entity → they cannot weld.
    assert "alice@gmail.com" not in ids
    assert "bob@gmail.com" not in ids
    assert not any(e["after"]["domain"] == "gmail.com" for e in persons if "domain" in e["after"])


# ---- 14. additivity: the document lane is unchanged -----------------------


def test_fact_lane_is_additive_document_events_unchanged():
    # The existing document-event behavior (participant tags + mirrored ACL) is
    # untouched by the fact lane: an inbox message still yields body + attachment
    # DocumentEvents with the same participant entity tags.
    (body,) = [e for e in _events("m-inbox-1") if not e.is_attachment]
    assert body.entity_tags == [
        "user:alice@corp.example",
        "user:bob@corp.example",
        "user:carol@corp.example",
    ]
    assert body.acl.resolvable is True


def test_facts_disabled_when_emit_facts_false():
    conn = _run_observe(_MIXED_BATCH, emit_facts=False)
    sink = DryRunFactSink(stream=io.StringIO())
    assert deliver_facts(conn, FACT_REGISTRY, sink) == (0, 0)
    assert sink.envelopes == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
