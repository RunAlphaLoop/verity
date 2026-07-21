"""Unit tests for the Salesforce fidelity-audit pure core (no live org)."""

from __future__ import annotations

from verity_ingest.salesforce_fidelity import (
    AuditUser,
    Cause,
    Verdict,
    attribute,
    classify,
    summarize,
)


def test_classify_all_four_quadrants() -> None:
    assert classify(True, True) is Verdict.MATCH_GRANT
    assert classify(False, False) is Verdict.MATCH_DENY
    assert classify(True, False) is Verdict.OVER_HIDE  # safe
    assert classify(False, True) is Verdict.UNDER_HIDE  # the leak


def test_attribute_prefers_unmapped_identity_over_view_all() -> None:
    # A non-human view-all user (integration account) has view-all BUT no fed id;
    # it can never resolve, so the dominant, honest cause is the missing identity
    # — NOT view-all (the view-all fix would leave it dropped, correctly).
    assert (
        attribute(has_federation_id=False, has_view_all=True) is Cause.UNMAPPED_IDENTITY
    )
    assert (
        attribute(has_federation_id=False, has_view_all=False) is Cause.UNMAPPED_IDENTITY
    )


def test_attribute_view_all_then_non_floor() -> None:
    assert attribute(has_federation_id=True, has_view_all=True) is Cause.VIEW_ALL
    # A mapped human SF grants but the floor does not stamp, and it is NOT view-all
    # → the role-hierarchy/sharing-rule/territory residue.
    assert attribute(has_federation_id=True, has_view_all=False) is Cause.NON_FLOOR


def test_summarize_counts_and_attributes() -> None:
    users = {
        "005owner": AuditUser("Owner", "fed-owner"),
        "005mgr": AuditUser("Manager", "fed-mgr"),  # role hierarchy, no floor mirror
        "005bot": AuditUser("Bot", None),  # non-human view-all
        "005none": AuditUser("Bystander", "fed-bystander"),
    }
    # The connector stamps only the owner's fed subject on the record.
    grants = {"001A": {"fed-owner"}}
    oracle = {
        ("005owner", "001A"): True,  # owner: SF grants, Verity grants  -> match
        ("005mgr", "001A"): True,  # SF grants (role hierarchy), Verity denies -> over
        ("005bot", "001A"): True,  # SF grants (view-all), Verity denies -> over
        ("005none", "001A"): False,  # neither -> match(deny)
    }
    report = summarize(users, grants, oracle, view_all_user_ids={"005bot"})

    assert report.count(Verdict.MATCH_GRANT) == 1
    assert report.count(Verdict.MATCH_DENY) == 1
    assert report.count(Verdict.OVER_HIDE) == 2
    assert report.count(Verdict.UNDER_HIDE) == 0
    assert report.leaks == []

    hist = report.cause_histogram()
    assert hist[Cause.UNMAPPED_IDENTITY] == 1  # the bot
    assert hist[Cause.NON_FLOOR] == 1  # the manager (role hierarchy)


def test_summarize_flags_a_leak_loudly() -> None:
    # A synthetic UNDER-HIDE: Verity would grant a user SF actually denies. The
    # audit must surface it as a leak (the gate's non-zero condition).
    users = {"005x": AuditUser("Mallory", "fed-x")}
    grants = {"001A": {"fed-x"}}  # Verity stamps fed-x
    oracle = {("005x", "001A"): False}  # SF denies
    report = summarize(users, grants, oracle, view_all_user_ids=set())
    assert report.count(Verdict.UNDER_HIDE) == 1
    assert len(report.leaks) == 1
    assert "LEAK" in report.render()


def test_user_with_no_fed_id_never_grants_even_if_subject_present() -> None:
    # Defensive: a user with no fed id must never be counted as a grant, even if
    # some stray empty/None sneaks into the subject set.
    users = {"005n": AuditUser("NoFed", None)}
    grants = {"001A": {"", "fed-real"}}
    oracle = {("005n", "001A"): False}
    report = summarize(users, grants, oracle, view_all_user_ids=set())
    assert report.count(Verdict.MATCH_DENY) == 1
    assert report.count(Verdict.UNDER_HIDE) == 0
