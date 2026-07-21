"""Salesforce ACL-fidelity audit (SPEC §14.3 — "the most likely real-world leak").

The Salesforce connector mirrors an APPROXIMATED visibility floor: it stamps a
record with the cross-source principals it can derive from ``AccountShare`` (the
owner + explicit shares, keyed on ``FederationIdentifier``). That floor is a
SUBSET of effective Salesforce visibility (which also flows through OWD, role
hierarchy, sharing rules, implicit parent→child, territories, and profile
View/Modify-All). SPEC forbids trusting an unmeasured approximation, so this
module MEASURES it against Salesforce's own effective-access oracle, the
``UserRecordAccess`` sObject.

``include_view_all_fix`` folds in the org-wide View/Modify-All users to preview
the RESIDUAL gap a view-all reconstruction would leave — the audit doubles as the
regression oracle for that (as-yet-unbuilt) connector extension.

For every (user, record) pair it compares two booleans:

- ``sf_read``  — ``UserRecordAccess.HasReadAccess``: Salesforce's ground truth.
- ``verity``   — does the connector stamp a principal this user resolves through?
                 (their ``FederationIdentifier`` ∈ the record's derived subject
                 set). A user with no ``FederationIdentifier`` never resolves.

and classifies the pair:

- **match**       — the two agree (grant or deny).
- **over_hide**   — SF grants, Verity denies. SAFE (fail-closed floor); costs
                    availability, never leaks. Every honest approximation gap
                    lands here.
- **under_hide**  — Verity grants, SF denies. THE LEAK. This count is the headline
                    safety number; the connector is designed so it stays 0.

Over-hides are attributed to a cause (owner-not-mapped, view-all, no federation
id / non-human, group-share, or unexplained-by-floor = the role-hierarchy /
sharing-rule / territory residue) so the report says WHY we differ, not just that
we do. The pure classification/attribution core (:func:`classify`,
:func:`attribute`, :func:`summarize`) is transport-free and unit-tested; the live
shell (:class:`SalesforceOracle`, :func:`audit`) speaks read-only SOQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence

from verity_ingest.connectors.salesforce import (
    API_VERSION,
    GROUP_KEY_PREFIX,
    USER_KEY_PREFIX,
    SalesforceConnector,
    SalesforceUserInfo,
    group_principal,
)

#: The connector's raw-share → (groups, owner fed subjects) crosswalk, reused
#: verbatim so the audit's "what Verity grants" is the connector's real logic.
resolve_share_principals = SalesforceConnector.resolve_share_principals


class Verdict(str, Enum):
    MATCH_GRANT = "match(grant)"
    MATCH_DENY = "match(deny)"
    OVER_HIDE = "over-hide"
    UNDER_HIDE = "UNDER-HIDE=LEAK"


class Cause(str, Enum):
    """Why an over-hide happened — what effective-visibility source the floor
    does not (yet) mirror. ``UNMAPPED_IDENTITY`` and ``VIEW_ALL`` are closable
    connector gaps; ``NON_FLOOR`` is the role-hierarchy/sharing-rule/territory
    residue that needs a real org to reconstruct safely."""

    NONE = "-"
    UNMAPPED_IDENTITY = "no-federation-id (non-human / unmapped)"
    VIEW_ALL = "view-all-data (profile/permset)"
    NON_FLOOR = "role-hierarchy / sharing-rule / territory (not in floor)"


@dataclass(frozen=True)
class Pair:
    """One audited (user, record) cell."""

    user_id: str
    user_name: str
    record_id: str
    sf_read: bool
    verity_grant: bool
    verdict: Verdict
    cause: Cause = Cause.NONE


def classify(sf_read: bool, verity_grant: bool) -> Verdict:
    """The four-way verdict for one (user, record) pair. Pure."""
    if sf_read and verity_grant:
        return Verdict.MATCH_GRANT
    if not sf_read and not verity_grant:
        return Verdict.MATCH_DENY
    if sf_read and not verity_grant:
        return Verdict.OVER_HIDE
    return Verdict.UNDER_HIDE


def attribute(
    *,
    has_federation_id: bool,
    has_view_all: bool,
) -> Cause:
    """Best-effort cause for an OVER-HIDE, most-specific first. Pure.

    A user with no FederationIdentifier can never resolve through ANY stamped
    principal, so that is the dominant explanation when present (it is also why
    integration/system users — which carry no SSO subject — are correctly held).
    Otherwise, org-wide View-All is the next closable cause. Anything left is the
    role-hierarchy / sharing-rule / territory residue the floor does not model.
    """
    if not has_federation_id:
        return Cause.UNMAPPED_IDENTITY
    if has_view_all:
        return Cause.VIEW_ALL
    return Cause.NON_FLOOR


@dataclass
class FidelityReport:
    pairs: list[Pair] = field(default_factory=list)
    #: records audited that get NO per-record resolution today (Contact/Opp etc.
    #: — the connector only mirrors AccountShare), reported separately so their
    #: over-hides are not mistaken for a role/sharing gap.
    unresolved_object_records: dict[str, int] = field(default_factory=dict)

    @property
    def leaks(self) -> list[Pair]:
        return [p for p in self.pairs if p.verdict is Verdict.UNDER_HIDE]

    def count(self, verdict: Verdict) -> int:
        return sum(1 for p in self.pairs if p.verdict is verdict)

    def cause_histogram(self) -> dict[Cause, int]:
        hist: dict[Cause, int] = {}
        for p in self.pairs:
            if p.verdict is Verdict.OVER_HIDE:
                hist[p.cause] = hist.get(p.cause, 0) + 1
        return hist

    def render(self) -> str:
        lines = [
            f"{'User':26s} {'Record':20s} {'SF':4s} {'Verity':7s} {'Verdict':16s} Cause",
            "-" * 108,
        ]
        for p in self.pairs:
            lines.append(
                f"{p.user_name[:25]:26s} {p.record_id[:19]:20s} "
                f"{('yes' if p.sf_read else 'no'):4s} "
                f"{('yes' if p.verity_grant else 'no'):7s} "
                f"{p.verdict.value:16s} {p.cause.value if p.verdict is Verdict.OVER_HIDE else ''}"
            )
        lines.append("-" * 108)
        lines.append(
            f"SUMMARY: match={self.count(Verdict.MATCH_GRANT) + self.count(Verdict.MATCH_DENY)}  "
            f"over-hide={self.count(Verdict.OVER_HIDE)}  "
            f"UNDER-HIDE/LEAK={self.count(Verdict.UNDER_HIDE)}"
        )
        if self.cause_histogram():
            lines.append("over-hide causes:")
            for cause, n in sorted(self.cause_histogram().items(), key=lambda kv: -kv[1]):
                lines.append(f"    {n:4d}  {cause.value}")
        if self.unresolved_object_records:
            lines.append(
                "records with NO per-record resolution today (ride admin floor; separate gap): "
                + ", ".join(f"{k}={v}" for k, v in sorted(self.unresolved_object_records.items()))
            )
        if self.leaks:
            lines.append(f"!!! {len(self.leaks)} LEAK(S) — investigate immediately:")
            for p in self.leaks:
                lines.append(f"    user={p.user_name} record={p.record_id}")
        else:
            lines.append("headline: 0 leaks — the mirror is a measured fail-closed floor.")
        return "\n".join(lines)


def summarize(
    users: Mapping[str, "AuditUser"],
    record_grant_subjects: Mapping[str, set[str]],
    oracle_read: Mapping[tuple[str, str], bool],
    view_all_user_ids: Iterable[str],
) -> FidelityReport:
    """Build the report from resolved inputs. Pure — the unit-test seam.

    ``users``                 — user_id → AuditUser (name, lowercased fed id).
    ``record_grant_subjects`` — record_id → set of lowercased fed subjects the
                                connector stamps (owner ∪ group members ∪ view-all).
    ``oracle_read``           — (user_id, record_id) → SF HasReadAccess.
    ``view_all_user_ids``     — users with org-wide View/Modify All Data.
    """
    view_all = set(view_all_user_ids)
    report = FidelityReport()
    for record_id, subjects in record_grant_subjects.items():
        for user_id, u in users.items():
            verity = bool(u.federation_id) and u.federation_id in subjects
            sf_read = oracle_read.get((user_id, record_id), False)
            verdict = classify(sf_read, verity)
            cause = Cause.NONE
            if verdict is Verdict.OVER_HIDE:
                cause = attribute(
                    has_federation_id=bool(u.federation_id),
                    has_view_all=user_id in view_all,
                )
            report.pairs.append(
                Pair(user_id, u.name, record_id, sf_read, verity, verdict, cause)
            )
    return report


@dataclass(frozen=True)
class AuditUser:
    name: str
    federation_id: str | None  # lowercased, or None


# ---------------------------------------------------------------------------
# Live shell — read-only SOQL against a real org (BYOT token).
# ---------------------------------------------------------------------------


class SalesforceOracle:
    """Thin read-only SOQL client (httpx). Speaks only GET /query — no writes.

    Auth is a bearer token the caller already holds (e.g. from the Salesforce
    CLI via `StaticKey`); this shell never mints or stores a credential.
    """

    def __init__(self, instance_url: str, token: str, client=None) -> None:
        import httpx  # local import keeps the pure core dependency-free at import

        self._base = instance_url.rstrip("/")
        self._path = f"/services/data/{API_VERSION}/query"
        self._client = client or httpx.Client(
            timeout=60.0, headers={"Authorization": f"Bearer {token}"}
        )

    def query(self, soql: str) -> list[dict]:
        records: list[dict] = []
        params: dict | None = {"q": soql}
        url = f"{self._base}{self._path}"
        while True:
            resp = self._client.get(url, params=params)
            resp.raise_for_status()
            body = resp.json()
            records.extend(body.get("records", []))
            nxt = body.get("nextRecordsUrl")
            if not nxt:
                return records
            url = f"{self._base}{nxt}"
            params = None

    def has_read(self, user_id: str, record_ids: Sequence[str]) -> dict[str, bool]:
        """UserRecordAccess.HasReadAccess for one user over many records. The
        object only permits selecting RecordId/Has*Access/MaxAccessLevel and
        filtering UserId in the WHERE — so it is one query per user."""
        out: dict[str, bool] = {rid: False for rid in record_ids}
        for chunk in _chunk(list(record_ids), 190):
            ids = "','".join(chunk)
            rows = self.query(
                "SELECT RecordId, HasReadAccess FROM UserRecordAccess "
                f"WHERE UserId = '{user_id}' AND RecordId IN ('{ids}')"
            )
            for r in rows:
                out[r["RecordId"]] = bool(r["HasReadAccess"])
        return out


def _chunk(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i : i + n]


def _view_all_user_ids(oracle: SalesforceOracle) -> set[str]:
    """Users with org-wide View All Data or Modify All Data — via ANY assigned
    permission set (a Profile is a PermissionSet with IsOwnedByProfile=true, so
    this one join covers both profile- and permission-set-granted view-all)."""
    rows = oracle.query(
        "SELECT AssigneeId FROM PermissionSetAssignment "
        "WHERE PermissionSet.PermissionsViewAllData = true "
        "OR PermissionSet.PermissionsModifyAllData = true"
    )
    return {r["AssigneeId"] for r in rows}


def _account_grant_subjects(
    oracle: SalesforceOracle, account_ids: Sequence[str]
) -> dict[str, set[str]]:
    """Replicate the connector's Account visibility derivation on live data:
    AccountShare 005/00G → (owner fed subjects ∪ group-member fed subjects),
    keyed on FederationIdentifier exactly as :func:`resolve_share_principals`."""
    if not account_ids:
        return {}
    ids = "','".join(account_ids)
    shares = oracle.query(
        "SELECT AccountId, UserOrGroupId FROM AccountShare "
        f"WHERE AccountId IN ('{ids}')"
    )
    per_account: dict[str, list[str]] = {}
    for row in shares:
        uog = str(row.get("UserOrGroupId") or "")
        if uog.startswith(USER_KEY_PREFIX) or uog.startswith(GROUP_KEY_PREFIX):
            per_account.setdefault(row["AccountId"], []).append(uog)

    # Roster: fed id for every share-005 AND every group member-005 (one hop of
    # GroupMember expansion covers the flat case; the connector's SpiceDB closure
    # handles deeper nesting, out of scope for this floor-vs-oracle audit).
    share_users = {s for ids_ in per_account.values() for s in ids_ if s.startswith(USER_KEY_PREFIX)}
    share_groups = {s for ids_ in per_account.values() for s in ids_ if s.startswith(GROUP_KEY_PREFIX)}
    group_members: dict[str, list[str]] = {}
    member_users: set[str] = set()
    if share_groups:
        gids = "','".join(sorted(share_groups))
        for row in oracle.query(
            f"SELECT GroupId, UserOrGroupId FROM GroupMember WHERE GroupId IN ('{gids}')"
        ):
            m = str(row.get("UserOrGroupId") or "")
            group_members.setdefault(group_principal(str(row["GroupId"])), []).append(m)
            if m.startswith(USER_KEY_PREFIX):
                member_users.add(m)

    roster: dict[str, SalesforceUserInfo] = {}
    all_users = sorted(share_users | member_users)
    if all_users:
        uids = "','".join(all_users)
        for row in oracle.query(
            f"SELECT Id, Email, FederationIdentifier, IsActive FROM User WHERE Id IN ('{uids}')"
        ):
            fed = (row.get("FederationIdentifier") or "").strip().lower() or None
            roster[str(row["Id"])] = SalesforceUserInfo(
                email=(row.get("Email") or "").strip().lower(),
                federation_identifier=fed,
                is_active=bool(row.get("IsActive", True)),
            )

    out: dict[str, set[str]] = {}
    for account_id, share_ids in per_account.items():
        _groups, owner_subjects = resolve_share_principals(share_ids, roster)
        subjects: set[str] = set(owner_subjects or [])
        for g in _groups or []:
            for m in group_members.get(g, []):
                info = roster.get(m)
                if info and info.is_active and info.federation_identifier:
                    subjects.add(info.federation_identifier.strip().lower())
        out[account_id] = subjects
    return out


def audit(
    oracle: SalesforceOracle,
    *,
    sample_accounts: int = 200,
    include_view_all_fix: bool = False,
) -> FidelityReport:
    """Run the live floor-vs-oracle audit over Accounts (the objects the connector
    resolves per-record). ``include_view_all_fix`` folds the org-wide view-all
    users' fed subjects into every record's stamped set — set True to measure the
    RESIDUAL gap after the view-all reconstruction lands."""
    users_rows = oracle.query(
        "SELECT Id, Name, FederationIdentifier FROM User WHERE IsActive = true"
    )
    users = {
        r["Id"]: AuditUser(
            name=r.get("Name") or r["Id"],
            federation_id=(r.get("FederationIdentifier") or "").strip().lower() or None,
        )
        for r in users_rows
    }
    view_all = _view_all_user_ids(oracle)

    account_rows = oracle.query(f"SELECT Id FROM Account LIMIT {int(sample_accounts)}")
    account_ids = [r["Id"] for r in account_rows]
    grants = _account_grant_subjects(oracle, account_ids)

    if include_view_all_fix:
        va_subjects = {
            users[uid].federation_id
            for uid in view_all
            if uid in users and users[uid].federation_id
        }
        for rid in grants:
            grants[rid] |= va_subjects  # type: ignore[arg-type]

    oracle_read: dict[tuple[str, str], bool] = {}
    for uid in users:
        for rid, has in oracle.has_read(uid, account_ids).items():
            oracle_read[(uid, rid)] = has

    report = summarize(users, grants, oracle_read, view_all)
    # Objects the connector does not resolve per-record today (honest note).
    for obj in ("Contact", "Opportunity"):
        n = oracle.query(f"SELECT COUNT(Id) c FROM {obj}")
        cnt = n[0].get("c") if n else 0
        if cnt:
            report.unresolved_object_records[obj] = int(cnt)
    return report


# ---------------------------------------------------------------------------
# CLI — read-only live audit. Token is BYOT (never minted here).
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import json
    import os

    p = argparse.ArgumentParser(
        prog="python -m verity_ingest.salesforce_fidelity",
        description="Audit the Salesforce connector's visibility floor against the "
        "UserRecordAccess oracle (read-only).",
    )
    p.add_argument(
        "--org-json",
        help="path to `sf org display --json` output (reads result.instanceUrl + "
        "result.accessToken); or set SF_INSTANCE_URL + SF_ACCESS_TOKEN",
    )
    p.add_argument("--sample-accounts", type=int, default=200)
    p.add_argument(
        "--with-view-all-fix",
        action="store_true",
        help="fold org-wide View/Modify-All users into every record's stamped set "
        "to measure the RESIDUAL gap after the reconstruction",
    )
    args = p.parse_args(argv)

    if args.org_json:
        result = json.load(open(args.org_json))["result"]
        instance_url, token = result["instanceUrl"], result["accessToken"]
    else:
        instance_url = os.environ.get("SF_INSTANCE_URL")
        token = os.environ.get("SF_ACCESS_TOKEN")
        if not (instance_url and token):
            p.error("provide --org-json OR SF_INSTANCE_URL + SF_ACCESS_TOKEN")

    oracle = SalesforceOracle(instance_url, token)
    report = audit(
        oracle,
        sample_accounts=args.sample_accounts,
        include_view_all_fix=args.with_view_all_fix,
    )
    print(report.render())
    # Exit non-zero iff a real leak exists — usable as a CI/conformance gate.
    return 1 if report.leaks else 0


if __name__ == "__main__":
    import sys as _sys

    _sys.exit(main())
