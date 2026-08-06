# Connectors

Verity connectors mirror a source system's content **and its ACLs** into the memory store, so
recall inherits that system's permissions instead of you hand-tagging them. This page is the
setup recipe for each one.

Every connector is **bring-your-own-token**: you create an app or key in your own account, and
the credential never leaves your infrastructure. Nothing here calls a Verity-hosted service.

## How connectors run

Each connector is a Python module you run against a running Verity server:

```sh
python -m verity_ingest.connectors.<name> --backfill   # one full historical crawl
python -m verity_ingest.connectors.<name> --once        # one incremental cycle (delta since last run)
python -m verity_ingest.connectors.<name>               # poll loop (--once every --interval seconds, default 300)
```

Add `--dry-run` to print what would be sent without writing anything. Run `--backfill` first (it
seeds the cursor and, for the newer connectors, stamps a reconcile SLA), then `--once` or the poll
loop for steady state.

### Things that trip people up

- **Always set `VERITY_URL` explicitly.** The built-in defaults are inconsistent across connectors
  (some default to `:7717`, the real dev-server port; others to `:8080`). Don't rely on them.
- **`--visibility` is not universal.** HubSpot, Salesforce, Notion, and Intercom **require** a
  `--visibility` token list (these sources don't expose a per-record audience, so you declare the
  floor). Google Drive, Gmail, SharePoint, Slack, Zoom, and both directory syncs **derive**
  visibility from the source and take no `--visibility` flag.
- **Two connectors use `VERITY_ADMIN_TOKEN`, not `VERITY_API_KEY`.** HubSpot, Salesforce, Notion,
  and Intercom share one sink that reads `VERITY_ADMIN_TOKEN` and strictly requires
  `VERITY_TENANT_ID`. Everything else reads `VERITY_API_KEY`. (Both are just the server's bearer;
  the split is historical.)
- **Secrets go in 0600 files where offered.** Connectors that take a `--credential-file` or a
  `*_SECRET_FILE` env var require the file to be owner-only (mode 0600) and read the secret from the
  file body. The secret is never passed on the command line or logged.
- **Group inheritance needs the matching directory sync running.** A Drive doc shared with a Google
  Group, or a SharePoint item shared with an Entra group, only resolves to that group's members if
  [Google Workspace](#google-workspace-directory-sync) or [Microsoft Entra](#microsoft-entra-directory-sync)
  directory sync is also running. See the [directory syncs](#directory-syncs) section.

### Maturity — read this before trusting a connector

Fidelity varies by what each source's API actually exposes. This mirrors
[HONESTY.md](../HONESTY.md); when the two disagree, HONESTY.md wins.

| Connector | ACL fidelity | Proven |
|---|---|---|
| Google Drive / Gmail | Real per-item ACLs, incl. nested Google Group inheritance | Live-validated once + fixtures |
| SharePoint / OneDrive | Per-item Graph permissions via Entra; site-native groups quarantine | Live-proven end to end (scratch tenant), incl. deletion-to-dark |
| Microsoft Entra / Google Workspace directory | Nested-group membership | Live-proven end to end |
| Salesforce | OWD / role / share / View-All, checked against Salesforce's own oracle | Live-validated once (trial org) |
| Slack | Channel membership as the audience | Fixture-tested + live-validated once |
| HubSpot | CRM object/owner visibility (approximated, under-grants) | Live-validated once + fixtures |
| Intercom | Assignee + operator teammate floor (fail-closed on unassigned) | Live-validated once + fixtures |
| Notion | Admin-assigned floor (no per-page API; over-hides, never leaks) | Fixture-tested |
| Zoom | Reconstructed from a 3-value sharing enum + operator token | Fixture-verified; not yet live-validated (needs a Pro+ seat) |

---

# Content connectors

## Google Drive

Mirrors Drive files with real per-item ACL inheritance, including transitive nested Google Group
membership. The strongest-fidelity connector.

**Set up:** create a **service account in your own GCP project** and grant it **domain-wide
delegation**. Grant the scope `https://www.googleapis.com/auth/drive.readonly`. Download the
service-account JSON key.

**Environment:**

| Var | Required | Purpose |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | yes | Path to the service-account JSON key |
| `GDRIVE_DELEGATED_SUBJECT` (or `--subject`) | for DWD | Workspace user to impersonate |
| `VERITY_URL`, `VERITY_API_KEY`, `VERITY_TENANT_ID` | url + tenant | Verity server + bearer + tenant |
| `GDRIVE_ANYONE_MAPS_TO` (or `--anyone-maps-to`) | no | Where "anyone with the link" maps; unset ⇒ those items quarantine |

```sh
export GOOGLE_APPLICATION_CREDENTIALS=/etc/verity/gdrive-sa-key.json
export VERITY_URL=http://localhost:7717 VERITY_API_KEY=<bearer> VERITY_TENANT_ID=my-workspace
export GDRIVE_DELEGATED_SUBJECT=admin@my-workspace.com
python -m verity_ingest.connectors.gdrive --backfill --subject admin@my-workspace.com --tenant-id my-workspace
python -m verity_ingest.connectors.gdrive --once     --subject admin@my-workspace.com --tenant-id my-workspace
```

Run [Google Workspace directory sync](#google-workspace-directory-sync) alongside it so
group-shared docs resolve to their members.

## Gmail

Same service account and domain-wide delegation as Drive. The **delegated subject is mandatory**
(Gmail is per-mailbox; the subject is the mailbox read). Scope
`https://www.googleapis.com/auth/gmail.readonly`.

**Environment:** `GOOGLE_APPLICATION_CREDENTIALS`, `GMAIL_DELEGATED_SUBJECT` (or `--subject`, required),
`VERITY_URL`/`VERITY_API_KEY`/`VERITY_TENANT_ID`. Optional: `GMAIL_QUERY`, `GMAIL_NEWER_THAN` (default `30d`).

```sh
export GOOGLE_APPLICATION_CREDENTIALS=/etc/verity/gsuite-sa-key.json
export VERITY_URL=http://localhost:7717 VERITY_API_KEY=<bearer> VERITY_TENANT_ID=my-workspace
export GMAIL_DELEGATED_SUBJECT=matt@my-workspace.com
python -m verity_ingest.connectors.gmail --once --subject matt@my-workspace.com --tenant-id my-workspace
```

## SharePoint / OneDrive

Mirrors per-item SharePoint permissions and resolves them through the Entra identity plane. Proven
end to end on a scratch tenant, including deletion-to-dark (delete a doc at the source, it stops
resolving on the next cycle).

**Set up:** an **Entra app registration** (the same BYOT app as Entra directory sync) with the
`Sites.Selected` posture, granted access to the specific sites you name. Auth reuses the `ENTRA_*`
credentials.

**Environment:**

| Var | Required | Purpose |
|---|---|---|
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` | yes | Entra app |
| `ENTRA_CLIENT_SECRET_FILE` **or** `ENTRA_CLIENT_CERT_FILE` | one | 0600 file holding the client secret (body) or cert PEM |
| `SHAREPOINT_SITE_IDS` (or `--site-ids`) | yes | Comma-separated Graph site ids to crawl |
| `SHAREPOINT_TENANT_GUID` | yes | Tenant GUID; unset ⇒ the "everyone-except-external" claim poisons |
| `SHAREPOINT_CANARIES_FILE` | recommended | `{driveId:{item_id,expected_user_oid}}` completeness canary; a drive without one quarantines wholesale |
| `VERITY_URL`, `VERITY_API_KEY`, `VERITY_TENANT_ID` | url + tenant | |

```sh
export ENTRA_TENANT_ID=contoso.onmicrosoft.com ENTRA_CLIENT_ID=<app-guid>
export ENTRA_CLIENT_SECRET_FILE=$HOME/.verity/entra_client_secret   # chmod 600, secret = file body
export SHAREPOINT_SITE_IDS="contoso.sharepoint.com,<site-guid>"
export SHAREPOINT_TENANT_GUID=<tenant-guid> SHAREPOINT_CANARIES_FILE=$HOME/.verity/sp_canaries.json
export VERITY_URL=http://localhost:7717 VERITY_API_KEY=<key> VERITY_TENANT_ID=my-workspace
python -m verity_ingest.connectors.sharepoint --backfill   # first: stamps the reconcile SLA
python -m verity_ingest.connectors.sharepoint --once        # then: incremental
```

**Honest limits:** SharePoint-native *site groups* currently quarantine rather than resolve (the
SP-REST lane isn't built); a drive without a configured completeness canary quarantines wholesale
(Graph returns partial ACLs to under-privileged callers with a 200, so we fail closed); change
subscriptions aren't wired, so it's poll-only. Requires [Entra directory sync](#microsoft-entra-directory-sync)
for group resolution.

## Slack

Channel membership is the audience: a message's visibility is `group:slack-channel-<id>`, and joins
and leaves enforce retroactively. This is the one connector with a guided setup wizard.

**Set up:** run the wizard, which walks you through creating a Slack app from a manifest and stores
the tokens 0600 in `~/.verity/config.toml` under `[connectors.slack]`:

```sh
verity-cli connect slack
```

The app needs bot scopes `channels:history`, `channels:join`, `channels:read`, `groups:history`,
`groups:read`, `users:read`, `users:read.email`. Invite the bot to the channels you want mirrored
(it can self-join public channels; private channels need an invite).

**Environment:** the wizard writes the token to config, so you only need the Verity vars. To use an
env token instead, set `SLACK_BOT_TOKEN` (`xoxb-…`), which overrides the config file.

```sh
export VERITY_URL=http://localhost:7717 VERITY_API_KEY=<key> VERITY_TENANT_ID=my-workspace
python -m verity_ingest.connectors.slack --backfill
python -m verity_ingest.connectors.slack --once
```

There is **no `--visibility` flag** — visibility comes from channel membership. (If you saw a
`--visibility 1` example, it's a stale hint; ignore it.)

## Zoom

Mirrors cloud-recording transcripts (VTT). Zoom exposes no per-recording audience, so visibility is
**reconstructed** from the recording's share setting plus an operator-declared token, and stated
honestly as such. Needs a Pro+ plan with cloud recording and audio transcripts enabled.

**Set up:** create a **Server-to-Server OAuth app** in your Zoom account. Note the Account ID,
Client ID, and Client Secret. The app needs cloud-recording read, past-participant read, and
`user:read:user:admin`.

**Environment:**

| Var | Required | Purpose |
|---|---|---|
| `ZOOM_ACCOUNT_ID`, `ZOOM_CLIENT_ID` | yes | S2S OAuth app |
| `ZOOM_CLIENT_SECRET_FILE` | yes | 0600 file holding the client secret (body) |
| `ZOOM_USER_IDS` (or `--users`) | yes | Comma-separated host ids/emails whose recordings to mirror |
| `ZOOM_INTERNAL_MAPS_TO` | for `internally`-shared | Principal that "share internally" maps to; unset ⇒ those recordings quarantine |
| `ZOOM_INTERNAL_DOMAINS` | no | Comma-separated internal domains |
| `VERITY_URL`, `VERITY_API_KEY`, `VERITY_TENANT_ID` | url + tenant | |

```sh
export ZOOM_ACCOUNT_ID=<acct> ZOOM_CLIENT_ID=<client-id>
export ZOOM_CLIENT_SECRET_FILE=$HOME/.verity/zoom_client_secret   # chmod 600, secret = file body
export ZOOM_USER_IDS="host1@acme.com,host2@acme.com"
export ZOOM_INTERNAL_MAPS_TO=group:everyone@acme.com ZOOM_INTERNAL_DOMAINS=acme.com
export VERITY_URL=http://localhost:7717 VERITY_API_KEY=<key> VERITY_TENANT_ID=my-workspace
python -m verity_ingest.connectors.zoom --backfill
python -m verity_ingest.connectors.zoom --once
```

**Honest limits:** `none` → host only, `internally` → `ZOOM_INTERNAL_MAPS_TO` + host (an
admin-assigned policy, not a mirrored source ACL), `publicly` → quarantined, anything unrecognized
→ quarantined. This connector is fixture-verified but **not yet validated against a live Zoom
account**.

## HubSpot

CRM object visibility, driven by owners and teams. Deliberately under-grants (per-user "Everything"
permissions and manual per-record shares aren't visible from the record side), so it over-hides
rather than leaks.

**Set up:** create a **Service key** (Development → Keys) or a legacy private-app token. It needs
`crm.objects.owners.read` plus CRM read scopes for contacts/companies/deals. If the owners scope is
missing, the run drops to the admin `--visibility` floor and the error names the scope.

**Environment:** `HUBSPOT_SERVICE_KEY` (or legacy `HUBSPOT_PRIVATE_APP_TOKEN`, or a 0600
`--credential-file`); **`VERITY_ADMIN_TOKEN`** (not `VERITY_API_KEY`); `VERITY_URL`;
**`VERITY_TENANT_ID` is strictly required** (a tenant UUID).

```sh
export HUBSPOT_SERVICE_KEY=<service-key>
export VERITY_URL=http://127.0.0.1:7717 VERITY_ADMIN_TOKEN=<admin-bearer> VERITY_TENANT_ID=<tenant-uuid>
python -m verity_ingest.connectors.hubspot --once --visibility 1,2
```

`--visibility` is a required comma-separated token list. Use `--backfill` for a full historical
crawl.

## Salesforce

Reconstructs OWD, role hierarchy, object shares, and View-All, then reconciles the result against
Salesforce's own `UserRecordAccess` API (0 disagreements on a trial org). Sharing-rule and territory
reconstruction are deferred until a real org can measure them.

**Set up:** a **Connected App in your own org** using the OAuth client-credentials flow with a
run-as integration user. The integration user needs read on `User`/`Group`/`GroupMember` (a 403
there drops the run to the admin floor). User identity resolves through **`FederationIdentifier`**
(the SSO subject), never `User.Email`, so this connector depends on a directory sync that publishes
SSO aliases.

**Environment:** `SF_MY_DOMAIN`, `SF_CLIENT_ID`, `SF_CLIENT_SECRET` (all required);
`VERITY_URL`/`VERITY_ADMIN_TOKEN`/`VERITY_TENANT_ID` (via the shared sink).

```sh
export SF_MY_DOMAIN=acme SF_CLIENT_ID=<consumer-key> SF_CLIENT_SECRET=<consumer-secret>
export VERITY_URL=http://localhost:7717 VERITY_ADMIN_TOKEN=<admin-bearer> VERITY_TENANT_ID=<tenant-uuid>
python -m verity_ingest.connectors.salesforce --once --visibility 1,2
```

## Notion

The public Notion API exposes no per-page sharing, so Notion content rides an **admin-assigned
visibility floor**: fail-closed (it over-hides, never leaks), but not true per-page ACL inheritance.

**Set up:** create an **internal integration** in your workspace and **share the target pages with
it** — `/v1/search` only returns content shared with the integration, which is the access floor.

**Environment:** `NOTION_TOKEN` (or a 0600 `--credential-file`);
`VERITY_URL`/`VERITY_ADMIN_TOKEN`/`VERITY_TENANT_ID`.

```sh
export NOTION_TOKEN=secret_<token>
export VERITY_URL=http://localhost:7717 VERITY_ADMIN_TOKEN=<admin-bearer> VERITY_TENANT_ID=<tenant-uuid>
python -m verity_ingest.connectors.notion --once --visibility 1,2 --with-content
```

`--with-content` also ingests page bodies (they inherit the same floor). Omit it to ingest metadata only.

## Intercom

Conversations ride an operator-declared teammate-audience floor plus the resolved assignee as a
provable superset; fail-closed on unassigned conversations.

**Set up:** create an **access token** (Settings → Developers, or a PAT). It needs the **Read
admins** and **Read teams** scopes (a 403 drops the run to the admin floor). The assignee resolves
to `user:<admin email>`, the team to `group:intercom-team-<id>`.

**Environment:** `INTERCOM_ACCESS_TOKEN` (or a 0600 `--credential-file`);
`VERITY_URL`/`VERITY_ADMIN_TOKEN`/`VERITY_TENANT_ID`. Optional `--public-maps-to` for published
help-center articles.

```sh
export INTERCOM_ACCESS_TOKEN=<token>
export VERITY_URL=http://localhost:7717 VERITY_ADMIN_TOKEN=<admin-bearer> VERITY_TENANT_ID=<tenant-uuid>
python -m verity_ingest.connectors.intercom --once --visibility 1,2 --public-maps-to org:everyone
```

---

# Directory syncs

Directory syncs don't ingest content. They mirror **group membership** into the permission graph so
that a document shared with a group resolves to that group's (nested) members. Run the one that
matches your identity provider alongside the content connectors that reference its groups.

## Google Workspace directory sync

Underpins Google Drive and Gmail group inheritance. Proven end to end against a real workspace,
including a hard-deleted-user proof.

**Set up:** the same **service account + domain-wide delegation** as Drive/Gmail, plus an
impersonable admin subject. Scopes: `admin.directory.user.readonly`, `admin.directory.group.readonly`.

```sh
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
export GADMIN_DELEGATED_SUBJECT=admin@yourdomain.com GADMIN_DOMAIN=yourdomain.com
export VERITY_URL=http://localhost:7717 VERITY_TENANT_ID=<tenant-uuid> VERITY_API_KEY=<key>
python -m verity_ingest.connectors.gdirectory --once
```

`--interval` (default 300s) is the membership-freshness bound: it's how stale a group membership can
be before the next sync catches a change. `--domain` maps whole-domain shares to `domain:<domain>`;
unset, domain-wide shares confer nothing.

## Microsoft Entra directory sync

Underpins SharePoint group inheritance, and is the identity plane SharePoint resolves grants
through. Proven end to end against a real scratch tenant, including a hard-deleted-user group-edge
purge.

**Set up:** an **Entra app registration** with the app-only (client-credentials) grant and **admin
consent**, holding Graph application permissions **`User.Read.All`, `Group.Read.All`,
`GroupMember.Read.All`**. Provide the secret as a 0600 file (or a cert PEM).

```sh
export ENTRA_TENANT_ID=<tenant-guid-or-domain> ENTRA_CLIENT_ID=<app-client-id>
export ENTRA_CLIENT_SECRET_FILE=/path/to/entra-secret.txt   # chmod 600; OR ENTRA_CLIENT_CERT_FILE=/path/cert.pem
export VERITY_URL=http://localhost:7717 VERITY_TENANT_ID=<tenant-uuid> VERITY_API_KEY=<key>
python -m verity_ingest.connectors.entra_directory --once
```

**Honest limit:** cross-IdP SSO-alias welding is inert on cloud-only tenants (`onPremisesImmutableId`
is null, so zero aliases are written — surfaced as a warning, never guessed) and hasn't been
confirmed against a federated tenant. `--alias-field` sets which attribute carries the SSO NameID
your other systems (e.g. Salesforce) key on.

---

## Validating a connector worked

After a run, mint a scope for a user and confirm recall returns what they should see (and nothing
they shouldn't). The fastest check is the CLI or the web console described in the
[README quickstart](../README.md#quickstart-dev). For the permission boundary specifically, the
two-agent demo (`python3 demo/two_agent_trust.py`) shows a group-shared doc visible to a member and
dark to a non-member.

If a connector quarantined more than you expected, that's the fail-closed posture working: check the
connector's stderr for the specific reason (a missing scope, an unresolvable principal, a missing
canary) rather than assuming a bug.
