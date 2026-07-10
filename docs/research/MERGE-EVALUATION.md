# Merge.dev Evaluation for Verity (as of July 2026)

> Commissioned 2026-07-09 after founder direction to use Merge.dev for OAuth/connectivity where possible.
> Verdict: adopted as the **long-tail provider** (§5d of SPEC.md); flagships stay native. Sources: docs.merge.dev, help.merge.dev, merge.dev pricing/blog/changelog, plus labeled third-party/competitor sources. Facts vs. inference labeled throughout.

---

## 1. Categories & coverage

**Documented.** Merge now offers **nine unified categories** (up from seven in 2024): HRIS, ATS, CRM, Accounting, Ticketing, File Storage, Knowledge Base, Marketing Automation, and **Chat** (new, announced via the [Chat Unified API blog post](https://www.merge.dev/blog/chat-unified-api-announcement)). The [integrations page](https://www.merge.dev/integrations) advertises **"240+ integrations"** total. Approximate per-category counts from the integrations page and docs:

| Category | Rough count | Notes |
|---|---|---|
| HRIS | ~50+ | largest category |
| ATS | ~40+ | |
| Ticketing | ~25–30 | Jira, Zendesk, Linear, Asana, etc. |
| CRM | **21** ([Merge blog](https://www.merge.dev/blog/power-your-crm-integrations-with-merge)) | Salesforce ✓, HubSpot ✓ |
| Accounting | ~15+ | |
| File Storage | ~5–6 | **Google Drive, SharePoint, OneDrive, Box, Dropbox** ([ACL help article](https://help.merge.dev/articles/10439047-file-storage-access-control-list-acls)) |
| Knowledge Base | 1–2 | **Confluence live (open beta)**; Notion and Salesforce Knowledge "on the horizon" ([KB announcement](https://www.merge.dev/blog/knowledge-base-unified-api-announcement)). A [Notion integration page](https://www.merge.dev/integrations/notion) exists — current GA status unverified |
| Chat | 1 | **Microsoft Teams only**; Slack "on the roadmap" ([Chat announcement](https://www.merge.dev/blog/chat-unified-api-announcement), [Chat docs](https://docs.merge.dev/merge-unified/chat/integrations/overview)) |

**Slack:** Not covered in the unified (data-sync) API. Slack exists only in **Merge Agent Handler**, their separate MCP/tool-calling product (Slack connector + "Slackbot" connector launched July 2026 per [changelog](https://www.merge.dev/changelog)). That is action execution, not data ingestion — it does not sync Slack messages into a store. For Verity's purposes, **Slack data sync is a gap**.

## 2. Freshness (the critical question)

**Sync model — documented.** Merge is fundamentally a **polling ETL** platform: it periodically fetches from source APIs into Merge's store, then notifies you via "Merge webhooks." Writes are real-time; reads follow the sync cadence ([help center](https://help.merge.dev/en/articles/5388387-merge-sync-frequencies)).

**Plan-dependent frequencies — documented, with gaps:**
- **Launch (free/self-serve):** syncs run **daily** by default; the pricing page lists "quarterly, monthly, daily, and our highest setting" as choices ([pricing](https://www.merge.dev/pricing), [help center](https://help.merge.dev/en/articles/5388387-merge-sync-frequencies)).
- **Professional/Enterprise:** "custom sync frequencies," cadence varies per integration and per common model. Docs describe the top option only as "the highest frequency supported by Merge" vs. "every 24 hours" ([docs](https://docs.merge.dev/merge-unified/hris/merge-api-basics/sync-frequency.md)). **Could not verify a published number (e.g., "hourly") for the "highest" tier** — the per-integration sync-frequency tables are rendered client-side and were not extractable. Treat "highest" as roughly minutes-to-hours depending on model/integration (inference). One concrete datapoint: File Storage **permission polling** runs every **5 minutes** for Google Drive/Dropbox/SharePoint/OneDrive and **1 hour** for Box ([ACL article](https://help.merge.dev/articles/10439047-file-storage-access-control-list-acls)).
- Chat (Teams) runs on a **10-minute sync cadence**, webhooks "in the next major release" ([Chat announcement](https://www.merge.dev/blog/chat-unified-api-announcement)).

**Source-side (third-party) webhooks — documented:** Merge supports receiving webhooks from sources ("double-webhook system"): source → Merge Receiver URL → Merge processes **immediately** → fires your Merge webhooks, "regardless of the rate at which Merge syncs" ([third-party webhooks doc](https://docs.merge.dev/merge-unified/reading-data/webhooks/third-party-webhooks)). Key constraints:
- **Professional/Enterprise plans only** (explicitly documented). Not available on Launch.
- Automatic webhook creation exists for supported integrations but is off by default; coverage is integration-specific. Confirmed webhook-supported integrations from help center guides: **Google Drive, Box** (file storage ACLs — "typically deliver updates within seconds"), Linear, QuickBooks Online, Xero, Front, Intercom, JazzHR, Ashby; HubSpot is referenced as having "Automatic Webhooks" on its marketing page. **Dropbox, SharePoint, OneDrive explicitly have no webhook support in Merge** — 5-minute ACL polling is the ceiling there ([ACL article](https://help.merge.dev/articles/10439047-file-storage-access-control-list-acls)). Salesforce third-party-webhook support: **not verified** (no help-center setup guide found; Salesforce lacks generic webhooks natively, so likely absent — inference).

**Merge webhook latency:** For webhook-backed paths, Merge claims "real-time" / "within seconds" (documented for Google Drive/Box ACLs, with a caveat about "occasional network or load-related delays"). For polled models, changed-data webhooks fire only when a scheduled sync detects the change — so **effective latency = sync cadence** (minutes at absolute best on top plans, daily on Launch). **There is a seconds-level path, but only for the subset of integrations with third-party webhook support, only on Professional+ plans.**

**2025–2026 changes:** Chat category launch (Teams), Knowledge Base launch (Confluence), Merge Agent Handler (MCP) buildout, sync-scheduling and webhook-reliability improvements, correlation IDs on `sync_complete` webhooks (May 2026) ([changelog](https://www.merge.dev/changelog)). **No announcement of a general "instant sync" tier or platform-wide real-time architecture change** — the polling+webhook hybrid remains.

## 3. ACL / permissions data

**File Storage — genuinely strong, documented:**
- `File.permissions` / `Folder.permissions` sub-models with **users, groups, roles (READ/WRITE/OWNER)** and **types (USER, GROUP, COMPANY, DOMAIN, ANYONE)** across all five file-storage integrations ([ACL article](https://help.merge.dev/articles/10439047-file-storage-access-control-list-acls), [Permissions docs](https://help.merge.dev/articles/10593571-understanding-access-control-lists-acls)).
- **Group memberships are exposed**: the [Group object](https://docs.merge.dev/filestorage/groups) has `group.users` and `group.child_groups` (nested groups require recursive expansion on your side).
- Files come with **folder-inherited ACLs already resolved** ("files already include the full ACL based on their folder context") per their [ACL-aware RAG guide](https://help.merge.dev/articles/4066107080), which explicitly documents the permission-filtered-retrieval pattern Verity needs, including granular `file.updated`/`group.updated` webhooks.
- Caveats (from competitor Paragon's [critique](https://www.useparagon.com/blog/paragon-vs-merge-different-approaches-to-file-storage-permissions) — marketing, but plausible): flattened ACL list may miss edge cases (Drive link-sharing without explicit roles, SharePoint deny/override semantics); no batch permission-check endpoint; you build enforcement yourself. Treat as unverified but design-relevant.
- Chat (Teams) and Knowledge Base categories also ship **Member/ACL models** with admin-flow vs user-flow access ([Chat announcement](https://www.merge.dev/blog/chat-unified-api-announcement)).

**CRM record-level sharing — not exposed.** Merge's CRM common models (Contact, Account, Lead, Opportunity, Engagement, User, custom objects) contain **no sharing-rule, territory, role-hierarchy, or record-visibility models**; nothing in docs or help center covers Salesforce sharing rules. (Verified absence in documentation; labeled as such — no positive statement from Merge either way.) You could pull raw sharing data (e.g., Salesforce `ShareRule`, group membership, territory objects) via **authenticated passthrough**, but then you're writing Salesforce-specific ACL code anyway — which defeats the unified-API value for CRM permissions.

**Passthrough:** yes — [Authenticated Passthrough Requests](https://docs.merge.dev/supplemental-data/passthrough/overview/) let you hit any endpoint of the underlying API using Merge-held tokens, on all plans per the pricing page.

## 4. Data model fidelity

Documented, four mechanisms ([supplemental data guide](https://help.merge.dev/en/articles/5779316-when-should-i-use-remote-data-a-passthrough-request-or-a-custom-field)):
- **Remote Data**: returns the **original raw third-party payload** alongside the normalized model for endpoints Merge already calls — normalization does *not* irretrievably lose the raw payload, you just have to enable Remote Data. Available on all plans per the pricing page.
- **Field Mapping**: map source custom fields onto target fields of Common Models — **Professional/Enterprise only**, and requires Remote Data enabled.
- **Remote Field Classes**: for highly variable custom fields incl. write-back.
- **Passthrough**: for endpoints Merge doesn't cover at all.

Net: fidelity is adequate; the raw data is reachable. Plan-gating of Field Mapping matters commercially (below).

## 5. Commercial fit for open source

Documented from [pricing](https://www.merge.dev/pricing) and [Launch FAQ](https://help.merge.dev/en/articles/6641605-launch-plan-faqs-self-serve-with-merge):
- **Model:** per **production Linked Account** (one end-customer's one connected integration). Launch: **free for first 3 linked accounts**, then **$650/mo up to 10**, **+$65/account** beyond. Unlimited API/data usage. Professional/Enterprise: contract; a competitor guide ([Knit, unverified](https://www.getknit.dev/blog/understanding-merge-dev-pricing-finding-the-right-unified-api-for-your-integration-needs)) estimates **$30k–55k/yr (Professional)** and **$100k+ (Enterprise)**.
- **20 linked accounts:** on Launch ≈ **$650 + 10×$65 = $1,300/mo (~$15.6k/yr)** — but Launch means **daily sync and no third-party webhooks**, i.e., fails Verity's freshness bar outright. Real-time-capable Merge at 20 accounts realistically means Professional: **~$30k+/yr** (inference from unverified competitor figures; Merge doesn't publish contract pricing).
- **BYO-key for self-hosters:** technically feasible — Launch is self-serve, and each self-hosting Verity user could create their own Merge org and get 3 linked accounts free (inference; nothing prohibits it in docs found). But they'd be stuck on Launch's daily sync unless they individually sign contracts. **No explicit OSS-embedding restriction found, but also no OSS/redistribution terms — unverified; Merge's ToS would need legal review.** There is no self-hosted Merge; it's SaaS-only, so all customer data (and ACLs) transits Merge's cloud — a real objection for an open-source, trust-sensitive memory plane.

## 6. Alternatives snapshot

**Nango** — Open source under **Elastic License 2.0**, self-hostable; **free self-hosted edition covers OAuth + API proxy only**; syncs, functions, webhooks, and MCP require Nango Cloud or Enterprise self-host ([Nango self-hosting docs](https://nango.dev/docs/guides/platform/self-hosting), [GitHub](https://github.com/nangohq/nango)). Supports receiving external webhooks for real-time sync triggers (billed per webhook on Cloud). No unified ACL/permissions model — you write the sync scripts, so you can fetch permission endpoints yourself. **Best OAuth-layer fit for an OSS project**: self-hosters get credential management free and Verity keeps its own sync engine.

**Paragon** — Closed-source embedded iPaaS (ActionKit for tool calling, Workflows/Managed Sync for ingestion), ~130+ connectors, per-connected-user contract pricing. Notably, it is **explicitly attacking the permission-aware-RAG use case** with an FGA/ReBAC permissions graph and `/batch-check`/`/expand` endpoints ([Paragon blog](https://www.useparagon.com/blog/paragon-vs-merge-different-approaches-to-file-storage-permissions) — marketing claims, unverified). Strongest ACL story of the group on paper, but proprietary, hosted, and enterprise-priced — poor fit as an OSS dependency.

**Composio** — Agent tool-calling platform: 500+ integrations, managed OAuth (AgentAuth), event-driven **triggers** (e.g., new Slack message, HubSpot deal stage) with a free tier (20K calls) and $29–229/mo self-serve tiers ([Composio](https://composio.dev/content/ai-agent-integration-platforms)). Oriented to actions/triggers, **not bulk data sync and no ACL/permission models** — could serve as a cheap OAuth+trigger layer, not as an ingestion backbone.

## 7. Verdict for Verity

**(a) Sole connector layer — No.**
- Freshness: seconds-level exists only where third-party webhooks are supported (Google Drive, Box, a scattering of others) *and* only on Professional+ contracts. **SharePoint/OneDrive/Dropbox cap at ~5-minute ACL polling with no webhook path; Salesforce webhook support unverified/likely absent; Chat is 10-minute polling; Launch plan is daily.** A flagship-freshness SLA of "seconds" cannot be met across flagships through Merge.
- ACLs: excellent for File Storage (permissions + group membership + inherited ACLs is exactly Verity's ingestion shape), decent for Chat/KB, but **CRM record-level visibility (Salesforce sharing rules, territories) is simply not modeled** — you'd fall back to passthrough and hand-rolled Salesforce ACL code, i.e., a native connector wearing a Merge hat.
- Slack data sync doesn't exist. Bi-temporality: Merge gives you `modified_at`/changed-data webhooks, not history — Verity's bi-temporal store must be built on top regardless.

**(b) Long-tail + OAuth layer, native push connectors for flagships — Yes, this is the defensible Merge role, but only for a hosted/commercial edition of Verity.** Merge is genuinely good at what Verity should not build: 240+ connectors across HRIS/ATS/Accounting/Ticketing where minutes-to-hours freshness is acceptable, normalized models, Remote Data for raw payloads, and passthrough as an escape hatch. Keep native connectors for HubSpot (webhooks) and Google Drive (Drive changes/push notifications + Permissions API), and Debezium/CDC where you own the database. Two hard caveats: (1) real-time-ish Merge (third-party webhooks, field mappings) requires a Professional contract (~$30k+/yr, unverified estimate) held by *someone* — which works for Verity Cloud, not for self-hosters; (2) even File Storage ACLs via Merge are seconds-fresh only on Drive/Box.

**(c) For the pure open-source, self-hosted distribution — effectively unsuitable.** Merge is SaaS-only (no self-host), free tier is 3 linked accounts at daily sync with no source webhooks, and every self-hoster would need their own Merge org and contract to hit Verity's freshness requirements. An OSS memory plane whose freshness and ACL guarantees depend on each user buying a third-party enterprise contract is not a credible default.

**Recommendation (adopted in SPEC.md §5d):** Architect Verity with a pluggable connector interface. Default OSS path: native connectors for flagships (HubSpot webhooks, Google Drive push + Permissions API, SharePoint via Microsoft Graph delta/change notifications — note Merge itself can't do SharePoint webhooks, so native beats Merge there) with Nango (ELv2, self-hostable auth) as the optional OAuth layer. Offer Merge as an optional long-tail provider for Verity Cloud/enterprise customers, leaning on its File Storage ACL models and the documented ACL-aware-RAG pattern where its freshness (webhooks on Drive/Box, 5-min ACL polling elsewhere) meets the "minutes for long tail" bar.

**Key unverified items:** exact "highest" sync cadence numbers per integration (JS-rendered tables inaccessible); Salesforce/SharePoint third-party webhook absence (strong inference from docs silence); Professional/Enterprise dollar figures (competitor estimates); Merge ToS on OSS embedding; current GA status of Notion in Knowledge Base.
