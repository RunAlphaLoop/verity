> Commissioned 2026-07-09 after founder suggestion of runalloy.com for managed ingestion.

# Alloy Automation (runalloy.com) — Evaluation for Verity Cloud's Unified-Integration Layer
*Research date: July 9, 2026. Sources: docs.runalloy.com (including llms.txt index, connector docs, OpenAPI spec), runalloy.com marketing pages (Firecrawl-scraped), Vendr, web search. Each claim labeled **[documented]** or **[inferred]**.*

## 1. Product shape in 2026

Alloy is no longer "the Shopify workflow tool" nor the 2023-era "Unified API" company. Its current lineup is three products **[documented — docs.runalloy.com index, changelog]**:

| Product | What it is | Fit for Verity ingestion |
|---|---|---|
| **Embedded (iPaaS)** | White-label, workflow-based integrations: visual workflow builder, per-end-user installations, triggers → blocks → destinations (your webhook, S3, BigQuery, Snowflake, Pub/Sub, etc.) | **The only product that actually moves data to you continuously.** Ingestion = build a workflow per integration: app trigger (webhook or poll) → transform → "Data Stream"/webhook to your endpoint ([destinations glossary](https://docs.runalloy.com/embedded/destinations.md)) |
| **Connectivity API (CAPI)** | REST gateway: `GET /connectors`, discover actions/schemas, `POST /connectors/{id}/actions/{actionId}/execute`, plus managed credentials/users ([intro](https://docs.runalloy.com/connectivity-api/introduction.md)) | Request/response only. Good for on-demand reads; **the public OpenAPI spec (docs.runalloy.com/openapi/connectivity.yaml) contains NO trigger/webhook-subscription endpoints** — only connectors, actions, credentials, users, files **[documented]** |
| **MCP (launched Oct 1, 2025)** | Hosted MCP servers exposing "1000+ tools" to LLM agents, free-tier login at ai.runalloy.com ([changelog](https://docs.runalloy.com/changelog.md)) | Action execution for agents — not an ingestion pipeline |

Important nuance: the marketing page for CAPI advertises a "**Trigger API** — receive events... set up subscriptions programmatically" ([runalloy.com/platform/connectivity-api](https://runalloy.com/platform/connectivity-api/)), but that capability **does not appear in the current public API reference or OpenAPI spec** — event delivery today lives in the Embedded workflow product. **[documented gap; interpretation inferred: Trigger API is aspirational or gated]**. The 2023 "Unified API" (normalized data models à la Merge) is no longer a listed product; CAPI is action-schema-normalized, **not data-model-normalized** — there is no "unified File object with permissions" like Merge's common models **[documented product list; "superseded" inferred]**.

**Fit verdict for ingestion:** Alloy Embedded, not CAPI. That means Verity would be authoring and maintaining **workflows per connector per object type**, not consuming a normalized sync API.

## 2. Connector coverage

- Claimed counts: "350+ prebuilt connectors" ([pricing page](https://runalloy.com/platform/pricing/)), "hundreds of supported connectors" (CAPI page). The docs site's llms.txt indexes **~136 connector doc pages** **[documented]** — the 350+/"1000+ tools" figures mix in MCP tool counts and undocumented connectors **[inferred]**.
- **Present [documented, docs.runalloy.com/connectors/]:** Salesforce CRM, HubSpot, Pipedrive, Copper (CRM); Google Drive, Dropbox, Microsoft SharePoint (file storage); Slack, Microsoft Teams, Gmail (communication); Zendesk, Freshdesk, Intercom, Jira, Linear, Monday, Asana (ticketing/PM); Notion, Google Docs/Sheets.
- **Absent [documented by omission + 404 checks on runalloy.com/integrations/]:** **Box, OneDrive, Confluence** — all three exist in Merge's File Storage category and matter for enterprise memory ingestion.
- **Commerce skew persists:** the catalog and docs are dense with Shopify, BigCommerce, Amazon Seller Central, Best Buy, 3PLs (ShipBob, Skubana), Loop Returns, Klaviyo, PushOwl, SMSBump; docs "blueprints" are dominated by e-commerce, ERP/accounting, and payments use cases; customer logos are Amazon, Anker, Brooklinen, Dr. Squatch, Recharge, Burberry **[documented]**. The 2025–26 repositioning adds ERP/fintech (NetSuite, SAP S/4HANA, Dynamics, Workday, ADP), but knowledge-work sources (docs/wiki/chat) are clearly the thinnest category **[inferred from catalog composition]**.

## 3. Freshness / event architecture

This is genuinely a strength:

- **Default is webhook proxying**: "By default, Alloy uses webhooks to proxy real-time events to your application and maintain a near-instant data sync," with geo-distributed servers ([real-time data flow page](https://runalloy.com/features/real-time-data-flow/)) **[documented]**.
- **Polling fallback is 12 minutes**: "Some apps don't offer webhooks... Alloy opts for a 12 minute polling mechanism; each object change captured creates a workflow execution" ([app-actions doc](https://docs.runalloy.com/embedded/calculating-app-actions.md)) **[documented]**. Scheduled syncs can run as often as every 1 minute ([scheduled-sync guide](https://docs.runalloy.com/embedded/knowledge-articles/scheduled-sync-of-data-3rd-party-to-your-app.md)).
- **Reconciliation**: hourly dropped-event detection with instant alerting **[documented, same page]**.
- **Yes, it pushes to your endpoint**: workflows terminate in a Data Stream block / your webhook server, or directly into S3/BigQuery/Snowflake/Pub/Sub/Postgres **[documented, destinations glossary]**.
- Per-connector reality check **[documented, connector docs]**: Salesforce — realtime via webhooks/Platform Events; Slack — realtime via Events API; SharePoint — realtime webhooks for document/list changes; **Google Drive — "Events Supported: No"** (you'd poll/schedule).

Compared to Merge's default polling-with-webhook-exceptions, Alloy's event posture is **more real-time by default** — but it's delivered through workflows you build, not a managed sync engine with cursors, backfills, and rate-limit-aware full syncs **[inferred]**.

## 4. Permissions / ACL metadata — the load-bearing question

**No Alloy product exposes a normalized ACL/sharing-metadata model. This is the disqualifier.**

- Google Drive connector objects: File, Folder, Drive, Drive List — **no Permissions object**; "Events Supported: No" ([GoogleDrive connector doc](https://docs.runalloy.com/connectors/GoogleDrive.md)) **[documented]**. A use-case blurb mentions "set initial permissions" on Shared Drives (write-side), not reading ACLs.
- SharePoint objects: Sites, Lists, List Items, Documents, Folders, Pages, Web Parts — **no permissions/role assignments** **[documented]**.
- Nothing anywhere in docs.runalloy.com resembles Merge's File Storage ACL/permissions common model **[documented by exhaustive absence in the llms.txt index]**.
- Workaround: the **Passthrough API** ([doc](https://docs.runalloy.com/embedded/passthrough-api.md)) lets you call raw provider endpoints (e.g., Drive `permissions.list`, Graph `driveItem/permissions`) using the end user's stored credential — so ACLs are *reachable*, but Verity would build and normalize permission ingestion per provider itself, which defeats the purpose of a unified layer **[documented mechanism; implication inferred]**.

## 5. Data fidelity / raw payloads

Good story here: **Passthrough API is documented and first-class** — arbitrary method/path/headers/body against any connected app's API under the end user's auth, explicitly including "access the raw data returned by the endpoints supported by Alloy" **[documented]**. Embedded workflows also pass through native payloads (Alloy normalizes action schemas, not stored data models), and there's a Custom API Call block. Raw fidelity is arguably *better* than Merge's common-model-first approach **[inferred]**.

## 6. Commercials

- **Sales-led, no self-serve, no published prices**: pricing page is "contact our team for a custom quote"; every path routes to a demo **[documented — pricing page]**. (Exception: the MCP product has a free login tier at ai.runalloy.com **[documented — changelog]**, but that's the agent-tools product, not ingestion.)
- **Metric**: "app actions" — every block execution in every workflow run counts ([calculating app actions](https://docs.runalloy.com/embedded/calculating-app-actions.md)); volumetric discounts at scale **[documented]**. Note the cost shape: a 12-minute poll finding 17 changed records fires 17 executions × blocks-per-workflow — high-churn sources multiply cost **[documented example; cost implication inferred]**.
- **Price points [third-party data, treat as directional]**: Vendr transaction data shows ~$7.5k average ACV (small sample, max ~$10k) on one guide, while Vendr's 2026 marketplace guide cites Starter-tier ACVs of **$12k–$30k**. Either way, entry is plausibly *cheaper than Merge Professional (~$30k+)* at 10–50 linked customers **[inferred]**.
- **OAuth app ownership — yes, they own them by default**: Alloy maintains default OAuth apps; end users see "Alloy Automation is requesting access" on consent screens unless you create a custom Auth Config with your own client ID/secret ("Use your own developer credentials" toggle) ([auth-config doc](https://docs.runalloy.com/connectivity-api/auth-config), [headless mode](https://docs.runalloy.com/embedded/headless-mode/), Google Drive connector doc: "you can provide your own developer keys instead of using Alloy Automation's") **[documented]**. So Verity registers zero OAuth apps to start — same as Merge.
- **Embedding terms**: the entire Embedded product is built for multi-tenant SaaS embedding — white-label modal/hosted link/headless mode, per-end-user credentials and installations, SOC 2 / GDPR / HIPAA / CCPA docs, US + EU data centers **[documented]**.

## 7. Verdict for Verity Cloud

**(c) Weaker than Merge as the primary unified-integration layer for Verity — with one narrow complementary niche.**

Scored against your four stated needs:

| Need | Alloy | Merge (prior eval) |
|---|---|---|
| **ACL/permissions metadata** | **Fails.** No normalized ACL model anywhere; Drive/SharePoint connectors don't expose permissions objects; only raw passthrough escape hatch | Strong File Storage ACLs (the load-bearing feature) |
| **Ingestion freshness** | **Wins on paper**: webhook-first push to your endpoint, 12-min poll fallback, hourly reconciliation — but you build/maintain a workflow per connector per object; Drive notably has no events | Polling-based with webhook exceptions; managed sync engine with common models |
| **Breadth (knowledge-work sources)** | Weaker: no Box, OneDrive, or Confluence; catalog still skews commerce/ERP; ~136 documented connectors | SaaS-only but purpose-built categories incl. File Storage, Ticketing, CRM |
| **Cost at 10–50 linked customers** | Likely cheaper entry ($7.5k–$30k ACV range, third-party data), but app-action metering on high-churn memory ingestion is an unpredictable multiplier; sales-led only | ~$30k+/yr Professional, predictable |

**Why it's not the primary:** Verity's differentiation is *permission-aware* memory. Merge hands you normalized ACLs across file-storage providers; with Alloy you'd re-implement permission ingestion per provider via passthrough — at that point you've rebuilt the thing you were buying. Add the missing Box/OneDrive/Confluence connectors and the workflow-per-integration maintenance model (vs. a managed sync API), and Alloy is architecturally the wrong shape for "unified ingestion into a memory plane."

**Where it could complement (b-lite):** (1) if Verity Cloud lands commerce/ERP-heavy customers (NetSuite, SAP, Shopify-ecosystem data as memory sources), Alloy's catalog and webhook-first eventing there beat Merge's; (2) Alloy's hosted MCP could later serve Verity's *action* side (agents acting on connected systems), which Merge doesn't do. Neither justifies adopting it now for ingestion.

**One caveat to monitor:** if the marketed CAPI "Trigger API" (programmatic normalized webhook subscriptions) actually ships in the public API, Alloy's freshness story would become consumable without workflow-building — worth a re-check in 6–12 months. It is not in the OpenAPI spec today.

Sources: [runalloy.com/platform/connectivity-api](https://runalloy.com/platform/connectivity-api/) · [runalloy.com/platform/pricing](https://runalloy.com/platform/pricing/) · [runalloy.com/features/real-time-data-flow](https://runalloy.com/features/real-time-data-flow/) · [docs.runalloy.com llms.txt index](https://docs.runalloy.com/llms.txt) · [Connectivity API intro](https://docs.runalloy.com/connectivity-api/introduction.md) / [OpenAPI](https://docs.runalloy.com/openapi/connectivity.yaml) · [Auth Config](https://docs.runalloy.com/connectivity-api/auth-config) · [Passthrough API](https://docs.runalloy.com/embedded/passthrough-api.md) · [Calculating App Actions (12-min polling)](https://docs.runalloy.com/embedded/calculating-app-actions.md) · [Destinations](https://docs.runalloy.com/embedded/destinations.md) · connector docs for [Google Drive](https://docs.runalloy.com/connectors/GoogleDrive.md), [SharePoint](https://docs.runalloy.com/connectors/MicrosoftSharepoint.md), [Slack](https://docs.runalloy.com/connectors/Slack.md), [Salesforce](https://docs.runalloy.com/connectors/SalesforceCRM.md) · [Changelog (MCP launch)](https://docs.runalloy.com/changelog.md) · [Vendr RunAlloy guide](https://www.vendr.com/buyer-guides/runalloy) · [Vendr marketplace/Alloy](https://www.vendr.com/marketplace/alloy)