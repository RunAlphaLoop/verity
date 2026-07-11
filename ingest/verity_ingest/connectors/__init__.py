"""Native flagship connectors (SPEC.md §5, tier 1) plus the Identity Plane's
directory-sync surface (SPEC.md §6a).

Content connectors implement the Connector ABC from
``verity_ingest.connector``. ``gdirectory`` is deliberately different: a
directory-sync connector emits principals and group-membership tuples, not
Fact/Document events. Flagships are few by design: the sources where the
product's claims live.
"""
