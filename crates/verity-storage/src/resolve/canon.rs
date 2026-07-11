//! S0 — canonicalize refs & keys (deterministic).
//! `docs/design/cross-source-entity-resolution.md` §4.2 (S0) and §4.4.
//!
//! Pure functions only. No DB, no I/O, no randomness, no LLM. Every function is
//! **fail-closed**: a value that cannot be normalized into a *trustworthy* key
//! returns `None` (or is rejected by the denylist) rather than producing a weak
//! key that could form a false merge edge (§3.2: a false merge is a scope leak).
//!
//! ## What "canonical" means here
//! - **email** → lowercase, strip the `+tag` sub-address, trim. Free-mail
//!   domains and role-based locals (`info@`, `sales@`, …) are **denylisted**
//!   and return `None`.
//! - **domain** → registrable domain (eTLD+1) via a small, *documented*
//!   public-suffix heuristic (NOT the full PSL — see [`registrable_domain`]),
//!   lowercased, `www.` stripped. Free-mail / placeholder domains denylisted.
//! - **Salesforce `Account.Website`** → the domain parsed out of the URL (SF
//!   exposes no clean domain field, only a `Website` URL string).
//! - **phone** → an E.164-ish digit string (`+<digits>`), best-effort.
//! - **name** → NFKC-ish + case-fold + strip legal suffixes (Inc/LLC/Ltd/Corp…)
//!   + collapse whitespace. Used only for *blocking* / display, never as a
//!     Tier-1 auto-merge key on its own.
//!
//! ## Namespace stamp (§4.4, the actor-email population fence)
//! Every email/domain key carries a [`KeyNamespace`]. An **actor / internal
//! directory** email (e.g. a Linear `assignee.email`) is stamped
//! `internal_directory`; a **CRM contact** email is stamped `customer_contact`.
//! The fold may only form an edge *within* a namespace, so an internal-employee
//! email can never weld to a customer-contact entity.

use std::borrow::Cow;

/// The `key_namespace` an email/domain key belongs to (§4.4). An edge may only
/// form *within* one of these — the primary defense against joining an internal
/// employee to a customer contact by a coincidentally-shared identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyNamespace {
    /// A CRM contact / account-side identifier (Salesforce/HubSpot contact
    /// email, account domain). The "customer" population.
    CustomerContact,
    /// An actor / internal-employee identifier (a Linear `assignee.email`, an
    /// ACL principal that is one of *our own* users). The "internal" population.
    InternalDirectory,
}

impl KeyNamespace {
    /// The stable string stamped into `entity_evidence.key_namespace` and matched
    /// by `entity_resolution_config`. Must round-trip with [`Self::from_stored`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CustomerContact => "customer_contact",
            Self::InternalDirectory => "internal_directory",
        }
    }

    /// Parse a stored `key_namespace`. Unknown strings fail closed to
    /// `InternalDirectory` — the *narrower* population — so a corrupt/unknown
    /// stamp can never widen an edge into the customer namespace.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "customer_contact" => Self::CustomerContact,
            _ => Self::InternalDirectory,
        }
    }
}

/// The kind of key a canonicalized value is, for `entity_resolution_config`
/// lookup (`key_kind`) and for choosing the producer method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Email,
    Domain,
    Phone,
    ExternalId,
}

impl KeyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Domain => "domain",
            Self::Phone => "phone",
            Self::ExternalId => "external_id",
        }
    }
}

/// A canonicalized, namespace-stamped key ready to become `entity_evidence`'s
/// `key_value` + `key_namespace`. Producing one of these means S0 *accepted* the
/// value: it is normalized and passed the built-in denylist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonKey {
    pub kind: KeyKind,
    /// The normalized value, e.g. `jane@acme.dev`, `acme.com`.
    pub value: String,
    pub namespace: KeyNamespace,
}

// ---------------------------------------------------------------------------
// Built-in denylist (§4.2: "apply the denylist immediately").
// ---------------------------------------------------------------------------
//
// These values must NEVER become a merge key regardless of tenant config — they
// are ambient false-friends, not identity. The tenant's `denylist_values` from
// `entity_resolution_config` is applied *in addition* to this floor, never
// instead of it. Kept small, documented, and case-normalized (lowercase).

/// Free-mail / consumer-mail domains: a shared `gmail.com` is not shared
/// identity. Non-exhaustive but covers the high-frequency offenders; tenants
/// extend via config.
const FREEMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
    "pm.me",
];

/// Placeholder / reserved domains (RFC 2606 + common test values): never
/// identity.
const PLACEHOLDER_DOMAINS: &[&str] = &[
    "example.com",
    "example.org",
    "example.net",
    "example.edu",
    "test.com",
    "localhost",
    "invalid",
    "none.com",
    "noemail.com",
    "no-reply.com",
    "noreply.com",
];

/// Role-based / shared-mailbox local-parts: an `info@acme.com` identifies a
/// mailbox, not a *person*, so it must not form a person↔person email edge.
const ROLE_LOCALS: &[&str] = &[
    "info",
    "sales",
    "support",
    "admin",
    "administrator",
    "contact",
    "hello",
    "help",
    "office",
    "team",
    "marketing",
    "billing",
    "accounts",
    "accounting",
    "finance",
    "hr",
    "jobs",
    "careers",
    "press",
    "media",
    "legal",
    "privacy",
    "security",
    "abuse",
    "postmaster",
    "webmaster",
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "mailer-daemon",
    "notifications",
    "notification",
    "newsletter",
    "enquiries",
    "inquiries",
    "service",
    "customerservice",
    "orders",
    "hi",
];

/// Is `value` a built-in-denylisted key of `kind`? Case-insensitive. This is the
/// non-negotiable floor; a tenant's own `denylist_values` is checked *on top of*
/// this in the producers, never as a replacement.
///
/// - `Domain`: matches free-mail and placeholder domains.
/// - `Email`: matches if the local-part is role-based OR the domain is denied.
/// - `Phone` / `ExternalId`: no built-in denylist (tenant config only).
pub fn is_denylisted(kind: KeyKind, value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    match kind {
        KeyKind::Domain => is_denied_domain(&v),
        KeyKind::Email => match v.split_once('@') {
            Some((local, domain)) => {
                // Strip any surviving +tag before role-local matching so
                // `info+x@…` is still caught.
                let local_base = local.split_once('+').map(|(l, _)| l).unwrap_or(local);
                ROLE_LOCALS.contains(&local_base) || is_denied_domain(domain)
            }
            None => true, // malformed email: fail closed.
        },
        KeyKind::Phone | KeyKind::ExternalId => false,
    }
}

fn is_denied_domain(domain: &str) -> bool {
    FREEMAIL_DOMAINS.contains(&domain) || PLACEHOLDER_DOMAINS.contains(&domain)
}

// ---------------------------------------------------------------------------
// email
// ---------------------------------------------------------------------------

/// Canonicalize an email into a namespace-stamped [`CanonKey`], or `None` if it
/// is malformed / denylisted (free-mail domain, role-based local).
///
/// Steps: trim, lowercase, strip a leading `mailto:`, strip the `+tag`
/// sub-address from the local-part (gmail-style plus-addressing — the same
/// inbox), reject if it fails the denylist. **Fail-closed:** anything without
/// exactly one `@` and a dot-bearing domain returns `None`.
///
/// `namespace` is supplied by the caller because it is a *provenance* fact about
/// where the email came from (an actor field vs a CRM contact field), not
/// something derivable from the string — see [`namespace_for_source_field`].
pub fn canonicalize_email(raw: &str, namespace: KeyNamespace) -> Option<CanonKey> {
    let s = raw.trim().to_ascii_lowercase();
    let s = s.strip_prefix("mailto:").unwrap_or(&s).trim();
    let (local_raw, domain_raw) = s.split_once('@')?;
    if local_raw.is_empty() || domain_raw.is_empty() {
        return None;
    }
    // A second '@' means it is not a bare address.
    if domain_raw.contains('@') {
        return None;
    }
    // Strip +tag sub-addressing: `jane+newsletter@acme.com` -> `jane@acme.com`.
    let local = match local_raw.split_once('+') {
        Some((base, _tag)) => base,
        None => local_raw,
    };
    if local.is_empty() {
        return None;
    }
    // Domain must be a plausible hostname with a dot (rejects `jane@localhost`).
    let domain = domain_raw.trim_matches('.');
    if !domain.contains('.') || domain.contains(' ') {
        return None;
    }
    let value = format!("{local}@{domain}");
    if is_denylisted(KeyKind::Email, &value) {
        return None;
    }
    Some(CanonKey {
        kind: KeyKind::Email,
        value,
        namespace,
    })
}

/// The registrable domain of an email's host (eTLD+1), e.g.
/// `jane@mail.acme.co.uk` → `acme.co.uk`. `None` on the same conditions as
/// [`canonicalize_email`] plus a denylisted registrable domain. Useful for the
/// account-level domain key derived from a contact email.
pub fn email_domain_key(raw: &str, namespace: KeyNamespace) -> Option<CanonKey> {
    let email = canonicalize_email(raw, namespace)?;
    let (_local, host) = email.value.split_once('@')?;
    canonicalize_domain(host, namespace)
}

// ---------------------------------------------------------------------------
// domain
// ---------------------------------------------------------------------------

/// Canonicalize a bare host/domain string into a registrable-domain
/// [`CanonKey`], or `None` if empty / denylisted / not a real domain.
///
/// Steps: trim, lowercase, strip a scheme + path if one slipped in, strip a
/// leading `www.`, reduce to the registrable domain (eTLD+1) via
/// [`registrable_domain`], then apply the denylist.
pub fn canonicalize_domain(raw: &str, namespace: KeyNamespace) -> Option<CanonKey> {
    let host = extract_host(raw)?;
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let reg = registrable_domain(host)?;
    if is_denylisted(KeyKind::Domain, &reg) {
        return None;
    }
    Some(CanonKey {
        kind: KeyKind::Domain,
        value: reg,
        namespace,
    })
}

/// Canonicalize a Salesforce `Account.Website` value (a URL string — SF exposes
/// no clean domain field) into a registrable-domain [`CanonKey`]. This is just
/// [`canonicalize_domain`] fed the URL; kept as a named entry point because the
/// SF `Website`→domain parse is a *documented, load-bearing* S0 step (§4.2, §7)
/// and the call sites read better for it.
///
/// Examples: `https://www.acme.com/contact` → `acme.com`;
/// `acme.co.uk` → `acme.co.uk`.
pub fn canonicalize_website_domain(raw: &str, namespace: KeyNamespace) -> Option<CanonKey> {
    canonicalize_domain(raw, namespace)
}

/// Pull a bare host out of anything domain-ish: a bare domain, a full URL
/// (`https://www.acme.com/x?y`), a `scheme://user@host:port/…`, or an email's
/// domain. Lowercased, no port, no path, no userinfo. `None` if nothing
/// host-like remains.
fn extract_host(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    // Drop a scheme: everything up to and including "://".
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    } else if let Some(rest) = s.strip_prefix("mailto:") {
        s = rest.to_string();
    }
    // Drop userinfo (`user@host`) — keep the host side.
    if let Some((_, host)) = s.rsplit_once('@') {
        s = host.to_string();
    }
    // Drop path / query / fragment.
    for sep in ['/', '?', '#'] {
        if let Some(idx) = s.find(sep) {
            s.truncate(idx);
        }
    }
    // Drop a port.
    if let Some((host, _port)) = s.rsplit_once(':') {
        // Only treat as a port if what follows is all digits.
        if s[host.len() + 1..].chars().all(|c| c.is_ascii_digit()) && !host.is_empty() {
            s = host.to_string();
        }
    }
    let host = s.trim_matches('.').trim();
    if host.is_empty() || !host.contains('.') || host.contains(' ') {
        return None;
    }
    Some(host.to_string())
}

/// A small, **documented** public-suffix heuristic — NOT the full Public Suffix
/// List. Reduces a host to its registrable domain (eTLD+1).
///
/// ## The heuristic
/// - If the host's last two labels form a known **multi-part public suffix**
///   (e.g. `co.uk`, `com.au`, `co.jp`), the registrable domain is the **last
///   three** labels (`acme.co.uk`).
/// - Otherwise the registrable domain is the **last two** labels (`acme.com`).
///
/// ## Known limitation (stated on purpose)
/// This is a hand-maintained list of the common multi-part TLDs, not the ~9k
/// entry PSL, and it does not handle exception rules (e.g. `!city.kawasaki.jp`)
/// or single-label private suffixes (e.g. `*.compute.amazonaws.com`). For those
/// hosts it will over- or under-collapse. We deliberately avoid pulling a heavy
/// PSL crate into the serving-core dependency tree for an MVP S0 step. When a
/// tenant needs exact PSL behavior, the domain producer should be fed a
/// pre-resolved registrable domain instead. The denylist floor still applies, so
/// a mis-collapsed free-mail/placeholder host is still rejected.
///
/// Returns `None` for a host with fewer than two labels.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_matches('.');
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if MULTI_PART_SUFFIXES.contains(&last_two.as_str()) && labels.len() >= 3 {
        Some(format!("{}.{}", labels[labels.len() - 3], last_two))
    } else {
        Some(last_two)
    }
}

/// Common multi-part public suffixes covered by the S0 heuristic (see
/// [`registrable_domain`] for the limitation note). Lowercased, `.`-joined.
const MULTI_PART_SUFFIXES: &[&str] = &[
    // United Kingdom
    "co.uk",
    "org.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "net.uk",
    "sch.uk",
    "ac.uk",
    "gov.uk",
    // Australia
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    // New Zealand
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "school.nz",
    // Japan
    "co.jp",
    "or.jp",
    "ne.jp",
    "ac.jp",
    "go.jp",
    // Brazil
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    // India
    "co.in",
    "net.in",
    "org.in",
    "gen.in",
    "firm.in",
    "ind.in",
    // South Africa
    "co.za",
    "net.za",
    "org.za",
    "gov.za",
    // Others commonly seen in B2B data
    "com.mx",
    "com.sg",
    "com.hk",
    "com.cn",
    "com.tr",
    "com.ar",
    "com.tw",
    "com.my",
    "co.kr",
    "co.il",
    "co.id",
    "co.th",
    "com.pl",
    "com.ua",
    "com.ph",
    "com.vn",
];

// ---------------------------------------------------------------------------
// phone
// ---------------------------------------------------------------------------

/// Canonicalize a phone number into an E.164-ish `+<digits>` [`CanonKey`], or
/// `None` if it has too few digits to be a real number.
///
/// **Best-effort, documented approximation** (not libphonenumber): strip all
/// non-digits; honor a leading `+` or `00` international prefix; if a bare
/// 10-digit number is given, assume NANP and prefix `+1`; if 11 digits starting
/// with `1`, treat as NANP. Numbers of other lengths keep their digits with a
/// `+` (we do not invent a country code). Fewer than 8 digits → `None`.
///
/// A phone is a MEDIUM key at best; it never auto-merges alone under
/// `min_independent_keys` — this only produces a normalized comparable value.
pub fn canonicalize_phone(raw: &str) -> Option<CanonKey> {
    let trimmed = raw.trim();
    let had_plus = trimmed.starts_with('+');
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    // Honor a `00` international prefix as `+`.
    let (digits, intl) = if !had_plus && digits.starts_with("00") {
        (digits[2..].to_string(), true)
    } else {
        (digits, had_plus)
    };
    if digits.len() < 8 {
        return None;
    }
    let e164 = if intl {
        format!("+{digits}")
    } else if digits.len() == 10 {
        // Bare NANP number.
        format!("+1{digits}")
    } else if digits.len() == 11 && digits.starts_with('1') {
        format!("+{digits}")
    } else {
        // Unknown country; keep digits, mark international. Documented approx.
        format!("+{digits}")
    };
    Some(CanonKey {
        kind: KeyKind::Phone,
        value: e164,
        // Phones inherit the caller's population context; default to customer.
        namespace: KeyNamespace::CustomerContact,
    })
}

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

/// Legal-form suffixes stripped from a company name during normalization. Order
/// matters only for readability; matching is by whole trailing token(s).
const LEGAL_SUFFIXES: &[&str] = &[
    "incorporated",
    "inc",
    "corporation",
    "corp",
    "company",
    "co",
    "limited",
    "ltd",
    "llc",
    "l.l.c",
    "llp",
    "lllp",
    "lp",
    "plc",
    "gmbh",
    "ag",
    "sa",
    "s.a",
    "nv",
    "bv",
    "ab",
    "as",
    "oy",
    "pty",
    "pte",
    "srl",
    "spa",
    "kg",
    "kk",
    "holdings",
    "group",
];

/// Normalize a company name for blocking / display: NFKC-ish compatibility
/// folding (best-effort without an ICU crate — see note), ASCII case-fold, strip
/// punctuation, strip trailing legal suffixes (`Inc`, `LLC`, `Ltd`, `Corp`, …),
/// collapse internal whitespace. Returns `None` if nothing is left after
/// stripping (e.g. the input *was* just "Inc.").
///
/// **Note on NFKC:** true Unicode NFKC needs `unicode-normalization`, not in the
/// tree. We do a pragmatic subset: trim, lowercase (ASCII + `char::to_lowercase`
/// for the rest), drop combining-mark-free punctuation, and collapse spaces.
/// Full-width/compatibility variants are *not* decomposed. This is adequate for
/// blocking (a recall aid), and name is **never** a Tier-1 auto-merge key on its
/// own, so the residual imprecision cannot cause a false merge.
pub fn canonicalize_name(raw: &str) -> Option<String> {
    // Lowercase (best-effort Unicode-aware) and map punctuation to spaces.
    let lowered: String = raw
        .trim()
        .chars()
        .flat_map(|c| c.to_lowercase())
        .map(|c| {
            if c.is_alphanumeric() || c.is_whitespace() {
                c
            } else {
                ' '
            }
        })
        .collect();

    // Tokenize, dropping empties.
    let mut tokens: Vec<Cow<'_, str>> = lowered.split_whitespace().map(Cow::Borrowed).collect();
    if tokens.is_empty() {
        return None;
    }

    // Strip trailing legal-form tokens (possibly several: "Acme Group Inc").
    while let Some(last) = tokens.last() {
        let t = last.as_ref();
        if LEGAL_SUFFIXES.contains(&t) {
            tokens.pop();
        } else {
            break;
        }
    }
    if tokens.is_empty() {
        return None;
    }
    Some(tokens.join(" "))
}

// ---------------------------------------------------------------------------
// namespace stamping helper (§4.4)
// ---------------------------------------------------------------------------

/// Decide the [`KeyNamespace`] for an email/domain given the *source* and the
/// *field* it was read from. This is the §4.4 fence made mechanical: identify
/// the actor/internal-directory fields explicitly; everything else on a CRM
/// contact/account defaults to `customer_contact`.
///
/// The known internal-directory shapes (from §1/§4.4):
/// - Linear actor fields: `assignee.email`, `creator.email`, `actor.email`,
///   `user.email`, `subscriber.email`.
/// - Any field the ingestion layer already knows is one of *our own* users.
///
/// Anything else (Salesforce/HubSpot contact `email`, account `domain` /
/// `website`) is `customer_contact`. When in doubt, callers should pass the
/// field name verbatim; an unrecognized field defaults to `customer_contact`
/// **only** for CRM sources — for the Linear source it defaults to
/// `internal_directory` (fail-safe: Linear's populated emails are actors).
pub fn namespace_for_source_field(source: &str, field: &str) -> KeyNamespace {
    let f = field.to_ascii_lowercase();
    const INTERNAL_FIELDS: &[&str] = &[
        "assignee.email",
        "assignee_email",
        "creator.email",
        "creator_email",
        "actor.email",
        "actor_email",
        "user.email",
        "user_email",
        "subscriber.email",
        "subscriber_email",
        "reporter.email",
    ];
    if INTERNAL_FIELDS.contains(&f.as_str()) {
        return KeyNamespace::InternalDirectory;
    }
    // Source-level fail-safe: a Linear-origin email that isn't a recognized
    // customer field is an actor, so treat unknowns from Linear as internal.
    match source.to_ascii_lowercase().as_str() {
        "linear" => KeyNamespace::InternalDirectory,
        _ => KeyNamespace::CustomerContact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- email ------------------------------------------------------------

    #[test]
    fn email_lowercases_and_strips_plus_tag() {
        let k = canonicalize_email(
            "Jane.Doe+Newsletter@Acme.COM",
            KeyNamespace::CustomerContact,
        )
        .unwrap();
        assert_eq!(k.value, "jane.doe@acme.com");
        assert_eq!(k.kind, KeyKind::Email);
        assert_eq!(k.namespace, KeyNamespace::CustomerContact);
    }

    #[test]
    fn email_strips_mailto_and_whitespace() {
        let k =
            canonicalize_email("  mailto:Bob@Acme.com  ", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "bob@acme.com");
    }

    #[test]
    fn email_denylist_blocks_freemail() {
        assert!(canonicalize_email("jane@gmail.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("x@yahoo.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("y@icloud.com", KeyNamespace::CustomerContact).is_none());
    }

    #[test]
    fn email_denylist_blocks_role_locals() {
        // The classic §4.2 examples.
        assert!(canonicalize_email("info@acme.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("sales@acme.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("support@acme.com", KeyNamespace::CustomerContact).is_none());
        // Role local survives even with a +tag.
        assert!(canonicalize_email("info+q3@acme.com", KeyNamespace::CustomerContact).is_none());
    }

    #[test]
    fn email_denylist_blocks_placeholder_domain() {
        assert!(canonicalize_email("jane@example.com", KeyNamespace::CustomerContact).is_none());
    }

    #[test]
    fn email_rejects_malformed() {
        assert!(canonicalize_email("not-an-email", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("a@@b.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("jane@localhost", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("@acme.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_email("jane@", KeyNamespace::CustomerContact).is_none());
    }

    #[test]
    fn email_preserves_namespace() {
        let k = canonicalize_email("jane@acme.dev", KeyNamespace::InternalDirectory).unwrap();
        assert_eq!(k.namespace, KeyNamespace::InternalDirectory);
    }

    #[test]
    fn email_domain_key_reduces_to_registrable() {
        let k = email_domain_key("jane@mail.acme.co.uk", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "acme.co.uk");
        assert_eq!(k.kind, KeyKind::Domain);
    }

    // ---- domain -----------------------------------------------------------

    #[test]
    fn domain_strips_www_and_lowercases() {
        let k = canonicalize_domain("WWW.Acme.COM", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "acme.com");
    }

    #[test]
    fn domain_handles_full_url() {
        let k = canonicalize_domain(
            "https://www.acme.com/contact?ref=1#top",
            KeyNamespace::CustomerContact,
        )
        .unwrap();
        assert_eq!(k.value, "acme.com");
    }

    #[test]
    fn domain_handles_url_with_port_and_userinfo() {
        let k = canonicalize_domain(
            "http://user:pass@acme.com:8443/x",
            KeyNamespace::CustomerContact,
        )
        .unwrap();
        assert_eq!(k.value, "acme.com");
    }

    #[test]
    fn domain_co_uk_keeps_three_labels() {
        let k = canonicalize_domain("shop.acme.co.uk", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "acme.co.uk");
    }

    #[test]
    fn domain_com_au_keeps_three_labels() {
        let k = canonicalize_domain("www.acme.com.au", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "acme.com.au");
    }

    #[test]
    fn domain_plain_two_label_unchanged() {
        let k = canonicalize_domain("sub.acme.com", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "acme.com");
    }

    #[test]
    fn domain_denylist_blocks_freemail_and_placeholder() {
        assert!(canonicalize_domain("gmail.com", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_domain("www.example.com", KeyNamespace::CustomerContact).is_none());
    }

    #[test]
    fn domain_rejects_single_label() {
        assert!(canonicalize_domain("localhost", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_domain("acme", KeyNamespace::CustomerContact).is_none());
        assert!(canonicalize_domain("", KeyNamespace::CustomerContact).is_none());
    }

    // ---- Salesforce Website URL ------------------------------------------

    #[test]
    fn website_url_parses_domain() {
        let k = canonicalize_website_domain("https://www.acme.com", KeyNamespace::CustomerContact)
            .unwrap();
        assert_eq!(k.value, "acme.com");
    }

    #[test]
    fn website_url_bare_domain() {
        let k = canonicalize_website_domain("acme.co.uk", KeyNamespace::CustomerContact).unwrap();
        assert_eq!(k.value, "acme.co.uk");
    }

    #[test]
    fn website_url_with_trailing_path() {
        let k = canonicalize_website_domain(
            "http://acme.com/about/team/",
            KeyNamespace::CustomerContact,
        )
        .unwrap();
        assert_eq!(k.value, "acme.com");
    }

    // ---- phone ------------------------------------------------------------

    #[test]
    fn phone_nanp_bare_ten_digits() {
        let k = canonicalize_phone("(415) 555-2671").unwrap();
        assert_eq!(k.value, "+14155552671");
    }

    #[test]
    fn phone_nanp_eleven_digits() {
        let k = canonicalize_phone("1-415-555-2671").unwrap();
        assert_eq!(k.value, "+14155552671");
    }

    #[test]
    fn phone_explicit_plus_preserved() {
        let k = canonicalize_phone("+44 20 7946 0958").unwrap();
        assert_eq!(k.value, "+442079460958");
    }

    #[test]
    fn phone_double_zero_intl_prefix() {
        let k = canonicalize_phone("0044 20 7946 0958").unwrap();
        assert_eq!(k.value, "+442079460958");
    }

    #[test]
    fn phone_too_short_rejected() {
        assert!(canonicalize_phone("12345").is_none());
        assert!(canonicalize_phone("").is_none());
    }

    // ---- name -------------------------------------------------------------

    #[test]
    fn name_strips_legal_suffix_and_punct() {
        assert_eq!(canonicalize_name("Acme, Inc.").as_deref(), Some("acme"));
        assert_eq!(canonicalize_name("Acme").as_deref(), Some("acme"));
        assert_eq!(canonicalize_name("ACME LLC").as_deref(), Some("acme"));
        assert_eq!(canonicalize_name("Acme Corp.").as_deref(), Some("acme"));
        assert_eq!(canonicalize_name("Acme Ltd").as_deref(), Some("acme"));
    }

    #[test]
    fn name_legal_dba_drift_collapses_equal() {
        // "Acme, Inc." vs "Acme" (the §7 worked example) normalize identically.
        assert_eq!(canonicalize_name("Acme, Inc."), canonicalize_name("Acme"));
    }

    #[test]
    fn name_strips_multiple_trailing_suffixes() {
        assert_eq!(
            canonicalize_name("Acme Holdings Group Inc").as_deref(),
            Some("acme")
        );
    }

    #[test]
    fn name_collapses_internal_whitespace() {
        assert_eq!(
            canonicalize_name("  Acme   Freight   Systems  ").as_deref(),
            Some("acme freight systems")
        );
    }

    #[test]
    fn name_only_suffix_returns_none() {
        assert_eq!(canonicalize_name("Inc."), None);
        assert_eq!(canonicalize_name("   "), None);
    }

    // ---- namespace fence stamping ----------------------------------------

    #[test]
    fn namespace_actor_email_is_internal() {
        assert_eq!(
            namespace_for_source_field("linear", "assignee.email"),
            KeyNamespace::InternalDirectory
        );
        assert_eq!(
            namespace_for_source_field("linear", "creator_email"),
            KeyNamespace::InternalDirectory
        );
    }

    #[test]
    fn namespace_crm_contact_email_is_customer() {
        assert_eq!(
            namespace_for_source_field("salesforce", "email"),
            KeyNamespace::CustomerContact
        );
        assert_eq!(
            namespace_for_source_field("hubspot", "email"),
            KeyNamespace::CustomerContact
        );
    }

    #[test]
    fn namespace_unknown_linear_field_fails_safe_to_internal() {
        assert_eq!(
            namespace_for_source_field("linear", "some_email"),
            KeyNamespace::InternalDirectory
        );
    }

    #[test]
    fn namespace_roundtrips() {
        assert_eq!(
            KeyNamespace::from_stored(KeyNamespace::CustomerContact.as_str()),
            KeyNamespace::CustomerContact
        );
        assert_eq!(
            KeyNamespace::from_stored(KeyNamespace::InternalDirectory.as_str()),
            KeyNamespace::InternalDirectory
        );
        // Unknown fails closed to the narrower population.
        assert_eq!(
            KeyNamespace::from_stored("garbage"),
            KeyNamespace::InternalDirectory
        );
    }
}
