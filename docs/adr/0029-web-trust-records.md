# ADR-0029: Web trust-boundary decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 44 comments on the web trust boundary were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/src/display.ts`

- L1: Terminal display neutralizes server-distributed free strings (names, user_ids) against terminal injection; values get the same neutralization as a separate (co-editor) threat, with a warning when display ≠ actual
- L23: ORDER_BREAKING enumerates order/visibility-manipulating characters only: Cf is not crushed wholesale because ZWNJ/ZWJ are required for legitimate Persian/Devanagari/emoji display; the deny-list is admitted not to close
- L73: escapeText passes only printable ASCII minus backslash and quote: backslash preserves reversibility, and excluding the quote prevents closing a quoted display early
- L176: escapeText is an allow-list (printable ASCII, everything else escaped) because a deny-list cannot distinguish look-alike characters; its purpose is identity as an operation target, not readability
- L207: Value display neutralizes injection-capable controls but keeps tab and newline so legitimate multi-line secrets (PEM keys) are not broken — a separate threat from server forgery
- L332: Multi-line values are framed with continuation markers instead of crushing newlines: raw streaming would let a co-editor forge variable rows, crushing would break legitimate multi-line secrets

### `apps/site/astro.config.ts`

- L3: Apex static site (LP+docs) deployed separately from the product origin; no analytics/trackers, self-hosted fonts, local Pagefind search.
- L40: Ruling D: stylesheets are never inlined into HTML because the CSP is style-src 'self'; postbuild allows inline scripts/styles by hash.

### `apps/site/scripts/postbuild.ts`

- L1: Postbuild finishes dist for Workers Static Assets (ruling D): externalizes style attributes to hashed classes and sets a hash-based CSP with no unsafe-inline.
- L70: The attribute-value regex covers double-quoted, single-quoted and unquoted forms so no attribute value escapes the check.
- L184: JSON data blocks are not executed, so they fall outside CSP scope when collecting inline hashes.
- L218: Inline event handlers and javascript: URLs are blocked by CSP, so they are detected at build time instead of silently losing functionality.
- L223: External-reference check excludes HTML comments (logo SVG provenance URL) and allows href navigation only to the repo GitHub and the product origin.
- L267: script-src allows 'wasm-unsafe-eval' solely so Pagefind's same-origin Wasm search index can instantiate; it permits no JavaScript eval.
- L294: Existing dist _headers are kept; postbuild appends charset/Link blocks and the /* security headers, with multi-block inheritance.

### `apps/site/src/components/ui/banner/Banner.astro`

- L11: Banner message HTML is rendered as written: trusted like the rest of the site's content.

### `apps/site/src/components/ui/banner/banner.client.ts`

- L29: Client-side dismissal check also covers banners from an older Banner.astro and pages whose CSP blocks the inline pre-paint script.

### `apps/site/src/pages/index.astro`

- L41: Trust boundary (ADR-0018 / CRYPTO_SPEC §14.2): only where a decryptor lives does plaintext appear.

### `apps/site/src/pages/robots.txt.ts`

- L9: Content Signals are declared deliberately (owner decision 2026-11-14): ai-train/search/ai-input all yes, since the docs are written to be used by AI systems too; revisit if restrictive-value content appears.

### `apps/site/test/e2e.test.ts`

- L166: Pagefind's Wasm index compilation is gated on 'wasm-unsafe-eval', which permits no JavaScript eval.
- L226: Style attributes are measured in the shipped HTML, not the live DOM, because the chrome's client code legitimately sets style properties at runtime.
- L522: Zero style attributes in shipped docs HTML is the precondition for not using 'unsafe-inline' in style-src-attr; Shiki tokens carry nb-shiki-* classes instead.

### `apps/web/public/pages.css`

- L1: pages.css styles only script-free pages under script-src 'none'; brand values are never written here (ADR-0013) — every value is a var() from /theme.css, which must define it.

### `apps/web/scripts/write-headers.ts`

- L1: write-headers permits the funstack bootstrap script and Astryx's runtime stylesheet only by SHA-256 hash (no unsafe-inline), and pins /invite's no-scripts invariant mechanically.
- L61: Astryx's runtime-inserted layer slide rules are fixed per release and take no nonce, so style-src allows their exact text by SHA-256 (owner approval 2026-10-23); e2e re-hashes the live element.
- L86: The invite check runs on the shipped build output, not the source, and does not strip HTML comments, so every path a script could slip into served bytes is covered.
- L106: The invite page's meta CSP is a second enforcement layer independent of the _headers per-path CSP, keeping script execution at zero regardless of serving-layer differences.
- L117: Invite page loads no external resources; only an href may point at this repo's GitHub, and protocol-relative // URLs are rejected as distinct from root-relative.
- L202: Tripwire (ruling BG): the word 'hash' must never appear in shipped JS/HTML so the SPA provably never reads the fragment; a #-literal check was rejected for measured false positives.
- L241: /invite's per-path CSP is script-src 'none' with everything else 'none' except self-hosted styles and the logo, structurally enforcing 'never interprets the fragment'.
- L255: HSTS omits includeSubDomains (the zone's subdomain structure is the self-hoster's jurisdiction); the /invite block detaches the /* CSP before replacing it so two CSPs aren't both enforced.
- L291: Near-miss /invite paths are 301-normalized via a generated _redirects: a 200 shield first, then 63 case-variant splats, then the catch-all; total kept at 65 of the 100-rule limit.

### `apps/web/src/components/Providers.tsx`

- L6: The prebuilt Astryx theme object injects no CSS at runtime, so it is compatible with the strict style-src 'self' CSP.

### `apps/web/src/dashboard/AuditEventList.tsx`

- L190: Astryx CodeBlock emits a per-chunk inline style, so it cannot render under style-src 'self' (K5-11); the recorded payload needs no highlighting and is drawn as pre-wrapped code text.

### `apps/web/src/dashboard/api.ts`

- L17: The CSRF header literal is bound at type level (ruling CN): a value import would pull api-schema executable code into the bundle (the TCB), so a source-side rename becomes a compile error instead.

### `apps/web/src/dashboard/types.ts`

- L1: Dashboard wire types are type-only imports from api-schema (ruling BR): types stay bound to the single Schema definition while no Effect/Schema code enters the bundle (the TCB); runtime validation is intentionally skipped (ADR-0018).

### `apps/web/src/styles/global.css`

- L1: global.css imports Astryx's prebuilt CSS only; everything is self-hosted via Workers Static Assets with no external CDN and no runtime injection.

### `apps/web/test/e2e.test.ts`

- L247: style-src allows Astryx's runtime slide rules only by their SHA-256 (write-headers.ts, owner approval 2026-10-23); the e2e hashes the live element so an upgrade changing the rules fails here.
- L298: /invite is pinned against the real serving (cf dev): a standalone static asset outside the SPA with per-path CSP script-src 'none', carrying no script and never interpreting the fragment (§15-3).

### `apps/web/test/unit/endpoints.test.ts`

- L146: Ruling BR (no Effect/Schema code in the bundle = the TCB) was a mere convention that a value import passed silently; under verbatimModuleSyntax it is mechanically checkable, and this sweep is the web half of the Effect fence.
- L190: ADR-0018: the web holds no keys or plaintext and ships no decrypt/wrap/verification code, so bundle source imports nothing from packages/crypto — not even types; tests may use it.

### `apps/web/theme/maruhi.ts`

- L1: The brand theme ships as static CSS because the <Theme> runtime injection inserts an inline <style>, incompatible with style-src 'self' (ADR-0013); the only raw hex values are the vermilion and on-accent pairs.

### `packages/core/src/egress.ts`

- L1: Egress policy: maruhi never forwards trace context — a shared trace id would give the server and third parties a common correlation identifier; the policy is bound to the client itself so it holds in every fiber
- L40: Fetch options ride on each request, not the layer build: a build-time RequestInit is lost when the layer is already built in the ambient memo map, and a dropped redirect: 'manual' would re-send the caller's headers

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
