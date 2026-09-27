# Session 41: W1 — implementation rulings for the statically reduced form (/invite + per-path CSP) (BA–BH)

Date: 2026-08-29. Purpose: record of implementation rulings in PR-W1 (web-dashboard-design.md
§7). The norm = AUTH_SPEC §15-3 (invite-link landing point = fully static, fragment not
interpreted — PR #103 merged = owner-approved) and ADR-0018 revision 2, item 5. What this
document rules on is only the concretizations the spec delegated to implementation (delivery
form, how to write the per-path CSP, styling of the static page, form of the fixture checks).
Each ruling follows "multiple options → upward-compatible exploration → 3-round comparison →
autonomous selection" (the session-27 §14 format. Symbols continue session-40's AZ, starting
at BA).

Reference material: AUTH_SPEC §15-3, ADR-0018 revision 2 (item 5), web-dashboard-design.md
§2–§3 (S1, S2) and §7, session-39 (ruling AR, §10-2), ADR-0013 / ADR-0017,
apps/web/scripts/write-headers.ts (spike-a's CSP generation).

## 1. Ruling BA: delivery form (which asset /invite is placed as)

### Round 1

- **Option BA-a: add as an SPA route** (`route({ path: "/invite" })` in `App.tsx`) — rejected:
  the funstack bundle's inline bootstrap script lands on the page, leaving "carries no scripts at
  all" as convention only (the shape session-39 §10-2 explicitly rejected. A norm violation)
- **Option BA-b: place in vite `publicDir` (`apps/web/public/invite.html`)** — vite copies it
  unconverted into `dist/public/` and Workers Static Assets serves it. The source lives in the
  repo in a directly reviewable form
- **Option BA-c: generate the HTML in a post-build script** (kin to write-headers.ts) —
  rejected: going through generated code loses the directness of "the delivered bytes = the
  literal text reviewed", and the generation logic itself becomes a new script-injection path.
  There are also no dynamic values to put in a template (fully static), so generation's advantage
  is zero

### Round 2 (upward-compatible exploration)

- **Placement comparison within BA-b: `invite.html` vs `invite/index.html`** — under Workers
  Static Assets' default `html_handling` (auto-trailing-slash), `invite.html`'s canonical URL is
  `/invite` (an exact match of §15-3's link format), while `invite/index.html` canonicalizes to
  `/invite/` and `/invite` gets redirected. The latter mismatches the link format (the displayed
  URL changes), so **`invite.html`** is the only choice
- Measured (wrangler dev): `/invite` = 200 direct response; `/invite.html` and `/invite/` are
  307-normalized to `/invite` (the browser preserves the fragment across the redirect). This
  behavior is pinned in e2e (ruling BD)

### Round 3 (re-check)

- Coexistence with the SPA fallback (`not_found_handling: single-page-application`): real assets
  take priority over the fallback, so there's no path for `/invite` to be swallowed by the SPA.
  Also didn't add `/invite` to the SPA-side route definitions (don't create a client-side
  navigation path)
- **Residual (record of a pullfrog review finding → mostly resolved in ruling BF)**: the above
  guarantee is limited to the canonical URL and its normalization targets (`/invite.html`,
  `/invite/`, percent-encodings) — **near-miss paths (`/Invite`, `/INVITE`, `/invite/x`, etc.)
  don't match an asset key and fell into the SPA fallback** (bootstrap script + `/*` CSP shell at
  200 — measured). Initially this was accepted in W1 and handed off to W2, but the
  upward-compatible exploration (at the owner's request) found `_redirects`-based normalization
  (ruling BF), and **the whole class of case variants × trailing continuations was closed by
  configuration**. What remains is only free-typing typos with no generation source (`/invte`
  etc.) — same treatment as any 404 path (the SPA has no code that reads `location.hash`). The
  design decision on `not_found_handling` itself stays deferred to W2's ruling
- Confirmed by measurement that vite `publicDir` copies unconverted (no script injection at
  build). However, the check (BD) targets not the source but the **build output**, in preparation
  for future build changes

**Choice: option BA-b (`public/invite.html` → canonical URL `/invite`)**.

## 2. Ruling BB: styling the static page (consistency with ADR-0013 and the `'unsafe-inline'` ban)

### Round 1

- **Option BB-a: inline `<style>` + hash allowlisting via per-path CSP** — rejected: the cost of
  extending the hash-computation mechanism (kin to write-headers.ts's script hashes) to styles is
  paid for the aesthetics of a single file. Increasing CSP exception surface (allowlisted hashes)
  runs opposite to CLAUDE.md's strict-CSP spirit
- **Option BB-b: a standalone static CSS (`public/invite.css`, `style-src 'self'`)** —
  self-served, no exceptions. Same shape as the existing `/*`'s `style-src 'self'`
- **Option BB-c: reference the SPA's built CSS (Astryx/theme)** — rejected: the build output's
  CSS has a content-hashed filename and can't be stably referenced from static HTML. Placing an
  unhashed duplicate would double-manage the theme

### Round 2 (upward-compatible exploration)

- **Handling the brand colors in BB-b**: considered copying the theme's derived accent
  (`--color-accent` = the #b22a2b/#ffb3a8 family) into invite.css — rejected as a duplication
  violating ADR-0013's "brand definitions live solely in `apps/web/theme/`" and drifting on theme
  updates. **Grayscale + system-default colors only (`color-scheme: light dark` +
  `light-dark()`)**, with brand expression limited to ㊙ and the wordmark (text). ADR-0013's raw
  hex ban is a StyleX/xstyle discipline, but its intent (preventing brand-value dispersion) is
  upheld on the static page in the form "don't bring brand values in"

### Round 3 (re-check)

- Confirmed ADR-0013's scope: that ADR is the styling discipline for the Astryx SPA, and static
  pages outside the SPA are out of scope (oxlint's className ban targets JSX too). Naturally,
  "don't bring in external CSS" (third-party CSS) and all-assets-self-served still apply, and
  invite.css is self-authored and self-served — conforming
- No `'unsafe-inline'` (no inline style either), no inline `style` attributes

**Choice: option BB-b (grayscale standalone invite.css, `style-src 'self'`)**.

## 3. Ruling BC: how to write the per-path CSP (its expression in _headers)

### Round 1

- **Option BC-a: add the CSP in the `/invite` block (no detach)** — rejected: Workers Static
  Assets' `_headers` co-applies the headers of multiple matching rules. Two CSPs are both
  enforced (intersection = effective script-src 'none'), which is the safe side, but "/invite's
  effective policy" becomes unreadable in one place and SPA-side hash churn keeps leaking into
  /invite's response headers
- **Option BC-b: detach with `! Content-Security-Policy`, then replace wholesale** — /invite's
  policy becomes a single self-contained declaration. Other security headers (nosniff /
  Referrer-Policy / HSTS) keep inheriting from `/*` unchanged

### Round 2 (upward-compatible exploration)

- Contents of the /invite policy: `default-src 'none'; script-src 'none'; style-src 'self';
  base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. `script-src 'none'` is covered by
  default-src but is **stated explicitly** because it's the literal text of the norm (§15-3)
  (it's also the string the check targets). `img-src` / `font-src` / `connect-src` aren't
  permitted because the page doesn't use them (narrower than `/*`).
  `form-action 'none'` (no forms — narrower than `/*`'s 'self')

### Round 3 (re-check)

- Measured the detach syntax's real behavior on wrangler dev: /invite's response CSP is only the
  single post-replacement one. e2e pins "does not contain `'self' 'sha256-`", so if a future
  wrangler disables detach it's detected (ruling BD)
- **Handoff (record of a pullfrog review finding → de-weighted by ruling BE)**: Cloudflare
  documentation does describe `_headers` on Workers Static Assets, the `!` detach syntax, and
  header inheritance from broader rules, but there's no documentation of this pattern —
  "redeclaring the same header right after detaching it within the same block" — nor of
  wrangler dev / production behavioral parity. Initially this was a loaded handoff — "if the
  redeclaration is dropped in production, we lose the CSP header entirely" — but the
  upward-compatible exploration added **asset-embedded meta CSP (ruling BE)**, so zero script
  execution is now enforced independently of header-layer behavior differences. Checking the real
  `/invite` response headers after first deploy **stays as a recommended confirmation**, but the
  invariant's holding doesn't depend on it
- No regression on existing paths: the `/*` block's string is unchanged (e2e's existing
  assertions already pin `script-src 'self'` + hash)

**Choice: option BC-b (detach + wholesale replacement)**.

## 4. Ruling BD: the form of the fixture check (mechanical checking of invariants)

### Round 1

- **Option BD-a: check only in the post-build script (inside write-headers.ts)** — against the
  build output's invite.html (the delivered bytes), check: zero scripts, no inline handlers, no
  `javascript:`, no external resource references (only navigation `<a href>` to our own repo's
  GitHub allowed); a violation throws = build failure. `_headers` is read back from the written
  file to confirm the `/invite` block and `script-src 'none'` are present
- **Option BD-b: e2e test only** — against wrangler dev's real serving, verify the response
  headers (per-path CSP effectiveness) and response body (zero scripts), plus
  `document.scripts.length === 0` and zero CSP violations in real browser rendering
- **Option BD-c: both (adopted)** — BD-a gives fastest failure (at build stage) plus checking
  "the final _headers artifact"; BD-b checks "the effectiveness through the delivery machinery
  (html_handling, detach)". Different defended layers. In CI both web build (step 8) and web e2e
  (step 9) are on the quality-gate path

### Round 2 (upward-compatible exploration)

- Unifying check strength: initially BD-a stripped HTML comments before looking for script tags,
  but that doesn't match e2e's strength (the whole delivered bytes). **Unified toward keeping
  `<script` at zero including inside comments** (comments are inert, but a rule with zero
  exceptions weakening the check is simpler, and grep reaches the same conclusion)

### Round 3 (re-check)

- The check targets the **build output**, not the source (BA round 3 — checks the copy /
  conversion path too)
- e2e renders with a dummy-fragment URL (mimicking §15-3's link format), guaranteeing via
  script-zero that the fragment's presence doesn't affect behavior (no interpreting code exists)
- Missed check-writing / future regression: if write-headers.ts stopped writing the `/invite`
  block, its own read-back check fails; if it writes it but the delivery doesn't apply it, e2e
  fails. If invite.html itself disappears, readFileSync fails the build

**Choice: option BD-c (two layers: build-time check + e2e)**.

## 5. Ruling BE: embedding meta CSP in the asset (making enforcement delivery-layer-independent — upward-compatible exploration)

Additional exploration from the owner's post-initial-PR (61d4a4d..b05616e) request to "look for
silver bullets / upward-compatible options". The target is ruling BC's handoff (the `!` detach's
production behavior being undocumented = header-layer enforcement resting on a single measured
point).

### Round 1

- **Option BE-a: status quo (_headers only + post-deploy confirmation)** — enforcement is
  concentrated in a single header-layer path whose production behavior is undocumented. The
  confirmation task is human-dependent
- **Option BE-b: drop detach, return to additive (two CSPs side by side)** — rejected: both are
  enforced (intersection), which is the safe side, but "co-applying same-named headers of
  multiple matching rules" is likewise undocumented, so it doesn't remove the uncertainty. Only
  loses readability
- **Option BE-c: embed `<meta http-equiv="Content-Security-Policy">` in invite.html itself** —
  enforcement **travels with the delivered bytes**, fully independent of `_headers`'s
  interpretation machinery (detach, rule matching, dev/prod differences). Multiple CSPs
  intersect with all policies enforced (per CSP spec), so coexisting with the header CSP is safe

### Round 2 (upward-compatible exploration)

- Confirmed BE-c's constraint: meta CSP can't specify `frame-ancestors` / `report-uri` /
  `sandbox` (CSP spec) → **the split is that only frame-ancestors stays on the _headers side**.
  The meta's content is every other directive (`default-src 'none'; script-src 'none'; style-src
  'self'; base-uri 'none'; form-action 'none'`)
- Integration into the fixture checks: added "meta CSP exists and contains `script-src 'none'`"
  to the build-time check, and a delivered-body meta-presence assertion to e2e. **3 enforcement
  layers** (① zero scripts in the static bytes [build check] → ② meta CSP [asset-embedded,
  browser-enforced] → ③ per-path header CSP [delivery layer]) each with mutually independent
  failure modes

### Round 3 (re-check)

- Meta CSP doesn't break the page's own resources: the stylesheet is allowed by `style-src
  'self'` (e2e's style-applied assertion is the regression check). The page has no scripts, so
  nothing gets blocked and no violations occur (confirmed by e2e's zero-violation)
- Parser behavior: meta CSP takes effect from its position onward, so it goes at the top of
  `<head>` (right after charset). The page's own-script-zero is guaranteed by a separate layer,
  and the "a script inserted before the meta" case is failed earlier by the build check
- Ruling BC (detach + wholesale replacement) is unchanged. BC's handoff (post-deploy
  confirmation) is demoted to an unloaded recommendation (reflected in §3 round 3)

**Choice: option BE-c (meta CSP embedded + added to the 2 check layers)**.

## 6. Ruling BF: `_redirects` normalization of near-miss paths (closing the residual class — upward-compatible exploration)

The target is ruling BA's residual (near-misses like `/Invite` falling into the SPA shell that
carries scripts — the one deferred to W2 on a pullfrog finding).

### Round 1

- **Option BF-a: status quo (defer to W2)** — the residual stays "harmless by convention"
- **Option BF-b: change `not_found_handling` (abolish the SPA fallback)** — rejected: SPA deep
  links like `/about` depend on the SPA fallback (funstack-static doesn't emit per-route static
  HTML), so it's a design decision exceeding W1's reduced scope. Stays a W2 ruling target
- **Option BF-c: add a Worker script to the web app for path normalization** — rejected: the
  current web is plain static serving (zero Worker code); adding executable code to the delivery
  surface runs opposite ADR-0018's "minimize the operation's delivery surface"
- **Option BF-d: `_redirects` (Workers Static Assets supports Pages format) 301-normalizes
  near-misses to `/invite`** — static declarations only, no executable code. The browser
  preserves the fragment across the redirect, so guidance works at the normalized `/invite`
  (zero scripts)

### Round 2 (upward-compatible exploration — measurement-driven)

- wrangler dev measurement: `_redirects` is effective. Matching is **case-sensitive** (a literal
  rule for `/Invite` doesn't hit `/INVITE`) → case variants need enumeration
- Tried exact-match + `/variant/*` 2 forms × 64 variants = 127 rules → **all rules count as
  dynamic with a 100-rule cap** (wrangler silently drops rule 101+ with "Maximum number of
  dynamic rules supported is 100. Skipping remaining 28 lines" — measured). Pages' "2,000 static
  + 100 dynamic" split doesn't apply here
- **Measured the compressed form `/{Variant}* /invite 301` (trailing splat attached directly to
  the variant name)**: catches `/Invite`, `/Invite/x`, `/InviteXYZ` together → **1 rule per
  variant = 64 rules**, within the cap. Only the lowercase one is limited to `/invite/*` because
  `/invite*` would match the canonical path itself (a loop) and `/invite.css` (style breakage)

### Round 3 (re-check)

- Closed class: case variants (2^6 = 64) × trailing continuations (including `/x`, `XYZ`, `/`).
  Covers all systematic generation sources (mobile auto-capitalization, trailing junk on paste)
- Remaining residual: free-typing typos with no generation source (`/invte` etc.) — "an invalid
  URL", the same class as any 404 path falling into the SPA shell (the SPA has no code reading
  `location.hash`). There's no generation source that lands with a fragment
- Effect on existing behavior: `/invite/` now hits `_redirects` (301) ahead of the old
  auto-trailing-slash (307) — same destination `/invite`. `/invite.html` stays 307. e2e
  expectations updated to follow
- Rules are machine-generated by write-headers.ts and pinned by read-back check (existence of
  `/invite/*` and `/Invite*`) + e2e (301 and Location on 7 representative near-miss paths)

**Choice (initial version 78a2c50): option BF-d (machine-generated compressed form, 64 rules)**.

### Round 4 (revision from a pullfrog finding — the 200-rewrite shield)

- **Correction of round 3's generation-source analysis error (pullfrog measured finding)**:
  "trailing junk on paste" lands on a **lowercase path** (`/inviteXYZ`) — invite links are
  machine-generated and always lowercase. Since initial BF-d limited lowercase to `/invite/*`,
  **the most probable of the listed generation sources remained on the residual side** (a
  description-vs-coverage mismatch. Measured: `/inviteXYZ` → 200, SPA shell)
- **Revision: a shield of 200 rewrites exploiting first-match-wins** — pullfrog's proposal,
  confirmed by measurement on both sides. ① `/invite /invite 200` and `/invite.css /invite.css
  200` (rewrite to self = pass-through) come first → ② the 63 case-variant rules `/{Variant}*` →
  ③ the lowercase catch-all `/invite* /invite 301` last. 66 rules total (within the cap of 100;
  wrangler parses all). The 2 reasons the initial version deepened `/invite*` (self-loop,
  `/invite.css` misfire) both disappear under the shield, and lowercase + trailing continuations
  close too
- Measured (this build + wrangler dev): `/invite` = 200, **per-path CSP preserved after the
  rewrite**, zero scripts; `/invite.css` = 200 with intact body; `/inviteXYZ`, `/invite.html`
  (previously 307), `/invite/`, `/invite/x`, case variants → all 301 → `/invite`
- **Analysis of the new failure mode**: if production "drops only the shield and leaves ③",
  `/invite` becomes a self-redirect loop (**loss of availability** — no effect on concealment or
  the invariant [zero script execution]. Obvious on first open; recover by removing
  `_redirects`). wrangler dev and production Workers Static Assets share the same asset-worker
  implementation (not a dual implementation), so there's no basis to expect selective dropping —
  but the post-deploy confirmation (BC/BE's recommendation) includes checking that `/invite`
  returns 200
- **Documentation corroboration (confirmed in pullfrog re-review)**: the official Redirects
  documentation for Workers Static Assets (not Pages) documents 200-status proxy/rewrite rules
  as a proper feature, and explicitly states match order as "when multiple rules match the same
  source, the topmost applies" (first-match-wins) (cap = 2,000 static + 100 dynamic). The 2
  properties the shield design depends on (200 acceptance, first-match-wins) are corroborated by
  both measurement and documentation, shrinking the failure mode's structural uncertainty to a
  single point of dev/prod parity
- Fixture-check follow-up: the read-back check additionally pins the shield's 2 rules + the
  catch-all's existence and **ordering** (shield before catch-all — the ordering invariant for
  loop safety). e2e pins 9 representative 301 paths + shield pass-through (`/invite` and
  `/invite.css` must not be 3xx)
- Residual (final): only mid-word typos (`/invte` etc.) = the same class as any 404 path

**Choice (revised): BF-d + the 200-rewrite shield (66 rules)**.

## 7. Ruling BG: checking that the SPA bundle doesn't read the fragment (turning the last convention into a check — second-stage upward-compatible exploration)

The second-stage exploration requested by the owner (after BE and BF were implemented). The
target is the last remaining "convention-only" guarantee — the basis for the harmlessness of
mid-word typos (`/invte` etc.) falling into the SPA shell, "the SPA has no code reading
`location.hash`", rests on visual inspection.

### Round 1

- **Option BG-a: status quo (visual inspection + design fact)** — funstack-router is
  Navigation-API-based and doesn't use the hash, but there's no mechanism to stop future drift
  (a feature addition sneaking in fragment reads)
- **Option BG-b: Proxy-ify `location` in e2e and detect hash reads at runtime** — rejected:
  checks only the code paths e2e exercised (partial coverage). Inferior to a static total check
- **Option BG-c: literal check on all built JS + index.html** — measured: the current bundle
  (5 JS + inline bootstrap) has **zero** `.hash` member accesses, destructuring `{hash}`,
  `["hash"]`, and bare `hash` identifiers (`location` itself appears at 27 places — pathname /
  href family only). A blanket ban on the word `hash` can be applied with zero false positives

### Round 2 (upward-compatible exploration — probing the check-strength ceiling by measurement)

- **Can `location.href.split("#")`-type circumvention also be closed**: tried a blanket ban on
  bare `#` string literals → **rejected on false positives** (legitimate uses exist: Astryx's
  color parser `startsWith(\`#\`)`, Intl numeric-pattern `#` tests). Also tried narrowing to
  extraction idioms only (`split|indexOf|lastIndexOf` + `#` literal) → **rejected on false
  positives too** (the RSC runtime splits module references `"path#export"` via
  `lastIndexOf(\`#\`)` + `slice` — a legitimate use unrelated to location). Literal checks on the
  `#` family are fundamentally indistinguishable from legitimate uses
- Settled form: **only a blanket ban on the word `hash` (case-insensitive)**. Natural code
  intending to read the fragment writes `location.hash` — covers every literal form of drift.
  Explicitly noted out of scope: manual `href` parsing and obfuscation (`charCodeAt(35)` etc.)
  (the target is drift; malicious code insertion is the domain of review / supply chain)

### Round 3 (re-check)

- Sustainability: funstack-router has no hash routing, and anchor links (`#section`) need no JS,
  so legitimate `hash` usage is unlikely to appear. If it does, the check fails and forces an
  explicit ruling — the same "deliberately breaks on upstream change" type as the existing
  "exactly 1 inline script" check
- Check targets are `dist/public/index.html` + `dist/public/assets/*.js` (the entirety of
  delivered executable code. RSC payload .txt files are data and excluded)
- Effect summary: now "no literal that could read the invite token (fragment) exists anywhere in
  the delivered bytes" is checkable for all paths (including mid-word typos that slip the
  near-miss normalization), extending §15-3's "structurally sever drift toward the web acceptance
  screen" to the SPA bundle side

**Choice: option BG-c (blanket ban on the word `hash`; the `#` family rejected)**.

## 8. Ruling BH: making default-dependence explicit and copy fidelity (second-stage upward-compatible exploration, 2 small items)

### Explicit pin of html_handling

- `/invite` → `invite.html` resolution implicitly depended on wrangler
  `assets.html_handling`'s **default** (auto-trailing-slash) (if the default changed, `/invite`
  would fall into the SPA fallback — e2e would detect it, but the configuration was
  default-dependent). After schema confirmation, added an explicit pin to `wrangler.jsonc`
- **Measured rejection of an upward-compatible candidate**: tried the hypothesis that a shield
  rule of `/invite /invite.html 200` (direct rewrite to the real file) would eliminate the
  html_handling dependence itself → measured that **the rewrite target gets reprocessed by
  html_handling into an infinite loop of 307 → `/invite`** — rejected. The shield stays `/invite
  /invite 200` + the explicit pin is the correct answer

### Byte-equivalence check of copy fidelity

- Pinned "vite publicDir is an unconverted copy" (the premise of ruling BA round 3) in the build
  check as byte equivalence of `public/invite.{html,css}` ↔ `dist/public/invite.{html,css}`.
  Fastest detection if a future build plugin starts transforming HTML/CSS (guaranteeing the
  directness of "delivered bytes = the literal text reviewed")

**Choice: explicit pin + byte-equivalence check (the direct-rewrite option rejected by
measurement)**.

## 9. Implementation record

- `apps/web/public/invite.html` + `invite.css` — independent static assets outside the SPA
  (BA-b, BB-b). Copy is English (ADR-0017), brand notation lowercase maruhi. `noindex` (don't
  index the invite landing page). Meta CSP embedded (BE-c)
- `apps/web/scripts/write-headers.ts` — /invite checks (BD-a + BE's meta check) + per-path CSP
  (BC-b) + `_redirects` generation / read-back check (BF-d) + bundle word `hash` check + copy
  fidelity check (BG, BH). The existing `/*` CSP / headers are string-unchanged
- `apps/web/test/e2e.test.ts` — 3 /invite tests added (BD-b): per-path CSP effectiveness,
  near-miss normalization (BF's 7 representative paths), real-rendering script-zero + style
  applied + violation-zero + meta CSP presence
- `apps/web/src/pages/HomePage.tsx` — minimal S1 cleanup (tagline + CLI onboarding path. e2e's
  mechanism-verification hooks retained. Full polish is W2 onward)
- Out-of-scope confirmations: no changes to server / api-schema / CLI / packages/crypto. No
  spec or ADR wording changes (implementation only)
