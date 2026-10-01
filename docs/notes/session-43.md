# Session 43: W2 — implementation rulings for the read dashboard (S3–S7) (BM onward)

Date: 2026-08-29. Purpose: recording the implementation-level rulings of PR-W2
(web-dashboard-design.md §7). Norms = ADR-0018 (revisions 1 · 2) ·
web-dashboard-design.md (§4 display discipline · §5 visibility matrix) · AUTH_SPEC
§5 / §11-4 / §11-5 · AUDIT_SPEC §6 / §7. What this document rules is only the
concretization that the specs and design document delegated to implementation
(serving topology, SPA routing, error branching, visibility UX, coexistence with
checks). Each ruling follows "multiple candidates → superior-alternative search →
3-round comparison → autonomous selection" (session-27 §14's format. Codes continue
from session-41's BH / session-42's BL: BM onward).

Prerequisite materials: web-dashboard-design.md in full, ADR-0018 revisions 1 · 2,
ADR-0013, ADR-0017, AUTH_SPEC §3 / §5 / §11-4 / §11-5, AUDIT_SPEC §6 / §7,
session-39 (AM–AT · §10), session-41 (BA–BH), session-42 (BI–BL), apps/web
(W1 current state), apps/server/wrangler.jsonc.

## 1. Ruling BM: the serving topology of web and server (how same-origin is established)

Confirming the constraints (all are implemented APIs / defenses; this PR cannot
change their behavior):

- The session cookie is `__Host-maruhi_session` (AUTH_SPEC §5) — `__Host-` is bound
  per host and is not sent from a different origin's Web. SameSite=Lax also blocks
  cookie attachment to cross-site XHR/fetch
- The OAuth callback 302s to `${origin}/` (handlers-auth.ts — origin derives from
  the server's own request URL). The landing point after login completion is the
  server's origin
- The existing CSP is `connect-src 'self'` (write-headers.ts). Fetching a different-
  origin API requires a CSP extension (= adding an exception surface)

In other words, "the dashboard and the API on the same origin" is required
independently by all 3 points.

### Round 1

- **Option BM-a: keep separate origins, switch to CORS + SameSite=None** — dismissed:
  changing the server's cookie attributes / CORS headers = changing API behavior
  (this PR's prohibition). It also removes the SameSite=Lax first CSRF layer
  ourselves — a defensive regression
- **Option BM-b: add a proxy script to the web Worker and relay the API** —
  dismissed: the current web is plain static serving (zero Worker code), and adding
  executable code to the serving surface runs against ADR-0018's "minimize the
  operator's serving surface" (the same dismissal reason as session-41 BF-c). It
  would also route auth requests through 2 Workers
- **Option BM-c: compose the 2 Workers into one origin via zone routing on a custom
  domain** (`example.com/auth/*` → maruhi-server, the rest → maruhi-web) — dismissed:
  routes presuppose a zone (a custom domain) and cannot hold for the self-host
  default URL = workers.dev (apps/server/wrangler.jsonc's `workers_dev: true` /
  SELF_HOSTING.md). A form that does not work on the default deploy cannot be
  adopted
- **Option BM-d: bundle the web build output into the maruhi-server Worker as
  Workers Static Assets (a single Worker)** — only wrangler.jsonc's `assets` setting
  (API implementation and endpoints unchanged). Satisfies all 3 constraints —
  session, CSP, callback — through configuration alone

### Round 2 (superior-alternative search)

- BM-d's detailed form: `assets.directory = ../web/dist/public` (bundles the web
  build output + write-headers.ts's generated `_headers` / `_redirects` as-is).
  `run_worker_first` enumerates the API's path space (`/auth/*` · `/projects` ·
  `/projects/*` — every api-schema endpoint falls under these two prefixes); API
  requests always go to the Worker (HttpApi), everything else to the asset layer
  (SPA fallback included). `html_handling` keeps W1's explicit pin (session-41
  ruling BH)
- Consistency with "one-shot `wrangler deploy`" (the CLAUDE.md self-host principle):
  the single-Worker form is actually more one-shot than the 2-Worker form (deploying
  web separately). The deploy script (apps/server) prepends the web build (`bun run
  db:migrate && web build && wrangler deploy`). SELF_HOSTING.md's steps do not grow
- Handling apps/web/wrangler.jsonc (maruhi-web): **kept as the static-serving
  verification harness** (e2e keeps running against this Worker's wrangler dev as
  before. The asset layer's behavior — `_headers` detachment, `_redirects`
  first-match — is the same asset-worker implementation, so the verification
  target's meaning does not change). It is not used as the hosted serving surface
  (the dashboard cannot stand without the API)

### Round 3 (re-inspection)

- Impact on W1's invariants: `/invite`'s per-path CSP, `_redirects` normalization,
  and meta CSP ride onto the server Worker along with the served bytes
  (dist/public). `run_worker_first` only covers the `/auth` and `/projects`
  prefixes and never touches `/invite`. Every existing check (write-headers.ts) is
  non-regressing
- Coexistence of SPA fallback and the API: inside the `run_worker_first`
  enumeration it is always the Worker (the API's 404 semantics — §11-2's existence
  concealment — are not eroded by the asset layer). Unknown paths outside the
  enumeration get the same SPA fallback as the previous web Worker
- Impact on server tests (vitest-pool-workers): because they read wrangler.jsonc,
  the assets directory must physically exist. The test config absorbs this by
  creating `dist/public` (empty) (an empty directory = zero asset matches = every
  request goes to the Worker as before. The API tests' meaning is unchanged) —
  confirmed by measurement
- A new failure mode: a deploy that forgets the web build serves stale assets
  (updates are missed independently of the API). Prepending the build to the deploy
  script closes the systematic source. A deploy without assets fails on wrangler's
  missing-directory check (there is no shape where it silently becomes API-only)

**Choice: option BM-d (single Worker — maruhi-server bundles and serves the web
assets)**.

## 2. Ruling BN: coexisting with the bundle-wide `hash` word ban check (session-41 BG)

Consuming the response fields of S5 (chain fetch) and S6 (audit) (`headHashHex` ·
`prevHashHex` · `chainHeadHashHex` etc.) appeared to break BG's check (the
`/\bhash\b/i` total ban) — that was this ruling's starting point.

### Round 1

- **Measurement**: `\bhash\b` has **word boundaries** and does not match compound
  identifiers like `headHashHex` / `auditHeadHashHex` / `prevMetaSigHashHex`
  (`d`↔`H` and `h`↔`H` are both word characters, so no boundary forms). It matches
  only the bare word `hash` (identifiers, strings, standalone occurrences in UI
  copy)
- **Option BN-a: relax the check (an allowlist of field names)** — dismissed: the
  measurement above shows no relaxation is needed. An allowlist would weaken the
  "never read the fragment" guarantee against future drift (the direction BG
  explicitly avoided)
- **Option BN-b: leave the check unchanged and avoid the bare word by web-side
  convention** — API fields are already compound names that do not match, and the
  implementation never needs to write a bare `hash` (variable names carry
  `headHashHex` as-is; UI copy can express it with "chain head" / "digest"-family
  words)

### Round 2 (superior-alternative search)

- Whether UI copy (English — ADR-0017) ever needs to name "hash": S5's head display
  gets by with "Chain head" + seq + the hex value, and S6's cross-check guidance
  with "verify with `maruhi audit verify`". Since the hex value itself carries the
  label's meaning, not a single piece of copy needs the bare word `hash` (the build
  check will attest this after implementation)
- The possibility that a chunk of a newly imported Astryx component brings in the
  word `hash`: this is exactly BG's designed-for "breaks deliberately on an
  upstream change" shape — if it breaks, that moment's ruling is enforced (no
  anticipatory relaxation)

### Round 3 (re-inspection)

- The check's target is all JS + index.html under `dist/public` (unchanged from
  BG). This ruling's acceptance condition is confirming 0 matches on the build
  after the dashboard is implemented
- Re-confirming the effect: "no byte sequence anywhere in the served artifact can
  read an invitation token (the fragment)" remains checkable on every path even
  after W2's bundle growth

**Choice: option BN-b (the check unchanged; the implementation convention brings
in no bare `hash` word)**. Zero weakening of the guarantee (BG's "when it breaks, a
ruling is forced" shape is also preserved).

## 3. Ruling BO: SPA routing and `not_found_handling` (session-41 BF's handoff)

### Round 1

- **Option BO-a: keep `not_found_handling` as SPA, and implement the dashboard as
  client routes under the `/dashboard` prefix** — deep links
  (`/dashboard/projects/:id`) work via the SPA fallback. The API's path space
  (`/auth` · `/projects` prefixes) and the SPA's route space are **plainly
  separated**
- **Option BO-b: emit per-route static HTML (abolish `not_found_handling`)** —
  dismissed: funstack-static does not emit per-route static HTML (the same
  confirmation as session-41 BF-b), and dynamic paths (`:projectId`) cannot be
  enumerated. Going multi-entry only adds build complexity
- **Option BO-c: place the dashboard's routes under `/projects/...` too** —
  dismissed: collides with BM's `run_worker_first` enumeration, and direct
  navigation to a deep link would land on the API's JSON (401/404). Overlaying the
  UI's path space onto the API's path space is also a direction that mixes
  existence-concealment (§11-2) response semantics into UI navigation

### Round 2 (superior-alternative search)

- The route set: `/dashboard` (S3 login / S4 listing — switched by auth state),
  `/dashboard/account` (S6 self axis = `/auth/audit/events`),
  `/dashboard/projects/:projectId` (S5 / S6 project axis / S7 — tabs). Tabs are not
  made routes (there is no necessity to put them in the URL, and keeping the route
  surface minimal keeps the near-miss class minimal)
- Confirmed that funstack-router's partial route definitions (`route()` in a shared
  module, bound server-side via `bindRoute()`) make typed `:projectId` capture
  (`useRouteParams`) work

### Round 3 (re-inspection)

- BF's target (near-miss normalization) is only `/invite` — unchanged. Typos under
  `/dashboard` are the same class as any 404 path (the SPA shell. BG's check
  guarantees fragments are never read), so no normalization rule is added
- Deep-linking while unauthenticated also yields the SPA shell, and each screen's
  401 branch (BP) presents the login path — no screen depends on
  `not_found_handling` semantics

**Choice: option BO-a (keep the SPA fallback; `/dashboard`-prefixed routes)**.

## 4. Ruling BP: branching and wording for not-logged-in / session-expired (401) / capability-restricted (403)

### Round 1

- **Option BP-a: per-screen individual handling** — dismissed: the 401/403/404
  branching is common to all screens, and individual handling creates wording drift
  (a surface for display-discipline §4 violations to creep in)
- **Option BP-b: a thin fetch layer maps HTTP status into a typed result,
  centralizing the branching** — the classification: `ok(T)` / `unauthorized` (401)
  / `forbidden` (403 — carries the reason) / `notFound` (404) / `error` (other +
  network). The UI looks only at this type

### Round 2 (superior-alternative search — wording. All English = ADR-0017)

- **401 (no logged-out vs expired distinction)**: the server returns no
  distinction, so the UI does not fabricate one. Directly under `/dashboard` = the
  S3 login card ("Sign in with GitHub"). A 401 on an in-screen refetch (the
  typical expiry case) = swap in the same login card + "Your session has ended.
  Sign in again to continue."
- **403 `session-not-allowed`**: every API this PR consumes is inside
  `SESSION_ALLOWED_ENDPOINTS`, so it does not occur in the normal course (occurring
  = an anomaly like an old/new mismatch). The generic wording "This action is not
  available to browser sessions. Use the maruhi CLI." guides to the CLI (not hidden
  — making fail-closed visible)
- **Other 403s (`insufficient-role` etc. — below-admin on S6 invites is a normal
  case)**: "Not available to your role in this project, as reported by the
  server." No hint at what is hidden (count, kind) is carried (AUDIT_SPEC §7)
- **404 (§11-2's existence concealment)**: "The server reports no such project for
  your account." — rendered without the UI distinguishing what the response cannot
  distinguish ("does not exist" vs "not a member")
- **Network / 5xx**: "Could not reach the server." + a retry button

### Round 3 (re-inspection)

- CSRF: the only write is logout (POST `/auth/logout`). The fetch layer attaches
  `x-maruhi-csrf: 1` uniformly to mutations (§11-4)
- When the 401 branch presents the login screen, returning to the original URL is
  not guaranteed (the callback is fixed at `${origin}/` — BM's constraint).
  Post-login re-navigation is served well enough by S1/S4's static links (carrying
  a return state somewhere would only grow storage surfaces)
- Consistency with the display discipline: error wording is also unified in the
  "server-declared" phrasing and contains no client-side guesses (assertions like
  expired / revoked / not a member)

**Choice: option BP-b + the above wording**.

## 5. Ruling BQ: the S6 audit viewer's visibility-class display UX (design document §8 handoff)

### Round 1

- **Option BQ-a: class-selection UI (class 1 / class 2 switching, advanced
  filters)** — dismissed: classes are the server authorization's internal
  structure, and the very act of showing the word "class 2" on a below-admin screen
  is the UI hinting at the invisible set's existence (counter to the spirit of
  count non-leakage). Advanced cross-search is the CLI's (`maruhi audit`)
  territory, and W2's demand is unmeasured
- **Option BQ-b: a single chronological list + a role-adaptive heading** —
  below-admin: "Events visible to your role" (AUDIT_SPEC §7 / design document
  §4-4's prescribed wording). Only for admins (when the response carries `seq`) is
  the seq column shown. No filter is placed — only "Load more" on the `before`
  cursor

### Round 2 (superior-alternative search)

- The seq column's switching is done not by "prejudging the role" but by "**whether
  the response has seq**": a form where the client guesses the role and switches
  would go beyond the §5 matrix's "the table is a UI split, not a defense" and
  become a duplication of the judgment logic. With response-adaptation, server
  authorization remains the single decision point
- The invites tab (the admin axis): a 403 is displayed with BQ/BP's role wording,
  and the tab itself is not hidden (hiding it would make the UI prejudge "whether
  I have invites audit". The display is unified under BP's "as reported by the
  server" wording)
- Excluding completeness claims: no gap checks or cross-checks are shown, and the
  footer carries only the static guidance "Integrity checks are the CLI's job:
  `maruhi audit verify`" (design document §3 S6's provision)

### Round 3 (re-inspection)

- The self axis (`/auth/audit/events`) uses the same list component (seq is always
  absent on the D1 path — AUDIT_SPEC §7 — so the seq column naturally does not
  appear)
- The event row's displayed fields: the event name · serverTs · actor (userId +
  FP) · target · environment/variable ID · payload (JSON folded). All are as
  recorded = server-declared raw values. Display-name resolution (via verified
  statements) is not done — name resolution on a Web with no verification would be
  trusting a name without statement verification (contrary to §12-2's "do not
  trust a name that did not pass verification"), so identifier-only display is the
  display-discipline-correct answer

**Choice: option BQ-b (a single list + the response-adaptive seq column +
prescribed wording + no filter)**.

## 6. Ruling BR: the implementation form of API consumption (types · the client layer)

### Round 1

- **Option BR-a: Effect HttpApiClient (the derived client from api-schema)** —
  dismissed: the Effect runtime + the whole Schema decoder set would enter the Web
  bundle (= the TCB). It runs against CLAUDE.md's "keep the frontend supply chain
  small" and ADR-0018 decision 1's bundle-check simplicity. Unlike the CLI, the
  Web's consumption surface is a GET-centric 9 faces, where derivation gains little
- **Option BR-b: plain `fetch` + hand-written types** — dismissed: type divergence
  from api-schema would not be detected at compile time (a drift risk across wide
  structures like audit responses)
- **Option BR-c: plain `fetch` + type-only imports from api-schema** — with
  `import type` (erasable) only, zero runtime code enters the bundle, and the types
  are bound to a single definition (`typeof XSchema.Type`). Only adds
  `@maruhi/api-schema` (workspace) to web's devDependencies

### Round 2 (superior-alternative search)

- The residual of carrying no runtime verification (Schema decode): these are
  display-only, value-less reads, and a shape breakage can only become a display
  breakage (authorization and concealment are server-side). Applicative client-side
  defense (optional chains) suffices. Rather, "not packing Schema verification into
  the Web bundle" stands on the same side as the display discipline (verification
  is not implemented)
- Enforcing type-only thoroughness: use `import type` only, guaranteed by oxlint /
  tsc (`verbatimModuleSyntax`-equivalent configuration where present). Bundle
  contamination would also be caught secondarily by the BG check (api-schema's
  runtime code contains the word `hash`)

### Round 3 (re-inspection)

- The fetch layer uses `credentials: "same-origin"` (default) + the CSRF header on
  mutations (BP) + `accept: application/json`. The API base URL is relative
  (same-origin — guaranteed by BM's construction)
- Pagination consumption (`nextAfter` / `before`) is also not placed in this layer
  but held in screen state (the layer stays stateless)

**Choice: option BR-c (plain fetch + type-only imports)**.

## 7. Ruling BS: the form of e2e's authenticated-screen tests (mocks / fixtures)

### Round 1

- **Option BS-a: e2e joined with a real server (vitest-pool-workers' SELF)** —
  dismissed: web e2e is wrangler dev (static serving) + the existing Playwright
  harness (session-41 BD); bringing the server's D1/DO startup and an OAuth fake
  into it would bloat the test from serving verification into integration
  verification. GitHub OAuth cannot be e2e'd as a real flow in the first place
- **Option BS-b: intercept the same-origin API paths with Playwright's `page.route`
  and return fixture JSON** — serving, rendering, and CSP stay real (wrangler dev +
  a real browser); only the API responses are swapped. The fixtures are literals
  conforming to api-schema's types (tsc binds them by type)

### Round 2 (superior-alternative search)

- Relationship with CSP: `page.route` swaps at the network layer, and the request
  destination seen from the page stays same-origin — it does not weaken the
  `connect-src 'self'` verification (the zero-violation assertion can be kept on
  every dashboard screen)
- The branches covered: not logged in (401 → S3), logged in (S4 listing + the
  presence/absence of the paging button), the project screen (S5 chain/environment,
  S6 audit + role wording, S7 flags + the dismiss static guidance), 403 (the
  below-admin wording on invites). Logout's CSRF-header attachment on the POST is
  verified inside the route handler

### Round 3 (re-inspection)

- The mock-drift risk: a surface remains where fixtures diverge from real server
  responses (e2e verifies rendering and gating; the wire-compat source of truth is
  api-schema's types + the server-side tests). Typed fixtures let compilation catch
  most divergence
- The existing e2e (CSP · /invite · SPA navigation) is left unchanged and passing —
  non-regression guaranteed

**Choice: option BS-b (page.route + typed fixtures)**.

## 8. Implementation record

- **Serving configuration (BM)**: `apps/server/wrangler.jsonc` gains `assets`
  (`../web/dist/public` · `run_worker_first: ["/auth/*", "/projects",
  "/projects/*"]` · the SPA fallback · the explicit html_handling pin).
  `apps/server/package.json`'s deploy / deploy:dry-run prepend the web build.
  Server tests (vitest-pool-workers) were measured to all pass even without the
  assets directory (504 — the pool does not require the assets setting)
- **Screens**: `apps/web/src/dashboard/` — `api.ts` (the fetch layer = BP/BR) ·
  `types.ts` (type-only imports = BR) · `routes.ts` (the `/dashboard` prefix = BO)
  · `shared.tsx` (unified failure-display wording = BP) · `chain-view.ts` (S5's
  display folding — no verification) · `DashboardScreen.tsx` (S3 + S4) ·
  `ProjectScreen.tsx` (S5 + S6 + S7) · `AccountAuditScreen.tsx` (S6 self axis) ·
  `AuditEventList.tsx` (BQ). Bound into `App.tsx` via bindRoute; a dashboard entry
  point was added to S1
- **Following the complexity discipline**: fallow's changed-files audit (the CRAP
  threshold) detected 14 new functions → all resolved by decomposition (op-handler
  tables, guard separation, subcomponentization). Since every high-complexity
  function in the repository was this PR's (14 out of 110k LOC), "function
  cyclomatic ≤ 4" was judged the de-facto discipline, and no suppression comments
  or baseline additions were used
- **Tests**: 4 new e2e (BS — page.route + typed fixtures. S3's 401 branch · S4
  paging + CSRF-bearing logout · S5–S7 tabs + the invites-403 wording + the seq
  response-adaptation · the self axis's seq non-display) + a new web unit-test
  setup (`vitest.unit.config.ts` = the root vitest integration, `test/unit/` —
  chain-view's folding, the api layer's classification and CSRF header). The
  existing 7 pass unchanged
- **BG check measured (BN)**: even on the grown bundle containing Astryx Table /
  TabList / SegmentedControl etc., the word `hash` stays at 0 hits = the check
  passes unchanged
- Out-of-scope confirmation: no changes to server implementation, api-schema, the
  CLI, or packages/crypto (server changes are only the serving configuration in
  wrangler.jsonc / package.json). No spec wording changes (only follow-ups in
  design document §3 S4 · §7 · §8)

## 9. Post-implementation re-inspection (one round of re-searching superior alternatives — task step 7)

- **BM re-inspection**: reconsidered and re-rejected `run_worker_first: true` +
  in-Worker asset-binding fetches (controlling serving in code) — it is the
  direction of adding executable code to the serving surface (same reason as BF-c /
  BM-b), and `_headers` / `_redirects`' asset-layer semantics would have to be
  re-implemented by hand. The declaration-only BM-d remains the superior
  alternative
- **Defect fix (BM — found by measurement)**: the first enumeration of
  `run_worker_first` (`/auth/*` · `/projects` · `/projects/*`) **missed `POST
  /invites/accept` (§15-2 — the CLI's invitation acceptance)**. Found by
  cross-checking against api-schema's complete endpoint catalog and confirmed by
  measurement — since it fell outside the enumeration, the request went to the
  asset layer, where `_redirects`' lowercase catch-all `/invite*` (session-41 BF)
  **swallows it, POST included, with 301 → `/invite`** (breaking the acceptance
  API). Resolved by adding `/invites` · `/invites/*` to the enumeration (measured:
  POST /invites/accept = Worker 401, `/invite` static 200 · `/Invite` 301
  unchanged). The lesson is the same shape as session-39 §10-1 — an enumeration
  that "should be covered by the prefixes" is mechanically cross-checked against
  the complete endpoint catalog
- **Incidental observation (BM)**: Worker responses via run_worker_first also get
  STS and nosniff from `_headers`' `/*` (measured). Adding security headers to API
  responses is additive; endpoint behavior and contracts are unchanged
- **BM measurement (wrangler dev — the combined configuration)**: `/` and
  `/dashboard` = SPA shell 200, `/auth/config` = Worker (503 SetupIncomplete — the
  correct response of an unconfigured server), `/projects` = Worker 401, `/invite`
  = the static page + per-path CSP `script-src 'none'`, `/Invite` = 301 →
  `/invite`, `/`'s CSP = the bootstrap-hash permission. Measured-confirmation that
  all of W1's invariants and the API path separation also hold in the combined
  form
- **Residual (BM)**: because pool-workers ignores the assets setting, the combined
  form's serving behavior (run_worker_first's actual effect) is outside CI's
  automated tests (the measurement above was a local wrangler dev). `deploy:dry-run`
  carries the configuration-validity check, and effect confirmation is placed on
  checking real responses after the first deploy (the same zero-load recommendation
  as W1's BC/BE recommendations)
- **BN re-inspection**: backed by measurement (§8). No need for relaxation or
  refinement arose
- **BP strengthening (adopted)**: added a sign-in path (Go to sign-in →
  `/dashboard`) to the in-screen 401 banner (session expired) — a form with wording
  but no path dead-ended users on expiry
- **Reconsidering the post-login landing (rejected)**: the OAuth callback is fixed
  at `${origin}/` (S1) (API behavior — unchanged in this PR). The option of having
  S1 automatically query `/auth/me` and auto-transition to the dashboard is
  rejected — it would bring an API call into P1's (unauthenticated visitor's)
  static landing and also rob the path of someone signed in who wants to see S1.
  S1's static link (open the dashboard) suffices
- **Reconsidering S5's FP column (rejected)**: adding a key-FP column to the
  member table is not placed — an add_member entry does not carry the target's FP
  (only the public key), and computing the FP client-side would be a crypto
  derivation (a half-step into bundling verification code). FPs are limited to the
  displays of chain heads, audit rows, and grant_server (whose entries carry the
  FP) — consistent with display-discipline §4's "an FP is a reference value"
- **Review follow-up (PR #107 Bugbot — both fixed as legitimate bugs)**:
  (1) **stale-fetch race** — `useApiResource` / `AuditEventList` could let a
  late-arriving in-flight response overwrite newer screen state (projectId ·
  audit-axis switching). Fixed to discard stale responses via an effect-cleanup
  stale mark / a generation counter. (2) **empty page + nextAfter end
  misjudgment (S4)** — §11-5's candidate pages can become `{ projects: [],
  nextAfter }` via ghost exclusion and confirmation-failure omission, but the
  first-version UI misjudged 0 rows = the end and hid the remaining memberships.
  Fixed to auto-follow the cursor until rows grow or nextAfter runs out (depth is
  bounded by the number of candidate pages — total-loss cost is on par with the
  CLI's full-page enumeration). An e2e covering paging across an empty page was
  added
- **Review follow-up (PR #107 pullfrog)**: (1) **making the run_worker_first
  coverage sweep checkable** — responding to the point that the enumeration is a
  hand-written copy of the api-schema path space whose drift is silent (navigation
  requests get swallowed by the SPA shell 200), a sweep test of the same shape as
  session-capability.ts was added (apps/server/test/serving-topology.test.ts —
  coverage of every registered endpoint + a regression guard for `/invite` being
  uncovered. wrangler.jsonc's real values are injected by vitest.config.ts via
  unstable_readConfig). Promotes §9's defect fix from a one-time cross-check to a
  permanent fail-loud. (2) **Added deploy:dry-run to CI** (step 8b — a
  credential-free configuration-validity check), moving the combined
  configuration's config verification from a human ceremony to CI (the actual
  serving behavior remains outside automated tests — residual). (3) **Asserting
  CSP-header presence** — a zero-violation check passes even with the header
  missing (it is vacuous), so the e2e directly pins header presence on the 3
  /dashboard-family paths. (4) **Prototype-chain-lookup self-defense** —
  `ENTRY_FOLDERS[entry.op]` / `ROLE_TOKEN_COLOR[role]` could hit prototype-chain
  values under a hostile server's op/role (`__proto__` etc.) (the consequence is
  only rendering breakage) — Object.hasOwn guards + a regression unit test.
  (5) Moved RoleToken into shared.tsx (the placement point). The stale-fetch
  finding had already been fixed in the Bugbot handling (40bd7b1) (pullfrog was
  reviewing an old commit). (6) The incremental review's passing note (infinite
  following under a broken or hostile server returning a non-advancing nextAfter)
  was also closed with the one condition "cursor not advancing = treated as the
  end" (uniformizing the server-distrust posture). **The scope question about the
  post-sign-in landing (`${origin}/`)** is accepted for W2 per this ruling (BP
  round 3) — adding a return path to the callback is an API-behavior change and is
  sent to a separate PR (an AUTH_SPEC §3 revision) when demand appears
- **Reconsidering S6's page-end determination (kept)**: "a page shorter than limit
  is the end" would add a dependency on the server's default limit (50), so the
  current "an empty page is the end" form is kept (one extra fetch in exchange for
  no assumption about the response shape)

## 10. Second-round superior-alternative search (owner request — 2026-08-29)

One additional round per the owner's request to "search for new options that could
be silver bullets or superior alternatives". The targets were the points **recorded
as residuals** through §9 (= the weakest parts of the current rulings). 3 were
adopted; 4 were considered and dismissed.

### Ruling BT: moving e2e's serving side to the combined configuration (the actually-deployed configuration) (adopted)

- **Target**: BM's largest residual — "the combined form's serving behavior
  (run_worker_first's actual effect, the SPA fallback, per-path headers) is outside
  CI's automated tests". pullfrog's approved review had also named it "the
  residual". The e2e ran against apps/web/wrangler.jsonc (a static-only harness
  that is **not deployed**), so the verification target and the served artifact
  were different things
- **Finding**: because the dashboard e2e mocks the API via page.route (ruling BS),
  **the API needs no preparation whichever Worker serves**. So if e2e's wrangler
  dev launches on apps/server (the production configuration bundling assets), every
  existing assertion (/invite's per-path CSP, the near-miss 301, the SPA fallback,
  the CSP header) becomes **a check of the deployed configuration** as-is — the
  change is one spawn cwd + added assertions only
- **Additional gain**: an unconfigured local server's bare responses (503 / 401
  JSON) serve as evidence that "the Worker was reached", so a **regression test for
  reaching API paths** can live in e2e — a test reproducing §9's measured defect
  (`POST /invites/accept` swallowed by `_redirects`' catch-all with a 301) is
  pinned (it becomes two layers: the sweep test's static check + real serving's
  dynamic check)
- **Confirming a concern that was not dismissed**: wrangler dev (server)
  auto-creates D1 / DO locally and starts without an OAuth secret (confirmed across
  §9's 4 BM measurements). D1 migrations and secrets are unneeded on the mocked-e2e
  path
- apps/web/wrangler.jsonc stays as the preview harness (e2e's source of truth moves
  to the server configuration under this ruling — matching the verification target
  to the served artifact is the body of the superior alternative)

### Ruling BU: returning to /dashboard after sign-in (adopted — resolving BP's residual)

- **Target**: BP round 3's accepted residual — "the callback is fixed at
  `${origin}/`, so sign-in lands on the landing page and needs one more click"
- **Adopted form**: clicking Sign in places a **one-shot marker** in
  sessionStorage, and only when S1 **consumes** the marker does it check `/auth/me`
  once and return to /dashboard (`resume.ts` + an invisible client island on S1).
  S1 without a marker (a P1 visitor) keeps making zero API calls — avoiding BP
  round 3's rejected "always query /auth/me on S1" while removing only the extra
  hop. When the session was not established (OAuth aborted), only the marker is
  consumed and the landing stays. When storage is unavailable (private mode etc.)
  it degrades to the typed "no marker" case
- **Rejected options**: (a) changing the callback's redirect target to /dashboard —
  an API-behavior change, which this PR prohibits (if demand remains, it is handed
  off to a separate PR as an AUTH_SPEC §3 revision. Adopting this ruling mostly
  erases that demand itself). (b) detecting the GitHub return via
  document.referrer — the received referrer depends on GitHub's Referrer-Policy and
  is non-deterministic. (c) returning via `_redirects` — the static layer cannot
  know session state and would break P1's landing

### Ruling BV: real Schema verification of e2e fixtures (adopted — shrinking BS's residual)

- **Target**: BS round 3's residual — "a surface remains where fixtures diverge
  from real server responses (typing catches most at compile time)". Type
  conformance does not see runtime constraints like hex length or patterns, so the
  fixtures' coordinate values (row_id length, projectId format) were only
  eyeballed
- **Adopted form**: add an e2e test that `decodeUnknownSync`s every fixture through
  api-schema's real Schemas. The Schema runtime code runs **inside the test process
  only** (not bundled — consistent with ruling BR's "no Schema in the Web bundle".
  The pin `effect@4.0.0-rc.111` already in effect is explicitly added to web's
  devDependencies — zero supply-chain increment)
- This makes "mock-to-wire-contract drift" mechanically checked in two layers:
  compile-time (types) + runtime (Schema). The remaining residual is only the
  "the server implementation returns a narrower response than the Schema" class
  (that is the server-side tests' territory)

### Considered and rejected (round 2)

- **Using a compat flag (`assets_navigation_has_no_effect`) to disable navigation
  absorption itself, eliminating the need for run_worker_first** — dismissed: API
  reachability would come to depend on Sec-Fetch-Mode semantics, a longer chain of
  inference than explicit enumeration + a sweep (checkable, fail-loud). It would
  also be exposed to future flag changes
- **Deleting apps/web/wrangler.jsonc** (resolving the harness duplication) —
  dismissed: `bun run preview` (a lightweight static-only preview) still has value.
  With e2e's source of truth moved to the server configuration (BT), the harm of
  "mistaking the verification target" is already gone
- **Return via referrer / callback changes** (recorded above as BU's rejected
  options)
- **Auto-generating fixtures (from Schema Arbitrary)** — dismissed: the screens'
  assertions are bound to concrete values (names, IDs); generated values make the
  verification non-deterministic. Real verification (BV) yields the same drift
  detection more simply

## 11. Third-round superior-alternative search (owner request — 2026-08-29)

A round targeting points still left at **manual verification or convention level**
after round 2 (§10). 2 adopted, 4 considered and dismissed.

### Ruling BW: a single catalog of the dashboard's consumption surface + a client-side sweep (adopted)

- **Target**: W2's core invariant — "every endpoint the screens call is inside
  `SESSION_ALLOWED_ENDPOINTS`" — was **manually verified** (pullfrog's first
  review also cross-checked it by hand). The path strings were also scattered
  hand-written across screens, and an api-schema rename or typo would stay silent
  until a runtime 404 / 403
- **Adopted form**: `src/dashboard/endpoints.ts` — all path builders + a catalog
  binding each builder to its api-schema (group, endpoint) identifier
  (`DASHBOARD_ENDPOINTS`). Screens fetch only through the builders. A unit test
  (test/unit/endpoints.test.ts) cross-checks the catalog against the registered
  HttpApi and pins (1) **path consistency** (builder-generated path = the
  template's sample substitution — unknown parameters are left unsubstituted and
  fail loud), (2) **session permission** (`isSessionAllowedEndpoint` — a new
  screen calling a non-enumerated API breaks not at runtime 403 but in the test),
  (3) no duplicate catalog entries
- **Effect**: paired with the serving-topology sweep (server-side — run_worker_first
  coverage), **both directions of consumption become mechanically checked around
  api-schema**. Along with it, the serving-topology side's negative-direction check
  was extended (`/invite` and the `/dashboard` family must not be swallowed by
  worker-first)
- The reverse direction ("does the dashboard consume every session-permitted read
  surface?") is not an invariant and is not imposed (recoveryStatus ·
  invites.list/revoke are permitted but outside W2's screens — W3b's territory)

### Ruling BX: making the wrangler configuration single-sourced — deleting apps/web/wrangler.jsonc (adopted)

- **Target**: apps/web/wrangler.jsonc, which §10 "kept for preview". After BT
  (e2e's move to combined), its sole consumer is the preview script, and only the
  **dual management of the configuration** (a drift surface) — the html_handling
  pin etc. — remained
- **Finding**: `wrangler dev --config ../server/wrangler.jsonc` works even with
  apps/web as cwd (path resolution is relative to the config file — measured: root
  200 / /projects 401 / /invite 200). Switching preview to it leaves
  apps/web/wrangler.jsonc with zero consumers → delete it
- **Effect**: the serving configuration converges to the single
  apps/server/wrangler.jsonc, and every path — deploy, e2e, preview — reads the
  same configuration. §10's keep decision had a premise (preview using the old
  configuration) that disappeared, so this ruling overrides it

### Considered and rejected (round 3)

- **`Cache-Control: immutable` on content-hashed assets** — dismissed: a
  performance improvement, not the resolution of a residual (security /
  correctness), and the cost of adding a checked surface (a new write-headers
  block) to an already-approved PR does not balance. An independent PR when demand
  appears
- **SRI (subresource integrity)** — dismissed: under all-assets self-served + strict
  CSP, SRI adds no guarantee (the server = verifier composition cannot be broken
  by SRI, as ADR-0018 Context states)
- **Strengthening the `/*` CSP's form-action 'self' → 'none'** — dismissed: the
  dashboard has no forms, and 'self' already confines it to the same origin — no
  threat is closed. Only the cost of breaking the `/*` CSP string's invariance
  fixed in W1 (a non-regression-check premise) remains
- **Exporting the return-marker key for sharing (resolving a duplicated literal
  with e2e)** — resolved (under the review follow-up below, the positive-side test
  stopped injecting the marker itself, so the duplicated literal remains only in 1
  negative test. A key-name drift would not change that test's expectation
  [staying on the landing], so it is harmless)
- **Review follow-up (pullfrog — BU's coverage finding)**: the first version's
  resume test injected the marker via addInitScript, so it would not break even if
  (1) the consume guard were removed and it regressed to "always /auth/me on S1",
  or (2) the Link stopped carrying onClick and the marker were never written. The
  positive test was replaced with a **real-navigation-driven** one (actually
  clicking /dashboard's login card → replacing the real navigation to
  /auth/github/start with a 302 → `/` → returning on the marker the
  implementation wrote), and a test was added that pins **zero API calls on a
  markerless landing** via request collection — both of BU's 2 invariants became
  fail-loud

## 12. Fourth-round superior-alternative search (owner request — 2026-08-29 · final round)

Request: "just one more time — search for further superior-alternative ideas". The
two sweeps introduced in round 3 (BW / serving-topology) themselves were included
in the candidate set, and a 3-round comparison targeted "check gaps" and "remaining
hand-written duplication".

### Ruling BY: completing the consumption-surface catalog (adopted)

BW's catalog had 3 check gaps left:

1. **The navigation consumption surface was outside the catalog** — the login
   card's `/auth/github/start` was a Link, not a fetch, so it never entered the
   catalog and had neither path-consistency nor session-surface classification
   checked. `apiPaths.githubStart()` was added, and an `access: "session" |
   "unauthenticated"` discriminator was introduced into the catalog. The sweep
   became access-aware: session surfaces go through `isSessionAllowedEndpoint` as
   before, and unauthenticated surfaces must belong to
   `UNAUTHENTICATED_ENDPOINTS` (AUTH_SPEC §5) (consuming an auth-required surface
   as a navigation path also breaks in the test)
2. **The triple duplication of cursor-query assembly** — projects' `?after=` and
   the two audit `?before=` were hand-written per screen. Unified into
   `withCursor(path, name, value)` (the single query-attachment point;
   encodeURIComponent included)
3. **Unchecked builder bypass** — the catalog's completeness depended on the
   discipline "screens fetch only through builders", yet that discipline itself
   was manual-verified. A source tripwire (scanning src/ for
   `["']/(auth|projects|invites)` excluding endpoints.ts) was added to the unit
   tests. Backtick strings are out of scope (they would collide with path
   examples inside comments) — positioned as the same "good-faith drift
   detection" as the word-hash tripwire (session-41 BG); preventing deliberate
   bypass is not the goal

### Ruling BZ: a non-intersection sweep of the SPA route space (adopted)

- **Target**: of BO's separation — "the SPA is `/dashboard`-prefixed; the API is
  `/auth` · `/projects` · `/invites`-prefixed" — the reverse direction, "no SPA
  route is swallowed by run_worker_first", was checked by a **hand-written path
  enumeration** (4 paths) inside serving-topology.test.ts. Forgetting to follow
  the enumeration when adding a route would silently narrow the check
- **Adopted form**: homeRoute / aboutRoute are moved into routes.ts, and a single
  catalog `SPA_ROUTES` of all routes is exported (App.tsx only binds them via
  bindRoute). A web-unit test (test/unit/spa-topology.test.ts) cross-checks the
  real route definitions against the real serving configuration (reading
  apps/server/wrangler.jsonc via `unstable_readConfig` — the same "read the real
  thing" posture as BT/BX), verifying that every SPA route's concretized path is
  covered by no run_worker_first rule. The rule semantics (exact match / prefix `*`
  only · everything else conservatively throws) are identical to the
  serving-topology side
- The serving-topology side's hand-written 4-path check **stays** (it verifies in
  the real workerd environment, and `/invite` is not an SPA route so it is outside
  BZ's catalog). The two are not duplication but complementary — "representative
  points on the server side, all-routes derivation on the client side"

### Considered and rejected (round 4)

- **Integrating fetching into loader hooks (data fetching via funstack-router's
  loader)** — dismissed: against the churn of wholesale-remaking the screens'
  useApiResource / manual paging, the only gain is earlier fetch timing. At a
  read-only dashboard's scale it is a lateral move, not a superior alternative
- **Branded types for parameters (branded types like ProjectId)** — dismissed: an
  option that would type-prevent builder-argument mix-ups, but W2's consumption
  surface has only 2 kinds (projectId / environmentId), and route-parameter-derived
  values are strings anyway. It only adds ceremony; there is no actual bug surface
- **Auto-generating run_worker_first from api-schema (code generation)** —
  dismissed: against the cost of bringing in a new mechanism (a generator +
  checking its output), the bidirectional sweep (coverage + non-intersection)
  already makes the same drift fail-loud. The configuration stays "plain readable
  JSONC", which is better for a self-hosted distribution

## 13. Fifth-round superior-alternative search (owner request — 2026-08-29)

Request: "they keep being found — that's a problem, so search once more for further
superior-alternative ideas". The search ran with the generation rule made explicit:
every round-3-to-4 finding came from "a place where a hand-written copy of a
machine-readable source of truth (api-schema / wrangler.jsonc / route definitions)
remained". So src/ in its entirety was mechanically grep-inventoried for
"hand-written copies", and the residual 2 were closed.

### Ruling CA: the SPA path builder (spaPaths) — BY's dual (adopted)

- **Target**: path literals for internal navigation were scattered across src/ in 9
  places (6 `/dashboard`-family + 3 `/` `/about`). Renaming a path in routes.ts
  would break links but stay **silent** — the SPA fallback returns the shell with a
  200 (the SPA side wholesale retained the same drift surface BY had closed on the
  API side)
- **Adopted form**: the path constants in routes.ts were made a single home, and
  route() definitions and the `spaPaths` builders (home / about / dashboard /
  account / project) read the same constants. Every screen href / navigateTo goes
  through the builders. `dashboard` was added to the tripwire's (ruling BY) prefix
  set, and its exclusions extended to the 2 builder homes (endpoints.ts ·
  routes.ts). The spa-topology test gained a builder ↔ SPA_ROUTES binding check
  (substitution completeness + every builder corresponds to a declared route)
- Because constants are shared inside a single module, a cross-check test like
  apiPaths ↔ api-schema is unnecessary in principle (the duplication itself does
  not exist) — a form stronger than BY

### Ruling CB: schema cross-checking the cursor query names (adopted)

- **Target**: the `after` / `before` attached by withCursor were hand-written
  strings, unbound from api-schema's query declarations (membership.list's `after`,
  the audit family's `before`). Renaming a parameter would break silently in the
  shape "paging keeps silently returning page 1", since the server ignores unknown
  queries
- **Adopted form**: the catalog gained `cursor?: "after" | "before"` (4 surfaces
  declare it). The sweep verifies that the registered endpoint's query Schema AST
  (`query.ast.propertySignatures`) declares a property of that name

### Considered and rejected (round 5)

- **Sharing ruleCovers (de-duplicating serving-topology / spa-topology)** —
  dismissed: the runtime environments differ (workerd / node), and sharing would
  need a new home (a test-support package etc.). The 15-line semantics sits
  alongside the consuming side in both places with conservative throw, so the
  mechanism cost of sharing is higher
- **Cross-checking RoleToken's color map against the role enumeration** —
  dismissed: api-schema has no closed role enumeration (it is chain-derived), and
  an unknown role degrades **visibly** to a neutral Token under the Object.hasOwn
  guard — not a silent breakage, so it does not meet the ruling's target criterion
  (silent drift)
- **Builder-izing e2e expectations** — dismissed: making a test's expected literal
  a builder output would become tautological (builder == builder) and lose
  checking power. The current two stages — the unit sweep binding builders ↔ the
  source of truth, e2e pinning rendering ↔ literals — is the correct form

### Convergence assessment

Every round-3-to-5 finding came from the single generation rule "look for
hand-written copies of machine-readable sources of truth". After CA/CB, zero
hand-written copies of paths, queries, or routes remain in src/ (confirmed by the
grep inventory), and the remaining literals are only (a) the definitions inside
the builder homes themselves, (b) test expectations (deliberate — the rejection
above). Findings from this rule are judged exhausted. The next superior
alternative, if any, would come from a different generation rule (e.g. when W3's
write family adds new sources of truth); on W2's read surface it is closed.

### Review follow-up (pullfrog — CB's call-site binding. 2026-08-29)

CB's first version cross-checked catalog ↔ api-schema but left **call sites ↔
catalog** as bare literals (`withCursor(path, "after", …)`), so passing `after` to
an audit surface still type-checked — a "silently repeating page 1" residual
remained (pullfrog's finding). Cursor names were raised to shared constants
(PROJECTS_CURSOR / AUDIT_CURSOR), and the paging surfaces' builders now take the
cursor value themselves and attach the name internally (withCursor became module-
private). The names disappeared from call sites, making a mix-up syntactically
impossible — the same "eliminate duplication by sharing constants" shape as
ruling CA. The real name a builder attaches is pinned by a unit test of
expectation literals (for the same reason as the e2e rejection, the literals on
the expectation side are deliberate).

## 14. Sixth-round superior-alternative search (owner request — 2026-08-29)

Request: "I think we should consider one more time whether there are
superior-alternative ideas, since something new keeps being found". The generation
rule was updated: even after §13's "duplication search" converged, pullfrog found
2 findings (the route() bypass, the cursor name on the call side) — both of the
type "**one link in an invariant's chain** relies on convention". So each
invariant was walked across all links: **definition → consumption → wire →
server**.

### Ruling CC: type-binding the 403-reason comparison literal (adopted)

- **Target**: shared.tsx's `reason === "session-not-allowed"` was a bare literal,
  unbound from api-schema's ForbiddenReasonSchema (a closed Literals). Renaming
  the reason would become "a silent fallback from the CLI-guidance wording to the
  generic 403 wording" (a quiet degradation of the display discipline)
- **Adopted form**: types.ts gained `ForbiddenReason = typeof
  ForbiddenReasonSchema.Type` (type-only — zero bundle impact), and the comparison
  literal became a shared constant declared `"session-not-allowed" satisfies
  ForbiddenReason`. A rename breaks at compile error (mutation-verified: TS1360).
  The runtime's defensive string treatment (ruling BP) is unchanged
- ApiFailure.reason's type itself stays `string` (the wire is not verified — BR).
  The distinction: only the literals **to which we assign meaning** are bound

### Ruling CD: mechanically checking the type-only-import discipline (adopted)

- **Target**: ruling BR's "bring no Effect / Schema runtime code into the bundle"
  was **convention only**: `import { MeSchema } from "@maruhi/api-schema"` passes
  build and run silently while the bundle (= the TCB) and the supply chain quietly
  grow — one of W2's heaviest invariants was the only unchecked link
- **Adopted form**: under verbatimModuleSyntax, type-only imports are explicit
  `import type` syntax, so a source tripwire rejects value imports from effect /
  @maruhi/api-schema under src/ (mutation-verified). The scan reuses
  findSourceOffenders

### Considered and rejected (round 6)

- **Making the CSRF header name a shared constant** — rejected (W3 handoff): the
  name appears in 3 places (web api.ts, server middleware.ts, an api-schema
  comment), and binding it requires changes to server / packages, which is outside
  this PR's "web only" scope (§1 (a)). The web side's name is already covered by
  the e2e checking the header is actually sent, and a server-side rename is a
  server-side PR's duty. The proposal is to place a constant export in api-schema
  at W3
- **Adding method to the catalog (checking apiGet/apiPost mix-ups)** — dismissed:
  a mix-up fails visibly as 404/405, not a silent drift (the logout POST is
  actually checked by e2e). A confusing-wording residual remains, but it does not
  reach the cost of one check surface
- **Runtime response verification** — rejected (re-confirming): ADR-0018 revision
  2 · item 4's deliberate non-implementation. Shape breakage is defended by the
  display layer's optional access without implying "verified" — design, not drift

### Convergence assessment (updated)

§13's assessment ("the duplication search is exhausted") was correct **within the
rule's scope**, but the higher-level rule of chain walking produced 2 more
findings. After CC/CD, across W2's invariant chains (paths · queries · routes ·
authorization classification · wording literals · the import discipline · the
serving topology), convention-reliant links are zero except recorded deliberate
rejections (test expectations, the server side of the CSRF name, runtime
verification). The next finding, if any, would come from a yet-higher generation
rule, and what that is cannot be identified at this point — the "keeps being
found" structure itself is a consequence of review bots and the searches
traversing the same rule space, and it will stop when the rule space stops
expanding.
