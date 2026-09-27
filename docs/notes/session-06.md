# Session 06 notes (auth / identity foundation — real AUTH_SPEC implementation + org integration)

Date: 2026-08-02. Prerequisites: PR #14 / #15 merged (chain persistence, append API).
Scope: real implementation of AUTH_SPEC §2–§6 (D1 + Drizzle, GitHub OAuth, sessions /
tokens), authorization wiring of the chain API (specified as §11), full rework of the
integration tests.

## 1. What was done (commit order = layer order)

1. **spec**: AUTH_SPEC v0.2 — added §11 (connection to the chain API), and defined
   scope expressions, per-op required permissions, and the v1 line in §6 (reflecting
   the §2 rulings below)
2. **core/api-schema**: new auth service boundary in core (Principal / RequestAuth /
   SessionService / TokenService), added AuthMiddleware contract + auth group +
   401/403/400 error types to api-schema. Made all membership endpoints require auth,
   added orgId to init
3. **server (D1)**: Drizzle v1 (fully pinned rc.4) + drizzle-kit generate. Repository
   layer isolated in `src/db.package/` (ImportLint boundary); only domain types are
   public
4. **server (auth.package)**: GitHub OAuth (web + device exchange), SessionService /
   TokenService, AuthMiddleware implementation
5. **server (wiring & authorization)**: per-env Layer construction, derived ChainState
   on the DO, §11's authorization order (404 concealment / actor match / scope / org)
6. **tests**: 59 (server) / 226 (root). Fully reworked to include the auth setup

## 2. Rulings (real-time owner rulings obtained)

Unlike session 05, real-time responses to AskUserQuestion were available.

- **Ruling 1 (actor correspondence)**: instructed "the optimal solution regardless of
  effort". Adopted: **require strict equality as the API acceptance policy** (both
  init and append require authenticated user_id == entry.actor.user_id). The chain
  consensus rules (crypto) stay ID-format-agnostic — pulling ID format into the
  validity rules would damage provider independence with no cryptographic gain, so
  this is optimal regardless of effort. Test vectors unchanged; the server
  integration tests are consistent via D1 seed (fixed user_id + linked_identities)
  + the real issuance path
- **Ruling 2**: refusal to non-members is **uniformly 404** (existence concealed).
  Not distinguished from uninitialized
- **Ruling 3**: init requires an org (member or above). **DO first + D1 projects
  catch-up + idempotent repair** (if the row is missing and the requester is the
  genesis actor, re-init is treated as success)
- **Ruling 4**: auth endpoints are **all in api-schema** (including the OAuth
  redirect ones). → HttpApi's 302 + Set-Cookie worked (see §3)
- **Confirmation A**: the audit-log schema proposal is treated as docs/AUDIT_SPEC.md
  (PR #10), already drafted by the owner — no duplicate is created. Implementation
  still awaits approval
- **Confirmation B**: tokens are issued via device flow, up to self-revocation (v1
  line)

### Other design decisions (mechanical, reversible)

- **Drizzle adopted (consequence of ADR-0006)**: drizzle-orm / drizzle-kit
  1.0.0-rc.4. However **the effect-d1 driver was rejected** — at rc.4 it lacks
  transaction / batch support, so getOrCreateUser's (§1-5) atomicity (users +
  linked_identities + org + membership) doesn't hold. Classic drizzle-orm/d1 + D1
  atomic batch is confined inside a thin tryPromise adapter at the boundary (the
  fallback path anticipated by ADR-0006). The DO-side chain table stays raw SQL
- **DO membership check runs before CAS**: returning a head-conflict (current head's
  hash / seq) or an acceptance-policy result to a non-member would break §11-2's
  existence concealment. The derived ChainState is cached in DO instance memory
  keyed by head hash
- **Authorization decision order (init)**: size 413 → actor 403 → token scope → org
  403 → DO. Resource protection (1 MiB early check) precedes semantic checks
- **ULID / Base62 are self-implemented** (no added dependency. These are encodings,
  not crypto primitives. Randomness and SHA-256 are WebCrypto)

## 3. Gotchas & environment findings

- **HttpApi redirect + Set-Cookie works** (unverified item from session-05). A
  handler can return `HttpServerResponse` directly instead of the success-schema
  value (`HttpServerResponse.redirect` + `setCookie` / `expireCookie`. The latter
  two return Effect, so compose with `Effect.orDie`). The normal path with
  success: `Schema.Void` returns 200 (return a raw response if you want 204)
- **`HttpServerRequest.url` is the path only**. Take the absolute URL (origin) from
  `request.source` (the raw Web Request)
- **HttpApiMiddleware's `requires` becomes a bare requirement**: handler-side
  requirements defer into toWebHandler's request context as the
  `Request<"Requires", T>` phantom, but a middleware's requires (SessionService
  etc.) must be satisfied statically at Layer construction. Since these services
  depend on env (D1 binding), **webHandler is built per-env and WeakMap-cached**.
  The middleware implementation must be declared as the concrete type
  `HttpApiMiddleware.HttpApiMiddleware<Provides, ErrorSchemas, Requires>` —
  otherwise provideService's Exclude doesn't reduce the generic and it fails to
  typecheck
- **vitest-pool-workers 0.20.1 has no fetchMock** (it disappeared from the
  cloudflare:test exports). Stub outbound fetch by **passing a function to
  miniflare's `outboundService`** (vitest.config.ts runs on the Node side, so no
  stub branch is needed in production code)
- **drizzle-kit v1 migrations are folder-form** (`drizzle/<name>/migration.sql`).
  wrangler already supports it via `d1_databases[].migrations_pattern:
  "drizzle/*/migration.sql"`, but vitest-pool-workers' `readD1Migrations` only
  supports flat `*.sql` → built D1Migration[] with a custom reader
  (test/support/read-migrations.ts) and pass it to `applyD1Migrations` via
  miniflare bindings (TEST_MIGRATIONS)
- **Dependencies removed via `bun x wrangler` etc. can leave lock entries**
  (@effect/sql-d1 came back as an optional peer resolution even after bun remove).
  Removed it from the lockfile by hand and verified consistency with `bun install`
- **`.dev.vars` is gitignored** → what gets committed is `.dev.vars.example`
  (dummy values)
- vitest.config.ts paths are **relative to process cwd** (breaks under root
  `vitest run`). Absolutize them off the config file with
  `new URL("drizzle/", import.meta.url).pathname`
- fallow: `*.package` index re-exports are also subject to unused-export checks.
  Narrow the public surface of a boundary to "what is actually consumed"

## 4. Updates to known constraints

- **Resolved**: "API request auth unimplemented (RequestAuth treats every request as
  anonymous)", "chain-read API fully public", "project creation not linked to org"
  (session-05 §4) → all resolved in this session. The test auth stub (auth-stub.ts)
  was replaced by the real issuance path + a fake GitHub (outboundService) and
  deleted
- **Remaining constraints**: rate-limiting recovery-blob fetch is undesigned
  (CRYPTO_SPEC §8. An optional item in this scope, not started). Token listing /
  extra issuance UI/API comes with the Web dashboard (confirmation B's line)

## 4.5 Review→fix loop (inside PR #16. 3 parallel review angles → verify → fix)

Accepted and fixed items (in order of severity):

1. **Missing audience verification in device exchange (security, high)**: checking
   validity only via `/user` allowed a token issued for another App to resolve
   someone else's account (confused-deputy). Fixed to also verify "issued by our
   OAuth App" via the check-token API (`POST /applications/{client_id}/token`) and
   documented in AUTH_SPEC §4-4. Added an other-app token to the fake GitHub to
   make it a discriminating test
2. **Same-name token rotation**: a device exchange for an existing (user, name)
   re-issues with revocation of the existing token (DoS defense against unbounded
   api_tokens growth. Documented in §6)
3. **Fixed credential precedence**: when an Authorization header is presented,
   don't fall back to cookies (invalid Bearer + valid cookie = 401). The Bearer
   scheme is case-insensitive per RFC 7235. Pinned by tests
4. **API contract drift**: logout / revokeToken declare
   `HttpApiSchema.NoContent` (204), the OAuth redirect ones declare
   `HttpApiSchema.Empty(302)` (so the derived client's success-status matching
   matches real responses)
5. **Making the §3-3 email filter verifiable**: the fake GitHub now branches
   responses by ID range (unverified / non-primary / emails 404); added 3 negative
   tests + self-repair on re-login (backfilling an email missed at signup once it's
   verified)
6. **Discriminating tests for the §6 op→permission table**: added rotate_epoch
   allowed with write scope, add_member 403, init 403 (makes detectable the
   regression that collapses every op to a single level)
7. **Monotonic guard on the DO cache**: prevented a race where permit-less
   snapshotFor could overwrite a fresh cache with an old ChainState (perf only) by
   comparing headSeq. The `?? ""` fallback (could turn corruption into a success
   response) became a defect
8. **Cron sweep of expired sessions**: scheduled handler + `triggers.crons` +
   sessions.expires_at index (rows not presented never get cleaned at resolve time)
9. **Thinning per-auth D1 writes**: both session extension and token last_used_at
   now threshold at 1 hour (30-day sliding semantics unchanged)
10. **Other**: getOrCreateUser race discrimination made strict by UNIQUE constraint
    message (so unrelated D1 failures aren't misclassified), dropped the
    requestOrigin Host-header fallback, added User-Agent to token-exchange
    requests, strengthened the fake's fidelity (UA required, Accept branching,
    check-token), and unit-tested the core scope combination rule (fixing the
    intent that an individual entry cannot narrow a wildcard = strongest match
    wins)

### Loops 2–3 (re-review + Bugbot / CI)

11. **CI failure fix**: the fake GitHub's check-token matching assumed values from
    .dev.vars (gitignored, absent in CI) → changed to wiring validation of "the
    client_id in the path matches the client_id in Basic + secret non-empty"
    (independent of env-injection source)
12. **Session protection for token-subject logout (Bugbot)**: a Bearer-authed
    request must not revoke the browser session cookie sent along with it (logout
    is restricted to session-subject operations)
13. **Atomic rotation (detected independently by Bugbot + re-review)**: merged
    delete + insert into a D1 atomic batch + UNIQUE (user_id, name). Concurrent
    device exchanges still yield exactly 1 same-name token
14. **Token-exchange body now form-urlencoded (Bugbot)**: RFC 6749 §4.1.3
    compliant (a JSON body is out of spec). The fake also requires form to pin it
15. **deviceExchange input boundary + issuance cap**: tokenName ≤ 128, scopes ≤
    100, project is a project-ID format or `"*"` only (Schema-enforced). Distinct
    token names capped at 100 per user (429 TokenLimit. Same-name rotation always
    allowed)
16. **Session-cookie sliding reflected**: not only the DB extension — session-auth
    responses reissue the cookie with Max-Age (in middleware; doesn't touch
    responses where the handler manipulated a same-name cookie). Also added a
    regression test for cookie attributes (HttpOnly / Secure / SameSite /
    Max-Age)
17. **isUniqueConflict cause-chain handling**: follows the cause so that race
    detection doesn't break on drizzle's single-query path (wrapped in
    DrizzleQueryError), pinned by a discrimination test (verified by workerd
    measurement that the batch path doesn't wrap)

Items recorded but not adopted (low impact, acceptable in v1):

- Starting OAuth in multiple tabs fails the earlier tab with 400 because the state
  cookie is single-slot (recovers on retry. A fix would allow multiple states)
- The callback failure path doesn't expire the state cookie (it expires naturally
  at the 10-minute TTL)
- transport 413 (raw body limit) is a schema-less raw response the derived client
  can't decode (the CLI implementation will need a handling branch)
- The token-issuance cap (100) checks count (read) in a separate transaction from
  the insert, so parallel issuance under distinct names can overshoot by a few
  (overshoot is bounded by parallelism. The DoS-cutoff goal is met. For strictness:
  conditional INSERT or DO serialization)
- The session-cookie attribute definition is duplicated between handlers-auth
  (issue time) and middleware (reissue time) (both paths are pinned by attribute
  regression tests. Common ground is future work)
- isUniqueConflict's cause chain assumes no cycles (D1 / drizzle errors have no
  cycles so it's effectively unreachable. A depth cap would defend it)

## 5. Handoff to the next session

- **After the PR merges**: update the note on ROADMAP Phase 1 "server: project DO,
  D1, HttpApi, audit log (append-only)" (D1 + auth + chain authorization done.
  Audit-log implementation awaits AUDIT_SPEC approval)
- **Reviewing / approving AUDIT_SPEC (drafted by the owner in PR #10) is the
  precondition for the audit-log implementation**
- ~~Disabling CI telemetry (handoff from spike-b)~~ → **confirmed resolved**:
  .github/workflows/ci.yml already sets DO_NOT_TRACK=1 /
  WRANGLER_SEND_METRICS=false (done on the owner side)
- Outstanding optional item: rate-limit design for recovery-blob fetch
  (CRYPTO_SPEC §8)
- For the CLI implementation: the CLI side of the device flow is
  `/auth/device/exchange` (HttpApi-derived client) + OS-keychain storage. Default
  token scope is `* × admin` (effective authority is bound by chain role)
- For the Web-dashboard implementation: the session cookie is `__Host-`, so it
  won't be stored by the browser under wrangler dev (http) (verify on https or via
  headers). Write-path fetches must carry `x-maruhi-csrf: 1`
- Needs adding to the self-host steps: `wrangler d1 create maruhi` + replacing
  database_id, `wrangler d1 migrations apply`, creating a GitHub OAuth App +
  setting GITHUB_CLIENT_ID (vars) / GITHUB_CLIENT_SECRET (secret) (inputs to the
  Phase 1 setup wizard)
