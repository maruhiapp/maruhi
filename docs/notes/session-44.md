# Session 44: W3a — token-management API + default-TTL implementation rulings (CE–CH)

Date: 2026-08-30. Target PR: PR-W3a (design document §7's 5 — server → api-schema →
CLI, no web changes). The format is the usual "multiple candidates → superior-alternative
search → 3-round comparison → autonomous selection" (session-27 §14's format. The codes
continue from session-43's CD). The spec's source of truth is AUTH_SPEC §6 (the W0 =
PR #103-approved revision). This note's rulings are drafted as the same PR's AUTH_SPEC
0.15-draft revision, and merge constitutes approval. This is the PR that resolves
SECURITY_REVIEW 2026-08-14 L-2 (tokens with no expiry).

## 1. Ruling CE: whether to apply retroactively to existing no-expiry tokens, and the migration rule (§6 handoff (a))

### Round 1 (multiple candidates)

- **CE-a (no retroactivity)**: existing `expires_at IS NULL` rows stay no-expiry until
  rotation — the form the design document §7's original wording suggested. Advantage = does
  not break any running unattended use. Downside = **L-2 (a leaked token persists unless the
  leak is noticed) is preserved permanently on existing rows** — this PR is the L-2-resolution
  PR, and "only new issuance is bounded" cannot be called a resolution
- **CE-b (retroactivity anchored at issuance)**: the migration bakes `expires_at =
  created_at + 90 days` in. Uniform semantics, but **every existing token older than 90 days
  dies instantly the moment the migration applies** — a silent mass shutdown at a stage with
  no way to warn users
- **CE-c (re-anchoring at application time)**: the migration writes `expires_at =
  application time + 90 days` onto NULL rows. Every existing token's lifetime becomes bounded
  (L-2 resolved) while keeping a 90-day re-login grace. The deadlines become visible via the
  same PR's listing API and the CLI's login-time display

### Round 2 (superior-alternative search)

- CE-c's weakness: on a self-host that deploys only the new code without applying the
  migration, NULL rows stay no-expiry (the migration is an application separate from the
  code). Superior alternative: **CE-c′ = CE-c + a NULL fail-closed on the verification side**
  — `isExpired` treats NULL as expired. If the migration lands first, NULL never reaches
  verification (zero behavior difference); if the migration is missed, no-expiry does not
  come back either, and 401 → re-login (same-name rotation) issues an expires_at-bearing row
  and **self-heals**. The failure direction is only the "unusable" side (the safe side)
- A variant taking `min(created_at + 90d, application + 90d)` was considered and dismissed:
  it partially re-introduces CE-b's instant-death problem for no gain

### Round 3 (re-inspection)

- CE-c′'s residual: the migration SQL (anchored on `unixepoch()`) carries the default TTL's
  90 days as a SQL literal (7776000000 ms) and cannot be bound to api-schema's
  `DEFAULT_TOKEN_TTL_DAYS` (a SQL file cannot import a constant). However, a migration is a
  one-time operation, and changing the constant afterward does not retro-contradict — the
  pairing is made explicit in comments on both sides and accepted (same shape as
  worker-env.ts's period note)
- Expired rows are not swept (deliberately asymmetric with sessions' resolve-time deletion):
  rows remain as inventory objects in the listing and keep counting toward the user's
  100-token cap. Sweeping is carried by targeted revocation and same-name rotation —
  automatic deletion was rejected because it erases the "notice the expiry" path (visibility
  in the listing)
- **Adopted: CE-c′**. Implementation = migration `token_ttl_reanchor` (application time +
  90 days) + `token.ts`'s `isExpired` (NULL = expired). A test pulls the real thing out of
  `TEST_MIGRATIONS` and verifies the migration SQL (no SQL duplicate is kept). The design
  document §7's original wording (the no-retroactivity suggestion) has already been revised
  to match this ruling

## 2. Ruling CF: the collision between unattended PATs on lease-incapable runtimes and the TTL (§6 handoff (b))

Premise (not moved): the option of returning to a no-expiry default is not taken
(re-introducing L-2 — the PR #103 review handoff).

### Round 1 (multiple candidates)

- **CF-a (do nothing)**: GitLab CI / k8s / cron etc. accept a re-login (human intervention)
  every 90 days. Only postpones the handoff again — not a resolution
- **CF-b (explicit TTL designation at issuance [capped])**: add `expiresInDays` (1..365) to
  `POST /auth/device/exchange`. Issuance is device flow = a path with human approval only, so
  the shape becomes "only a human's explicit choice can lengthen it, and even then it is
  bounded at 1 year"
- **CF-c (extending supported issuers)**: add OIDC issuers like GitLab to leases (§14), making
  PATs themselves unnecessary. In principle the best, but it is a large independent work
  needing per-issuer verification implementations + a spec revision, and k8s / cron
  (environments without OIDC) still cannot be saved

### Round 2 (superior-alternative search)

- CF-b and CF-c are not exclusive: CF-b saves every environment today (including OIDC-less
  cron) with a cap, and CF-c is the long-term path that erases PATs themselves from supported
  environments. Taking CF-b does not reduce CF-c's value (leases are always superior in
  value non-transit and short lifetimes). Therefore "CF-b now + CF-c later (separately, as a
  §14 extension)" is the superior alternative to both
- CF-b's cap: 365 days (draft value). Together with the existing mitigations — 90-day
  default × extension only when explicit · a secret-scanning-compatible prefix · effective
  authority min(scope, chain role) — it lowers operational load within the range that does
  not re-introduce L-2's essence (unboundedness). The cap is enforced by the wire Schema
  (an integer in 1..365), never left to an in-server default branch

### Round 3 (re-inspection)

- Re-checked "should an explicit TTL be allowed for scoped tokens too" — allowed (not
  restricted). A TTL is the token's lifetime, not its authority; long lifetime × narrow scope
  is rather the recommended shape (CI tokens conventionally take a project-scoped scope + a
  longer TTL)
- The CLI flag name is `--token-ttl-days` (a pair with `--token-name`). The range check looks
  at api-schema's shared constant (`MAX_TOKEN_TTL_DAYS`) and fails **before any
  communication** (the same discipline as MAX_TOKEN_NAME_LENGTH)
- **Adopted: CF-b (+ CF-c recorded as a non-exclusive future path)**

## 3. Ruling CG: the decision order of expiry 401 / authorization 403 / uniform 404 (§6 handoff (c))

### Round 1

The token-management surface (listing · targeted revocation) is a per-user resource, and
unlike §12-3's project surfaces (out of scope = 404) there is no "does the scope cover the
target" stage. The only ordering candidate is "which comes first, the principal-condition
403 or the target-resolution 404":

- **CG-a (404 first)**: look at the target's existence / ownership first. Against probing with
  a scoped token, the response would differ on the target's existence (exists = 403, absent =
  404) — **the 403/404 difference becomes an existence oracle for token ids**, violating
  §12-6's uniform-response discipline
- **CG-b (403 first)**: look at the principal condition (session or `*` × admin) first. This
  determination is **computed from the calling principal's credentials alone and carries no
  information about the target** (the same "computable from the request content alone"
  argument as §5's session-capability restriction and §12-3's authorization-first exception).
  Only a principal satisfying the credentials reaches target resolution (uniform 404)

### Round 2 (superior-alternative search)

- The position of expiry: an expired token **folds uniformly into anonymous** — alongside
  revoked and unknown — at verification (§6) = 401 on every endpoint. The option of
  distinguishing "it is expired" on the wire is dismissed — it becomes extra information for
  an attacker (a token thief), while a legitimate user is served by the CLI's 401 guidance
  (expired or revoked + re-login) and the issuance-time expiry display · listing API
- Session CSRF / capability restriction stay in the existing order where the middleware
  (W2b's single implementation point) returns 403 (capability restriction → CSRF —
  preserving the existing ruling that the rejection reason must not vary with the presence of
  a header the caller can add themselves)

### Round 3 (re-inspection)

- CG-b's 403 says only "a token without `*` × admin called the token-management surface",
  and the uniform 404 does not distinguish not-owned-by-self from nonexistent. Mutation
  verification: DELETE a real id and a nonexistent id with a scoped token → a test pins the
  responses (403) being byte-identical. Sessions against another's id / a nonexistent id →
  404 body match is also pinned
- **Adopted: CG-b** — 401 (verification folds uniformly to anonymous) → capability
  restriction / CSRF (sessions — middleware) → principal-condition 403 (computed from
  credentials only) → uniform 404 (existence concealment)

## 4. Ruling CH: the principal condition of the listing `GET /auth/tokens` (filling a spec gap)

§6 defines the principal condition of targeted revocation (session or `*` × admin) but left
the listing unspecified.

- **CH-a (allow every token principal)**: the listing is a read with no destruction. However,
  the response is an account-wide token inventory (names, prefixes, scopes, last used) =
  **reconnaissance material** — stealing a scoped token placed in CI etc. would enumerate
  "what other tokens are alive with which scopes"
- **CH-b (same condition as targeted revocation: session or `*` × admin)**: aligns with the
  same norm as self-axis audit (`GET /auth/audit/events` — ensureSelfAuditAccess):
  "account-wide self-information is not readable by easily-exposed scoped tokens"
- Round-3 confirmation: W3b's (S9 screen) consuming principal is the session, so CH-b has no
  impact. The CLI's future `maruhi token list` also works under the default token (`*` ×
  admin). The only thing lost is self-enumeration from scoped tokens, for which no
  legitimate path exists
- **Adopted: CH-b** (implementation = `ensureTokenManagementAccess`. A single implementation
  point by delegating to ensureSelfAuditAccess — a comment states that the norms are
  identical)

## 5. Confirming handoffs (session-43 §14)

- **Making the CSRF header name an api-schema constant** (session-43 §14's W3 handoff):
  **resolved** — `CSRF_HEADER_NAME` is exported from api-schema (auth-middleware.ts) and the
  server's middleware.ts references it — bound that way. AUTH_SPEC §11-4 also records the
  source of truth. **The web side (dashboard/api.ts's literal) is not bound in this PR** —
  this PR is "no web changes" (design document §7's 5), and the web literal is already
  covered by the e2e that verifies the header is actually sent. W3b (the next web-touching
  PR) replaces it with the constant import (handoff)
- session-43 §14's other rejected items (adding method to the catalog, runtime response
  verification) are web territory and do not apply to this PR

## 6. Implementation record

- **api-schema**: added `auth.listTokens` (GET /auth/tokens) / `auth.revokeTokenById`
  (DELETE /auth/tokens/:tokenId). `TokenSummarySchema` structurally has no raw-value or
  token_hash columns. `TokenNotFoundError` (404 — a uniform response with no fields). The
  deviceExchange payload gains `expiresInDays` (1..365), the response `expiresAtMs`.
  `DEFAULT_TOKEN_TTL_DAYS` / `MAX_TOKEN_TTL_DAYS` / `CSRF_HEADER_NAME` are exported. Both
  surfaces are added to `SESSION_ALLOWED_ENDPOINTS` (AUTH_SPEC §5's permission enumeration
  was already added in the W0 revision — implementation follow-up)
- **server**: `issueToken` now takes ttlMs as required and fixes expires_at at issuance
  (cannot be omitted — a forgotten call fails at the type level). `isExpired` became
  NULL-fail-closed (CE-c′). `TokenRepo.listForUser` (does not select token_hash) /
  `revokeById` gained an actor parameter and became boolean (false = the uniform-404
  derivation. The ownership condition lives at the repo boundary — the form in which deepsec
  S8's defense became effective with targeted revocation's introduction). Handlers use
  `ensureTokenManagementAccess` (CG-b / CH-b)
- **migration**: `token_ttl_reanchor` — `unixepoch()*1000 + 90 days` onto NULL rows (CE-c′)
- **CLI**: `--token-ttl-days` (1..365 — a pre-communication check), an expiry display on
  successful login (`The token expires on YYYY-MM-DD (UTC)`), and the 401 guidance updated
  to "expired or revoked" (since expiry folds into the same 401 as revocation, both
  possibilities are named). All wording is English (ADR-0017)
- **AUDIT_SPEC 1.1-draft**: clarified `auth.token_revoked`'s actor = the acting principal
  (the target id is payload.tokenId). No new events were added (the existing system
  suffices)
- **Tests**: 13 new server tests (tokens.test.ts — TTL issuance · expiresInDays boundaries
  and 400 · NULL fail-closed + re-login self-healing · re-running the real migration SQL ·
  pinning the listing's fields [exact match of the key set = a structural check that raw
  values and hashes are absent] · expired rows visible in the listing · CH's 403 · the
  targeted-revocation authorization matrix · body match of the uniform 404 · the audit
  actor) + following up an existing sweep (session-capability's `:tokenId` concretization —
  the unknown-parameter fail-loud worked as designed and forced the addition). 4 new CLI
  tests (the TTL flag's pre-communication check · payload pass-through · the expiry display ·
  the 401 wording). 2,197 tests pass overall
- Out-of-scope confirmation: no changes to web / packages/crypto / the docs site. No
  additional issuance UI / API or rename API was built (the v1 line stays)

## 7. Post-implementation superior-alternative search (1 round — a chain walk of the new surfaces' invariants)

Following session-43 §14's procedure, each invariant of the new surfaces was walked across
all links — definition → consumption → wire → server:

- **"Never return raw values / token_hash"**: the repo's select columns (listForUser does not
  SELECT token_hash) → the domain type (ApiTokenSummary has no such column) → the wire
  Schema (TokenSummarySchema has no such column) → tests (exact match of the response key
  set). All 4 links are structural, none convention-reliant
- **"TTL fixed at issuance"**: issueToken's ttlMs is a required argument, and NewApiToken's
  expiresAtMs is a required field — omission fails at compile time. The issuance path is a
  single conditional INSERT in the repo
- **"The session-permission enumeration"**: the load-time sweep + the mechanically derived
  matrix already exist, so the new surfaces were covered automatically (concreteUrl's
  unknown-parameter fail-loud also worked as designed)
- **Residuals accepted as convention-reliant (recorded)**: (1) the migration SQL's 90-day
  literal is unbound from `DEFAULT_TOKEN_TTL_DAYS` (CE round 3 — a one-time operation. The
  pairing is made explicit in comments on both sides). (2) `expiresInDays`' cap lives at the
  single point of the wire Schema (the same shape as §12-10 (1)'s single implementation
  point for acceptance policy; not duplicated). (3) the web's CSRF header-name literal
  (handed to W3b per §5)
- No additional findings emerged (a consequence of choosing from the start a design whose
  new surfaces sit inside the coverage of the existing sweep mechanisms [session-capability /
  serving-topology])

## 8. Review follow-ups (PR #108)

- **pullfrog (2 findings — both legitimate, fixed)**:
  (1) **the expiry display bypassing the total formatter** — the new line in login.ts called
  `new Date(ms).toISOString().slice(0, 10)` directly. `expiresAtMs` is an unconstrained
  number on the wire: out-of-Date-range values defect (crash) with RangeError, and the
  extended-year format shifts the slice position — a bypass of exactly the discipline that
  display.ts's header comment (deepsec B1/B4/B5) names `expiresAtMs` for. Replaced with
  `formatUtcDate`, and explicit degradation on an out-of-range value (9.9e15) is
  mutation-verified by a test. (2) **version skew from making `expiresAtMs` required** —
  making the response field required breaks `maruhi login` (the only recovery command from a
  fail-closed expiry) at response decode under "new CLI × old server" and orphans the issued
  token. The bot offered "make it optionalKey or record a hard break in the ops runbook",
  but **the superior alternative to both = optionalKey + a note when absent + a two-way skew
  description in SELF_HOSTING "Updates"** was adopted: absence becomes detection material
  for an old server (it can even tell the user that `--token-ttl-days` is inert), and it
  matches the repository's precedent (head attestations' two-way graceful-degradation
  description). A successful login against an old server + the note is pinned by a test

## 9. Handoffs (to W3b)

- Replace web's `x-maruhi-csrf` literal with a non-type-only constant import of
  `CSRF_HEADER_NAME` (in a form consistent with ruling CD's import discipline — because it
  becomes a value import, how the BR/CD tripwires treat it is ruled in W3b)
- The S9 token-management screen consumes `auth.listTokens` / `auth.revokeTokenById`
  (do not forget adding them to the DASHBOARD_ENDPOINTS catalog — the sweep enforces it).
  Expired tokens appear in the listing (expiresAtMs in the past) — display them as a
  server-declared label like "Expired" (display discipline §4)

## 10. Second-round superior-alternative search (owner request — 2026-08-30)

Request: "look for new options that could be silver bullets or superior alternatives". Beyond
re-inspecting the rejected options of rulings CE–CH, the search targeted **the new residuals
produced by the solutions the rulings placed** (the consequence side of rulings).

### Ruling CI: self-disclosure of the presented token's expiry on `/auth/me` (adopted)

- **The targeted residual**: CF (explicit TTL) solved the unattended-PAT 90-day problem via
  "can be extended with a cap", but **the expiry is not self-observable from any principal**,
  so expiry always appears as "a sudden 401". Because the listing (ruling CH) is `*` ×
  admin-only, the very targets CF saved (scoped tokens placed in CI etc.) have no path to
  learn their own expiry — a blind spot created by the composition of CF and CH
- **Adopted form**: `GET /auth/me` returns `tokenExpiresAtMs` to a token principal. It is the
  same "attribute of the credential you yourself presented" class as §16-2's `tokenScopes`,
  and discloses no new information (session principals get it absent = no token presented).
  The implementation bakes it into the principal type (core's AuthenticatedPrincipal) —
  a principal that passed verification (expired = anonymous) always carries a non-null
  expiry, so the type is non-null too. Same idea as GitHub self-disclosing a PAT's expiry in
  a response header
- CH-b′ (returning a "listing of just your own row" to scoped tokens) is dismissed:
  conditional visibility where the response set changes by principal class is the complexity
  AUDIT_SPEC §7 pays for in audit, and it is not worth carrying into the token-management
  surface for a single self-attribute. Placing it on /auth/me preserves the factoring
  "listing = account inventory (privileged) / me = self-attributes (every principal)"

### Considered and rejected (round 2)

- **Sliding TTL (extend on use)**: a shape that appears in L-2's recommended responses too,
  but "fixed at issuance, deliberately asymmetric with sessions" is an owner-approved
  decision from W0 (PR #103) and is not relitigated. It is also substantively inferior: a
  stolen token never dies while the attacker keeps using it = the forced periodic
  re-authentication (fixed TTL's purpose) disappears
- **Lazy re-anchoring (on verification, bake now + 90 days onto a NULL row and accept)**:
  looks same-shaped as §11-5's lazy backfill but runs backward — a leaked-and-unused old
  token (L-2's main target) would persist until first use, and moreover the attacker's first
  use would grant it 90 fresh days. Anchoring every row at one fixed point in the migration
  (CE) is strictly superior
- **Making expires_at NOT NULL (in this PR)**: in the deploy gap where the migration has
  applied but the old code still runs, the old code's issuance (writing NULL) would break
  with an INSERT failure. Handed off as "a follow-up migration after all deploys stabilize"
  — the same shape as AUDIT_SPEC §5.1's row_id (below)
- **Excluding expired rows from the 100-token cap / auto-sweeping them**: the cap's purpose
  is bounding api_tokens bloat DoS (§6), and exclusion breaks boundedness. Auto-sweeping
  erases inventory visibility (CE round 3). Same-name rotation is CI's routine shape and
  prevents accumulation, and differently-named accumulation is resolved by the user via the
  listing + targeted revocation — kept

### Handoffs (from round 2) (a merged item is at the end of §11)

- **The expires_at NOT NULL follow-up migration**: once the W3a code has reached every
  deploy, a follow-up migration of NULL re-anchoring (idempotent) + the NOT NULL constraint
  promotes "no no-expiry row exists" to a DB constraint and turns the verification side's
  fail-closed branch into a defensive leftover (dead code) (same shape as row_id's
  precedent)
- ~~**CLI approaching-expiry warning**: now that the material exists via `tokenExpiresAtMs`
  (ruling CI), a "warn 7 days before expiry" via storing the expiry in the keychain or
  querying /auth/me can be added anytime in an independent CLI PR with no wire change. Not
  packed into this PR (the login-time expiry display covers the minimum)~~ **Withdrawn and
  implemented in the fourth-round search (§13 — ruling CL)**: the walk in §13 noticed that
  "an extra query is needed", the basis for deferral, had already disappeared as a
  consequence of CI (the env path calls /auth/me on every command)

## 11. Third-round superior-alternative search (owner request — 2026-08-30)

Request: "search once more". The generation rule was updated — round 1 walked the new
surfaces' invariant chains, round 2 targeted "blind spots the rulings' composition creates".
Round 3 is **a walk backpropagating the new invariant (every token has a finite lifetime)
into all existing consumption paths**: every path that observes / reports the fact "a token
dies" (the rendering of 401s, auth-failure guidance, audit, sweeping) was enumerated and
checked for leftovers still written under the pre-W3a premise (a token lives unless revoked).

### Ruling CJ: making the MARUHI_TOKEN path's 401 guidance expiry-aware (adopted)

- **Target**: the CLI draws 401s on two paths — failure.ts's generic 401 (for keychain
  tokens. Updated to "expired or revoked" in the first wave) and **session.ts's MARUHI_TOKEN
  auth failure** ("check revocation, scope, and the target server"). The latter had been left
  under the old premise. MARUHI_TOKEN is exactly the unattended-runtime path (CI / cron)
  ruling CF targeted, and post-W3a the most likely cause of this 401 is **expiry** (every
  token dies within 365 days at most) — yet the wording neither named the cause nor gave the
  fix destination (re-issue at a work terminal → replace the env var) — guidance naming only
  `maruhi login` (keychain-oriented) is inaccurate for env-var users
- **Adopted form**: the wording is updated to "expired or revoked, or the scope or target
  server may not match" + "re-issue with `maruhi login --token-name <name>` and replace
  MARUHI_TOKEN". units.test.ts pins the expiry mention and the env-replacement guidance.
  Comments and negative assertions that referenced the old wording (redacted.test /
  units.test) were followed up to the current wording (prevention of the "dangling
  reference" class that pullfrog hit in the round-2 review)
- Confirmed that ci-run (the OIDC lease path — no PAT used) is out of scope

### Considered and not taken (round 3)

- **CLI token-management commands (`maruhi token list` / `revoke`)**: follows W2a's "the CLI
  = the first consumer of the same API" pattern, but it is outside this PR's task boundary
  (the CLI scope = expiry 401 guidance), and as a consumption surface W3b (S9) is the
  designed source of truth. It also fills no residual of a ruling — if demand (self-host
  operators doing CLI inventory) is measured, an independent PR (handoff)
- **A short-lived access-token + refresh-token structure**: a fundamental strengthening that
  shrinks a stolen token's exposure to hours, but it is territory §6 already carries on the
  roadmap as "short-lived lease tokens for agents (Phase 3)" and requires a full revision of
  the W0-approved issuance path (device flow only). Not W3a's superior alternative — a
  Phase-3 design task (only the default course is confirmed — no new handoff is filed)
- **NULL rows issued in the deploy gap (migration applied, old worker still running)**: old
  code's issuance writes NULL, which the (already-applied) migration does not pick up. New
  code's fail-closed makes it a 401 and re-login self-heals — a window of seconds-to-minutes
  already covered by CE's residual description; an additional mechanism does not reach its
  cost (record only)

### Convergence assessment

The three generation rules (chain walk / blind spots of ruling composition / backpropagating
the new invariant into existing paths) were exhausted, and round 3's findings shrank to one:
"wording written under pre-W3a premises". The remaining convention-reliant and deliberately
accepted items are recorded in §7 and §10, and the next findings, if any, are expected from
review bots or real operation (the first expiry observation under dogfooding).

## 12. Ruling CK: the supply path of MARUHI_TOKEN — `--show-token` (originating in PR #108 review)

pullfrog's fourth review hit a defect in ruling CJ's wording: the guided recovery procedure
(re-issue → replace MARUHI_TOKEN) cannot be completed because **no command exists that
displays an issued PAT's raw value**. Digging surfaced a two-stage pre-existing gap:

- **Spec–implementation divergence (pre-W3a)**: AUTH_SPEC §6 (W0-approved) defines the raw
  value's place of appearance as "one display on the terminal at issuance", but the CLI's
  loginOp only saved to the keychain and never implemented the terminal display — CJ's
  wording was the first thing to depend on the divergence
- **CF's residual**: for the unattended PAT on lease-incapable runtimes (ruling CF's target),
  the very **path that supplies** the token into the environment existed in neither
  documentation nor implementation. Without a supply path, explicit TTL (CF) does not hold —
  the last link needed for CF to complete

### Adopted form

- `maruhi login --show-token` (an explicit opt-in) displays the issued raw value once on the
  terminal (keychain storage is unchanged — the display is one additional place, not a
  replacement). It is a concretization of §6's implementation form "one terminal display at
  issuance", not a spec change
- **The gate is the same fail-closed two layers as value display** (ADR-0016 decision 7's
  `ensureValueDisplayAllowed` — interactive terminal × non-agent): a PAT is a credential to
  every secret, and the discipline of never flowing it into an agent's transcript or CI logs
  is the same level as values. Placed on the allow-list side, not the deny-list (invite
  family)
- **The check happens before any communication**: letting browser approval complete in an
  environment that will be rejected means the same-name rotation revokes only the old token
  while no new raw value is obtained (the worst failure shape — it only breaks the CI token
  being replaced) — the same "writing and environment mistakes fail before communication"
  discipline as --token-name's length check
- CJ's 401 wording was updated to the real procedure including `--show-token`. SELF_HOSTING
  got the first documentation of the MARUHI_TOKEN supply procedure (+ the lease-preferred
  note). The login.ts display point was registered in redacted.test's inventory table of
  stripping locations (with a reason comment)

### Round-2 review follow-up (pullfrog)

- **Neutralizing the display**: token is an unconstrained Schema.String on the wire (the
  server chooses every byte) yet the display was un-neutralized — since it is a value that
  gets copied, it now passes through **escapeText** (allow-list — an honest Base62 value
  passes through, an injection becomes visible \u{hex} sequences) instead of displayText
  (destructive substitution to U+FFFD = the value would break). Mutation-verified that a
  hostile server's ANSI + fake extra lines (impersonating supply instructions) do not arrive
  raw. Format constraints on the wire-Schema side (prefix + charset) were not taken — they
  would break old CLIs' login at decode on a future format change — so it was closed by
  neutralizing at the display point

### Rejected

- **Always displaying (no flag)**: the raw value would routinely land in every login's
  terminal scrollback and CI logs — "fixed to one place" is a discipline of location, not an
  obligation to always display
- **Softening the wording only (stop at enumerating causes; procedures go to docs)**: the
  operator dead-ends at the moment of the 401 (as pullfrog pointed out, "the path is missing
  at the very moment an exit is most needed"). The supply path itself is needed for CF to
  complete, and there is no reason to delay it
- **Guidance to read it out of the keychain manually** (extraction with OS tools): the
  procedure differs per OS and would promote a surface outside maruhi's control into the
  sanctioned procedure — display at issuance is the spec's designated place, so that is what
  was implemented

## 13. Fourth-round superior-alternative search (owner request — 2026-08-30)

The generation rule was updated: round 4 is **a lifecycle-transition observer walk** — every
state transition of the new object (the finite-lifetime token) was enumerated (issuance →
use → approaching expiry → expired → re-issue/revoke → sweep), and each transition was
checked for whether "operator, observer, recovery procedure" are all present. Issuance (login
+ display + keychain), use (self-observation = ruling CI), expiry (401 + a real-procedure
guidance = CJ/CK), re-issue (rotation), and sweep (targeted revocation + listing) are all
present. **Only approaching expiry is observed by no one until the 401 lands in unattended
environments** — the CF–CK arc completed "recovery after death" but lacked "advance notice
before death".

### Ruling CL: the approaching-expiry early warning (adopted — retracting §10's deferral)

- **The basis for deferral had disappeared**: round 2 (§10) deferred the CLI warning to "an
  independent PR", but its basis — "an extra query is needed" — had already disappeared as a
  consequence of ruling CI itself: **the MARUHI_TOKEN path calls /auth/me on every command,
  so tokenExpiresAtMs is in hand with no added request**. The keychain path also needs only
  a local, communication-free check if the login response's expiry is saved into the record.
  The ruling had invalidated the premise of its own deferral (a self-application of round 2's
  blind-spot rule)
- **Adopted form**: from 14 days remaining (draft value), every command emits a one-line
  warning to stderr (the expiry date via the total formatter + days remaining + a per-path
  re-issuance procedure). stderr to preserve stdout's machine readability (value / JSON
  pipes). Silent when the expiry is unknown (old server / old record) and when it is already
  locally past (the 401 side says that — never said twice). `expiresAtMs` is added to the
  keychain record as optional (old records have it absent = behave as before; it appears on
  re-login — backward compatible). In CI this warning lands in the job log, letting the
  operator schedule re-issuance before the 401
- **Verification**: pinned by tests — the env path's in-window warning (with the --show-token
  procedure), out-of-window silence, the keychain path's **communication-free** determination
  (zero requests to the server), and backward compatibility of old records
- Rejected: emitting the warning on stdout (breaks pipes) / auto re-issuing on warning (no
  issuance path without browser approval exists — the device flow's design is as intended) /
  a server-side approaching-expiry notification (no notification infrastructure + a new
  surface colliding with the telemetry-minimal policy)

### Convergence assessment (re-updated)

§11 estimated "the next findings will come from review bots or real operation", but the
actual round-4 finding came from **ruling CI having invalidated an earlier deferral
decision** — every adopted ruling requires re-evaluating the premises of past rulings and
deferrals (rulings are not independent; a later ruling rewrites the grounds of an earlier
decision). After CL, every transition of the lifecycle has an observer and a recovery
procedure aligned, and no "silent state change" remains in a token's lifetime.

## 14. Fifth-round superior-alternative search (owner request — 2026-08-30 · final round)

The generation rule was updated: round 5 is **a live walkthrough of the recommended
procedure (a credential-custody walk)** — the recommended procedure this PR documented
(CK's MARUHI_TOKEN supply) was performed end to end, and after each step "which credential
exists, where, and in how many copies" was tracked. CK had verified the procedure's
**feasibility** (whether it dead-ends), but the **world after the procedure is executed**
(the soundness of where credentials sit) was unverified.

### Ruling CM: making the identity swap of a supply login visible (adopted)

- **Finding**: the keychain's token slot is **one per origin** (`token::${origin}` — it has
  no name component). Running CK's supply procedure `maruhi login --token-name ci
  --show-token` on a work terminal makes the issued CI token **also replace that terminal's
  active token**. Consequences: (1) the same token value exists in two environments — the
  work terminal and CI — and **actor_api_token_id is identical in both** — AUDIT_SPEC's
  actor attribution (which environment an operation came from) is structurally muddied.
  (2) A targeted revocation meant to kill "only the CI one" (W3a's new surface!) kills the
  work terminal's CLI too (and vice versa). (3) The recovery is actually one command — a
  plain `maruhi login` (same-name rotation under the default name) returns the terminal to
  its own token, leaving the CI token unharmed — **but nobody is told that**
- **Adopted form (minimal)**: append a one-line note to the end of --show-token's output
  ("this token also became this terminal's active token. If it is for another environment,
  plain re-login returns the terminal's own token" + the 2 harms of sharing). SELF_HOSTING's
  supply procedure gained a final step (plain login once more). The note is pinned by a test
- **Rejected**: (a) keying the keychain slot per token name — session resolution would come
  to need choosing "which name to authenticate as", a wholesale keying change plus ambiguity
  in the resolution path. Not worth it for inventory. (b) not saving to the keychain when
  `--show-token` is passed / a `--no-keychain` flag — the surprise of "I just wanted to
  display my token" not being saved, plus a new flag's surface growth. Guidance closes it
  well enough (the procedure becomes 2 commands, both existing ones)

### Review follow-up (Bugbot — the defect in ruling CM's note)

- **Wrong guidance when supplying under the default name**: CM's note unconditionally
  recommended a "plain re-login", but **when the supply ran under the default name
  (`cli:<hostname>`)**, a plain re-login = same-name rotation **revokes the very token just
  displayed**, disconnecting the environment it was pasted into (Bugbot finding — Medium).
  The note now branches on the issued name: for the default name "issue again under a
  different name"; for a different name "plain re-login returns the terminal's own token".
  The determination compares resolved actual names (explicitly passing the default name
  counts as the default name — it branches on fact). Both cases are pinned by tests, and
  SELF_HOSTING also gained "do not omit --token-name in the supply step"

### Convergence assessment (final)

The five generation rules (chain walk / blind spots of ruling composition / backpropagation
of the new invariant / lifecycle observers / the recommended-procedure walkthrough) were
exhausted. CM emerged from "the procedure's documentation (CK) created a new walkthrough
target" — the same structure as up through round 4 — each ruling generating the next search
target — but CM's adopted form is one line of guidance + one line of procedure, and the
scale of findings has shrunk round over round (CI: the wire surface → CL: behavior → CM:
guidance). I judge that the full credential lifecycle (issuance · supply · custody ·
observation · death · recovery · sweeping) has reached a state covered across the 4 layers:
spec, implementation, documentation, and tests.
