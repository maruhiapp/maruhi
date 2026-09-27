# Session 40: W2b — implementation rulings for session-principal capability limits (AU–AZ)

Date: 2026-08-29. Purpose: record of implementation rulings in the implementation PR (PR-W2b)
of AUTH_SPEC §5 "session-principal capability limits" (0.13-draft — PR #103 merged =
owner-approved). The norm (the enumeration of permitted and explicitly denied surfaces, the
fail-closed default) has §5 itself as its sole source of truth, and this document doesn't move
that — what gets ruled here is only the concretizations the spec explicitly delegated to
implementation rulings (expression of declarations, enforcement layer, check order, error shape,
authz reorganization, fixture-test derivation form). Each ruling follows "multiple options →
upward-compatible exploration → 3-round comparison → autonomous selection" (the session-27 §14
format. Symbols continue session-39's AT, starting at AU).

Reference material: AUTH_SPEC §5 / §11-2 / §12-3 / §12-10, ADR-0018 revision 2 (item 1),
docs/notes/web-dashboard-design.md §6–§7, session-39 (ruling AT, §10),
session-32 (the lesson of AST-annotation loss).

## 1. Ruling AU: expressing the declaration (where session-allowedness is baked)

### Round 1

- **Option AU-a: annotations on endpoint ASTs** (isomorphic to §12-10 (1)'s strictPayload:
  attach a `sessionAllowed` annotation to each endpoint definition, which the implementation
  reads) — rejected: strict's annotation was chosen because **decode's behavior itself** required
  the annotation; capability determination doesn't ride on decode (middleware reads it).
  Annotations can silently lapse under check-composition order (session-32 §2-3), and
  HttpApiEndpoint's annotation read location depends on upstream internals. There is no necessity
  to carry behavior via annotation here
- **Option AU-b: a positive-enumeration `[group, endpoint]` table in api-schema
  (`SESSION_ALLOWED_ENDPOINTS`) + a load-time sweep + middleware referencing by identifier
  directly** — the declaration lives on the contract side (api-schema) and becomes text that can
  be matched 1:1 against §5's permission enumeration. No losable intermediate representation
  (annotations)
- **Option AU-c: a second middleware (SessionDeny) individually declared on denial surfaces** —
  rejected: "forgot to attach = passes through" is fail-open, the reverse of §5's
  "default = sessions disallowed"

### Round 2 (upward-compatible exploration)

- Strengthening AU-b: a permissions list alone leaves "unauthenticated surfaces (no
  AuthMiddleware)" outside the declaration's view — a new surface whose middleware declaration
  was dropped despite intending auth-required passes through the auth gate itself before the
  session gate. **Added an explicit enumeration of unauthenticated surfaces
  `UNAUTHENTICATED_ENDPOINTS` and extended the sweep to a complete classification: "every
  endpoint either has AuthMiddleware or is on this list"** (isomorphic to strict.ts's 2-list
  classification). Adopted
- Option of keeping an explicit-denial list (a copy of §5's "in particular, the following are
  explicitly denied") on the declaration side — rejected: behavior is complete as "outside the
  permission enumeration = denied"; a denial list would be a second source of truth contributing
  nothing to behavior (a missed update could make the declarations contradict). Matching against
  the spec text is the fixture-side pin's (AZ) job

### Round 3 (re-check)

- Consistency with §5's implementation-form recommendation ("declarations baked into the endpoint
  contract = single implementation point"): the contract = the api-schema package, and the table
  is part of the contract (the SECURITY_CRITICAL_PAYLOAD_ENDPOINTS precedent). The enforcement
  point is the single middleware (AV), satisfying "single implementation point"
- Confirmed the sweep's check content: permission enumeration's existence + AuthMiddleware
  presence (rejects stale entries, renames, permission designations on unauthenticated surfaces),
  unauthenticated enumeration's existence + AuthMiddleware absence, complete classification of
  all surfaces. Runs at import time right after `maruhiApi` construction (same position as the
  strict sweep)

**Choice: AU-b + round 2's complete-classification extension**. Implementation:
`packages/api-schema/src/session-capability.ts`.

## 2. Ruling AV: the enforcement layer (where denial happens)

### Round 1

- **Option AV-a: inside the AuthMiddleware implementation (right after authentication)** —
  Effect v4's HttpApiMiddleware receives a second argument `options: { endpoint, group }`
  (upstream `HttpApiBuilder.applyMiddleware` — confirmed by implementation check), so the
  existing auth middleware can draw the declaration by endpoint identifier. A single
  implementation point with zero added middleware declarations / handler changes
- **Option AV-b: checks in each handler / authz helper** — rejected: the "per-handler manual
  check" §5 explicitly dismissed, verbatim
- **Option AV-c: path-matching in the raw HTTP layer before routing (index.ts's fetch)** —
  rejected: it would hold a second router (duplicate patterns) independent of api-schema's route
  definitions, and divergence in path interpretation becomes a new lapse surface

### Round 2 (upward-compatible exploration)

- Considered the position within AV-a: middleware is applied wrapping the handler effect
  (including payload decode), so capability denial is settled **before Schema decode**. Sending a
  huge body at a denial surface doesn't pay decode cost (also the right direction for resource
  protection). §12-3's check order is "auth → size → scope → ...", but the size check (413) is
  decided by the HTTP raw-body cap (index.ts), and capability determination doesn't depend on
  request content, so no order conflict arises
- Defense in depth: if the declaration layer were the only enforcement point, a regression in
  middleware application itself (e.g. `.middleware(AuthMiddleware)` dropped from an endpoint
  definition) would erase every gate. The sweep (AU — unclassified surfaces crash at import) and
  the matrix test (AZ — the behavior side) catch this doubly. An added second enforcement layer
  stays limited to AY's `ensureKeyMaterialAccess` inversion (same direction, unreachable
  fail-closed)

### Round 3 (re-check)

- The middleware `options` argument is part of the type
  (`HttpApiMiddleware<Provides, E, R>`)'s public signature, not a dependency on internal API.
  identifier is a public property of group / endpoint
- It's an addition to existing middleware; Layer wiring and endpoint definitions are unchanged

**Choice: option AV-a**. Implementation: `authMiddlewareImpl` in
`apps/server/src/auth.package/middleware.ts` (order: auth → capability → CSRF).

## 3. Ruling AW: check order (consistency with §11-2's existence concealment and §12-3's check order)

### Round 1

- **Option AW-a: auth (401) → capability (403) → CSRF (403) → handler (existing check order)** —
  the capability check's material is only (principal kind, endpoint identifier) = computable from
  the request's content alone, referencing no project existence or state. By the same argument as
  §12-3's exception allowing auth-first (1a — AAD coordinate-match check), placing it anywhere
  doesn't break existence concealment, but frontmost (right after authentication) has the
  smallest attack surface
- **Option AW-b: CSRF → capability** — rejected: the response reason on denial surfaces would
  wobble on the presence of "a header the attacker can attach themselves". Capability denial is
  an invariant fact determined by principal and endpoint alone, and putting it ahead of
  variable-condition checks is the fail-closed order. Practically, the denial-surface fixture
  tests stop depending on CSRF-header combinations
- **Option AW-c: the same position as token-scope determination (the authz stage inside the
  handler)** — rejected: reaching the handler = dispersing the check point per handler (AV-b
  again). Also, a session's capability — unlike scope — is project-independent, so there's no
  reason to drop down to project context

### Round 2 (upward-compatible exploration)

- Re-verifying existence concealment: denial is a uniform 403 (invariant, including the reason)
  for all project IDs and all resources, satisfying "the same response to a principal that knows
  nothing" with the same information content as 404. Conversely, on permitted surfaces
  (membership.get etc.) sessions still flow to non-member 404 (§11-2) as before — the capability
  gate is an independent layer ahead of existence concealment and doesn't touch concealment
  determinations
- §12-7's CSRF requirement for value-bearing pulls (sessions only) is per §5 "defenses that
  precede it + insurance against future relaxation — not removed" — the in-handler
  `statefulGetCsrfViolated` call **stays** (unreachable under the capability gate, but keeps the
  CSRF layer independently alive should a future revision loosen §5)

### Round 3 (re-check)

- The position — after 401, before all 403s — is also consistent with §14-3's precedent (auth
  attribution failure = 401 first). Only the ordering of CSRF's 403 vs capability's 403 was a new
  ruling point, and AW-b's rejection reason decided it
- Because denial is settled before the handler, no audit row (var.read etc.) is ever written —
  naturally consistent with "don't record reading what wasn't read" (AUDIT_SPEC §3.3)

**Choice: option AW-a** (+ keeping the CSRF insurance).

## 4. Ruling AX: error shape (status and reason)

### Round 1

- **Option AX-a: uniform 403 `ForbiddenError` + new reason `session-not-allowed`** — matches the
  design doc §7 (W2b)'s explicit "403 denial". A uniform response depending only on endpoint
  identity is compatible with existence concealment (AW). When W2 (web screens) is implemented it
  enables wording like "this operation can't be done from the web (use the CLI)"
- **Option AX-b: uniform 404** — rejected: existence concealment's essence is "being uniform",
  not that it must be 404, and on project-unrelated surfaces (`/auth/recovery` etc.) 404 collides
  with "unregistered" (existing contract). Existing denials in §13-2's table are also 403
  (insufficient-permission); 404 is inconsistent
- **Option AX-c: reusing the existing reason `insufficient-permission`** — rejected: token
  insufficiency (raising the scope gets you through) and capability limits (no session ever gets
  through) carry different implications for the client. CLI failure display, web wording, and
  fixture-test discrimination all depend on the reason, so a dedicated reason is
  upward-compatible

### Round 2 (upward-compatible exploration)

- Compatibility of the reason addition: adding a literal to ForbiddenReasonSchema is an
  addition on the response side. The only path where an old CLI decodes the new reason is "an old
  CLI calling with a session", but the CLI is always token-principled (§5) so it never occurs.
  Request payload schemas are unchanged (no change to §12-10's strict classification — this PR's
  declaration change is one error-reason literal only)
- Dedicated error class (SessionNotAllowedError) option — rejected: AuthMiddleware's declared
  error set (Unauthorized / Forbidden) is automatically on the contract of every auth-required
  surface, and adding a reason to the existing class means **zero changes to every endpoint's
  error declarations**. A new class would require adding error declarations to all surfaces
  (wire-contract inflation) and only widens the additive-verification surface

### Round 3 (re-check)

- Denial surfaces include ones that conventionally didn't return Forbidden
  (`membership.attest` / `auth.revokeToken` etc.), but via AuthMiddleware's middleware
  declaration the 403 is already within the contract of all auth-required surfaces (CSRF 403
  rides the same path) — nothing new added contractually either
- `auth.revokeToken`'s session denial was conventionally an in-handler 403
  (insufficient-permission) — being moved earlier to middleware's 403 (session-not-allowed)
  changes only the reason; status-compatible (the handler's token-principal-only check remains
  for non-session abnormal paths)

**Choice: option AX-a**.

## 5. Ruling AY: reorganizing existing authz (no double source of truth with the declaration)

### Round 1

- `ensureKeyMaterialAccess`'s "session = always allowed" branch flatly contradicts §13-2 /
  §15-2's revision (tokens only) — removal is mandatory (as the task specified). The behavior on
  post-removal session reach is the ruling point:
  - **Option AY-a: deny with 403 session-not-allowed (an unreachable fail-closed second
    layer)** — redundant in the same direction as the declaration layer, and not a "double source
    of truth" (the source of truth is the declaration; this is insurance that tilts toward
    closing, not opening, should the declaration layer ever be bypassed)
  - **Option AY-b: make session reach a defect (500)** — rejected: would emit a user-visible 500
    on a (hypothetical) declaration-layer regression. No reason to choose a crash over denial
    where denial is possible
  - **Option AY-c: exclude sessions at the type level (narrow the argument to token
    principal)** — rejected: "proof of not being a session" (narrowing + else branches) would
    disperse across the 3 call sites — you end up writing the same branch as AY-a per call site

### Round 2 (upward-compatible exploration)

- `audit.self` (self-axis audit) shared the same function, but there sessions are the norm (§5's
  permission enumeration "audit read" / AUDIT_SPEC §6 self viewing). **Split the functions**:
  `ensureKeyMaterialAccess` (key-material class — sessions denied) and `ensureSelfAuditAccess`
  (self audit — sessions allowed + tokens need `*` × admin). The option of giving one function
  both semantics via a bool flag was rejected (a flag mistake at a call site becomes a permission
  bug as-is — pin semantics by name)
- **Kept** the session pass-through in `ensureTokenScopeForProject` /
  `tokenScopeAllowsForProject`: the legitimate shape on permission-enumeration surfaces (reads +
  revocation family) (sessions hold no scope; the chain role binds — §9-2). Updated comments to
  reference §5, noting the pass-through is "limited to permitted surfaces that already passed the
  declaration layer"

### Round 3 (re-check)

- Confirmed no function where session denial actively operates remains in authz (single
  enforcement point): `ensureKeyMaterialAccess`'s branch is unreachable (the matrix test pins
  middleware-stage denial on those 3 surfaces — recoveryPut / recoveryGet / invites.accept) and
  doesn't affect check order or response shape
- `handlers-auth`'s logout (session-principal normal path) and revokeToken (token-principal-only)
  in-handler branches are semantics independent of capability limits — unchanged

**Choice: AY-a + function split**.

## 6. Ruling AZ: the derivation form of fixture tests

### Round 1

- **Option AZ-a: test with hand-written endpoint enumeration** — rejected: the shape the task
  explicitly forbids (can't detect declaration misses / baked-declaration lapse)
- **Option AZ-b: a mechanically derived matrix from `maruhiApi.groups`** — enumerate group /
  endpoint / method / path / AuthMiddleware presence at runtime, fix-substitute path parameters
  (`:projectId` → real fixture, `:environmentId` / `:variableId` / `:id` → fixed values; unknown
  parameters fail loud), and send through the real workerd path. Denial surfaces (= auth-required
  ∖ permission enumeration) get exact-match 403 + reason; permitted surfaces are checked for "not
  session-not-allowed"
- **Option AZ-c: unit tests of the declaration (sweep) only** — rejected: a repeat of
  session-32's lesson (testing the declaration's presence doesn't detect enforcement-path lapse).
  The sweep is a precondition that runs at import; tests pin the behavior side

### Round 2 (upward-compatible exploration)

- 3 strengthenings of AZ-b (adopted):
  1. **Spec-match pin**: text-pin that §5's explicit-denial enumeration (value-bearing pull, the
     DEK 3 surfaces, chain append / init, environment-variable mutation, invite issuance /
     acceptance, rotation dismiss, the recovery 2 surfaces) is not included in the permission
     enumeration — detects "mistaken additions to the permission list" from the spec-text side,
     independent of mechanical derivation
  2. **Token-principal full-surface regression**: send to all auth-required surfaces with a token
     and verify session-not-allowed is never returned (no CLI impact — fixing §5's "CLI and
     `maruhi ui` are token-principled and unaffected"). `auth.revokeToken` revokes the presented
     token itself, so it's sent last
  3. **Check-order pin**: denial surfaces return session-not-allowed even without CSRF headers
     (AW's capability-first), and a permitted-surface write (logout) still gets CSRF 403
     (insurance layer preserved)
- Permitted surfaces' normal paths (200) stay with the existing suite + a representative-surface
  positive control (forcing all-surface 200 in the matrix would drag endpoint-specific fixtures
  into the matrix and reintroduce hand-written enumeration)

### Round 3 (re-check)

- Confirmed the inversion points of existing tests from the spec side: the existing tests of
  session init / env create / value-bearing pull / invite acceptance / recovery registration get
  are tests of "before W2b, sessions were allowed" (§13-2 / §15-2's note) behavior, so inverting
  them is spec-following itself. Each test is rewritten into "uniform denial regardless of CSRF
  presence + the same body passes with a token (proving the denial is session-principal-caused)"
- The session-actor DO-side audit (env.created's authMethod payload) disappears along with the
  surface itself, so that test inverts to "denial + no audit row". Session-actor audit
  attribution is carried on by the D1 side (auth.*) and by a new test of invites.revoke — the
  only remaining session mutation (actor = user_id + authMethod, no token id)

**Choice: option AZ-b + the 3 strengthenings**. Implementation:
`apps/server/test/session-capability.test.ts` (+ inversion updates: the membership /
data-dek / data-variable / invites / audit / recovery tests).

## 7. Deliverable summary

- **api-schema**: `session-capability.ts` (SESSION_ALLOWED_ENDPOINTS = the 12 implemented
  permitted surfaces / UNAUTHENTICATED_ENDPOINTS = the 5 unauthenticated surfaces / predicates /
  load-time sweep), `session-not-allowed` added to ForbiddenReasonSchema (response-side addition
  only — payload schemas and strict classification unchanged)
- **server**: capability check in `authMiddlewareImpl` (auth → capability → CSRF),
  `ensureKeyMaterialAccess`'s session branch inverted, `ensureSelfAuditAccess` split,
  comments updated to follow §5 (removed the "self full-power" phrasing)
- **CLI**: no behavior change (token-principled). Only the session mention removed from the
  invite-accept 403 guidance text
- **tests**: the mechanically derived matrix (22 denial surfaces × session, 12 permitted surfaces
  × session, 34 auth-required surfaces × token regression, check order, positive control) +
  inversions / supplements to the existing 6 files
- **No spec changes**: no ambiguity requiring a clarifying note in §5 was found during
  implementation (error shape and check order fall within what §5 delegated to implementation
  rulings — recorded by this document)

## 8. Handoffs

1. **The implementation PRs of W2a (project list) and W3a (token list / designated revocation)
   are already listed in AUTH_SPEC §5's permission enumeration, so the addition to
   `SESSION_ALLOWED_ENDPOINTS` happens in the same PR** (the fail-closed default means the
   default is 403 — forgetting the addition surfaces via the matrix test's permitted-surface
   count expectation, not the sweep)
2. Session list / designated revocation (S10) requires §5 revision first (as per design doc §8)
3. The in-handler `statefulGetCsrfViolated` calls (value-bearing pull, recoveryGet) are
   unreachable under the capability gate but intentionally retained per §5 / §12-7's "don't
   remove implemented defenses" discipline — a future removal proposal requires re-ruling that
   discipline
