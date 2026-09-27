# Session 42: W2a — design rulings for the project-list API (BI–BL)

Date: 2026-08-29. Purpose: record of design rulings in PR-W2a (web-dashboard-design.md §7).
Target: S4 (project list)'s missing API — "the list of projects where the caller is a
chain-derived member" — its server-side derivation form, endpoint spec, and the projection's
maintenance discipline. The norm's home is AUTH_SPEC §11-5 (drafted in this PR — merging the
implementation PR containing this revision counts as owner approval); this document records the
rulings' course (options considered, rejection reasons). Each ruling follows "multiple options →
upward-compatible exploration → 3-round comparison → autonomous selection" (the session-27 §14
format. Symbols continue session-41's BH, starting at BI).

Reference material: AUTH_SPEC §5 / §9-2 / §11-2 / §11-3, CRYPTO_SPEC §6.4 (the chain is
authorization's source of truth; the ban on two sources of truth), web-dashboard-design.md §3 S4
and §7, session-39 §10-1 (adding W2a to §5's permission enumeration), session-40 (W2b —
baked-in declarations, the fixture-test form), AGENTS.md / CLAUDE.md.

## 1. Ruling BI: the list's derivation form (D1 projection vs fan-out vs composite)

Compared the design doc S4's enumerated 2 options (D1 projection / org-mediated candidate
enumeration + DO-confirmation fan-out) plus upward-compatible candidates. Required conditions:
compatible with §11-2 (existence concealment) and "what's returned is only the caller's own
membership".

### Round 1

- **Option BI-a: org-mediated candidate enumeration + confirmation fan-out to DOs** —
  `/auth/me`'s orgs → D1 `projects` (org attribution) → membership confirmation against each
  project DO. **Rejected (on correctness, not performance)**: chain membership is
  org-independent (as the contrapositive of AUTH_SPEC §9-2's "org joining grants no project
  access automatically", **chain members of out-of-org projects legitimately exist** — the
  invite flow §15 never looks at the invitee's org). Org-mediated candidate enumeration
  structurally drops invite-path cross-org members (precisely P5's — stakeholders who don't
  install the CLI — main use). Extending to scanning all projects is an O(all projects) fan-out —
  out of the question
- **Option BI-b: create a D1 projection of membership (a derived cache maintained at chain
  acceptance) and make the list a pure D1 read** — the cross-cutting index resolves in one
  query. But DO (chain acceptance) and D1 (projection) are separate transactions, and the
  dual-write lapse window remains in both directions: add_member accepted + projection insert
  failed = absent from the list (missing); remove_member accepted + projection delete failed =
  an expelled member stays in the list (ghost). The ghost direction has no self-healing path, and
  "only the caller's (current) membership is returned" is broken for exactly the D1-failure
  window
- **Option BI-c (prototype of the adopted shape): demote the D1 projection to a candidate index
  and confirm each candidate against the DO at list time (the existing RPC `memberRoleFor` —
  the same one as the invite API's authz input)** — responses always carry acceptance-time
  chain-derived truth (role included). A candidate row the DO answers non-member gets deleted on
  the spot (ghost self-healing). The fan-out is bounded to "the caller's own projection rows"
  and lacks BI-a's candidate-enumeration incompleteness (org dependence)

### Round 2 (upward-compatible exploration)

- **Minimizing BI-c's projection schema**: a **set of (project_id, user_id) only**, with no
  role or status columns. Since the confirmation RPC returns the current role value, all
  projection-follow-up code for `change_role` becomes unnecessary, and the projection's
  maintenance points shrink to 2 kinds: "insert into the set (genesis / add_member)" and "remove
  from the set (remove_member)". Adopted
- **Reusing D1 `invitations` (no new table)**: the option of drawing candidates from completed
  invites' invitee_user_id — rejected: genesis actors (owners of projects they created
  themselves) have no invite row, so the most frequent case is missing from the start. Adding
  org-mediated enumeration for completion brings back BI-a's incompleteness, and invite-row
  expiry / cleanup couples accidentally with membership lifetime (the bad form of a second
  source of truth)
- **List from CLI local pins only (non-secret local state)**: the option of building no server
  API — rejected: W2 (web S4) doesn't stand (the browser has no local floor). CLI-only demand
  could get a pin-derived display later, but it fails this task's purpose (S4's prerequisite API
  + verification with the CLI as first consumer)
- **Placing the projection in a DO (a singleton reverse-lookup DO)**: rejected: project DO →
  reverse-lookup DO cross-DO writes keep the dual-write problem identical to D1's, and only add
  a hotspot singleton DO plus a new entity. User-axis queries' existing home is D1 (cohabiting
  with auth / sessions)

### Round 3 (re-check)

- **Consistency with existence concealment (§11-2)**: the endpoint takes no project ID (no
  target specifier in path or query) and the response contains only the caller's own rows —
  structurally no surface for a non-member to probe the existence of arbitrary IDs. Projects
  outside the token scope simply don't appear in the response (same information content as the
  elsewhere "out of scope = 404")
- **Consistency with the ban on two sources of truth (CRYPTO_SPEC §6.4)**: the projection is
  **a derived cache for discovery only** and is used in no authorization determination
  (authorization / role stay chain-derived state in each DO as before; the role in list
  responses is the DO confirmation's return value). It doesn't constitute "an independent
  permission table contradicting the chain on project access" — a contradicting row loses to the
  DO at read time and gets deleted
- **DO-instantiation concern (is this the same shape as AUTH_SPEC §14-3's DO mass-production?)**:
  projection rows are born only from already-accepted chains (init / add_member), so there's no
  path where the confirmation fan-out instantiates a DO for an unknown ID
- **Cost boundedness**: the confirmation fan-out is per-request candidate-page cap (BK — 100) ×
  DO RPC. Candidates are only the caller's own membership rows — no one else can inflate them
  (inflating your own only grows your own paging). Against the Workers subrequest cap (1,000),
  the page cap also works as a breakwater

**Choice: BI-c (role-less D1 projection = candidate index + read-time DO confirmation)**.
BI-b's "projection = truth" shape can never skip confirmation on any read (expulsion ghosts
don't self-heal) — inferior; BI-a fails on correctness. The adopted shape is a **composite** of
"create a D1 projection" and "confirmation fan-out to DOs" with a narrower lapse window than
either of S4's two options alone.

## 2. Ruling BJ: the projection's maintenance points, repair, and migration

### Round 1

The projection (`project_members(project_id, user_id, created_at)`)'s maintenance points:

- **init (genesis acceptance)**: insert the genesis actor (owner)'s row in the same D1 batch as
  the worker's `projects.insertIfAbsent` (atomicity of projects row and projection row — same
  batch on §11-3's idempotent-repair reinsertion path too)
- **After accepting append's add_member**: upsert (INSERT OR IGNORE). At the same position and
  for the same reason as the invite-completed match (the existing exception in
  handlers-membership.ts), **swallow the defect and move on**: the chain is already final, and
  propagating a D1 failure to the response makes a successful append look like a 500 whose retry
  becomes a ChainHeadConflict. The failure's consequence is only a visible, repairable display
  gap — "doesn't appear in the list" (access itself stands on chain truth) — and the repair path
  (below) closes it
- **After accepting append's remove_member**: delete (same defect-swallowing position). The
  failure's consequence is a ghost row, but BI-c's read-time DO confirmation excludes it from
  responses + deletes the row, so **the list's correctness doesn't depend on this delete's
  success** (the delete is hygiene / candidate-set shrinkage)

### Round 2 (upward-compatible exploration — repair / migration paths)

- **Self-healing of the missing direction + migration of existing projects**: lazy-upsert the
  projection row when a chain fetch (`membership.get`) succeeds (one INSERT OR IGNORE statement,
  defect swallowed). A get success = the DO already confirmed chain-derived membership, so it
  can't work in the ghost-creating direction. With this: (a) a missing caused by a D1 failure at
  add_member self-heals on the subject's next sync; (b) **existing projects created before the
  projection's introduction (the dogfooding environment) get backfilled unattended on each
  member's next chain sync** (no dedicated migration script or explicit init operation — the
  reason §12-5 (6)'s manifest-v1 migration needed an explicit operation was that issuing a signed
  structure was required; the projection is an unsigned derived cache, so automatic suffices)
- Scope note: the task's out-of-scope clause is "behavior changes to existing endpoints (...except
  adding projection maintenance to the chain-acceptance path when adopting the D1 projection)".
  The get-side lazy upsert isn't an acceptance path, but it's **projection maintenance proper
  that changes no wire behavior (response, errors, check order) at all**, and without it
  migration becomes manual work — taken on the side of the exclusion clause's intent
  ("projection-maintenance additions are allowed") — noted explicitly in the PR description
- **Bulk backfill script (scanning all projects)**: rejected — lazy upsert doubles as permanent
  self-healing, while a script only adds a one-shot operational procedure without narrowing later
  lapse windows
- **Writing the acceptance-side upsert from inside the DO to D1 (single-transaction-izing)**:
  rejected — DO SQLite and D1 are separate stores; atomicity was impossible from the start.
  Bringing a D1 dependency into the DO widens chain acceptance's failure surface to D1
  availability (polluting acceptance's authority). The worker-side after-commit position (same
  as invite-completed) is correct

### Round 3 (re-check)

- Failure-direction summary: missing = display gap (self-heals on next sync), ghost = excluded
  at read time (never appears in the response) + row deleted. **Under neither window can the
  response invariant "only the caller's current membership" be broken** (what can break is only
  completeness, and self-healing)
- No FK on the projection row (same reason as invitations: a derived cache must not impede
  acceptance / repair via referential integrity). No join against the projects row is needed for
  the response (BK's minimal response uses no projects-row columns), so it doesn't interfere with
  §11-3's partial-failure window either
- Audit: projection upserts / deletes write no audit events (the evidence of chain acceptance is
  already carried by the `chain.member_added` / `chain.member_removed` mirrors. Derived-cache
  convergence is like §12-6's old-key-wrap cleanup — not action information in itself — and
  unlike cleanup, the deletion target is "a by-definition invisible row", so it needs no visible
  event like dek.deleted either)

**Choice: BJ = 3 acceptance-path points (init same batch / add upsert / remove delete) +
lazy upsert on get success (migration / self-healing)**.

## 3. Ruling BK: endpoint shape, response, authorization, acceptance policy

### Round 1

- **Placement**: `GET /projects` (membership group, endpoint name `list`). A GET on the same
  resource as init (`POST /projects`) — REST-natural — and since it's a chain-derived-membership
  surface, the membership group is semantically right. The `/auth/projects` (auth group) option
  was rejected — §6's `/auth/tokens` lists the auth resource (tokens) itself, whereas this is a
  chain-derived project surface
- **Response (minimal form)**: `{ projects: [{ projectId, role }], nextAfter? }`. role is the
  DO confirmation's return value (acceptance-time chain-derived role). **No org info, creation
  time, or head info** — pinned to minimal from two sides: don't newly disclose other orgs'
  attribution info to cross-org members (the subject of BI-a's rejection reason), and don't
  duplicate onto the list what S5 (overview) onward carries. Extension stays possible additively
  (optionalKey)
- **Authorization**: session principal = allowed (§5's permission enumeration — added to
  SESSION_ALLOWED_ENDPOINTS in the same PR. session-39 §10-1 / session-40 handoff 1). Token
  principal = intersect with scope — of the candidates, only respond with ones satisfying
  `tokenScopeAllowsForProject(id, read)` (a `*` scope gets all; a project-scoped one gets only
  that project). Out of scope is **non-appearance**, the same information content as the
  elsewhere "out of scope = 404" (§11-2)

### Round 2 (upward-compatible exploration)

- **Paging**: `after` (optional query, projectId-exclusive cursor) + a server-fixed page of 100
  (candidates-basis, project_id ascending). `nextAfter` (= the page-tail projectId) is returned
  only when the D1 page is full. Bounds one call's DO confirmations to 100 (puts the
  Workers-subrequest-cap breakwater on the contract side). No client-specified limit (don't
  create a knob pointing toward inflating the acceptance-policy value). Order is project_id
  ascending (stable, unique); display-order processing is the client's domain
- **Rate limiting**: none. No enumeration attack surface (responses are only the caller's own
  rows, no target specifier), cost is bounded by the caller's own projection-row count (can't be
  inflated by others), and the per-call cap is bound by page-100 — unlike §13-3 (monitored
  blobs) or §15-2 (issuance), there's no scarce resource or concealment target to protect.
  Introduction remains possible as a future addition
- **CSRF header (session principal)**: not required. The "state" in §11-4's "stateful GET"
  refers to writing audit rows / counters, and this endpoint writes neither. Ghost rows'
  read-time deletion is the derived cache converging to chain truth (the same class as §12-6's
  old-key-wrap cleanup and §16-1's declared-row deletion) — even if induced cross-site, the same
  convergence as a legitimate list occurs, so there's no attack gain
- **No 404-class errors at all**: with no target specifier, ProjectNotFound structurally can't
  occur. Declared errors are only AuthMiddleware-derived (401 / 403)

### Round 3 (re-check)

- DO confirmation's denial vocabulary: `memberRoleFor`'s denials are only not-member /
  not-initialized (floor reader = being a member. Since every member is reader or above,
  insufficient-role never occurs). Both mean "the candidate row is stale", so they're folded
  into row-delete + non-appearance. Other denial kinds are invariant violations = defect
- Concurrency: DO confirmations are issued with bounded parallelism (implementation value 10 —
  one user's list doesn't instantiate 100 DOs simultaneously). Confirmations are read RPCs; the
  DO side follows its existing permit serialization
- Is it a §12-10 (1) strict target: no — it's a GET carrying no security-critical mutation
  payload (no strictPayload needed)
- Connection to the W2b matrix test: the SESSION_ALLOWED_ENDPOINTS addition automatically
  enrolls it in the machine-derived matrix's permitted surfaces (session-not-allowed not
  returned, not 401). No path parameters means the concreteUrl substitution table needs no
  additions either

**Choice: BK = `GET /projects` (membership.list) + minimal response + scope intersection +
cursor paging (fixed 100) + no rate limit / CSRF**.

## 4. Ruling BL: fixture-test form

- **Own membership only / existence concealment**: a 2-user × 2-project cross fixture pins that
  each principal's list returns only their own memberships (others' projects never appear at
  all, including status)
- **Expulsion follow-through**: add_member accepted → appears in the list (role included) →
  change_role accepted → role follows (doubles as verification that the projection has no role
  column) → remove_member accepted → gone from the list (the task's specified fixture test)
- **Read-time exclusion of ghosts**: create a state where only the projection row remains while
  the DO side is non-member (re-insert the projection row directly after a remove_member
  acceptance), pinning that the list converges via exclusion + row deletion (the key of BI-c —
  proof of real behavior that correctness doesn't depend on the D1 delete's success)
- **lazy upsert (migration path)**: delete the projection row directly → list is empty
  (reproduces the missing window) → chain fetch succeeds → returns to the list (the same path as
  unattended backfill of existing projects)
- **Token-scope intersection**: a project-scoped token gets only that project; `*` gets all.
  read suffices as the level (every scope is read or above)
- **Paging**: nextAfter chaining across the page cap, full traversal, and ordering (project_id
  ascending) — but since creating 100+ real projects is heavy, don't make the page constant
  injectable (respect the acceptance-policy bake-in); construct "full page + nextAfter" by
  composing direct projection-row inserts + ghost exclusion
- **Session permission**: session-capability.test.ts's machine-derived matrix automatically
  picks up the SESSION_ALLOWED_ENDPOINTS addition (the permitted-surface count expectation is
  the enumeration's length, so no hand-written follow-up occurs). Added the list's 200 to the
  positive control

## 5. Post-implementation re-check (one more pass of upward-compatible exploration — task procedure 7)

One pass after implementation completed (all server 7 tests + CLI 3 tests passing). The core
rulings (BI-c / BJ / BK) stand. Candidates, including rejected ones:

### 5-1. Exploration 1: bundling head info into the list response (rejected)

A candidate where carrying headSeq / headHashHex on each row would let the CLI warn "sync is
stale" in the list. Rejected: requires adding head to memberRoleFor's return, and the
response's "server-declared head" without verification adds no fork-attack detection (same
argument as CRYPTO_SPEC §6.6's rejection of bundled leases — only the mistaken sense of
"verified" grows). CLI freshness checks stay the domain of the existing `project verify` / floor.

### 5-2. Exploration 2: omitting the confirmation fan-out (regressing to projection = truth; rejected)

The list's dominant cost is DO confirmation, but in measurement (vitest-pool-workers) the
worst shape — a full page of 100 candidates all being uninitialized DOs (cold start + instant
denial) + 1 extra page — completes in ~1.1 seconds including test scaffolding, not a cost level
worth trading correctness (closing the ghost window) for. The list is low-frequency (dashboard
display, explicit CLI operation). The page-100 × concurrency-10 shape stands.

### 5-3. Exploration 3: bundling counts into the `me` response / folding the list into `/auth/me` (rejected)

The option of absorbing projects into `/auth/me` permanently adds DO-fan-out cost to me
(authentication self-info — on every call), and mixes W2b's permission-enumeration granularity
(me is auth-family; the list is read-family). Separation stays.

### 5-4. Exploration 4: conditional-izing the lazy upsert (rejected)

The option of turning the per-fetch projection upsert (one INSERT OR IGNORE) into "write only
when the row is absent" (read first + branch). Rejected: D1 read + conditional write moves
toward more statements; INSERT OR IGNORE's no-op side is already minimal cost. The fetch path's
dominant cost is the DO RPC (carrying the whole chain); one D1 upsert statement doesn't change
the order.

### 5-5. Exploration 5 (review follow-up): nextAfter leaking out-of-scope IDs (defect fix)

PR #106's Cursor Security Agent finding (MEDIUM). The initial version derived `nextAfter` from
the candidate page's tail **before** scope intersection and DO confirmation, so a scoped token
got "project_ids in the caller's projection but out of scope" (ID = genesis hash = effectively a
capability) leaked via the cursor — a self-made violation of §11-5's "out of scope =
non-appearance" (ruling BK round 2 decided "pages are candidates-basis" first, and round 3 never
checked the cursor's contents as an information-disclosure surface).

Fix comparison:
- **Cursor on confirmed rows + continue scanning inside the server** — rejected: with a long
  tail of ghosts / out-of-scope rows, one call's scan is unbounded, and bounding it makes the
  cursor stop advancing (a truncation-position cursor carries the same leak)
- **Opaque cursor (encrypted)** — rejected: adds key management and implementation surface, and
  the leak's root is "the candidate space is wider than the scope" — concealment isn't a cure
- **SQL-level intersection of the candidate enumeration (adopted)**: pass the project-ID list the
  token scope names (schema cap 100 entries) into the candidate query's `IN`, closing the
  candidate space itself inside the scope. `nextAfter` then carries only in-scope IDs by
  construction. `*` scope and sessions are unlimited (the full set is the principal's rightful
  view). The conventional predicate application on response rows stays as defense in depth

Residual (accepted, noted in §11-5): a session / `*`-scope principal's `nextAfter` can carry
IDs of the caller's own stale ghost rows, but they come from the caller's own membership history
and carry no new information. Added a regression test (100 out-of-scope candidates + a scoped
token → no out-of-scope ID appears in any response field).

Supplement (pullfrog round-3 proposal): don't swallow the isolation's catchDefect silently —
same discipline as worker-env.ts's fail-open warning: leave only a static message + error kind
name in Workers logs (no request-derived identifiers. Since a corrupted chain's die is
deterministic and the omission could become permanent, an operator signal is needed). Also made
explicit in §11-5: "a full DO-layer outage becoming `200 { projects: [] }` = the
under-reporting failure direction is an intended contract including full outage" (so W2's
implementation doesn't re-rule it; the distinguishing response shape was rejected because it
exposes unconfirmed candidate IDs on the wire).

### 5-5b. Review follow-up 2: per-candidate isolation of confirmation defects (defect fix)

pullfrog finding. The initial version let confirmation-RPC (`rpcCall` = Effect.promise) defects
pass through `Effect.forEach`, so **one candidate DO's unreachability / stored-chain corruption
made the entire list a 500** (an asymmetry where every other cross-boundary write swallowed
defects, yet this read alone let one item sink the aggregate). Fix: swallow confirmation-RPC
defects per candidate and **only exclude that row from the response while retaining it** (ghost
deletion only on the DO's explicit non-member answer — the row can reappear after the fault
recovers. The option of adding "enumeration of unreachable rows" to the wire was rejected: it
would put DO-unconfirmed candidate IDs on the wire, breaking the invariant "only confirmed rows
appear in responses"). The die on an unexpected rejection kind (the contract-violation detection
line) stays outside the isolation, loud. The failure direction is "looks smaller" only.
Regression test: mix a corrupted-chain DO into the candidates, pinning that the rest of the
enumeration still works + the row is retained.

### 5-5c. Review follow-up 3: correcting the no-rate-limit rationale (spec wording)

pullfrog finding. "The projection-row count can't be inflated by others" is inaccurate — §11-1
doesn't require an accepted invite for add_member acceptance, so an admin of another project who
knows the caller's public key can inflate the row count via unconsented add_member. Replaced the
rationale with "the per-call cost cap is bound by the fixed page (independent of row count)" and
noted the residual in §11-5 (visible injection of junk memberships = griefing class; at the
attacker's own expense; the list if anything visualizes unconsented additions).

### 5-5d. Review follow-up 4: scope-intersection IN exceeding D1's parameter cap (defect fix)

pullfrog finding (incremental review of 5-5's fix eee24e3). D1's bound-parameter cap per query
is 100, and the token scope's schema cap is also 100 entries — a single `IN` hits 103
parameters worst-case together with userId / after / limit, making **a legitimately issued
wide-scope token's list hard-fail** (confirmed by measurement that a 103-parameter query is
actually rejected by the test environment's D1 simulator too — the basis for the boundary
test's falsifiability).

Fix comparison:
- **userId-only scan + application-side intersection** — rejected: reintroduces the same
  unbounded-tail problem as 5-5's rejected confirmed-row cursor
- **Chunking the IN (adopted)**: split the scope ID list at chunk width 50 (parameter budget
  100 − 3 for userId/after/limit, with headroom), issue each chunk with the same cursor and same
  limit → concatenate + sort the whole + limit-cut. Chunks are mutually disjoint ID sets, so
  they give the same page as a single query. The loop form is also safe for stored wide scopes
  from before the issuance cap (2026-08-27 S7). The mutual dependence of caps (scope cap ⇄ chunk
  width ⇄ D1 budget) is baked into the chunk constant's comment

Regression test: pins success on all pages (worst-case parameter count including after) with a
100-scope token at the schema cap.

### 5-6. Exploration 6: a platform mechanism making the projection unnecessary (rejected)

Durable Objects have no primitives of the kind "enumerate entities in a namespace" or "tags /
reverse index" (only resolution by specified name), so putting the user-axis cross-cutting query
in D1 is the only implementable form. Projections to KV / R2 are inferior to D1 on both
atomicity (init's same batch — BJ (1)) and index queries. No silver bullet.
