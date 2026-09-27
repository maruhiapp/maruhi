# Session 45: W3b — implementation rulings for the revocation-family screens (S8 invite management, S9 token management) (CN onward)

Date: 2026-08-30. Target PR: PR-W3b (design doc §7's item 6 — **web only**.
No server / CLI / crypto changes; api-schema is consumed via existing exports
only). The final PR of the W series, consuming W3a's (PR #108) API. The
format is the usual "multiple options → strictly-better search → 3-round
comparison → autonomous choice" (session-27 §14's format. Letters continue
from session-44's CM to CN onward). Norms = ADR-0018 revision 2 (no
issuance-family / warning-dismissal / chain-writing; server-claim display) /
design doc §3 S8/S9 / §4 display discipline / §5 visibility / AUTH_SPEC §5 /
§6 (0.15-draft) / §15-2. Inherits W2's implementation format (session-43
rulings BM–BS, CC, CD).

## 1. Ruling CN: the binding form of the CSRF header name (resolving session-44 §9's handoff)

Premise: W3a already exports `CSRF_HEADER_NAME` from api-schema
(auth-middleware.ts), and the server side is bound. What remains is binding
the `"x-maruhi-csrf"` literal in web (dashboard/api.ts). The constraint is
rulings BR/CD — the form must not collide with the mechanical check (the
source tripwire for value imports) of "don't bring Effect / api-schema
runtime code into the bundle (= TCB)".

### Round 1 (multiple options)

- **CN-a (naive value import + a limited exemption on the tripwire)**: put
  api.ts on CD's exclusion list. Rejected — for a single constant,
  api-schema's **module graph** (the whole set of effect Schema runtime code
  via index) becomes bundle-eligible, and exclusion becomes dependent on
  tree-shaking behavior. It's a regression from "an inspectable
  configuration" (BG/CD's stance) to "trusting the bundler's optimization",
  paying an exception into W2's heaviest invariant for the price of one
  constant
- **CN-b (literal matching on the test side)**: the bundle stays pure, and a
  unit test (the test process may import values — same footing as ruling BV)
  matches the literal against `CSRF_HEADER_NAME`. Binding detection defers to
  test-run time
- **CN-c (type-level binding)**: `import type { CSRF_HEADER_NAME }` (a
  type-only import of a value binding — usable only in typeof contexts) +
  `const CSRF_HEADER = "x-maruhi-csrf" satisfies typeof CSRF_HEADER_NAME`.
  Since the api-schema side is a const declaration carrying a literal type,
  renaming the value breaks at compile error. Zero bundle impact, zero
  tripwire change (`import type` is outside CD's scan) — same shape as
  ruling CC (the satisfies binding of 403 reasons)

### Round 2 (strictly-better search)

- CN-c is strictly better than both CN-a (bundle impact) and CN-b (detection
  timing). And **combine** CN-b on top: the unit test matches the header name
  apiPost / apiDelete **actually send** against api-schema's real value (the
  type binding is "literal ↔ truth", the actual-send matching is "send ↔
  truth" — complementary, not tautological)

### Round 3 (re-inspection)

- CN-c's residue: if api-schema later adds a `: string` type annotation, the
  literal type vanishes and `satisfies string` accepts anything (silent decay
  of the binding). CN-b's real-value matching detects this degradation too
  (value matching stays concrete even when the type widens) — closed in two
  layers
- **Adopted: CN-c (type binding) + CN-b (the test's actual-send matching)**

## 2. Ruling CO: misuse protection on revocation (whether/how to confirm)

The premise's asymmetry: invite revocation is recoverable via re-issuance
(CLI). S9's self-token revocation **immediately turns running CLI / CI into
401** (token re-issuance is the device flow = browser-approved, and
recovering an unattended environment takes a human — rulings CF/CK's
provisioning procedure).

### Round 1 (multiple options)

- **CO-a (no confirmation, 1-click revoke)**: rejected — on top of the
  asymmetry above, Astryx's design guideline also explicitly avoids
  unconfirmed destructive actions. Undo is structurally impossible (undo =
  re-issuance = credential generation, outside ADR-0018 revision 2's
  boundary), so pre-confirmation is the only misuse protection
- **CO-b (browser-native `confirm()`)**: rejected — blocks the thread,
  departs from style / wording consistency (ADR-0013 / display discipline),
  and makes e2e depend on a dialog handler
- **CO-c (inline 2-step confirmation)**: clicking a row's Revoke arms it, and
  the same row shows Confirm revoke (destructive) + Cancel. At most 1 row is
  armed (arming another row or Cancel disarms). No added components, all
  state visible in the DOM, e2e-friendly
- **CO-d (a modal dialog)**: rejected — the target's details are already
  visible on the list row; no gain in adding a new surface with a focus trap

### Round 2 (strictly-better search)

- CO-c + **a consequence warning line**: on S9's confirm row, add "Revoking
  immediately signs out any CLI or CI still using this token" (S8 says the
  invite link stops working). Raises the confirmation's meaning from "one
  more click" to "presenting the consequence"
- After revocation, re-fetch the list (mirror the server-declared state —
  don't paint client-guessed state via optimistic update. Same side as
  display discipline §4)

### Round 3 (re-inspection)

- Auto-timeout disarm of the armed state is rejected (non-deterministic
  behavior only adds untestability). It's naturally disarmed by navigation /
  reload
- **Adopted: CO-c + consequence warning + server re-fetch after revocation**

## 3. Ruling CP: screen placement / routing of S8 / S9

### Round 1 (multiple options)

- **CP-a (S8 = ProjectScreen's 4th tab, S9 = independent route
  /dashboard/tokens)**: axis consistency — S8 is project-axis (authorization
  is the project's chain role too), so a tab of the project screen; S9 is
  user-axis (one's own tokens), so an independent account-family route.
  Follows ruling BO "tabs aren't routed"
- **CP-b (S8 as an independent route too,
  /dashboard/projects/:id/invites)**: rejected — increases the route surface
  (near-miss class) and re-litigates BO round 2's decision
- **CP-c (integrate S9 as a tab of /dashboard/account)**: rejected — it would
  mix a revocation-mutation surface into W2's audit-reading screen, weakening
  per-screen degradability (design doc §2). It would also involve modifying
  the W2 screen
- **CP-d (S9 as a section right under /dashboard)**: rejected — same as
  above; mutation mixed into S4 (the list)

### Round 2 (strictly-better search)

- The tab name "Invites" overlaps in wording with the invites axis inside the
  S6 audit tab (SegmentedControl), but one is management (list / revoke /
  issuance guidance) and the other is audit event history, and the contexts
  (directly under tabs vs an axis inside the Audit tab) separate them.
  Renaming (e.g. "Invitations") would only split the same word across
  different screen hierarchies — no actual collision — keep it as-is
- /dashboard/tokens is automatically covered by the existing BZ sweep
  (non-intersection of SPA routes × run_worker_first) and CA (the spaPaths
  builder binding)

### Round 3 (re-inspection)

- The S8 tab isn't preemptively hidden by role (below admin gets the 403 role
  wording — same as ruling BQ's invites audit axis: "don't replicate the
  pre-judgment into the client")
- **Adopted: CP-a**

## 4. Ruling CQ: S9's expiry display — expired vs null (session-44 §9's homework)

- **Expired (expiresAtMs in the past)**: an "Expired" Token + the declared
  time, side by side. Past-ness is a comparison against the client clock, but
  the display's subject is always the server-declared expiresAtMs (§4's
  format). S8's invite expiry (expiresAtMs — non-null) uses the same display
  component (unifying the format)
- **null (pre-migration old no-expiry rows)**: per AUTH_SPEC §6 (ruling
  CE-c′), the verification side treats NULL **as expired (fail-closed)**. So
  the display is also "Expired" + a "no expiry recorded" note — a mirror of
  spec-defined behavior, not client fabrication
- Rejected: displaying null as "Never expires" (false after CE-c′ — a
  recital of the pre-migration semantics) / hiding null rows (denying the
  inventory surface — contradicts CE round 3's "the path to noticing expiry =
  making it visible in the list")

## 5. Incidental concretization (no ruling letters — an extension of BP's format)

- **Classification of 410 (InviteGone)**: consuming the revocation DELETE
  brings 410 to web for the first time (it didn't exist on W2's consumption
  surface). Added `gone` (+ the server-declared reason) to api.ts's
  classification; the wording is "The server reports this invitation as
  {reason}." Folding into unreachable (the first version's behavior) would
  violate the "mirror the server's declaration" discipline, so the
  classification was widened
- **The target noun of the 404 wording**: BP's "The server reports no such
  project for your account." is the project surface's wording. Introduced
  subject (project / invitation / token) on FailureNotice for S8 revocation
  (invitation) and S9 (token) — change only the noun without changing the
  uniform 404 meaning (doesn't distinguish another's from nonexistent) — the
  wording unification (BP) is preserved
- **Revoke-button display condition**: S8 only on rows with status pending |
  accepted (mirroring the server's acceptance condition — expired pending
  rows can be cleaned too — handlers-invites.ts's B1a ruling). S9 all rows
  (cleaning expired rows is carried by explicit revocation — CE round 3)
- **New builders' path parameters go through encodeURIComponent** (inviteId /
  tokenId are server-issued opaque ids — unlike projectId there's no
  client-side format check — keep a hostile server's id from escaping the
  path down to a visible 404/405)

## 6. Implementation record

- **api layer**: added `apiDelete` (DELETE + CSRF header). The CSRF header
  name is type-bound per CN via a type-only import + `satisfies typeof
  CSRF_HEADER_NAME` (mutation-verified: altering the literal gives TS1360).
  Added `gone` (410 + reason) to the classification, and unified the
  reason extraction of 403/410 into 1 implementation (turned reason-family
  kinds into a lookup, matching fallow's cyclomatic ≤ 4 discipline)
- **endpoints.ts**: 4 builders — `invites` / `inviteRevoke` / `tokens` /
  `tokenRevoke` — + 4 catalog surfaces (the BW sweep mechanically checks —
  added `:tokenId` / `:id` to the sample parameters). New builders' path
  parameters go through encodeURIComponent per §5
- **S8**: `InvitesTab.tsx` — ProjectScreen's 4th tab (CP). status Token
  (Object.hasOwn self-defense — same shape as RoleToken) / invited /
  accepted by / ExpiryCell / RevokeControl (pending | accepted rows only —
  the literal is type-bound via `satisfies ReadonlyArray<InviteStatus>`).
  Permanent display of issuance's static guidance (`maruhi invite create`) +
  the revocation-consequence note
- **S9**: `TokensScreen.tsx` — independent route `/dashboard/tokens` (CP.
  routes.ts constant + SPA_ROUTES + spaPaths.tokens — automatically covered
  by the BZ/CA sweeps). name / prefix / scopes / last used (null =
  "never") / ExpiryCell (CQ) / RevokeControl on all rows. An "API tokens"
  path on the dashboard header. No createdAtMs column (issuance history is
  Account audit's — S6's self axis — territory. Doesn't reach the cost of
  the width)
- **Shared parts**: `use-api-resource.ts` (extracted into an independent
  module from W2's ProjectScreen-internal hook — behavior unchanged) /
  `use-revocation.ts` (CO's state machine. 1-row arming, re-fetch on
  completion. **State lives outside the list resource** — so a failure
  display doesn't vanish on unmount during re-fetch) / shared.tsx's
  `ExpiryCell` / `RevokeControl` / `FailureNotice`'s subject (§5) + gone
  display
- **Tests**: 29 web unit (matching apiDelete's actually-sent CSRF against
  api-schema's real value = CN's second layer / 410 classification / catalog
  sweep following / spa-topology following). 24 e2e (S8 revocation success +
  list refresh + actual DELETE/CSRF send / 410 wording / 403 role wording /
  S9 Expired ×2 + no expiry recorded + never display / revocation + list
  refresh / uniform 404's token wording / CSP headers actually present on
  /dashboard/tokens). All fixtures added to Schema real-verification (BV)
- **Hardening an existing sweep (found by measurement)**: CD's value-import
  tripwire **false-matched by concatenating the word "import" inside a
  comment through to a real import statement's from clause in one match**
  (api.ts's CN note comment was the first trip). The regex was strengthened
  to a line-start anchor (`^import` + m flag) — import statements are
  top-level declarations and appear at line start. Mutation verification:
  still detects on an actual value import, as before
- **Following existing tests**: W2 e2e's audit invites-axis click collided
  in wording with the management tab "Invites" (S8) → changed to point at
  the SegmentedControl (radiogroup) side by role. S8's e2e also mocks the
  Overview tab's consumption surface (a real server's 401 response blocks
  networkidle with the body unread — a measured confirmation of why W2 tests
  are fully mocked)
- Out-of-scope confirmations: no changes to server / api-schema / CLI /
  packages/crypto. No issuance UI, raw-value display, S10, or rotation
  dismiss was built. The BG check (0 occurrences of the word `hash`) passes
  unchanged even after the bundle grew
- `bun run check` fully passed (2211 tests) + 24 e2e passed

## 7. Post-implementation strictly-better search (iterating with changed generation rules — until convergence)

Applied each known generation rule from session-43 §10–§14 / session-44
§7–§14 in turn:

1. **Looking for hand-written copies of the machine-readable truth**: the
   new code's inventory turned 2 items into type bindings — the CSRF literal
   (ruling CN's body) and `isRevocable`'s status literal (`satisfies` — same
   shape as CC). The only remaining literals are builder definitions and
   test expectations (intentional — same as session-43 §13's rejection)
2. **Walking the invariant chain** (definition → consumption → wire →
   server): "no issuance surface" is enforced by the server's capability
   restriction (W2b — invites.issue is outside SESSION_ALLOWED); the web has
   no consumption code at all. "No raw-value / hash display" is W3a's schema
   structure (no column) + S8's choice not to display tokenHashHex. "CSRF on
   DELETE" is the api layer's single point + type binding + real-value
   matching + e2e actual send ×2. No convention-dependent link was found
3. **Blind spots of ruling composition**: the composition of CN (type
   binding) × CD (tripwire) **surfaced the tripwire's own false positive**
   (§6 — resolved by the line-start anchor. Structurally, the more bindings
   you write, the more the word "import" appears in comments). The
   composition of CO (re-fetch on completion) × the list resource's state
   management produces "failure display vanishes on unmount during re-fetch"
   — resolved by lifting the state (§6)
4. **Back-flow of a new invariant** ("the web has destructive mutations now"
   into old-premise descriptions): updated api.ts's comment "mutations are
   logout only". The design doc §6's XSS residual evaluation already
   incorporates revocation-family abuse (no revision needed). BP's 404
   wording assumed the project noun → subject branching (§5)
5. **Lifecycle-observer walk**: every state of invite (pending → accepted →
   completed / revoked / expired) and token (issued → used → expired →
   revoked) is visible in the list, and operations appear only on revocable
   states. A token's revocation deletes the row, but the Account audit
   (auth.token_revoked) remains as the observer of its history
6. **Acting-out scan of recommended procedures**: S9's note (revoke →
   re-issue by `maruhi login --show-token` on the CLI) connects to CK/CM's
   provisioning procedure. S8's note (revoke → re-issue via `maruhi invite
   create`) is also not a dead end

### Accepted residuals (recorded)

- ForbiddenNotice's generic 403 wording contains "in this project" — S9's
  (token surface) generic 403 can't occur for a session principal (CG-b:
  insufficient-permission is the token-principal condition; sessions get the
  dedicated session-not-allowed wording), so it's accepted as a noun
  mismatch on an unreachable path
- ExpiryCell's Expired judgment compares against the client clock (recorded
  in CQ — the display's subject is always the server-declared expiresAtMs)
- 410's reason embeds a server-declared defensive string into English text
  (React escaping + display only — the same class as other server-declared
  strings)

## 8. Review reflections (PR #109)

- **Bugbot + pullfrog (same finding — fixed as legitimate)**: while a
  revocation was in-flight, arming another row or re-confirming the same row
  was possible, and a late completion overwrote the armed state, making a
  failure's attribution appear to be a different revocation (a duplicate
  DELETE could also emit a false 404/410 banner on an already-succeeded
  revocation). Extended ruling CO's "at most 1 row armed" to in-flight too:
  a pendingRef guard on `useRevocation` (arm / confirm are ignored while
  running) + `RevokeControl`'s `isLocked` (disables other rows' Revoke
  buttons — don't create a button that does nothing). Mutation verification
  = a gated-DELETE regression test in e2e (other row disabled while
  in-flight → re-enabled after completion)
- **pullfrog (GoneNotice's noun pinning)**: the 410 wording's noun also goes
  through subject (same selection as NOT_FOUND_DESCRIPTION — consistency of
  ruling BP's single implementation point)
- **pullfrog (the tripwire's re-export hole)**: `export { X } from` /
  `export * from` also pull the same runtime code into the bundle — widened
  to `^(?:import|export)\s+(?!type\b)` (mutation-verified: detected on adding
  a re-export)
- **pullfrog (nit — e2e's header-observation key)**: bound e2e's
  `headers()["x-maruhi-csrf"]` to a value import of `CSRF_HEADER_NAME`
  (actual-request observation also gets ruling CN's second layer. Test
  process only — same footing as BV)
- **pullfrog wave 2 (the lock-regression e2e locator)**: Playwright's name
  matching is substring by default — while in-flight, the running row's
  "Confirm revoke" (disabled via isLoading) stood first in DOM order, so the
  test passed even with `isLocked` removed. Fixed to point only at the
  un-armed row via `exact: true`. Lesson: **always run component-mutation
  verification after a build** (e2e verifies the dist bundle — the first
  mutation verification modified only source and forgot the build, seeing a
  false success. After the fix, isLocked removal + rebuild was measured to
  fail the test → restore → all pass)

### Convergence assessment

One pass over the 6 known generation rules shrunk new findings to 1 — "the
sweep's own false positive" (rule 3's composition blind spot) — a further
shrink from session-44's arc (wire surface → behavior → guidance). The W
series' consumption surface is hereby closed, and findings from this rule
space are judged exhausted until the next positive addition (a new screen, a
new API).
