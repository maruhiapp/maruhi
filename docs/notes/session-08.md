# Session 08 memo (the implementation PR A for the 3 review rulings = the non-crypto layer)

Date: 2026-08-02. Prerequisite: PR #18 merged (the variable-value API + audit logging. Its merge
fixed the owner's approval of AUDIT_SPEC). The ROADMAP note went ahead as the independent PR #19.
Scope: PR A, the one of session-07.md §3.5's three owner-ruled items that does not touch the crypto layer
(1-B + 3-D + the B/D of 2). 2-E (mandating signatures on wrap registration) is the next PR B.

## 1. What was done (commit order = layer order)

1. **spec**: AUTH_SPEC v0.4 (§12-2 suite / the §12-3 table / the §12-6 repair path /
   §12-8 row-count limit + a Phase 2 notice), AUDIT_SPEC v0.3 (dek.registered /
   dek.deleted added to §3.3, Status updated to approval-confirmed). **CRYPTO_SPEC unchanged** (per the rulings)
2. **api-schema**: suite added to WrappedDek / RecipientDek (pinned to the Literal `"maruhi/v1"`),
   DekWrapRef, DELETE .../deks (the repair path), DekWrapNotFound (404),
   dek-wrap-rows added to DataLimitResource
3. **server (DO)**: the suite column in do-schema (direct DDL change — pre-release, no deployed
   environments. No new table, so PROJECT_DO_TABLES unchanged), policy's
   MAX_PROJECT_DEK_WRAP_ROWS, data-store's suite read/write + countWrapRows +
   deleteWrap, data-programs' row-limit wiring + the dek audit events +
   deleteDekWrapsProgram, chain-do's deleteDekWraps RPC
4. **server (HTTP)**: data-http's mapping (dek-wrap-not-found → 404) and
   toValueInput now takes suite; handlers-deks' remove (admin);
   handlers-variables' suite now returned from the stored row
5. **tests**: 7 added (311 green). The repair path is verified as a round trip through client decryption
6. **docs**: this memo

## 2. Implementation form of the ruled items (details only proposed — the confirmation condition = PR review approval)

The rulings themselves (session-07.md §3.5) are not relitigated. The following are proposals
on implementation details — "values, names, granularity":

### 2-1. The cumulative row limit for dek_wraps = 1,000,000 (detail of 1-B)

Realistic usage is member × environment × epoch, i.e. hundreds to thousands of rows (e.g. 10 members ×
10 environments × 10 epochs = 1,000 rows). Following the ruling's "3 orders of magnitude above
realistic usage", it is 1,000,000 rows. At ~300 bytes per row, the worst case ~300 MB is safe
against DO SQLite's 10 GB. The check is wired into a single point, ensureWrapSetAcceptable, shared by
environment creation and DEK registration (every insertion path passes through it). It counts
"rows currently stored", and rows are freed by environment deletion / wrap deletion.

### 2-2. Granularity of dek.registered / dek.deleted = one recipient per row (detail of 2-B)

| Option | Content | Evaluation |
|---|---|---|
| A: one row per request (the recipient list in the payload) | Minimal row count | Inconsistent with §5.1's column structure (target_user_id is single-valued). Indexing by recipient becomes a JSON scan of the payload |
| **B: one row per recipient (adopted)** | The recipient goes to target_user_id | Directly queryable by the (target_user_id, seq) index. Uniform with §3.4 mirror's one row per target. Registration is infrequent (only on rotation / member addition), and the row count is bounded by §12-8's wrap-row limit |

The event name pairs `dek.deleted` with the already-ruled `dek.registered`
(domain.verb system, same shape as var.created / var.deleted). The epoch-1 wraps bundled at
environment creation are also dek.registered targets (uniformity of registration paths).

### 2-3. The endpoint form of wrap deletion (detail of 2-D)

`DELETE /projects/:id/environments/:envId/deks` + body `{ wraps: [{epoch,
recipientUserId}] }`. (environment, epoch, recipient) is not put in path segments:
recipientUserId is a free string under chain consensus rules (≤ 1024 bytes)
and cannot be safely represented as a path segment. Effect HttpApi's DELETE accepts a
payload as a JSON body (HttpMethod.hasBody is false only for GET / HEAD /
OPTIONS / TRACE).

Acceptance-rule details: a nonexistent tuple is 404 (silently succeeding would leave "a poisoned wrap
thought deleted"). The order is verify-all-tuples-exist → delete, so no partial deletion
exists (verification under the permit; deletion + audit is a single synchronous task). A duplicate in the enumeration is 422
duplicate-recipient (the same vocabulary as the registration side). The count is bounded by the same
MAX_DEK_WRAPS_PER_REQUEST as the registration side. **An empty enumeration is 400** (added in review
loop 1. See §4-2).

### 2-4. Permission level = same as environment deletion (detail of 2-D, per the task instruction's starting point)

Token scope admin × chain role admin or above. Deletion robs other members of their ability
to decrypt; placing it at member level would resurrect through the deletion path the availability
attack that the overwrite ban (§12-6) closed off.

### 2-5. Reading suite back (detail of 3-D)

A stored row's suite is read back via `storedSuite` (an unknown value is a defect) to the literal type,
and pull / distribution responses return **the stored row's value**, not a wire hardcode
(carrying CRYPTO_SPEC §2 design principle 4's "a row carries its own suite" through to response
generation). Since Schema's Literal enforces writes, anything other than a known value can
only arrive as storage corruption.

## 3. Pitfalls and environment learnings

- **Effect HttpApi's DELETE takes payload = a JSON body** (2-3 above).
  The GET-style urlParams conversion does not happen
- **fallow's one new-clone warning is left as-is**: the skeletons of
  listActiveVariables and latestVersions in data-store.ts (Effect.sync + exec + map)
  match as token sequences — a structural detection. It surfaced only because the suite-column
  addition touched the lines; extracting them would make two different queries less clear.
  warn level, check is green
- **audit.test.ts's event-list assertions had to account for dek.registered × member count
  right after env.created** (existing tests picking env.created via `.at(-1)` were changed to find)
- Seeding 1,000,000 rows (a single-statement WITH RECURSIVE INSERT) passes in a few seconds in
  workerd's DO SQLite (about +3 s on the whole suite). The row-limit plumbing was verified
  by real generation (a unit check of the pure function wrapRowsExceeded runs alongside)
- **Because the suite column (NOT NULL) was changed directly in DDL, the `.wrangler/state`
  local dev storage created on main must be discarded before running this branch**
  (`CREATE TABLE IF NOT EXISTS` does not alter existing tables). Acceptable under the
  unreleased premise (per session-07 ruling 10, the migration mechanism stays deferred).
  Post-release, this kind of change needs an ALTER path = a trigger to re-evaluate ruling 10

## 3.5 The review→fix loop (inside PR #20. 3-angle parallel review → fixes)

### Loop 1 findings and responses

All 3 angles (security / correctness & concurrency / tests & contract) found zero high/medium
implementation defects. Findings adopted and fixed:

1. **Deleting an empty `wraps: []` was a 204 no-op (detected independently by all 3 angles; medium on the contract angle)**:
   it created a call shape where a destructive API leaves no audit trace at all,
   in tension with §12-6's "do not silently succeed" discipline (nonexistent tuples are 404). The spec now states "the enumeration
   is ≥ 1 item (empty enumeration is 400)", enforced by Schema's `isMinLength(1)` +
   a negative test. The registration side (`deks: []` no-op) originates on main and is
   non-destructive, so this PR does not touch it (if aligned, an independent PR — handoff)
2. **"Re-registration after deleting all wraps is exact-match as a first registration" — a new spec
   sentence untested (medium)**: added a test: full delete → partial re-registration 422 recipient-missing →
   full set 204 → decryption
3. **The delete endpoint's EnvironmentNotFound / count limit (dek-wraps-per-
   request) untested (medium)**: tested delete to a tombstoned environment returning 404 (because the body carries
   environmentId, not DekWrapNotFound) and 10,001 items returning 422
   (every declared error's reachability is pinned)
4. **Low**: added tests that dek.registered records actor_api_token_id, and that a rejected delete
   keeps dek.deleted at 0 rows (the contrapositive of verify/write separation)

### Observations recorded but not acted on (judged to need no response)

- **Between deletion and re-registration, a member can refill the freed slot with a poisoned wrap**
  (security angle, informational): members have always been able to register poison into empty slots —
  not a new capability (overwrites remain 409). dek.registered records the registrant as
  actor, so attribution is traceable. Attribution against a distrusted server is the main line of PR B (2-E's
  per-wrap client signature). Also noted in §4
- **fallow's structural-clone warning** (left as-is per §3)

### Loop 2 (re-verification of the fixes)

All 3 angles confirmed zero findings (security = the Schema enforcement of empty-enumeration 400 and absence of
bypass, correctness = no change to write discipline / permit design after the added tests, contract =
every one of the delete endpoint's 6 declared errors has a reachability test).
`bun run check` + `wrangler deploy --dry-run` green.

## 4. Known limitations — acceptable for v1

- dek.registered does not participate in v1's rotation-needed detection (§4.1) (the candidate set is
  all members × all environments). It is recorded as evidence for when environment-scoped roles
  (CRYPTO_SPEC undecided #11) land (noted in AUDIT_SPEC §3.3)
- The total DO storage guard (the databaseSize threshold = the ruling's F) is only noted in §12-8 as a
  Phase 2 notice (not implemented)
- Between deletion and re-registration the affected recipient cannot decrypt that epoch, and the freed slot
  can be refilled at member permission (registering into an empty slot is a pre-existing capability, not
  something the repair path newly grants). Operationally the deleter = admin holds responsibility within one session
  until re-registration completes; registration attribution is tracked via dek.registered (in the future, PR B's signatures)

## 5. Handoff to the next session

- **PR B (2-E: mandatory signatures on wrap registration)**: strictly keep the order CRYPTO_SPEC revision → test
  vectors first → human review of packages/crypto. The signature target includes this PR's
  suite (which is why PR A came first). The ruling list is in session-07.md §3.5
- Since this PR put suite on WrappedDek's wire, **CLI / Web implementations must always
  carry suite** (the client generation side also uses SUITE_ID)
- The repair path's UI / CLI display: it must make explicit that "the affected recipient cannot decrypt
  until delete → re-register completes" (when the Web dashboard is implemented)
- Whether to align the registration API's empty `deks: []` (no-op 204) with the deletion side's
  "empty enumeration 400" is decided in an independent minor PR (main-originated and non-destructive, so this PR does not touch it)
- session-07.md §5's handoffs (the CLI's 409 retry loop, client sync's
  §6.3 checks, the recovery blob's rate limit, etc.) remain valid and untouched
