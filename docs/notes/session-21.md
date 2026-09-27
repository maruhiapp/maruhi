# Session 21 memo (the D1-side audit-log foundation — AUDIT_SPEC §3.1–§3.2 / §5.2 option A)

Date: 2026-08-10. Prerequisite: started from main with PR #41 (session 20) merged.
Scope: the only remaining ROADMAP Phase 1 server item — "the D1 side of the audit log
(authentication / org family)" — plus clearing session 18's handoff (recording auth.recovery_* =
AUTH_SPEC §13-5). Storage is AUDIT_SPEC §5.2's already-ruled option A (D1).

## 1. Spec (codifying the implementation's fine rules — merge constitutes approval)

- **AUDIT_SPEC 0.6**: §5.2 gained an implementation note (tables = `user_audit_events` /
  `org_audit_events`, no DO-only columns — org_id / project_id are promoted to columns,
  no FK to users, same-transaction append = bundling into each repository's batch). §3.1 gained 4 recording
  rules: login_succeeded copies the session id (the same hash as the stored id) into its payload /
  session_revoked records only explicit revocations (expiry cleanup is not recorded) /
  login_failed's actor is type=user with no user_id / a same-name rotation is
  1 token_created row (deleting the old row does not become a separate token_revoked). §3.2 gained
  the personal org's org.created + org.member_added and "do not copy the org-name
  snapshot" (providerLogin-derived = §1-2's forbidden information)
- **AUTH_SPEC §13-5**: the handoff cleared. Fetches are recorded **only for distributed responses (200)**
  (rate-limit rejections and unregistered 404s are not recorded — the same line as §13-3's
  counted set)

## 2. Design decisions

- **The form of same-transaction append**: the audit insert statements (userAuditInsert / orgAuditInsert)
  are bundled by each repository into its own D1 batch. The D1 counterpart of the DO-side audit-store's appendSync
  (synchronous-block atomicity). A standalone append service (D1AuditRepo) is
  only for events with no accompanying main-data write (login_failed / the device flow's
  login_succeeded)
- **Event ↔ write-path correspondence**:
  - createUserBatch: user_created + identity_linked (provider kind name only) +
    org.created (personal) + org.member_added (the owner themself) bundled into the existing batch
  - sessions.insert: login_succeeded (fixed inside the repository per §3.1's 1:1 rule)
  - sessions.revokeByHash (new): explicit revocation only. Observes the deletion succeeding via returning
    before recording session_revoked (actor = the deleted row's owner / auth_method.
    Pullfrog finding handled: a read → delete two-step could record 2 rows for 1 revocation
    under concurrent logouts. Err on the side of missing rather than duplicating). The expiry-cleanup deleteByHash /
    deleteExpired stay event-free as before
  - tokens.replaceForUserAndName: token_created (tokenId / name / scopes).
    tokens.revokeById (replacing deleteById): token_revoked (the actor's token id =
    the revoked id — v1 only revokes one's own token). Records after observing the deletion succeed via returning
    (Cursor Security Agent finding handled: concurrent revokes can both pass findByHash, so an unconditional
    batch would write multiple rows per revocation = overcounting.
    Same shape as the revokeByHash ruling)
  - recovery.upsert / recordFetch: actor (derived from the principal) is passed as an argument, and
    reissued / blob_fetched are bundled into each batch
  - projects.insertIfAbsent: org.project_created is recorded **only when the row was
    actually inserted** (PR review = Cursor Bugbot finding; the fix adopts the Bugbot Autofix
    proposal: drop onConflictDoNothing in favor of a plain insert + audit row as a 2-statement batch, and on a
    PK conflict roll the whole batch back atomically into a no-op (detected via isUniqueConflict).
    Neither phantom events nor missing audit rows can occur)
- **Device-flow login success**: creates no session, so it cannot ride sessions.insert.
  It is appended standalone in the handler right after getOrCreateUser. **The reference point is
  "GitHub verification succeeded", not "exchange 200"** (the ruling answering Pullfrog's
  question): the token limit (429) is not an authentication failure and matches none of login_failed's
  reason vocabulary, so moving it after issuance would create a path where "authentication succeeded with zero
  audit trace". The asymmetry where an audit-write failure fails the exchange with 500 is accepted (making it
  best-effort = never silently drop audit — the do-not-swallow-errors convention)
- **login_failed is a D1 write from an unauthenticated path** (the spec requires recording it).
  Following the PR review finding (Cursor Security Agent, MEDIUM), a fixed-window global cap
  (100 rows per hour; beyond that, best-effort non-recording — codified in AUDIT_SPEC §3.1)
  bounded the write amplification. The window's measured rate and the cap's value are revisited together with §5.3's dogfooding
  measurements

## 3. Implementation

- db.package: 2 tables in the schema + indexes (actor / target / event; org also has org_id),
  audit.ts (the insert-statement builders + D1AuditRepo + principalAuditActor), and batch bundling at
  various points in repos. One drizzle migration
- auth.package: session.revokeSession → revokeByHash, token.revokePresentedToken
  → revokeById
- handlers-auth: login_failed (state-mismatch / code-exchange-failed /
  github-token-invalid × web and device), the device flow's login_succeeded, recovery's
  actor pass-through. handlers-membership: passes principal into init for
  org.project_created

## 4. Tests and quality

- server +15 (audit-d1.test.ts): the sign-up batch event sequence / re-login deltas /
  login_failed's fixed-window cap (suppressed at the cap, resumes after the window) / an idempotent-insert
  miss not adding org.project_created /
  the 3 login_failed reasons and the anonymous actor / the device flow's token_created (id, name,
  scopes cross-checked) / rotation's 2 rows / session_revoked's id cross-check and a re-logout
  unrecorded / **expiry cleanup does not emit session_revoked** / token_revoked's
  actor = the target / recovery records only on distribution (404 / 429 unrecorded) /
  org.project_created's coordinates and actor / the forbidden-information scan (no provider numeric ID,
  login, or @ appears in any row — the D1 counterpart of the DO-side §1-2 test)
- Existing-test follow-up was limited to adding the reset table in test/support/auth.ts (the API change
  stayed inside the server)
- `bun run check` green (940 tests)

## 5. Out of scope (handoffs)

- The audit-log read API and the read-permission details come together with Phase 2's audit-log UI
  (AUDIT_SPEC §6–§7 / undecided #1)
- Org rename / delete / member-management APIs are unimplemented, so recording of the corresponding §3.2 events
  starts when those APIs land (codified in the AUDIT_SPEC §5.2 implementation note)
- login_failed's write volume and var.read's aggregation policy are revisited after dogfooding measurements
  (AUDIT_SPEC §5.3 / undecided #4)
- The human tasks at dogfooding start (creating the GitHub OAuth App + registering it on the
  verification deploy — session-19 §6) remain valid and untouched
- The chain-append commands and the crypto test/checks organization candidate (session-17 §4) remain
  valid and untouched
