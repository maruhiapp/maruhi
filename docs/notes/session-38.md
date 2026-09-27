# Session 38 notes (admin audit-matching CLI + bounding the audit-head lazy extension)

Date: 2026-08-28. Target: the 2 remaining items of PR-M2 (#99) — (1)
AUDIT_SPEC §6's admin audit matching (`maruhi audit reconcile`), (2) turning
`ensureHeadCurrent` (audit-head lazy extension) into a bounded contract
(`AuditHeadNotReady` — the handoff of PR #99 review thread r3877856076; the
proposal shape is r3877888910's reply). Prerequisites: session-27 §14's
implementation split (PR-M1–M4, PR-F1–F4, final = #101) is fully merged. The
ruling process followed the goal's instruction "multiple options →
strictly-better search → 3 rounds of comparison → autonomous choice". Ruling
letters continue from session-37's X–AE (AF onward). 2 spec additions
(bounded-extension tolerance in AUDIT_SPEC §5.1, `AuditHeadNotReady` in
AUTH_SPEC §16-2 — the goal pre-approves minimal additions; finalization is at
PR review).

## 1. Ruling AF: the extension cap's unit and value

### Round 1

- **Option AF-a: a wall-clock / CPU-time budget** — rejected: non-
  deterministic; tests can't pin the value (pass/fail varies with the
  runtime's speed). Unobservable as a contract of "one call's work"
- **Option AF-b: a row-count cap** — unless it's an integer multiple of the
  chunk size (50 rows), fractional-chunk handling creeps in. The
  implementation's persistence granularity is chunks (atomic commit per
  task), so the natural contract uses the same unit
- **Option AF-c: a chunk-count cap (the proposal shape of the PR #99 reply)**
  — same unit as the persistence granularity. The value is 200 chunks =
  10,000 rows

### Round 2 (strictly-better search)

- **Option AF-d: different caps per call path (smaller for GET, larger for
  acceptance, etc.)** — rejected: two contracts, and tests, spec description,
  and the client's retry-budget estimate all double. There's also no measured
  load difference to justify a per-path difference (every path runs the same
  computation under the same permit)

### Round 3 (re-inspection)

- Connected the 10,000-row value's basis to an existing spec quantity: equal
  to §12-8's max audit rows per request (appendManySync's bulk var.read
  limit). The steady-state backlog (extend on every read) is "appends since
  the previous read", and even the largest single burst resolves in one call
  — hitting the cap is only possible on the first materialization of a huge
  existing log
- Confirmed the bound on one call's work: 10,000 rows × SHA-256 × 2
  (row_digest + h_n) is small enough as workerd execution / permit-holding
  time (measured on the order of 1–3 seconds). So a call completing exactly
  at the cap doesn't return a spurious "more-remains": only on hitting the
  cap does it settle remaining-work presence with a cheap existence check
  (`SELECT 1 ... LIMIT 1`)
- Testability: pin the unit semantics by injecting a shrunken production
  value (`makeAuditStore` options), and reach integration (the 3 paths' 503)
  with direct seeding at the production value

**Choice: option AF-c**. `MAX_HEAD_EXTENSION_CHUNKS_PER_CALL = 200` (× 50
rows/chunk = 10,000 rows/call).

## 2. Ruling AG: AuditHeadNotReady's status code and error shape

### Round 1

- **Option AG-a: 422 (a new reason on CheckpointStateMismatch)** — rejected:
  (1) wrong semantics — 422 is "matching declared content against stored
  state failed", whereas this is "a server-side derivation incomplete", with
  the client's content still correct. (2) GET /audit-head has no declared
  content, so 422 vocabulary can't form. (3) Adding a value to the reason
  Literals breaks old clients' Schema checks (not additive)
- **Option AG-b: 409** — rejected: collides with the CAS-conflict semantics
  (ChainHeadConflict). Riding the existing 409 handling that prompts re-sync
  / re-sign would trigger pointless rebuilds
- **Option AG-c: 503 + typed `AuditHeadNotReady` (no body)** — the standard
  expression of transient server-side readiness, natural on both the GET and
  POST paths. The typed body distinguishes it from "a 503 of an outage"

### Round 2 (strictly-better search)

- **Option AG-d: 503 + Retry-After header / remaining-work field** —
  rejected: remaining work / progress is ordinal information about the audit
  row count and violates §7's non-leakage of counts (recipients are limited
  to effective admin, but making the body empty removes the need to consider
  a leakage surface at all). Retry-After is also unneeded — while processing
  the failed response the server has already advanced to its cap, so an
  immediate retry is productive (no reason to wait)

### Round 3 (re-inspection)

- Confirmed compatibility with §11-2's existence concealment: the rejection
  fires only after the authorization decision (non-member 404 / insufficient
  permission 403) (inside the DO the judgment comes after requireMemberState
  / requireRole; on composites, after the worker's scope check)
- Old CLI × new server: an undeclared error becomes a generic error — per the
  goal's instruction, SELF_HOSTING.md notes that it fires only on "first
  materialization of a huge log" and resolves on re-run. New CLI × old
  server = the previous behavior (this error never arrives)
- The CLI's retry budget: 10 attempts. Budget × server cap = 100,000 rows of
  guaranteed extension per command run. On exhaustion it guides the
  triggering condition and the re-run resolution (progress is saved, so a
  re-run always continues forward). The budget is independent between fetch
  (GET) and acceptance (send) — acceptance-stage incompleteness is a
  different rare shape ("mass appends between declare and accept"), and
  mixing them would make it impossible to tell from the message which budget
  was exhausted

**Choice: option AG-c**. api-schema's `AuditHeadNotReadyError`
(httpApiStatus 503, no fields). Additions to the contract declarations are
only additive on 4 endpoints (auditHead / membership append / environments
create / rotate); payload Schemas unchanged (no change to §12-10 (1)'s
strict classification).

## 3. Ruling AH: where the spec addition lives

### Round 1

- **Option AH-a: add to CRYPTO_SPEC §6.4** — rejected: §6.4 is the home of
  consensus rules and the acceptance policy (content matching); this is a
  derived column's readiness, not a content judgment. Don't mix an
  availability response into the crypto spec
- **Option AH-b: AUDIT_SPEC §5.1 only** — natural in that lazy
  materialization's tolerance lives there, so bounding lives there too. But
  the wire response (503 / type name / position) is API-spec territory, and
  writing HTTP into §5.1 is out of bounds
- **Option AH-c: AUDIT_SPEC §5.1 (storage contract: allowing bounded
  extension + fail-closed) + AUTH_SPEC §16-2 (the API surface: 503
  `AuditHeadNotReady`, empty body, after the authorization decision,
  retryable) — the minimal 2 points** — split per the existing division of
  labor (§5.1 owns the column's semantics, §16-2 owns the checkpoint-support
  APIs)

### Round 2 (strictly-better search)

- **Option AH-d: AH-c + 1 cross-reference sentence in CRYPTO_SPEC §6.4** —
  rejected: §6.4's acceptance verification already references "the stored
  cumulative-hash column (AUDIT_SPEC §5.1)", and the column's
  materialization discipline is already carried by the referenced §5.1.
  Adding to a third document only increases the sync burden

### Round 3 (re-inspection)

- Confirmed the fail-closed statement goes on the §5.1 side: "§6.4's checks
  and head responses must not run on a stale column" is the column's
  observation contract and doesn't depend on which API carries it (it holds
  even if more readers appear in the future)

**Choice: option AH-c**.

## 4. Ruling AI: where the matching command lives (integrate into verify or create new)

### Round 1

- **Option AI-a: integrate into `maruhi audit verify` (matching also runs
  when admin)** — rejected: verify's design claim is that every member can
  run it (class 1 only), and the tests pin that. If behavior changes by
  permission, the meaning of "OK" becomes runner-dependent — a reader's OK
  and an admin's OK would differ (given that an audit command's output gets
  quoted as evidence, uniqueness of meaning matters more than wording)
- **Option AI-b: create `maruhi audit reconcile` (effective admin required)**
  — matches §6's name (admin matching) too. What it checks also differs
  (verify = mirror bijection; reconcile = consistency of the cumulative-hash
  column with notarizations)
- **Option AI-c: `maruhi project reconcile`** — rejected: the subject is the
  audit log (AUDIT_SPEC §6), and the audit family (list / invites / self /
  verify) is the discoverability home. The project side is where checkpoint
  issuance (the writing side) lives — don't mix the reading side's
  verification in

### Round 2 (strictly-better search)

- **Option AI-d: AI-b + a path where verify guides admins to reconcile** —
  rejected: adding permanent guidance to verify's success output would make
  output for all members advertise an admin-only operation every time.
  --help and docs explanations suffice

### Round 3 (re-inspection)

- Report format: violations are explicitly labeled with §6's 2 classes —
  `Row-tampering evidence` (membership violation (a) = evidence of row
  tampering) and `Acceptance-policy violation (stale-replay risk)` ((b)(c) =
  a server not enforcing its acceptance policy = evidence of a
  stale-replay-capable state). A summary sentence explains both classes'
  implications in §6 vocabulary, exit 1. A positive reports a row-count /
  notarization-count summary + OK, exit 0
- A seq gap (a trace of deletion), once detected, **aborts**: the h_n chain
  disagrees for everything after the gap, and continuing would mass-produce
  derived false positives where every notarization looks like a "membership
  violation". Fail-closed reporting only the strongest evidence (deletion)
- The effective-admin pre-judgment follows the same discipline as checkpoint
  issuance (chain role = verified view, scope = /auth/me's tokenScopes; don't
  trip a 403). Below it, a clear error before matching starts — running it
  below admin would misjudge a visibility hole (class-2 concealment) as a
  gap

**Choice: option AI-b**.

## 5. Ruling AJ: the consistency strategy for fetching all rows

### Round 1

- **Option AJ-a: copy verify's discipline verbatim (duplicate-id detection +
  a static page cap)** — rejected: verify's static cap (100 pages) was
  derived from the chain acceptance policy (10,000 entries) as a theoretical
  maximum, and audit rows have no such cap (retention is indefinite — §5.3).
  Any static cap would artificially disable legitimate matching of huge logs
- **Option AJ-b: share the paging engine, and guarantee termination by strict
  decrease of the admin-visible `seq`** — an admin response's `seq` is a
  positive integer. Enforcing strict decrease within and across pages bounds
  the total row count by the first page's max seq, so paging always
  terminates (non-advancing cursor, duplicate distribution, or order
  violation all abort as self-contradictions of the response)

### Round 2 (strictly-better search)

- **Option AJ-c: AJ-b + a snapshot-dedicated API (consistent read)** —
  rejected: a new endpoint is an out-of-scope API extension. Snapshot
  consistency holds with existing paging anyway — appends during the fetch
  are newer than the first page's cursor and never appear on later pages, so
  the fetched set closes at the first page's point in time

### Round 3 (re-inspection)

- Connection to the gap check: strict decrease + positive integers
  structurally exclude duplicates, so the gap check only needs to look one
  way — "complete coverage of 1..maxSeq"
- Documented the premise of the recomputation input (payloadText): the wire
  payload's JSON.stringify. The stored TEXT is what the server's own
  JSON.stringify wrote (only the server writes), and an object containing
  only identifier keys is byte-stable across a parse → stringify round-trip.
  A disagreement means "received row ≠ the row the server used for column
  computation" = a self-contradiction of the response, and since the audit
  log is server-managed data (§6) it may be treated as evidence of
  tampering/corruption (pinned in a code comment. A non-ASCII payload [㊙] is
  actually computed in a test)
- Progress visibility: print the fetched row count every 50 pages (surfacing
  no-response situations on huge logs / a non-advancing server)

**Choice: option AJ-b**. The engine (`paginateAuditEvents`) is shared with
verify in audit.ts — no duplicate implementation.

## 6. Ruling AK: whether to match against GET /audit-head's declared value

### Round 1

- **Option AK-a: don't match (checking notarizations suffices)** — leaning
  rejected: for false declarations in un-notarized periods (keep returning a
  nonexistent head to the admin, then rebuild the column before
  notarization), no detection material exists until the next notarization.
  The match costs 1 GET + 1 Map lookup — nearly free
- **Option AK-b: match (the declared value's membership in the recomputed
  column)** — becomes an immediate check, without waiting for notarization,
  of consistency between "the value the server is declaring now" and "the
  rows the server is returning now"

### Round 2 (strictly-better search)

- **Option AK-c: AK-b + also track non-regression of the declared value's
  position via a floor record** — rejected: tracking the declaration's
  position means new local state (floor), which is out of scope. (b)(c)
  carry non-regression for notarized positions, and the next reconcile /
  notarization picks up continued tracking of the un-notarized part

### Round 3 (re-inspection)

- Pinned the fetch order: the declaration comes **before** the all-rows
  fetch. The column as of the declaration time becomes a prefix of the fetch
  snapshot, so the membership check's universe is always covered by the
  snapshot (in reverse order the declaration could point at post-fetch
  appends, producing false positives on an honest server)
- Pinned the meaning of an empty declaration: an empty string is correct only
  when there are zero audit rows (declaring empty when rows exist = reported
  as a contradiction)

**Choice: option AK-b**. Violations are reported under the tampering /
false-declaration class as a mutual contradiction of the declaration and the
rows.

## 7. Ruling AL: whether matching results get evidence preservation

### Round 1

- **Option AL-a: write an evidence file (JSON report)** — rejected: it would
  create a new file kind outside the CLI's persistence allowlist (CLAUDE.md —
  token / master key / non-secret config only). The matching inputs (verified
  chain, audit rows) are all re-fetchable / recomputable, and the strongest
  evidence is the signed chain itself (already persisted)
- **Option AL-b: don't save (stdout / stderr report + exit code only)** — a
  re-run reproduces the same conclusion, and if preservation is needed the
  user can redirect (an explicit operation)

### Round 2 (strictly-better search)

- **Option AL-c: a --json flag for structured output (still not saved)** —
  rejected (this time): machine-readable output should be designed
  consistently across the whole audit family (including list / verify);
  letting only reconcile go first would fossilize the format as a fait
  accompli. Design it family-wide when it becomes needed (handoff)

### Round 3 (re-inspection)

- Consistency with the head-declaration contradiction-evidence preservation
  (session-37 ruling Z — a floor record): that one preserves "a signed
  declaration that later becomes non-repudiation material" — the subject is
  signed data. A reconcile violation is a derived result re-derivable by
  recomputation any number of times — no intrinsic value in storing it. The
  distinction stays consistent at "reproducible or not"

**Choice: option AL-b**.

## 8. Summary of what was implemented

- **api-schema**: `AuditHeadNotReadyError` (503, no fields). Declaration
  additions on 4 contracts: auditHead / membership append / environments
  create / rotate (additive only; payload Schemas unchanged)
- **server**: `ensureHeadCurrent` became `Effect<AuditHeadExtensionOutcome>`
  ("current" | "more-remains") + `MAX_HEAD_EXTENSION_CHUNKS_PER_CALL = 200`
  (shrink-injectable via `makeAuditStore` options for tests). The 3 read
  paths (`auditHeadProgram` / `ensureAuditHeadAcceptable` [shared by
  standalone and boundary composites]) reject with `audit-head-not-ready` on
  "more-remains" — never judge unknown / stale on a stale column
  (fail-closed). The DataRejection / data-http mapping is auto-derived from
  the contract declaration (unwrapDataOutcome)
- **CLI (retries)**: `fetchAuditHead` (checkpoint.ts — shared with
  reconcile) got a bounded retry on AuditHeadNotReady (10 attempts,
  immediate). `issueCheckpoint`'s send stage re-fetches the declaration and
  resends under an independent budget of 10. On exhaustion it guides the
  triggering condition (first materialization of a huge log) and resolution
  by re-run. Composites' (env create / rotate) retryOnConflict also
  classifies it as retryable (the CLI's boundary checkpoints don't notarize
  [ruling M-b], so this is a defensive classification unreachable from the
  current server). Added to isServerRejection (even on 503, a typed body =
  certainly not accepted)
- **CLI (matching)**: `maruhi audit reconcile` (audit-reconcile.ts) —
  effective-admin pre-judgment → declaration fetch → all-rows fetch (shared
  paging engine + strict seq decrease) → gap check → recompute the
  cumulative column with @maruhi/crypto's canonical implementation →
  membership (a) / non-regression (b) / position floor (c) of notarizing
  checkpoints (missing or duplicated mirror rows are tampering-side
  evidence) → the declared value's membership (ruling AK) → a report in the
  2 classes
- **docs**: AUDIT_SPEC §5.1 (allowing bounded extension + fail-closed),
  AUTH_SPEC §16-2 (the API surface of 503 `AuditHeadNotReady`),
  SELF_HOSTING.md (update-order impact: old CLI × new server can yield a
  generic error — only on first materialization, resolves on re-run)

## 9. What the tests pin (summary)

- Server (vitest-pool-workers): unit semantics of bounded extension (with a
  shrunken cap: more-remains → resume from the stored tail → converge;
  exactly-at-cap is current), GET /audit-head's 503 → progress saved → retry
  gets 200, standalone fail-closed (a forged head is also 503 while
  backlogged — 422 audit-head-unknown only after the column arrives =
  post-completion acceptance semantics unchanged), boundary composite
  (rotate) 503 → accepted on resend
- CLI (vitest + local HTTP mock): 503 absorption on declaration fetch
  (issued on the 3rd attempt), a 503 at the acceptance stage (re-fetch the
  declaration and resend), the exhaustion guidance wording (condition +
  re-run), reconcile's positive (advancing through 2 notarizations —
  including a ㊙ payload's round-trip), membership violation (a), position
  violations (b)(c), gap (aborts), declared-value contradiction, the 2
  classes' report wording, 503 absorption, the effective-admin-below early
  error (0 row fetches), abort on a seq-missing response
