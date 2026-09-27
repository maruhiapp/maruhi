# Session 35 notes (PR-M2 implementation — standalone checkpoint acceptance / audit-head cumulative hash / CLI periodic issuance)

Date: 2026-08-28. Target: session-27 §14's PR-M2 (= the M2 body).
Prerequisites: PR-F1 (#87), F2 (#88), F3 (#96 / #97), F4 (#98) are merged to
main. Standalone checkpoints have so far been fail-closed by CompositeRequired,
and a boundary checkpoint's non-empty audit_head_hash was F-3's provisional
fail-closed (payload-mismatch: checkpointAuditHead). This PR implements
(1) the audit-head cumulative hash (AUDIT_SPEC §5.1) +
`GET /projects/:projectId/audit-head`, (2) acceptance of standalone
checkpoints (AUTH_SPEC §16-2 / CRYPTO_SPEC §6.4), (3) moving boundary
checkpoints' non-empty audit head under §16-2, (4) the CLI's periodic issuance
(triggers (i)(ii)(iii) + session-25 §8's anchor-update offer), and (5) tests.
The ruling process followed the goal's instruction "multiple options →
strictly-better search → 3 rounds of comparison → autonomous choice",
recording each round's rejection reasons.

## 1. Ruling J: where the canonical implementation of row_digest / h_n lives

### Round 1

- **Option J-a: keep it inside apps/server** — advantage: audit logs exist
  only on the DO, so there's a single consumer. Drawback: M4 (head-notarization
  verification / gossip) and AUDIT_SPEC §6's admin-matching CLI are already on
  the roadmap as client-side re-implementations of the same computation
  (§5.1 makes "the same h_n across independent implementations" a
  requirement). If it's server-private, the future CLI implementation has no
  fixed artifact other than "read the server's code"
- **Option J-b: put it in packages/crypto, pinned by test vectors** — only a
  composition of existing primitives (LP / SHA-256 / tagged byte strings; no
  custom primitives). Rides the existing verification discipline: vectors
  first (committed ahead) + a 4-runtime harness
- **Option J-c: put it in @maruhi/core** — rejected: core is the home of
  domain types / Schemas and has no crypto-computation verification discipline
  (vectors, 4 runtimes). §5.1's computation is part of the crypto spec

### Round 2 (strictly-better search)

- **Option J-d: put it in crypto and also share the audit-row mapping (SQL row
  → AuditHeadRow)** — rejected: column names and NULL representation are DO
  SQLite's storage form; crypto knowing the storage shape is a boundary
  violation (same kind as the "don't leak Drizzle types outside services"
  discipline). crypto's input stops at the domain shape (AuditHeadRow)

### Round 3 (re-inspection)

- Re-inspected vector expressiveness: confirmed that how h_{n-1} and
  row_digest go on the LP (hex string or raw bytes) isn't uniquely determined
  by §5.1's text alone → made the vector (audit-head.json) fix the values and
  added a minimal spec note to §5.1 spelling out the representation (ruling K
  item (1)). Followed the precedent of the chain hash (§6.2's entry hash),
  which likewise concatenates lowercase-hex strings as LP fields
- Included in the vectors the discriminating cases for a non-ASCII payload
  (㊙), an all-NULL row, and non-NULL empty string (0x01 + empty) vs NULL
  (0x00), pinning the tagged-byte-string essentials

**Choice: option J-b**.
`packages/crypto/src/internal.package/audit-head.ts` (`computeAuditRowDigest`
/ `computeAuditHeadHash`) + `test-vectors/audit-head.json` (additions only,
advance commit 4a73515) + the 4-runtime harness.

## 2. Ruling K: how h_n is maintained (the same-transaction requirement collides with async SHA-256)

AUDIT_SPEC §5.1 writes "advance h_n in the same transaction as the audit-row
append", but WebCrypto's SHA-256 is async and can't compose with the DO's
write discipline (a single synchronous block = an atomic commit within one
task — where chain insertion, mirror appends, and acceptance side effects are
written). Mirror events are generated **inside** the synchronous block, so
their h_n can't be precomputed either.

### Round 1

- **Option K-a: restructure every write path as "settle rows first → await h_n
  → write the head in a second task"** — rejected: a big rework splitting the
  write phase of every acceptance path (chain acceptance, data plane, lease)
  into 2 tasks, and a crash between task 1 and task 2 still yields the
  intermediate state "rows exist but no head" (= needing the same recovery as
  lazy extension). No atomicity gain
- **Option K-b: node:crypto's synchronous SHA-256 (nodejs_compat)** —
  rejected: introduces a new compat flag (ripples into the self-host
  distribution's wrangler.jsonc) and brushes the gray area of the "crypto
  primitives are WebCrypto + the selected HPKE only" rule. No reason to make
  an exception to the rule when lazy extension suffices
- **Option K-c: lazy materialization** — a derived column
  `audit_head_hashes(seq PK, head_hash_hex)`, where **every read path
  (GET /audit-head, checkpoint acceptance) always extends to MAX(seq) before
  reading**. Row bodies are immutable (append-only), so h_n is a pure function
  of seq — computing it anytime yields the same value — observationally
  equivalent

### Round 2 (strictly-better search)

- **Option K-d: eagerly extend in a second task on every append (read-path
  extension as a safety net)** — rejected: read mirrors like var.read are
  high-frequency paths and would charge every read with a SHA-256 chain
  catch-up. Charging every writer when readers (checkpoint issuance, audit
  matching) are rare is backwards. The lazy form puts the cost on the
  beneficiary

### Round 3 (re-inspection)

- Confirmed the partial-failure invariant: chunks (50 rows) commit
  deterministically in seq order, so a mid-way failure leaves the column
  **prefix-contiguous** — the next extension resumes from where it stopped. A
  seq gap means append-only storage corruption, so it becomes a defect (500)
- Confirmed no separate initialization migration is needed: "the first
  extension" over existing rows IS the initialization (empty table + N
  existing rows → full recomputation). SELF_HOSTING.md notes the first-access
  bulk-computation cost
- Spec consistency: made the minimal addition rewording §5.1's "same
  transaction" to "same transaction **or** observationally-equivalent lazy
  materialization (read paths extend first, prefix-contiguous on partial
  failure)" (the goal pre-approves minimal spec additions; approval is at PR
  review). Also spelled out h_{n-1} / row_digest's LP representation
  (lowercase-hex strings) (ruling J round 3)

**Choice: option K-c**. `apps/server/src/audit-store.ts`'s `ensureHeadCurrent`
(extend-before-read under permit) + a derived table in do-schema.ts.

## 3. Ruling L: the CLI's "pre-judgment of effective admin permission" (without tripping a 403)

§16-2: a non-empty audit_head_hash requires effective permission admin =
min(token scope, chain role). The CLI can learn the chain role from the
verified view, but there's no API to learn the scope half.

### Round 1

- **Option L-a: send it, and if 403 resend with empty** — rejected: the goal
  explicitly forbids this shape (don't trip a 403). It would leave pointless
  rejections in the audit log and rate limits
- **Option L-b: judge by whether GET /audit-head answers** — rejected: the
  discipline is to fetch audit-head **after** fixing the CAS parent (fetching
  first would invite stale), so the fetch order is backwards for use as
  decision material. And inferring write permission indirectly via a read-side
  403 is brittle
- **Option L-c: add tokenScopes to /auth/me (additive)** — a token principal
  receives its own scopes in the response. A session principal sees the field
  absent = full authority. The decision is the pure function "chain role
  admin+ AND scopePermissionFor === "admin""

### Round 2 (strictly-better search)

- **Option L-d: a dedicated endpoint (GET /auth/effective-permission?project=)**
  — rejected: half of effective permission (the chain role) is territory where
  the server's claims aren't trusted (the client derives it from the verified
  chain — §6.3). An API where the server answers "effective permission" blurs
  the verification boundary. An /auth/me addition returning just the scope
  half is enough

### Round 3 (re-inspection)

- Old-server compatibility: how to read tokenScopes' absence (an old server's
  response). Absence = "no scope info" and is indistinguishable from full
  authority, but an old server doesn't accept standalone checkpoints at all
  (CompositeRequired), so there is no combination where this ambiguity is
  observed. SELF_HOSTING.md notes the server-first update order
- Confirmed that additive addition via optionalKey (possibly absent) doesn't
  break existing clients' Schema checks (api-schema's MeSchema)

**Choice: option L-c**.

## 4. Ruling M: does the CLI notarize the audit head on boundary checkpoints (bundled with rotate / create)?

### Round 1

- **Option M-a: notarize boundary checkpoints too when effectively admin** —
  advantage: the notarized prefix advances on every rotate. Drawback: a
  boundary checkpoint is re-signed on composite CAS retries, and the audit
  head can advance after being fetched via mirror appends etc. — the
  notarization would drag the rotate body's acceptance into
  audit-head-stale / unknown, coupling the liveness of a revocation op
  (rotate) to audit-head contention
- **Option M-b: no notarization on boundary ones (empty string). Notarization
  is carried by the trigger-(i) periodic ones** — the post-rotate periodic
  checkpoint (standalone) supplies notarization at the same milestone, so the
  notarized prefix advances as often as under M-a. Rotate's liveness stays
  independent of audit-head contention

### Round 2 (strictly-better search)

- **Option M-c: notarize on boundary ones with a fallback that re-signs empty
  on 422** — rejected: imports a "notarized→not" branch into the composite
  retry loop, making two kinds of re-signing on failure. What it buys is the
  same as M-b (notarization ends up carried by the periodic ones) with more
  complexity

### Round 3 (re-inspection)

- Confirmed the server accepts non-empty as per spec (§16-2 doesn't
  distinguish paths) — the acceptance rule is the shared implementation in
  checkpoint-accept.ts (ensureCheckpointAuditHead), identical to standalone.
  The CLI's policy (empty) and the server's acceptance capability (non-empty
  OK) are independent; other clients' freedom to send non-empty is preserved.
  On the data-fixture side, added an additive argument to the signing helper
  so it can build non-empty boundary checkpoints, and pinned the acceptance
  path with a test

**Choice: option M-b**.

## 5. Ruling N: the coverage of trigger (i)'s (after rotate + re-encryption completes) periodic checkpoint

### Round 1

- **Option N-a: cover all environments (§6.3's SHOULD as-is)** — rejected:
  rotate is a 1-environment operation, yet covering all environments would
  force **fetching values of environments it didn't read** to build their
  values_digest. Same argument as the audit discipline (don't increase reads)
  that limited §12-4's boundary checkpoint to "1 tuple for that environment".
  Under §7's all-environment sweep it would also be O(n²) pulls
- **Option N-b: 1 tuple for that environment** — can be built only from what
  the rotate read (all values of that environment). The SHOULD for all-
  environment coverage is carried by triggers (ii) (explicit command) and
  (iii) (the offer)

### Round 2 (strictly-better search)

- **Option N-c: widen to cover "environments already in the verified view"** —
  rejected: at rotate time the view normally has no other environments' values
  (pull is per-environment), so it degenerates to essentially N-b's set. A
  non-deterministic coverage that's "wide only sometimes" makes both tests and
  operational prediction worse

### Round 3 (re-inspection)

- Confirmed limiting issuance timing to "only on complete re-encryption
  completion" (remaining === 0 and no failure): on partial completion no
  "post-completion data state" exists, so there's no milestone to notarize.
  Since it's a SHOULD, an issuance failure doesn't overturn the rotate's
  success and is disclosed as a warning

**Choice: option N-b**.

Addendum (PR #99 review response): the completion milestone applies equally to
the **resume path** (resumeReencryption) — if the first run crashed, it's only
the resume-side run that completes that reaches issuance (an implementation
gap fixed on a Bugbot finding). The remaining uncovered window is a crash in
"after the last push succeeds, before the checkpoint is issued", where the
next run enters the up-to-date path (nothing incomplete) and doesn't issue.
This is **recorded as a boundary**: issuing from the up-to-date path would
write a checkpoint on every "just checking" run (unconditional issuance
diverging from §6.3's periodicity), which is excessive as a way to close the
window. The trigger-(iii) 7-day staleness offer picks up this window, and
since §6.3 issuance is a SHOULD the gap is spec-tolerated (per the pullfrog
incremental review's finding — no change, only recording the boundary).

## 6. Ruling O: applying the 3-F intent discipline (journal-before-send) to checkpoint issuance

Rotate recovers from interruption via "journal the intent before sending"
(3-F) — does checkpoint issuance get the same discipline?

### Round 1

- **Option O-a: introduce an intent journal** — rejected: a checkpoint
  advances no local state (floor update and anchor update are separate
  operations), and whether the send "landed or was lost" is harmless either
  way (landed = one more notarization, lost = nothing changes. Re-running is
  always safe). There's no "in-flight state lost to interruption" for a
  journal to protect. The chain itself is the persistent record
- **Option O-b: no journal + only §12-10(3)'s post-acceptance confirmation** —
  the mutation's effect is confirmed only through verifiable distribution
  (that the re-synced chain contains your entry). On transport failure it
  reports honestly — "unknown whether it landed, safe to re-run" — rather
  than a rotate-style probe

### Round 2 (strictly-better search)

- **Option O-c: automate the landing check with a post-send probe (same shape
  as rotate's appendRotation)** — rejected: rotate's probe exists to prevent
  the intermediate state "epoch advanced but re-encryption not run". A
  checkpoint has no intermediate state, and the probe-failure branch (resend
  or not) would only produce non-equivocating double issuance (harmless but
  wasteful)

### Round 3 (re-inspection)

- §12-10(3)'s confirmation happens via resync → `history.entryHashAt(seq) ===
  computeChainEntryHash`, and the test pins the form that doesn't trust the
  server's 2xx (lying server → exit 1)

**Choice: option O-b**.

## 7. Ruling P: the attachment point of session-25 §8's anchor-update offer

### Round 1

- **Option P-a: dedicated detection logic (independent anchor-freshness
  judgment)** — rejected: the primary driver of anchor "staleness" is epoch
  advancement (rotate), and a time-based independent judgment would create a
  second freshness concept duplicating (iii)'s checkpoint offer
- **Option P-b: unconditional guidance after rotate succeeds; after push
  succeeds, tied to (iii)'s staleness** — rotate always invalidates the epoch
  floor (guidance is always warranted). push only advances the data state, so
  it's bundled at the same milestone as the 7-day staleness ((iii))

### Round 2 (strictly-better search)

- **Option P-c: integrate the rotate side into (iii) too, unifying the offer
  to one path** — rejected: right after a rotate the anchor is **certainly**
  stale (the epoch advanced), yet this form would wait for the 7-day
  condition. Forcing two triggers of different certainty onto the same
  threshold delays guidance from the certain one

### Round 3 (re-inspection)

- Checked the noise side: on a sweep (all-environment rotate) it guides once,
  not per environment (aggregated in reportSweepOutcome). All offers are
  non-failing (guidance only) and don't affect the command's exit code

**Choice: option P-b**. The attachment point of trigger (iii) is only after
push / pull commands succeed (`run` / `ci run` have value injection as their
substance — no interactive guidance is inserted). The admin staleness basis is
"the latest **notarizing** checkpoint"; others use "the latest checkpoint"
(without the split, a member's issuance would consume the admin's trigger and
the notarized prefix would never advance).

## 8. Ruling Q: PR splitting

### Rounds 1–3 (summary)

- **Option Q-a: a stack of crypto-first PR + server PR + CLI PR** — rejected:
  this session was assigned a single development branch (the goal's absolute
  constraint), so a stack's intermediate branches can't be pushed. The
  crypto's "committed first" requirement is satisfiable by commit order within
  one PR (vectors → implementation)
- **Option Q-b: a single PR, commits in layer order** — keeps reviewability
  via the order: vectors (4a73515) → crypto implementation → api-schema /
  server → CLI → tests / docs

**Choice: option Q-b**.

## 9. Summary of what was implemented

- **crypto** (human review required): `audit-head.json` vector (additions
  only, committed ahead) + `internal.package/audit-head.ts` (`AuditHeadRow` /
  `computeAuditRowDigest` / `computeAuditHeadHash`) + a 4-runtime harness
  check (checks/audit-head.ts)
- **api-schema**: `CheckpointMismatchReasonSchema` (5 values), narrowed
  CompositeRequired's ops to create_environment / rotate_epoch, the
  `auditHead` endpoint, `MeSchema.tokenScopes` (optionalKey, additive),
  CheckpointStateMismatchError added to membership append's error list
- **server**: the `audit_head_hashes` derived table (do-schema) + lazy
  extension (audit-store `ensureHeadCurrent`). `checkpoint-accept.ts` gained
  standalone acceptance (CAS → verifyChain → per-tuple acceptance-time
  matching → audit-head existence / position check → atomic commit with
  snapshot save in the synchronous block). The boundary path shares
  `ensureCheckpointAuditHead`, replacing F-3's provisional fail-closed.
  `requiredPermissionForEntry` (checkpoint: empty = write / non-empty = admin)
  checks the scope half at the worker; the role half is the DO's requireRole
  (403)
- **The floor of audit-head-stale**: the seq of the chain.checkpointed mirror
  row of the immediately-previous checkpoint (regardless of whether it
  notarized). Vacuously true on the first checkpoint — the same predicate and
  basis as AUDIT_SPEC §6's admin matching
- **CLI**: `maruhi project checkpoint` (trigger (ii)) / trigger (i) after
  rotate completes / the (iii) offer + anchor guidance after push / pull
  succeed. The audit head is fetched after the CAS parent is fixed; a 422 is
  bounded-retried via full re-pull (3 attempts), and after exhaustion it
  issues once with the subset unchanged across the last 2 builds. A head-CAS
  conflict re-syncs + re-signs (5 attempts). After acceptance it confirms via
  §12-10(3)'s verifiable distribution
- **docs**: minimal additions to AUDIT_SPEC §5.1 (hex-string LP
  representation, allowing lazy materialization — approval at PR review), and
  SELF_HOSTING.md notes the server-first update order and the first lazy
  extension's bulk-computation cost

## 10. What the tests pin (summary)

- Server (vitest-pool-workers): the permission matrix (a)(b)(c)(d) (session-27
  §13-5), the 5 kinds of 422 reasons, **rejecting notarization of a
  nonexistent future manifest_version + atomicity** (session-33 §5's negative
  — head unchanged, no mirror growth, a subsequent legitimate checkpoint
  succeeds), path-identity of snapshots under subset re-issuance
  (environment-B rows byte-identical), non-empty notarization on a boundary
  checkpoint (owner 200 / member 403)
- CLI (vitest + local HTTP mock): tuple construction derives from the
  verified view (never signs server-declared values), notarization
  pre-judgment (member 0 times / write scope 0 times), 422 retry and subset
  fallback, trigger (i)'s rotate integration, the admin/member basis
  difference of the (iii) offer, exit 1 on a lying server (2xx but not landed)
