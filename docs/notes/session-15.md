# Session 15 notes (name-authenticity implementation — implementation PR-3 of the session-12 spec)

Date: 2026-08-04. Prerequisites: confirmed PR #30 (implementation PR-2 = value authenticity.
squash merge `9b9fec1`) is an ancestor before starting.
Scope: session-12.md §9's **PR-3 = metadata statements (option D)**. Per the approved
CRYPTO_SPEC §4.2, signed metadata statements (create, rename, delete) for variables and
environments plus authenticated name resolution land in layer order — vectors first → crypto/core →
api-schema → server → CLI.
**PR #31 merged 2026-08-04** (squash merge `d0b9107`. §2's rulings are owner-approved.
§6's 2 spec-sync items — AUTH_SPEC §12-8 / §12-4 — were applied in post-merge session 15.5).

## 1. What was done

1. **Test vectors first** (an independent commit ahead of implementation; human review target):
   - New `metadata-signature.json` (session-12 §8-2): references chain-entries.json's canonical
     12-entry chain (the cross-file precedent). The 9 positive cases pin the prev chain of
     "create → rename → delete" (deletion preserves the immediately-prior active name), the
     environment version (a composite-bundled declared head = the pre-append head; delete-only at
     admin level), a deleted author's in-membership head, and
     **`var-meta-head-before-env-create` = positive** (no epoch anchor = the intended asymmetry of
     not checking environment existence — §14.3-5 / AUTH_SPEC §12-4)
   - 15 tamper/transplant negatives (tampered-status = blocking an unsigned delete forgery,
     nfc-variant = pinning byte-exact signing, cross-kind-transplant = includes var / env
     domain separation) and 11 verification-rule negatives (2 head kinds, membership, key binding,
     the role-level difference `env-delete-role-insufficient`, prev shape / chain,
     `revive-after-delete`). `rename_fork` (a fork at the same metaVersion = equivocation evidence
     where both verify successfully) and `name_swap` (a name swap fails signature) went into
     dedicated sections (session-14 §5's lesson — in negative shape a wrong implementation can't be
     detected)
   - Added an independent verification to verify_reference.mjs (all 425 checks PASS). The existing
     8 vector files are byte-identical after oxfmt (confirmed mechanically via git diff)
2. **crypto**: `meta-sign.ts` (LP canonicalization of var-meta-sig / env-meta-sig,
   signMetaStatement / verifyMetaStatementSignature / computeMetaSignedBytesHash),
   `meta-verify.ts` (`verifyDistributedMetaStatement` — per ruling A, an isomorph of PR-2's
   verifyDistributedValue reusing ChainHistoryIndex. No double implementation of the machinery).
   Introduced `MetaInvalidReason` (10 kinds) + the `MetaStatementInvalid` kind; core maps it fully
   onto `CryptoMetaStatementInvalidError`
3. **api-schema**: `VariableMetaStatement` / `EnvironmentMetaStatement` (the request shapes
   narrow by lifecycle: create = metaVersion 1, active, prev empty / rename = active / delete =
   deleted) + distribution-only Distributed* (author info). Variable creation = v1 value +
   statement bundled (bare variableId / name abolished), rename / delete carry statements, the
   `name` of composite environment creation was replaced. **Revised every response returning a
   name** (EnvironmentSummary / EnvironmentPull / PulledVariable + `deletedVariables`).
   422 `MetaStatementRejected` (the 3-word vocabulary shared with value signatures) / 409
   `MetaVersionConflict` (latest number only) / 422 `NameNotNfc`
4. **server**: `variable_meta_statements` / `environment_meta_statements`
   (NOT NULL raw DDL — see §4), `acceptMetaStatement` (cap → CAS → predecessor → signature
   verification) shared across the 4 rename / delete paths, NFC check (check only, no
   normalization), the delete statement's name-preservation check (byte-exact), composite
   creation's declared head = strict equality with the pre-append head + verification against
   pre-append history, continued distribution of delete statements and deleted-environment
   tombstones, author key FP on the 5 audit kinds
5. **CLI**: extended pull's full verification to statements (environment, active, tombstone —
   future head reuses PR-2's bounded re-sync), made name resolution verification-mandatory
   (NFC-normalized key + byte-exact, duplicate active same-name = resolution rejected), bundled
   author-signed statements into push's create path, extended winnerRegression with the meta
   isomorph (metaVersion regression, differing signed bytes at the same metaVersion = reject),
   env create's composite CAS retry **re-signs both the entry and the statement**, warns on
   non-NFC distribution
6. **Tests**: vector-driven across crypto's 4 runtimes (metadata-signature checks added)
   + server 193 / CLI 127 (see §7)
7. **docs**: this memo

## 2. Ruling details (multi-option comparison → proceeded on recommendation → finalized)

2026-08-04 owner judgment: 2-1 through 2-3 / 2-5 through 2-7 approved as presented. 2-4 was
delegated to the implementation side and finalized via the re-examination below (a 5-option
comparison including 3 new options).

### 2-1. MetaInvalidReason is a separate vocabulary from Value (task ruling A's implementation shape)

The crypto layer's reason codes became an independent `author-*`-prefixed vocabulary (10 kinds).
Reusing ValueInvalidReason would drift the word "writer" from meta's semantics (author), and the
2 kinds `epoch-not-current-at-head` / `epoch-regressed` would remain as structurally impossible
values. The wire is mapped by the server into the spec's 3-word vocabulary (session-12 §6-7)
(`META_REJECT_REASONS` — Record-type coverage statically checked).

### 2-2. deleted semantics on the verification side: if the predecessor is deleted, all successors are rejected

§4.2's "re-activation after deleted is forbidden" was implemented in predecessor-bearing
verification as "any statement succeeding a deleted is rejected regardless of status
(`revived-after-delete`)" (even deleted → deleted overwriting has no legitimate use case; a
tombstone is terminal). The signing side rejects binding violations (metaVersion 1 ⇔ prev empty,
metaVersion 1 = active) with InvalidInput (the same asymmetry as value-sign — the verification
side must reject "valid signature + rule violation" wire data with reason codes).

### 2-3. Request Schema lifecycle narrowing (final)

Pinned **in the wire Schema**: create = `metaVersion: Literal(1)` / `status: Literal("active")` /
`prev: Literal("")`, rename = active, metaVersion ≥ 2, prev 64hex, delete = deleted, same as rename
(e.g. "deleted at creation" is a 400, not a server check). The distribution shape is the union over
all lifecycles. The alternative (single Schema + server-side checks) only loosens the wire with no
benefit. As a result, `MetaVersionConflict` on variable creation is practically unreachable, but it
was declared on the endpoint as the CAS contract (the mapping target of the DO's defensive CAS +
the receptacle for concurrent-rename races — the CLI re-resolves from the name).

### 2-4. Distribution channel for delete statements (final — re-examined after delegation)

As the concretization of "keep storing and distributing" (§12-4/-5): (a) added `deletedVariables`
to bulk pull (the list of tombstone statements for deleted variables — no values since ciphertexts
are deleted), (b) the environment list also enumerates deleted environments with their latest
deleted statement. The client verifies tombstones too and rejects an active / deleted pair at the
same variableId (the carrier shape of unauthorized revival). On environment deletion, the
**variable statements under it are deleted** (environment IDs can't be reused under chain consensus
rules, so variable-side tombstones have no residual value as detection material — the environment's
own deleted statement is the detection material).

**How deleting subordinate statements on cascade was finalized** (2026-08-04 owner delegation →
re-examined via 5 options): ① keep everything — a deleted environment's subordinate statements have
no distribution channel (pull is 404; the environment list shows only the environment tombstone),
and server-stored data that isn't distributed can't be verified by clients, so it doesn't function
as detection material. ② the compromise of keeping only deleted tombstones — an environment
tombstone alone already guarantees non-revival of everything under it, so additional detection value
is zero; a degraded form that only keeps names longer. ③ keep with name edited — the signature
covers all fields including name, so editing destroys evidence value; doesn't work. ④ keep only a
digest of the signed bytes hash — under this design the server is an untrusted party; equivocation's
evidentiary force lives in client-held verified copies + the chain. A digest inside the server's own
storage is not evidence against the server. ⑤ delete (adopted) — detection-material value is
structurally zero, consistent with the "freed on deletion" principle (§12-8) and E2EE deletion
semantics (a variable name itself may carry information). Operational traceability is held
independently by the audit log (append-only; name snapshot + author key FP — AUDIT_SPEC's design).

### 2-5. The delete statement's name preservation is server-enforced byte-exact

A delete where `statement.name !== stored current name` is a 422 `PayloadMismatch` (field =
"name"). The stored name passed NFC checking at acceptance, so the delete side needs no independent
NFC check (equality is stronger).

### 2-6. meta-versions cap (final — an acceptance-policy addition not in §12-8's table)

Applied the same cap as "versions / variable" (1,000) to rename statement rows (the
`meta-versions` resource). Statement rows weren't bound by any §12-8 cap, so rename spam could pile
up without bound (it's an acceptance policy, not a consensus rule — raising it in self-hosting
doesn't break consensus). Adding it to the spec table was planned on the AUTH_SPEC side after PR
review approval (→ applied to AUTH_SPEC §12-8 in post-merge session 15.5).
**Deletion (status deleted) is exempt from the cap** (the fix for §8 review ②③ major):
a tombstone is the chain's terminal with at most 1 additional row, and blocking even deletion would
leave a cap-reached resource permanently undeletable at any role (conflicts with §12-8's "freed on
deletion" principle, and also violates the remove endpoint's wire contract — `DataLimitExceededError`
is undeclared). The check is based on stored state (latest + 1 > cap)
(`metaVersionsExceeded` — doesn't misreport a stale declared metaVersion as limit-exceeded).

### 2-7. Composite creation's declared head is checked with strict equality

§12-4's "the bundled statement's declared head is the pre-append current head (= identical to the
bundled entry's prev)" was implemented as an **equality check** (both hash + seq), not an existence
check (mismatch = 422 `PayloadMismatch` field "statementChainHead"). Existence-only would pass
"a declaration of an old real head" and split acceptance ranges across implementations (reading the
spec's "is" as normative). Since head CAS (parent-head mismatch) is judged first, the legitimate
retry flow stays 409 → re-sign both → 200.

## 3. DDL & storage (ruling E)

Added to Project DO SQLite as raw DDL, NOT NULL (D1 / Drizzle / migrations unchanged):

| Table / column | Content |
|---|---|
| `variable_meta_statements` | (environment_id, variable_id, meta_version) PK. suite / name / status / prev_meta_sig_hash_hex / declared head (hash + seq) / signature_hex / **server-recomputed** signed_bytes_hash_hex (material for prev checks and 409 retries; not distributed) / author_user_id + author_key_fingerprint (chain-derived at acceptance) / created_at |
| `environment_meta_statements` | same as above minus variable_id ((environment_id, meta_version) PK) |
| `variables.latest_meta_version` / `environments.latest_meta_version` | derived cache of the latest statement (for metaVersion CAS / distribution join. The name column is likewise a copy of the latest statement) |

The signed bytes themselves and public keys are not stored (reconstructible from coordinates and
the chain). No backfill or nullable transition was created (pre-release; no applied environments).
**Old local-dev `.wrangler/state` must be discarded before running this branch**
(same caveat as session-08 §3 / session-13 / session-14 — old-schema environments / variables rows
lack the latest_meta_version column, and `CREATE TABLE IF NOT EXISTS` can't add missing columns to
an existing DB for the 2 new tables either).

Distribution returns the stored statement + author as-is without re-deriving from the current
member set (keeps a deleted author's past statements verifiable with the keys of their time —
pinned in integration tests). Audit copies only the author's key FP; signatures, signed bytes, and
hashes are never recorded (AUDIT_SPEC §3.3). Since cascade var.deleted rows of environment deletion
carry no individual statements, they copy the env delete statement's author FP (the semantics of
"FP = evidence of the signature" — the signature that authorized this deletion is on the env side).

## 4. Known constraints / v1 tolerances (what this PR does **not** guarantee)

- **Meta forward-injection is undetected in v1** (§14.3-5 — the most important honest record):
  meta statements carry no epoch anchor (§4.2), so a holder of a key with a "member-or-above
  membership interval" in chain history + the server can sign a fake statement at a declared head
  inside that interval at **the metaVersion after the real latest** (attributed) and inject it
  passing chain verification. No structural equivalent of value signing's epoch monotonicity +
  floor rule (c) exists, and **even introducing the floor (PR-4) won't detect it**. v1 goes as far
  as fork evidence (a fork in the prev chain = non-repudiable evidence). Closure is the duty of
  Phase 2's environment manifest / checkpoint (CRYPTO_SPEC open item #12) and head gossip.
  The vector `var-meta-head-before-env-create` (positive) and this PR's verification implementation
  **not having** an epoch check is the intentional pinning of this asymmetry — no test or
  implementation is left that would misread it as "detected"
- **latest-only**: pull holds no predecessor, so meta's prev existence match and
  revive-after-delete can't be checked at distribution time (shape checks only; server acceptance
  and predecessor-bearing verification — the 409 procedure — do check). Persistent detection of
  rollback / omission is PR-4's local floor (meta's floor is a metaVersion floor — forward
  injection isn't closed by the floor either, per above)
- No rename / delete commands were added to the CLI (task ruling F). Statement author signatures
  exist only on the create path; server acceptance of rename / delete is verified by integration
  tests
- The execution-control variable-name denylist (session-11) is maintained as a defense layer and
  applies to verified names (even with name authenticity in place, the path where a legitimate
  member signs a malicious name — G9 — remains)
- gossip / checkpoint / manifest / rotate CLI / chain-operation CLI /
  remove+rotate composition / DO total-size guard / session-11 follow-up PRs / variable-name
  secrecy are not in this PR (out of the task-specified scope)

## 5. Sticking points & environment findings

- **Unifying "name carriage" into one path breaks the most tests**: abolishing bare `name`
  (EnvironmentSummary / PulledVariable / create payloads) touched nearly every fixture across
  server 84 / CLI 127 tests. Settled on having fixtures hold "latest statement + author records"
  (Maps of varStatements / envStatements), with rename / delete prev chaining automated by a test
  helper
- **Setting the CLI mock's pull-response statement declared head to genesis (seq 1) works under
  every view**: genesis's entry hash = projectId exists in every extension view, and the owner is
  member-or-above since seq 1. Even in future-head tests (short chain → re-sync) the statement side
  doesn't accidentally become future
- **Expected audit rows shift by one position at the cascade-deletion point**: environment deletion
  writes in the order "remaining variables' var.deleted (env author FP) → env.deleted", so a test
  that deleted a variable individually first ends up with 5 lifecycle rows at the tail (pinned by
  the helper as event-name/FP pairs)
- **fallow's audit gate is on changed files**: the 4 rename / delete programs became an isomorphic
  4-block of "cap → CAS → predecessor → signature" and tripped the gate on dupes / complexity.
  Resolved by extracting into `acceptMetaStatement` (the cli / server test-support clone groups
  stay as baseline warnings — the domain of session-11's ruled independent PR)
- **Python's `unicodedata.normalize` and JS's `String.prototype.normalize` agree on NFC**: the
  nfc-variant vector generated NFD in Python and pinned it against the JS side's
  (verify tool / implementation / tests) `normalize("NFC")` comparison

## 6. Handoffs

- **PR-4 (CLI local floor)**: the metaVersion / metaSignedBytesHashHex that values.ts returns
  become the floor's record material (same arrangement as the value side's signedBytesHashHex /
  version / epoch). **Also document in the floor's docs that meta's floor detects only rollbacks —
  forward injection is not closed** (per §4)
- **Adding `meta-versions` to AUTH_SPEC §12-8's table** (§2-6 is owner-approved): recommend a
  spec-sync PR adding "metaVersion rows / variable (environment) = 1,000 (status deleted exempt)"
  to the acceptance-policy table (→ applied in session 15.5)
- **Documenting cascade targets in AUTH_SPEC §12-4** (review ③ minor): propose to a human a
  revision stating "variable meta statements" in the environment-deletion cascade enumeration
  ("variables, versions, wrapped DEKs under it") (rationale = environment IDs can't be reused on
  the chain; the spec-side pinning of §2-4's ruling) (→ applied in session 15.5)
- **Consistency of crypto's defensive checks (independent-PR candidate — review ① minor / ③ nit)**:
  (a) add projectId / environmentId non-empty checks to `meta-sign.ts` / `value-sign.ts`'s context
  checks (LP makes encoding unambiguous even when empty = not a vulnerability, but inconsistent with
  other fields' check level). (b) make `verify_reference.mjs`'s signature field order a spec
  hardcode + consistency check with the JSON, instead of deriving it from the vector JSON
  (chain-entries's `payload_field_order` is the same shape — do it at the same time)
- **Shared extraction of test support (session-11 §5's ruled independent PR)**: this session grew
  signMetaStatementAs / statementFor clones further on both cli and server sides (fallow dupes 8
  groups). Clear them together with the baseline at extraction time
- session-11 §5's remainder (public-config endpoint / metadata-only pull mode — at implementation
  time the meta-only response must also bundle §4.2 statements + signatures = session-12 §13) and
  chain-append commands + remove_member's all-environment rotate (incl. session-12 §10-7's
  composition consideration) remain untouched and still valid

## 7. Test results

- vectors tools: `bun run generate` (existing 8 files byte-identical) +
  `bun run verify` all 425 checks PASS (including the metadata-signature additions)
- `@maruhi/crypto`: node 460 / workerd 460 / browser 460 / Bun 459 (the vitest
  aggregation 1-count diff is as before) — metadata-signature checks added
- server (vitest-pool-workers): 194 tests green (10 new meta acceptance checks; existing fixtures
  fully updated to require statements — intentional pre-release wire incompatibility. A review fix
  added a test accepting deletion at the cap)
- CLI: 128 tests green (added 9 statement distribution-time verifications, 4 push meta-409
  procedure cases, and the composite-CAS re-sign-both check. A review fix added an
  adjacent-prev-mismatch rejection test)
- `bun run check` (fmt / lint / typecheck / importlint / fallow / doctor / test)
  green (809 tests)

## 8. Review→fix loops (inside the PR. 3 parallel review perspectives → fixes)

After implementation, 3 independent review perspectives ran in parallel (① security & crypto
② correctness, concurrency & fork ③ spec, vectors & wire). No blocking findings. 1 major
(found independently by ②③) and 1 minor were fixed in code; the rest were resolved on the record /
via handoffs.

### Fixed findings

- **[major / ②③] the meta-versions cap also blocked delete statements, leaving a cap-reached
  resource permanently undeletable**: a delete (metaVersion 1,001) against a variable / environment
  at latest_meta_version = 1,000 also returned `limit-exceeded`, after which no role could delete it
  (an environment a member renamed 999 times would remain active and undeletable even by admin,
  permanently occupying one of the 100 active-environment slots). Furthermore the remove endpoint
  doesn't declare `DataLimitExceededError`, so the response is a 500 (a wire-contract violation).
  → fixed `ensureMetaQuota` to **exempt status deleted** + **base the check on stored state
  (latest + 1)** (ruling added to §2-6). Pinned by a test seeding a cap-reached state and accepting
  deletion, plus judgment tests of the pure function `metaVersionsExceeded`
- **[minor / ②] `winnerMetaRegression` lacks the adjacent-predecessor prev match check**: the value
  side's `winnerValueRegression` checks prev against the verified signed-bytes hash when
  winner.version = known + 1 (from the PR-2 review loop), but the meta side had no isomorphic check
  and missed a branch chain detectable for free inside a retry session holding the adjacent
  metaVersion. → added the verified statement's `prevMetaSigHashHex` to `VerifiedPulledValue` and
  implemented the isomorphic adjacent check. Pinned by a CLI test rejecting distribution of a
  successor statement with a prev mismatch

### Findings resolved on the record (no code change)

- [minor / ①] `meta-sign.ts`'s missing projectId / environmentId non-empty check: LP makes
  encoding unambiguous even when empty, and the server re-derives coordinates itself, so it's not a
  vulnerability. Same shape as PR-2's `value-sign.ts` — consolidate both into an independent PR
  (§6 handoff)
- [minor / ③] the physical deletion of variable statements on environment-delete cascade is an
  implementation ruling not in AUTH_SPEC §12-4's enumeration: no real harm since environment IDs
  can't be reused on the chain (§2-4). Proposed spec-side documentation to a human (§6 handoff)
- [nit / ②] `ensureMetaQuota`'s judgment basis: bundled into the major fix (changed to state-based)
- [nit / ②] deletion's name byte-exact check (422) is judged before the metaVersion CAS (409): both
  are deterministic rejections with no security difference. Just note that when a delete command is
  added to the CLI (ruling F) the race won't be visible from 409-driven retries (current order =
  intended; the name check is a "payload shape" check one layer before CAS)
- [nit / ②] the path where `reresolveTarget` discards a verified floor without comparison: only
  reachable on a create attempt, and create has no floor, so it's unreachable under the current
  contract. Add `winnerRegression` application when widening the error contract (natural to do
  with PR-4's floor implementation)
- [nit / ①] that the `MetaVersionConflict` declaration on variable creation is practically
  unreachable: already noted in an existing comment at the corresponding spot in `data-api.ts` (§2-3)
- [nit / ③] `verify_reference.mjs`'s field order derives from the vector JSON: same shape as
  chain-entries' existing pattern. Spec-hardcode it in an independent PR (§6 handoff)

### Re-review

Both fixes only narrowed the acceptance range / added checks (the delete quota exemption removes the
defect of "caps blocking deletion"; CAS, signature verification, and prev-chain checks are
unchanged). After the fixes, the full quality gate re-ran green, converging with zero blocking /
new major findings.
