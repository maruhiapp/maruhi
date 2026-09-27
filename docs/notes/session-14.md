# Session 14 notes (value-authenticity implementation — implementation PR-2 of the session-12 spec)

Date: 2026-08-04. Prerequisites: confirmed PR #28 (implementation PR-1 = DEK authenticity, merge `3250571`) and
PR #29 (docs sync `808c61e`) are ancestors before starting.
Scope: session-12.md §9's **PR-2 = value signing (option A + C minimal core)**. Per the approved
CRYPTO_SPEC §4.1, commits land in layer order — vectors first → crypto/core → api-schema → server → CLI —
for value writer signatures, authorization-time binding, prev chaining, and fork evidence.

## 1. What was done

1. **Test vectors first** (committed before implementation; human review target):
   - New `value-signature.json` (session-12 §8-1): references chain-entries.json's canonical
     12-entry chain (the cross-file precedent). ciphertext is a real AES-GCM ciphertext under
     `environment_deks`'s dummy DEK (value signature → §4 decryption is one continuous real data
     flow). The 6 positive cases pin §6.3's inclusive convention at boundaries
     (a push whose declared head is the create / rotate entry itself, a removed writer's
     past value from its membership interval, the rotation executor's re-encrypted push = an
     epoch-monotonic prev chain)
   - 14 tamper/transplant negatives (Ed25519 failure of the original signature) and 12
     verification-rule negatives (rejected via `expected_reason` while **the signature stays valid**). The 2 head-mismatch kinds
     (`chain-head-mismatch` = immediate evidence / `chain-head-future` = entry to re-sync),
     a tenure-crosser (`tenure_extension` = derived chain of canonical 12 + seq 13 re-add with a
     new key — chain-entries.json itself unchanged), and prev's shape / chaining /
     epoch monotonicity pinned by reason code
   - `fork_same_version`: 2 valid signatures at the same coordinates = equivocation evidence
   - Added the missing `signer_user_id` to `dek-wrap-signature.json`'s description
     (session-12 §13's handoff. `signed_fields_order` unchanged). Confirmed other existing
     vectors are byte-identical after oxfmt
2. **crypto**: `value-sign.ts` (LP canonicalization, signValue / verifyValueSignature /
   computeValueSignedBytesHash), `chain-history.ts` + `verifyChainWithHistory`
   (ruling A's ChainHistoryIndex — see §2), `value-verify.ts`
   (`verifyDistributedValue` = §6.3's composite check of items 1–4 & 6).
   Introduced `ValueInvalidReason` / the `ValueInvalid` kind, and core maps it fully onto
   `CryptoValueInvalidError` (kind-table coverage statically checked)
3. **api-schema**: signature block on `EncryptedPayload` (prevValueSigHashHex =
   ""|64 hex / chainHeadHashHex / chainHeadSeq ≥ 1 / signatureHex), the distribution-only
   `DistributedEncryptedPayload` (writerUserId + writerKeyFingerprintHex),
   `PulledVariable.value` moved to the distributed type. 422 `ValueSignatureRejected` (3 reasons)
4. **server**: added 7 NOT NULL columns to `variable_versions` (see §4),
   StateCache became a state + history-index pair, push / create (bundled v1 also gets the same
   verification) acceptance checks inserted right after CAS and before quantity policy (ruling D's
   check order), pull distributes the stored writer / signature block as-is, `var.created` /
   `var.version_pushed` carry the chain-derived writer FP (AUDIT_SPEC §3.3)
5. **CLI**: verify all values before decryption (values.ts), bounded re-sync + extension check on
   future heads (sync.ts's ensureExtensionOf), push's prev chaining (self-computed hash of the
   verified latest) & signing with own user id + master sig key, the 409 VersionConflict
   winner re-fetch procedure, EpochConflict's re-sync with extension check
6. **Tests**: vector-driven across crypto's 4 runtimes (chain-history / value-signature
   checks added) + server 181 / CLI 109 (see §7)
7. **docs**: this memo

## 2. Ruling details (multi-option comparison → proceeded on recommendation; confirmation = PR review approval)

### 2-1. ChainHistoryIndex is built inside verifyChain's loop (ruling A's implementation shape)

| Option | Evaluation |
|---|---|
| **`verifyChainWithHistory` builds the index alongside the verification loop (adopted)** | it's structurally guaranteed that "the index can only come from a verified chain", and the state-machine semantics (role transitions, epoch transitions) stay aligned with verifyChain in a single implementation. The verification loop computes entry hashes anyway for the prev chain, so recording them is free |
| A separate `buildChainHistoryIndex(entries)` | creates a misuse surface where an index is built from an unverified chain, and the role/tenure derivation loop duplicates verifyChain's (a breeding ground for semantic divergence when consensus rules are added later) |

The index's query API was kept minimal (ruling A): `entryHashAt` (seq → hash),
`memberStateAt` (role / key binding / tenure-start seq at the inclusive point — remove →
re-add is a separate tenure), `environmentStateAt` (created? + epoch at that point),
`sigKeyByFingerprint` (§6.3-1 key selection — covers all tenures. Since head-time binding checks
are done separately by `memberStateAt`, a tenure crosser resolves to "signature verifies → rejected
on binding mismatch" = per check order (provisional ruling C) a broken signature is judged first).
No timestamp is used in any index query. The CLI's existing `keyHistory` stays dedicated to DEK-wrap
§5.1 verification (head-binding-free semantics) and is not used for value verification.

### 2-2. Mapping of the 422 reasons (provisional ruling C — confirmation = PR review approval)

Only the spec's (session-12 §6-7) 3 reasons go on the wire; the server maps from the crypto layer's
detailed reasons (12 `ValueInvalidReason`s) via `toValueRejectReason`:

- `signature-invalid` ← only Ed25519 failure on a valid-format signature
- `chain-head-unknown` ← `chain-head-mismatch` / `chain-head-future` (to the server,
  "a seq not on its own chain" is the same absence. The re-sync branch is a client-side
  concept the server doesn't have)
- `chain-head-state-mismatch` ← everything else (membership, key binding, role, environment,
  epoch at the head point; prev's shape / mismatch against the stored predecessor; writer-unknown)

**Comparison of alternatives**:

| Option | Evaluation |
|---|---|
| **3 reasons + check order = broken signature → unknown head → state mismatch (adopted)** | matches the spec's reason enumeration. A prev mismatch doesn't collapse into an Ed25519 failure (ruling B). For all 3 reasons the client enters the same recovery path (re-sync → rebuild) as "a bug in my assembly or sync state / a view difference vs the server", so this wire granularity suffices |
| Fold prev mismatch into `signature-invalid` | crushes the evidence information "signature itself is valid but the chain differs". Not adopted since it harms fork-evidence debuggability (§14.2-5) |
| Add a 4th reason (e.g. `prev-mismatch`) | a wire change (the reason vocabulary is API contract) requiring a revision of the spec's 3-reason enumeration. If finer granularity is ever needed, do it in a future PR together with the spec revision |

### 2-3. Implementation shape of the latest-only limit (ruling B)

`verifyDistributedValue`'s check coverage changes with whether a predecessor argument is passed:

- **Always checked**: signature, head (2 kinds distinguished), membership / key binding /
  role at the declared head, environment created, epoch consistency, coordinates (the caller builds
  context from expected coordinates), prev's **shape** (version 1 = empty / version > 1 = 64 hex —
  `prev-shape-mismatch`)
- **Only when a predecessor is passed**: prev's existence match (`prev-hash-mismatch`) and
  epoch non-regression (`epoch-regressed`). When not passed, it doesn't pretend to be "checked"

The server always passes the stored N-1's signed_bytes hash for version > 1 (it's post-CAS so it
always exists — absence is a defect). The CLI's pull is latest-only so it can't pass one
(persistent detection of rollback / omission / forward-injection is PR-4's local-floor domain — see §6).
In push's 409 procedure, the "verified winner" plays the predecessor-equivalent role
(the next version's prev uses the self-computed hash).

Note that the signing side (`signValue`) rejects version ↔ prev binding violations with
InvalidInput (it won't produce a signature that violates the binding itself), while the verification
side must reject wire data of "valid signature + rule violation" with reason codes — hence the
asymmetry of putting the binding in verification rules (pinned by vectors `v1-nonempty-prev` /
`v2-empty-prev`).

### 2-4. Handling future heads (ruling G's implementation shape)

- Hash mismatch at `seq <= own head` → immediate rejection (`chain-head-mismatch` —
  hard evidence of a fork or forgery)
- `seq > own head` → re-sync **exactly once** (bounded). The new snapshot passes
  syncProject's full verification + genesis match plus an **extension check**
  (`ensureExtensionOf`: new head ≥ old head AND the old verified head's seq/hash matches inside the
  new snapshot). Then **all values** in the pull response are re-verified under the new view; still
  future → reject
- EpochConflict re-syncs also pass the same extension check (on top of the existing discipline of
  not treating the server's currentEpoch declaration as truth, redirection to a different
  consistent chain is also rejected)

### 2-5. Server check order (ruling D)

`Schema (400) → value size (413) → AAD-coordinate consistency (422) → token scope / chain
role / existence (404 / 403) → epoch / version CAS (409) → value signature (signature → declared
head → head-time state → predecessor = 422's 3 reasons) → quantity policy (422) →
atomic write`. Value signing is **inserted only** between CAS and quantity in the existing order.
The declared head need not equal the current head (an older head satisfying the same epoch, tenure,
and role is accepted — pinned by vector positives); no monotonicity on declared-head seq or a
server-specific epoch-monotonic comparison is added (it follows structurally from "accept current
epoch only + rotate +1 + version CAS" — as clarified in AUTH_SPEC §12-5 on 2026-08-03).
All crypto awaits complete inside the verification Effect; no await is interposed in the
synchronous-SQL write phase (same discipline as PR-1). On non-acceptance, variable / version /
latest / audit all stay unmodified (pinned in tests).

The versions-per-variable quantity-cap test (which raises latest_version directly) was updated to
seed a version row just below the cap, because the new check order (CAS → value signature →
quantity) makes the predecessor row's existence a premise (§12-8's check itself is unchanged).

## 3. DDL & storage (ruling E)

Added to `variable_versions` as NOT NULL (direct change to the Project DO SQLite raw DDL.
D1 / Drizzle / migrations untouched):

| Column | Content |
|---|---|
| `prev_value_sig_hash_hex` | SHA-256 of the previous version's value_signed_bytes (empty string for version 1) |
| `chain_head_hash_hex` / `chain_head_seq` | declared head (exact pair) |
| `signature_hex` | the value's write signature (Ed25519) |
| `signed_bytes_hash_hex` | **server-recomputed** signed_bytes hash (verification material for the next version's prev check and 409 retries. **Not distributed**) |
| `writer_user_id` / `writer_key_fingerprint` | the chain-derived writer at acceptance time (user_id + key FP) |

The signed bytes themselves and public keys are not stored (reconstructible from coordinates and
the chain).
No backfill or nullable transition was created (pre-release; no applied environments).
**Old local-dev `.wrangler/state` must be discarded before running this branch**
(same caveat as session-08 §3 / session-13 — old-schema variable_versions rows lack the
NOT NULL columns and `CREATE TABLE IF NOT EXISTS` doesn't add columns).

pull returns the stored writer / signature block as-is without re-deriving from the current member
set (keeps a removed writer's past values verifiable with the chain-history keys of their time —
pinned in integration tests). Audit copies only the chain-derived writer FP; signatures,
signed bytes, hashes, nonces, ciphertexts, and plaintext are never recorded. Rename / delete /
env-family FPs are PR-3's domain (meta statements).

## 4. Known constraints / v1 tolerances (what this PR does **not** guarantee)

- **latest-only**: first sync and pull hold no predecessor, so prev existence matching,
  epoch non-regression, and persistent detection of rollback / omission / forward-injection are
  impossible (§14.3-3/5). The local floor is PR-4 (session-12 §10-4's ruled policy)
- **Name authenticity**: name → variable_id resolution stays unauthenticated until PR-3
  (VariableMetaStatement / EnvironmentMetaStatement / NFC check / authenticated name resolution).
  Value signatures don't authenticate names (§4.1 semantics). The execution-control variable-name
  denylist (session-11) stays as a defense layer
- **Fork detection stops at evidence**: 2 valid signatures at the same coordinates become
  non-repudiable evidence (vector fork_same_version / CLI's 409 equivocation rejection), but
  mechanical split-view detection is Phase 2 head gossip (§14.3-4)
- gossip / checkpoint / manifest / rotate CLI / chain-operation CLI /
  remove+rotate composition / DO total-size guard / session-11 follow-up PRs are not in this PR
  (out of the task-specified scope)

## 5. Sticking points & environment findings

- **The "versions cap" test's premise breaks under the changed check order**: the old shortcut of
  raising only latest_version via SQL contradicts the new invariant "after CAS the predecessor row
  always exists" (absence = defect). Resolved by seeding a version row just under the cap
  (signed_bytes_hash_hex included) in the test — in real operation the invariant always holds via
  CAS + no per-row deletion (variable deletion removes all rows)
- **CLI transplant-test expected messages move "upstream"**: coordinate transplants and ciphertext
  swaps that previously advanced to decryption failure (AAD mismatch) now get dropped earlier by the
  value-signature coordinate check (§6.3-5). Same defense semantics, detection moved one layer up
  (the GCM layer's defense independently remains, per §4)
- **Pin "both verify successfully" first in fork-evidence tests**: fork_same_version went into its
  own section rather than negative. In negative shape (must_fail) you can't catch a wrong
  implementation of "fails standalone" (e.g. believing fork detection works via the prev chain alone)
- **Old fixtures on the mock server all die with Schema 400**: adding required fields to
  EncryptedPayload breaks wire compatibility (an intentional pre-release incompatibility). Every
  value fixture in the CLI tests was updated to a signed one carrying writer, declared head, and prev

## 6. Handoffs

- **PR-3 (metadata statements)**: metadata-signature.json →
  crypto (§4.2) → api-schema (VariableMetaStatement / EnvironmentMetaStatement,
  replacing name in the environment list with statements) → server (meta CAS, non-NFC 422,
  author FP on `env.created` etc.) → CLI (route name resolution through verification).
  The verification machinery (declared head, authorization-time, prev chain) can reuse this PR's
  ChainHistoryIndex / verifyDistributedValue isomorphs
- **PR-4 (CLI local floor)**: implement exactly per session-12 §12 loop 2's norm, including
  the floor-extension rule (c) (pull-time epoch basis). values.ts's returned
  signedBytesHashHex / version / epoch become the floor's record material
- Shared extraction of test support (session-11 §5's ruled independent PR): this session grew
  signValueAs / encryptValueFor / valueHashOf clones on both server and CLI sides. Also clear the
  fallow dupes baseline at extraction time (session-13 §3-6)
- The 409 retry cap (5) and bounded re-sync (1) are implementation constants. Consider making them
  configurable if operation observes insufficiency

## 7. Test results

- vectors tools: `bun run generate` (existing vectors byte-identical) +
  `bun run verify` all PASS (including the value-signature additions)
- `@maruhi/crypto`: node 364 / workerd 364 / browser 364 / Bun 363 (the vitest
  aggregation 1-count diff is as before) — chain-history / value-signature checks added
- server (vitest-pool-workers): 181 tests green (8 new value-signature acceptance checks;
  existing fixtures fully updated to require value signatures)
- CLI: 109 tests green (added negatives for value-signature verification, future head, and the
  409 winner procedure)
- `bun run check` (fmt / lint / typecheck / importlint / fallow / doctor / test)
  green

## 8. Review→fix loops (inside the PR. 3 parallel review perspectives → fixes)

### Loop 1 findings and responses

Ran 3 perspectives in parallel (security & crypto / correctness, concurrency & fork / spec, vectors
& wire). **[high] 1 = independently detected as the same root as [med] (security)**:

1. **409 retry doesn't detect regression from the session's verified latest
   (correctness [high] + security [med], same root detected independently)**: `adoptConflictWinner`'s
   consistency checks only covered (a) `winner.version < currentVersion` (inconsistency vs the
   declaration) and (b) `winner.version === known.version` with a hash difference (equivocation),
   not rejecting `currentVersion < known.version` / `winner.version < known.version`
   (a regression from the latest this session already §6.3-verified). A malicious server could
   declare a rollback + distribute a rollback view (an old canonical value that passes every check
   standalone), making an honest writer **chain onto the rolled-back branch's coordinates with their
   own signature** (the victim produces one half of a same-coordinate fork proof against real
   history). The local floor (PR-4) is "persistent detection across sessions"; the point is that
   **as long as the same push flow holds `state.target.latest`, regression detection is zero-cost**.
   → Response: introduced `winnerInconsistency`, adding (i) reject `currentVersion < known.version`
   / `winner.version < known.version` as rollback evidence. On an honest server latest_version is
   monotonic (no per-row deletion), so no false rejections
2. **The 409 path with an adjacent predecessor doesn't check §6.3-6 (prev existence match, epoch
   non-regression) (correctness [med])**: ruling B says "pull is latest-only and can't pass a
   predecessor", but at `winner.version === known.version + 1` the client holds exactly the previous
   version's verified anchor. → Response: added to `winnerInconsistency` (ii) when
   `winner.version === known.version + 1`, directly compare `winner.prevValueSigHashHex ===
   known.signedBytesHashHex` and `winner.epoch >= known.epoch` (added `prevValueSigHashHex` to
   VerifiedPulledValue). Detects chaining onto a forked history for free
3. **A value written by a new member outside the own view gets instantly rejected as
   `writer-unknown` and never enters §6.3-2b's bounded re-sync (security [low])**: under the check
   order (provisional ruling C: signature → head), key selection runs before the head-binding check,
   so when the declared head is ahead of the own view **and** the writer is a new member added in
   the un-synced interval, it dies on `writer-unknown` before reaching `chain-head-future`.
   Fail-closed, but deviates from §6.3-2b's "re-sync first" norm, letting a malicious server induce
   warning fatigue. → Response: in values.ts's classification, route "`writer-unknown` AND
   `chainHeadSeq > own view's headSeq`" onto the same bounded re-sync path as future (reject if
   still unknown after re-sync). The crypto layer's check order is unchanged
4. **[low] / [info] group**: note the possibility of a concurrent deletion in the winner-missing
   message (correctness [low]) / update `dataEvent`'s JSDoc to "operations carrying a client
   signature (dek.registered / var.created / var.version_pushed) copy the signer FP"
   (contract [low] — implementation matches spec; only the JSDoc was stale) / the server-side
   `epoch-regressed` branch is unreachable post-CAS but a harmless defense line in the shared
   verifier (correctness [info]) / create-path quota being pre-CAS is consistent with "insertion
   only into the existing order" (correctness [info]) / recommend adding a server integration test
   for tenure-crossing rejection (security [info])

All 3 perspectives judged **blocking / new major findings = the above only**, and signed-bytes /
verification rules / server acceptance / atomicity / inclusive boundary / cache consistency /
vector-spec conformance / wire contract / no-change-to-normative-spec were each judged "verified
(no issues)".

### Loop 2 (re-verification of the fixes)

All 3 perspectives judged loop 1's fixes **sufficient, no new blocking issues** (verified that the
rollback / equivocation / prev-chain / new-member re-sync branches produce no false rejections under
honest-server invariants — latest_version monotonicity, delete = 404 / tombstone). Detected and
handled 2 new [low] + [info]:

1. **Epoch monotonicity of non-adjacent winners unchecked (correctness [low])**: §4.1's monotonicity
   is transitive, so as long as `winner.version > known.version`, epoch non-regression can be
   required even across a version-number gap. The old implementation only checked the adjacent case
   (`known.version + 1`), so shifting the version number by +2 or more let an old-epoch signature
   injection by a removed member bypass the adjacent check. → lifted `winnerRegression`'s epoch
   check to cover all of `winner.version > known.version` (prev existence match stays adjacent-only).
   Honest servers are epoch-non-decreasing in acceptance order, so no false rejections. Added a
   cross-version-gap regression rejection test
2. **Mutation-detection power of the server tenure-crossing test (contract [low])**: with the new
   test's prev being a dummy 64hex, mutating away the tenure check still returns the same wire
   reason (`chain-head-state-mismatch`) via `prev-hash-mismatch` and the test stays green. →
   made prev the stored v1's real signed-bytes hash, pinning the tenure check (head-time state —
   upstream of the prev check) as the sole failure factor
3. [info]: consolidated `winnerRegression`'s doubled JSDoc, added documentation to
   `winnerInconsistency` (both split leftovers)

Quality gate re-run: `bun run check` green (686 tests), crypto's 4 runtimes green,
vectors verify all PASS.

### Loop 3 (final check)

After reflecting loop 2's 3 branches (epoch-monotonicity lift, test detection power, docs), the
remainder is [info] only (dedicated negative test for the epoch-regression branch = already added;
the "writer-unknown → still unknown after re-sync → reject" negative = covered by existing
boundedness / extension-check negatives), zero blocking. Timeline: loop 1 = 1 high (2 perspectives,
same root), 1 med, 3 low, several info → loop 2 = 2 low, info → loop 3 = zero.
