# Session 33 notes (PR-F3 implementation — early landing of 2-G′ boundary checkpoints)

Date: 2026-08-27. Target: PR-F3 of session-31 §6 (the PR-F3 allocation of M1-A6 / M1-B1 / M1-T2).
Ruling 2 is the owner-approved option 2-G′ (session-32 §5-1), and the spec revisions
(CRYPTO_SPEC §4.3 / §6.2–§6.4, AUTH_SPEC §12-4 / §16-2) are merged via PR #83 family = approved.
This note records the implementation rulings of the implementation PRs (F3a / F3b). The ruling
process followed the goal's instruction of "multiple options → upward-compatible exploration →
3 rounds of comparison → autonomous selection", recording each round's rejection reasons.

Split (adopting session-32 §5-1's bounding as-is):

- **F3a** = implementing the `checkpoint` op's consensus rules (CRYPTO_SPEC §6.2) +
  `packages/crypto` test vectors (additions only, into chain-entries.json) +
  the canonical-form implementation of the env values digest. A pure M2 early landing with no
  change to existing behavior
- **F3b** = atomic bundling of a boundary checkpoint into create / rotate composites (AUTH_SPEC
  §12-4), checkpoint-bound manifest verification (CRYPTO_SPEC §4.3 verification rule (2) —
  retiring the old H+1 exception), §6.4 acceptance verification (content matching, atomic
  snapshot storage), the M1-B1 fix, and the SELF_HOSTING.md update-order note.
  A stacked PR based on F3a's branch

Scope boundary (goal / session-32 §5-1): up to checkpoint acceptance and snapshot storage.
Snapshot distribution and the client-side consistency rule-2 verification stay in M2 proper.

## 1. Ruling A: where the checkpoint-binding match material is drawn from (F3a's API shape)

CRYPTO_SPEC §4.3 verification rule (2) says "when a `checkpoint` entry containing a tuple for the
(environment_id, manifest_version) exists on the verified chain, it must match that tuple's
(epoch, manifest_sig_hash) exactly (strict is not an alternative path)". Who performs this
"when it exists" determination?

### Round 1

- **Option A-1: explicit input (isomorphic to 2-D's anchor)** — `verifyDistributedEnvManifest`
  takes an optional `checkpoint?: { epoch, manifestSigHashHex }` that the caller draws from the
  verified chain and passes. Advantages: the crypto core's API stays small; minimal impact on
  existing vectors. Drawback: **a caller that forgets to draw it falls back to strict** —
  for a legitimate composite manifest that's fail-closed (surfaces immediately as an availability
  bug), but **in the attack case it's fail-open**: verifying without drawing a tuple that exists
  on the chain lets a different-content manifest at the same (env, mv) pass via the strict path,
  reproducing — as a call-convention bug — the reason session-32 §4-2 killed the disjunctive form
  ("if the strict path stays alive even when an anchor exists, the equivocation advantage
  disappears")
- **Option A-2: internal query of the history index** — add an (environment_id,
  manifest_version) → tuple query to `ChainHistoryIndex`, which the verifier always consults.
  The MUST form is structurally enforced and doesn't depend on caller conventions.
  Drawback: the existing composite positive vectors (manifest-v1-create / manifest-rotate)
  verified against canonical chains containing no checkpoints, so the verification-target chain
  must be swapped (to a checkpoint-bearing derived chain)

### Round 2 (upward-compatible exploration)

- **Option A-3: both (internal query + explicit-input match)** — the verifier queries internally
  and the caller also passes an expected tuple for a double check. Rejected: the explicit-input
  side has no independent meaning (the internal query always wins) — over-engineering that only
  fattens the API
- **Option A-4: cover it with just the ChainState-side derived value (each environment's latest
  checkpoint)** — rule (2) is about "the tuple for that manifest_version", which isn't necessarily
  the latest (the shape where a periodic checkpoint re-notarizes the same mv after a boundary
  checkpoint; re-verifying an old legitimate manifest). Latest-only can't express the (env, mv)
  match — rejected

### Round 3 (re-check)

- Confirmed A-2's drawback (swapping vectors) is **not regenerating** vectors: no existing vector's
  signed bytes / signature / hash changes at all; swapping the verification premise chain to a
  checkpoint-bearing derived chain (**added** to chain-entries.json's extended_chains) is a test
  harness (code) change, consistent with session-32 §4-2's "additions only" constraint (human
  review can review just the additions)
- A-1's fail-open looks like "default strict = safe side", but it's only the availability
  direction that's safe; the point that the exact-match MUST's purpose (blocking equivocation)
  depends on the call convention doesn't go away. Also inconsistent with the PR-F1 ruling (1-E)
  that made "not cooperative but structural" a principle

**Choice: option A-2** (internal query of the history index). Added
`checkpointTupleFor(environmentId, manifestVersion)` to `ChainHistoryIndex`, which the verifier
always consults. The failure mode of forgetting to draw is eliminated at the type level.

## 2. Ruling B: the identity criterion for equivocation on the same (environment_id, manifest_version) tuple

§4.3 (2) says "if tuples with **different manifest_sig_hash** coexist at the same
(environment_id, manifest_version), reject and warn as hard evidence of manifest equivocation".
A tuple carries (epoch, manifest_sig_hash, values_digest) — which field differences count as
equivocation?

### Round 1

- **Option B-1: manifest_sig_hash difference only** (minimal reading of the spec text)
- **Option B-2: (epoch, manifest_sig_hash) difference** — since epoch is baked into the
  manifest's signed bytes, a tuple pair with matching hash but differing epoch is evidence that
  "one of the checkpoints notarized an epoch inconsistent with the manifest content" — the same
  class as a hash difference
- **Option B-3: difference in all fields (including values_digest)**

### Round 2 (upward-compatible exploration)

Option B-3 turned out to **misjudge a legitimate flow as equivocation** and was rejected:
after a rotate boundary checkpoint (mv N, pre-re-encryption = a values_digest of the current
values at the old-epoch equivalent), the periodic checkpoint issued after re-encryption completes
re-notarizes the same mv N (value pushes don't advance the manifest version — §4.3 issuance
occasions) with a new values_digest — a legitimate succession the spec anticipates (§6.3 issuance
SHOULD (i)). values_digest legitimately changes at the same (env, mv).

### Round 3 (re-check)

- B-1 vs B-2 differ only on the "same hash, different epoch" pair. That can occur with 2 entries
  that passed chain consensus rules (checkpoint's strict epoch match) — mv non-regression allows
  equality, so a same-mv re-notarization straddling a rotate (though in a legitimate flow a
  manifest reissuance intervenes, so mv also advances). It can't arise in a legitimate flow, and
  if it arises it's evidence of inconsistency. Under B-1 such a pair leaves "which tuple to match
  exactly" undetermined
- Since the exact-match check runs on both (epoch, manifest_sig_hash) (the spec's "match
  (epoch, manifest_sig_hash_hex) exactly"), B-2 is the consistent choice for match uniqueness too

**Choice: option B-2**. The query returns (env, mv) → the unique (epoch, manifest_sig_hash), or
"conflicting" once a differing pair is observed; the verifier rejects `conflicting` as
`checkpoint-equivocation`. values_digest is not part of the equivocation determination (the
value-side reference is the latest checkpoint + server-stored snapshot — the domain of M2's
rule 2).

## 3. Ruling C: reason-code precedence across multi-environment entries in checkpoint consensus rules

§6.2's check order "role → audit admin → unknown-environment → checkpoint-epoch-mismatch →
checkpoint-regression" is unique for a single-environment entry, but when multiple entries carry
different violation kinds (e.g. entry 1 has an epoch mismatch, entry 2 an unknown environment),
the priority was unpinned.

- **Option C-1: run all checks per entry in list order** (entry 1's epoch-mismatch surfaces first)
- **Option C-2: scan all entries per check stage (stage-wise)** (unknown-environment surfaces first)
- Round 2: considered "attach environment_id to the reason" as an upward-compatible option —
  it's a revision changing ChainInvalid's shape (seq + reason), extending the existing error
  surface, so not taken in PR-F3 (can be proposed independently as a future DX improvement)
- Round 3: the spec's check-order text lists code kinds as "the check order of the authorization
  stage", and C-2 is the natural reading (same "order of reason-code kinds" as rotate's
  unknown-precedes-epoch). C-1 would vectorize an accident of implementation order, forcing other
  implementations (the server / future other-language ones) into the same loop structure for no
  gain

**Choice: option C-2** (stage-wise). Pinned by the vector
`authz-checkpoint-unknown-precedes-epoch` (priority opposite to entry order).

## 4. F3a implementation content (summary)

- `packages/crypto`: the `checkpoint` op's type & canonicalization (payload =
  `LP(environments_lp_hex, audit_head_hash_hex)`, environment entry = nested LP of
  `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
  values_digest_hex)`), consensus rules (§6.2 — structure check includes rejecting duplicate
  environment_id / role member+ / non-empty audit head requires admin / unknown-environment /
  strict epoch match at entry time (before applying the entry itself) / manifest_version
  non-regression against prior checkpoints of the same environment), derived state (each
  environment's latest checkpoint), the history index's (env, mv) tuple query (rulings A / B),
  `computeEnvValuesDigest` (§6.2's canonical values_digest form)
- New reason codes: `checkpoint-audit-role-insufficient` / `checkpoint-epoch-mismatch` /
  `checkpoint-regression` (duplicate environment_id is a payload structure check =
  `invalid-payload`, per spec)
- chain-entries.json: **additions only** (checkpoint description in canonicalization, 2
  valid_appends, extended_chains `checkpoint-baseline`, 18 negatives, a values_digests section).
  Not a single byte of the existing 12 entries / expected_head_states / existing negatives changed
  (confirmed via git diff). Generation extended the existing independent reference generator
  (generate_reference.py), reproducing existing output byte-identically so only additions appear
  in the diff
- `checkpoint-baseline` derived chain's manifest_sig_hash is a dummy value (chain consensus
  rules don't verify content — §6.2's "format is consensus rules; content is the matching side").
  Derived chains of boundary checkpoints bound to real manifest hashes are added in F3b (the same
  PR as the manifest-verification-rule consumer)

## 4-1. F3a's ripple (the minimal surface touched outside crypto)

The `ChainOp` / `ChainState` / `ChainInvalidReason` extensions forced the following follow-ups
via the repo-wide typecheck (all are direct consequences of F3a's consensus-rule implementation;
the only new behavior is "fail-closed rejection"):

- `packages/api-schema`: 3 reasons added to the error vocabulary (`CHAIN_INVALID_REASONS`)
  (enforced by the reverse-direction static check `AllReasonsListed`). `checkpoint` added to the
  wire `ChainEntrySchema` union (the chain-distribution response type carries crypto's
  `ChainEntry`, so without it in the union the distribution handler fails to typecheck).
  `CompositeRequiredError`'s op literal gained `checkpoint`
- `apps/server`: the generic append (worker + DO multi-layer) rejects the `checkpoint` op with
  `CompositeRequired`. **Accepting a standalone checkpoint without §16-2's acceptance checks
  (content matching against acceptance-time state + atomic snapshot storage) would be fail-open:
  a forged tuple could pollute §4.3 (2)'s checkpoint binding** — so the acceptance path stays
  structurally closed until implemented (boundary = F3b's composite bundling; standalone = M2)
- `packages/core`: `chain.checkpointed` added to the chain mirror's (AUDIT_SPEC §3.4) exhaustive
  Record (copies the notarized digest into the payload. Doesn't copy the audit seq — per spec)
- Following up on fallow's complexity findings, the 3 op dispatch sites (applyOperation /
  recordHistory / the test's toOperation) were aligned to the existing idiom (exhaustive Record
  table lookup like PAYLOAD_SHAPES / mirrorTails), and the shared skeleton of §4.3
  variables_digest and §6.2 values_digest was consolidated into a single implementation in
  `sorted-digest.ts` (canonical form pinned by vectors — behavior unchanged)

## 5. F3b implementation rulings

Same process as F3a (multiple options → upward-compatible exploration → 3-round comparison →
autonomous selection). Per-round records are attached to the 2 major rulings (D, E); the minor
rulings (F family) get conclusions and rejection reasons only.

### Ruling D: manifest-verification check order — prev chain ahead of epoch consistency (rule (2))

The old implementation order was signature → head binding → epoch → prev → content. With
checkpoint binding introduced, the "no tuple → strict" path pre-empted the v1 (empty prev)
negative vector (v1-nonempty-prev) with `environment-not-created-at-head`, never reaching the
expected reason `prev-shape-mismatch`.

- Round 1: option D-1 = change the vector's expected reason (impossible — the additions-only
  constraint, and §4.3's rule numbering prescribes (1) prev chain → (2) epoch consistency, so the
  spec is right). Option D-2 = move the prev check before epoch consistency
- Round 2 (upward-compatible exploration): option D-3 = give reason codes priority metadata to
  decouple them from check order — excessive machinery. Verification should be a linear sequence
  readable in the spec's rule-number order; making order into data destroys the correspondence —
  rejected
- Round 3 (re-check): D-2 is "structure (prev) first, then context (epoch)", consistent with
  §12-5's description of the acceptance sequence too. Adopted = **D-2** (prev → epoch consistency
  (incl. checkpoint binding) → content → checkpoint reference line (4)).

### Ruling E: reconciling replay of the canonical vector and mandatory checkpoint insertion in membership.test.ts

Since composites now insert an H+2 checkpoint, "API replay of the canonical chain with fixed
bytes" (composites present from seq 3 on) became structurally impossible (the canonical vector is
still valid at the chain layer — checkpoints are optional under consensus rules — but it's become
a shape the API can't produce. That is itself 2-G′'s spec consequence).

- Round 1: option E-1 = seed DO storage directly to keep the fixed bytes — requires duplicating
  environments / statements / wraps / manifest rows on top of chain rows, couples deeply into
  do-schema, and loses the "the API accepted it" meaning of the fixture. Option E-2 = make replay
  adaptive: re-sign while keeping op / payload / actor on the real head (Ed25519's determinism
  keeps bytes identical to the original until a divergence occurs)
- Round 2 (upward-compatible exploration): option E-3 = the server transiently accepts
  checkpoint-less composites (schema optional) — rejected as a spec violation (§12-4 mandatory
  bundling). Old CLIs' create / rotate going fail-closed (400) is the approved consequence
  (SELF_HOSTING's update order carries the operational side). Option E-4 = regenerate the
  canonical vector with checkpoints built in — rejected as a violation of the additions-only
  constraint (session-32 §4-2)
- Round 3 (re-check): the only thing E-2 loses is "byte-pinning of negative entries in server
  tests", which crypto's 4-runtime tests already pin (server tests pin check order and the status
  surface). Negative entries also keep their semantics under the same re-signing (role /
  duplicates / epoch order / key-FP mismatches) — copying the actor block verbatim and re-signing
  with the real key reproduces FP-mismatch cases as-is. Adopted = **E-2** (`resignEntryAt` —
  data-crypto.ts)

### Ruling family F (minor rulings — conclusions and rejection reasons)

- **F-1 simulating the old generation in the migration-path test**: deleting just the manifest
  row produces "a checkpoint tuple left on the chain with no stored row", a state real operation
  never reaches, and rule (2) (correctly) drops it as binding-mismatch. Real migration targets
  (environments predating manifest / checkpoint introduction) have no tuple on the chain either,
  so the test reproduces the old-generation chain by directly stripping the boundary checkpoint
  entry at the chain tail plus the snapshot row (`stripTrailingCheckpoint` — same "outside the
  append-only invariant" handling as membership's direct canonical_bytes modification; after the
  modification the DO is evicted back to a full load). Alternatives = deleting the migration-path
  test (loses the server-side fixture), a dedicated seed (same reason as E-1) — both rejected
- **F-2 material for rotate's values_digest (CLI)**: copied from the verified pull's
  `VerifiedPulledValue` (the current values actually read for re-encryption) as (variable_id,
  version, self-computed value_signed_bytes hash). No additional reads occur (as session-32 §5-1
  premised). The server-side match re-enumerates stored rows (`checkpointValueEntries`); a
  concurrent push after the declared head is fixed produces 422 `CheckpointStateMismatch`
  (values-digest-mismatch) → the client re-pulls + retries bounded. The CLI's bounded retry was
  implemented per #97's pullfrog review finding (the first version fell through on an unmapped
  generic error): `mapRotateFailure` maps the 422 to `RotateValuesConflictError` (a CliError
  refinement — passes through toCliError across layers), and `envRotateOp` restarts from a
  verified pull (cap 3 attempts; since values can't be re-fetched inside the re-sign loop, the
  retry unit is the whole flow from pull, not just the composite send). Also added to
  `isServerRejection` (422 is a final rejection = closes the intent; no probe needed)
- **F-3 boundary checkpoint's audit head**: while `GET /audit-head` (§16-2) is unimplemented,
  a boundary checkpoint with a non-empty audit_head_hash is fail-closed rejected as
  payload-mismatch (checkpointAuditHead). Acceptance without §6.4's existence/position checks
  would let false notarizations be pinned (same argument as F3a's standalone rejection)
- **F-4 division of labor for §12-4's hash-match check**: the tuple ↔ bundled-manifest
  (manifest_version, signed_bytes hash) match is uniquely carried by acceptEnvManifest's
  checkpoint binding (post-application history = exact match against the H+2 tuple), while
  coordinates (env / epoch / manifestVersion / empty audit head) are pre-checked by
  ensureBoundaryCheckpointShape. Writing the same check in two places would create a "which is
  authoritative" branch — rejected
- **F-5 M1-B1**: limited the pin's applicability to "no anchor established (no stored manifest)
  AND manifestVersion 1" (the anchor is fetched at acceptance via `environmentManifestAnchor`).
  A stale v1 against an initialized environment falls into manifestVersion CAS's 409 (with
  currentManifestVersion), joining the legitimate client's re-fetch / re-sign loop. The existing
  422 pin test (anchor not established) stays valid (on top of F-1's old-generation reproduction)
- **F-6 boundary chains in test vectors**: re-pointed the match chains of the existing composite
  positives (manifest-v1-create / manifest-rotate) to checkpoint-boundary-* chains with real
  manifest hashes baked in (additions to chain-entries.json). Two are needed because
  manifest-v1-create falls to rule (4) (the mv2 reference line) on any post-rotate chain. Existing
  vectors' crypto material is unchanged; only prose fields and the harness's reference targets
  change (compatible with the additions-only constraint)

- **F-7 CLI mock server and rollback tests**: the CLI tests' mock server appends 2 entries
  (rotate + boundary checkpoint) to the distribution chain on rotate acceptance (mimicking the
  real server's 2-entry acceptance — without the append, post-acceptance re-pull verification
  would fail the strict epoch rule, applying the retired old H+1 exception to the test itself).
  The 2 tests of "a server that keeps distributing the old manifestVersion after acceptance" now
  get dropped by §4.3 (4)'s checkpoint-regressed before the floor check (rule (a)) — the
  acceptance version's reference line is now pinned on the chain (shared) in addition to the
  floor (local), an added detection layer. Updated the expected wording to checkpoint-regressed
  (the fixture's invariant — "the swallow is dropped within the same run" — is unchanged)
### Handoffs to M2 (record of the #97 review)

- pullfrog's base-side observation (F3a scope): chain-consensus checkpoints require role member+,
  and tuple contents (manifest_version) are unverifiable at the chain layer — if a malicious
  member could notarize a manifest_version that doesn't exist, every subsequent legitimate
  manifest would jam on `checkpoint-regressed` (the availability side of fail-closed).
  **Currently unreachable**: the only accepted checkpoints are boundary-bundled ones, whose tuple
  manifest_version is match-checked against the CAS-accepted bundled manifest's version, and
  standalone is rejected with CompositeRequired until §16-2 is implemented. M2's standalone
  acceptance is designed so §6.4 / §16-2's "match against the latest manifest at acceptance time"
  check closes this hole — at implementation time, make sure to include this negative (rejection
  of notarizing an ahead manifest_version)

### F3b implementation content (summary)

- `packages/crypto`: manifest-verify.ts's check order moved to D-2 (prev → checkpoint-bound epoch
  consistency → content → reference line). `epochIntegrityReason` = tuple conflicting →
  `checkpoint-equivocation` / unique → `checkpoint-binding-mismatch` unless an exact
  (epoch, manifest_sig_hash) match / absent → strict. `checkpointIntegrityReason` =
  non-regression against the latest-checkpoint reference line (`checkpoint-regressed`). Vectors:
  3 checkpoint-boundary-* + 5 rule_negatives in env-manifest.json (all additions)
- `packages/api-schema` / `apps/server`: mandatory `checkpoint` bundling into the composite
  payload, `CheckpointStateMismatchError` (422), single-verifyChain acceptance of the H+1/H+2 pair
  (chain-accept.ts's pair path), atomic upsert of environment_checkpoints /
  checkpoint_snapshot_values (cascade on retire), ensureBoundaryCheckpointShape +
  ensureCheckpointValuesDigest
- `apps/cli`: boundary-checkpoint.ts (signing H+2), bundling into env-create / env-rotate
  composites (re-signed on CAS retry)
- docs: SELF_HOSTING.md's update order revised to 2-G′'s shape (① server → ② CLI/CI →
  ③ migration rotate of all environments. Old CLI goes fail-closed on the unknown op)
