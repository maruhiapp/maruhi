# Session 13 notes (implementing DEK authenticity — implementation PR-1 of the session-12 spec)

Date: 2026-08-04. Prerequisites: started after confirming PR #27 (CRYPTO_SPEC
0.4-draft = authenticity spec for values, DEKs, and variable metadata) is merged
(merge commit `5d0f576`. With the merge, the spec — including the recommended
options for the to-be-ruled items in session-12.md §10 — is treated as
owner-approved).
Scope: **PR-1 = DEK authenticity (option B)** from session-12.md §9. Commits in
layer order: vectors first → crypto → api-schema → server → CLI.

## 1. What was done

1. **Test vectors first** (committed before implementation. Human-review
   targets):
   - Extended `tools/generate_reference.py`: new op `create_environment`
     (payload order `[environment_id, dek_commitment_hex]`), `rotate_epoch`
     becomes 4 fields (trailing `dek_commitment_hex`), reference computation of
     the §5.2 commitment (LP + SHA-256)
   - **Regenerated** `chain-entries.json` (matching the impact list in
     session-12 §8-4): a canonical 12-entry chain where every rotate is preceded
     by a create; semantic extension of `expected_head_states`'s environment set
     (current epoch, creation seq, epoch-start seq, per-epoch commitments —
     dropping "unobserved = 1"); added authz negatives
     (`authz-create-env-duplicate` / `authz-rotate-unknown-environment` /
     `authz-create-env-reader` / 3 check-order cases / 4 commitment-format
     violations = payload-structure check stage / 2 signature-side commitment
     tampers); added 2 allowed-boundary environment-lifecycle cases to
     `valid_appends`; an `environment_deks` section (dummy DEKs and actually
     computed commitments — so implementation tests can check through the §5.2
     match)
   - New `dek-commitment.json` (session-12 §8-3): positive (same DEK and
     coordinates as dek-wrap.json basic + epoch 1) + `dek-mismatch` / 3
     coordinate-transplant cases / `wrong-domain` / `uppercase-hex` +
     `rewrap_invariance` (invariance across backfill and repair
     re-registration)
   - Diff check: the existing 6 vector files (encoding / variable-encryption /
     recovery-wrap / dek-wrap / dek-wrap-signature / hpke) are byte-identical
     (mechanically verified via git diff after oxfmt). Committed only after
     confirming verify_reference.mjs passed all 191 checks
2. **crypto**: verification of `create_environment` (role member or above,
   `duplicate-environment` = uniqueness across whole history), `rotate_epoch`'s
   `unknown-environment` (create must precede — the default fallback is gone),
   extended state derivation (`ChainState.environmentEpochs` → `environments` =
   current epoch, creation seq, epoch-start seq, commitments),
   `dek-commitment.ts` (computeDekCommitment / verifyDekCommitment),
   `ChainInvalidReason` + `DekCommitmentMismatch`. core's Effect mapping follows
3. **api-schema**: create_environment added to the op union, environment
   creation replaced by the composite form (parentHeadHashHex + entry + name +
   deks), new rotate composite endpoint (the former 2-round-trip removed),
   `EnvironmentConflict`'s `exists` / `retired` removed (absorbed into
   consensus rules; only `duplicate-name` remains), `CompositeRequired` (422),
   error contracts moved to the composite endpoints
4. **server**: composite acceptance (composite-programs.ts — atomicity,
   in-composite consistency checks, wrap evaluation against post-entry state,
   row-count/request caps applied on every path), the generic append rejects
   the 2 ops, rotate to a deleted environment is 404, `chain.environment_created`
   + the rotate mirror gain dek_commitment payloads, `currentEpochOf`'s new
   semantics (unobserved = defect)
5. **CLI**: env create became composite (the CLI's first non-genesis chain
   append. On ChainHeadConflict it re-syncs → re-signs and retries; the wrap set
   is rebuilt only when the member set changed), §5.2 commitment matching after
   unwrap and before DEK use, epoch derivation moved to the environment-set
   basis (rejects phantom environments)
6. **tests**: crypto vector-driven on 4 runtimes (node / workerd / browser /
   bun) + server 173 / CLI 98 acceptance cases (the PR-1 share of session-12
   §8-5). All fixtures reworked so create_environment precedes
7. **docs**: this memo

## 2. Staged ruling (per the task's specification)

**`EnvironmentMetaStatement` is not bundled into PR-1** (as the task's ruling
specifies): composite environment creation still carries a bare `name`. The
statement's bundling, verification, storage, the statement side of §12-4's
"re-sign both on CAS retry", and AUDIT_SPEC §3.3 `env.created`'s author key FP
come in PR-3. This is an intentional intermediate state of a pre-release wire,
and session-12.md §9's "guarantees grow monotonically even in intermediate
states" already holds with PR-1 alone (the commitment alone closes §1-i/ii =
forged-DEK injection and induced encryption under a forged DEK). The alternative
(pulling forward env-meta-sig's minimal core) was rejected — partially
implementing PR-3's verification machinery (declared head, authorization point,
prev linkage) would duplicate machinery that should be shared with PR-2's value
signatures, losing the review-granularity benefit (the reason for §9's split).

## 3. Detail decisions of the rulings (multi-option comparison → provisional progress on the recommendation. Finalization condition = PR review approval)

### 3-1. Shape of ChainState's environment state = per-environment struct (replacing environmentEpochs)

| Option | Assessment |
|---|---|
| **`environments: Map<envId, {currentEpoch, createdAtSeq, epochStartSeqs, dekCommitments}>` (adopted)** | §6.3's "each epoch's validity interval (start seq)" and §5.2's commitments come from the same derivation loop, keeping an environment's existence, epoch, and commitment on one source of truth. Inputs for PR-2's value verification (epoch consistency, the current epoch at declared-head time) fall out ready-made |
| Keep environmentEpochs and add a separate map | The two lookups "does the environment exist" and "what is its current epoch" split across maps, breeding ground for surviving `?? 1` default-1 remnants. The replacement flushed out every call site via compile errors, structurally preventing leftover "unobserved = 1" |

### 3-2. Commitment API = DEK is received as Uint8Array

`computeDekCommitment({context, dek: Uint8Array})` internally `encodeHex`s
(lowercase) before placing it in the preimage. The hex-string option was
rejected because it would permit the accident where caller-side uppercase hex
becomes a different preimage (an implementation version of the vector negative
`uppercase-hex`). `verifyDekCommitment`'s expected value (the chain-published
value) accepts only lowercase 64-char hex (pinning the comparison canonical
form to one — same reason as the §5.1 implementation's "allowing uppercase hex
produces multiple canonical forms").

### 3-3. Check order of the composite endpoint (server)

`role(member) → [rotate only: URL/entry environment_id match → active
environment (404)] → parent-head CAS → entry size / capacity → verifyChain
(consensus rules) → in-composite consistency (every wrap epoch = the epoch being
established) → wrap acceptance (§12-6 + §12-8) → atomic write`. Discussion
points:

- **rotate's 404 placed before CAS**: a rotate to a deleted environment is a
  deterministic rejection regardless of the parent head; placing the 404 after
  CAS would make the client spin through many rounds of "409 that retries never
  resolve"
- **A rotate composite for an uncreated environment is 404 on the server** (not
  the 422 `unknown-environment`): the environment's data row is created
  atomically with the chain entry by composite acceptance, so "a chain create
  exists but no row" is an invariant violation, while "no row and no chain
  entry" = uncreated hits the row check (404) first. The consensus rule
  `unknown-environment` itself is pinned by the crypto layer's 4-environment
  vector test (the server acceptance-side expectation is spelled out in
  membership.test.ts's correspondence table)
- **Wrap exact-match (recipient-missing) runs after per-wrap checks
  (recipient, duplicates, signature)**: preserves the old environment-creation
  program's decision order (reason-code compatibility)

### 3-4. Composite worker / DO split

actor = authenticated-principal match (§11-1 equivalent) is checked early at
the worker (handler), and the DO trusts callerUserId — the same split as the
generic append. The DO side runs role, CAS, verifyChain, consistency, and wrap
checks under permit. The genesis hash (the project_id coordinate) comes from
the DO's own chain (following session-09 §3's invariant).

### 3-5. CLI CAS retry = 5-attempt cap, wrap set rebuilt only on diff

Same cap as push's MAX_ATTEMPTS. If the current member set (user_id → enc key)
is unchanged after re-sync, the wrap set is reused (§12-4's "rebuild the wrap
set only when the current member set changed". Since HPKE Seal is randomized,
unnecessary re-wraps are not just wasteful — they break diff comparison). The
DEK and commitment are invariant across retries (only the entry's re-signing
changes).

### 3-6. fallow dupes baseline

The test-helper clones ruled on in session-11 (cli / server buildChain, op
builders, etc.) changed fingerprints under this session's rework and no longer
match the baseline (warning only; the gate passes). Shared extraction belongs
to the separate PR already ruled in session-11 §5, so this PR doesn't touch it;
the extraction PR will resolve it together with the baseline.

## 4. Gotchas & environment findings

- **Chain-vector negatives get stronger by picking "values the old semantics
  would have accepted"**: `authz-rotate-unknown-environment`'s new_epoch is 2
  (the value the old "unobserved = 1 + 1" would have accepted). An
  implementation that kept the default fallback fails on this single vector
- **Going composite breaks test assumptions broadly**: once the generic append
  rejection (CompositeRequired) landed, every membership test that used rotate
  as a pretext — "vector replay", "CAS", "size cap", "write/admin scope
  discrimination" — was affected. Absorbed by swapping to an op that uses no
  rotate/create (remove_member) and a replay-via-composite helper (derives the
  member set while walking ops to build the complete wrap set)
- **On the server acceptance surface, consensus-rule reason codes sometimes
  don't appear verbatim**: insufficient role hits DO's requireRole (403) before
  verifyChain (422); an uncreated environment hits the data-row 404 first; a
  commitment-format violation hits api-schema's hex Schema (400) first.
  membership.test.ts carries a "vector name → server expectation (status +
  reason)" correspondence table, and that mapping itself is pinned as a test
- **Fixture commitments must be actually computed**: CLI pull tests run through
  the §5.2 match, so a commitment placed on the chain that isn't computed from
  the fixture's real DEK makes every test fail as a poison wrap. Since the
  commitment preimage includes project_id (= the genesis hash), buildChain
  gained a lazy op (LazyChainOperation) that "builds the payload after genesis
  is fixed"
- **`bun run check`'s oxfmt also covers generated JSON**: applying oxfmt to
  generated output leaves existing vectors byte-identical (reconfirmation of
  the session-10 §3 finding)

## 5. Known constraints / v1 tolerances

- The rotation CLI command is unimplemented (out of scope — to come together
  with the family of chain-append commands). The rotate composite is verified
  by server implementation + tests
- The intermediate state without `EnvironmentMetaStatement` (§2). Environment
  display-name authenticity stays unauthenticated as before until PR-3
- The non-NFC-name 422 (§8-5) comes in PR-3 (together with statement
  acceptance)
- The CLI's local floor (§6.3 SHOULD) stays unimplemented pending PR-4
  (to-be-ruled §10-4) — commitment matching is a guarantee that completes
  "within the presented chain view" (§14.2-1); view rollback itself remains
  the domain of the floor and gossip
- On the server's composite acceptance, the state "a data row exists but the
  chain has no environment" is an invariant violation treated as defect
  (currentEpochOf throws). This assumes rows created by the old API don't
  exist (pre-release, no applied environments)

## 6. Handoff

- **PR-2 (value signatures)**: build value-signature.json against the
  regenerated canonical chain (12 entries). `ChainState.environments`'s
  epochStartSeqs is the input to §6.3-4 (epoch consistency, rejection of
  pre-create heads). Also fix the existing dek-wrap-signature.json
  description's missing signer_user_id then (session-12 §13)
- **PR-3 (metadata statements)**: bundling EnvironmentMetaStatement into the
  composite create (re-signing both on CAS retry), author FP on `env.created`,
  non-NFC 422, environment-list name → statement replacement
  (EnvironmentSummary revision)
- **Shared extraction of test helpers (session-11 §5's already-ruled separate
  PR)**: the clone sets drew even closer this session (commitmentOf /
  createEnvironmentOp family also grew on both sides). Resolve the fallow
  dupes baseline mismatch warning (§3-6) at extraction time
- The rest of session-11 §5 (the publish-settings endpoint / metadata-only
  pull mode) and the chain-append command family + remove_member's all-
  environment rotate (including the composite consideration of session-12
  §10-7) remain valid and unstarted

## 7. Review→fix loop (inside PR #28. 3 parallel review angles → fix)

### Loop 1 findings and responses

3 angles run in parallel (security / crypto, correctness / concurrency, tests /
vectors / wire contract). **[high] 1 (contract) = same root as [medium]
(correctness)**:

1. **The §12-1 acceptance-policy format disappeared from the composite create
   entry's environment_id (contract [high] / correctness [medium], detected
   independently)**: the old create payload's `EnvironmentIdSchema` had
   degraded to `Schema.String` when compositing moved ID carriage inside the
   chain entry (it also has no URL coordinate). A write-scoped member could
   atomically commit an environment whose ID is like `"my env/💥"` —
   unreachable from later endpoints that take a URL param (rotate / rename /
   **remove** / pull) = an environment that is **unrotatable (conflicting with
   §7's all-environment obligation), undeletable, permanently consuming quota,
   with the ID burned forever**. → `CreateEnvironmentEntrySchema` /
   `RotateEpochEntrySchema`'s environmentId are now `EnvironmentIdSchema`
   (rejected at the wire acceptance-policy layer. Not promoted to a consensus
   rule = §6.1 bounded string — keeping project.ts's line). Added a composite-
   create 400 negative with 3 malformed-ID variants. No impact on existing
   chains (the 2 ops' acceptance point is only the composite + pre-release
   with no applied chains. A malicious server distributing a non-conforming ID
   makes the CLI's decode fail-closed — strictly better than before the fix)
2. **The generic append's 2-op rejection was worker-only (security [low] /
   correctness [low], same root detected)**: the DO's `appendProgram` could
   accept consensus-valid create / rotate, so adding a future call path could
   create the intermediate state "the chain has an environment but no
   wrap/environment row". → added the same guard on the DO (`composite-required`
   outcome → `CompositeRequiredError` mapping) (defense in depth). Since the
   decision depends only on request content, it's also compatible with §11-2's
   existence concealment (same shape as §12-3 1a)
3. **Tests [medium]–[low]**: the audit mirror's dek_commitment was pinned only
   by format (64 hex) → strengthened to exact `toEqual` match against the §5.2
   value computed from the fixture's real DEK / the kind-less negative check
   silently dropped additions to vector regeneration via a hardcoded name →
   added an exhaustive guard (fail on an unchecked name) / the reuse side of
   the CLI CAS retry's "reuse the wrap set when the member set is unchanged"
   was untested (an always-rebuild implementation passed) → added a deks
   exact-match + prev-update test
4. **[info] group**: updated stale comments (seq 1–9 etc.), added a README note
   on kind carriage of invalid-payload negatives, the phantom-environment
   error's wording (guidance to re-run on a benign race), and a design comment
   on env-create's final attempt (noting it's the same judgment as push.ts)

### Loop 2 (re-verify the fixes)

All 3 angles confirmed **loop-1 fixes are sufficient, zero new blocking
findings**:

- Security = verified that enumerating every chain-entry insertion point
  (`insertSync` callers) leaves no bypass of the 2 ops at either worker or DO
  layer, and that `EnvironmentIdSchema` enforcement doesn't contradict snapshot
  distribution / CLI decode (there is no structural path for a non-conforming
  ID to land on the chain)
- Correctness = re-ran the 3 malformed-ID repro scripts to confirm the fixed
  schema rejects. Judged the DO guard's decision-order arrangement sound
  (depends only on the op = carries no existence info)
- Tests = traced the mutation-detection power of the 3 new tests (a
  `Schema.String` regression / constant copying / always-re-wrap each fail
  reliably)
- 1 new [info] (if a third value ever enters the negative kind vocabulary, it
  would slip through both sieves) → handled by adding a pin on the kind
  vocabulary (undefined | "authorization")

### Loop 3 (final confirmation)

Each of loop 2's 3 angles stated "fixes sufficient, zero new findings"; all
residue is [info] (non-constant-time hash comparison = compares only public
values / the wire format being narrower than the consensus rule = documented
in a comment / chain-view rollback residue = PR-4's floor, within §14.2-1's
guarantee scope). Quality gate: `bun run check` 541 tests green + crypto on 4
runtimes (node 243 / workerd 243 / browser 243 / Bun 242) green. Progression:
loop 1 = 1 high (same root across 2 angles), 2 medium, 3 low, many info →
loop 2 = 1 info → zero (blocking) findings.

### Automated-review responses after the PR opened (2026-08-04)

- **Bugbot [Medium] × 1 (dismissed, no code change)**: claimed "the composite
  create writes the chain entry then the environment row inside a
  non-transactional Effect.sync, so a later throw leaves only the chain and the
  ID is unrecoverable". Judged a non-issue with grounds — (1) that block is a
  sequence of synchronous `sql.exec` with no intervening await, and a
  SQLite-backed DO **atomically commits "a series of writes with no intervening
  await" as one transaction** (the official docs' Write Coalescing; a
  storage-layer failure makes the Output Gate replace the response with an
  error and restart the whole DO = partial persistence is unobservable),
  (2) the "a later step throws" path itself is unreachable (under permit
  serialization, pre-checks guarantee the freshness of every INSERT's key —
  the environment-row PK is the duplicate-environment consensus rule, wrap PKs
  are structurally absent for uncreated environments / new epochs plus dedupe,
  the audit seq is a single MAX+1 statement; only pure synchronous JS sits
  between statements), (3) the same pattern is an established convention
  approved in every write phase since insertWithMirror (documented in
  data-store.ts). Security Agent and CI (check) passed with no findings
