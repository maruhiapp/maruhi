# Session 36 notes (PR-M3 implementation — value-snapshot distribution / verification = client rule 2 of checkpoint consistency)

Date: 2026-08-28. Target: session-27 §14's PR-M3. Prerequisites: PR-M1,
PR-F1–F4, and PR-M2 (#99) are merged. Under M2, the server already atomically
stores "an enumeration of the acceptance-time value snapshot + the
corresponding checkpoint seq / hash" as each environment's latest covering
checkpoint when a checkpoint is accepted (both standalone and boundary paths)
(data-store.ts's upsertCheckpointSnapshot / checkpointValueEntries). This PR
implements (1) api-schema response bundling (additive), (2) the server
distributing the stored enumeration (valued pull §12-7 / lease §14-2),
(3) verification of client rule 2 (CRYPTO_SPEC §6.3 checkpoint consistency 2
— value non-regression) on both the bulk-pull and lease paths, and (4) tests.
The ruling process followed the goal's instruction "multiple options →
strictly-better search → 3 rounds of comparison → autonomous choice". Ruling
letters continue from session-35's J–Q (R–W).

## 1. Ruling R: where rule-2 verification's implementation lives

### Round 1

- **Option R-a: a shared verification function in packages/crypto** (following
  the precedent of manifest-verify.ts's rule 1 = checkpoint-regressed) —
  advantage: a formal continuation of the "don't implement a verification
  mechanism twice" principle. Drawback: rule 2 has no server-side consumer
  (the acceptance-time values_digest matching — checkpoint-accept.ts — is
  already implemented as a different rule with different inputs; rule 2 is a
  distribution-**receiving**-side check). Rule 1 lives in crypto only because
  it's **incidental to** manifest verification, a function shared by server /
  CLI — not a precedent for an independent rule's home. Also, crypto changes
  require vectors first + the 4-runtime harness + human review, yet rule 2's
  body (the comparison set against the basis) contains no canonical form that
  vectors could pin (session-27 §13-5 already classified "snapshot-bundling
  verification" as implementation tests. The canonical form — values_digest's
  LP — is already pinned as computeEnvValuesDigest)
- **Option R-b: a CLI-layer composition (a new module wired into values.ts's
  shared verification skeleton)** — since bulk pull and lease already pass
  through the same verification skeleton (values.ts's verifyAll —
  verifyLeaseDistribution calls the same function), a single CLI-layer
  implementation structurally satisfies "the same rule on both paths" (§6.3).
  Consistent with the precedent of floor rules (a)(b)(c) living in
  floor-check.ts (client-only verification rules belong to the CLI layer). The
  canonical digest computation only calls crypto's public API
  (computeEnvValuesDigest — already vector-pinned); no new crypto operation is
  introduced

### Round 2 (strictly-better search)

- **Option R-c: put a "comparison-only" pure function in crypto, with the CLI
  passing the materials** — rejected: the inputs (verified distributed values,
  verified tombstones) are CLI-layer types, so passing them to crypto would
  mean creating copies of domain types (a dead dual-type). The payoff is just
  a "where it lives" label, for adding vector-unbacked logic to a
  human-review-mandatory package. When the Web dashboard's valued pull gets
  implemented and sharing becomes real, that PR can promote it to crypto
  (recorded as the re-consideration trigger)

### Round 3 (re-inspection)

- Re-inspected whether the lease path's asymmetry (future head = immediate
  rejection, no floor) is compatible with a shared implementation: rule 2's
  decision rides the existing 2-classification "future (possibly just a stale
  self chain) / rejected" (ruling S), and on the lease side
  verifyLeaseDistribution already maps future to rejection — both paths'
  semantics (pull = bounded re-sync, lease = reject as self-contradictory)
  emerge without added branches
- Pinned the check order: environment statements → values / statements →
  tombstones → names → manifest (incl. rule 1) → **rule 2**. Rule 2's
  "disappearance explained by a tombstone" judgment presupposes the
  manifest-consistent tombstone set (digest recomputation already rejected
  hidden tombstones), so it sits after the manifest stage (the implementation
  shape of §6.3's "verified tombstones (including manifest consistency)")

**Choice: option R-b**. `apps/cli/src/checkpoint-integrity.ts` (the single
implementation) is wired into values.ts's verifyAll (valued paths only —
metadata-only is out of scope per §12-7).

## 2. Ruling S: bundling the corresponding checkpoint seq / hash onto the wire

§12-7's wording mentions only "the enumeration (variable_id / version /
value_signed_bytes hash)", while the storage discipline (§16-2 / §6.4) is
"enumeration + corresponding checkpoint seq / hash". Whether to put
coordinates on the wire is M3's ruling item (goal-specified).

### Round 1

- **Option S-a: enumeration only (the spec's literal wording)** — drawback:
  can't distinguish a benign race (another member's checkpoint lands between
  the client's chain sync and the pull fetch, making the response's
  enumeration correspond to a checkpoint newer than the self view's basis)
  from an attack (enumeration tampering). A digest mismatch would always
  degrade to a blind "re-sync once, then re-judge", asymmetric with §6.3-2's
  established 2-classification ((a) mismatch at-or-below own head = immediate
  hard evidence / (b) beyond own head = re-sync → resolve)
- **Option S-b: enumeration + corresponding checkpoint seq / entry hash
  (advisory locator)** — enables the same-shape 2-classification as §6.3-2:
  declared seq > own head = possibly just a stale self chain (pull = one
  bounded re-sync; lease = self-contradictory since the chain is bundled =
  immediate rejection), declared seq ≤ own head = the basis is settled on the
  verified chain and an enumeration inconsistent with the basis checkpoint is
  immediate rejection as hard evidence. The verification basis itself is
  always chain-derived (history.latestCheckpointFor); the wire coordinates
  are used only for re-sync routing and diagnostics — compatible with
  CRYPTO_SPEC §1 principle 6 (non-signed carried fields are advisory; never
  make them inputs that weaken verification branches): lying about the
  coordinates stays fail-closed (over-declare → rejected on basis mismatch
  after re-sync / under-declare → immediate basis mismatch)

### Round 2 (strictly-better search)

- **Option S-c: enumeration + the whole stored tuple (epoch / manifest
  reference / values_digest too)** — rejected: epoch and digest are copies of
  chain-derived values; putting them on the wire only grows the misuse surface
  of "verifying against declared values" (an entry point to a principle-6
  violation). Carry nothing beyond the enumeration (the only distributed
  material not re-derivable from the chain) and the position (locator)

### Round 3 (re-inspection)

- Settled the locator's hash side use: for a declared seq at-or-below own
  head, match against entryHashAt(seq), and a mismatch is rejected as evidence
  of branched distribution (fewer misdiagnoses than seq alone). The basis-side
  match is checked by seq equality with the basis checkpoint's seq
  (chain-derived); the hash match is its prerequisite check
- Old-client compatibility: the response field is additive (optionalKey). The
  old CLI's decode ignores unknown keys, so it doesn't break. The reverse
  direction (new CLI × old server = no enumeration) is fail-closed per rule
  2's MUST (basis exists + no enumeration = reject) — recorded in
  SELF_HOSTING.md as server-first update order (§8)

**Choice: option S-b**. Response field `checkpointSnapshot = { chainSeq,
entryHashHex, values[] }`.

## 3. Ruling T: whether the checkpoint-digest.json vector (session-27 §13-4) is needed

### Rounds 1–3 (summary)

- Confirmed that §13-4's enumeration (LP canonical forms of variables_digest /
  values_digest / audit-head) is already fully pinned by existing vectors:
  variables_digest = env-manifest.json (PR-M1), values_digest =
  chain-entries.json's values_digests section (PR-F3a/M2 — referenced by
  values-digest.ts's module comment), audit-head = audit-head.json (PR-M2
  ruling J). M3 introduces not a single new canonical form (byte-string
  format) (rule 2's comparison set is §13-5's implementation-test
  classification)
- **Re-listing in a separate file (option T-a) is rejected**: duplicating the
  same canonical form in another vector creates a divergence surface ("only
  one side gets updated") (and sits badly with the vectors-are-additions-only,
  never-regenerate discipline)

**Choice: no vector additions** (§13-4 is judged already satisfied by the 3
existing files). Since crypto isn't touched at all, the vectors-first commit,
4-runtime harness, and human-review requirements are out of scope for this PR
(there is nothing they would apply to).

## 4. Ruling U: recording rule-2 verification success in the floor (monotonic join of verified observations)

### Round 1

- **Option U-a: join the snapshot enumeration into the value floor** —
  rejected: the floor's recording rule is "the value floor records only values
  it actually verified (no fabrication)" (§6.3). An enumeration's entries get
  matched against the chain basis via digests, but the client hasn't verified
  that version's value signature — joining would violate the recording rule.
  Also, the enumeration is the checkpoint-time state, always dominated by the
  floor records of the distributed values (≥ the enumeration's versions) that
  passed §6.3 verification in the same response (no lattice increment from
  joining)
- **Option U-b: a new record kind "rule 2 verified against checkpoint seq S"**
  — rejected: no detection rule consumes this fact (the basis is chain-derived
  — the next verification re-derives its basis from the next chain). Copying
  a chain-re-derivable state into the floor is a dual source of truth (the
  floor is the home of "verified observations that don't ride the chain" —
  the chain-head floor already pins the chain itself)
- **Option U-c: no new record** — the existing commitPull after rule-2 success
  (atomic commit of verified distributed values + chain head) already
  satisfies "joining the fact that verification succeeded" (the
  journal-before-release ordering also stays as implemented: floor commit →
  decrypt & use)

### Round 2 (strictly-better search)

- **Option U-d: join the basis epoch into the environment-watermark epoch
  observation (coordinate (ii))** — rejected: the basis epoch is a
  chain-derived value, always restorable via the chain-head floor +
  re-derivation. The observedEpoch join exists for "observations that don't
  ride the chain" (manifest baking etc.); making a precedent of pouring
  chain-derived values in would muddy (ii)'s semantics

### Round 3 (re-inspection)

- Confirmed the lease path remains the first-sync class without a floor
  (§14.3-3) — introducing rule 2 doesn't require a floor from lease (the basis
  is chain-derived, server-independent)

**Choice: option U-c (no new floor record)**.

## 5. Ruling V: the verification layer on the lease path and where the no-basis warning (SHOULD) lives

### Round 1

- **Option V-a: an independent implementation in lease-client.ts** — rejected:
  keeping "the same rule on both the bulk-pull and lease paths" (§6.3 / goal)
  via 2 implementations breeds divergence bugs (same root as ruling R)
- **Option V-b: integrate into values.ts's shared skeleton (verifyAll); the
  lease-client just passes the wire's checkpointSnapshot through** — since
  verifyLeaseDistribution already calls verifyAll, rule 2 automatically becomes
  the same implementation. The future → immediate-rejection lease semantics
  also applies the existing mapping unchanged

### Round 2 (strictly-better search)

- **Option V-c: a downstream check in ci-run.ts (the command layer)** —
  rejected: verification must complete before decryption / injection
  (values.ts's raison d'être). Placing it in the command layer would split the
  check position from the run path (valued pull — run.ts uses the pull path)

### Round 3 (re-inspection)

- **Where the no-basis warning lives (§6.3 SHOULD — a client with no floor
  warns when it detects that an environment it received a valued distribution
  for has no basis)**: the target is the "clients without a floor" class
  (workloads in particular). The CLI's pull path is the class with a
  persistent floor and is out of scope (a first pull without an established
  floor is "a first pull by a client that can hold a floor", not the same
  class — warning there would make every new project's first pull warn
  permanently, which departs from the SHOULD's intent [surfacing that this
  class's main guarantee isn't working]). So the warning goes into
  verifyLeaseDistribution (the workload path), surfaced via the existing
  warnings array (non-failing)

**Choice: option V-b + a lease-path-only no-basis warning**.

## 6. Ruling W: whether a cross-layer regression test is needed

### Rounds 1–3 (summary)

- An interaction of the same shape as PR-F4's precedent (manifest.test.ts —
  "the chain's checkpoint baseline does not substitute for floor rule (a)")
  does exist once in M3: since rule 2's basis stops at checkpoint time (a
  version at-or-above the enumeration's passes), **a rollback where the floor
  knows a newer version than the checkpoint passes rule 2 and only floor rule
  (a) rejects it**. This "rule 2 does not substitute for the floor" is pinned
  by 1 test (the reverse direction = "rule 2 rejects a rollback even without a
  floor" is pinned by M3's main negative set)
- Exhaustive all-combinations coverage beyond that (option W-a) is rejected:
  the floor rules and rule 2 are independent implementations with independent
  inputs, and a Cartesian enumeration isn't cost-justified (F4 drew the same
  line)

**Choice: include 1 cross-layer regression (rule-2 pass × floor-rule-(a)
rejection) in the CLI tests**.

## 7. Summary of what was implemented

- **api-schema** (additive only): `CheckpointValueSnapshotEntrySchema`
  (variableId / version / valueSigHashHex) and `CheckpointValueSnapshotSchema`
  (chainSeq / entryHashHex / values — ruling S) placed in data.ts, and
  `checkpointSnapshot` added via optionalKey to `EnvironmentPullSchema`
  (§12-7) and `LeaseResponseSchema` (§14-2). metadata-only pull is out of
  scope (§12-7 — carries no values)
- **server**: a read path `checkpointSnapshot(environmentId)` in data-store.ts
  (a join of environment_checkpoints + checkpoint_snapshot_values — M2's
  stored rows themselves; not re-derived). pullEnvironmentProgram / issueLease
  bundle it only when the row exists (LeaseValue derives from
  EnvironmentPullValue so the type follows automatically). Deletion cascade
  (§12-4) keeps existing behavior (snapshot rows are deleted too)
- **CLI**: `checkpoint-integrity.ts` (ruling R) — basis =
  history.latestCheckpointFor (chain-derived, server-independent). (1) basis
  exists + no enumeration = reject (MUST), (2) the locator's 2-classification
  (ruling S), (3) reject duplicate variableIds in the enumeration +
  computeEnvValuesDigest recomputation = match the basis values_digest,
  (4) per distributed variable: version ≥ enumeration's, hash match if equal,
  epoch ≥ basis epoch on an advancing version (the checkpoint version of
  floor rule (c)), (5) a variable in the enumeration but absent from the
  distribution is rejected unless explained by a verified tombstone,
  (6) distributed variables not in the enumeration require epoch ≥ basis
  epoch (same shape as version-0 equivalent; manifest consistency is
  guaranteed by the earlier digest recomputation), (7) no basis + enumeration
  present = the locator's 2-classification for future / reject. Wired into
  values.ts's verifyAll (valued paths) after the manifest stage; both the pull
  (bounded re-sync) and lease (future = immediate rejection) paths go through
  the same implementation. The lease path warns on valued distributions of
  no-basis environments (ruling V)
- **floor**: unchanged (ruling U)
- **In-flight addendum 1 (consistency between migration tolerance and the
  basis)**: `--init-manifest`'s "absence tolerance" does not apply to an
  environment holding a basis checkpoint on the verified chain (values.ts's
  manifest stage). Since a checkpoint tuple binds manifest_version (§6.2 /
  §12-4), an environment with a basis always has a manifest — its absence is
  evidence of suppression even under the migration op (the chain-derived
  version of rejecting absence after the floor's manifest record is
  established — §6.3)
- **In-flight addendum 2 (typing evidence — applying the F4 discipline to
  rule 2 / the floor)**: rule-2 rejections and floor-violation rejections are
  typed via `CliError.evidence` (a new field), and rotate's sweep-outcome
  classification (env-rotate.ts settlePass) classifies an evidence-carrying
  re-scan pull failure as **immediate abort**, not "unverified (may heal on
  re-run)". Because M3 moved the detection layer for "old-epoch value
  injection mid-sweep" from the decrypt stage (AEAD failure) to the pull-
  verification stage (rule 2), untyped it would break the F4-pinned discipline
  of "don't demote evidence to re-run guidance" (pinned by the corresponding
  test in env-rotate.test.ts)
- **Making test fixtures honest servers**: CLI mocks that accept a rotate
  composite also simulate snapshot storage (§16-2) and pull bundling (§12-7).
  Two old tests modeled "accepting a composite inconsistent with acceptance-
  time matching" and "an old-epoch variable appearing late after a
  checkpoint" — states a real server turns into 422 (§12-4) / rule-2
  rejection — so the tests were reshaped into honest form (422 → re-pull retry
  / rule-2 evidence abort) (env-rotate.test.ts — intent preserved via in-test
  comments)
- **docs**: SELF_HOSTING.md gained M3's update order (server-first mandatory —
  a new CLI × old server gets all valued pulls / leases of checkpointed
  environments rejected by rule 2's MUST). No spec-body revision needed (M3 is
  implementation-following of the Wave 3 D approved wording; bundling wire
  coordinates — ruling S — is an advisory addition to §12-7's "enumeration",
  consistent with the verification rules' and storage discipline's wording)

## 8. Review response (PR #100)

- **Bugbot (low) — bounded re-sync could wrongly convict an honest snapshot as
  evidence**: bounded re-sync re-verifies on the post-advance view without
  re-fetching the response body, so if another covering checkpoint lands in
  the window between fetch and re-sync, an honest response's locator /
  enumeration (corresponding to the old basis) falls into "inconsistent with
  the latest basis = evidence" and rotate's sweep classification misguides
  "won't resolve on re-run" (it actually resolves on re-pull). **Fix**: give
  rule-2 rejections an evidence type, and the form "the basis advanced beyond
  the response's fetch view (fetchedAtHeadSeq — pull = the head of the
  fetch-time view, lease = the bundled chain's head)" — both the
  old-position-enumeration and no-enumeration forms — is rejected as retriable
  (guiding a re-pull). A form whose basis was already stored at the fetch-view
  point has no benign explanation (the server stores atomically with
  checkpoint acceptance — §16-2), so it stays evidence as before. The lease is
  self-contained, so basis ≤ fetch view holds structurally and it's always on
  the evidence side (no loss of detection strength). Fail-closed unchanged
  (the response is rejected under either classification — only the honesty of
  re-run guidance changes)

## 9. What the tests pin (summary)

- Server (vitest-pool-workers): bundling into valued pull (after basis
  establishment) with content matching the stored enumeration / absent on a
  no-basis environment / absent on metadata-only pull / per-environment
  correspondence after a subset checkpoint (B keeps its own-basis enumeration
  after A's re-checkpoint) / bundling into the lease response
- CLI (pull path): acceptance positives (advancing version after a
  checkpoint, a disappearance explained by a tombstone, new creation after a
  checkpoint) and every rejection path — missing enumeration, digest
  mismatch, version regression, same-version hash mismatch, advancing version
  on an old epoch, unexplained disappearance, old-epoch creation of a
  variable outside the snapshot, locator forgery (hash mismatch at seq ≤ own
  head) — the corresponding items of session-27 §13-5
- CLI (lease path): the same rule is reached (1 rejection + positive) + the
  no-basis warning
- cross-layer (ruling W): 1 test of rule-2 pass × floor-rule-(a) rejection
