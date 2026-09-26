# Session 31 notes (PR-M1 environment manifest — post-merge audit and handoff of the fix work)

Date: 2026-08-19. Subject: PR #81 (`a69cf63`, implementation head `885ab69`).
Form: **audit and handoff only**. The PR adding these notes does not fix the
implementation. Fixes happen in a separate chat · separate PR.

Premises:

- For PR-M1's design · implementation decisions see `docs/notes/session-27.md`
  §5 / §13 / §14 / §16 and `docs/notes/session-28.md`
- The canonical crypto spec is `docs/CRYPTO_SPEC.md` §4.3 / §6.3 / §6.4; the
  canonical acceptance · distribution spec is `docs/AUTH_SPEC.md` §12
- Fixes that change `packages/crypto` require human review per CLAUDE.md
- Do not confuse the known non-guarantees carried by M2 (checkpoints) · M3
  (value snapshots) · M4 (head attestations) with PR-M1 implementation defects

## 1. Conclusion

No plaintext · key-material leak, no crypto-primitive breakage, no LP
field-order mistake, and no `variables_digest` tombstone / empty-set /
byte-order mistake was found. On the other hand, there **are implementation
defects worth fixing** in the fail-closedness of the manifest chaining ·
local floor · rolling update that PR-M1 intended.

The 6 highest-priority items:

1. The CLI does not verify the prev chaining of adjacent manifestVersions
2. New CLI × old server silently drops `manifest`
3. `env create → push a first variable` also fails to establish the
   environment floor
4. There is a failure path where the manifest of an
   acceptance-confirmed rotate doesn't reach the floor
5. A concurrent CLI's floor commit can lose rollback · equivocation
   evidence
6. The H+1 epoch exception's scope is too broad — it doesn't bind the H+1
   entry's actor / op to the manifest issuer

Below, the reproduction conditions · impact · fix proposals · tests to pin
are recorded.

## 2. Facts confirmed by the audit

### 2-1. Merged code and verification results

- PR #81's merge commit `a69cf63` and implementation head `885ab69` have
  identical trees
- main CI / installer after the PR merge: passing
- Root `bun run check`: passing (52 files / 1711 tests)
- crypto:
  - Node: 646 / 646
  - workerd: 646 / 646
  - Chromium: 646 / 646
  - Bun: 645 / 645
  - `test-vectors/tools/verify_reference.mjs`: passing
- `fallow audit`:
  - dead code 0
  - complexity finding 0
  - duplication: warnings only
- No repository file was modified during the audit

All tests being green doesn't catch the paths below — they are boundary
conditions existing tests never create.

### 2-2. Reproduced locally

1. Effect `Schema.Struct` doesn't reject unknown fields — it drops them:
   decoding `{ ..., manifest: {...} }` against the old payload schema
   removes `manifest` and keeps only the known fields
2. Committing to the local floor the same manifestVersion with different
   hashes in sequence stores the later hash and erases the earlier
   equivocation evidence
3. Against floor v1, handing `checkEnvironmentPull` a v2 whose
   `prevManifestSigHashHex` differs from the floor hash still returns
   `null` (no rejection)

## 3. Fix targets

### M1-A1 [high] The CLI doesn't verify prev chaining of adjacent manifests

Relevant:

- `apps/cli/src/manifest.ts`
  - `verifyDistributedManifest`
- `apps/cli/src/floor-check.ts`
  - `checkManifestAgainstFloor`
- `apps/cli/src/floor.ts`
  - `ManifestFloor`

Current state:

- `verifyDistributedManifest` never passes `predecessor`
- The floor holds `(manifestVersion, epoch, manifestSigHashHex)`
- The floor check covers only regression · same-version-different-hash ·
  rule (c); it doesn't compare `prevManifestSigHashHex`

CRYPTO_SPEC §4.3 makes "prev chaining when a floor exists" a verification
rule. Even with latest-only distribution, when
`pulled.manifestVersion === floor.manifestVersion + 1` the floor IS the
immediately preceding manifest, so prev can be strictly verified.

Impact:

- An adjacent version with a valid signature · correct digest / epoch still
  passes CLI verification with an arbitrary 64-hex prev
- The manifest's fork-evidencing · chaining guarantee is effective on the
  server acceptance side but missing on the client distribution side

Fix proposal:

1. When pulled version = floor version + 1:
   - pass `signedBytesHashHex = floor.manifestSigHashHex`
   - `epoch = floor.manifest.epoch`
   to the shared verifier as `EnvManifestPredecessor`
2. When the version differs by 2 or more:
   - since the design keeps · distributes no intermediate manifests, mark
     explicitly that predecessor-existence matching is unverifiable, as
     today
3. If adding floor-evidence wording equivalent to `manifest-prev-mismatch`,
   include the pulled signature / issuer / declared head and the floor hash

Tests to pin:

- floor v1 → v2 with the correct prev: accepted
- floor v1 → v2 with a different prev: rejected
- floor v1 → v3 (version gap): accepted per the known latest-only
  limitation
- same result on both a metadata-only pull and a value pull
- `maruhi ci run`'s lease response: **prev-chain checking does not apply**
  (`verifyLeaseDistribution` doesn't use a floor — a workload is the
  floorless first-sync class [§14.3-3], and `RepositoryAnchor` also carries
  no manifest coordinates. Consistent with §11's "no persistent floor on
  disposable CI"). The lease pin-test is limited to the shared verifier's
  sameness: signature · digest · epoch consistency · missing-manifest
  rejection are at the same level as pull, AND the floor-derived prev
  check does **not** fire on the lease path

### M1-A2 [high] New CLI × old server silently drops manifest

Relevant:

- `apps/cli/src/env-create.ts`
- `apps/cli/src/env-rotate.ts`
- `packages/api-schema/src/data-api.ts`
- the create / rotate payload schemas as of old main `5cf9138`

Current state:

- The new CLI sends `manifest` in the create / rotate payload
- The old server schema doesn't know that field
- Since Effect `Schema.Struct` drops unknown fields, the old server
  continues the old manifest-less processing and can return 200

Concrete consequences:

- `env create`: the CLI reports success while the server has no manifest
- `env rotate --init-manifest`: the old server accepts only the rotate,
  and the CLI can record into the floor a self-issued manifest the server
  never stored
- Updating the server afterwards then judges the missing manifest as an
  omission past floor establishment, which a normal `--init-manifest` can't
  recover from

`docs/notes/session-28.md`'s operating order "server → environment
initialization → CI / CLI update" mitigates this, but
the protocol itself is not fail-closed. In self-hosting the server and CLI
are updated independently, so it's better not to depend on the document
alone.

Fix proposal (revised 2026-08-19 — following §7 ruling 1's final
recommendation [1-E + 1-E′]. The original mandatory-capability-gate design
[old fix proposals 1–3] was demoted to optional UX in §7 so it is replaced.
Same granularity of re-reading as ruling 3):

1. **Main defense = strict acceptance (1-E)**: make acceptance of
   security-critical mutation payloads reject unknown fields (applied
   across the board while pre-release). The first work is confirming how
   Effect v4 `onExcessProperty` applies to the HttpApi acceptance path
   (§7 ruling 1's implementation-cost row)
2. **Definition of success = verifiable effect confirmation (1-E′)**:
   after create / init rotate is accepted, fetch the distributed manifest
   via the chain / a metadata-only pull, reconcile it against the
   self-computed `(version, epoch, signed-bytes hash)`, and only then
   record to the floor and report success (confirmation-material kind
   handling and the non-application to value push are §7 ruling 1
   tertiary)
3. A capability (`/auth/config`'s `apiCapabilities` etc.) is an **optional
   UX addition** (a kind pre-send guidance message) and does not count as
   defense. A follow-up PR is fine

Tests to pin (identical to §9 DoD's 2 configurations):

- A strict-introduced server: rejects a composite payload containing an
  unknown field at the decode stage
- A pre-strict old server: even if the server returns 200, the pull lacks
  the manifest → the floor doesn't advance and it fails (post-acceptance
  reconciliation)
- The server returns a different manifest: fails on hash mismatch

### M1-A3 [high] env create / first-variable push don't establish the floor

Relevant:

- `apps/cli/src/env-create.ts`
- `apps/cli/src/values.ts`
  - `enforceMetadataFloor`
- `apps/cli/src/floor.ts`
  - `applyPush`
- `apps/cli/src/push.ts`
  - `pushVariable`'s post-acceptance floor commit

Current state:

1. `env create` self-computes v1 and its signed-bytes hash but discards
   them without handing them to the floor
2. A first-variable push's name resolution uses a metadata-only pull
3. A metadata-only pull only checks the floor; it doesn't commit
4. `commitPush`, when there is no environment floor, doesn't fabricate a
   pullEpoch and so creates no environment record — only the head
   advances

Reproducible result:

- env create (v1) → first-variable push (v2) both succeed, yet no
  environment floor exists
- A malicious server can return the regular v1 it once received plus an
  empty variable set, getting a rollback view that omits the new variable
  accepted by the next first full pull

Fix proposal:

1. Add an "environment-level-only floor commit" for the metadata-only
   pull:
   - chain head
   - environment meta `(version, hash)`
   - manifest `(version, epoch, hash)`
   - create no value floor for active variables whose values weren't read
   - **don't advance pullEpoch (rule (c)'s reference for values)**
     (reflecting the 2026-08-19 pullfrog review — CRYPTO_SPEC §6.3's norm
     "rule (c)'s reference must not be advanced by a chain sync alone".
     Detail in §7 ruling 3)
2. `env create` creates an empty-variable-set environment floor after
   confirming acceptance via the chain / distribution
3. A subsequent `commitPush` adds v2 + the new variable's value floor to
   the same environment record

Type choices:

- Split `EnvironmentFloor` into environment / manifest parts and a value
  floor part
- Or hold a metadata-only partial floor as a separate type and merge on a
  full pull
- Make it a discriminable type rather than growing impossible states with
  an optional field bag

Tests to pin:

- after env create, a v1 floor exists
- after env create → variable create, a v2 floor exists
- then distributing v1 + the empty set is rejected as manifest rollback /
  omission
- a metadata-only pull doesn't fabricate a value version / value hash

### M1-A4 [high] An acceptance-confirmed rotate can end before the floor commit

Relevant:

- `apps/cli/src/env-rotate.ts`
  - `describeSendFailure`
  - `appendRotation`

The current `commitManifest` sits after:

1. the rotate HTTP succeeds
2. the chain is re-synced
3. the current epoch exactly matches the target epoch
4. the target epoch's DEK commitment matches

Paths that can confirm acceptance without reaching the floor commit:

- After HTTP response loss / a 502, `describeSendFailure`'s probe confirmed
  the target-epoch commitment matches
- After HTTP 200, another rotate advanced before the re-sync and
  currentEpoch overtook the target — but one's own rotate acceptance is
  confirmable from the past epoch's commitment

Impact:

- The CLI knows "this very rotate was accepted" yet leaves no self-issued
  manifestVersion on the floor
- A window remains where a malicious distribution immediately after can
  roll back to the pre-acceptance manifest / epoch reference

Fix proposal:

1. Keep the manifest and entry signed in each CAS attempt
2. Make the send result a discriminable outcome:
   - `rejected`
   - `not-accepted`
   - `accepted-and-current`
   - `accepted-but-superseded`
   - `acceptance-unknown`
3. Once the on-chain target-epoch commitment matches one's own value,
   advance the manifest floor even if the command ultimately exits in
   error
4. If the probe itself fails and acceptance is unknown, don't advance the
   floor
5. Integrate into the same confirmation path as M1-A2 fix proposal 2
   (1-E′'s post-acceptance reconciliation — effect confirmation via the
   chain / a metadata-only pull)

Tests to pin:

- 502 + own commitment matching on the chain: the floor advances even on
  error exit
- 200 + another rotate right after: one's own manifest remains as the
  minimum floor
- an on-chain commitment that is different: the floor doesn't advance
- probe failure: the floor doesn't advance and `unknown` is guided

### M1-A5 [high] A concurrent CLI's floor commit can lose evidence

Relevant:

- `apps/cli/src/floor.ts`
  - `mergeHead`
  - `mergeVariableFloor`
  - `mergeManifestFloor`
  - `makeFileFloorStore.write`
- `apps/cli/src/floor-check.ts`
  - `makeFloorHandle.commitPush`'s fallback when the on-disk environment
    record is missing
  - `makeFloorHandle.commitManifest`'s in-process prior advancement
- `apps/cli/src/values.ts`
  - the check–commit separation of the floor

Current state:

- the distribution is checked against the floor read at command start
- at commit, the file is re-read and merged monotonically
- for the same manifestVersion, `>=` makes the incoming one win
- there is no inter-process lock between read → merge → temp write → rename
- `makeFloorHandle`'s 2 in-process merge paths likewise let the later win
  on `manifest.manifestVersion >= current.manifest.manifestVersion`. Even
  fixing only `floor.ts`'s disk merge, the in-command later-check
  reference remains overwritable by a same-version-different-hash

Problems:

1. If 2 processes verify different same-version manifests from the same
   old floor, the later commit can overwrite the earlier hash
2. A truly concurrent read-modify-write can go last-writer-wins: both read
   the same old file and the later rename loses the earlier union
3. Even if the merge saves the newer side, the command in question has
   already accepted the distribution under a stale in-memory floor, so it
   can succeed using stale data

Fix proposal:

1. Introduce an inter-process lock per project floor
2. Under the lock:
   - re-read the latest file
   - re-check the incoming response / commit
   - merge
   - temp + rename
3. Don't let same-coordinate mismatches be "later wins":
   - same chain seq + different hash
   - same value version + different hash
   - same metaVersion + different hash
   - same manifestVersion + different hash
   are rejected as a typed conflict
4. Share the same typed-conflict determination into `makeFloorHandle`'s
   in-process fallback / prior advancement too — leave no simple `>=`
   replacement
5. lower-version / omitted-known-record cases are also re-checked at
   commit time
6. Design the lock's crash recovery:
   - use an OS advisory lock
   - or a lock file with owner PID / timestamp + staleness determination
   - don't fail-open to floorless on lock-acquisition failure

Tests to pin:

- a real-concurrency test with 2 processes / 2 store instances
- one side of a same-version-different-hash is not overwritten; rejection
  carries both pieces of evidence
- concurrent commits of different variables union
- a stale lower-version commit fails that command too
- recovery after the lock-holding process exits abnormally

### M1-A6 [medium] The H+1 epoch exception's scope and actor binding

Relevant (the verifier and every caller that has to specify the epoch
handling):

- `packages/crypto/src/internal.package/manifest-verify.ts`
  - `epochIntegrityReason`
- `packages/crypto/src/internal.package/chain-history.ts`
- `apps/server/src/verify-manifest.ts`
  - `acceptManifestForMetaOp` (the strict side's application surface)
- `apps/server/src/composite-programs.ts`
  - the 2 `acceptEnvManifest` call sites in create / rotate (the composite
    side's application surface — the bundled entry is the anchor material)
- `apps/cli/src/manifest.ts`
  - `verifyDistributedManifest` (the distribution-verification side's
    application surface — the verified chain's H+1 entry is the anchor
    material)

First, **the bindings already checked** (recorded so the audit doesn't
mis-detect):

- In both composite create / rotate, the worker checks
  `entry.actor.userId === principal.userId` via `ensureCompositeActor`
  (`handlers-environments.ts`)
- The DO re-runs `verifyChain` at append acceptance and enforces that the
  entry actor's fingerprint matches the member record on the chain
  (`actor-key-mismatch`)
- The server-acceptance manifest issuer doesn't trust the wire:
  `verify-manifest.ts` force-overwrites it with the calling principal's
  member identity (`input.member.userId` / `keyFingerprintHex`)

So there is no server path accepting with "actor / issuer ≠ caller". The
remaining mismatch is the shape of the H+1 exception itself:

1. `epochIntegrityReason`'s H+1 exception only looks at "mismatch at H ·
   match at H+1" and doesn't compare the H+1 entry's actor / op against
   the manifest issuer. Since the epoch can move at most +1, the H+1 entry
   being that environment's create / rotate follows as a consequence —
   but **a speculative epoch bake-in riding on another member's rotate**
   (a manifest declaring an epoch its issuer never established) gets
   accepted by distribution verification (the CLI side)
2. The same H+1 exception also applies to server acceptance of
   non-composite meta operations (`acceptManifestForMetaOp`), so an
   ordinary meta op can bake in "an epoch that was not established at the
   declared head H but was established at H+1". AUTH_SPEC §12-4's intent
   was that the H+1 exception exists only for the create / rotate
   composite

Fix proposal:

1. Make `verifyDistributedEnvManifest`'s epoch mode explicit:
   - `strict-at-head` (non-composite server meta op)
   - `allow-composite-next-entry` (create / rotate, distribution
     verification)
2. Add to `ChainHistoryIndex` an API that queries the H+1 entry's actor /
   op / environment coordinates as verified info
3. When using the H+1 exception, require:
   - the op is a create / rotate of that environment
   - the issuer user / fingerprint matches the entry actor
4. This fix modifies `packages/crypto`, so human review is required

Pin vectors / server tests:

- create / rotate: issuer = H+1 entry actor → accepted
- issuer ≠ H+1 entry actor (riding on another member's rotate) → rejected
- an ordinary meta op using an H+1 epoch → rejected
- pin, as regression tests, the existing actor / issuer bindings (worker
  userId check · DO fingerprint check · server issuer overwrite)

## 4. Low-priority fixes

### M1-B1 The v1 head pin runs ahead of the manifestVersion CAS

`acceptManifestForMetaOp` checks the `manifestVersion === 1` head pin
before fetching the stored anchor and the CAS.

Sending a stale v1 to an initialized environment can produce
`payload-mismatch` 422 where it should return `ManifestVersionConflict`
409 + `currentManifestVersion`. A honest client can't join its re-fetch ·
re-sign loop.

Fix proposal:

- Keep the order anchor fetch → manifestVersion CAS
- head-pin only when `anchor === null && incomingVersion === 1`
- When initialized, return 409 first regardless of the head's recency

### M1-B2 The `--init-manifest` wording on an initialized environment

`rotateSituationWarnings` shows "this rotation will re-issue the next
manifestVersion" when a manifest already exists, but when the path is
`resume` / `up-to-date` no rotate composite is sent.

Fix proposal:

- Choose the wording after `rotatePathOf`'s result settles
- `rotate`: issue the next version as usual
- `resume`: the flag isn't needed; this run only resumes re-encryption
- `up-to-date`: the flag isn't needed; this run issues nothing

## 5. Test fixes · additions

### M1-T1 The legacy-init positive uses a different DEK
the legacy-init positive in `apps/server/test/data-manifest.test.ts` uses
`wrapDekForAll({ dek: makeDek() })` and `commitmentOf(..., makeDek())` —
two different random DEKs.

The server can't open the plaintext of member-addressed wraps, so it
accepts, but the distributed new-epoch DEK doesn't match the chain
commitment and a peer CLI rejects it.

Fix proposal:

- Use a single `const nextDek = makeDek()` for both wrap / commitment
- Don't end at the server's 200; run it through the CLI's pull /
  commitment verification

### M1-T2 Strengthening the crypto boundary vectors

The current UTF-8 ordering cases are mostly ASCII; the implementation is
correct but the following aren't pinned directly:

- UTF-8 byte order of BMP vs astral code points
- a fractional integer (`1.5`)
- `Number.MAX_SAFE_INTEGER + 1`
- uppercase hex of the same length

Added to:

- `packages/crypto/test-vectors/env-manifest.json`
- the standalone Python generator / JS reference verifier
- the Node / Bun / workerd / Browser common check

Since this includes a test-vector change, keep the discipline **vectors
commit first → crypto test**.

## 6. Recommended split and order of fix PRs

### PR-F1: old-server fail-closed (making strict acceptance a spec principle)

Subject:

- M1-A2 (ruling 1's revised recommendation = option 1-E: across-the-board
  rejection of unknown fields + post-acceptance reconciliation. A
  capability is optional UX, later)
- SELF_HOSTING / update-order public docs

Reasons:

- Defends the entry point from creating new inconsistent states via the
  wrong update order
- Closes ahead of the server / CLI releases
- First work = confirming how Effect v4 `onExcessProperty` applies to the
  HttpApi acceptance path (§7 ruling 1)

### PR-F2: CLI manifest-floor completeness

Subject:

- M1-A1
- M1-A3
- M1-A4
- M1-A5
- M1-B2

It's large as an implementation, so it may be further split into:

1. adjacent prev + metadata floor + env create anchoring
2. rotate's acceptance outcome / floor commit
3. floor storage form (follows §7 ruling 3's adoption: if 3-E is adopted,
   append-only + fold; if not, §3 M1-A5's inter-process serialization)

### PR-F3: H+1 epoch mode and issuer binding

Subject:

- M1-A6 (the owner picks from §7 ruling 2's ladder — 2-F / 2-E / 2-D, with
  2-H added at the 5th iteration and 2-G′ [recommended] at the 6th —
  docs/notes/session-32.md §4-2 / §5-1)
- M1-B1
- the H+1 / actor negatives of M1-T2

Notes:

- changes `packages/crypto`
- vectors first
- human review required
- if 2-F is adopted, includes a consensus-rule change: full regeneration
  of `chain-entries.json` + re-genesis of existing dogfooding chains
  (§7 ruling 2 quaternary)

### PR-F4: test hardening

Subject:

- M1-T1
- the rest of M1-T2
- cross-layer regression of every fix

## 7. Items needing an owner ruling

Most of the fixes are conformance work against already-approved specs, but
the following 3 **advance a spec revision** (CLAUDE.md — a spec change
first updates the spec and gets human approval before implementation).

### Ruling 1 (PR-F1 / M1-A2): the shape of old-server fail-closedness

Problem: on new CLI × old server, the `manifest` field is silently
dropped, and the CLI can misread "a manifest the server never stored" as
success.

Options:

- **Option 1-A: add a capability declaration to `/auth/config`
  (pre-check)**
  - A string array like `apiCapabilities: ["environment-manifest-v1"]`.
    The CLI checks **before** a manifest-bearing mutation, and if absent
    sends nothing and guides a server update
  - Advantages: stops **before creating** the inconsistent state (the
    chain has the entry but no manifest). Judgeable on a public endpoint,
    unauthenticated, in 1 GET. A general-purpose surface usable for
    future feature additions. Since Workers is a single deploy unit, a
    divergence between config and handlers can't structurally occur
  - Drawbacks: requires revising AUTH_SPEC §4 (this ruling's subject)
- **Option 1-B: a server version-number declaration + the CLI's minimum
  requirement**
  - Drawbacks: poor fit with self-hosted forks · partial application, and
    a number doesn't carry the semantics of "which features exist".
    Forever maintaining a per-feature minimum-version table
- **Option 1-C: post-reconciliation only (fetch the stored manifest via
  the accept response · pull and reconcile against the self-computed
  (version, epoch, hash))**
  - Advantages: directly confirms "it was actually stored" — no TOCTOU
  - Drawbacks: alone, detection comes **after** the mutation is sent —
    with rotate the failure lands after the entry is already carved into
    the chain, and it can't prevent M1-A2's inconsistent state of
    "missing manifest misjudged as omission"
- **Option 1-D: reject unknown fields on security-critical payloads
  (strict-ify the server schema)**
  - Advantages: structural prevention of future same-kind accidents
    (silent drops of new fields)
  - Drawbacks: can't fix already-distributed old servers, so it isn't a
    countermeasure to this issue itself. Deviating from Effect Schema's
    default (dropping), so the policy needs to be put in writing
- No option (only session-28's operating-order document) doesn't make a
  permanent fix, since in self-hosting the server and CLI update
  independently — dismissed

Old recommendation (2026-08-19 first version): option 1-A primary +
option 1-C in combination + option 1-D for new schemas. → Replaced by the
strictly-better option below.

#### Strictly-better option (reconsidered 2026-08-19)

**Option 1-E: make "unknown field = reject" a spec principle of
security-critical acceptance (structural fail-closed while pre-release)**

Facts surfaced on re-confirming the frame:

- maruhi is pre-release (ROADMAP Phase 2 not reached). The spec repeatedly
  uses the principle "being pre-release, no backward-compatibility
  clause" — §6.2 (member-key uniqueness) · the `checkpoint` op · the
  grant_server extension
- No "old server" exists externally. What exists is only the internal
  dogfooding deployment, whose migration session-28 §2-2's procedure
  already covers
- The chain layer already has the same-shaped principle: **the consensus
  rule "unknown op = chain invalid"**. Only the API acceptance layer has
  the opposite default of Effect Schema's (silently dropping unknown
  fields) —
  this option is positioned as resolving that asymmetry
- Effect v4 (rc.109) has `SchemaAST`'s `onExcessProperty` /
  `UnexpectedKey`, so strict acceptance is implementable (confirming how
  it applies via HttpApi is PR-F1's first task)

Content:

1. Make acceptance of security-critical mutation payloads (chain appends ·
   composites · value push · meta operations · wrap registration · lease
   requests) reject unknown fields (strict). Being pre-release, it can be
   introduced with no backward-compatibility clause
2. Put a 1-line design norm into the spec for future wire-incompatible
   changes: "shape them so old implementations reject them
   structurally" — field additions · removals are auto-caught by strict.
   A semantics-only change must always carry a structural marker (a new
   field, or a bump of a mandatory literal version pin)

Comparison with capability (option 1-A):

- 1-A is **cooperative** — it depends on the discipline of every future
  client never forgetting to check. 1-E is **structural** — the old
  server itself rejects, so no client-side discipline is needed
- 1-A protects only the enumerated capabilities. 1-E auto-catches every
  field addition · removal
- 1-A has a TOCTOU window between checking and sending. 1-E rejects at
  acceptance-time decode = atomic per request (a composite is 1 request,
  so partial acceptance can't structurally occur)
- 1-A's remaining advantage is UX only (a pre-send guidance message
  saying "the server is old")
- **1-E's implementation cost (reflecting the 2026-08-19 pullfrog
  review)**: `onExcessProperty` is a `ParseOptions` of the decode call,
  not a schema annotation, and the current `HttpApiBuilder` assembles the
  payload decoder without ParseOptions. Confirming the route to strict
  acceptance (an option on the endpoint definition · a manual decode
  layer · an upstream change — one of these) is PR-F1's first task, and
  this option's cost is settled by its outcome

Revised recommendation (secondary): make option 1-E the main defense as a
spec principle (across-the-board application while pre-release), keep
option 1-C (post-acceptance reconciliation) as a defense layer, and
demote option 1-A to an optional UX addition (a follow-up is fine). It is
the strengthened form of 1-D's "from new schemas" → "while pre-release,
across the board", and moves fail-closedness from protocol cooperation to
the structure of the deployed artifact. The spec-revision surface also
shrinks from AUTH_SPEC §4 (a new endpoint surface) to 1 clause of §12's
acceptance principles.

#### Further consideration (2026-08-19 tertiary) — 1-E's residual and promoting the definition of success

Re-inspected the premises option 1-E leaves accepted as-is:

- (i) A semantics-only change (schema-invariant) can't be caught by
  strict; it remains under the "carries a structural marker" design norm
  (human discipline)
- (ii) strict is a **acceptance-side** defense of the server; "may the
  client trust a 2xx" remains a separate problem

Options considered and dismissed:

- Auto-reconciliation of a schema fingerprint (putting a build-derived
  schema hash on the payload, the server checking it against its
  acceptance set): adds machinery while not closing (i) (a semantics
  change is schema-invariant) — dismissed as over-engineering
- Strict version-match between CLI and server (full lockstep): an
  operating rigidity that unnecessarily rejects self-hosted independent
  updates and application of compatible fixes — dismissed

The promotion adopted — **option 1-E′: promote post-acceptance
reconciliation to "the definition of success"**:

- The spec defines a security-critical mutation's success not as "a 2xx
  was received" but as "**the effect was confirmed on a verifiable
  artifact (the chain · a verified pull)**"
- This is a consistent application of maruhi's existing principle (don't
  trust the server — E2EE · chain verification · distribution-time
  verification) onto the mutation side; the same defense works against
  not only old servers but **malicious or buggy new servers**
- 1-E (atomicity of acceptance — never **let** a half state be created)
  and 1-E′ (the source of truth of success — never **believe** one was
  created) are the two faces of the same principle: "a 2xx is only a
  transport-layer fact"
- **The confirmation material is fixed per mutation kind (reflecting the
  2026-08-19 pullfrog review)**: chain appends · composites use a chain
  sync; meta operations (statements · manifests) use a metadata-only pull
  (a path that records no `var.read`). **Value push is outside 1-E′'s
  scope**: the only artifact usable for effect confirmation is a value
  pull, which would bring `var.read` audit onto the write path (the same
  collision as option 3-B's dismissal basis — the flip side of why
  `pullVerifiedEnvironmentMetadata` exists for push). A value push's
  success is carried as before by the server's CAS + value-signature
  verification and the own floor's `commitPush`; value-rollback detection
  is checkpoint's (M2) domain
- Recording to the floor (M1-A4's acceptance confirmation) · reporting
  success to the user are done only by what passed this confirmation —
  M1-A2 fix proposal 4's "fetch and reconcile" changes from a defense
  layer into the definition itself

Final recommendation (tertiary): 1-E (strict acceptance) + 1-E′
(promoting the definition of success) + the structural-marker norm for
semantics changes. Capability (1-A) stays optional UX as before. Since
residual (i) can't be erased even by a schema fingerprint, this form is
judged the ceiling of this ruling's design space.

#### Quaternary consideration (2026-08-19) — reducing the residual norm to an existing invariant

On re-inspecting (i), which the tertiary left as "human discipline" (the
structural-marker norm for semantics-only changes), **it reduces to an
existing invariant with no new mechanism**:

- Every security-critical structure in maruhi (chain entries · values ·
  statements · manifests · DEK wraps · leases) already carries a
  **canonicalized LP signed-bytes string with a domain-separation tag**
  (§2.1). A semantics change to a signature structure IS a change to the
  LP field list, which an old implementation **auto-rejects as a
  signature-verification mismatch** — the signature itself is the
  structural marker
- So the norm is not "attach a marker to semantics changes" (operating
  discipline) but "**security-critical semantics always live inside a
  domain-separated signed-bytes string**" (codifying existing
  architecture)
- Two surfaces where human discipline remains (reflecting the
  2026-08-19 pullfrog review — the original "effectively empty set" was
  an overclaim): (i) the non-signed transport parts — coordinates are
  already guaranteed by §12-5's server-side reconstitution, and advisory
  flags like `reencryption` are by design not security-critical;
  effectively an empty set. (ii) **the acceptance side's
  verification-mode selection** — M1-A6 is exactly the counterexample:
  "does the epoch look at the declared head or allow up to H+1" lives in
  no signed bytes and is decided only by the acceptance side's routing.
  This residual depends on ruling 2's outcome: adopting 2-E / 2-F
  structures the selection into data (a signature field / the chain
  payload) and it disappears; under 2-D it remains as a calling
  convention (strict by default) discipline

Also, if ruling 2 adopts option 2-F (reverse binding), a composite's
success confirmation (1-E′) **completes with a chain sync alone** (since
the entry carries the manifest hash, no distribution-pull reconciliation
is needed) — recorded as a synergy.

**Final recommendation (settled): 1-E + 1-E′ + codifying "semantics live
inside the signed bytes"**. The quaternary confirmed no new mechanism is
needed — the ceiling of this ruling is conditioned on the
verification-mode-selection residual being decided by ruling 2's outcome
(structured away under 2-E / 2-F; remaining as discipline under 2-D).

### Ruling 2 (PR-F3 / M1-A6): writing the H+1 exception into the spec

- CRYPTO_SPEC §4.3 verification rule (2) and §6.3's manifest verification
  read, literally, as an exact match "manifest epoch = the current epoch
  **at the declared head**", and the exception that accepts the composite
  issuance form (declared head H = pre-append head, the epoch established
  by the H+1 bundled entry) has **no written text in the spec** (only the
  session-28 notes and a comment in `manifest-verify.ts`)
- A legitimately composite-issued manifest (create = epoch 1, rotate =
  new_epoch) can't be verified under exact matching, so some exception is
  needed

Options:

- **Option 2-A: binarize the verification mode + codify the H+1 entry's
  op / actor binding**
  - Write `strict-at-head` (non-composite server meta op) and
    `allow-composite-next-entry` (create / rotate composite acceptance,
    client distribution verification) as distinct spec verification
    rules. The latter adds to its acceptance conditions "the H+1 entry is
    a create / rotate of that environment and its actor (user + FP)
    matches the manifest issuer"
  - Advantages: no wire-format · storage-format change (only
    verification-rule strengthening). Every legitimately issued manifest
    passes; no re-issuance · migration needed. Blocks both speculative
    epoch bake-in (riding another's rotate) and H+1 use in non-composites
  - Drawbacks: a mode argument on the verifier, an H+1-entry
    lookup API on `ChainHistoryIndex` (the crypto API surface thickens
    slightly)
- **Option 2-B: change a composite-bundled manifest's declared head to
  "the post-append head (= the bundled entry itself)" and abolish the
  exception entirely — always strict-at-head**
  - Advantages: the very concept of an exception disappears; the
    verification rule unifies
  - Drawbacks: **re-litigation of an existing AUTH_SPEC §12-4 ruling
    (2026-08-03: "the form that declares the bundled entry itself as the
    head is not accepted — removing the ambiguity of which chain is being
    checked")**. Statements (values · meta) keep pointing at the
    pre-append head, so the manifest alone becomes asymmetric. Already
    issued manifests become the old format, requiring dogfooding
    environments to be re-initialized (migration)
- **Option 2-C: ratify the current unconditional H+1 exception into the
  spec as-is (no binding)**
  - Drawbacks: speculative epoch bake-in becomes spec-sanctioned, and
    H+1 use in non-composite meta operations stays contradictory to
    AUTH_SPEC §12-5 (4)'s current wording. Equivalent to dismissal

Old recommendation (2026-08-19 first version): option 2-A. Option 2-B is
a re-litigation of an existing ruling (the shape CLAUDE.md forbids), and
the migration cost + introduced asymmetry aren't worth the
simplification gained. → While keeping 2-A's intent, the form below is
strictly better.

#### Strictly-better option (reconsidered 2026-08-19)

**Option 2-D: enable the exception not by a mode enum but by explicit
presentation of a verified composite anchor (default = strict)**

Option 2-A's mode argument (`strict-at-head` /
`allow-composite-next-entry`) leaves fail-open room — a caller passing
the wrong mode, or the default landing on the lenient side. Replaced by
this shape:

- `verifyDistributedEnvManifest` takes an optional `compositeAnchor`
  (the coordinates of the verified H+1 entry: op · environmentId · actor
  user + FP · the established epoch)
- **Unspecified = strict (match at the declared head only)**. A
  non-composite meta operation's server acceptance becomes correct by
  "just passing nothing" — the failure direction when forgotten is fixed
  on the safe side
- Only when specified does acceptance widen, and it requires **all** of:
  - anchor.op is a create / rotate of that environment
  - the epoch the anchor establishes (create = 1, rotate = new_epoch)
    = manifest.epoch
  - **anchor.actor (user + FP) = manifest issuer**
- The anchor's provenance: server composite acceptance = the bundled
  entry itself (just verified — no history lookup needed). Client
  distribution verification composes it from the seq H+1 entry of its
  own verified chain (the client holds the whole chain — §6.3. A lease
  recipient likewise — the lease response bundles the chain — AUTH_SPEC
  §14)

Comparison with option 2-A:

- Since the default is strict, the fail-open mode-passing mistake
  disappears type-wise
- The exception's premise (the H+1 entry's coordinates · actor) becomes
  the verifier's **explicit input**, pinnable directly in test vectors.
  No history lookup grows inside the verifier — the crypto core stays
  small and the human-review burden stays small
- No need to add an H+1 query API to `ChainHistoryIndex` (the caller
  composes the anchor from verified material — same "caller's verified
  material" trust class as `entries` / `history`)
- On the anchor path, even the `environmentStateAt` lookup becomes
  unnecessary, and the verification rule's branching folds into the
  single axis of "anchor present or not"

Revised recommendation (secondary): codify option 2-A's intent (limiting
the exception's scope + issuer binding) in option 2-D's form. The spec
wording is "the exception is enabled only by presenting a verified
anchor. The default is strict" — stronger as a norm than enumerating
mode names.

#### Further consideration (2026-08-19 tertiary) — self-describing the issuance mode

The premise option 2-D leaves accepted: the manifest itself doesn't
declare "composite issuance or not" — the issuance mode sits **outside
the signed bytes** (the verifier infers it from context, strict →
anchor). Break this:

**Option 2-E: adding a `composite_entry_hash_hex` field — the manifest
self-describes its composite binding**

- Add `composite_entry_hash_hex` to §4.3's LP signed bytes (at the end).
  Composite issuance = the bundled entry's entry_hash; non-composite =
  the empty string (same pattern as manifestVersion 1's empty prev
  string)
- Verification becomes deterministic in a single pass:
  - empty → exact match with the current epoch at the declared head
    (strict)
  - non-empty → exact match with `entryHashAt(H+1)` (**already exists**
    on `ChainHistoryIndex`) + the epoch established at H+1 =
    manifest.epoch + **the H+1 entry's actor = manifest issuer**
- Since entry_hash covers the whole of actor · payload (including the
  dek commitment), it is a **cryptographically stronger binding than the
  coordinate enumeration (2-D's anchor)**: speculative piggybacking
  (riding someone's **future** rotate) can't know the entry_hash in
  advance and is structurally impossible. What remains is post-hoc
  piggybacking (copying a public hash on the chain), which the
  actor = issuer rule closes
- **Doesn't collide with §12-4's existing ruling (declared head =
  pre-append)**: the declared head stays H (the head-existence check's
  subject is also unchanged). The added field is an epoch-anchor
  binding, not a head declaration
- CAS retry already re-signs "the entry · statement · manifest in full"
  (env-create.ts), and the order entry-hash-settles → manifest-signs
  works under the existing construction order

Costs (the only burden this option has that 2-D lacks):

- A wire · signed-bytes change = full regeneration of the
  `env-manifest.json` vectors + re-issuing manifests in existing
  dogfooding environments (one meta operation / rotate per environment.
  Since the server keeps only the latest manifest, the old format
  disappears naturally. The floor's prev chaining is unaffected because
  the hash is an opaque value)
- The crypto diff is bigger than 2-D's (though the verification logic
  itself simplifies — the probe goes away)

Decision material — precedent: the grant_server lease-policy extension
(§6.2) chose full vector regeneration, reasoning "fixing the payload
format before release dissolves it without paying the grandfathering
cost". **Once released, this option becomes unselectable** (it would
need a backward-compatibility clause) — if it is chosen at all, it must
be now.

Final recommendation (tertiary): if the owner accepts the one-time cost
of vector regeneration + manifest re-issuance, option 2-E; if not,
option 2-D.

#### Quaternary consideration (2026-08-19) — inverting the binding's direction

The premise option 2-E leaves accepted: the binding direction is
"manifest → entry", and since post-hoc piggybacking (copying a public
entry_hash on the chain) is possible, **the actor = issuer rule remains
as an independent check**. Inverting the direction removes that rule
too:

**Option 2-F: reverse binding — the chain entry carries the manifest**

- Add `manifest_version` + `manifest_sig_hash_hex` to the
  `create_environment` / `rotate_epoch` payloads. **Same shape and same
  fields as the checkpoint op's payload entry
  `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
  values_digest_hex)`** (§6.2); rides fully on the precedent "the chain
  carries manifest hashes, whose contents chain verification can't
  verify (the data layer's job)"
- The verification rule becomes a single check: the manifest's epoch
  equals the current epoch at the declared head. The exception applies
  only when "**the H+1 entry is a create / rotate of that environment
  and its payload's manifest_sig_hash_hex equals this manifest's
  signed_bytes hash**"
- **The actor = issuer rule becomes unnecessary**: the entry's actor
  signed "I rotate accompanied by this manifest (hash)", establishing a
  bidirectional cryptographic binding. Post-hoc piggybacking is
  structurally impossible because one's own manifest's hash isn't on
  the entry — both speculative and post-hoc cases disappear without a
  check rule
- **The manifest's wire format is unchanged** (2-E's
  `composite_entry_hash_hex` addition becomes unnecessary — the
  env-manifest vectors only gain negatives; no format regeneration)
- Ripple effects (what this option strengthens at the same time):
  - **An issuance-time chain anchor**: the rotate / create manifest's
    hash lands on the authenticated broadcast (the chain). On top of
    checkpoints (periodic), the most important point — the epoch
    boundary — is anchored immediately at issuance
  - M1-A4: acceptance confirmation = just confirming one's own entry on
    the chain, and the manifest's floor-commit material (version + hash)
    is all present
  - M1-A3: the floor's manifest record right after env create can be
    established by chain derivation
  - 1-E′: a composite's success confirmation completes with a chain
    sync
- The construction order works: manifest signs (binding declared head
  H) →
  hash computation → entry construction · signing. CAS retry re-signs
  everything as today (only the order is swapped)

Costs (heavier than 2-E — this option's only burden):

- A chain **consensus-rule** change = simultaneous update of every
  implementation + full regeneration of the `chain-entries.json` vectors
  (including expected_head_states) + **rebuilding the existing
  dogfooding chains (re-genesis)** — because existing chains contain
  old-format create / rotate entries. The flip side of what the
  checkpoint op explicitly listed as an advantage — "touches no existing
  op payload" (§6.2)
- **Re-genesis doesn't stay inside the chain layer (reflecting the
  2026-08-19 pullfrog review — the original estimate was too small)**:
  projectId = the genesis hash, and the signed bytes of values ·
  environment meta · manifests all bake in project_id and
  chain_head_hash_hex (§4.1 / §4.2 / §4.3). Regenerating genesis makes
  all existing signed data unverifiable on the new chain, so it comes
  with **a full rebuild of the data layer** — re-pushing every variable,
  re-registering members, re-pinning repository anchors, discarding the
  floor. One granularity coarser than 2-E's "re-issue by one meta
  operation per environment"
- PR-F3's crypto diff · human-review burden becomes the largest

Decision material: the grant_server lease-policy extension and adding
the commitment to rotate are both precedents of choosing "fix the
payload format before release and dissolve it without paying
grandfathering". **Once released, a chain-op format change becomes
practically impossible** (every existing chain would need a
backward-compatibility clause), so this option too is now-or-never.

**Final recommendation (settled) — the ladder of strength vs one-time
cost**:

1. **Option 2-F** (recommended): if re-genesis (**including a full
   data-layer rebuild** — the cost row above) is acceptable, it's the
   strongest — the fewest check rules, plus a permanent structural gain:
   an issuance-time anchor at the epoch boundary. Consistent with
   maruhi's choices so far (pay before release for permanent
   simplicity)
2. Option 2-E: if only manifest re-issuance is acceptable
3. Option 2-D: if all wire changes must be avoided

All of them close this finding. 2-F / 2-E are pre-release-only options.

**5th and 6th iterations (2026-08-19 — after these notes were
written)**: the addition of option 2-H (a dedicated anchor op
composite-atomically bundled) is in docs/notes/session-32.md §4-2, and
option 2-G′ (checkpoint's composite atomic bundling — regenerated after
correcting an error in 2-G's dismissal reason) is in the same §5-1.
The ladder became **2-G′ (recommended)** / 2-H / 2-F / 2-E / 2-D.

- Note that **AUTH_SPEC §12-5 (4)'s current wording already limits the
  exception to "the part bundled in a rotate composite"** — making
  non-composite meta operations strict-at-head is conformance fixing
  and needs no ruling. The ruling's subject is only codifying the
  client-verification rule on the CRYPTO_SPEC side and adding the
  actor / op binding
- `packages/crypto` is modified, so human review is also required (§3
  M1-A6)

### Ruling 3 (PR-F2 / M1-A3): extending when the floor is established

Problem: CRYPTO_SPEC §6.3's local floor defines the recording trigger
as "the last successful pull (verified)"; under the flow `env create →
first-variable push` the environment floor is never once established.

**Limiting the ruling's subject (reflecting the 2026-08-19 pullfrog
review)**: floor recording after a rotate's acceptance is confirmed
(M1-A4) is outside this ruling — CRYPTO_SPEC §6.3 already writes its
rule presupposing floor promotion at rotate acceptance ("immediately
after the rotate composite is accepted — the accepted manifest is
promoted to the floor but the pull reference doesn't move until the
next pull"). M1-A4 is conformance fixing (consistent with these notes'
ruling-not-needed list). The ruling's subjects are only the 2 triggers:
**the metadata-only pull's environment-level commit and env create's
post-acceptance-confirmation v1 floor**.

Options:

- **Option 3-A: generalize the recording trigger to "every verified
  distribution · acceptance confirmation" and codify an
  environment-level partial floor**
  - A metadata-only pull commits only the environment level (chain head
    / envMeta / manifest) and **creates no value floor for variables
    whose values weren't read** (no fabrication). env create records
    the self-issued v1 after confirming acceptance via the chain /
    distribution
  - **Does not redefine rule (c)'s reference for values (the pull
    reference)** (reflecting the 2026-08-19 pullfrog review — the
    original redefinition to "latest observation regardless of source"
    is retracted): CRYPTO_SPEC §6.3 explicitly states "**rule (c)'s
    reference must not be advanced by a chain sync alone** — promoting
    to the reference without a pull would falsely reject legitimate
    latest values left at the old epoch between rotation and
    re-encryption completion (AUTH_SPEC §12-7). This reference point is
    normative". If the metadata-only environment-level commit advanced
    even the pull reference, a floorless-in-values variable
    (version-0-equivalent)'s legitimate old-epoch value would be
    falsely rejected by stale-epoch-injection (false-rejection case: a
    variable Y left at epoch 1, un-re-encrypted, is received on the
    first full pull by a floor that gained reference 5 via
    metadata-only → rejected)
  - What an environment-level commit may advance: only the chain-head
    floor · the envMeta floor · the manifest floor (rules (a)(b) and,
    of the manifest rule (c) baseline, the floor-manifest-epoch side).
    The pull reference advances only atomically with the value floor,
    as before
  - Drawback: the floor type becomes two layers (environment level /
    value level) and type · merge implementation gets more complex
    (noted in M1-A3's type design)
- **Option 3-B: keep floor semantics unchanged; the CLI automatically
  does a full pull right after a create-kind command to establish the
  floor**
  - Advantages: the spec revision is one sentence — "do a full pull
    after creation (SHOULD)"
  - Drawbacks: **it fetches ciphertext + DEKs of unread values, so
    `var.read` gets recorded per variable (AUTH_SPEC §12-7). It
    collides with the audit discipline of "don't record as read what
    wasn't read" and contaminates the rotation-needed detection's
    (AUDIT_SPEC §4.1) "definitely fetched" rank**. If metadata-only is
    used to keep the audit clean, we're back to the current problem of
    the floor not committing (a circle)
- **Option 3-C: keep the status quo + make the operating guard
  (recommend a manual full pull) permanent. Leave detection to the M2
  checkpoint**
  - Drawback: the window right after env create = no checkpoint issued
    yet remains structurally. Against these notes' §11 line of "don't
    defer"

Old recommendation (2026-08-19 first version): option 3-A. Option 3-B's
collision with audit semantics is essential (unavoidable as long as a
full pull is automated), so it's weak. → Below is the generalization
subsuming 3-A.

#### Strictly-better option (reconsidered 2026-08-19)

**Option 3-D: redefine the floor as "the monotone join of verified
observations" (a generalization subsuming option 3-A)**

Option 3-A has the shape "add to the enumeration of triggers
(metadata-only pull · acceptance confirmation)", but as long as triggers
are enumerated, the same ruling recurs with every future new path
(lease · environment listing · the next feature). Replace the floor's
definition itself:

- Floor = **the monotone join (join-semilattice) of facts verified so
  far (chain head · environment-epoch observations · envMeta ·
  manifest · values)**. Not "a snapshot of the last successful pull"
- There is exactly one recording rule: **every fact that verified is
  joined. A value floor only for values actually verified** (no
  fabrication — same pair as option 3-A)
- For facts incomparable at the same coordinates (same version ·
  different hash) no join is defined = a typed conflict, evidenced as
  equivocation (floor rule (b) becomes the merge semantics itself)
- An epoch observation is joined not as a single lattice point but as
  **a typed 2-coordinate** (reflecting the 2026-08-19 pullfrog review —
  the original "maximum regardless of source" collides with CRYPTO_SPEC
  §6.3's norm "rule (c)'s reference must not be advanced by a chain
  sync alone (falsely rejecting legitimate un-re-encrypted values —
  this reference point is normative)", so it is retracted):
  - (i) **the pull reference of value rule (c)** — advanced **only** by
    observations established atomically with value-floor coverage. The
    norm is kept inside the join's definition as the coordinate's type
    (the premise "a variable absent from the floor = version-0
    equivalent" [atomicity of reference advancement and value-floor
    recording] doesn't break)
  - (ii) **the environment-level epoch observation** — used for the
    manifest rule (c) baseline · rollback / equivocation detection and
    joined regardless of source (this side has no path that falsely
    rejects a value)

What this solves at once:

- M1-A3: the facts of a metadata-only sync · env-create acceptance
  confirmation get joined (no need to enumerate triggers)
- M1-A4: "a self-issued manifest whose acceptance was confirmed via the
  on-chain commitment" is also a verified fact, so it is joined even
  when the command exits in error — the design question "at which point
  to commit" itself disappears
- M1-A5's merge semantics: the disk merge and the in-process merge
  become the same join operation, and the `>=`-later-wins duplicate
  implementation (the hotbed of the 3-path inconsistency the audit
  found) disappears structurally. An inter-process lock (atomicity of
  read-join-write) is still needed — the separation is: join owns
  "what gets written", the lock owns "writing it safely"
Cost: rewriting §6.3's floor section is larger than option 3-A's
addition. But the guaranteed content is identical to the composition
"option 3-A + M1-A4 / A5 fixes" — it invents no new guarantee (only a
generalization of the definition).

Revised recommendation (secondary): option 3-D becomes the spec's
shape, and the implementation moves toward join in stages, in the order
M1-A3 → A4 → A5. Strictly better than standalone 3-A in that it stops
the recurrence of future "should this operation write to the floor"
rulings.

#### Further consideration (2026-08-19 tertiary) — making the storage form append-only

The premise option 3-D leaves accepted: even once join's semantics is
fixed, as long as the storage form is "single-file read-modify-write",
the inter-process lock remains **on the critical path of evidence
preservation** (a lock-implementation bug = a recurrence point of
evidence loss). Break this:

**Option 3-E: make the storage form an append-only observation log +
a derived join**

- Replace the floor file from "a snapshot of the latest state (update =
  whole read · merge · write-back)" to "**an append-only log of
  verified observations (1 observation = 1 line)**", and **derive** the
  floor as the join of folding the log
- Appends use O_APPEND so offset races are eliminated, and per-line
  writes don't practically interleave on a local FS (a torn tail line is
  ignored by fold — self-healing). Observations of concurrent processes
  **both remain in the log** — 2 observations of same-coordinates ·
  different hashes surface at fold time as a typed conflict.
  **Evidence loss by overwriting goes from "forbidden" to
  "inexpressible"**
- Read-modify-write leaves the critical path. Under M1's operation no
  inter-process lock is needed at all (compaction is also done by
  **appending** a snapshot row; physical reclamation doesn't exist
  until M2 — the compaction policy below). Evidence only ever changes
  in the direction the log grows
- Consistency with precedent: the membership chain and the audit log
  are both append-only — this becomes the third instance of maruhi's
  existing pattern "a structure carrying evidence is append-only"
- Implementation-form choices: JSONL (readable · easy diagnosis ·
  transparency of non-confidential local state) is the first candidate;
  `bun:sqlite` (the CLI may use Bun-specific APIs — CLAUDE.md's ban is
  server-only. Zero added dependencies, and WAL provably solves
  concurrency) is the fallback if Windows append semantics become a
  problem

Final recommendation (tertiary): semantics = option 3-D (monotone
join), storage form = option 3-E (append-only log). The step up from
standalone 3-D is from "implement join correctly" to "make it
impossible to write anything but a join", and it removes M1-A5's root
cause (RMW races) without depending on lock correctness.

#### Quaternary consideration (2026-08-19) — the discipline of recording timing and compaction

Options considered and dismissed:

- Self-hash-chaining the log lines (detecting local tampering ·
  truncation): an attacker with local write permission can replace the
  CLI binary itself — outside the threat model (the floor is
  non-confidential local state) — dismissed as over-engineering
- Server-side custody · chaining of the floor: the former contradicts
  server distrust; the latter is exactly M2 (checkpoint) / M4 (gossip)'s
  domain — out of scope

The promotion adopted — breaking the premise 3-E leaves accepted,
"recording follows use":

**Option 3-E′: journal-before-release (WAL discipline)**

- Put into the spec the discipline that appending the observation
  (journal) **precedes the release of values · DEKs, the use of the
  floor check's pass determination, and the success report** — all of
  them
- A discipline that only becomes placeable because appending is cheap
  (3-E); it closes the "verified but crashed · interrupted before
  recording" window — the failure direction of a missed record is
  fixed to "too many observations remain" (the safe side)
- The current pull path is roughly this order (verify → floor →
  decrypt) but not codified as a discipline, and it doesn't hold on
  rotate · error-exit paths (M1-A4) — codification makes M1-A4's
  "where to commit" mechanically derivable from the discipline

Compaction policy (reflecting the 2026-08-19 pullfrog review —
checkpoint is only drafted in §6.2 and unimplemented, and these fixes
must not spread into M2, so M1's interim form is specified here):

- **M1's interim form = appending a snapshot row (never rewriting)**
  (reflecting the 2026-08-19 pullfrog review — the original
  "rewrite under the lock" form was retracted because, racing
  lock-free appends, it would silently erase observations that landed
  while compaction ran — breaking 3-E's central invariant with the
  very mechanism meant to protect it): when **the amount stacked after
  the latest snapshot row** (line count / byte count — not total file
  size. Reflecting the 2026-08-19 pullfrog review: since the whole log
  grows monotonically, a total-size criterion once exceeded holds
  forever and a snapshot would be stacked on every floor write. The
  relative amount returns to 0 at each snapshot, so the trigger
  re-arms) exceeds a threshold, **append to the log a snapshot row**
  carrying "the current fold result + the end position of the prefix
  one folded". A fold is "the latest snapshot row's state ⊔ every row
  after its end position" — bounding fold cost is carried by this very
  relative criterion (the un-folded remainder after a snapshot is
  always below the threshold). By join's idempotence · commutativity,
  when position info is absent / corrupt, falling back to a full fold
  changes only cost, not correctness. **The evidence rows of a
  same-coordinate conflict remain as evidence in the fold result**
  (folding them into a snapshot doesn't erase them)
- **Serialization rule (unique): M1's log is append-only**. Ordinary
  observation appends and snapshot appends are both O_APPEND only (no
  lock needed — 2 concurrent snapshots are harmless: fold uses the
  latest one, and join's idempotence makes double-folding correct too).
  **Physical reclamation of file size is not done in M1** — rewriting /
  truncation fundamentally race lock-free appends (even taking an
  exclusive lock, appenders not participating makes it ineffective),
  so it's excluded from M1's mechanism. Fold cost is bounded by
  snapshot rows; file-size growth is tolerated until M2 given the
  scale (below). Physical reclamation is designed together with M2's
  checkpoint-reference migration, including append-side shared-lock
  participation
- **After M2 arrives**: migrate the reference to "observations at or
  below a verified checkpoint", connecting the local log's growth to a
  reference the chain keeps permanently
- Scale: a floor is 1 log per project with 1 observation ≈ a few
  lines, so the interim form is amply bounded in practice

**Final recommendation (settled): semantics = 3-D, storage form = 3-E,
recording discipline = 3-E′, compaction = M1 uses the
threshold-triggered snapshot-row form and migrates to
checkpoint-reference linkage once M2 arrives**. The quaternary
confirmed no structural change is needed — the residual (floorlessness
of first-time clients · disposable CI) is, per the design, M2 / M4's
domain.

**The re-reading if 3-E is adopted (uniquifying the implementation
brief — reflecting the 2026-08-19 pullfrog review)**: §3 M1-A5's fix
proposals 1 / 2 / 6 (read-modify-write under an inter-process lock ·
the ban on fail-open on lock failure) and the pinned test "recovery
after the lock-holding process exits abnormally" are **replaced by the
append + fold premise** — in M1 no inter-process lock exists at all
(appends only. Compaction is also a snapshot-row append; physical
reclamation is an M2 design matter). The fail-open concern also
disappears: since an append loses no evidence, no state equivalent to
"failing open to floorless" arises. §3's same-coordinate typed
conflict (proposals 3 / 4) and re-checking (proposal 5) live on
as-is as fold-side rules. §6 PR-F2's split 3 is re-read as "making the
floor storage form append-only + fold". Only if 3-E is NOT adopted do
§3's descriptions live verbatim.

### Confirmed as needing no ruling

- M1-A1: CRYPTO_SPEC §4.3 verification rule (1) already requires "prev
  chaining (when a floor exists)" — conformance implementation
- Of M1-A6, making non-composite meta operations strict-at-head:
  conformance implementation of AUTH_SPEC §12-5 (4) (see the ruling-2
  note above)
- M1-A4 / A5 / B1 / B2 / T1 / T2: within the scope of CLI
  implementation · tests. A5's rejection of same-coordinate mismatches
  is exactly what floor rule (b) (same version · different hash = fork
  evidence) requires — not a semantics change

## 8. Operating guards until the fixes land

Things to honor before the code is fixed:

1. **Do not run a new CLI's create / `--init-manifest` against an old
   server**
2. Update order: server → init every environment → CI / CLI
3. Do not run multiple CLIs concurrently against the same project
4. After env create / first-variable creation, do a full pull to
   establish the floor (this is a mitigation under honest-server
   operation, not a substitute for the code fix)
5. If a rotate reports response loss · a post-accept failure, verify
   state after connectivity returns with a full pull and a re-run
6. Do not initialize manifestVersion 1 via the non-composite API. Use
   only the documented `env rotate --init-manifest`
## 9. Definition of Done

Completion conditions of the fix group:

- Each pinned test of M1-A1 through A6 exists
- M1-B1 / B2 are pinned by API / CLI tests
- The CLI actually verifies legacy init's DEK commitment
- A PR that changed crypto vectors passes on Node / Bun / workerd /
  Browser all
- No regression in server's every meta-operation API:
  - create / rename / delete variable
  - rename environment
  - create / rotate composite
  - environment delete cascade
- Manifest verification at the same level on metadata-only / value pull /
  lease (the level's scope = signature · digest · epoch consistency ·
  missing rejection. Prev chaining only on floor-holding paths —
  consistent with M1-A1's lease-exemption note)
- A real 2-process floor test passes
- Ruling 1's tests are split per target server configuration (reflecting
  the 2026-08-19 pullfrog review):
  - A strict-introduced server: rejects a composite payload containing
    an unknown field at the decode stage (the strict-rejection test)
  - A pre-strict old server: post-acceptance reconciliation detects "a
    manifest that wasn't stored" and the CLI fails without advancing the
    floor (the post-acceptance-reconciliation test. Preventing the
    inconsistent state itself is carried by §8 operating guards 1 / 2 and
    session-28 §2-2's update order — since under 1-C detection happens
    post-append on rotate)
- `bun run check` fully green
- Crypto changes carry a human review

## 10. Instructions for starting the separate chat

In the separate chat, first read these notes plus:

- `docs/notes/session-27.md` §5-1 / §13-2 / §13-5 / §14 / §16
- `docs/notes/session-28.md`
- `docs/CRYPTO_SPEC.md` §4.3 / §6.3 / §6.4
- `docs/AUTH_SPEC.md` §12-2 / §12-4 / §12-5 / §12-7 / §12-8
- These notes `docs/notes/session-31.md`

The opening request text:

> Read session-31's PR-M1 post-merge audit and fix following the
> recommended split. First make the reproduction tests of the target
> findings fail. For the §7 ruling subjects (strict acceptance +
> promoting the definition of success / the composite binding [the owner
> picks from the 2-F · 2-E · 2-D ladder — note 2-F in particular involves
> a chain re-genesis] / the floor's monotone join + append-only storage
> form + journal-before-release), draft the spec revision first based on
> each ruling's **final recommendation (settled)**, obtain the owner's
> ruling via the Status line and the PR body's "rulings needed", and only
> then implement. `packages/crypto` changes are vectors-first and require
> human review. Don't spread into adjacent cleanup or M2–M4.

## 11. The boundary against known non-guarantees

Not fix targets of these notes:

- An internally consistent old view to a floorless first-time client
- The absence of a persistent floor on disposable CI
- The chain head's own freshness
- Predecessor-existence matching at a manifestVersion gap > 1

These are recorded in session-27 / session-28 and are M2 (checkpoint) /
M4 (gossip)'s job.

However, the following are not deferred to M2 / M4:

- Not checking prev when the floor predecessor of an adjacent version is
  already known
- Not recording to the floor a manifest one got accepted
- A concurrent floor commit erasing known evidence
- An old server silently dropping manifest
- The H+1 exception not binding issuer to the H+1 entry actor
