# Session 37 notes (PR-M4 implementation — head declarations / gossip = making split views detectable)

Date: 2026-08-28. Target: session-27 §14's PR-M4 (the final piece of the
implementation split — independent of M1–M3). Prerequisites: PR-M1, PR-F1–F4,
PR-M2 (#99), PR-M3 (#100) merged. This PR implements CRYPTO_SPEC §6.6 (head
declarations), §6.3 head gossip, §6.4 acceptance / distribution, and
AUTH_SPEC §16-1 in the layer order "vectors first → crypto → api-schema →
server → CLI". The ruling process followed the goal's instruction "multiple
options → strictly-better search → 3 rounds of comparison → autonomous
choice". Ruling letters continue from session-36's R–W (X onward). Judged
that no spec-body revision is needed (PR-M4 is implementation-following of the
Wave 3 D approved wording [PR #80/#81]) — no point requiring a minimal spec
addition was found (adopted §16-1's drafted 60/hour as-is).

## 1. Ruling X: the submission trigger's implementation location (which sync path to wire into)

### Round 1

- **Option X-a: submit on every successful sync inside syncProject
  (sync.ts)** — rejected: syncProject shares its implementation with lease's
  bundled-chain verification (verifyChainSnapshot) and completes **before**
  floor checks and matching. Submission happens "after chain sync +
  verification succeed" (§6.3); declaring a view that hasn't passed floor
  checks, anchor matching, or gossip matching would leave your signature on a
  view that's interrupted on hard evidence right after. Also, the signing key
  is outside sync.ts's concern (don't bring keys into a verification-only
  module)
- **Option X-b: wire into the pre-command attachProject (context.ts)** —
  attachProject is the single sync point shared by all data commands (the
  unified point for floor / anchor / intent matching — the existing
  discipline that "splitting into 2 lineages means they'll silently diverge"),
  so only the final view that passed every floor check and match can be
  declared. The signing key is passed by openProjectWith from the master key
  (the attester argument — the keyless pre-stage openMetadataProjectWith
  doesn't pass it = match only)

### Round 2 (strictly-better search)

- **Option X-c: X-b + additional submissions on every pull / push success** —
  rejected: since the pre-stage syncs on every command, additionally wiring
  into in-command re-syncs (CAS retries etc.) only raises submission frequency
  without adding detectability (declaration granularity is "a sync's reached
  point"; 1 declaration per command suffices). It also wastefully consumes
  the rate window (60/hour)

### Round 3 (re-inspection)

- Consistency of metadata-only pre-stages (env diff, invite family) not
  submitting: submission is a SHOULD, and the line that doesn't break
  MARUHI_TOKEN execution (no keychain) for the sake of submission takes
  precedence. Matching (the detection side) needs no key and runs on both
  pre-stages — the "detection on all paths, submission only on key-holding
  paths" asymmetry is a consequence of §6.6's semantics (declarations require
  a signature)
- `project verify` doesn't pass through attachProject (openSession + direct
  sync), so matching is wired separately (verify is the verification command
  itself — without gossip matching you'd get the inconsistency "verify passes
  but pull aborts"). It does not submit (keeping the line that read commands
  don't require the master key)
- ci run (the lease path) stays non-participating (§6.6 / §14-2 — the lease
  response doesn't bundle declarations. The goal's pinned condition)

**Choice: option X-b + a matching connection for project verify**.

## 2. Ruling Y: how "previous declaration" is tracked (whether a floor record is needed)

### Round 1

- **Option Y-a: add a new record kind (attested) to the floor log and derive
  via fold** — rejected: the floor's lattice is "a monotonic join of verified
  observations" (§6.3), and your own submission record isn't an observation
  (the verified head itself is already joined by the head record — double
  recording). Also, an old CLI warns on unknown record kinds as torn lines,
  so a downgrade would create permanent warning noise (and unlike an intent
  it carries no "must-match obligation" — declaration is a SHOULD with no
  submission-evidence duty)
- **Option Y-b: a mutable JSON outside the lattice
  (<projectId>.attested.json)** — tracking only suppresses duplicate
  submissions and carries no safety: the consequence of loss / corruption is
  "re-submitting the same seq", absorbed by the server's idempotent 204
  (§16-1). Mis-submission from a regressed self view is governed by the
  server's seq-monotonic check (409) as the authority — local tracking is
  never the authority. A tmp → rename replace-write (readers never see a
  partial write) suffices

### Round 2 (strictly-better search)

- **Option Y-c: no tracking (submit every time)** — rejected: re-submitting
  the same head is idempotent server-side, but the SHOULD's trigger is "when
  it advanced" (§6.3), and unconditional per-command submission could drain
  the rate window (60/hour) under interactive continuous runs (just 60 pulls
  exhausts the window and a genuinely advanced declaration hits 429). No
  reason to accept a degradation a single tracking file avoids

### Round 3 (re-inspection)

- Consistency with the verified-observation join (the goal's point):
  attested.json is never an input to the join (fold doesn't read it).
  Confirmed that divergence between the floor's chainHead and the attested
  head doesn't affect detection rules (the former is detection material; the
  latter is submission suppression only)

**Choice: option Y-b** (add loadAttestedHead / saveAttestedHead to the
FloorStore service — located in the same non-secret local-state directory as
the floor).

## 3. Ruling Z: the evidence-storage format for contradicting declarations

### Round 1

- **Option Z-a: join as a chain-head observation in the floor log (turning it
  into a conflict)** — rejected: a declaration is "another member's signed
  claim", not your own §6.3 verified observation. Putting it on the lattice
  merges it into floor-conflict semantics (a contradiction between 2
  observations you verified = permanent rejection of all commands), becoming
  a DoS surface where **one leaked member key (or an insider gone attacker)
  permanently halts every other member's CLI with a single fake-head
  declaration**. What §6.6's matching (a) asks for is "stop using that
  sync's artifacts + preserve evidence", not permanent rejection (as long as
  the contradicting declaration keeps being distributed, every sync aborts —
  the distribution itself carries detection continuity)
- **Option Z-b: a dedicated append-only JSONL
  (<projectId>.attestation-evidence.jsonl)** — each record appends: the full
  declaration (signature included — the substance of non-repudiation) + the
  self view's chain digest (headSeq / headHash / the entry hash at the
  declared seq position) + detection kind (head-mismatch /
  unresolved-after-resync) + local detection time. Same physical discipline
  as the floor log (O_APPEND, newline-first, datasync, 0600)

### Round 2 (strictly-better search)

- **Option Z-c: Z-b + a reference record in the floor log** — rejected: no
  consumer of the reference exists (fold doesn't read the evidence file).
  Only adds a new invariant of keeping 2 files consistent

### Round 3 (re-inspection)

- Even when evidence saving itself fails (disk unavailable), the abort and
  warning still happen (saving is extra preservation; detection must not
  depend on savability). Since the warning text contains all evidence
  material (the declaration, signature, both hashes), preserving just the
  output suffices for third-party presentation
- The floor-evidence format (the goal's specification) is satisfied by
  placing the formatting function formatAttestationEvidence in
  floor-evidence.ts (joining the existing evidence-display discipline:
  coordinates + both sides' signed material + preservation guidance)

**Choice: option Z-b**.

## 4. Ruling AA: the bounded shape of (b)'s re-sync (sharing an existing mechanism)

### Rounds 1–3 (summary)

- Share the existing resyncExtended as-is (option AA-a) (sync.ts — §6.3-2b /
  session-14 ruling G's one re-sync + extension checks). A dedicated retry
  loop (option AA-b — N times with backoff) is rejected: align with the
  established semantics of value signatures' and floor heads' future branches
  ("if it doesn't resolve in one shot, it's evidence"), and don't create a
  surface where a malicious server stretches re-syncs with future declarations
- The match target after re-sync is the union of "the new view's own
  declaration set + the unresolved future declarations": matching only the
  new set would let omission (distributing a future declaration, then
  removing it from distribution) dodge the "unresolved → (a)" judgment.
  Carrying the original declarations over and re-verifying them on the new
  view always settles each into either resolved-on-extension (hash match) or
  evidence (mismatch / still future). The new view's declaration set is also
  matched to keep the invariant "a view in use is matched" (no second
  re-sync — bounded)

**Choice: sharing resyncExtended + union re-matching (cut off after one)**.

## 5. Ruling AB: the range of paths that perform matching

### Rounds 1–3 (summary)

- The target is "every path that receives a chain-fetch response (§16-1's
  distribution surface)" = attachProject (the pre-stage of all data
  commands — ruling X) and project verify. In-command re-syncs (CAS retries
  using resyncExtended etc.) do not match (option AB-b's match-all-resyncs is
  rejected): a re-sync is "an extension-checked fetch of a view already
  matched at the pre-stage", and that response's declaration set is matched
  by the next command's pre-stage. Placing it at the single pre-stage point
  structurally preserves "the order of matching vs view adoption" (only
  matched views get used)
- lease (ci run) stays non-participating per spec (the response carries no
  declarations — what verifyChainSnapshot receives is always empty, so no
  missing-rejection branch exists)
- Declarations that fail verification and declarations whose attester isn't a
  current member are silently excluded from matching (§6.6 — eliminating a
  warning-triggering DoS via fake declarations. No logging either: don't
  leave a surface where a malicious server injects invalid declarations to
  create warning noise)

**Choice: 2 points — attachProject + project verify (= every chain-fetch
path)**.

## 6. Ruling AC: whether §12-10 (3) (effect confirmation) applies to submission

### Rounds 1–3 (summary)

- Not applied (option AC-a). §12-10 (3)'s effect confirmation defines success
  for mutations "whose effect is confirmable in a verifiable distributed
  artifact", but declaration distribution is a **normative non-guarantee**
  the server may selectively omit (§6.3 — omission = G8); making "my
  declaration appears in the next chain fetch's attestations" the definition
  of success would create a confirmation duty that can't distinguish honest
  omission / other members not yet synced from malicious omission (a check
  that can always fail where failure means nothing). Declarations are a
  SHOULD-level advisory and don't fall under the "mutations whose effect
  grounds a guarantee" that §12-10 (3)'s target enumeration (chain appends,
  composites, meta ops) protects — they sit on the same side as this
  section's own line that excluded value pushes (mutations without
  confirmation material, or where it means nothing, are out of scope)
- strict acceptance (§12-10 (1)) applies (the goal's pinned condition —
  already added to the enumeration). The submission's failure direction is
  fail-closed (old server 404 / mixed old-new 400) + one line of non-failing
  warning (don't silently swallow — the goal's ruling frame)

**Choice: (3) doesn't apply, (1) does**. No intent record either (§6.3
recording discipline (ii)) — an intent is a mechanism bundled with the
effect-confirmation duty; stacking an unresolved intent on a mutation you
don't confirm would leave a permanent "needs matching" surface.

## 7. Ruling AD: the implementation shape of server acceptance verification

### Rounds 1–3 (summary)

- Rather than implementing §6.4's acceptance enumeration separately (option
  AD-a — caller = attester, signature verification under a current-member sig
  key, declared-head consistency with own chain, seq monotonicity), apply the
  client-identical verifyDistributedHeadAttestation to the acceptance-time
  history index (option AD-b — following the shape verify-value.ts
  established in §12-5). The consequence: the "membership and key binding as
  of the declared head (inclusive)" check (the second half of §6.6 client
  verification (1), and (2)) is added to the acceptance surface too — this is
  a strictly-better superset of the spec's enumeration: a distributed
  declaration should always pass §6.6 client verification (§6.4's two wheels
  — the server doesn't store data all clients would reject), and an honest
  client's declaration (a head it synced and verified as a member can only be
  at positions after its own add) always satisfies it, so there's no
  deviation toward rejecting legitimate submissions
- Reason-code folding is identical to value signatures (3 vocabulary items —
  no new reason codes). chain-head-future maps to chain-head-unknown on the
  server (the server has no re-sync branch — same mapping as
  VALUE_REJECT_REASONS)

**Choice: option AD-b (don't implement a verification mechanism twice)**.

## 8. Ruling AE: the rate window's position / granularity / consumption discipline

### Rounds 1–3 (summary)

- Position: after the membership check (404), before signature verification.
  The former follows §11-2 (429 must not leak existence to non-members — the
  same argument as the lease window's "behind authorization"); the latter
  bounds Ed25519 verification work by rate (repeated rejected submissions
  also consume the window — unlike the lease where consumption is limited to
  successful acceptance, the resource the declaration window protects is the
  verification computation itself)
- Granularity is per member (per §16-1's wording). Rows are bounded by member
  count, and remove_member acceptance deletes the window row together with
  the declaration rows (storage convergence)
- Idempotent 204 (re-submitting the same seq) also consumes the window:
  exempting "same seq" would let verification-passing resends pierce the
  window. An honest client doesn't re-submit the same head thanks to tracking
  (ruling Y), so the real cost closes at 1 hit on tracking loss

**Choice: as above (adopted the drafted 60/hour as-is — adjustment is for PR
review)**.

## 9. Summary of what was implemented

- **test-vectors** (advance commit f5abc69): head-attestation.json — 3
  positives (basic / reader / removed-attester-in-tenure [pins the intent
  that verification passes but it's excluded from distribution]) + 6
  signature-family negatives + 3 verification-rule negatives (the 2-way
  distinction of chain-head-mismatch / chain-head-future, and a membership
  boundary). Confirmed byte-identical reproduction of existing vectors on a
  full generator re-run (additions only). Recorded as README convention 23
- **crypto**: head-attestation.ts — §2.1 LP + domain-separated signed_bytes,
  Ed25519 sign / raw verify, history-based verifyDistributedHeadAttestation
  (validate.ts's shared core — the same check order as value / meta).
  Current-member selection is intentionally the caller's job (consistent with
  the removed-attester positive). 4-runtime harness all PASS
- **api-schema / core**: PUT /projects/:projectId/head-attestation (204,
  strict §12-10 (1)), AttestationRegression (409 + storedSeq) /
  AttestationRejected (422, 3 reasons) / AttestationRateLimited (429),
  attestations added to the chain-fetch response via optionalKey (absence is
  not rejected)
- **server**: attestation-accept.ts (the acceptance row of rulings AD/AE) +
  DO migrations for head_attestations / attestation_windows + row deletion as
  a remove_member acceptance side effect (chain-accept.ts — same shape as old
  key-wrap cleanup) + current-member narrowing on the distribution side (an
  independent defense layer). Acceptance time is stored but not distributed
  (the distributed material's type doesn't carry it)
- **CLI**: attestation.ts (matching + submission — rulings X/Y/Z/AA/AB),
  attestations carriage in sync.ts (unverified), the tracking / evidence
  stores in floor.ts / floor-log.ts, wiring into attachProject / project
  verify
- **docs**: SELF_HOSTING.md gained the update order (new CLI × old server =
  submission is a non-failing warning, missing attestations = treated as
  empty and not rejected)

## 10. What the tests pin (summary — session-27 §13-5's declaration items)

- crypto (4 runtimes): all vectors (deterministic re-signing of positives,
  distribution verification, reason codes of negatives) + current-member
  selection material for removed attester + invalid-input boundaries
- Server (vitest-pool-workers): a reader submitting with read scope +
  distributed attester info + acceptance time not distributed (pinned by the
  wire's key set) / monotonic acceptance (advancing upsert, idempotent 204,
  regression 409 + storedSeq) / verification rejections (broken signature,
  unknown head, future) / structural enforcement of caller = attester /
  non-member & uninitialized 404 / per-member rate window 429 (independent
  across members) / row deletion on remove + disappearance from distribution
  / strict acceptance (unknown field 400 — strict-payload.test.ts)
- CLI: selection (fake signature, outside history, non-current-member,
  in-tenure past declaration by a removed member) / matching's 2-way
  distinction ((a) immediate evidence, (b) resolved-by-resync, (b) unresolved
  = evidence) / evidence JSONL's content (declaration + self-view digest) /
  abort via runCli(project verify) / submission triggers (only on advance —
  tracking persistence) / non-failing warning on submission failure (old
  server 404) / distinct warning on 409

## 11. PR #101 review response (pre-merge addendum)

- **pullfrog**: (1) changed submission suppression from seq-only to head
  identity (seq + hash) — don't close the declaration path on same-seq
  different-hash equivocation under floor fail-open. (2) introduced
  deduplication in the re-match union, keyed on all 6 wire fields — with a
  partial key a malicious server could rewrite just 1 field of a record and
  make the carried-over one (first.future) be dropped on a key collision,
  nullifying ruling AA's omission-bypass closure (the forged side falls into
  the silent skip of signature verification, leaving no trace)
- **Cursor Security Agent (HIGH)**: floor-head advancement was inside
  loadCheckedFloor (before gossip matching), so a view aborted on hard
  evidence had its head recorded permanently in the floor. Once a rejected
  fork becomes the floor, every subsequent honest chain is permanently
  rejected on floor hash mismatch (a detected equivocation converts into a
  wedge). Fix: moved floor advancement from loadCheckedFloor to the end of
  reconcileGossip (after all floor / anchor / gossip checks pass), and
  unified project verify to go through the same reconcileGossip. Pinned by
  command-level tests that the floor doesn't advance on abort and advances as
  before on success
