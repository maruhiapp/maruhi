# Session 32 notes (spec drafting of session-31 ruling 1 and proving the strict acceptance path)

Date: 2026-08-19. Target: spec drafting of ruling 1 among the 3 owner rulings in
session-31 (post-PR-M1-merge audit) §7. Format: spec revision + record of technical verification.
Implementation (PR-F1–F4) happens in a separate PR after spec approval.

## 1. What this PR drafted (ruling 1 = session-31's final recommendation adopted as-is)

- AUTH_SPEC §12-10: strictness of security-critical acceptance schemas (1-E) /
  design norms for wire-incompatible changes / the definition of mutation success (1-E′)
- CRYPTO_SPEC §1 principle 6: semantics live inside the signed byte string (codifying the
  existing architecture; the remainder = noting that the accepting side's verification-mode
  choice follows ruling 2's outcome)

Ruling 2 (the H+1 exception — the 2-F / 2-E / 2-D ladder) and ruling 3 (floor — 3-D + 3-E + 3-E′)
are not in this PR. Ruling 2's one-time cost (2-F = re-genesis + full data-layer rebuild) can only
be accepted by the owner, and ruling 3's §6.3 floor-section rewrite entangles wording with ruling
2's outcome (under 2-F the floor's manifest record material becomes chain-derived — session-31 §7
ruling 1 round-4 synergy), so both are drafted together after the rulings are finalized.

## 2. Proof of the strict-acceptance implementation path (what session-31 called "PR-F1's first task")

Environment: effect rc.109 (the repo's strict pin). Verification scripts are throwaway
(not committed).

### 2-1. Conclusion: reachable with schema AST annotations alone (no HttpApiBuilder changes needed)

session-31 expected that one of an endpoint-definition option, a manual decode layer, or an
upstream change would be needed, because "`onExcessProperty` is a `ParseOptions` of the decode
call, not a schema annotation, and the current `HttpApiBuilder` builds the payload decoder
without ParseOptions". Measurement found that **a 4th path exists — baking it into the schema
itself — and that alone suffices**:

- `SchemaParser.makeParser` (dist/SchemaParser.js) reads the AST annotation
  `annotations["parseOptions"]` and merges it at parse time via
  `mergeParseOptions(options, astOptions)`
- The merge has **AST annotations winning over caller ParseOptions** (the 2nd argument is
  last-wins). Even though HttpApiBuilder decodes with no options — and even if a future
  implementation passed looser options — strict baked into the schema is preserved

### 2-2. Measured results (bun + effect rc.109)

For `Schema.Struct({...}).annotate({ parseOptions: { onExcessProperty: "error" } })`,
with the same assembly as HttpApiBuilder (`Schema.decodeUnknownEffect(Schema.Union([schema]))`,
no options):

| Case | Result |
|---|---|
| Bare Struct + unknown field | silently stripped, succeeds (reproduces M1-A2's default behavior) |
| Annotated + unknown field | rejected with `Expected no excess property at ["manifest"]` |
| Annotated + normal input | succeeds |
| Annotation on parent only + unknown field in a nest | rejected (**propagates to children**) |
| Annotated + caller explicitly passes `onExcessProperty: "ignore"` | rejected (**the annotation wins**) |
| Through a `Schema.Union` wrap (isomorphic to HttpApiBuilder's real path) | rejected |

### 2-3. Implications for PR-F1 implementation

- The application point is only the security-critical payload schemas in `packages/api-schema`
  (one top-level annotation covers all nesting). A single shared wrapper (e.g.
  `strictPayload(...)`) makes it a single implementation point
- No HttpApiBuilder fork, manual decode layer, or upstream issue needed.
  Reflected in AUTH_SPEC §12-10 (1)'s implementation note
- The error surfaces as an existing Schema validation error (400) (via HttpApiSchemaError)
  — adds no new error surface
- **Application-order constraint (2026-08-19 pullfrog review finding — confirmed by measurement)**:
  `SchemaParser.makeParser` reads `parseOptions` from **the last check's annotations** when the
  AST has checks (dist/SchemaParser.js:892). `SchemaAST.annotate` likewise attaches the annotation
  to the last check when checks exist, so **composing `.check(...)` after the annotation silently
  loses strictness** (measured on rc.109: annotate only → rejects / check → annotate → rejects /
  annotate → check → **accepts; unknown fields silently stripped**).
  Since a fail-closed mechanism's failure is silent, PR-F1 adopts:
  (1) a convention that `strictPayload(...)` is **applied last** (only draped over a schema whose
  checks are all done), and
  (2) for every covered endpoint, an acceptance-path test pinning that "an unknown field is
  actually rejected with 400" (test the effectiveness of rejection, not the presence of the
  annotation — catches both application-order bugs and upstream changes to the read location)

## 3. Awaiting-ruling state (for the owner)

- Ruling 1: merging this PR = approval
- Ruling 2: **2026-08-19 owner ruling = option 2-G′** (ladder history: 2-H added in §4-2
  round 5 → 2-G′ revived and recommended in §5-1 round 6). Spec revisions already drafted in this
  PR (CRYPTO_SPEC §4.3 / §6.2 / §6.3 / §6.4, AUTH_SPEC §12-4) — merge = approval of the spec wording
- Ruling 3: **2026-08-19 owner ruling = 3-D + 3-E + 3-E′ + 3-F** (compaction is the M1
  snapshot-record method). Spec revisions already drafted in this PR (CRYPTO_SPEC §6.3 local-floor
  section) — merge = approval of the spec wording

## 4. Upward-compatible exploration of rulings 2 & 3 (2026-08-19 round 5 — owner request)

Re-checked whether any further upward-compatible option exists against session-31 §7's final
recommendations.

### 4-1. Options considered and rejected (ruling 2)

- **Option 2-G: atomically bundle the `checkpoint` op (§6.2 — already drafted, unimplemented) into
  the composite**: the idea of realizing 2-F's "the chain carries the manifest hash" by reusing an
  already-drafted op, through consensus-rule **addition only** (existing op payloads unchanged =
  no re-genesis). Rejection rationale: the checkpoint payload must carry values_digest_hex, and
  acceptance verification (§6.4) requires matching against server-stored state at acceptance time,
  so the issuer needs the latest value-level view (variable_id / version / value_sig_hash).
  metadata-only pull doesn't carry it (AUTH_SPEC §12-7 — confirmed by measurement), so a full pull
  is required, and every rotate / create records a `var.read` per variable — audit pollution, the
  same circularity as option 3-B's rejection ground (**→ this rejection rationale was wrong.
  Corrected in §5-1 and revived as option 2-G′**)
- **Option 2-I: allow checkpoint's values_digest to be empty (manifest-only checkpoint)**: §6.3
  checkpoint-consistency rule 2 holds invariant "reject a value-bearing distribution for an
  environment that has a reference checkpoint when the snapshot enumeration is missing" (the line
  hardened in the 2026-08-18 pullfrog review). A checkpoint without value notarization introduces a
  third state of "reference present, enumeration absent", giving an attacker a selectable rule-2
  skip path. Rejected

### 4-2. Option 2-H: atomic composite bundling of a dedicated anchor op (2-F's strength without re-genesis)

**Idea: 2-F's cost originates in "changing existing op (create / rotate) payloads", so carrying the
binding via "adding a new op" makes it additive** (reusing the shape the checkpoint op noted as its
advantage in §6.2: "doesn't touch existing op payloads").

- New op `anchor_manifest` (name fixed at drafting time): payload =
  `LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex)` —
  the same shape as a checkpoint environment entry minus values_digest. It belongs to the class
  "the chain carries a hash; content verification is the data layer's job" (rides the §6.2
  precedent)
- A composite (create / rotate) **atomically appends 2 entries in one request: H+1 = create /
  rotate, H+2 = anchor_manifest** (a single DO transaction — partial acceptance is structurally
  impossible)
- Consensus rules (all confined to the new op = no effect on existing chains):
  (i) adjacency rule — an anchor is valid only when the immediately preceding entry is a create /
  rotate of the same environment by the same actor (eliminates standalone anchors),
  (ii) epoch strictly equals the current epoch at entry time (before applying the entry itself)
  (same shape as checkpoint). **At H+2, H+1 is already applied, so new_epoch matches strictly —
  the anchor itself needs no H+1 exception**,
  (iii) manifest_version monotonic increase — greater than any prior anchor's value for the same
  environment (same shape as checkpoint-regression; verifiable from the payload's public values
  alone). This makes at most one anchor per (environment_id, manifest_version) on a valid chain,
  making the verification rule's match target deterministic
- Manifest verification (**not a disjunction — reflecting the 2026-08-19 pullfrog review**.
  The original "strict OR anchor match" shape leaves the strict path alive even when an anchor
  exists, so the same issuer could bake a declared head of H+2 or later into a different-content
  manifest at the same (environment_id, epoch, manifest_version) and pass on the strict side,
  erasing the equivocation advantage):
  1. If an anchor for the (environment_id, manifest_version) **exists on the verified chain, an
     exact manifest_sig_hash match is a MUST** (strict is not an alternative path in that case).
     epoch must also match the anchor's value
  2. strict (epoch = current epoch at the declared head) applies only when no anchor exists
  3. A distributed manifest's manifest_version must be **at least the latest anchor's value** for
     that environment on the verified chain, and its epoch at least that anchor's epoch
     (chain-derived floor. Since manifestVersion is monotonic across epochs — §12-5 CAS — every
     version before the boundary falls below the latest anchor's value, so no false positives on
     legitimate distributions)
  - No actor = issuer rule needed (same argument as 2-F: speculative piggybacking can't predict the
    hash; after-the-fact piggybacking finds its own manifest's hash absent from the anchor). Note
    that if 2-F is taken instead, session-31 §7's rule text ("the exception is ... only when") is
    the same disjunctive shape, so at drafting time rewrite it into this MUST form (the
    manifest_version corresponding to a create / rotate whose entry carries the manifest hash
    must match that hash)
- Preserves all of 2-F's ripple effects: the chain anchor at issuance at epoch boundaries,
  M1-A4 (acceptance confirmation = floor-commit material complete with just a chain sync), M1-A3
  (the floor's manifest record right after env create is established chain-derived), 1-E′
  (composite success confirmation completes within a chain sync)
- **Detection difference vs 2-E (narrowed in 2026-08-19 pullfrog review round 2 — the original
  "equivocation detectable by all clients" was an overclaim)**: anchors only cover boundary
  (create / rotate composite) versions; later in-epoch versions (per-meta-operation
  manifestVersion = latest + 1 — AUTH_SPEC §12-5) remain structurally unanchored and fall to
  rule 2 (strict). So what 2-H / 2-F newly close over 2-E shrinks, in headline terms, to
  **(i) equivocation of anchored versions (= boundary manifests)**. Cross-boundary rollback is
  counted in separated layers (reflecting the 2026-08-19 pullfrog review's self-correction):
  **the shape that rewinds the chain itself** is always an epoch regression (monotonicity
  argument), and the floorless class already drops it via the existing repository-anchor
  acceptance rule (§6.3 out-of-band anchor (b) — chain-derived environment epoch ≥ anchor), so it
  doesn't count in the diff. On the other hand, **the shape that keeps the chain current but
  pairs and distributes only a legitimate pre-boundary manifest (declared head = old, epoch = old)**
  passes existing rules because manifest epoch consistency is a match against declared-head time,
  head binding doesn't require recency, and the anchor rule binds the chain layer — 3 points.
  Checkpoint-consistency criteria are **chain-derived** (§6.3 — they reach the floorless class
  independent of the floor), so once a post-boundary reference is pinned, rule 1 drops this shape —
  rule 3 is the sole defense only during **the window until a reference is pinned** (always-on
  while M2 is unimplemented; after implementation still limited to the interval rotate →
  re-encrypt → checkpoint issue — the issuance SHOULD (i)) (the manifest layer's floor and the
  chain layer's anchor rule bind different things — that character doesn't change).
  Rule 3's value lies in this **(a) manifest-layer rollback floor** (it also blocks downward
  circumvention of the anchored-version match [rule 1]) and **(b) supplying a boundary-immediate
  reference against M2 checkpoints' periodic non-regression coverage**. **Forward injection
  claiming an unanchored version beyond the latest anchor is the issuer's legitimate issuance
  capability itself and remains under every option** (the same class as the non-guarantee already
  recorded in CRYPTO_SPEC §14.3-5 residual (i)). For a class holding neither floor nor out-of-band
  anchor, rule 3 is powerless too (the range §14.3-3 records as fundamentally impossible).
  A client with a floor can achieve equivalent detection under 2-E via §6.3 floor rule (b), and in
  environments where a checkpoint reference (chain-derived — independent of floor presence) is
  pinned, via consistency rule 1. Requiring the manifest's prev chain (prevManifestSigHashHex) to
  reach the latest anchor could transitively bind unanchored versions too, but the server retains
  only the latest 1 copy (§12-5) and intermediate versions aren't distributed, so it would require
  revising retention/distribution rules — not counted in 2-H's cost and not taken in this
  exploration (2-H's point is not the detection difference but "2-F's strength without re-genesis";
  the ladder ranking is unchanged even after this narrowing)
- **The cost is additive**: existing chains stay valid under the new rule (old entries contain no
  new op) → **no re-genesis, no data-layer rebuild**. chain-entries.json is addition-only (no
  regeneration of existing vectors / expected_head_states). The manifest wire format is unchanged
  → env-manifest.json only adds negatives. Migration = one rotate / meta operation per environment
  (same level as 2-E). The crypto human review is also satisfied by additive vectors (2-F needs a
  full-regeneration review)
- Points where 2-F permanently wins (honest diff): one fewer op, no adjacency rule needed, 1 entry
  per epoch boundary. 2-H pays these 3 as permanent costs in exchange for erasing the one-time cost
  (full data-layer rebuild)
- **Update ordering (reflecting the 2026-08-19 pullfrog review — part of session-28 §2-2's order
  inverts)**: the moment the first migration rotate lands an anchor entry, an old CLI fails chain
  verification for the **whole project** via "unknown op = invalid chain" (including CI jobs on
  unmigrated environments). So the order is ① server → ② **CI / CLI updates** → ③ migration
  rotate of all environments, swapping session-28 §2-2's "② migrate → ③ CLI". Between ② and ③
  there's a window where a remaining old client can't read the project at all, and this is counted
  in the ladder comparison as a migration cost 2-E / 2-D don't have (it's still a fail-closed
  failure, not a silent degradation)

**Ladder revision (round 5)**: 2-F ⇔ **2-H** ⇔ 2-E ⇔ 2-D.
Recommendation = **2-H**: most of 2-F's one-time cost disappears (re-genesis = projectId update →
all signed data unverifiable → full data-layer rebuild), and the permanent diff shrinks to
1 op + 1 adjacency rule + 1 boundary entry. The precedents of "pay before release, be simple
forever" (grant_server extension, commitment into rotate) were all format finalizations **without
rebuilding existing data** — there's no precedent reaching a full data-layer rebuild, and 2-H
reaches 2-F's strength at the precedents' level.

### 4-3. Option 3-F: intent journaling (3-E′'s upward-compatible — journal-before-send)

3-E′ (journal-before-release) is the discipline "recording a verified fact precedes its use /
report", but it **doesn't cover the sending of a mutation itself**. The window of M1-A4's lost
response / post-accept failure (what session-31 §8 operational guard 5 closes manually) comes from
the non-persistence of "sent but acceptance unobserved".

- **3-F**: before **sending** a security-critical mutation, append an intent record
  (op kind, environment_id, manifest_version + sig hash, declared head — non-secret only;
  compatible with the diskless invariant) to the floor log. On success of the acceptance check
  (the effect check of §12-10 (3)), append a resolution record to close it. A client holding an
  unresolved intent SHOULD resolve it by reconciliation (chain sync / metadata-only pull) before
  the next mutation to the same environment or a success report
- Relationship to join: an intent is not a verified fact, so it **doesn't enter the join lattice**
  (observations stay a separate record class). fold surfaces unresolved intents as "needs
  reconciliation" — doesn't pollute 3-D's semantics
- Failure direction: what a crash / lost response loses is not "the belief that it succeeded" but
  "the record of the confirmation duty" — the direction of a missed record is pinned to the safe
  side (3-E′'s property extended to the send side)
- Synergy with §12-10 (3) (1-E′): 1-E′ normalizes "don't call it success until confirmed", and
  3-F makes that unconfirmed state crash-resilient. When 2-H / 2-F is taken under ruling 2,
  resolving a rotate / create intent completes entirely within a chain sync
- 3-E′ refinement (specified at the same time): the "record" of journal-before-release /
  before-send is measured by **persistence (fsync-equivalent)**, not by the write succeeding.
  Floor-log append frequency is low, so the cost is negligible

**Recommendation (round 5)**: ruling 3 = 3-D + 3-E + 3-E′ + **3-F** (compaction stays the M1
snapshot-row method of session-31).

## 5. Round-6 exploration (2026-08-19 — owner-requested final re-check)

### 5-1. Ruling 2: option 2-G′ — correcting 2-G's rejection error and reviving it (atomic composite bundling of checkpoint)

§4-1's rejection of 2-G had wrong premises at each of the composite's two generation points:

1. **create**: the new environment's variable set is empty, and values_digest is the digest of an
   empty enumeration. **No pull is needed at all**
2. **rotate**: the rotation executor bears the duty "re-encrypt current values under the new DEK
   and sign each re-encrypted value as writer" (CRYPTO_SPEC §7. That writer = the executor is also
   stated in §6.3's checkpoint-issuance SHOULD (i)). In other words **a real read of all current
   values is an operation intrinsic to rotate**, and its `var.read` is a truthful record — building
   values_digest generates no additional reads (it just serializes pull → rotate composite →
   re-encrypt)

So "values_digest forces full pull = audit pollution" doesn't hold. If the boundary checkpoint's
coverage is **limited to the single tuple of the environment in question** (the periodic
checkpoint's SHOULD of covering all environments stays as-is — that one is an occasion design that
piggybacks on real pulls and doesn't pollute the audit), no reads of other environments occur either.

**Content**: composite (create / rotate) = atomic append of the H+1 create / rotate entry +
the H+2 `checkpoint` entry (the environment's single tuple).

- **Not even a new op needed** — the checkpoint op already exists in the approved spec (0.6-draft
  §6.2, PR #80 merge = approval). What's untouched is only the implementation, and this becomes an
  early landing of a layer M2 must build anyway (no throwaway work)
- The manifest-verification exception has the same MUST shape as 2-H: "an exact match against the
  checkpoint tuple (environment_id, epoch, manifest_version, manifest_sig_hash) on the verified
  chain". Non-regression and the floor are carried **as-is by the already-approved
  checkpoint-consistency rule 1** — no need for 2-H's new rule 3
- **The decisive difference vs 2-H**: a **complete value-bearing reference** is pinned immediately
  at every boundary. The **residual window itself** that §4-2 confined to "rule 3 is the sole
  defense only until a reference is pinned" disappears — checkpoint consistency reaches the
  floorless class from every epoch boundary. A gain neither 2-H (anchor covers the manifest only)
  nor 2-F has. **Qualification on timing (reflecting the 2026-08-19 pullfrog review)**: what takes
  effect at PR-F3 is only rule 1 (manifest non-regression / epoch reference); the value-side gain
  (rule 2) arrives at M2 when snapshot distribution + client verification land (corresponds to the
  "honest cost" split below). Since the reference checkpoints themselves accumulate from PR-F3's
  boundary onward, they apply retroactively to past boundaries once M2 is reached. The ladder
  ranking doesn't change because rule 1's boundary reference alone subsumes 2-H's rule 3
- 2-H's permanent costs (a partially-duplicate checkpoint op + the adjacency rule) also disappear.
  No adjacency rule needed — a checkpoint is inherently a legitimate standalone op; composite
  bundling just makes "the issuance occasion atomic with acceptance". Entry-count and
  consensus-rule surfaces end up completely identical to the post-M2 shape
- **Honest cost**: PR-F3 gets M2's checkpoint layer early (consensus rules, §6.4 acceptance
  verification [content matching], atomic snapshot storage). Bounded by splitting: F3a = checkpoint
  op consensus rules + vectors (a pure M2 early landing), F3b = composite bundling + manifest
  verification rules. Snapshot **distribution** and the client-side consistency rule-2 check can
  stay in M2 proper (pull acceptance + storage forward; consumers later)
- Construction order: pull (same as the reads re-encryption needs) → manifest signing →
  checkpoint construction + signing → atomic acceptance of 2 entries + statement + manifest +
  wraps
- **rotate's liveness couples to concurrent pushes (reflecting the 2026-08-19 pullfrog review —
  counted in the ladder comparison as a permanent liveness characteristic)**: today a value push
  doesn't touch the manifest and doesn't race a rotate composite, but under 2-G′'s mandatory bundling
  a concurrent push between pull and acceptance fails the values_digest content match (§6.4) and
  turns **the whole rotate composite into a 422**. The existing escape path (issuing on a subset of
  environments) degenerates to the empty set under the single-tuple mandatory bundling and is
  unusable. Evaluation: (i) the retry's re-pull isn't throwaway work but **work needed for
  correctness** — under the current design, values from a concurrent push landing after the pull
  are silently dropped from re-encryption by the executor (silent acceptance of a stale view), and
  a 422 turns that into a forced refresh. (ii) Starvation via push spam by a malicious member is the
  same class as chain-CAS 409 spam starvation (member-privilege DoS — the domain of acceptance
  policy / rate limits); 2-G′ doesn't create a new attack class. (iii) Relaxing the MUST bundling to
  SHOULD isn't taken because it opens the same hole (unbundled composites slipping through) that
  §4-2 killed in 2-H's disjunctive form — a rotate that exhausts its bounded retries is reported as
  failed and the user re-runs it (§7's emergency-rotation duty is something to complete outside
  this retry loop, not to be reinterpreted as infinite retries)
- Migration / update order: identical to 2-H (old CLI rejects the checkpoint op as unknown =
  fail-closed. CLI / CI update first → then migration rotate of all environments)
- Spec revision surface: AUTH_SPEC §12-4 (add the checkpoint entry to the composite's bundle),
  CRYPTO_SPEC §6.3 issuance SHOULD (i) (the division "a boundary checkpoint is a mandatory part of
  the composite [coverage = that environment only]; the post-re-encryption checkpoint is as
  before"), **CRYPTO_SPEC §6.4 checkpoint acceptance verification (reflecting the 2026-08-19
  pullfrog review)**: the current text makes the content-match reference point "the server-stored
  state at acceptance time", but a bundled checkpoint's manifest is registered by H+1 in the same
  transaction, and on create the environment itself doesn't exist beforehand, so **re-specify the
  bundled tuple's match reference as "the stored state after the composite is applied"**
  (standalone checkpoints stay as before. The division of labor with the same-request bundle-match
  check — §12-4 — is unified at drafting time)

**Ladder revision (round 6)**: **2-G′ (recommended)** > 2-H > 2-F > 2-E > 2-D.
2-G′ keeps all of 2-H's advantages (no re-genesis, additive vectors, unchanged manifest format,
2-E-level migration) while adding no new surface (op or rules), reaching beyond-2-F strength
(boundary-immediate value-bearing references) via only early implementation of an already-approved
mechanism. Its sole burden is PR-F3's scope increase — and that is the very work of the next
milestone M2.

### 5-2. Ruling 1: ceiling check and 1 implementation guard

- No upward-compatible structure found. Considered and rejected: bundling an acceptance proof
  (server signature) into the server response — it would make the verifier trust the server,
  contradicting the "don't trust the server" principle. The source of truth for success correctly
  stays with distributed artifacts (1-E′)
- **Implementation guard (instruction to PR-F1)**: `strictPayload(...)` re-reads the AST at load
  time (same path as the parser — the last check's annotations if checks exist, otherwise
  ast.annotations), asserts the strict annotation is **in the effective position**, and throws if
  not. Promotes §2-3's silent application-order loss to fail-loud at module load, before tests can
  reach it (the pinned test requirement stays — double defense)
- The future unlock option for 1-E′'s value-push exemption (sig-hash listing) —
  **examination complete, not adopted (examined early at the owner's 2026-08-19 request)**:
  the audit-semantics question resolves (a listing doesn't distribute ciphertexts, so it doesn't
  meet `var.read`'s record condition — §12-7 "the record condition is ciphertext distribution" —
  and a principal able to call it already holds the privilege to legitimately read the values
  themselves via full pull = the disclosure is a strict subset of legitimately obtainable
  information; consistent with metadata-only mode's "don't record" class). But the examination
  settled a deeper reason for non-adoption: **a listing is server-declared unsigned data and doesn't
  meet 1-E′'s "verifiable distributed artifact" bar** — a malicious server can echo the expected
  (version, sig_hash) without storing anything (equivalent to trusting a 2xx). Confirmation via
  chain sync / metadata-only pull works because what comes back is signed artifacts (entries,
  statements, manifests) hooked into chain verification — a listing has none of that. There's no
  value in adding a new distribution surface for a check that only works against honest-but-buggy
  servers (the M1-A2 class), and the correct mechanism for verifiable confirmation of values is
  checkpoints carrying values_digest on the chain (ruling 2 = 2-G′'s boundary checkpoints + M2's
  periodic / rule 2). Finalized as not adopted; 1-E′'s value-push exemption stays the current line
  of being checkpoint territory

### 5-3. Ruling 3: ceiling check

- No upward-compatible structure found over 3-D / 3-E / 3-E′ / 3-F. Considered and rejected:
  storing the floor log in the OS keychain (the floor is non-secret and needs append semantics —
  wrong tool), splitting observations into files (one file per observation — worse than JSONL on
  inode count and order management)
- Added a note on synergy when 2-G′ is adopted: boundary checkpoints supply an M2 compaction
  reference of "observations up to the checkpoint" (session-31 §7 ruling 3 round 4) at every epoch
  boundary, making the floor log's physical-collection design (M2) easier to connect
