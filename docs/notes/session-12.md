# Session 12 notes (authenticity of values, DEKs, and variable metadata — threat analysis and crypto-spec revision. docs/spec-only)

Date: 2026-08-03. Premise: started after confirming PR #25 (CLI MVP) was merged.
Scope: **specification review and drafting only**. Implementation code and the real test-vector
files in `packages/crypto`, server, CLI, etc. are not changed. Merging this PR = the owner's
approval of the specification. Implementation happens in a separate session / separate PR after
approval, test-vectors-first (the split plan in §9).

Starting point: the 2 "spec-side considerations" of session-11.md §5 (chain-binding of
values / DEKs, cryptographic binding of variable names) + the same §6 review-loop 3 record
([info] the residual of fake-DEK injection into real epochs, the name ↔ variableId binding
being unauthenticated, split-view undefended).

## 1. Problem statement (what was not being proved)

CRYPTO_SPEC §5.1 (DEK-wrap registration signature) proves the **attribution** of "who brought
this wrap" but does not prove:

1. That the DEK is the **legitimate** DEK for that (environment, epoch)
2. That the wrap was registered **while the signer was a current member** (client verification
   uses keys from chain history — the very property that lets it verify past legitimate
   registrations of deleted members becomes a hole that cannot distinguish "new registration
   after deletion")
3. That a distributed value is the **latest** written by a legitimate writer (values are
   unsigned — any DEK holder can make a decryptable ciphertext at any coordinate)
4. That the server has not **omitted, rolled back, or forked** legitimate data
5. That the variableId ↔ display-name correspondence is legitimate (names are plaintext
   metadata outside the AAD)

Concrete attacks (reconstruction of session 11's known residuals): collusion between a
malicious server and a holder of a key from chain history (a removed ex-member, a leaked old
key) can (i) distribute a wrap of self-made DEK′ addressed to real epoch e in a form that
passes §5.1 verification and make the victim decrypt a fake value encrypted under DEK′, (ii)
make the victim encrypt and push a new value under DEK′ so the attacker reads the plaintext
(a confidentiality attack), (iii) encrypt a fake value under the real epoch's real DEK and
distribute it (an ex-member holds every DEK from their membership), (iv) swap the name ↔
ciphertext correspondence (`DATABASE_URL` ↔ `DEBUG_ENDPOINT`).

## 2. Decomposing the security goals

Written into CRYPTO_SPEC §14.1 as the norm (G1 attribution / G2 authorization-point / G3
content authenticity / G4 context binding / G5 freshness / G6 completeness / G7 fork
resistance / G8 availability = not guaranteed / G9 plaintext correctness = not guaranteed).
Every ruling in this session is based on this decomposition, avoiding the conflation
"signature = authenticity" (an extension to values and metadata of the "attribution ≠
freshness" distinction already made when §5.1 was drafted).

Two especially important non-goals were fixed first:

- **G8 (availability)**: a malicious server's refusal to respond, deletion, or delay cannot be
  prevented. Every design aims to convert "invisible tampering" into "a visible fault or
  attributed evidence"
- **G9 (plaintext correctness)**: a malicious current writer writing a bad value cannot be
  prevented. The ceiling of provability is "a writer with legitimate authority wrote this
  ciphertext"

## 3. Threat-model table

Attacker class × attack × "v1 today (as of PR #25) → after this revision → after Phase 2
(head gossip)". ◯ = impossible (cryptographically blocked), attribution = possible but
attribution-fixed to the actor's key, floor = detectable only by clients holding a local
floor, × = possible (residual).

| attacker | fake DEK injection (real epoch) | fake value injection | name ↔ ciphertext swap | rollback / omission | split view |
|---|---|---|---|---|---|
| server alone | now ◯ (§5.1 blocks unsigned registration) → ◯ | now **×** → **◯** (§4.1 — holds no signing key) | now **×** → **◯** (§4.2) | now × → floor (→ mutual detection in Phase 2) | now × → evidence-preserving only (→ detection in Phase 2) |
| server + current reader (no member history) | now × (a reader can also generate a §5.1 signature — the registration API rejects for insufficient role, but a colluding server can ignore the acceptance check and distribute) → **◯** (§5.2. If the DEK content is fake it fails the commitment check. Redistributing the real DEK is harmless) | now × (holds the DEK) → **◯** (§4.1's authorization-point verification — holds no member role at any head) | now × → **◯** (same) | same | same |
| server + demoted current reader (has member history) | ◯ (§5.2) | now **×** → **attribution + bounded** (coordinates inside the member-membership interval only. **Because demotion is accompanied by an all-environment rotate — §7's 2026-08-03 extension — it shrinks to the same "epochs of that time only" as a removed member**. Skip the rotate and injection addressed to the current epoch stays possible indefinitely until the next rotate — detected in review loop 2, §7 extended) | attribution + bounded (same as removed) | floor | evidence-preserving |
| server + current member (writer) | ◯ (§5.2 — the path of injecting DEK′ without rotating is gone. A malicious rotate is a legitimate operation and attributes on the chain) | × (G9 — bad values by a legitimate writer. Attribution-fixed) | × (legitimate rename authority. Attribution-fixed) | same | same |
| server + removed ex-member (old DEK + old signing key) | now **×** → **◯** (§5.2) | now **×** → **attribution + bounded** (coordinates inside the membership interval = only the epoch and head of that time. The current epoch is impossible — §7's mandatory rotate + §6.3-4. Backward-direction injection is floor-detected. **Forward direction (forging the real latest's next version under an old epoch) needs no rollback and slips through a naive floor** — detected for floor-holding clients by epoch monotonicity §4.1 + the floor's extension rule §6.3-(c). Residual = first sync and the window until remove→rotate completes. §14.3-5) | now **×** → **attribution + bounded** (only meta signatures at heads inside the membership interval. **With no epoch anchor, injection of a forward meta_version is undetectable even by the floor** — v1 reaches evidence-preservation via the prev chain at most. Closure is Phase 2 manifest / checkpoint = undecided #12. §14.3-5) | floor | evidence-preserving (binding to an in-membership head leaves evidence distinguishable from a legitimate fork) |
| server + leaked old signing key (no DEK) | ◯ (§5.2) | **◯** (cannot make a decryptable fake value — AES-GCM tag unforgeable. Injection degrades to decryption failure = an availability problem. CRYPTO_SPEC §14.3-5) | attribution + bounded (meta needs no DEK — the residual including forward injection is the same as an ex-member's) | floor | evidence-preserving |
| malicious current owner / admin | × (near-omnipotent via the legitimate powers of rotate · add_member · remove. However every operation is attribution-fixed on chain + signature and mechanically traceable) | × same | × same | × (data deletion is an admin's legitimate power) | — (chain appends are DO-serialized) |
| multiple legitimate writers (concurrent) | — | serialized by 409 CAS. Re-sign and retry (AUTH_SPEC §12-5). A fork arises only from server equivocation, and the prev chain preserves it as evidence | same shape via metaVersion CAS | — | — |
| first-sync client | ◯ (commitments complete inside the presented chain view) | attribution + bounded (**but if the presented view itself is rolled back, it holds only relative to that view's point in time** — the dominant residual. CRYPTO_SPEC §14.3-3) | same | **×** (undetectable) | × (undetectable) |
| client that remembers a previous legitimate head | ◯ | attribution + bounded | same | **floor-detected** (chain shortening, version / metaVersion / epoch regression) | partial detection (rejects the view that contradicts its own floor) |

Reading the table — the essentials:

- With this revision, "server alone" is completely neutralized (every piece of data carries a
  signature or a chain binding)
- Collusion attacks shrink to "attributed injection into coordinates inside the membership
  interval". Detectability splits on the direction of injection (correcting an error in the
  original claim, found in review loop 1 — §12): **backward** (substitution, rollback) is
  floor-detected. **Forward** (forging the real latest's next version / meta_version) needs
  no rollback, slips through a naive floor, and is closed for values by epoch monotonicity +
  the floor extension, but **meta has no epoch anchor and is not closed in v1**
  (evidence-preservation at most. Closure is Phase 2)
- "A view with the whole chain rolled back" (a removed member looks like a current member) is
  the dominant residual for a first-sync client. No signature scheme can solve this; it is the
  responsibility of head gossip, external checkpoints, and floors (the responsibility split is
  CRYPTO_SPEC §14.3)

## 4. Comparing the design options

### Option A: per-value writer signature → **adopted** (§4.1. Integrates C's minimal core)

| consideration | ruling |
|---|---|
| canonical signed form | `LP("maruhi/v1/value-sig", project_id, environment_id, epoch, variable_id, version, nonce_hex, ciphertext_hex, prev_value_sig_hash_hex, writer_user_id, chain_head_hash_hex, chain_head_seq)`. Follows §5.1's conventions (the domain string binds the suite · binary is lowercase hex · every wire field is enumerated, leaving none unbound · signer user_id baked in) |
| point-in-time proof of write authority | chain-head binding (hash + seq) + the verifier's "role at the declared head" derivation. The declared head is the writer's self-declaration, but **it must be an entry that exists on the verifier's own verified chain** (which doubles as fork detection), and a removed member can only declare heads inside their membership interval. **Monotonicity of declared-head seq (along the version chain) cannot be a rule** — honest concurrent writers synced at different times can legitimately push under a head older than the previous version (the point where the security viewpoint's countermeasure was rejected by the correctness viewpoint in review loop 1). Instead, **epoch monotonicity** (non-decreasing along the version chain — always holds in honest flows because the current epoch is non-decreasing in acceptance order) becomes the verification rule |
| verifying past values of a removed writer | the same key-history matching as §5.1 (user_id + FP → that time's key on the chain history). Pinned by a positive vector (§8) |
| forks at the same version | prevention is impossible (the server can fake concurrent acceptance). The `prev_value_sig_hash` chain converts it into **non-repudiable evidence** (two valid signatures at the same coordinate = proof of equivocation) |
| rollback / omission | a lone signature cannot prevent them (a signature does not prove freshness — the lesson of §5.1's semantics). Explicitly carved out as the responsibility of the local floor (§6.3 SHOULD) + Phase 2 gossip |
| cross-checking against the audit log | the signer key FP is copied into `var.version_pushed` etc. (AUDIT_SPEC §3.3 — a generalization of the dek.registered precedent) |
| relation to AAD | AAD is unchanged (kept as GCM-layer defense; existing vectors unchanged). The variant "add the writer to the AAD" is dismissed — AAD verifiers are limited to DEK holders, who are exactly the attacker class, so it cannot carry authenticity |

### Option B: authenticated descriptor / commitment of the epoch DEK → **adopted** (B-4 = a commitment posted on the chain. §5.2)

| variant | evaluation |
|---|---|
| B-1: domain-separated commitment to the DEK itself (posting location a separate question) | **Adopted: SHA-256 of the preimage = LP(domain, coordinate, dek)**. Independent of the recipient set; invariant under backfill, repair, HPKE randomness, and recipient growth via add_member. The DEK is a uniform-random 256-bit value, so publishing it leaks no information (low-entropy reuse is prohibited in §12) |
| B-2: commitment to the recipient wrap set | **Dismissed**: the set grows under add_member's backfill, and repair re-registration changes the HPKE ciphertexts (Seal is randomized), so a set commitment is invalidated on every registration. Since distribution is per-recipient (§12-6), no recipient can verify the whole set — the same root as session 09's §2-1 (dismissing set-level signatures) |
| B-3: signature on an (environment, epoch) descriptor (posted on the data plane) | **Dismissed**: signer selection goes circular — without a ledger deciding "which descriptor is legitimate", a colluder's self-key-signed descriptor is indistinguishable. If the ledger = the chain, it coincides with B-4; an independent data-plane location only adds attack surface |
| B-4: posting the commitment on the membership chain (adopted) | The chain is the already-existing "authenticated broadcast everyone verifies", and rotate_epoch is already a chain op. The epoch ↔ commitment correspondence becomes a derived value of the consensus rules, and a fake DEK becomes **uninjectable without a chain fork** |

Answers to the required considerations:

- **epoch 1 (the problem that environment creation is not a chain op)**: resolved by adding the
  chain op `create_environment` (§6.2). Large side benefits: (i) environment existence becomes
  chain-derived, so AUTH_SPEC §12-4's two workaround rules — "rotate does not cross-check
  against environment metadata" and "observing a rotate burns the ID" — disappear, (ii) the
  ban on environment-ID reuse is promoted to a consensus rule, (iii) epoch 1's starting seq
  becomes observable, making §4.1's epoch-consistency check uniform across all epochs.
  Alternatives (commitments only for epoch 2+, or a retroactive commitment on the first
  rotate) were dismissed for leaving the non-uniformity "only epoch 1 has weaker guarantees"
- **rotate_epoch**: the new epoch's commitment is added to the payload (+64 bytes)
- **backfill of past epochs to new members**: unaffected — the commitment is
  recipient-independent (the inviter holds only the real DEK and can wrap only the real DEK —
  "backfilling a fake DEK the attacker knows" fails the commitment check)
- **repair (wrap deletion → re-registration)**: re-wrapping the same DEK leaves the commitment
  unchanged. Repair when the DEK itself was wrong is a rotate (the legitimate procedure)
- **HPKE randomness**: unaffected — the commitment is over the DEK, not the wrap
- **post-hoc growth of the recipient set**: same
- **information leak from publishing the commitment**: none (SHA-256 preimage resistance +
  a 256-bit uniform-random input. Because coordinates are part of the preimage, DEK equality
  across contexts does not leak from comparing commitments either). Compliance with "no
  inventing new primitives" also confirmed: a hash commitment over a random 256-bit key is the
  same application of "identification by public hash" as the §3 key fingerprint — no new
  construction like a salted commitment scheme is needed (prohibiting low-entropy inputs in
  §12 fixes the hiding premise as spec)
- **Effect on chain limits**: create_environment ≤ 1,000 entries (the environment cap),
  rotate +64 B. Negligible against 10,000 entries / 32 MiB

### Option C: authenticated data history → **minimal core only** (prev chain + local floor. Manifest / checkpoint go to Phase 2 = undecided #12)

| variant | evaluation |
|---|---|
| C-1: per-variable prev-hash chain (integrated into the value signature) | **Adopted**: one extra field on the signed subject yields authentication of version order and fork evidence-preservation. No extra signatures or round trips |
| C-2: per-environment signed manifest (variable set + latest version) | **To Phase 2**: adds variable-set omission detection, but (i) including the latest version in the manifest makes every push pass through a manifest CAS (a serialization point on the hot path + constant contention for concurrent writers), (ii) without it the gain is only "variable-set omission detection", which a local floor (remembering each variable's metaVersion) already achieves for returning clients, while for first-sync clients the manifest's own freshness cannot be guaranteed, so it cannot be achieved. The cost-benefit does not stand |
| C-3: periodic checkpoints on the chain (value / audit heads) | **To Phase 2** (merge with undecided #4/#12): the only option that could give G5/G6 to first sync as an external anchor, but the design questions of chain bloat and write frequency are large. Designing it together with head gossip is the right order |
| C-4: Merkle tree (version history / whole environment) | **Dismissed (v1)**: the added gain over a prev chain is "size of partial proofs", but v1's pull is latest-only + all-variables bulk, so no partial-proof demand exists. Only implementation and vector complexity would grow |

Answers to the required considerations: connection to the VersionConflict CAS (409 → re-attach
prev to the winner's signed_bytes hash and re-sign — AUTH_SPEC §12-5), concurrent writers (CAS
serializes; a fork is server equivocation only = evidence), multiple legitimate signatures on
the same version (the server stores one row; observing multiple valid signatures = evidence of
equivocation), the basis for a first sync's latest determination (**none** — stated in §14.3-3.
Without head gossip, the guaranteeable range ends at "internal consistency and attribution of
the presented view"), the combination with Phase 2 gossip (the write signature's head binding
doubles as the carrier of the declared head — §6.3), impact on the DO (+~350 B/row. §12-8).

### Option D: authenticated correspondence of variable name and variableId → **D-2 adopted** (signed versioned metadata statements. §4.2)

| variant | evaluation |
|---|---|
| D-1 / D-3: include the name in the value AAD (re-encrypt on rename) | **Dismissed**: a rename re-encrypts every version (worst case 1,000 versions × 64 KiB) + verifying old versions would require keeping name history. Head-on collision with the existing design decision "the crypto context uses stable identifiers unaffected by renames" (the justification for §3's environment_id). Making a display edit a cryptographic operation is the worst design smell |
| D-2: immutable ID + signed metadata statements (rename = a versioned op) (adopted) | The name ↔ ID correspondence becomes limited to "a statement signed by a key holder with the required role", and server-side swaps become impossible. metaVersion + the prev chain preserves rename history as fork evidence too. The same verification machinery as the value signature (A) (head binding, authorization point) can be reused, minimizing the implementation increment |
| D-4: bind to an environment / variable metadata manifest | **To Phase 2** (same thing as C-2. Variable-set completeness is the manifest's territory) |

Answers to the required considerations: rename (a new statement at metaVersion+1), tombstone
and the ban on ID reuse (a status=deleted statement + "no re-activation after deleted".
Environment IDs are promoted to a consensus rule — §6.2), Unicode normalization and case
(**signatures are byte-exact; normalization is an input-boundary acceptance policy** — putting
normalization into the verification rules would split verification across implementations with
different normalization. NFC + case-sensitivity is prescribed in §12-1), server-side name ↔
ciphertext swap (blocked by signatures; clients refuse to resolve duplicate active names under
the same name), the relation to CLI environment-variable names (name → ID resolution is
required to go through verified statements. The denylist of execution-control variable names —
session-11 — stays as a defensive layer).

The same mechanism was applied to environment names (`env-meta-sig`). The same attack (luring
a push to the wrong environment by swapping the dev / prod names) works, and the mechanism is
entirely shared, so there is no reason to limit it to variables only. **This is a scope
expansion beyond the task spec (variable names), so it needs a ruling — §10-2**.

### Option E: composition → B + A (with C's minimal core) + D in a single spec revision

Derivation of the minimal composition: closing G1–G4 needs both "key authenticity (B)" and
"data authenticity (A·D)"; either alone leaves an attack from §1 —

- without B (A·D only): inducing encryption under a fake DEK remains (the confidentiality
  attack §1-ii). A value signature is authenticity of ciphertext and does not protect "the key
  for the value about to be written"
- without A (B·D only): fake-value injection under the real DEK remains whole (§1-iii) (a DEK
  holder can make a valid ciphertext at any coordinate under GCM)
- without D (A·B only): an attack remains that abuses legitimate signed values via name swaps
  (values are bound to variable_id, but name → ID resolution stays unauthenticated)

**The split judgment for the spec PR (a comparison required by the task)**:

| option | evaluation |
|---|---|
| **Single spec PR (adopted = this PR)** | The 3 mechanisms share §14's guarantee table, and each one's residuals are closed by the others (above). Splitting means the intermediate states' guarantee table gets rewritten twice and the material for "how far is it protected" scatters. The verification machinery (head binding, authorization point, chaining) is also shared, so separate reviews invite convention mismatches |
| Split the spec PR into DEK-authenticity and name-binding PRs | Each PR gets smaller, but the mutual-dependency explanation above would be duplicated into both. The review-granularity gain is already available from splitting the implementation PRs (§9), so it is no reason to split the spec |

**The implementation is split into 3 PRs** (§9) — the spec is approved wholesale; the
implementation and vectors are reviewed independently per mechanism.

## 5. Required design confirmations (answers to the task-spec checklist)

| item | answer |
|---|---|
| plaintext values / DEK / master secret key never cross the server API | unchanged. What is added is signatures (public), commitments (one-way hashes), and hash chains only |
| no new custom primitives | Ed25519 / SHA-256 / §2.1 LP only. See option B in §4 for the commitment's positioning (same-shaped application as FPs. The hiding premise is fixed by §12's prohibition) |
| domain separation of signed bytes / enumeration of all fields | 4 new domains: `value-sig` / `var-meta-sig` / `env-meta-sig` / `dek-commit`. They differ from existing domains and the chain signed_bytes (first field = suite) from the first LP field — no collisions. Each signed subject enumerates every wire field (§5.1's discipline) |
| binding of signer_user_id and FP | user_id is baked into signed_bytes (same as §5.1); FP is distributed on the wire + the selection rule "the key bound to that user_id in chain history whose FP matches" (same shape as RecipientDek) |
| basis for verifying "at registration time" | declared-head binding + role derivation at the declared head (§6.3). The head is self-declared but limited to entries that exist on the verifier's own view, and removed members can only declare inside their membership interval |
| guarantee deltas across server-only / collusion / old-key | the §3 table. In particular, the distinction "a leaked signing key alone (no DEK) cannot make a decryptable fake value" is stated in §14.3-5 |
| residuals of rollback / omission / equivocation | §14.3-3 through -5. Confirmed that all residuals converge on G5/G6/G7 |
| responsibility split with head gossip | the write signature's head binding = passive carriage of the declared head (always on, no added wire). Phase 2 gossip = reader-side declarations + mutual distribution via the server (active detection). Stated in §6.3 |
| behavior on chain fork | binding to a head not present in one's own view = reject + warn (evidence of a fork or a forgery). §6.3-2 |
| suite / wire version | stays `maruhi/v1`. No primitive changes, and the suite identifies the algorithm bundle (§2). The additions are only domain strings and wire shapes, and because nothing is published and no chains are deployed, no protocol-version addition is needed either. The chain-op addition (create_environment) is a consensus-rule change but carries no backward-compat clause on the same "no existing chains" basis as §6.2's member-key uniqueness |
| API bodies, signature-verification counts, chain capacity, DO storage | push +1 Ed25519 (§12-8). Compound rotate / env-create fit inside the existing 8 MiB implementation cap (the wrap set is the dominant term, as before). Chain +1 op/environment +64 B/rotate. Stored row +~350 B (§12-8) |
| audit actors are internal user_id + FP only | unchanged. The only addition is an expanded set of writes into the existing actor_key_fingerprint column (AUDIT_SPEC §3.3) |

## 6. Wire-change catalog (pre-publication = no backward compatibility needed. Reflected into api-schema in the implementation PR)

1. `EncryptedPayload` gains `prevValueSigHashHex` / `chainHeadHashHex` / `chainHeadSeq` /
   `signatureHex` (shared by push and distribution). The distribution side additionally carries
   `writerUserId` + `writerKeyFingerprintHex`
2. New types `VariableMetaStatement` / `EnvironmentMetaStatement` (+ author information on the
   distribution side). They ride the requests for variable creation (bundled with version 1),
   rename, and deletion, and environment rename and deletion
3. The environment-creation endpoint becomes compound: a `create_environment` chain entry +
   an `EnvironmentMetaStatement` + the complete epoch-1 wrap set (replacing the old
   environment_id + display name + wrap set)
4. Rotation becomes a compound endpoint: a `rotate_epoch` entry + the new epoch's complete
   wrap set (previously two round trips: the chain-append API and the DEK-registration API).
   The existing DEK-registration API remains dedicated to backfill and repair re-registration
5. Chain entries: new op `create_environment` (payload order: [environment_id,
   dek_commitment_hex]); `rotate_epoch`'s payload gains dek_commitment_hex at the end.
   ChainInvalidReason gains `duplicate-environment` / `unknown-environment` (format violations
   of dek_commitment_hex merge into the existing payload-structure check).
   **The generic chain-append API rejects `create_environment` / `rotate_epoch` entries with
   a typed error** (compound endpoints only — AUTH_SPEC §6)
6. Pull responses: the per-value signature block + writer info, the latest meta statement +
   author info per variable and environment. **Other responses that return names (the
   environment list etc.) also replace the bare name snapshot with statement + author info**
   (AUTH_SPEC §12-2). The current shape of `EnvironmentSummary` etc. is subject to revision
7. New errors: 422 `signature-invalid` (value and meta. Shares §12-6's existing code) /
   `chain-head-unknown` / `chain-head-state-mismatch`, 409 (metaVersion CAS — returns only the
   latest metaVersion number. **The 409s for version / metaVersion do not carry the winner's
   signed_bytes hash**: the client re-fetches, verifies per §6.3, and recomputes itself —
   AUTH_SPEC §12-5)
8. Error-contract moves from compoundization: the environment-creation and rotation endpoints
   come to return `ChainHeadConflict` (parent-head CAS) and chain-entry verification errors
   (`duplicate-environment` etc.). The old `EnvironmentConflict`'s `retired` reason (ID
   burning on rotate observation) changes meaning under promotion to a consensus rule
   (absorbed into a chain-verification error)
9. Audit: new `chain.environment_created`; extension of data-family events'
   actor_key_fingerprint; an applicability note on `dek.registered` (the compound-bundled
   portion) (AUDIT_SPEC §3.3 / §3.4)

## 7. Reflection into CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC / ADRs

- CRYPTO_SPEC 0.4-draft: §4.1 (value signatures) · §4.2 (meta statements) · §5.2 (DEK
  commitments) · §6.2 (create_environment + environment-lifecycle consensus rules) · §6.3 /
  §6.4 (verification rules) · §7 (connection with rotate) · §11 (vector catalog) · §12 (the
  low-entropy-commitment ban) · §13 #12 · §14 (guarantees and non-guarantees)
- AUTH_SPEC 0.6-draft: §12-1 through §12-8 (concretization of this memo's §6 wire and
  acceptance conditions)
- AUDIT_SPEC 0.5: §3.3 (generalizing the FP column) · §3.4 (chain.environment_created)
- ADRs: **judged to need no revision**. ADR-0002 (selective-disclosure E2EE) already decided
  "signed membership log, head gossip, context binding, epoch system", and this revision is
  their elaboration (CRYPTO_SPEC's territory) containing no architecture-choice change. No
  decided matter is relitigated either (§6.2's consensus-rule addition stays inside that ADR's
  frame)

## 8. Test-vector plan (committed before implementation in the post-approval implementation PR)

Generation follows the existing independent-reference-tool scheme (pyca/cryptography's
generate_reference.py cross-checked against verify_reference.mjs). The task-specified
negatives are marked ✓ with what covers them. Response-family behaviors that cannot be pinned
by vectors (omission, rollback) are stated as an implementation-test plan.

**Change of practice from the precedent (sessions 09 / 10 = spec and vectors committed first
in the same PR)**: at the task's instruction this session does not change the real vector
files, and the vectors are committed ahead of implementation in the implementation PR after
the owner's spec approval (the discipline of "before implementation" itself is maintained.
"Do not invest in vectors before the spec is approved" is this session's instruction).

### 8-1. `value-signature.json` (new. PR-2)

- Fixture method: verification rules that need chain state are built **referencing the
  canonical chain (post-revision) of chain-entries.json** (following dek-wrap-signature.json's
  cross-file precedent of reading dek-wrap.json)
- Positive cases: basic (version 1, empty prev) / version 2 (prev chain) / a past value at an
  in-membership coordinate by a removed writer (✓ verifying a legitimate past registration) /
  a re-encrypted push by the rotate performer (**the rotate_epoch entry itself is the declared
  head** — pins §6.3's inclusive convention)
- Negatives: `tampered-signature` / `tampered-ciphertext` / `tampered-nonce` / coordinate
  transplants `transplant-project` / `-environment` / `-epoch` / `-variable` / `-version`
  (✓ transplant) / `transplant-signer` (user_id swap) + `wrong-signer-key` (FP swap)
  (✓ signer swap) / `chain-head-swap` (hash substitution) + `chain-head-seq-mismatch`
  (✓ chain head / seq swap) / `prev-hash-mismatch` (chain inconsistency) /
  `epoch-regression-across-versions` (epoch smaller than the previous version's epoch — §4.1
  epoch monotonicity) / `fork-same-version` (two valid signatures with different content at
  the same coordinate — both verify, and the chain / uniqueness check detects equivocation;
  pinned) (✓ double-fork of one version) / `suite-mismatch` (✓ suite mismatch)
- Verification-rule family (the authorization class — same shape as chain-entries' authz
  negatives): `head-not-in-chain` (✓ fork) / `writer-role-insufficient` (reader signature) /
  `writer-removed-at-head` (a declared head at a post-removal seq — ✓ new registration by an
  old key after removal) / `epoch-not-current-at-head` (✓ same) /
  `head-before-environment-create` (a declared head before environment creation — §6.3-4) /
  `key-from-other-tenure` (remove → re-add with a different key under the same user_id;
  combining an old-interval key with a new-interval head — §6.3-1's head-point binding)

### 8-2. `metadata-signature.json` (new. PR-3)

- Same fixture method as 8-1 (references chain-entries.json's canonical chain)
- Positive cases: creation (metaVersion 1) / rename chain / deletion (status deleted, name
  retains the last active name) / the environment version / **a past statement at an
  in-membership head by a removed author** (the counterpart of 8-1's positive)
- Negatives: `tampered-signature` / coordinate transplants / `transplant-signer` +
  `wrong-signer-key` / `chain-head-swap` + `chain-head-seq-mismatch` / `prev-hash-mismatch`
  (chain inconsistency) / `suite-mismatch` (same shape as 8-1) / `name-swap` (swapping the
  names of two variables — each signature verifies but the ID ↔ name binding detects it)
  (✓ variable-name swap) / `rename-fork` (a fork at the same metaVersion) /
  `revive-after-delete` (activating after deleted) / `nfc-variant` (names whose bytes differ
  before and after NFC normalization — pins that signatures are byte-exact and they are
  different objects)
- Verification-rule family (includes meta-specific role levels — not derivable from 8-1):
  `author-removed-at-head` (a declared head at a post-removal seq) /
  `author-role-insufficient` (reader signature) / `env-delete-role-insufficient` (a
  member-signed status=deleted environment statement — pins the level difference that only
  deletion requires admin) / `var-meta-head-before-env-create` (**positive** — var meta at a
  pre-environment-creation head is accepted. Pins the intentional asymmetry of not checking
  environment existence, unlike the value signature's §6.3-4. AUTH_SPEC §12-4)

### 8-3. `dek-commitment.json` (new. PR-1)

- Positive cases: basic (same DEK and coordinate as dek-wrap.json's basic) / epoch 1
  (from create)
- Negatives: `dek-mismatch` (a different DEK) / coordinate transplants `transplant-project` /
  `-environment` / `-epoch` / `wrong-domain` / `uppercase-hex`
- The positives pin "the commitment is unchanged across backfill and repair re-registration"
  (✓ past-epoch backfill after add_member, ✓ re-registration after repair — re-wrapping the
  same DEK matching the same commitment)

### 8-4. `chain-entries.json` revision (PR-1. **Regeneration, not mere appending**)

- **The existing canonical chain must be regenerated**: the current chain contains
  `rotate_epoch` at seq 3 / seq 8 without a preceding `create_environment`, which under the
  new consensus rules makes the whole chain invalid as `unknown-environment`. On top of that,
  adding dek_commitment_hex to the rotate payload changes every payload, signature, and
  prev_hash link from seq 3 onward. Done via full regeneration through the generation tool +
  diff review of the existing parts (session-10 §3's method)
- Effects on existing cases (to be checked exhaustively in the implementation PR):
  `authz-epoch-first-jump` needs its expected reason reviewed because of check order
  (unknown-environment precedes epoch order) / `expected_head_states` is extended in meaning
  to carry the environment set and epoch-start seqs (the "initial value 1 when unobserved"
  convention is abolished) / re-inspection of coordinate consistency for every negative
  referencing an environment ID
- Added positive: the sequence `create_environment` (new env) → `rotate_epoch` (with
  commitment)
- Added negatives (authorization class): `authz-create-env-duplicate` (history-uniqueness
  violation — including re-creating a deleted ID) / `authz-rotate-unknown-environment` /
  `authz-create-env-reader` (role) / pinning the authorization-stage check order (role →
  duplicate / unknown → epoch order). Format violations of dek_commitment_hex (uppercase hex,
  wrong length) are placed as **payload-structure-check negatives** (before the authorization
  stage — §6.2's stage order)
- valid_appends: tolerated boundaries like "creation under a **different ID** after a
  tombstone is valid"

### 8-5. Items that cannot be vectorized (implementation-test plan — included in each implementation PR)

- Omission: floor detection when a specific variable, wrap, or meta is dropped from a pull
  response (✓ omission of values, wraps, and metadata)
- Rollback: rejection of floor (version / metaVersion / epoch / chain length) regression
  (✓ rollback to an older legitimate value)
- **Floor detection of forward injection**: rejecting a distribution whose new version beyond
  the floor's version carries an epoch below the current epoch at the floor's point in time
  (§6.3 floor rule (c)). Evidence-preservation of differing signed_bytes at the same version
  (content substitution)
- Fork: distinguishing the two kinds of heads absent from one's view (seq ≤ own head with
  hash mismatch = immediate evidence / seq > own head = re-sync → re-verify → evidence if
  unresolved)
- Server acceptance family: each 422 reason · 409 (re-fetch + verify + re-sign) · atomicity of
  compound requests · compound CAS retry (re-signing both the entry and the statement) ·
  rejection of create_environment / rotate_epoch on the generic chain-append API · 422 for
  non-NFC names · 404 for rotate into a deleted environment

## 9. Implementation split plan (after spec approval. All follow the layer order "vectors first → crypto → server → CLI"; human review mandatory)

1. **PR-1: DEK authenticity (option B)** — chain-entries extension + dek-commitment.json →
   crypto (verification of create_environment, state derivation, commitment computation /
   matching) → server (compound env-create / rotate endpoints, replacing the old paths) →
   CLI (compound env create, post-unwrap matching). The top-priority PR — it closes §1's
   (i)(ii)
2. **PR-2: value signatures (option A + C's minimal core)** — value-signature.json → crypto
   (sign / verify / chaining) → api-schema (EncryptedPayload extension) → server (push
   acceptance verification, stored columns) → CLI (push signing, pull verification, 409
   re-signing)
3. **PR-3: metadata statements (option D)** — metadata-signature.json → crypto → api-schema →
   server (meta CAS) → CLI (routing name resolution through verification)
4. **PR-4 (optional / needs ruling §10-4)**: the CLI's local floor (persisting non-secret
   state) + the UX for reporting fork evidence
- The order is 1 → 2 → 3 (1 closes the worst known residual. 2 and 3 are independent once 1
  lands). On the roadmap they can run in parallel with Phase 1's remaining items (the CLI
  family)
- Confirmed that guarantees grow monotonically even in the intermediate state between PR-1
  and PR-2 (commitments alone already close §1-i/ii. In reverse order §1-ii would remain to
  the end)

## 10. Requests for ruling (items asking the owner's judgment in PR review)

1. **Making environment creation a chain op (§6.2 create_environment)**: the change with the
   largest blast radius in this revision (consensus rules + wire + replacing the existing
   implementation). The alternative (keeping epoch 1 off the chain) leaves the non-uniformity
   "only epoch 1 has no commitment". Recommendation = introduce it
2. **Applying D to environment names (env-meta-sig)**: the task spec covers variable names.
   It was included symmetrically because the attack and mechanism are identical, but scoping
   to variables only remains an option. Recommendation = include it
3. **The positioning of variable deletion**: deletion was made "a member-signed statement"
   (the existing §12-3 role level is unchanged). Raising deletion to admin was an option, but
   an authorization-model change is outside this revision's purpose (authenticity) and was set
   aside. Recommendation = keep as-is (member)
4. **The CLI's local floor (PR-4)**: what is stored is chain heads and sequence numbers only,
   which I judged compatible with the diskless invariant (non-secret configuration may be
   persisted), but because it includes changing the "the CLI never caches the chain" policy
   (session-11 §2-3), an explicit ruling is requested. Recommendation = introduce it (as the
   SHOULD says)
5. **Wholesale approval of the spec PR** (option E's split judgment in §4): approval as a
   single PR is recommended. If a split is preferred, the spec can also be split along §9's PR
   boundaries
6. **Handling the meta-statement forward-injection residual** (the residual confirmed in
   review loop 1 — §14.3-5): for v1, "documentation + evidence-preservation" is recommended
   (the adopted draft's position). The alternative — adding the current epoch at the declared
   head to the meta signed_bytes and imposing the same-shaped monotonicity as values — was
   judged not worth its complexity because it is only a partial mitigation: (i) since rotate
   does not re-issue statements, injection into dormant meta still cannot be blocked, (ii)
   verification would require distributing statement history. If there is disagreement, a
   ruling is requested
7. **Compoundizing remove_member + all-environment rotate (future PR candidate)**: the current
   spec's "rotate follows remove" window (§14.3-5 residual (ii)) is narrowed by an operational
   obligation (§7) but not by mechanism. Making the remove_member entry + all-environment
   rotate entries + wrap set one compound request would raise it to a mechanism guarantee
   (body size and DO execution time need examination). Proposed to be considered together with
   implementing the chain-append command family (session-11 §5)
8. **Mandating all-environment rotate on demotion below member (§7's 2026-08-03 extension)**:
   review loop 2 detected a missing attacker class — "a demoted reader can forward-inject
   addressed to the current epoch at a member-interval head indefinitely until the next
   rotate". The same-shaped rotate obligation as on removal shrinks it to the same "epochs of
   that time only" as a removed member (the motivation is not confidentiality but epoch-anchor
   soundness — the demoted keeps receiving new DEKs as a reader). Demotion is rare and costs
   the same as removal. A ruling vs the alternative (v1 documents it only) is requested.
   Recommendation = mandate it

## 11. Where we got stuck and design lessons

- **"A signature is attribution, not freshness" (§5.1's lesson) applies to values
  verbatim**: adding value signatures does not prevent a single millimeter of rollback. If
  the G1–G9 decomposition hadn't been done first to fix "which mechanism carries which goal",
  it would have felt like value signatures solved everything (the task instruction's
  decomposition requirement was right)
- **remove_member ⇒ all-environment rotate (§7) is the cornerstone of authorization-point
  verification**: thanks to this existing rule, "within a removed member's membership interval
  there is no head at which the current epoch was current" holds, and the epoch-consistency
  check (§6.3-4) alone yields "the old key cannot write at the current epoch". Conversely, in
  an operation that neglects rotate this guarantee weakens (honest clients enforce rotate, but
  a malicious admin can skip it — attribution still remains in that case)
- **Backfill kills the "membership-overlap check"**: the option of imposing an
  authorization-point check on wraps (overlap between the signer's membership interval and
  the epoch) collides head-on with legitimate past-epoch backfill after add_member (where the
  inviter's membership and the epoch do not overlap) and fails. Wrap-layer authenticity only
  closes via the commitment (recipient-independent) — that is why the task instruction listed
  backfill among the required considerations
- **The commitment's location is "the already-existing authenticated broadcast", the only
  choice**: the data-plane option (B-3) always falls into the circularity of "which is the
  legitimate one". Since the chain is already what everyone verifies, there is no reason to
  put it anywhere else
- **The dismissal of putting the name in the AAD was mechanically derivable from the existing
  principle "do not put mutable metadata in the crypto context"** (reusing §3's
  environment_id justification)
- **"Rollback is needed, so the floor detects it" misses the forward direction** (review loop
  1's most important point — 3 viewpoints independently detected the same root): injection at
  an in-interval coordinate needs no rollback if it simply claims the real latest's "next"
  version / meta_version, and a floor that only checks sequence-number monotonicity lets it
  through. Values close via epoch monotonicity — "a time proxy baked into the coordinate" —
  which meta lacks. The intuition "injection always involves some regression" forgets that
  **the attacker gets to choose unused parts of the coordinate space (the next sequence
  number)**
- **A countermeasure itself can be rejected in review**: the security viewpoint's proposal
  "monotonicity of declared-head seq" was rejected when the correctness viewpoint showed it
  breaks a legitimate flow (honest concurrent writers synced at different times). The parallel
  3-viewpoint review functioned not only to detect points but as **mutual verification of the
  proposed fixes**

## 12. Review → fix loops (in-PR. Parallel review by 3 viewpoints → fixes)

### Loop 1's main findings and handling

3 viewpoints (security/crypto · correctness/concurrency/fork · spec/vector/wire contract) run
in parallel. **[High] = the same root independently detected by all 3 viewpoints**:

1. **Forward injection slips through the floor (3 viewpoints [High])**: §14.3-5's "a 'latest'
   presentation requires an accompanying rollback = floor-detected" was wrong — with a removed
   member's key, forging "the real latest's next version at an in-membership epoch × an
   in-membership head" passes all of §6.3's verification + the sequence-number floor (prev can
   use the real latest's signed_bytes hash, which is a public value). → Handling: (i) add
   **epoch monotonicity** (non-decreasing along the version chain) to §4.1 as a verification
   rule, (ii) extend §6.3's floor to (version, epoch, signed_bytes hash) + environment current
   epoch and add rule (c) "a new version's epoch ≥ the current epoch at the floor's point",
   (iii) split §14.3-5's writing into the backward / forward two directions and honestly
   correct it — **meta forward injection is undetected in v1** (no epoch anchor.
   Evidence-preservation at most), (iv) propagate to §4.2 · §14.2-4 · the threat table · the
   vector plan (`epoch-regression-across-versions` etc.)
2. **The security viewpoint's countermeasure (declared-head seq monotonicity) was rejected by
   the correctness viewpoint's examination**: an honest concurrent writer synced earlier can
   legitimately push under a head older than the previous version, so it cannot be a rule.
   Only epoch monotonicity was adopted (the rejection reason is written into §4.1 itself)
3. **Correctness [Medium] group**: the prev-obtaining path for 409 re-signing (re-fetch +
   verify + recompute. The 409 carries no hash — chaining a signature to an unverified value
   is prohibited) / the declared head of a statement bundled in a compound request is fixed to
   the pre-append head + CAS retries re-sign both / the two-way distinction of fork detection
   (seq ≤ own head mismatch = immediate evidence, seq > own head = re-sync → re-verify) /
   rejecting the 2 ops on the generic chain-append API (updating AUTH_SPEC §6's table) / the
   implementer of NFC normalization = the client (the server checks only, does not normalize) /
   rotate into a deleted environment = 404 + the definition of "all environments" in §7
   (active only)
4. **Contract [High]–[Medium] group**: chain-entries.json is **regenerated**, not "extended"
   (the existing chain becomes invalid under the new consensus rules — the impact list is in
   §8-4) / the wire catalog gained notes on the compound error-contract move, the environment
   list's name → statement replacement, and the 409 carrying no hash / §4.2's encoding note
   (decimal stringification of meta_version and chain_head_seq) / filling in the meta
   negatives suite-mismatch and prev-hash-mismatch
5. **[Low] / [info] group**: "a binding valid at the declared head" added to §6.3-1's key
   selection (rejecting key × head combinations that straddle intervals) / server-side
   reconstruction of the signed coordinates (from the DO chain — §12-5) / the inclusive
   convention of declared-head state + `head-before-environment-create` / the environment-
   creation statement's role made explicit / the stage order of the dek_commitment_hex format
   check (moved into the payload-structure check — the existing verification order unchanged) /
   fixing dangling references in §10 · §11 / the AUDIT dek.registered note / §12-6's "only
   client signature verification" time qualification / pinning the name-resolution and
   denylist comparison rules

### Loop 2 (re-verifying the fixes)

All 3 viewpoints judged the loop-1 fixes **sufficient** (zero remaining [High]. The security
viewpoint also agreed with not adopting declared-head seq monotonicity — it independently
confirmed even "adopting it would not close meta's dominant residual"). Detected and fixed 2
new [Medium]s:

1. **Floor rule (c)'s reference point unspecified (the security and correctness viewpoints
   detected complementarily)**: an implementation reading the reference as "the current epoch
   at chain-sync time" wrongly rejects legitimate data (the old epoch's latest value after
   rotate and before re-encryption — §12-7) (the correctness viewpoint's counterexample), and
   one reading it as "the persisted floor forever" lets a remove → rotate attack spanning an
   offline gap through (the security viewpoint's counterexample). → The reference was
   normalized to "the current epoch chain-derived at the time of the last successful pull
   (with verification) for that environment (recorded in the same transaction as the variable
   floor; chain sync alone does not advance it)" (§6.3). With this, residual (iii) (a returning
   client whose epoch floor is older than the attacker's membership interval) was added to
   §14.3-5
2. **Missing attacker class: demoted current reader (has member history) (contract
   viewpoint)**: because demotion does not force a rotate, "the demoted's member-interval head
   × current epoch" remains a valid forgery coordinate indefinitely until the next rotate. →
   Added to §7 "demotion below member is also accompanied by an all-environment rotate"
   (needs ruling §10-8); split the threat table's reader row; generalized §14.2-3 / §14.3-5's
   attacker-class enumeration to "keys with a membership interval at member or above"
3. [Low] / [info] group also handled: correcting the scope description of meta forward
   injection (dormant meta is one example — it works on any variable / environment) / the
   §6.3 · §7 grant_server v1 notes / §7's rule that rotate 404s are not silently skipped /
   NFC normalization of the client's name-lookup keys + a warning on non-NFC distribution
   (SHOULD) / filling in 8-2's meta-specific verification-rule vectors
   (author-removed-at-head · env-delete-role-insufficient · var-meta-head-before-env-create
   etc.)

### Loop 3 (final check)

All 3 viewpoints confirmed **zero blocking findings**: security = verified that floor (c)'s
pull-time reference is the maximal closure — "no formulation exists that closes residual
(iii) without wrongly rejecting" — and demotion-rotate strengthens the guarantee structure /
correctness = re-running R1's counterexample shows no wrongful rejection, the demote →
rotate → re-encrypt legitimate flow holds, and no new contradictions across the 3 documents /
contract = confirmed the different purposes of AUDIT §4.1 (rotation-needed detection) and the
demotion rotate (a demoted keeps read authority, so staying outside the trigger is correct).
The 2 remaining [info] items (a sentence on the floor reference's update order, 8-2's positive
notation) were also reflected. Progression: loop 1 = 3 High (same root) · many Medium → loop
2 = 2 Medium (new) · a few Low → loop 3 = zero (blocking).

### Automated-review handling after the PR went public (2026-08-03)

- **Bugbot [High]**: AUTH_SPEC §12-5's meta-statement provision referenced the value
  signature's acceptance conditions "the above 1–3" wholesale, and because condition 3 was a
  compound rule of role check + epoch check, a reading existed under which every meta
  operation (which carries no epoch) is rejected (CRYPTO_SPEC §6.4's "role · epoch consistency
  (§6.3's 3–4)" was equally guilty). → Rebuilt the acceptance conditions into 5 items
  (3 = authorization point [shared], 4 = epoch consistency [values only — the same split as
  §6.3's 4], 5 = prev chain) and made the meta reference precise — "1–3 + prev chain
  (metaVersion chain)". §6.4 also states "values only". The client-side §6.3 already said
  "values only" from the start; the problem was only how the server-side reference was written
  (comparison of alternatives — fixing only the reference wording / creating a meta-only
  list / adding epoch to meta [already rejected in §10-6] — this option was adopted for
  removing the compound rule)
- **Bugbot [Medium]**: §12-8's wrap-row cap's enumeration of application paths ("DEK
  registration, environment creation") had not caught up with 12-4's new compound requests →
  updated the enumeration to all paths (the registration API + the compounds [creation,
  rotation]), and also stated the compound application of per-request caps
- **Bugbot round 2 (High 2 · Medium 2)**: (1) applying §12-6's epoch cap against the
  pre-append state would reject every legitimate rotate compound bundling a wrap addressed to
  the new epoch → the evaluation basis was clarified per path (independent API = acceptance
  time / compound = after applying the bundled entry), (2) the server-side coordinate-
  reconstruction provision covered values only → made explicit that it applies to meta
  statements too, (3) the environment_id / epoch consistency check across sub-payloads inside
  a compound was unspecified → a consistency check was added to §12-4, (4) §12-5's item 4 was
  missing "a pre-environment-creation head is invalid" (§6.3's 4 latter half) → transcribed.
  All are precision improvements with no semantic change (Bugbot detected, in stages, places
  where the existing provisions' premises had not caught up with the new compound acceptance)
- **Bugbot round 3 (High 1 · Medium 2)**: (1) the metaVersion CAS retry referenced the
  value-only procedure (re-encryption, prevValueSigHashHex) as "the same procedure" → the
  same-shaped statement procedure was spelled out (fetch → verify → recompute
  prevMetaSigHashHex → re-sign at metaVersion+1. No re-encryption), (2) epoch monotonicity
  (§4.1) had no independent server-side check → stated that "acceptance is current-epoch-only"
  + the current epoch's time monotonicity is structurally guaranteed, so no independent check
  is placed (with a caution for future revisions that might loosen "current epoch only"),
  (3) made explicit that value-signature verification (items 1–5) applies to the version 1
  bundled with variable creation (removing the reading that the creation route bypasses
  verification)
- **Bugbot round 4 (Medium 3)**: (1) the meta-statement storage requirements (per-metaVersion
  signed_bytes hash, signature, author) existed only on the value side → a stored-row
  provision was added to §12-5, (2) a wording bug in the round-2 fix — the coordinate-
  reconstruction enumeration included variable_id, which env meta does not have → written
  separately per §4.2's LP fields, (3) acceptance of environment rename / delete was only "the
  same shape as CAS" and the applicability of signature verification 1–3 + prev chain was
  unreadable → explicit reference from §12-4 to §12-5's meta rules + a note in §12-5 that it
  is common to both Variable and Environment statements
- **Bugbot round 5 (Medium 1)**: §12-2's AAD-consistency-check enumeration lumped "URL
  coordinates (request content only · 422 · authorization may come first)" and "version /
  current epoch (state-dependent · 409 · after authorization)" together, and the same
  failure's status could be read as contradicting §12-5 (an existing ambiguity surfaced by
  this revision's §12-5 expansion) → split into 1a / 1b and limited the §12-3 authorization-
  first exception to 1a only, stating that state-dependent checks and signature verification
  are out of scope (the existence-concealment rationale of §11-2 is also noted)
- **Bugbot round 6 (Medium 1)**: the asymmetry between server acceptance (verify the
  signature under the acceptance-time key) and client verification (the key bound at the
  declared head — §6.3-1 strengthened in loop 2) meant that an actor removed → re-added with
  a different key could declare an old-interval head and produce data that "the server accepts
  but every honest client rejects" (fail-closed but an availability/consistency defect) →
  added to §12-5's 3 the match "the key bound at the declared head = the key at acceptance
  time", and CRYPTO_SPEC §6.4 was aligned to reference §6.3's 1 and 3

- Adding the current epoch to meta signed_bytes (partial mitigation — listed as
  needs-ruling §10-6)
- Compoundizing remove + rotate (future PR candidate — §10-7)
- The existing dek-wrap-signature.json's `description` string is missing signer_user_id
  (`signed_fields_order` is correct. Fixed when PR-2 is implemented — §13)

## 13. Handoff to the next session

- After this PR merges (= spec approval): start from §9's PR-1. Vectors first, and
  `packages/crypto` changes require human review
- Still-valid handoffs not yet started: session-11 §5's 3 ruled follow-up PRs (the
  public-settings endpoint / extracting shared test support / the pull metadata-only mode —
  all outside this session's scope by instruction), the chain-append command family + CAS
  retry (session-11 §5), Phase 2's DO-total-storage guard (session-09 §5), recovery-blob rate
  limiting etc. (session-07 §5)
- Newly filed future work from this revision: CRYPTO_SPEC undecided #12 (environment manifest
  and checkpoint — designed together with Phase 2 head gossip)
- **Intersection with the pull metadata-only mode (session-11 ruling 3)**: when implementing,
  meta-only responses must also include the §4.2 statement + signature (because name → ID
  resolution becomes the pull's substitute path, the verification material must ride at the
  same level)
- When implementing grant_server (Phase 2): apply the §5.2 check to wraps addressed to the
  server key too (design it so the server checks after unwrap and leaves an audit event). The
  grant_server portion joins the rotate compound request's complete wrap set (v1 covers the
  current member set only — AUTH_SPEC §12-4)
- A small fix when implementing PR-2: the existing `dek-wrap-signature.json`'s `description`
  string drops `signer_user_id` from the LP enumeration (`signed_fields_order` is correct.
  Fix it as part of vector regeneration)
