# Session 09 notes (implementing review rulings, PR B = 2-E: require signatures on DEK wrap registration)

Date: 2026-08-02. Prerequisites: PR #20 merged (PR A = suite persistence, row cap,
repair path, dek audit events. The 3-D suite is already on the wire and in stored rows,
so this PR's premise that signed bytes include the suite holds).
Scope: owner ruling 2-E from session-07.md §3.5 (crypto layer). **That 2-E itself will
be done is already ruled — every comparison in this note is a "detail"; the
finalization condition = PR review approval.**

## 1. What was done (commit order = layer order)

1. **spec**: CRYPTO_SPEC v0.2-draft (new §5.1 = per-wrap Ed25519 registration
   signature. Updated the §11 vector list), AUTH_SPEC v0.5-draft (§12-2 wire /
   §12-6 acceptance conditions / §12-8 verification-cost note), AUDIT_SPEC v0.4
   (§3.3 dek.registered gains signer FP — **a revision of an owner-drafted
   document; the changes are called out in the PR description**)
2. **test-vectors**: committed dek-wrap-signature.json (1 positive case + 9
   negative cases) **before the implementation**. Generated with
   pyca/cryptography → cross-checked by WebCrypto (Bun) verify_reference.mjs, all
   PASS. The vectors themselves are also human-review targets (noted in README)
3. **crypto**: dek-wrap-sign.ts (buildDekWrapSignatureBytes / signDekWrap /
   verifyDekWrapSignature). Built only from existing parts (WebCrypto Ed25519 +
   §2.1 LP). Added DekWrapSignatureInvalid to CryptoError and an Effect wrapper
   in core
4. **api-schema**: WrappedDek gains signatureHex, RecipientDek gains signatureHex
   + signerUserId + signerKeyFingerprintHex, reject reasons gain
   signature-invalid
5. **server**: dek_wraps gains signature_hex / signer_user_id /
   signer_key_fingerprint (direct DDL change), wired ensureWrapSignatures into
   the shared point of every wrap-insertion path (ensureWrapSetAcceptable),
   dek.registered gains signer FP, the distribution response gains signature +
   signer. StoredChain gains genesisHashHex (the signed project_id comes from the
   DO's own chain)
6. **tests**: +25 cases worth (313 → 338 green). Includes path coverage
   (registration API + bundled environment creation), client verification on
   distribution, and attribution matching on the repair path
7. **docs**: this note

## 2. Detail decisions of the rulings (multi-option comparison → provisional progress on the recommendation. Finalization condition = PR review approval)

### 2-1. Signature unit = per wrap (as noted at ruling time)

| Option | Content | Assessment |
|---|---|---|
| **A: per wrap (adopted)** | 1 signature per wrap addressed to 1 recipient | At distribution the recipient can verify the wrap addressed to them **standalone** (as noted at ruling time). Orthogonal to the repair path (2-D)'s individual delete / re-register — the signatures of remaining wraps are unaffected by deletion |
| B: per request (set) | 1 signature per registration | Fewer signatures, but the recipient must fetch the whole set to verify (distribution is only to the addressee — contradicts §12-6). Individual deletion changes the signed set and breaks verification |

### 2-2. Canonicalization of the signed payload

`signed_bytes = LP("maruhi/v1/dek-wrap-sig", project_id, environment_id, epoch,
recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex)`

- **Suite binding happens in the domain string** (`<suite>/dek-wrap-sig`): same
  shape as the §5 HPKE info (`maruhi/v1/dek-wrap`). A separate suite field would
  just be double-binding with no gain (pinned by negative `suite-mismatch`)
- **Binary sequences go on the LP as lowercase hex strings**: same convention as
  §6.2 grant_server's scope_environments_lp_hex (an open question in the task
  instructions → adopted following precedent). The crypto implementation
  requires the signed hex fields to be lowercase and fixed-length (allowing
  uppercase hex would give the same wrap multiple canonical forms and break
  signature uniqueness)
- **Include recipient_enc_pub_hex in the signed payload (added proposal beyond
  the ruling)**:

| Option | Assessment |
|---|---|
| **Include (adopted)** | Every field of the wire WrappedDek is bound by the signature, leaving no unbound field (eliminating room for future drift if unbound fields ever gain meaning). The recipient knows their own public key so standalone verifiability at distribution is preserved (and RecipientDek doesn't need the enc pub added) |
| Don't include (the ruling's minimal enumeration) | One could argue it's redundant since HPKE cryptographically binds ct to the recipient key, but a state where "the signature covers only part of the wire" carries high audit and implementation explanation cost |

- **Include signer_user_id in the signed payload (added proposal beyond the
  ruling, part 2 — in response to review loop 1's [medium] security finding)**:
  a signature alone only fixes "the holder of key K signed"; the chain's
  consensus rules allow multiple members holding the same public key (add_member
  does not reject key duplicates). A malicious admin could add a sockpuppet M′
  reusing existing member A's public-key set, then re-insert "a wrap A signed in
  the past" into a slot emptied via the repair path as M′ — key verification
  passes and the attribution records M′ (attribution reassignment). Baking the
  signer's own user_id into signed_bytes makes the signature itself reject this.
  The signer knows their own user_id and the recipient can reconstruct it from
  the distributed signerUserId, so standalone verifiability is preserved. The
  alternative (invalidating key-duplicate add_member in the chain consensus
  rules) is a §6 consensus change with a large blast radius, so we took the
  §5.1-local fix before freezing the wire / vectors

### 2-3. Replay handling = strict "API caller = signer" equality (adopting the task instructions' starting option)

- **Acceptance condition**: the server verifies each wrap's signature only
  against the **caller's sig key derived from the chain at acceptance time**. No
  signer ID on the wire (the contract is that the caller is the signer)
- **Verified compatible with every v1 registration path**: environment creation
  (the creator wraps and registers themselves) / post-rotation (the operator
  does both) / backfill to a new member (the inviter does both) / re-registration
  on the repair path (the re-registrar does both) — in each, CRYPTO_SPEC §7's
  "the wrap's performer = the client holding the DEK" naturally makes
  signer = registrar
- **Consistency with 2-D (delete → refill)**: the path where a third party
  re-inserts "a past wrap signed by someone else" into a deleted slot is closed
  by signer mismatch. session-08 §4's v1-tolerated "poison refill of an empty
  slot by a member" was hardened into a form where attribution is pinned by
  server distrust (attribution, not poison prevention — as ruling E positions it)
- **No timestamp / nonce in the signed payload**: a signature is attribution, not
  a freshness proof (stated as semantics in CRYPTO_SPEC §5.1). Re-registering
  the same signature in the same context has no effect beyond "restoration of
  the same content by the same signer" (overwrite is forbidden and deletion is
  admin-only). If freshness becomes needed it goes through a spec revision

Alternatives considered:
| Option | Rejected because |
|---|---|
| Put signerUserId on the wire and allow third-party submission | No v1 path needs it; it would only permit re-insertion of others' signed wraps (muddying attribution) |
| Give signatures freshness via challenge / nonce | The signature's purpose is attribution. Under slot semantics (no overwrite), replay does no real harm, so extra round-trips and spec complexity aren't justified |

### 2-4. Verification rule = "chain-derived sig key at registration time"

- Server verification uses the keys of the current member set at acceptance time
  (= registration time under permit serialization). The implementation uses the
  ChainMember sigPubHex returned by requireMemberState as-is
- **CRYPTO_SPEC §5.1 documents how past signatures surviving member removal are
  verified**: client verification at distribution uses "the sig public key bound
  to the signer's user_id in the verified chain history whose signer FP matches"
  (payload of genesis / add_member). Since the chain is append-only, removed
  members' keys of the time remain usable for verification. RecipientDek returns
  signerUserId + signerKeyFingerprintHex precisely for this matching (the FP
  removes ambiguity when the same user_id was removed → re-added with a
  different key)
- Client-verification logic itself is implemented when the CLI / Web are
  (together with §6.3. Out of scope — the wire and storage were made to enable
  it)

### 2-5. Server verification cost (an open question in the task instructions)

- Worst case: 10,000 wraps/request × Ed25519 verify runs under permit
  serialization. That is **the same order as full re-verification of a chain
  append (§6.4: max 10,000 entries × Ed25519)** and stays within already-accepted
  resource-consumption levels (noted in AUTH_SPEC §12-8)
- Lowering the per-request cap was considered and **declined**: it would break
  §12-8's invariant "wraps/request ≥ member count bound by the chain-entry cap"
  (incompatible with the exact-match requirement of first registration). Real
  sets are member-count-sized (a few to a few dozen)
- The implementation verifies signatures only after every cheap check has
  passed (count → recipients/duplicates → row cap → set membership), so no
  Ed25519 is wasted on rejected requests

### 2-6. dek.registered's signer FP (ruling B's "copy E's signer FP")

This is the **first change to break** the existing premise "only the chain
mirror carries actor_key_fingerprint" (the dataEvent JSDoc in data-plane.ts and
the audit test's NULL assertion), so the comments, tests, and AUDIT_SPEC §3.3's
premise were revised together: only dek.registered is the exception (it copies
the registration signature's signer FP — for cross-matching audit rows with
off-chain signatures). dek.deleted carries no signature, so it stays NULL as
before (pinned by a test).

## 3. Gotchas & environment findings

- **Adding the signature pushed a max-count wrap registration into transport
  413**: one wrap's wire grew to ~500 bytes, so a 10,001-item request (~5 MB)
  exceeded MAX_REQUEST_BODY_BYTES (4 MiB) and returned a bare 413 before
  422 (dek-wraps-per-request). To preserve **reachability of declared errors**
  (the discipline from session-08's review loop), the limit was raised to 8 MiB
  (an implementation detail, not a spec value. The theoretical extreme — a
  1024-byte user_id — can still hit 413 first, as before — within the existing
  §12-8 note)
- **Direct DDL change on dek_wraps (adding NOT NULL columns)**: `.wrangler/state`
  created on main must be discarded before running on this branch (same as
  session-08.md §3. `CREATE TABLE IF NOT EXISTS` does not alter an existing
  table)
- **The signed project_id comes from the DO's own chain**: added genesisHashHex
  (= the project ID — §6.4) to StoredChain so it doesn't rely on the worker's
  declared value (defense against worker-side bugs; same posture as the
  project-id-mismatch check at init)
- The generation tool's (generate_reference.py) JSON output differs from the
  repo's oxfmt formatting in array wrapping. Existing vectors reproduce
  byte-identically, but formatting alone would show a diff, so only the new file
  was committed after oxfmt
- fallow's duplicate detection already excludes the same structural clone as
  session 08 (data-store.ts query skeleton) as an inherited finding. The gate is
  green

## 4. Known constraints / v1 tolerances

- The signature is **attribution**, not poison-wrap **prevention** (as ruled). A
  properly-caller-signed undecryptable blob is accepted — but its attribution is
  pinned to the signature + FP by server distrust (semantics pinned by the test
  "accepts a caller-signed poison wrap")
- Client verification at distribution (matching chain history) is unimplemented
  (comes with the CLI / Web). The test's verifyDistributedWrapSignature is a
  verification helper that pre-empts that shape
- suite × epoch binding is deferred until the v2 design (as ruled. Since the
  signature's domain string includes the suite, the v2 migration produces
  signatures under a new domain)
- Wraps addressed to the server key of a grant_server'd project (Phase 2) remain
  unimplemented. On introduction, this spec (§5.1's caller = signer) should apply
  as-is to "the signer of a server-key-addressed wrap" (the wrap performer is the
  rotation performer — §7)

## 5. Handoff to the next session

- **Prohibiting key duplication in the chain consensus rules (2026-08-03 owner
  decision: consider in a separate PR)**: §2-2's anti-attribution-reassignment
  fix closed this PR via signer_user_id binding (option A), but option B —
  forbidding "add_member tolerating multiple members with the same public key"
  itself in the chain consensus rules — should be **considered in a separate PR
  as a future defense layer (defense in depth)**. It's a crypto-layer change
  involving a CRYPTO_SPEC §6 consensus-rule change + chain-entries.json vector
  revision (adding an authz negative for key-duplicate add_member) + verifyChain
  implementation, so it must follow the same order as this PR: "spec revision →
  vectors first → human review". Discussion points at that time: whether there
  are legitimate key-sharing use cases (v1 has no device-key separation), and
  drawing the line so remove → re-add with the same key (the same person
  returning) is not prohibited
- **Memo on the implementation shape of Phase 2's F (DO storage-total guard)
  (session-08 discussion outcome)**: design it as "**accounting byte budget
  (primary, deterministic) + databaseSize alarm (secondary, measured)**". Primary
  = per-insertion-path row-size accounting for a deterministic budget (same
  shape as §12-8's cumulative ciphertext bytes; testable and exact under
  permit), secondary = a measured dike that turns `ctx.storage.sql.databaseSize`
  threshold crossings into typed errors (covering consumption outside
  accounting: fragmentation, indexes, audit-log bloat). Because it is the only
  defense line covering the indefinite retention of audit_events (AUDIT_SPEC
  §5.3), design it together with a measured judgment of the audit-log
  aggregation policy (corresponds to AUTH_SPEC §12-8's Phase 2 preview)
- For CLI / Web implementation: **the client performs wrap generation →
  signDekWrap → registration as one sequence** (the signer = the caller of the
  registration API). The distributing side matches RecipientDek's
  signerUserId + signerKeyFingerprintHex against chain history and verifies
  with verifyDekWrapSignature before unwrapping (implement together with §6.3's
  client sync check)
- Handling of the registration API's empty `deks: []` (no-op 204) remains a
  handoff (session-08 §5. Even after mandatory signatures, an empty set stays a
  no-op that passes with zero signatures — it's non-destructive so there's no
  real harm, but aligning it with the deletion side's "empty enumeration 400"
  would be a small independent PR)
- session-07.md §5's handoffs (the CLI's 409 retry loop, recovery-blob rate
  limiting, etc.) remain open and valid

## 6. Review→fix loop (inside PR #21. 3 parallel review angles → fix)

### Loop 1 findings and responses

All 3 angles (security / crypto, correctness / concurrency, tests / contract)
had zero [high]. Accepted and fixed items:

1. **Signer identity not bound into signed_bytes (security [medium])**: because
   the chain tolerates key-duplicate members, attribution reassignment to a
   key-reusing sockpuppet could succeed. → **Added signer_user_id to
   signed_bytes** (see §2-2. Spec, vectors, crypto, server, and tests revised
   together. Pinned by negative `transplant-signer`, and on the server side by
   an integration test "re-insertion by a STRANGER reusing a MEMBER's key set →
   422")
2. **signatureHex malformed 400 untested (tests [medium])**: tested 3 variants —
   uppercase hex / wrong length / non-hex — plus the missing-field 400 on the
   registration API path
3. **No negative for "third-party re-insertion of an originally-signed wrap" on
   the repair path (tests [medium])**: item 1's integration test pins the
   stronger form (same key, different user_id) rather than simple signer
   mismatch (different key)
4. **Low / optional responses**: added non-empty validation of suite /
   signerUserId in crypto, added a signature bit-flip negative vector, tested
   "re-registration of the same signature by the original signer = 204" (the
   positive side of §5.1 semantics), pinned the current empty-`deks: []` no-op
   204 behavior of the registration API in a test (spelling out the handoff),
   made the audit test's epoch-2 FP check loop over all rows, and wrote into a
   comment the runtime assumption ensureWrapSignatures' die relies on (raw
   Ed25519 import only checks length)

### Observations recorded but not adopted (judged as needing no response)

- **Flat-concat negative vector** (security [low]): not added because the
  positive case's signed_bytes match check directly fails a mis-encoded
  implementation (reason noted in README). chain-entries' flat-concat had the
  subtlety of nested LP to guard, but this signed payload is a single flat LP
  level
- **MAX_REQUEST_BODY_BYTES 8 MiB is shared across all endpoints** (security /
  correctness [low]): the pre-buffer cap including unauthenticated routes
  doubles, but it's a marginal availability-only change. Two-tiering restricted
  to the DEK registration route is for when it becomes needed (already noted in
  §3)
- **verifyDekWrapSignature's catch-all** (correctness [info]): consistent with
  the "don't throw on untrusted input" contract (the verifyEntrySignature
  precedent); no change needed
- **Asymmetry between crypto's epoch lower bound (≥ 0) and the wire's (≥ 1)**
  (correctness [info]): same choice as dek-wrap.ts's checkEpoch. The server's
  epoch-out-of-range fires first

### Loop 2 (re-verify the fixes)

All 3 angles confirmed **zero remaining [high] / [medium] findings**:

- Security = the signer_user_id addition fully closes the finding (the
  integration test is the attack's strongest form = key match, user_id
  mismatch) and introduces no new ambiguity, cross-protocol confusion, or
  semantic breakage. A side effect closed off servers mis-declaring
  signerUserId: RecipientDek's signerUserId is now cryptographically pinned by
  the signature, so client verification at distribution would catch it
- Correctness = a non-structural change adding 1 field to the verification
  context; permit serialization and the "all-verify → single Effect.sync write"
  structure are unchanged
- Contract = all 6 loop-1 findings adequately addressed. New-test quality and
  independence are fine

The 2 [low] items left at loop 2 are also handled: added "signer" to §5.1's
semantics bullet's bound-field enumeration, and added a client-verification
negative for a forged signerUserId on the distribution path to the integration
tests. `bun run check` (346 cases) + `wrangler deploy --dry-run` + CI (check)
all green.

### Loop 3 (final confirmation)

All 3 angles confirmed **zero findings** (security = the 2 [low] fixes are
correct, and deferring option B to a separate PR leaves no security gap /
correctness = 6403810 has no production-code change and no regression /
contract = enumeration complete). Progression: loop 1 = 3 medium, several low
→ loop 2 = 2 low → loop 3 = zero. Next: mark ready → handle Bugbot / Security
Agent findings (drive-to-green) → merge on owner instruction.
