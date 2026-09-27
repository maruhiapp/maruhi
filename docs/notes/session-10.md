# Session 10 notes (member-key uniqueness on the chain = option B of the session-09 ruling. Crypto layer + 2 pieces of cleanup)

Date: 2026-08-03. Prerequisites: PR #21 merged (2-E = DEK wrap registration
signatures. With the merge, CRYPTO_SPEC §5.1 — including the signer_user_id
binding = option A — is owner-approved).
Scope: **consider → implement according to the conclusion** of session-09.md §5's
handoff "prohibit key duplication in the chain consensus rules (option B)"
(executing the 2026-08-03 owner decision "consider in a separate PR".
**What is ruled is only "to consider" — the details, including whether to adopt,
went through multi-option comparison → provisional progress on the
recommendation, with finalization condition = PR review approval = owner
approval of the consensus-rule revision**) + 2 independent PRs (ROADMAP
annotation, settling empty `deks: []`).

## 1. What was done

### Main PR (#22. Exit (a) = adopted as a consensus rule)

Commit order = layer order (spec → vectors first → implementation → tests →
review responses → this memo):

1. **spec**: CRYPTO_SPEC v0.3-draft (new §6.2 bullet "member-key uniqueness".
   Updated 5 factual mentions of "add_member does not reject key duplicates" in
   §5.1 / AUTH_SPEC §12-6 — §5.1's norms = signed payload and verification rule
   unchanged)
2. **test-vectors**: added 6 authz negatives to chain-entries.json (whole-key-set
   reuse, enc-only reuse, sig-only reuse, owner-key reuse, 2 ordering fixes) +
   **committed before the implementation** with a new `valid_appends` section (2
   positive cases at the allowed boundary) (initial commit had 3; the review loop
   added 3 more + 2 positives). Generated via generate_reference.py;
   verify_reference.mjs all PASS
3. **crypto**: implemented a key index in chain-verify.ts (MutableChainState's
   memberEncPubs / memberSigPubs Sets) and the check in applyAddMember. Added
   `duplicate-member-key` to ChainInvalidReason and the api-schema sync list
4. **server**: no implementation change (§6.4 re-runs verifyChain, so it follows
   automatically). Updated only the factual comments in data-programs.ts /
   dek-wrap-sign.ts
5. **tests**: 346 → 363 green (both crypto and server layers. What replaced the
   removed test is in §4)
6. **docs**: this memo

### 2 independent PRs (cleanup that doesn't need the full loop)

- **#23 ROADMAP**: noted PR #20 / #21 completion on the Phase 1 "server" row +
  fixed the unchecked Phase 0 "audit-log schema design" box (AUDIT_SPEC was
  already approved in PR #18)
- **#24 empty `deks: []`**: unified the registration side to the same 400 as the
  deletion side (`Schema.isMinLength(1)`) (§2-6). Closed the handoffs of
  session-08 §5 / session-09 §5

## 2. Detail decisions of the rulings (multi-option comparison → provisional progress on the recommendation. Finalization condition = PR review approval)

### 2-1. Whether to adopt = adopt

| Option | Assessment |
|---|---|
| **Adopt (chosen)** | (i) The unique reverse lookup "key → principal" is a property §5.1 client verification (signer-FP matching), the audit UI (FP display), and §6.3 wrap-target matching all depend on — high value as an invariant. (ii) Eliminating the root cause of the attribution reassignment that option A closed = defense in depth (even if §5.1 breaks via an implementation bug or future revision, it can't happen at the chain layer). (iii) Now — before the CLI / Web (client verification) ship, with no applied chains — is the cheapest time to adopt |
| Decline | Considered whether legitimate key-sharing use cases exist (session-09 §5's question): in v1, 1 user = 1 master keypair (no device-key separation — §3), so there is no legitimate case for **cross-user** key sharing. Multiple accounts for the same person are fine if each generates its own keys. Device-key separation (undecided item #2) is multiple keys **within a user**, orthogonal to this rule (its introduction would come with a §3-side revision). No gain in declining |

### 2-2. Check unit = individual enc / sig keys (not FP units)

- Matching only FP (enc‖sig) lets a sockpuppet reusing one of the two keys
  through. Reusing sig alone = the ambiguity of "multiple principals whose
  dek-wrap signatures verify" (FP matching makes it unique, but the crypto
  layer's uniqueness is still broken). Reusing enc alone = multiple wraps to the
  same key + muddied delete / rotation semantics (a key that should be deleted
  lives on as a remaining member). Neither has a legitimate use case, so the
  stronger form was adopted
- No cross-type comparison needed (new enc == existing sig): X25519 (HPKE) and
  Ed25519 (signature verification) never share a purpose, and byte equality
  means nothing given different encodings — it doesn't even imply scalar reuse
  (no confusion attack can be built). Confirmed in review

### 2-3. Prohibition scope = current member set only (not whole history)

- **remove → re-add with the same key (the same person returning) is not
  prohibited** (same line as session-09 §5). Scoping to the current set makes
  this hold naturally with no exception clause
- **Reusing a removed member's key under a different user_id is also allowed**:
  equivalent to an act within the admin / owner's authority "can add a member
  with any public key". The FP stays on the chain so it's mechanically
  traceable, and wrap attribution is independently defended by option A
  (signer_user_id)
- A whole-history ban would need an exception clause like "the same user_id may
  reuse its own past keys", adding complexity, while the extra defense
  (prohibiting the same key reappearing under another name) buys nothing on the
  permission model
- **Constraints on existing fixtures**: `authz-admin-adds-admin` (which pins
  re-adding removed user-member-0002's same keys as insufficient-role) keeps its
  expected reason unchanged thanks to current-set scoping + role-first check
  order. `chain-negative.ts`'s "add_member duplicate" is also unaffected because
  the reused key's owner is already removed (stays duplicate-member)

### 2-4. Rule layer = consensus rules (exit (a))

| Option | Assessment |
|---|---|
| **(a) Consensus rules §6.2 (adopted)** | A property we also want clients (§6.3) to reject (clients depend on it as an invariant). Peer to `duplicate-member` (user_id uniqueness) as its key version. The §6.1 size-cap vs §6.4 precedent = "semantics that would fork if implementations disagree are consensus rules; tunable resource protections are acceptance policy" — key duplication is the former |
| (b) Acceptance policy §6.4 | A self-host could disable it and clients couldn't depend on the invariant (halving the value of layering). Not breaking consensus has its merits, but it's inconsistent with this item's purpose |

- No backward-compatibility exception clause, since pre-release + no applied
  chains exist (§6.2 states "no chain accepted before the rule was introduced
  exists")

### 2-5. Op coverage and reason code

- genesis: the member set is empty, so duplication is structurally impossible.
  The genesis-derived owner key is a comparison target for later add_member
  (stated in the spec. Vectored in review loop 1 as a [high])
- change_role / remove_member / rotate_epoch: register no keys → out of scope
- grant_server: collision between the server enc key and member keys is out of
  scope (different recipient class and FP definition — §9. owner-only + wraps to
  the server are Phase-2 unimplemented). **However, since grant_server itself is
  an already-live consensus rule, §6.2 notes that prohibiting it in Phase 2 will
  require grandfathering** (a review loop-1 finding. Makes the deferral cost
  visible)
- Reason code: `duplicate-member-key` (consistent with the `duplicate-member`
  family). The check order role → duplicate-member → duplicate-member-key is
  pinned by vectors including reason codes

### 2-6. Unifying empty `deks: []` (independent PR #24) = align (registration side also 400)

- No meaningful use case calls an empty registration (first registration's empty
  set is already rejected by the exact-match requirement's 422
  recipient-missing; an appended empty set is a purely meaningless call). A
  silent no-op hides client bugs (mistaking "sent an empty array" for
  "registration completed"). Pre-release, so changing the wire contract costs
  nothing. The same discipline as the deletion side: "don't silently succeed"
- The keep-as-is option (non-destructive, no real harm) was rejected for
  permanently costing explanation of the asymmetry and hiding bugs
- session-09's test pinning the current behavior was reworked into a negative
  (400 + no audit row). The bundled deks of environment creation are out of
  scope (unchanged per the task instructions)

## 3. Gotchas & environment findings

- **Appending to chain-entries.json = regeneration formatting diff** (applying
  the session-09 §3 finding): the generation tool's JSON output (Python
  `indent=2`) and oxfmt differ in array wrapping, but **regenerate → apply oxfmt
  to all vector JSON** left the existing 5 files diff-free and
  chain-entries.json with only added lines. Byte-identical reproduction of
  existing parts is mechanically checkable via git diff (policy noted in the PR)
- fallow's complexity gate: adding a `?? ""` fallback to the test case table
  (semanticCases) exceeded the cyclomatic threshold. Since missing vector-pinned
  keys are fixture corruption, resolved it by routing to a throwing helper
  (keysOf. Same style as entryAt)
- Mutation experiments became the main review equipment: green alone can't show
  "does the test constrain the rule". A reviewer demonstrated ([high]) that a
  mutation deleting the 2 index-registration lines in applyGenesis passes all
  tests green (= owner-key reuse unchecked); after adding the vector, the same
  mutation fails at both crypto and server layers. Also verified that mutations
  for check-order swap and index residue on remove are likewise caught by
  multiple tests
- Discarding `.wrangler/state` (session-09 §3's direct-DDL-change workaround)
  was unnecessary in this environment (no state generated). Environments with
  main's state left locally still need it discarded

## 4. Impact on existing tests (what replaced the removed test)

- `data.test.ts` "rejects third-party re-submission into a deleted slot, even
  via a duplicated chain key" (session-09) assumed key-duplicate add_member, so
  it was reworked: (1) the third party became **a legitimate member with their
  own keys**, keeping the signer-mismatch check (422 signature-invalid); (2) a
  new chain-layer test was added where the key-reusing sockpuppet's add_member
  itself gets 422 duplicate-member-key. The removed strongest form "same key,
  different user_id" stays pinned by the crypto layer's `transplant-signer`
  vector + the "rejects wraps signed by someone other than the caller" test
  (after §6.2's introduction that state cannot exist on the server, so the
  crypto layer is the only and correct pinning site)
- `chain-negative.ts`'s "add_member duplicate" check: unaffected under the
  "current member set only" option (the reused key's owner is removed. The
  expected reason stays duplicate-member)
- Other cross-checks done: `data.test.ts`'s recipientEncPubHex reuse (around
  lines 330 / 350) is wrap-layer only and puts no keys on the chain, so it's
  unaffected. No key-duplication assumptions in membership / audit / auth tests

## 5. Handoff to the next session

- **CLI implementation (the next session's main task)**: `maruhi run` (memory
  injection) / push / pull / device flow / OS keychain + §6.3 client sync check
  + §5.1 distribution-time signature verification. Chain verification uses
  @maruhi/crypto's verifyChain as-is (including §6.2's key uniqueness). The
  client performs wrap generation → signDekWrap → registration as one sequence,
  and the distributing side matches RecipientDek's signerUserId +
  signerKeyFingerprintHex against chain history (continuation of session-09 §5's
  handoff)
- **grant_server vs member-key collision check (Phase 2)**: as §6.2's note says,
  introducing it needs a grandfathering clause (grant_server is an already-live
  consensus rule, so the "no existing chains" argument doesn't apply). Consider
  together with grant_server's data-plane implementation (server-addressed
  wraps)
- **Caution when implementing §6.3 differential verification**: the key index
  (Sets) is local state within one verifyChain run. In differential verification
  resuming from a verified position, rebuild the index from the verified members
  Map (reconstruction is trivial since the rule guarantees uniqueness — a
  review loop-1 observation)
- **Phase 2's F (DO storage-total guard)**: session-09 §5's design memo (the
  two-tier accounting byte budget + databaseSize alarm) remains valid and
  unstarted
- session-07.md §5's handoffs (the CLI's 409 retry loop, recovery-blob rate
  limiting, etc.) remain valid and unstarted
- The empty `deks: []` handoff (session-08 §5) is **closed** by PR #24

## 6. Review→fix loop (inside PR #22. 3 parallel review angles → fix)

### Loop 1 findings and responses

1. **Genesis-derived owner-key reuse unchecked (tests [high])**: all 3 negatives
   were biased to add_member-derived keys, and a mutation experiment proved a
   mutation deleting applyGenesis's index registration passed 355 tests green.
   → added vector `authz-add-member-duplicate-owner-key` (confirmed the mutation
   now fails)
2. **role → key check order unpinned (tests [low])**: → added vector
   `authz-add-member-role-precedes-duplicate-key` (admin granting role admin to
   the key-reuse target → insufficient-role)
3. **Missing positive for "reuse of a removed key under another user_id is
   allowed" (correctness / tests [low]) + re-add positive absent from the vector
   layer (security [low])**: → **added a `valid_appends` section** to
   chain-entries.json (2 positive cases at the allowed boundary. Fails a wrong
   implementation that bans duplication against whole history). Made the
   implementation test vector-driven, and also added index re-formation after
   re-add (re-rejection of the duplicate at seq 11)
4. **README convention 12's attribution of order dependence was inaccurate
   (tests [low])**: corrected to note that authz-admin-adds-admin is
   order-independent (the reused key's owner is removed)
5. **Backward-compat cost of deferring grant_server collision not documented
   (security [low])**: added the grandfathering note to §6.2 (§2-5)

### Loop 2 (re-verify the fixes)

All 3 angles have **zero remaining [high] / [medium] findings**. The reviewer
independently reproduced the mutation experiments (deleting the genesis index →
only the new vector fails; swapping check order → 2 tests fail; index residue on
remove → 3 tests fail). The remaining 1 [low] + 2 [info] also handled: added
payload_bytes / entry_bytes / entry_hash matching to verify_reference.mjs's
valid_appends check, vectored the user_id → key order too
(`authz-add-member-duplicate-user-precedes-key`), and updated the header
comment.

### Loop 3 (final confirmation)

All 3 angles confirmed **zero findings** (security = the prohibited side,
allowed side, and ordering are pinned entirely at the vector layer /
correctness = closed through the reference verifier's completeness / tests &
contract = the 5-point mutual constraint[spec, generation tool, vectors,
implementation, both test layers]is complete). Progression: loop 1 = 1 high, 5
low → loop 2 = 1 low, 2 info → loop 3 = zero. `bun run check` (363 cases) +
`wrangler deploy --dry-run` + all crypto tests passing on 4 runtimes. Next: mark
ready → merge on owner instruction (merge = owner approval of the §6.2
consensus-rule revision).
