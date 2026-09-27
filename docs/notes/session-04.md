# Session 04 memo (packages/crypto implementation — Phase 1 kickoff)

Date: 2026-08-02. Prerequisite: all of session 03's PRs (#8–#11) are merged to main.
Scope: packages/crypto (the E2EE core) only. CRYPTO_SPEC-conformant + all test vectors passing.

## 1. What was done (commit order = layer order)

1. **Test-vector completion** (committed before implementation): extended chain-entries.json to seq 5–9
   (add_member(reader) → change_role(admin) → grant_server → rotate_epoch(executed by admin) →
   revoke_server). Added 4 signature-family negatives + 7 authorization-family negatives (`kind: "authorization"`) +
   `expected_head_states` (expected values of the state-derivation API). Extended verify_reference.mjs; all 99 checks PASS
2. **§2.1 encoder** + typed errors + the `internal.package` boundary
3. **§3 keys**: X25519 (via the panva hpke API) / Ed25519 (WebCrypto), FP, DEK generation
4. **§4 variable encryption**: AES-256-GCM + LP AAD. Nonces are internally generated only (no injection API)
5. **§5 DEK wrap**: HPKE Base one-shot Seal/Open. Open takes a KeyPair only
6. **§6 chain**: canonicalization, signing, verification (including role permissions), state derivation (member set + valid grants + observed epochs)
7. **§8 recovery wrap**: HKDF (salt = empty) + AES-256-GCM
8. **3-environment test harness**: vitest for node / workerd / browser + direct Bun execution. Added an independent step at CI step 11

All 123 checks PASS across all 4 execution environments (Node / workerd / Chromium / Bun 1.3.14).

## 2. Implementation decisions (the points to watch in PR review)

- **Error design settled as (b)** (2026-08-02; the recommendation was adopted after comparing 7 options): crypto is Effect-free pure functions + a discriminated union (`CryptoResult`); the Effect wrapper lives on the core side. The deciding factors were keeping the TCB's dependencies at zero and the asymmetry of reversibility ((b)→(a) is an additive change, (a)→(b) is breaking)
- **Server key FP = `SHA-256(server_enc_pub)[:16]`** (owner ruling 2026-08-02; 5 options compared):
  the server holds only an enc key (§9), so §3's user FP definition (enc||sig) cannot apply.
  The domain-separation option was rejected because "the preimage spaces are already separated by input length — zero cryptographic gain — and it is inconsistent with the session 03 decision that FP is outside LP". Codified in CRYPTO_SPEC §9
- **grant_server's scope_environments** (owner ruling 2026-08-02; 6 options compared): LP-encode the
  environment-ID list and place its lowercase hex string as one payload field on the outer LP
  (nested LP, same shape as the binary_encoding convention). List order is part of the signed data. Sorting is
  a generation-time SHOULD, not a verification requirement (scope is never byte-compared, and enforcing it would require regenerating existing vectors).
  Codified in CRYPTO_SPEC §6.2
- **Re-grant to the same server key is accepted only as a scope widening (old ⊆ new)** (owner ruling
  2026-08-02. Initially implemented as a replacement, but allowing narrowing opens a hole that bypasses revoke_server + rotate_epoch (§7's all-environment rotation duty). Narrowing must always go through the revocation path.
  Pinned by vector `authz-grant-scope-narrowed`; rejection reason code `grant-scope-narrowed`)
- **Epoch = a per-environment counter (initial value 1; rotate_epoch is always +1)** (owner ruling 2026-08-02,
  option 3. Initially deferred as "monotonicity unverified" → the Bugbot HIGH finding prompted a 7-option comparison and a ruling.
  Strict +1 prevents not just rewinds (re-exposure of an old DEK retained by a removed member) but also
  the "one member-permission signature jumps to the safe-integer ceiling and permanently disables
  environment rotation" DoS that mere strict increase does not prevent. Rejection reason code `epoch-out-of-sequence`.
  Codified in CRYPTO_SPEC §3 / §6.3. The re-grant rule is also codified in §6.3)
- **The error discriminator is `kind`, not `_tag`**: it collides with oxlint's no-underscore-dangle.
  The Effect mapping is done per kind on the core side
- **Field-size limits** (owner ruling 2026-08-02, option 2; 4 options compared): free-string fields are
  ≤ 1024 bytes in UTF-8; scope_environments is ≤ 256 elements. Exceeding them is invalid-payload.
  Because the limits are "consensus rules of chain validity" (implementations disagreeing splits the chain), they were codified as spec constants in
  §6.1 and pinned by vectors. The check runs in two stages — a length pre-check → actual encode —
  so the check itself does not allocate huge buffers. When implementing server §6.4, add a total-entry-size limit
- **Verification order**: framing → payload structure → actor resolution (non-member / FP mismatch) → signature →
  authorization + semantic checks. The authorization-family vectors' expected_reason values are pinned assuming this order
- **Using Ed25519's determinism in tests**: every vector entry is re-signed from its seed and signature_hex is
  compared for exact equality (pinning canonicalization and signing at once. WebCrypto Ed25519 is RFC 8032 deterministic)
- **Private keys default to extractable=false**. Only at generation needing export
  (recovery-blob creation) does the caller explicitly opt in. Nonces and HKDF salts cannot be injected via the API (structurally excluding misuse)

## 3. Pitfalls and environment learnings

- **The system Python's cryptography is broken** (`_cffi_backend` missing). Created a venv and
  ran the reference tool with `pip install cryptography` (50.0.0). Regenerating the vectors was
  verified by diff to be bit-identical to the existing bytes for entries 1–4 (append-only extension)
- **Chromium revision mismatch for browser tests**: the preinstalled one is chromium-1194 (playwright
  1.56 line), but the repo's playwright pin is 1.62.1 (requires revision 1234). A bare
  `bunx playwright install chromium` hits the trap of **resolving to the global cache's 1.56.1 and no-opping**.
  Resolving the repo's pin with `cd apps/web && bun x playwright install chromium` and downloading
  1234 made the browser project PASS. CI should not hit this since bunx resolves the repo's
  node_modules (a safety install is included in step 11)
- **fallow's complexity gate** (error at cyclomatic ≥ 10 / over 60 lines) trips easily on crypto
  verification code. Resolved by splitting into per-op apply / shape functions (more readable in the end)
- The root vitest glob (packages/*/vitest.config.ts) is an "exact filename match", so
  vitest.workerd.config.ts / vitest.browser.config.ts can coexist without being picked up by step 7

## 4. Handoff to the next session

- **After the PR merges, check off ROADMAP's "E2EE core"** (not done this session since the PR is awaiting review)
- All 4 spec interpretations + the error design are owner-ruled (2026-08-02) and codified in CRYPTO_SPEC
  §3 / §6.2 / §6.3 / §9. When implementing core, write a wrapper that maps `CryptoResult` per kind
  into Data.TaggedError (a consequence of ruling (b))
- Unimplemented (intentionally out of scope): §6.3's DEK-wrap-destination match check and head gossip (the
  sync logic taking the verification API's ChainState as input), §6.4 server-side verification and CAS, §7 rotation
  orchestration, the recovery code's Base32 display and the master-key blob's serialization format (at CLI implementation time)
- spikes/ is kept (the spike-c setup's porting is done; the deletion call is the owner's)
- The reference tool's venv procedure is not written in test-vectors/README.md (disposable tool).
  If regeneration is needed, see §3 of this memo
