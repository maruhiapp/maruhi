# KL3 spec revision drafts — the master-key wrap ledger (drafted 2026-09-12, pending owner approval)

**Position**: the deliverable of the KL3 phase 1 (design session). The overall design, the iterated ruling record, and the implementation split live in docs/notes/integration-options.md §3 supplement 19. This file is the **as-drafted copy of the revision text** that was applied to the three canonical documents (CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC). **On 2026-09-12 the owner approved the 13 design items, and they were applied to the canonical texts the same day as K1** (CRYPTO_SPEC 0.9-draft §8 / §11 / §13 / §14.3, AUTH_SPEC 0.21-draft §5 / §13, AUDIT_SPEC 1.6-draft §3.1). From here on, the canonical texts are the source of truth; this file remains as a record of the process (if a discrepancy arises, the canonical texts win).

Each draft is shown as a "substitution" or an "addition". Parts of the existing text that do not change are not quoted.

---

## A. CRYPTO_SPEC revision proposals

### A-1. Substitution of §8 (including the heading)

> ## 8. Master-key wrap ledger (recovery codes, passkey PRF, guardians, handoff)
>
> **Revised 2026-09-12 (KL3)**: the former §8 "recovery code" is generalized into **a set (ledger) of per-recipient wraps** over the same master-key blob. The recovery-code path's structure, byte strings, and test vectors (`recovery-wrap.json`) are **unchanged**; this revision only adds paths (no re-wrapping or migration of existing blobs). The design record is docs/notes/integration-options.md supplement 19.
>
> ### 8.1 Common provisions
>
> - **Wrap target B**: an opaque blob of the user master private keys (enc / sig). The serialization format is a client (CLI) contract; the server does not care (currently = JSON of a keychain record. The restoring side stores it after passing self-verification)
> - **Recipient classes**: (S) symmetric KEK — `recovery-code` / `passkey-prf`. (G) guardian group — `guardian`. (H) handoff — ephemeral recipient (holds no persistent row in the ledger. The same response scope as §9.1's lease wrap)
> - **Wrap** (common to class S / G / H and device migration): AES-256-GCM, a 96-bit random nonce (stored alongside the ciphertext). AAD in §2.1's encoding:
>
>   ```
>   master_wrap_aad = LP("maruhi/v1/master-wrap", user_id, kind, wrap_ref, mode)
>   ```
>
>   `kind` ∈ {`passkey-prf`, `guardian`, `device`}. `wrap_ref` = passkey-prf: `wrap_id` / guardian: `group_id` / device: `request_id` (8.4). `mode` = `any` | `all` for guardian only; the empty string otherwise. **Exception: `recovery-code` keeps the old §8 AAD `LP("maruhi/v1/recovery-wrap", user_id)`** (preserving byte compatibility. Not used by the new paths)
> - Every wrap and segment is opaque to the server, and no KEK material (recovery code, PRF output, segment plaintext, ephemeral private key) ever appears in any API payload. Transplanting to another user or another context fails to decrypt thanks to the AAD / info bindings (design principle 3)
> - **Prerequisite for fetching**: in every class, fetching a wrap or segment is limited to the authenticated person themself (or the handoff approver) (authentication + key material — the same double defense as old §8). Fetch endpoints are rate-limited (AUTH_SPEC §13-8)
>
> ### 8.2 Symmetric-KEK recipients (class S)
>
> - **recovery-code** (unchanged from old §8): a 256-bit random value generated at sign-up. Displayed grouped in Base32. `KEK = HKDF-SHA256(recovery_secret, salt = empty, info = "maruhi/v1/recovery")`. The rationale for the empty salt (RFC 5869 §3.1 — the IKM is uniform random), no stretching, the Argon2id clause (introducing a passphrase-derived key requires Argon2id = requires a spec revision), and reissue = new code → re-wrap → delete the old wrap are all unchanged. **A passphrase-derived KEK is not introduced in KL3 either** (supplement 12 L4-a)
> - **passkey-prf** (new): the output `prf_out` (32 bytes — the authenticator's HMAC-SHA-256 output, uniform random) of the WebAuthn PRF extension (CTAP2 hmac-secret) as the IKM:
>
>   ```
>   prf_out = PRF(credential, eval.first = prf_salt)
>   KEK     = HKDF-SHA256(prf_out, salt = empty (length 0), info = "maruhi/v1/passkey-prf")
>   ```
>
>   - `prf_salt` is a **32-byte random value generated per registration**, placed alongside the ledger row as a public parameter (same treatment as credential_id and rpId). Why not a fixed string: if fixed, the KEK becomes a fixed function of the credential, and a once-leaked KEK would open wraps made after re-registration. With a random salt, re-registration = a new KEK, and the same semantics as recovery-code's "reissue → delete the old wrap" holds
>   - The rationale for the empty salt is the same as recovery-code's (prf_out is uniform random 256-bit). Separation of uses is carried by info. No stretching needed
>   - PRF can **only be obtained in a browser**. Obtaining happens on a localhost page distributed by the CLI (`127.0.0.1`, rpId = `localhost`), and the PRF output is passed to the CLI process in a single loopback POST (ADR-0018: the hosted Web holds no key / wrap code path). PRF must never be obtained on the operated production Web. Authentication between the page and the CLI (one-time token + Origin check) follows the requirements of ADR-0018 decision 2
>   - One user may hold multiple passkey-prf wraps (multiple authenticators). Each row is independent (identified by wrap_id)
>
> ### 8.3 Guardian groups (class G)
>
> Wraps B to the public keys of guardians the ward (the person) has named. The path for "even if both the key and the recovery code are lost, recovery is still possible with a guardian + the person's own account authentication".
>
> - **Group**: `group_id` (random ULID), `mode` ∈ {`any` (1-of-n: any one suffices), `all` (n-of-n: everyone is needed)}, group KEK = a 256-bit random. B is wrapped with 8.1's AES-GCM binding `kind = "guardian"`, `wrap_ref = group_id`, `mode` into the AAD
> - **Segments** (share_index = 1..n):
>   - `mode = any`: every `s_i = KEK`
>   - `mode = all` (n ≥ 2): `s_1 … s_{n-1}` are independent 32-byte randoms and `s_n = KEK ⊕ s_1 ⊕ … ⊕ s_{n-1}`. Restoration XORs all segments. Any n−1 segments are independent of the KEK (the standard form of information-theoretic n-of-n secret sharing). **k-of-n (Shamir etc.) is not introduced** (a new primitive). Nested HPKE (wrapping in A then wrapping in B) is not adopted because approvals could not be parallelized under sequential dependence
> - **Sealing a segment**: one-shot HPKE Base-mode Seal (the same primitive as §5). Recipient = the guardian's master enc public key (the same key that receives DEK wraps). Plaintext = `s_i` (32 bytes). aad is empty; info is
>
>   ```
>   guardian_wrap_info = LP("maruhi/v1/guardian-wrap", user_id, group_id, mode, share_index, guardian_user_id)
>   ```
>
>   The domain string makes it non-transplantable with §5 `dek-wrap` / §9.1 `lease-wrap` / 8.4 `handoff-wrap`. `mode` is included in both AAD and info so a server swapping `any` ↔ `all` (making the requester seek the XOR of n segments / believe one segment suffices) fails at decryption
> - **Authenticity of guardian keys**: guardians are chosen from **chain-derived current members** who share a project with the ward, and their enc public keys are taken from the chain (the payloads of add_member / genesis). Key confirmation follows §6.5's "satisfaction forms of explicit confirmation" (read-aloud ceremony / flag / verified-ledger hit + yes). No global public-key directory is built (§6.5). The ledger records the guardian's key FP alongside, and the client cross-checks it against the guardian's current key (chain-derived) and warns on mismatch (a guardian key rotation) — under `all`, one person's mismatch makes the group unrestorable
> - **No guardian consent procedure in v1**: naming is a unilateral operation by the ward. Since restoration requires the guardian's active approval (8.4), all that a no-consent naming produces for a guardian is "a ward appears on their own ledger". Consent signatures (an invite-style handshake) are a future revision candidate
> - Deleting a group = a unilateral operation by the ward (deletes the row; the old segments vanish). Replacing a guardian is delete → recreate
>
> ### 8.4 Handoff (class H — the common mechanism for device migration and guardian approval)
>
> A response-scoped mechanism that "re-seals B (or a segment) to the requester's ephemeral public key and hands it over". **Device migration** (the old device approves) and **guardian recovery** (a guardian approves) use the same request and the same approval payload; the requester's procedure does not depend on the approver's kind.
>
> - **Ephemeral key E**: an X25519 keypair the requester (the new device) generates in memory. Never persisted. It disappears when the requester process exits
> - **request_id**: `lower_hex(SHA-256(LP("maruhi/v1/handoff-id", E_pub_hex)))`. Requester and approver can compute the same value independently
> - **Handoff code (client spec)**: `E_pub (32 bytes) ‖ the first 4 bytes of SHA-256(E_pub)` encoded in Base32 (RFC 4648 alphabet, no padding) (displayed grouped; the display form is fixed by test vectors). **The code is carried by a person** (copy & paste between the same person's devices; out-of-band to a guardian). **The server neither relays nor stores E.pub**: the approver obtains E.pub and request_id from the carried code. This makes server-side swapping of the receiving key structurally impossible, and no 12-word matching ceremony is needed (§3's "no shortening to a truncated code" — the situation where an attacker chooses one of the keys — does not arise). The code is public information (a public key), not key material
> - **Approval**: the approver HPKE Base-mode single-Seals a 32-byte value `v` to E.pub (empty aad, info below). **There is one approval per (approver, source) for a given request_id**
>
>   ```
>   handoff_wrap_info = LP("maruhi/v1/handoff-wrap", user_id, request_id, source, share_index, approver_user_id)
>   ```
>
>   - **Guardian approval**: `v = s_i` (fetch your own segment from the ledger → Open with your own master enc key → Seal to E.pub **on the spot**. Segments and B are not stored). `source = group_id`, `share_index` = your own segment number, `approver_user_id` = the guardian's user_id
>   - **Old-device approval (device migration)**: approver = the ward themself (the device holding B). Generate `KEK_h` as a 256-bit random; `v = KEK_h`, `source = "device"`, `share_index = 0`, `approver_user_id = user_id`. At the same time, wrap B with 8.1's AES-GCM as `kind = "device"`, `wrap_ref = request_id`, `mode = ""` under `KEK_h`, and piggyback it on the approval
> - **Requester assembly**: split the received approvals by `source`. If `device` exists, `KEK = v`; open the piggybacked wrap. If `group_id`, obtain the KEK per that group's `mode` (any: any one segment; all: the XOR of all n segments) and open the group's wraps fetched from the ledger. The obtained B is stored to the keychain (or agent memory) after passing self-verification (key integrity)
> - **Identity check before approval (a norm)**: before approving, a guardian verifies out-of-band (a call etc.) that the requester is the ward themself. The server shows the approver the request's ward (user_id and a display snapshot), but that is a display, not a proof (even if the server showed a fake ward, the info's user_id binding keeps anyone but the legitimate requester from opening it — fail-closed). Approval, PRF acquisition, and restoration are ceremonies, and are refused in AI-agent environments and non-interactive terminals (the existing gate of ADR-0016 decision 7)
> - **Validity period**: a request expires after the drafted 15 minutes, and approvals disappear from the server together with the request (response scope — they never enter the persistent ledger). The requester may delete the request after success
>
> ### 8.5 Prohibitions (scope of this section)
>
> - Do not emit KEKs, segments, ephemeral private keys, or plaintext B to disk, logs, or error messages
> - Passphrase-derived KEKs (the Argon2id clause — 8.2)
> - k-of-n threshold sharing, custom key-agreement or confirmation protocols (including SAS shortening)
> - Implementations that distribute the handoff E.pub to approvers via the server (the code is carried by a person)

### A-2. Additions to the §11 test vectors

> - Vectors added in 0.9-draft (KL3) (**committed before the implementation, in the post-owner-approval implementation PR [K2]**): `master-key-wrap.json` (new — §8). Positive cases = `passkey-prf-basic` (prf_out → KEK → AES-GCM, AAD bytes) / `guardian-any-2` / `guardian-all-3` (XOR segments, HPKE Seal with a fixed ephemeral key, info bytes) / `handoff-guardian-share` / `handoff-device` (KEK_h + the device-form AAD) / `handoff-id` / `handoff-code` (encoding and decoding of the display form). Negative cases = AAD kind / wrap_ref / mode substitution (swapping `any` ↔ `all`), user_id transplant, guardian-wrap share_index / guardian_user_id / group_id transplant, handoff-wrap request_id / approver / source transplant, a missing segment (XOR of n−1), a handoff code with a checksum mismatch, prf_salt substitution, suite mismatch. **`recovery-wrap.json` is unchanged** (byte compatibility — recorded as README convention 25)

### A-3. A note on §13 open items

> 2. Device key separation / passkey PRF (WebAuthn PRF extension) support (Phase 2 and later) **— added 2026-09-12: passkey PRF was introduced into §8.2 as "KEK material for sealed backup" in KL3. Device key separation (per-device revocation) remains open under this item**

### A-4. Addition to §14.3 explicit non-guarantees

> 8. **Collusion in guardian recovery and handoff (2026-09-12 — §8.3 / §8.4)**: if one guardian under `mode = any` (or all guardians under `all`) colludes with someone who obtained the ward's account authentication, the ward's master key can be restored. A guardian is someone the ward trusts as "that kind of person"; crypto does not prevent this (one can also choose to name no guardian). An attack where the ward's account hijacker impersonates a ward to a guardian to obtain approval is prevented only by the guardian's out-of-band identity check (the server cannot prove it). If the path carrying the handoff code is actively tampered with, the approval is directed at the attacker's ephemeral key — but obtaining the approval / wraps requires the ward's account authentication (the condition is code tampering + account takeover combined)

---

## B. AUTH_SPEC revision proposals

### B-1. Substitution of the §13 heading and preamble

> ## 13. Interfacing with the master-key wrap ledger API (drafted in session 18 on 2026-08-09. Revised 2026-09-12 KL3 — §13-6 onward added)
>
> Provisions on the server storage / distribution side of CRYPTO_SPEC §8 (the master-key wrap ledger). Every wrap and segment of the ledger is **ciphertext opaque to the server**, and no KEK material (recovery code, PRF output, segment plaintext, ephemeral private key) ever appears in any API payload. Transplanting fails at decryption thanks to the AAD / info bindings (no additional server-side checks needed). **§13-1–13-5 are the recovery-code path (unchanged); §13-6 onward are the paths added in KL3**.

(§13-1–13-5 remain as they are. §13-3's rate limit reads as the combined window of 13-8 below — targets and limits are unchanged)

### B-2. §13-6 the ledger's resource model (addition)

> ### 13-6. The ledger's resource model (2026-09-12)
>
> ```sql
> master_key_wraps (                      -- class S (passkey-prf). recovery-code stays in recovery_wraps
>   id              TEXT PRIMARY KEY,     -- wrap_id (ULID)
>   user_id         TEXT NOT NULL REFERENCES users(id),
>   kind            TEXT NOT NULL,        -- 'passkey-prf'
>   suite           TEXT NOT NULL,
>   params          TEXT NOT NULL,        -- JSON (public parameters: credentialIdHex, prfSaltHex, rpId, label?). The server does not interpret it
>   nonce_hex, ciphertext_hex,            -- AES-256-GCM (AAD = the master-wrap form)
>   created_at, updated_at
> )
> guardian_groups (
>   id              TEXT PRIMARY KEY,     -- group_id (ULID)
>   user_id         TEXT NOT NULL,        -- ward
>   mode            TEXT NOT NULL,        -- 'any' | 'all'
>   suite, nonce_hex, ciphertext_hex,     -- a wrap of B under the group KEK
>   created_at
> )
> guardian_shares (
>   group_id        TEXT NOT NULL REFERENCES guardian_groups(id) ON DELETE CASCADE,
>   share_index     INTEGER NOT NULL,     -- 1..n
>   guardian_user_id TEXT NOT NULL REFERENCES users(id),
>   guardian_enc_pub_hex TEXT NOT NULL,   -- the seal destination (a key the ward client has confirmed)
>   guardian_key_fingerprint_hex TEXT NOT NULL,
>   enc_hex, ciphertext_hex,              -- HPKE (guardian-wrap form). The ciphertext is 48 bytes
>   PRIMARY KEY (group_id, share_index),
>   UNIQUE (group_id, guardian_user_id)
> )
> key_handoff_requests (
>   id              TEXT PRIMARY KEY,     -- request_id (CRYPTO_SPEC §8.4 — derived from E.pub. E.pub itself is not stored)
>   user_id         TEXT NOT NULL,        -- ward (the requester)
>   created_at, expires_at                -- issued + 15 min
> )
> key_handoff_approvals (
>   request_id      TEXT NOT NULL REFERENCES key_handoff_requests(id) ON DELETE CASCADE,
>   source          TEXT NOT NULL,        -- 'device' | group_id
>   share_index     INTEGER NOT NULL,     -- device = 0
>   approver_user_id TEXT NOT NULL,
>   approver_key_fingerprint_hex TEXT NOT NULL,
>   enc_hex, ciphertext_hex,              -- HPKE (handoff-wrap form)
>   blob_suite, blob_nonce_hex, blob_ciphertext_hex,  -- only when source = 'device' (a wrap of B under KEK_h)
>   created_at,
>   PRIMARY KEY (request_id, source, share_index)
> )
> key_blob_fetch_counters (               -- the combined window of 13-8 (mutable state, not an audit row — same nature as the counter rows of AUDIT_SPEC §3.1)
>   user_id TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL
> )
> ```
>
> - All in D1 (per user. Unrelated to projects / orgs / chains). The token-scope table and chain roles do not participate in authorization (same as §13-1)
> - `recovery_wraps`' `fetch_window_start / fetch_count` reads as the combined-window counter row (migration is at the discretion of the server implementation [K3]. The limit values are unchanged)
> - Approvals disappear together with the request's expiry or deletion (response scope. They never enter the persistent ledger — CRYPTO_SPEC §8.4). Sweeping expired rows is opportunistic deletion (same as §4's flow rows)

### B-3. §13-7 endpoints and authorization (addition)

> ### 13-7. Endpoints and authorization (2026-09-12)
>
> | op | Endpoint | Authorization |
> |---|---|---|
> | Ledger state | `GET /auth/key-wraps` (200) | Any authenticated principal (**session principals allowed** — added to §5's permission enumeration. Same nature as `recovery/status`). Carries no secrets of wraps, segments, or parameters: only per-kind registration existence, wrap_id / group_id, mode, guardian user_ids and key FPs, and update times |
> | Register a passkey | `POST /auth/key-wraps/passkey` (201 → `{ wrapId }`) | Only a token of `*` × admin scope (same as §13-2's key-material condition. **Session principals denied**) |
> | Fetch a passkey blob | `GET /auth/key-wraps/passkey/:wrapId` (200 / 404) | Same + the combined rate limit (13-8) |
> | Delete a passkey | `DELETE /auth/key-wraps/passkey/:wrapId` (204) | Same |
> | Create a guardian group | `POST /auth/key-wraps/guardians` (201 → `{ groupId }`) | Same. payload = mode + wrap + n segments (13-9). A segment's `guardian_user_id` must be an existing user. **The server does not verify key correctness (match against chain-derived keys)** — the source of truth is the ward client's confirmation (CRYPTO_SPEC §8.3); do not build a double source of truth |
> | Delete a guardian group | `DELETE /auth/key-wraps/guardians/:groupId` (204) | Same (ward only) |
> | Fetch a group's blob | `GET /auth/key-wraps/guardians/:groupId` (200 / 404) | Same (ward only) + the combined rate limit |
> | List wards for whom one is a guardian | `GET /auth/guardian/wards` (200) | `*` × admin token. Response = `[{ wardUserId, wardLogin, groupId, mode, shareIndex, createdAtMs }]`. `wardLogin` is a display snapshot of `linked_identities.provider_login` (not used as an identifier — §2) |
> | Fetch one's own segment | `GET /auth/guardian/shares/:groupId` (200 / 404) | Same (only a segment holder of that group) + counted in the approval window (13-8). A watch-listed event |
> | Handoff request | `POST /auth/handoff` (201 → `{ expiresAtMs }`. body: `{ requestId }`) | `*` × admin token (ward). 5 requests / hour / user. Collision with an existing id is 409 |
> | Query a request (approver) | `GET /auth/handoff/:requestId` (200) | `*` × admin token. The calling principal must be the ward themself or a segment holder of one of the ward's groups. **Everything else, unknown, or expired is uniformly 404** (the same existence-hiding as §11-2). Response = `{ wardUserId, wardLogin, expiresAtMs, roles: [ "device" \| { groupId, mode, shareIndex } ] }` (the approval shapes the calling principal may take) |
> | Approve | `POST /auth/handoff/:requestId/approvals` (201) | `*` × admin token. `source = "device"` is the ward themself only; `source = group_id` is only the segment holder of `share_index` in that group (matched against stored rows — authorization is never on wire-declared values). A double approval of the same (request, source, share_index) is 409. 20 approvals / hour / approver |
> | Fetch approvals (requester) | `GET /auth/handoff/:requestId/approvals` (200) | `*` × admin token (ward only). Response = the enumeration of approvals (13-9). A response that returned at least one records `auth.key_handoff_collected` |
> | Cancel a request | `DELETE /auth/handoff/:requestId` (204) | ward only |
>
> - Unauthenticated is always 401. 404 is returned only to authenticated and authorized principals
> - **Addition to session-principal capability limits (§5)**: only `GET /auth/key-wraps` is added to the permission enumeration. Registration, deletion, fetching, and approval are all device-limited (ADR-0018 revision 2: credential generation and key material live on devices)
> - The hosted Web (`apps/web`) does not touch the ledger in KL3 (state display comes in the later W series. Deletion is also device-limited in v1 — operations affecting key-material availability are kept out of session-XSS range)

### B-4. §13-8 rate limits, validity periods, acceptance policy (addition)

> ### 13-8. Rate limits, validity periods, acceptance policy (2026-09-12)
>
> - **Combined window for blob fetches**: `GET /auth/recovery`, `GET /auth/key-wraps/passkey/:id`, and `GET /auth/key-wraps/guardians/:id` (each returns the wrap of B itself) are **combined in a single per-user fixed window at 5 per hour** (§13-3's limit reads as kind-combined). Excess is 429 + retryAfterSeconds. Counting is a single-statement conditional UPSERT on a dedicated counter row (same shape as AUDIT_SPEC §3.1's counter rows). Unregistered 404s are not counted
> - **Approval window**: `GET /auth/guardian/shares/:groupId` and `POST /auth/handoff/:id/approvals` are combined in a per-approver-user fixed window at **20 per hour**
> - **Request window**: `POST /auth/handoff` is **5 per hour** per ward user
> - **Request validity**: 15 minutes. Querying, approving, or fetching an expired request is 404. Approvals disappear together with the request
> - Acceptance policy (not a consensus rule — can be raised in self-hosting): passkey-prf wraps ≤ 5 / user, guardian groups ≤ 5 / user, segments 1..5 / group (`all` is ≥ 2), `params` ≤ 4 KiB, wrap ciphertext is 16 bytes to 16 KiB including the tag (same as §13-4), segment ciphertext = 48 bytes and enc = 32 bytes (fixed length), approvals ≤ (group count + 1) × 5 / request
> - Every mutation is strict acceptance (§12-10 (1))

### B-5. §13-9 wire representation (addition)

> ### 13-9. Wire representation (2026-09-12)
>
> ```
> MasterKeyWrap = { suite: "maruhi/v1", nonceHex, ciphertextHex }          // same shape as RecoveryWrap (§13-4)
> PasskeyWrapRegistration = { wrap: MasterKeyWrap, credentialIdHex, prfSaltHex /* 64 */, rpId: "localhost", label? }
> PasskeyWrapResult       = PasskeyWrapRegistration + { wrapId, updatedAtMs }
> GuardianShare = { shareIndex, guardianUserId, guardianEncPubHex, guardianKeyFingerprintHex, encHex, ciphertextHex }
> GuardianGroupRegistration = { mode: "any" | "all", wrap: MasterKeyWrap, shares: GuardianShare[] }
> GuardianGroupResult       = { groupId, mode, wrap: MasterKeyWrap, createdAtMs }
> HandoffApproval = { source: "device" | groupId, shareIndex, encHex, ciphertextHex, blob?: MasterKeyWrap /* required only for device */ }
> HandoffApprovalResult = HandoffApproval + { approverUserId, approverKeyFingerprintHex, createdAtMs }
> ```
>
> - Distribution returns stored values verbatim (the server does not interpret them). B's serialization format and the handoff code's display form are client (CLI) contracts
> - `label` is a short display string identifying the passkey (no control characters or bidi — the same acceptance discipline as §6's token names)

### B-6. §13-10 audit events (addition)

> ### 13-10. Audit events (2026-09-12)
>
> Events added to AUDIT_SPEC §3.1 (D1 side; same batch as the record operation). The existing `auth.recovery_blob_fetched` / `auth.recovery_code_reissued` keep their names on the recovery-code path. 429 / 404 rejections are not recorded (what was not distributed or accepted is not recorded — the same line as §13-5).

---

## C. AUDIT_SPEC revision proposals (addition to §3.1 authentication-family)

> | Event | Main attributes | Notes |
> |---|---|---|
> | `auth.key_wrap_registered` | kind (`passkey-prf` / `guardian`), wrapId / groupId, mode, recipientCount | Registration to the ledger (AUTH_SPEC §13-7). actor = ward |
> | `auth.key_wrap_removed` | kind, wrapId / groupId | Deletion from the ledger. actor = ward |
> | `auth.key_wrap_fetched` | kind, wrapId / groupId | Fetching a passkey / guardian-group wrap body (**watch-listed** — same standing as `auth.recovery_blob_fetched`). actor = ward |
> | `auth.guardian_designated` / `auth.guardian_released` | groupId, mode, shareIndex | Naming / releasing a guardian. actor = ward, **target = the guardian** (also appears on the guardian's own axis). One row per segment |
> | `auth.guardian_share_fetched` | groupId, shareIndex | A guardian fetched a segment addressed to them (**watch-listed**). actor = the guardian (user_id + key FP), target = ward |
> | `auth.key_handoff_requested` | requestId | Creating a handoff request. actor = ward |
> | `auth.key_handoff_approved` | requestId, source (`device` / groupId), shareIndex | Accepting an approval (**watch-listed**). actor = the approver (user_id + key FP), target = ward |
> | `auth.key_handoff_collected` | requestId, approvalCount | The requester fetched at least one approval = the fact that a restoration happened. actor = ward |
>
> - **Visibility**: per the user-family rules (§6), the person's own axis — a person can read rows where the actor or the target is themself. A guardian can trace on their own audit what they were named for and approved; a ward can trace whom they named and who approved
> - **The identity rule (§1-2) is unchanged**: guardian, ward, and approver are all internal user_id + key FP. Display snapshots such as `wardLogin` appear only in API responses and are never written to audit rows
> - Not involved in rotation-needed detection (§4) (events outside the project)
> - Version: 1.6-draft (KL3). Merging the implementation PR containing this revision constitutes owner approval
