# DK spec revision drafts — device key separation (per-device revocation) (drafted 2026-09-19, owner-approved 2026-09-20, applied to the canonical texts the same day as K1)

**Position**: the deliverable of DK phase 1 (the design session). The overall design, the iterated ruling record, the implementation split, and the approval-request items live in docs/notes/dk-design.md. This file is the **as-drafted copy of the revision text** that was applied to the three canonical documents (CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC). **On 2026-09-20 the owner approved items 1–16 on the adopted-option side, and they were applied to the canonical texts the same day as K1** (CRYPTO_SPEC 0.12-draft §1 / §3 / §5.1 / §6.2 / §6.3 / §6.4 / §6.5 / §6.6 / §7 / §8 / §10 / §11 / §13 / §14, AUTH_SPEC 0.24-draft §5 / §6 / §11-1 / §12-3 / §12-6 / §12-8 / §13 / §16-1, AUDIT_SPEC 1.9-draft §2 / §3.1 / §3.4 / §4.1 / §4.2 / §6). From here on, the canonical texts are the source of truth; this file remains as a record of the process (if a discrepancy arises, the canonical texts win). Rulings that arose while writing K1 into the canonical texts (promoting principle D1 into §1, the writing structure of §6.2, the scope of the sweep, how deletion was written, reconciling HTTP statuses [B-7's approved `201` became the canonical `204`; the creation endpoints in §13-11 follow the precedent `200` rather than the draft's `201`]) are recorded in the design record's "§6 K1 addendum".

Each draft is shown as a "substitution" or an "addition". Parts of the existing text that do not change are not quoted. Version numbers: CRYPTO_SPEC 0.11 → **0.12-draft**, AUTH_SPEC 0.23 → **0.24-draft**, AUDIT_SPEC 1.8 → **1.9-draft**. Sentences to append to each Status line are placed in section D at the end. Ruling numbers (DK-A…) refer to design record §2.

Terminology (common to this draft): **device key** = a per-device key pair of enc (X25519) + sig (Ed25519). Identified by key fingerprint (§3). **reserve key** = a device key whose private key lives only in the §8 ledger (indistinguishable from other device keys on the chain). **device cap** = the (role_cap, scope_kind, scope_environments) in an `add_device` payload. **device effective authority** = (min(person's role, role_cap), person's scope ∩ device's scope). The cap on the first key carried by `add_member` / `genesis` is structurally (owner, all) (= the person's authority itself). A cap is an **upper bound** on a person's authority, not authority itself (`owner` = no bound). Monotonicity (§6.2) compares caps to caps, never effective authorities.

---

## A. CRYPTO_SPEC revision proposals

### A-1. Substitution in §3 (key hierarchy diagram and the final two items — DK-A)

> ```
> User (a chain member — user_id, role, scope)
> ├─ device keys d1 … dn (per device. enc: X25519 + sig: Ed25519 each)
> │     cap = (role_cap, scope) — device effective authority = (min(role, role_cap), scope ∩ scope_d)
> └─ reserve key r (same shape as a device key. Its private key lives only in the §8 ledger)
>         │
>         └─ Wrap target: Environment Epoch DEK (per project × environment × epoch) — recipients are (user, device key)
>                 └─ Encryption target: variable values, and future secret metadata
> ```
>
> - **Device key (2026-09-19 DK — formerly "User master keypair")**: generated on the client, per device. The private key is never sent to the server; it lives only in that device's secure storage (CLI: the OS keychain, or `maruhi agent` memory). **A device key is never copied to another device**. A member on the chain (user_id) holds a **set** of device keys: `add_member` / `genesis` carries the first one, `add_device` / `revoke_device` (§6.2) carries the later additions and removals. Signer identification stays (user_id, key fingerprint) as before — the fingerprint now names the device
> - **Reserve key (2026-09-19 DK)**: a key pair of the same shape as a device key whose private key is **not kept on any day-to-day device and lives only in the §8 ledger**. On the chain it is an ordinary device key registered via `add_device` (cap = (owner, all)) and it receives DEK wraps (so that after losing every device it can still backfill even when no other device exists). After recovery (§8), `add_device` a new device key first, then erase the reserve key secret from the device
> - **Key fingerprint**: the first 16 bytes of `SHA-256(enc public key || sig public key)`. Used for key identification in logs and the UI — **unchanged**. After DK, a fingerprint identifies a device
> - ~~v1 simplification: no per-device keys; the master keypair is placed on each device. Adding a device is done by entering a recovery code (§8). Device key separation and passkey PRF are future work (**open item #2**)~~ **Revised 2026-09-19 (DK — resolves open item #2)**: device key separation is introduced as above. Devices are added by `add_device` signed by another of the same person's devices (no ceremony — §6.2); revocation is `revoke_device` (a rotate obligation of the same shape as `remove_member` — §7). The design record is docs/notes/dk-design.md

### A-2. Addition to §5.1 (one sentence on client verification — DK-A)

> - **Device key (2026-09-19 DK)**: "a matching signer fingerprint" is chosen within the **validity interval of that user_id's device keys** (a key carried by `add_member` / `genesis` uses the membership interval; a key carried by `add_device` is valid after `add_device` and before `revoke_device`). The shape of the rule is unchanged (key selection by fingerprint)

### A-3. Substitution / addition in §6.2 (role table, op table, the consensus rule "device keys", the wording of four-eyes votes, key uniqueness — DK-A / DK-C / DK-D)

Substitute the `reader` row of the role table:

> | `reader` | May only fetch and decrypt values of environments in scope (receives DEK wraps for in-scope environments). Chain appends are **limited to `add_device` / `revoke_device` of one's own devices** (2026-09-19 DK) |

Append two rows to the op table (after `withdraw`):

> | **`add_device`** | **enc_pub_hex, sig_pub_hex, role_cap, scope_kind, scope_environments_lp_hex** (the new device's public keys and its caps) | **Every role (the actor adds a device of their own — the target is the actor themself. The new device's cap ≤ the actor's own signing device's cap — not the effective authority)** |
> | **`revoke_device`** | **target_user_id, device_fingerprints_lp_hex** (the list of device FPs to revoke) | **Own device: every role. Another person's device: the same role rule as `remove_member` (revoking a reader / member's device requires admin or above; an admin / owner's device requires owner) + target's scope ⊆ actor's effective scope. Carries a `rotate_epoch` obligation for every environment in the revoked device's effective scope (§7)** |

Append a consensus-rule block (immediately after the "environment scope" block):

> - **Device keys (2026-09-19 DK — formerly open item #2. Design record: docs/notes/dk-design.md)**: a member holds a **set** of device keys. `genesis` / `add_member` carries the first device key (the payload is unchanged; that key's cap is structurally (owner, all)) and `add_device` / `revoke_device` grows and shrinks the set. **Principle D1 — keys belong to devices; authority belongs to people**: role, scope, and the distinctness of four-eyes votes are counted by user_id; key material and its revocation are handled per device. A signer is identified by (user_id, key FP), and the FP picks the device. **Device effective authority** = (min(person's role, device's role_cap), person's scope ∩ device's scope), and **every check in this spec of "the role / scope of actor / writer / author / issuer / attester" is performed against the effective authority of the device that signed** (role rules, principle 1 containment, environment-targeting ops, §6.3's 1 / 3 / 3′, §6.6, four-eyes votes). The individual rules below are derivations from this principle
>   - **Payload and structure (the structural-check stage)**: `add_device` = `[enc_pub_hex, sig_pub_hex, role_cap, scope_kind, scope_environments_lp_hex]` (public keys are lowercase hex, 64 chars. `role_cap` ∈ {`reader`, `member`, `admin`, `owner`} — `owner` means "no bound". The two scope fields use the same encoding and the same structural rules as "environment scope" [`all` ⇒ empty list, at most 256 elements, duplicates invalid; an empty `listed` list is valid = a device that receives no DEK]). `revoke_device` = `[target_user_id, device_fingerprints_lp_hex]` (a list of FPs [lowercase hex, 32 chars] nested-LP-encoded per §2.1. At least 1 element, at most 256, duplicates invalid. Order is signed. Generation SHOULD be ascending; verification is set-wise)
>   - **Authorization of `add_device`**: the actor is a current member (any role — a reader may). The target is the actor themself (the payload carries no target). Each of the new device's public keys must not duplicate a same-kind public key of **any device key** in the current member set (the target of `duplicate-member-key` is extended to the device set; collisions with the server key of a valid `grant_server` remain out of scope of this rule, as with `add_member`). Each `listed` environment_id must have a preceding `create_environment` (`unknown-environment`). **Monotonicity (principle D2)**: the new device's cap must not exceed the signing device's **own cap** (the bound written in the payload; keys of `add_member` / `genesis` are structurally (owner, all)) — role_cap_new ≤ role_cap_signer, and device scope_new ⊆ device scope_signer (the set algebra is the same as "environment scope": `all` = U. Rejection reason `device-cap-exceeded`). **The comparison is between caps, not effective authorities that take the person's role into account** (compared as effective authorities, a member could not register a reserve key with cap (owner, all) — a cap is "an upper bound on the person's authority", not authority itself, and `owner` means "no bound". A member's reserve key's effective authority stays min(member, owner) = member — addressed per a 2026-09-19 Cursor Bugbot report). This rule exists so a stolen device cannot mint a device with a stronger bound than itself; the reserve key (cap (owner, all)) is registered by the first device key (cap (owner, all))
>   - **Authorization of `revoke_device`**: if the target is the actor themself, any role. Otherwise the same role rule as `remove_member` (determined by the target's role) plus principle-1 containment (target's scope ⊆ actor's effective scope — only someone who can fulfill the revocation's rotate obligation [§7] may revoke. Rejection reason `scope-not-contained`). Each FP must be a **currently valid** device of the target (`unknown-device`). An entry that would leave the target with zero devices is invalid (`last-device-protected` — a member with no device cannot come back; that shape is expressed by `remove_member`). One may revoke the very device one is signing with (it is valid at entry time; signatures after that are invalid)
>   - **Device validity interval**: a device key is valid from the seq of its `add_device` (or `add_member` / `genesis`) to **just before** the seq of its `revoke_device` (inclusive convention — the post-application state of a `revoke_device` entry does not contain that device). The verification state is the device set per current member (FP → public keys, cap); the history index derives each device's validity interval and cap (inputs to §6.3's key selection and 3′, and to AUTH_SPEC §12-6's recipient determination). `remove_member` ends all of the target's devices at once. Re-adding the same user_id (`add_member`) starts from a single first device
>   - **Recipient set R(E) (device axis)**: the complete set of recipients of environment E's DEK wraps = { (m, d) | m ∈ current members, d ∈ devices(m), E ∈ scope(m) ∩ scope(d) } ∪ { valid `grant_server` g | E ∈ scope_environments(g) }. Determination is the single predicate "identified (id + key) ∧ E ∈ effective scope" across recipient classes
>   - **Relationship to four-eyes**: `add_device` / `revoke_device` cannot be included in `set_approval_policy`'s `ops` (structural check — `invalid-payload`), nor proposed (`approval-not-required`) — adding a device does not increase user_ids and does not affect quorum, and revocation is a fail-safe operation (same line as `rotate_epoch`). The element (user_id, key FP) of S in principle 2 is unchanged, and the FP names the device that signed (see the `approve` wording below)
>   - **Check order (fixed per reason code, for vectors)**: `add_device` = actor rules (`actor-not-member` / `actor-key-mismatch`) → `duplicate-member-key` → `unknown-environment` → `device-cap-exceeded`. `revoke_device` = `unknown-target` → `unknown-device` → target-dependent role rule (passes for self, `insufficient-role` for others) → `last-device-protected` → `scope-not-contained` (others only) — the same shape as the existing order of `remove_member` / `change_role`, which resolves the target's existence before deciding the target-dependent role rule (`resolveTargetedOp`) (addressed per a 2026-09-19 pullfrog report). The check order of existing ops is unchanged (substituting in effective authority only changes the inputs to each check)
>   - Introducing this rule adds new ops; it does not touch the payload format of existing ops. Existing chains accepted before introduction are **valid** under the new rule (each member's devices = the single first key). `chain-entries.json` is extended by appending (§11)

Substitute the vote wording of `approve` in the "four-eyes" block (only the relevant passage):

> - **`approve`** (device-key vocabulary — 2026-09-19 DK): the actor must be an owner at that point, and the signing device's effective role must be owner (`insufficient-role` — a device with cap < owner cannot cast a vote). If the actor's user_id already holds a **live vote** in S (a signature by a device valid for that person at application time), the result is `duplicate-approval` (a second vote from the same device and a second vote from another device are both duplicates — one vote per person). Vote count = the number of distinct user_ids among elements of S where "at this `approve`'s point, that FP is a valid device of a current owner and the device's effective role is owner". **Votes of a revoked device are revoked** (a `revoke_device` is a declaration that "this key may have been compromised" — same as the 2026-09-15 ruling that a key change expires the old key's votes). If the same person re-registers a revoked device key via `add_device`, the old vote revives (the device form of "revocation is not monotone" — a consequence. The CLI warns on re-registering a revoked FP). `proposal-void`'s "the same key FP as at proposal" reads as "the device that proposed is still valid at application time and its effective role suffices for the inner op"

Substitute the one sentence on the unit of determination in the "member key uniqueness" block:

> - **The unit of determination is the individual enc / sig key** (key fingerprint = enc‖sig equality does not apply). The comparison set is **all device keys** of the current member set (2026-09-19 DK — there are multiple device keys per person, and sharing one of the two keys produces the same ambiguity across devices). enc and sig keys are not compared across kinds

### A-4. Additions to §6.3 (4 places — DK-A / DK-E)

> - **Device key selection (2026-09-19 DK)**: the "key validly bound to that user_id at the declared head" in 1 means a key whose device-key validity interval (§6.2) for that user_id contains the declared head. A signature in which a revoked device declared a head at or after the revocation seq is `*-key-mismatch-at-head` (an existing reason code — same shape as spanning the membership interval). The role in 3 and the scope in 3′ are determined by the **effective authority of the signing device** (a value signature from a device with cap < member is `*-role-insufficient-at-head`; outside device scope is `*-environment-out-of-scope-at-head` — both existing codes; only the input changes to effective authority)
> - **Wrap target = R(E) (device axis)**: "current members in scope" reads as "each device of the current members in scope whose effective scope contains E" (R(E) of §6.2). Receiving side: do not use, and warn on, wraps addressed to you for environments ∉ **this device's effective scope** (norm unchanged)
> - **(a) Invite link anchor**: "the sig public key bound to the inviter's user_id on the chain at that seq matches the link's `is`" reads as "matches the sig public key of one of the inviter's devices valid at that seq" (an invite is issued from a device)
> - **Handling of out-of-scope environments**: environments outside device scope are treated the same as outside person scope (metadata is visible; no DEK is received). Device scope is a subset of person scope, so it can never exceed the person's visibility range (ruling G)

### A-5. Addition to §6.4 (one acceptance-policy item — DK-E)

> - **Device count (2026-09-19 DK)**: up to **16** valid devices per member (acceptance policy — not a consensus rule. An `add_device` in excess is a typed error — AUTH_SPEC §12-8). Acceptance side-effects of `revoke_device`: deleting the target device's attestation rows (AUTH_SPEC §16-1), rotation-needed detection (the `revoke_device` variant of AUDIT_SPEC §4.1), mirroring (§3.4). Acceptance side-effects of `add_device`: mirroring only (DEK backfill is the client's — §7). `add_device` / `revoke_device` are accepted through the generic chain-append API (AUTH_SPEC §11)

### A-6. Addition to §6.5 (one sentence — DK-D)

> - **Relationship to device keys (2026-09-19 DK)**: both the key that accepts an invite and the key that issues an invite are **the device key of the device performing the operation**. What gets registered to the backing source (`github-signing-keys`) (`maruhi key publish`) is the sig public key of the device used for acceptance (registration is per device — GitHub can hold multiple signing keys). The path by which a person adds another device of their own is `add_device`, not invites (§6.2 — needs neither third-party vouching nor mutual confirmation: it is an operation where the person grows their own keys, and it carries only the FP [public information]; if the server swapped the public key, the FP check would fail). The verified fingerprint ledger (satisfaction form 3) records a **set** of (origin, user_id) → FPs, and an unknown FP of a known peer is treated like a key change (warning + ceremony)

### A-7. Addition to §6.6 (one sentence — DK-A)

> - **Device keys (2026-09-19 DK)**: an attester's key is the device key of the signing device. In client verification (1)(2), "the key that was valid at the attested head" is determined by the device's validity interval. Attestations are stored and distributed as the latest one row **per device**, not per member (AUTH_SPEC §16-1 — because devices sync independently, no seq monotonicity across devices is required)

### A-8. Additions to §7 (two items — DK-B)

> - **Device revocation (2026-09-19 DK)**: `revoke_device` carries the same `rotate_epoch` obligation as `remove_member`, for every environment in each revoked device's **effective scope** (person's scope ∩ device's scope) (confidentiality — revocation of the DEKs that device held. Revoking a device whose scope is empty [a vote-only device] carries no obligation). The obligation's origin is the seq of that `revoke_device`. The fulfiller is the actor who signed the revocation (another device of the same person, or an admin / owner who revoked someone else's device — which holds the DEKs by principle-1 containment). **When a reader revokes their own device**, the actor lacks `rotate_epoch` authority and cannot fulfill — this revocation is not rejected by a consensus rule (revocation is a fail-safe operation; same line as not delaying `rotate_epoch` under four-eyes); instead the obligation is surfaced to members and above of that environment via rotation-needed detection (the `revoke_device` variant of AUDIT_SPEC §4.1) and `project verify`'s unfulfilled-obligation warning, and the CLI shows the revoker "who to ask for a rotate"
> - **Backfill on device add**: the `add_device` actor (a device of the same person) wraps and registers the DEKs of **all epochs** for each environment in the new device's effective scope, to the new device's enc public key (the append path of AUTH_SPEC §12-6 — same shape as the backfill after `add_member`. Includes the reserve key [cap (owner, all)]). The actor is a device of the same person and holds those DEKs ("the wrap performer = a DEK holder"). A reader's device can also register its own backfill (AUTH_SPEC §12-3 — recipients are limited entirely to the caller's own device keys). When an approver performs a backfill for a four-eyes application (`add_member` / scope expansion), the destinations are the target's **all devices** (per R(E))

### A-9. Substitution in §8 (heading, 8.1, 8.3, 8.4, 8.5 — DK-G)

> ## 8. Reserve-key wrap ledger (recovery codes, passkey PRF, guardians, handoff)
>
> **Revised 2026-09-19 (DK)**: the ledger's wrap target B is now a blob of the **reserve key** (§3 — a device key whose private key lives only in the ledger). The former "master key" splits into device keys (kept on day-to-day devices) and the reserve key (kept in the ledger); the ledger protects only the latter. The ledger's structure (classes S / G / H), AAD, segments, handoff request / approval payloads, and the `recovery-wrap.json` byte strings are unchanged. What changes: (1) the meaning of B, (2) the **removal** of the handoff old-device path (`kind = "device"` / `source = "device"`) (a day-to-day device does not hold B, so it cannot work — adding a device is handled by `add_device` in §6.2), (3) the seal destination of guardian segments becoming the guardian's **each device key**, (4) changing the ledger (adding wraps, reissuing, naming guardians) now **requires unsealing the reserve key** (since the reserve key is not on a device, the client first opens B with a code or a passkey, then builds new wraps. At initial key generation, the device key and the reserve key are generated together, and the recovery-code wrap and any passkey wraps are created on the spot)
>
> ### 8.1 Common provisions (substituted passages only)
>
> - **Wrap target B**: an opaque blob of the reserve key (enc / sig). The serialization format is a client (CLI) contract; the server does not care (currently = JSON of a keychain record, the same shape as a device-key record. The restoring side uses it **only to mint device keys**, after passing self-verification, and does not place it in day-to-day storage)
> - **Recipient classes**: (S) symmetric KEK — `recovery-code` / `passkey-prf`. (G) guardian group — `guardian`. (H) handoff — ephemeral recipient (a response scope carrying a guardian's approval to the requester)
> - `kind` ∈ {`passkey-prf`, `guardian`} (`device` was removed on 2026-09-19 — 8.4). `wrap_ref` = passkey-prf: `wrap_id` / guardian: `group_id`. `mode` = `any` | `all` for guardian only; the empty string otherwise. **Exception: `recovery-code` keeps the old AAD** (unchanged)
>
> ### 8.3 Guardian groups (substituted passages only)
>
> - **Seal destination of segments**: the enc public key of the guardian's **each currently valid device key** (chain-derived — the device set of §6.2). The same `s_i` is sealed once per guardian device (info does not contain the device, but the recipient keys differ so they cannot open each other's). The ledger records the guardian's user_id and the device's key FP alongside each segment, and the client cross-checks them against the guardian's current device set (chain-derived) and warns on mismatch (STALE) if every sealed destination device has been revoked / rotated — under `all`, one person's mismatch makes the group unrestorable. Existing segments do not follow when a guardian adds a device (the ward recreates them)
>
> ### 8.4 Handoff (substituted passages only)
>
> - Remove the "device migration" item. Approvers are **guardians only** (`source = group_id`). There is no `source = "device"`, no `KEK_h`, no piggybacked B on the approval. The requester's assembly has a single form: "obtain the KEK per that group's `mode`, then open the group's wraps fetched from the ledger"
> - **Adding a device is out of scope of this section** (§6.2 `add_device` — it carries no secret). Recovery from losing every device: a device that obtained the reserve key B via this section's path signs `add_device` with the reserve key to register its own new device key, then erases the reserve key secret from the device (§3)
>
> ### 8.5 Prohibitions (addition)
>
> - **Keeping** the reserve key's private key in day-to-day device storage (keychain, agent memory) (keep it in memory only during recovery or ledger changes; erase it when done)
> - Sealing the reserve key with a device-bound sealer (SE / TPM etc.) (recovery must be possible from any device — the ledger only)

### A-10. Additions to the §11 test vectors

> - Vectors added or revised in 0.12-draft (DK) (**committed before the implementation, in the post-owner-approval implementation PR [K2 — the implementation split is docs/notes/dk-design.md §3]**): **appends** to `chain-entries.json` (seq 25 onwards — positive cases of `add_device` / `revoke_device` [reserve key; a vote-only device (owner, listed{}); a CI box (member, listed{dev}); derivation of a valid value signature by a second device; self / batch / admin revocations; derivation that a revoked device's vote is not counted; re-voting from another device] and negative cases [`duplicate-member-key`; `unknown-device`; `last-device-protected`; `device-cap-exceeded` on each of the role / scope axes; `scope-not-contained`; a revoked device's signature = `actor-key-mismatch`; an approve with cap < owner = `insufficient-role`; a second vote from another device of the same person = `duplicate-approval`; proposing `add_device` = `approval-not-required`; the fixed check order]). `expected_head_states` members gain `devices`. **The byte strings and hashes of canonical-chain seq 1–24 are unchanged** — no regeneration needed because no existing op's payload format is touched [same shape as when the `checkpoint` op was added]); **appends** to `value-signature.json` / `metadata-signature.json` / `env-manifest.json` / `head-attestation.json` (device-axis negative cases = declared head by a revoked device [`*-key-mismatch-at-head`], insufficient cap [`*-role-insufficient-at-head`], outside device scope [`*-environment-out-of-scope-at-head`], and a positive case for a second device. Existing positive and negative cases are unchanged); **regeneration** of `master-key-wrap.json` (removing the `handoff-device` positive case and the negative case re-pointed at kind `device` — a reflection of the ruling not to build a compat path. Byte strings of the other cases are unchanged. The intentional exception is recorded as README convention 28). **All other vectors are unchanged** (HPKE info, AAD, registration signatures, issuance text, acceptance text, and attestation LP are untouched)

### A-11. Substitution of §13 open item #2

> 2. ~~Device key separation / passkey PRF (WebAuthn PRF extension) support (Phase 2 and later)~~ **Resolved (drafted 2026-09-19 — finalized on merge of this revision PR)**: passkey PRF was designed in KL3 (0.9-draft — §8.2), device key separation in DK (§3 / §6.2 / §7 / §8 — device keys, reserve key, `add_device` / `revoke_device`). The design record is docs/notes/dk-design.md

### A-12. Additions to §14.2 / §14.3

> 11. **Guarantee of per-device revocation (2026-09-19 — DK)**: for a device key d revoked by `revoke_device` on a verified chain (seq s), DEK wraps of epochs at or after s are not generated for d by spec-conforming clients and not accepted by spec-conforming servers (§6.2's R(E) / AUTH_SPEC §12-6). Signatures by d on values, metadata, manifests, and attestations declaring heads at or after s, and chain entries and four-eyes votes by d at or after s, are rejected by every verifier. The person (user_id)'s membership, role, scope, and other devices are unaffected (no re-invite or re-voting needed). **Not guaranteed**: undoing DEKs or plaintext that d obtained before revocation (§1 principle 5 — covered by §7's rotate obligation and rotation-needed detection); automatic revocation of devices that d registered via `add_device` before being revoked (visible on-chain as "added by d" — the revoker revokes them in batch in the same entry); anything beyond **prior** prevention of creating devices exceeding cap monotonicity (a stolen device can mint devices at or below itself)

> 10. **Reserve-key exposure (2026-09-19 — §8 / DK)**: in recovery from losing every device, the reserve key B is placed in the memory of the device performing the recovery. If that device is compromised, the reserve key is compromised too (crypto cannot prevent this — `key reserve rotate` after recovery [registering a new reserve key + revoking the old one = rotate obligation] is the remedy). Not keeping the reserve key on day-to-day devices (§8.5) limits exposure opportunities to the moments of recovery and ledger changes

---

## B. AUTH_SPEC revision proposals

### B-1. Addition to §5 (session-scope permission enumeration — DK-K)

> - Add **`GET /auth/devices`** to the permission enumeration (authentication / self-information kind) (§13-11 — reading the device registry. Carries display names, key FPs, and public keys only. Carries no secrets). Session principals are denied device-add requests, registry writes, and deletions (device-limited — 2026-09-19 DK)

### B-2. Addition to §6 (one sentence — DK-L)

> - **Correspondence with device keys (2026-09-19 DK)**: a token issued at CLI login (default name `cli:<hostname>`) is one per device and lives on the same device as the device key. Device revocation (`revoke_device` — CRYPTO_SPEC §6.2) is a chain fact and independent of tokens, but the client proposes targeted revocation (this section) of that device's token at revocation time. The correspondence is held in the device registry's (§13-11) `tokenId` (optional, advisory)

### B-3. Addition to §11-1 (one sentence — DK-F)

> - **`add_device` / `revoke_device` (CRYPTO_SPEC §6.2. 2026-09-19 DK) are accepted through the generic append API** (they carry no accompanying data). The token level is **admin**, same as `add_member` etc. (§6). Acceptance side-effects of `revoke_device` = deleting the target device's attestation rows (§16-1), rotation-needed detection (AUDIT_SPEC §4.1), mirroring. The device-count limit is §12-8

### B-4. Addition to §12-3 (one table row — DK-E)

> | DEK wrap registration (**when every recipient is the calling principal's own device keys** — 2026-09-19 DK) | write | **reader or above** | environment ∈ the calling principal's effective scope (recipient side too) |
>
> - The path by which a reader re-wraps their own DEKs to their own new device (including the reserve key) (the device-add backfill of CRYPTO_SPEC §7). The reader legitimately holds those DEKs; re-wrapping to their own keys grows no one else's capabilities. If even one recipient is another person's key, member or above is required as before

### B-5. Substitutions in §12-6 (4 places — DK-E)

> - Recipient identification is **both user_id and enc public key** (unchanged). After 2026-09-19 DK, the same user_id can hold multiple enc public keys (device keys), so a public key identifies a device. Acceptance requires both to exactly match a chain-derived current member's **valid device key**, and the target environment to be contained in **that device's effective scope** (CRYPTO_SPEC §6.2 — out of scope is 422 `scope-out-of-range`). The storage slot is **(environment_id, epoch, recipient_user_id, recipient_enc_pub_hex)** (previously (environment_id, epoch, recipient_user_id) — one slot per device). No overwrite (409 `DekWrapExists` — including `storedRecipientEncPubHex` is unchanged); exact match, appending the shortfall, and the repair path are unchanged
> - **Sweeping wraps to old keys**: when a re-add `add_member` is accepted, delete stored wraps addressed to that user_id whose recipient enc public key does not match the **added device key** (the device form of the old rule — a re-add starts from a single device). Nothing is deleted on `revoke_device` / `remove_member` (the existing discipline: return happens by re-registering the same key)
> - Add a sixth entry to the **paths where the standalone registration API remains**: "**the backfill of all epochs to the new device by a device of the same person, after `add_device`** (environments in the new device's effective scope. Includes the reserve key — CRYPTO_SPEC §7. A reader's self-backfill is §12-3)". The acceptance rules are common to all paths (signer = calling principal, recipients ∈ R(E), no overwrite)
> - **The registering signer's scope**: the "signer = calling principal" determination is unchanged. Scope is determined by **the signing device's effective scope** (§12-3's 403 `InsufficientScope`). Matching the calling principal's user_id to the signing device's user_id is carried by §5.1's signer_user_id binding

### B-6. Addition to §12-8 (one table row)

> | Valid devices / member / project | 16 (decided at `add_device` acceptance. Excess is typed 422 `DeviceLimit`. Freed by `revoke_device` / `remove_member` — 2026-09-19 DK) |

### B-7. Substitutions / additions to §13 (preamble, 13-1, 13-6, 13-7, 13-9, new 13-11 — DK-G / DK-F / DK-D)

Substitute one sentence of the preamble:

> Provisions on the server storage / distribution side of CRYPTO_SPEC §8 (the **reserve-key** wrap ledger — 2026-09-19 DK). The ledger's wrap target is the reserve-key blob; device keys do not go on the ledger (adding a device is via §13-11's request rows and CRYPTO_SPEC §6.2's `add_device`).

Append one sentence to §13-1:

> - 2026-09-19 DK: the blob's contents are the reserve key (CRYPTO_SPEC §3). Existing `recovery_wraps` rows (copies of the master key) are **replaced** by reserve-key wraps at migration (the same upsert as reissuance — the migration procedure is docs/SELF_HOSTING.md "Updates")

Substitution in §13-6 (only `guardian_shares` and `key_handoff_approvals`):

> ```sql
> guardian_shares (
>   group_id        TEXT NOT NULL REFERENCES guardian_groups(id) ON DELETE CASCADE,
>   share_index     INTEGER NOT NULL,     -- 1..n (logical segment — one per guardian)
>   guardian_user_id TEXT NOT NULL REFERENCES users(id),
>   guardian_key_fingerprint_hex TEXT NOT NULL,   -- the sealed-destination device key (2026-09-19 DK — one row per guardian device)
>   guardian_enc_pub_hex TEXT NOT NULL,
>   enc_hex, ciphertext_hex,              -- HPKE (guardian-wrap form. info does not contain the device — the same s_i is sealed per device)
>   PRIMARY KEY (group_id, share_index, guardian_key_fingerprint_hex),
>   UNIQUE (group_id, guardian_user_id, guardian_key_fingerprint_hex)
> )
> key_handoff_approvals (
>   request_id      TEXT NOT NULL REFERENCES key_handoff_requests(id) ON DELETE CASCADE,
>   source          TEXT NOT NULL,        -- group_id (2026-09-19 DK — 'device' removed)
>   share_index     INTEGER NOT NULL,
>   approver_user_id TEXT NOT NULL,
>   approver_key_fingerprint_hex TEXT NOT NULL,   -- the device key used for the approval
>   enc_hex, ciphertext_hex,              -- HPKE (handoff-wrap form)
>   created_at,
>   PRIMARY KEY (request_id, source, share_index)
> )
> ```
>
> - `blob_suite / blob_nonce_hex / blob_ciphertext_hex` (the piggyback blob of the former `source = 'device'`) are removed. The acceptance policy's "segments 1..5 / group" is a bound on **logical segments** (guardian count); device rows are allowed up to 16× that (the device count of §12-8)

Substitution in §13-7 (relevant rows only):

> | Querying a request (approver) | `GET /auth/handoff/:requestId` (200) | The calling principal must be a segment holder of one of the ward's groups (under one of their device keys). **No queries by the ward themself** (the old-device approval path was removed — 2026-09-19 DK). Everything else, unknown, or revoked is uniformly 404. Response = `{ wardUserId, wardLogin, expiresAtMs, roles: [ { groupId, mode, shareIndex } ] }` |
> | Approval | `POST /auth/handoff/:requestId/approvals` (201) | Only the segment holder of `share_index` of the group given by `source = group_id` (matched against stored rows — the FP of the device key used for the approval matches one of the segment rows). `source = "device"` is not accepted (Schema 400) |

Substitution in §13-9 (relevant rows only):

> ```
> GuardianShare = { shareIndex, guardianUserId, guardianKeyFingerprintHex, guardianEncPubHex, encHex, ciphertextHex }   // one element per device (multiple entries share a shareIndex)
> HandoffApproval = { source: groupId, shareIndex, encHex, ciphertextHex }                                              // no blob
> ```

New §13-11:

> ### 13-11. Device registry and device-add requests (2026-09-19 DK — advisory)
>
> The source of truth for device keys is each project's chain (CRYPTO_SPEC §6.2 — `add_device` / `revoke_device`). The registry in this section is **a place for display names, token correspondence, and the public keys of add requests**, and is **never an input to any verification or authorization** (even if the server inserts rows, the client does not add devices — the keys a client may `add_device` are limited to keys it generated itself, keys it approved itself, and keys observed as that person's devices on a verified chain — like CRYPTO_SPEC §6.5's satisfaction forms, server claims are never a key's provenance).
>
> ```sql
> devices (                                -- device registry (D1, per user, advisory)
>   user_id TEXT NOT NULL REFERENCES users(id),
>   key_fingerprint_hex TEXT NOT NULL,     -- device-key FP (CRYPTO_SPEC §3)
>   enc_pub_hex TEXT NOT NULL, sig_pub_hex TEXT NOT NULL,
>   label TEXT NOT NULL,                   -- display name (same acceptance discipline as §6 token names — no control characters or bidi, ≤ 128 chars)
>   token_id TEXT,                         -- optional: this device's API token id (§6)
>   created_at INTEGER NOT NULL,
>   PRIMARY KEY (user_id, key_fingerprint_hex)
> )
> device_add_requests (                    -- request rows carrying a new device's public keys to approver devices (TTL 15 min)
>   user_id TEXT NOT NULL, key_fingerprint_hex TEXT NOT NULL,
>   enc_pub_hex TEXT NOT NULL, sig_pub_hex TEXT NOT NULL, label TEXT NOT NULL,
>   created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
>   PRIMARY KEY (user_id, key_fingerprint_hex)
> )
> ```
>
> | op | Endpoint | Authorization |
> |---|---|---|
> | Read the registry | `GET /auth/devices` (200) | Any authenticated principal (**session principals allowed** — §5). Response = `[{ keyFingerprintHex, encPubHex, sigPubHex, label, tokenId?, createdAtMs }]`. Carries no secrets |
> | Register to / rename in the registry | `PUT /auth/devices/:fp` (204. body: `{ encPubHex, sigPubHex, label, tokenId? }`) | `*` × admin token (same level as §13-2. Session principals denied). `fp` must match the value recomputed from the body's public keys (400). At most 32 rows per user (429) |
> | Delete from the registry | `DELETE /auth/devices/:fp` (204 / 404) | Same (deletion of advisory data — independent of chain revocation) |
> | Create an add request | `POST /auth/devices/requests` (201. body: `{ encPubHex, sigPubHex, label }`) | `*` × admin token (the new device itself — the device has already logged in via §4). 5 per user per hour (429). Collisions with a same-FP request or an existing registry row are 409 |
> | List / query add requests | `GET /auth/devices/requests` (200) / `GET /auth/devices/requests/:fp` (200 / 404) | `*` × admin token (approving devices — the person themself only). Response = `[{ keyFingerprintHex, encPubHex, sigPubHex, label, expiresAtMs }]`. **The approving client recomputes the FP from the response's public keys and ignores everything that does not match the FP the person carried over** (a server swapping public keys fails the FP check) |
> | Cancel an add request | `DELETE /auth/devices/requests/:fp` (204) | Same (the person themself). The client deletes it after approval. Expired rows are deleted opportunistically |
>
> - No audit events (a ledger of self-information that touches neither values nor key material — same discipline as the §6 token list. Records of device adds and revocations are carried by the chain's mirror rows — AUDIT_SPEC §3.4)
> - The hosted Web may show only reads of the registry (as "server claims" — ADR-0018 revisions 2 and 4. The revocation affordance stops at targeted token revocation [§6]; the chain's `revoke_device` is CLI)

### B-8. Addition to §16-1 (one item — DK-A)

> - **Per-device attestation (2026-09-19 DK)**: storage and distribution keep the latest one row per **(attester_user_id, attester_key_fingerprint_hex)**, not per member (because devices sync independently, no seq monotonicity across devices is required — the 409 on regression applies only against the same device's stored row). On accepting a `revoke_device`, delete the device's attestation rows; on accepting a `remove_member`, delete all the target's devices' rows. The acceptance-policy window (60 per hour) stays per member

---

## C. AUDIT_SPEC revision proposals

### C-1. Addition to §2 (one sentence — DK-F)

> - **A key FP names a device (2026-09-19 DK)**: after device keys are introduced, `key_fingerprint` identifies "the device that user_id used for that operation, at that point". The actor carries no separate device field (identifiers remain user_id + key FP — §1-2 unchanged)

### C-2. Addition to §3.4 (2 table rows + 1 item)

> | **`chain.device_added`** | `add_device` (target_user_id = actor, payload = { deviceKeyFingerprint, roleCap, scopeKind, scopeEnvironmentIds }. 2026-09-19 DK) |
> | **`chain.device_revoked`** ★ | `revoke_device` (target_user_id = the target, payload = { deviceKeyFingerprints }. ★ because **it triggers §4.1 detection**) |
>
> - Device adds and revocations are also one row per entry (the bijection is unchanged). `chain.device_added` is not a detection trigger, but Q1 reads it as the start of a device's window in §4.1

### C-3. Addition to §4.1 (one variant — DK-B / DK-F)

> **The `revoke_device` variant (2026-09-19 DK)**: same skeleton with the following substitutions — step 1's interval is each revoked device's **validity interval** (`chain.device_added` [or the first key of `add_member` / `genesis` starts the membership interval] ~ `chain.device_revoked`), intersected with the target's per-environment access windows (step 2) and the device's scope (the payload of `chain.device_added`). Step 3's (a) is the `var.read` rows within the membership interval whose **`actor_key_fingerprint` is in the revoked FP set** (per-device "definitely obtained" — more precise than the remove variant's user_id matching. Aggregate-form `var.read` rows also carry the actor key FP). Steps 4–5 are the same. `rotation.recommended` gets `trigger = revoke_device`, with the target user_id and the revoked FP set in its payload. The target stays a member, so the membership interval does not close (like the demotion variant, detection uses "a window cut at the trigger seq"). Revoking a device whose scope is empty (a vote-only device) yields empty candidates and writes no row

### C-4. Addition to §4.2 (one sentence in Q1)

> Add `chain.device_added` / `chain.device_revoked` to Q1's enumeration (the payload's FPs and cap are the open/close points of a device's window — the `revoke_device` variant of §4.1). The index (target_user_id, seq) is unchanged (`chain.device_added`'s target is the actor themself)

### C-5. Addition to §6 (one item)

> - **Device keys do not change visibility classes (2026-09-19 DK)**: `chain.device_added` / `chain.device_revoked` are class 1 (`chain.*`). The device registry (AUTH_SPEC §13-11) is not an audit target (same discipline as the token list). The rotation-needed flag view, including the `revoke_device` variant, is class 1

---

## D. Sentences appended to the Status lines

CRYPTO_SPEC:

> 0.12-draft = DK (device key separation — per-device revocation. 2026-09-19 design session. Design record: docs/notes/dk-design.md, as-drafted drafts: docs/notes/dk-spec-drafts.md): §3's device keys / reserve key / cap (resolving the v1 simplification — open item #2) / §5.1's device-key selection / §6.2's `add_device` / `revoke_device` (principle D1 = keys belong to devices, authority to people; substitution of effective authority; monotonicity; key uniqueness over the device set; R(E) on the device axis; four-eyes votes in device vocabulary) / §6.3's key selection and 3′ / §6.4's device count / §6.5 / §6.6's one sentence / §7's revocation obligation and backfill / §8's reserve-key-ification, removal of `kind = "device"`, guardian segments expanded per device / §11 vector appends and `master-key-wrap.json` regeneration / §13 #2 resolved / §14.2 guarantee 11, §14.3 non-guarantee 10. The 16 design items were owner-approved on 2026-09-20 (design record §4) — **merging this revision PR constitutes approval of the spec wording**

AUTH_SPEC:

> 0.24-draft = DK (2026-09-19 — CRYPTO_SPEC 0.12-draft. Design record: docs/notes/dk-design.md): §5's registry read / §6's device-token correspondence / §11-1's two ops / §12-3's reader self-backfill / §12-6's slot on the device axis and sixth registration path / §12-8's device count / §13's reserve-key-ification, removal of the old-device path, guardian segments as device rows, new §13-11 device registry and add requests / §16-1's per-device attestation. The 16 design items were owner-approved on 2026-09-20 (design record §4) — **merging this revision PR constitutes approval of the spec wording**

AUDIT_SPEC:

> 1.9-draft = DK (2026-09-19): §2's note that key FP = device / §3.4's `chain.device_added` / `chain.device_revoked` / §4.1's `revoke_device` variant (device windows, (a) matching by actor key FP) / §4.2 Q1's enumeration / §6's classes unchanged. The 16 design items were owner-approved on 2026-09-20 (design record §4) — **merging this revision PR constitutes approval of the spec wording**
