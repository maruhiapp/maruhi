# Working notes: hardware backing for device keys — comparing sealing approaches

Date: 2026-08-10. Working notes toward the future design of CRYPTO_SPEC open item #2 (device key separation / passkey PRF).
**This memo is not a spec change**. Adoption and detailed design are ruled on by the owner when device key separation is designed in Phase 2 or later (the order — CRYPTO_SPEC revision → human approval → implementation — is unchanged).

**Cross-reference (added 2026-09-19)**: the device key separation (DK) design record is docs/notes/dk-design.md (ruling DK-I confirms its relationship to this memo's approach 3 [sealed backends] — the shape of the device key record is unchanged and does not preclude sealing. The reserve key is not sealed with a device-bound sealer). The sketch in this memo's §6 "revisions required on adoption" dates from 2026-08-10 and does not reflect the later KL3 (§8 ledger) / ES (scope) / PF1 (four-eyes) revisions — dk-design.md §1-3 is the source of truth for the current impact surface. The contents of this memo itself have not been rewritten.

## 1. Background and trigger

The trigger was mizdra's article "Managing Git commit signing keys with Secure Enclave" (<https://www.mizdra.net/entry/2026/08/07/101542>). Key points:

- Generate a non-exportable ECDSA P-256 key inside macOS Secure Enclave (SE) (`sc_auth create-ctk-identity`) and use it for Git commit signing as an SSH signature
- The motivation: "while work is delegated to a coding agent, commits get interrupted by 1Password's biometric authentication timeout." A resident SE key can sign without interactive authentication, and the private key never leaves the chip
- A limit the article itself states: malware on the same device can *request* signatures from the SE (the key cannot be stolen, but it can be used)

maruhi's current state and points of contact:

- The CLI stores the master private key as raw bytes in the OS keychain and imports it on each use. Per spike-c.md finding 4, "the moment a raw key exists in memory it is equivalent to extractable=true" — this is effectively the weakest point of the client TCB
- v1 copies one master keypair per user to every device (CRYPTO_SPEC §3). Losing one device = compromising the whole identity, with no way to revoke per device
- The concern behind agent detection (`gunshi/agent`) lies on the same line as the article's motivation

What maruhi should take from the article is not "Secure Enclave the tool" but **the property of "a long-term key cannot be taken out of the device"**.

## 2. Premise: every approach requires device key separation first

All approaches below assume device key separation (open item #2). The core security value is not the hardware itself but **revocability** (device lost → revoke only that device's key on the chain and rotate the epoch). Device key separation itself is a large spec revision reaching §3 (key hierarchy), §5 (wrap fan-out = members × devices), §6 (chain ops: device add/revoke), §8 (recovery), and AUTH_SPEC (device registration API); hardware backing is a hardening layer on top of it.

## 3. Comparing the approaches

### Approach 1: hardware-resident keys (a direct translation of the article)

Generate the device key itself as non-exportable inside SE / TPM and delegate signing and key agreement to the hardware.

- Advantage: the private key never appears even in process memory (strongest custody)
- Disadvantages:
  - SE is P-256 only. `maruhi/v1`'s X25519 / Ed25519 cannot be hosted — **a suite change is mandatory**
  - **Structural collision with PQ migration**: `maruhi/v2` (X25519+ML-KEM-768 hybrid) KEM cannot be hosted on hardware. Binding keys to hardware binds the algorithms to the hardware's update cycle
  - Not reachable from WebCrypto; per-OS native bindings (Security.framework / CNG / TPM2-TSS) would invade the crypto protocol implementation (collides with the absolute rules)
  - CI runners and containers have no SE / TPM, so it cannot be made mandatory (a soft-key path permanently coexists, doubling the test matrix)
- Verdict: unsuitable for enc (HPKE) keys. The "put only sig keys in SE" variant is sound, but nearly the same gain can be recovered without a suite change as a sealing backend in approach 3, so it is not adopted on its own

### Approach 2: PRF sealing (sealed device keys)

Device keys stay software keys (still X25519 / Ed25519); a secret derived from hardware via the WebAuthn PRF extension / CTAP2 hmac-secret is used as a KEK to **seal (encrypt) them for storage**. They are unsealed in memory only at use time.

- Zero suite change (sealing is a local storage layer; it never appears in the wire protocol)
- No impact on PQ migration (just swap the sealed key)
- Same mechanism on two transports: Web (WebAuthn PRF) and CLI (CTAP2 hmac-secret)
- Same family as ADR-0014's sealed backup and the ROADMAP's "device keys via passkey PRF" (a concrete realization of the default route)
- What is lost: the key is exposed in memory while unsealed. However, since maruhi injects plaintext values into child-process environment variables at runtime, the effective delta of "never even in memory" against same-device malware was small to begin with (per the article, approach 1 also cannot beat request attacks). What sealing protects is **exfiltration at rest** (long-term key leakage via disk, backups, keychain dumps) — equivalent to approach 1 there

### Approach 3: sealing backend abstraction (the general form of approach 2. **This memo's recommendation**)

Make "device keys are stored sealed" the contract, with the sealer pluggable:

| Sealing backend | Supported environments | Characteristics |
|---|---|---|
| FIDO2 hmac-secret (roaming authenticators such as YubiKey) | All OSes (CLI via libfido2 family) | Reference implementation. Portable, shares the mechanism with Web |
| Secure Enclave (wrap key protected by `kSecAttrAccessControl`) | macOS | No dongle needed. **Used only for sealing, so even P-256 requires no suite change** (recovers the article's benefit while avoiding every approach-1 drawback) |
| TPM2 | Windows / Linux | Platform version of the above |
| Passphrase (KDF must be chosen; Argon2id etc.) | All environments | Fallback. For hardware-less environments and emergencies |

- The essential difference from approach 1 is that SE / TPM **reappear here as sealers**: the hardware key never appears in maruhi's crypto protocol at all — it stays at the level of using the OS's secure storage feature (the same layer as the current OS keychain trust)
- The same device key can be **multiply sealed** under several sealers (e.g. YubiKey + passphrase). Losing or breaking one sealer does not directly mean lockout — redundancy that is impossible in principle with approach 1's non-exportable
- A sealed blob is ciphertext, so server custody becomes an option too, and there is room to unify it with sealed backup (ADR-0014) and the device-add flow into a single mechanism

## 4. Alternatives considered and rejected, or deferred to complements

- **Direct PRF derivation** (no sealed blob; keys derived deterministically from the PRF output): zero stored material is attractive, but PRF output differs per authenticator so multiple sealers cannot be stacked, and the identity is irreversibly bound to a single piece of hardware. Recovery design also breaks. **Rejected** (the sealing approach is a strict superset)
- **Server-assisted unlock** (split the KEK into a device share and a server share, 2-of-2, released by the server only on authentication): it has unique value — "immediate remote kill without epoch rotation" and "defeating offline attacks against a stolen sealed blob + PIN". But every unlock requires being online, and server availability = lockout risk; and it is **composable** with sealing (KEK = KDF(hardware secret, server share)). So it is classified not as a replacement but as **a future option layer that can be stacked on top of approach 3**
- **Delegation to ssh-agent / age plugins**: signing can be delegated but HPKE Open (Decap) does not go through, so it cannot cover maruhi's core operations. It also increases dependence on external agents' security. **Rejected**

## 5. To verify (spike items when adoption is considered)

1. Whether a CTAP2 hmac-secret can be obtained **without a touch** (an assertion with up=false) depends on the authenticator's implementation and settings. Is "unseal once at session start → cache in process memory (consistent with the diskless invariant)" sufficient for agent operation, or is touchless unsealing mandatory
2. Platform authenticators (Touch ID etc.) cannot be reached from the CLI via CTAP (native OS APIs are needed). The plausibility of the realistic default CLI configuration = roaming key + SE/TPM backend
3. Supply-chain evaluation of native dependencies such as libfido2 (reconciling with the minimal-dependency rule). Sealing is a local storage layer, not wire crypto, but because it touches key handling it requires the same level of human review as `packages/crypto`
4. Feasibility of CTAP access paths from Bun (FFI / subprocess) and the coexistence design with Bun.secrets (the current keychain storage)

## 6. Revisions required on adoption (impact surface sketch)

- CRYPTO_SPEC: §3 (device key hierarchy), §5 (device granularity of wrap targets), §6.2 (chain ops for device add/revoke), §8 (relationship to recovery). All via the owner approval flow
- AUTH_SPEC: device registration / revocation APIs
- ROADMAP: this memo's concrete realization of the future item "device keys via passkey PRF"

## 7. Recommendation summary

| Item | Recommendation |
|---|---|
| Device key separation (the premise architecture) | **Strongly recommended** (revocability is the core value. The main line of open item #2) |
| Approach 3: sealing backend abstraction (reference = FIDO2 PRF) | **Recommended** (adopt as the default route) |
| Approach 1: hardware-resident keys | Not recommended on its own (even limited to sig keys, approach 3's SE sealing yields nearly the same gain without a suite change) |
| Server-assisted unlock | A future option layer (composable with approach 3. Not adopted standalone) |
