# Spike C results: the E2EE round trip + selecting an HPKE library

Date: 2026-08-01. A ROADMAP Phase 0 verification spike. Input for CRYPTO_SPEC undecided item #1 (the HPKE library choice).
**The throwaway code lives in `spikes/spike-c/` and is not product code. No code was placed in `packages/crypto` at all.**
The final selection is made by a human (this memo goes only as far as a recommendation).

## What was verified

CRYPTO_SPEC §2's suite **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM** (HPKE Base mode), verified against the 2 leading candidate libraries as of 2026-08.

| Candidate | Composition | Version (exact pin) |
|---|---|---|
| **hpke-js** (dajiaji) | `@hpke/core` + `@hpke/dhkem-x25519` (+ the internal dependency `@hpke/common`) | 1.9.0 / 1.8.0 |
| **hpke** (panva) | a single package, zero dependencies | 1.1.3 |

Results of mapping the candidates (the latest survey as of 2026-08-01):

- **No standalone HPKE implementation exists in the @noble family**. @noble/curves and @noble/ciphers are primitives only. A noble-based HPKE does exist as `@panva/hpke-noble` (an extension of panva's hpke — for PQ KEMs / SHAKE KDFs / ChaCha20Poly1305), but it is not needed for this suite (X25519 + AES-256-GCM). CRYPTO_SPEC undecided #1's candidate notation "the @noble family" effectively converges onto panva's hpke
- Other candidates (`hpke-wasm` etc.) were not dug into — they trail the above two on maintenance status and adoption
- panva's hpke has existed since 2022 (0.x), **reaching v1.0 in 2025-12** — a newer option. It also tracks RFC 9180's Standards Track republication (draft-ietf-hpke-hpke)

## What was verified, and the results

Verification items (`spikes/spike-c/src/checks.ts` — the same checks run in every environment):

1. Each library's self round trip (Seal → Open)
2. Context binding: decryption must fail on an info mismatch and an aad tampering (the premise of CRYPTO_SPEC design principle 3)
3. Interop: Seal with hpke-js → Open with panva, and vice versa (indirect evidence of RFC 9180 compliance)
4. The RFC 9180 official test vectors (this suite's Base mode extracted from cfrg/draft-irtf-cfrg-hpke's test-vectors.json):
   - DeriveKeyPair(ikmR) matching (pkRm, skRm) (both libraries)
   - Vector match in the Open direction (both libraries — the receiver side is deterministic, so no derandomize needed)
   - Vector match in the Seal direction (hpke-js only — derandomizable via the `ekm` parameter)

Result matrix (**all environments, all checks pass**):

| Environment | How it ran | hpke-js | hpke (panva) |
|---|---|---|---|
| Node 22 (baseline) | vitest project `spike-c-node` | PASS | PASS |
| workerd | `@cloudflare/vitest-pool-workers` 0.20.1 (userAgent = `Cloudflare-Workers` confirmed) | PASS | PASS |
| Browser (Chromium 151 headless) | vitest browser mode + `@vitest/browser-playwright` | PASS | PASS |
| Bun 1.3.14 | `bun run src/run-in-bun.ts` (run directly since vitest runs on Node) | PASS | PASS |

## What worked

- Both libraries pass this suite's Seal/Open round trip, info/aad context binding, interop, and the RFC 9180 vectors (the scope above) **in all 4 environments**
- WebCrypto X25519 (what panva depends on) works in workerd, Bun 1.3.14, and Chromium by direct measurement. The browser support floor is Chrome/Edge 133+, Firefox 130+, Safari 17.0+ (per caniuse; effectively Baseline in 2026)
- panva hpke: even with a non-extractable (extractable=false) private key, **Open works if a KeyPair (including the public key) is passed** (measured on Bun / Node). Compatible with CRYPTO_SPEC §3's "browser: IndexedDB + non-extractable" policy
- hpke-js: `createSenderContext({ ekm })` can derandomize the Seal direction too, and an exact match with the official vectors' enc / ct was confirmed

## What did not work / what tripped us up

- **When passing a bare private key to panva hpke's Open, extractable=true is required** (Node / workerd / Bun / Chromium — all). The error is `"privateKey" must be extractable or a Key Pair must be used in this runtime`. A constraint for deriving the public key from the private internally. → In implementation, standardize on "pass a KeyPair" and non-extractable operation works (measured, as above)
- panva hpke offers no way to inject ikmE/skE into a one-shot Seal (an intentional API design), so **vector matching in the Seal direction cannot be verified**. It is covered indirectly by Open-direction vectors + interop
- Since `spikes/` is outside the root workspaces (`packages/*`, `apps/*`), `bun install` resolves it as the root workspace and dependencies never install. **Putting a `bunfig.toml` at the directory root makes it resolve as an independent project** (the same trick works for spike-b / future spikes)
- On the first bundle-size measurement I forgot to delete the generated artifacts (`.bundle-tmp/`), and the root oxlint linted the generated JS into a mass of errors. The rule is now to delete generated artifacts immediately

## Comparison per evaluation axis

| Axis | hpke-js (dajiaji) | hpke (panva) |
|---|---|---|
| Works across environments | ✅ 4/4 environments | ✅ 4/4 environments |
| Dependency count | One: `@hpke/common` (though its X25519 is a **vendored copy of noble-curves' ed25519 module** — the audit lineage is cut off from npm's @noble/curves) | **0** (WebCrypto only) |
| Bundle size (bun build --minify, the full suite) | **566 KB (gzip 169 KB)** — includes a full vendored ed25519/ristretto code set | **16 KB (gzip 5 KB)** |
| Audit status | No formal audit (stated in the README). **CVE-2025-64767 (Critical 9.1, 2025-11)**: concurrent SenderContext.seal() reuse of AEAD nonces. Fixed in 1.7.5 | No formal audit. A threat-model document and Security Policy exist. No known CVEs. Author Filip Skokan is a Node.js TSC member and the author of jose (tens of millions of weekly DL) |
| RFC 9180 vectors | ✅ pass (the Seal direction is directly verifiable via ekm. The project itself also tests with the official vectors + Wycheproof) | ✅ pass (Open direction + DeriveKeyPair. Seal direction is confirmed indirectly via interop. The project itself tests with the official vectors) |
| Maintenance | Continuous since 2022; @hpke/core 1.9.0 (2026-03); 257K weekly DL; 120 stars | v1.0 in 2025-12 (young); 1.1.3 (updated 2026-06); 854 weekly DL (still low). Tracks draft-ietf-hpke-hpke (the Standards Track republication) |
| Future PQ migration (maruhi/v2) | ML-KEM family is separate packages (@hpke/ml-kem etc.) | **The MLKEM768-X25519 hybrid is already defined in the core API** (runtimes without WebCrypto support are filled by @panva/hpke-noble). Matches CRYPTO_SPEC's v2 concept |
| Testability | ekm derandomize exists, so the official vectors can be pinned directly even in the Seal direction | No derandomize. Our own test vectors (§11) must be written as "fixed keys + the Open direction" + round trips |

## Recommendation (the final selection is the human's)

**First choice: `hpke` (panva); the fallback path: hpke-js.**

Reasons:

1. **The web dashboard is the Trusted Computing Base** (CLAUDE.md), and "zero dependencies, 16 KB, WebCrypto delegation" has an overwhelming fit with the principle "keep the third-party supply chain minimal". Most of hpke-js's 566 KB is vendored curve implementations whose audit lineage is cut off from npm's @noble/curves (Cure53 audit 2024) — a supply-chain weakness
2. A structure that delegates the crypto implementation to the runtime (a native implementation like BoringSSL) shrinks the surface for nonce-management bugs in JS implementations (like hpke-js's CVE-2025-64767)
3. The X25519+ML-KEM-768 hybrid envisioned for maruhi/v2 already exists in its core API
4. The concerns (young age, low download count) are mitigated by maruhi using only one-shot Seal/Open, and by the existence of a fallback path. The spike confirmed both libraries' API surfaces can be absorbed by one thin adapter (`HpkeAdapter` in `spikes/spike-c/src/adapters.ts`)

What to do on adoption (after human approval):

- Revise CRYPTO_SPEC §2's "candidates: hpke-js, the @noble family" to the selection result, closing undecided item #1
- In the `packages/crypto` implementation, standardize on **KeyPair-passing Open** (compatible with non-extractable keys) and do not build a bare-private-key + extractable path
- Define test vectors (§11) as "the Open direction + DeriveKeyPair + round trips" (fully pinning the Seal direction is impossible with panva)

## Implications for the adoption decision / remaining questions

1. **Browser measurement covered Chromium only**. Firefox / Safari (WebKit) were judged from caniuse's support table (FF 130+ / Safari 17+). Recommend either adding a browser matrix to Phase 1's CI or one manual check on a real Safari
2. Bundle sizes are reference values from `bun build --minify`. Production web is Vite (rolldown), so re-measure in spike A / Phase 1
3. panva hpke's low download count carries the "if it breaks, you're the first to find it" risk. Covered by exact pinning + independent-PR updates (ADR-0011's operation)
4. The CLI (Bun) stores raw bytes in the OS keychain → expected to import each time. Since that import is extractable=true anyway, panva's extractable constraint is a non-issue on the CLI side (equivalent once a raw key is in memory)
5. Neither library is audited. No HPKE library in the JS ecosystem as of 2026-08 literally satisfies "audited libraries only" (CRYPTO_SPEC design principle 2). The cleanest framing is: panva is the option with the highest degree of delegation to the runtime's built-in WebCrypto (an audited native implementation). **Reconciling design principle 2's wording with reality needs human judgment**

## Root changes to integrate when adopting for real (including what is already done on this branch)

- Added `spikes/**` to `.fallowrc.json`'s `ignorePatterns` (done — excludes throwaway code from dead-code analysis). Revert this line too if spikes/ is deleted wholesale after the spike completes
- Root `package.json` / `vitest.config.ts` / `ci.yml` are unchanged. The spike's tests are not included in the root `bun run test` (intentionally — throwaway code does not become a CI target)
- When building crypto's 3-environment CI (CRYPTO_SPEC §11) in Phase 1, this spike's vitest 3-project setup (node / workerd / browser) + a direct Bun run is the ready-made template. The browser side is reproducible on CI via `@vitest/browser-playwright` 4.1.10 + `bunx playwright install chromium`
