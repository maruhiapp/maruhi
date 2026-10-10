# Reviewing maruhi — a guide for external security reviewers

This guide is for a cryptographer or security engineer who has never seen the
repository and wants to attack it. It tells you what the system claims, where
each claim is specified and enforced, how to re-check the test vectors on your
own, and what is known not to hold. It is a map, not a second specification:
the normative text is [CRYPTO_SPEC](CRYPTO_SPEC.md) (the single source of truth
for cryptography), [AUTH_SPEC](AUTH_SPEC.md) and [AUDIT_SPEC](AUDIT_SPEC.md).
Section references below (`§`) point into those documents. maruhi has not had
a paid audit; this guide is one part of the free substitute (with
[SECURITY.md](../SECURITY.md), named requests and formal models —
[ROADMAP](../ROADMAP.md) H5).

## 1. What maruhi is, and whom it trusts

maruhi is a secrets manager. The server is a Cloudflare Worker with one
Durable Object per project and D1; the client is the `maruhi` CLI, which does
every encryption, decryption and signature, and every verification a member
relies on (the server also verifies, against rogue clients — §6.4; with an
opt-in grant it unwraps and re-wraps DEKs for workload leases — §9.1). Values are encrypted
with AES-256-GCM under a per-environment, per-epoch DEK; each DEK is
HPKE-wrapped to every device key allowed to read that environment; who may do
what is decided by a per-project signed hash chain (the membership log) that
the CLI re-verifies in full on each sync (CRYPTO_SPEC §2–§6). maruhi's own
data is protected with WebCrypto and the `hpke` library only, with no custom
protocol or primitive (§1 principle 2, §2, §12).

The trust model, as the specs state it:

| Property | Does it depend on the server? | Where it is stated |
|---|---|---|
| Confidentiality of values, DEKs and private keys | No, against the chain view the client verified. The server stores ciphertext and wrapped DEKs only. Two qualifications: a project owner can grant the server key ("member N+1") for chosen environments (opt-in; while a verified grant is active, every CLI command that opens the project states the disclosure with the server-key fingerprint and the granted environments, and the web dashboard lists granted server keys); and a client encrypts to the recipients of the view it verified, so a server that withholds a removal or a rotation from a client without a floor or anchor past it (the freshness row) can get new values written under a DEK a removed member still holds | CRYPTO_SPEC §1 principle 1, §7, §9, §14.3-3 |
| Integrity and attribution of values, metadata statements, DEKs and the chain | No. Clients verify signatures, the chain's consensus rules and the DEK commitments; "the server alone can forge neither values, names, nor DEKs" | §6.3, §14.2-1, §14.2-2 |
| Freshness and completeness (rollback, omission) | Partly. Detected through the local floor, out-of-band anchors, checkpoints and head gossip; not guaranteed for a client that holds neither a floor nor an anchor, and a split view is not guaranteed to be detected | §14.1 G5–G7, §14.3-3, §14.3-4 |
| Availability | Yes. A malicious server can refuse, delete or delay | §14.1 G8, §14.3-1 |
| Who may download ciphertext; plaintext metadata | Yes. The server gates reads by the chain-derived member set and scope. Environment and variable names, schema fields, org attribution and membership are plaintext metadata the server can read | §6.4, AUTH_SPEC §11-2, CRYPTO_SPEC §14.2-9, §13 open item #3 |
| The audit log | Yes at record time (server-managed data). Post-hoc tampering of a prefix notarized in a checkpoint is detectable | AUDIT_SPEC §6, CRYPTO_SPEC §14.2-7 |
| Authentication (sessions, API tokens) | Yes (GitHub OAuth, server-issued sessions and tokens). A session cannot sign chain entries: device private keys never leave the device | AUTH_SPEC §1, §5, §6; CRYPTO_SPEC §3 |

Short form: the server is trusted for availability, for freshness toward a
client that holds neither a floor nor an anchor, and for gating access to
ciphertext and metadata, not for the confidentiality or integrity of secrets
against the view a client has verified.
The hosted web dashboard holds no keys and no plaintext and does not verify
anything; it shows what the server reports ([ADR-0018](adr/0018-web-trust-boundary.md),
revision 2).

## 2. Invariants worth attacking

Paths are from the repository root. "Break" describes what a finding would
look like.

| Invariant | Specified | Enforced | Break |
|---|---|---|---|
| Plaintext secrets and key material never cross the API, and never reach logs or error messages | CRYPTO_SPEC §10, §12; AUTH_SPEC §12-2, §12-10; [CLAUDE.md](../CLAUDE.md) | `packages/api-schema/src/data.ts` (`EncryptedPayloadSchema`), `packages/api-schema/src/strict.ts`; client-side encryption in `packages/crypto/src/internal.package/variable.ts` | Any wire field, server log, CLI error or crash path that carries a value, a DEK or a private key |
| The membership chain alone decides authorization (roles, scopes, device caps, four-eyes; an API token can only narrow it — AUTH_SPEC §6) | CRYPTO_SPEC §6.1–§6.4, §1 principle 7 | `packages/crypto/src/internal.package/chain-verify.ts` (consensus rules, shared by both sides); server `apps/server/src/do/chain-accept.ts` re-runs it on every append; CLI `apps/cli/src/chain-sync.ts` re-verifies the whole chain and checks genesis hash = project ID | An entry one verifier accepts and the other refuses; a role or scope escalation; a four-eyes target applied without the quorum |
| DEKs are authentic and reach only in-scope device keys | CRYPTO_SPEC §5.1, §5.2, §14.2-1, §14.2-9; AUTH_SPEC §12-6 | `dek-commitment.ts`, `dek-wrap-sign.ts` (crypto); `apps/server/src/dek-wraps.ts`; `apps/cli/src/dek-wrap.ts` (builds the recipient set R(E)), `apps/cli/src/deks.ts` | A DEK accepted without matching the on-chain commitment; a wrap for an out-of-scope or revoked device accepted or generated |
| A workload uses a lease only when the verified chain's active grants cover the environment | CRYPTO_SPEC §9.1 obligation (6); AUTH_SPEC §14-1 (the server's own scope check) | `apps/cli/src/lease-client.ts` (`requireLeaseGrant`, after chain verification and the anchor, mints the `LeaseGrantCheck` that `unwrapLeases` requires, so no lease wrap is opened without it; the active grants come from `apps/cli/src/server-disclosure.ts`); server `apps/server/src/programs/programs-lease.ts` (`grantCoversEnvironment` — a uniform 404) | A lease wrap opened, or a value decrypted, for an environment no active grant on the verified chain names |
| Meta statements: a stale-but-honest statement gets 409, a 422 always means malformed or forged | CRYPTO_SPEC §4.2; AUTH_SPEC §12-5 "Check order" | `apps/server/src/data/verify-meta.ts` (`acceptMetaStatement` — every predecessor-dependent check runs after the metaVersion CAS); `meta-sign.ts` / `meta-verify.ts` (crypto) | A predecessor-dependent check reachable before the CAS (an honest client is told its statement is forged), or a forged statement answered 409 |
| Environment deletion is chain-derived and terminal | CRYPTO_SPEC §6.2 `delete_environment`, §6.3 "Chain-deleted environments", §14.2-12; AUTH_SPEC §12-4 | `chain-verify.ts` (`environment-deleted`, no reuse); `apps/server/src/programs/composite-programs.ts` (`deleteEnvironmentCompositeProgram`: the entry and the data cascade in one DO transaction; scope judged after the head CAS); CLI `apps/cli/src/scope.ts`, `apps/cli/src/values-verify.ts` (refuses a resurrection), `apps/cli/src/env-rm.ts` | A deleted environment served as live and accepted; an id reused; a deletion by a signer without admin role or scope |
| The local floor detects rollback, regression and equivocation for a returning client | CRYPTO_SPEC §6.3 "The local floor", rules (a)–(c) | `apps/cli/src/floor.ts` (join semantics), `apps/cli/src/floor-check.ts` (rules), `apps/cli/src/floor-log.ts` (append-only storage) | A shortened chain, an older version or epoch, or a forward injection that a floor-holding client accepts; a fact joined into the floor without having been verified |
| Out-of-band anchors and head gossip narrow the first-sync and split-view residue | CRYPTO_SPEC §6.3 "Out-of-band anchors", "Head gossip", §6.6; AUTH_SPEC §16 | `apps/cli/src/anchor.ts` (repository anchor), `apps/cli/src/invite-accept.ts` (invite-link anchor pin), `apps/cli/src/attestation.ts`; `head-attestation.ts` (crypto); `apps/server/src/attestation-accept.ts` | A view that omits the anchored head yet passes; a contradicting head declaration that is not reported as evidence |
| The invite link key: the server can never swap the acceptance key | CRYPTO_SPEC §6.5, §14.3-9; AUTH_SPEC §15 | `invite-link.ts`, `invite-accept-sign.ts` (crypto); CLI `apps/cli/src/invite-create.ts` (the seed lives only in the URL fragment), `apps/cli/src/invite-accept.ts`, `apps/cli/src/github-signing-keys.ts`; server `apps/server/src/handlers/handlers-invites.ts` verifies both acceptance signatures | The link-key seed reaching the server; a valid acceptance under a key the link holder never approved; an issuance signature that does not bind role, scope or head |
| Values are shown only to a person at an interactive terminal | [ADR-0016](adr/0016-effect-cli.md) decision 7; CLAUDE.md | `apps/cli/src/agent-gate.ts` (`ensureValueDisplayAllowed`: refuses a known agent, detected in `apps/cli/src/live.ts`, and refuses unless stdin and stdout are both terminals) | A value-displaying path that skips the gate; a non-terminal context that passes. Note the TTY check is a fail-closed guard, not human authentication (ADR-0018 revision 1 item 4) |
| The web dashboard ships no decryptor and runs under a strict CSP | ADR-0018 decision 1 and revision 2; AUTH_SPEC §15-3; CLAUDE.md | `apps/web/scripts/write-headers.ts` (`script-src 'self'` plus the build-time hash of our own bootstrap script, `script-src 'none'` on `/invite`, the build fails on violation); `apps/web/test/e2e.test.ts`; `apps/web/test/unit/endpoints.test.ts` (import tripwires: no value import of `effect` or `@maruhi/api-schema`, and no reference to `@maruhi/crypto` at all — `apps/web/src` imports nothing from it) | Script execution under the CSP; a decrypt or wrap code path in the shipped bundle; `/invite` interpreting the fragment |
| Actors in the chain and the audit log are internal user ids and key fingerprints only | CRYPTO_SPEC §12; AUDIT_SPEC §2, §5.1; AUTH_SPEC §11-1 | `packages/core/src/identity.ts` (`UserId` / `ProviderUserId` / `KeyFingerprintHex` brands, minted only at trust boundaries; the mint sites are restricted in `.oxlintrc.json`), `packages/core/src/audit-payloads.ts` (one payload schema per audit event, checked at each store's append; `packages/core/test/audit-inserts.test.ts` pins that no insert bypasses it) | A provider identity (GitHub id, login, email) written into an append-only structure |
| The CLI writes no plaintext secret to disk | CLAUDE.md "CLI diskless invariants" | `apps/cli/src/run.ts` (values injected into the child's environment only), `apps/cli/src/keychain.ts` | A value, DEK or key in a file, a temp file, a cache or the floor |

## 3. Spec-to-code correspondence

Crypto files are in `packages/crypto/src/internal.package/`, server files in
`apps/server/src/`, CLI files in `apps/cli/src/`, vectors in
`packages/crypto/test-vectors/`. `packages/crypto` is Effect-free and has one
implementation per operation, shared by server and CLI.

| Mechanism | Spec | crypto | server | CLI | Vectors |
|---|---|---|---|---|---|
| Length-prefixed encoding (all AAD, info, signed bytes) | CRYPTO §2.1 | `encoding.ts` | — | — | `encoding.json` |
| Value encryption | CRYPTO §4 | `variable.ts` | — | `push.ts` | `variable-encryption.json` |
| Value write signature | CRYPTO §4.1; AUTH §12-5 | `value-sign.ts`, `value-verify.ts` | `data/verify-value.ts` | `push.ts`, `values-verify.ts` | `value-signature.json` |
| Variable / environment meta statements | CRYPTO §4.2; AUTH §12-5 | `meta-sign.ts`, `meta-verify.ts` | `data/verify-meta.ts` | `meta-statement.ts` | `metadata-signature.json` |
| Environment manifest | CRYPTO §4.3 | `manifest-sign.ts`, `manifest-verify.ts` | `data/verify-manifest.ts` | `manifest.ts` | `env-manifest.json` |
| DEK wrap (HPKE), registration signature, commitment | CRYPTO §5, §5.1, §5.2; AUTH §12-6 | `hpke.ts`, `dek-wrap.ts`, `dek-wrap-sign.ts`, `dek-commitment.ts` | `dek-wraps.ts` | `deks.ts`, `dek-wrap.ts` | `dek-wrap.json`, `dek-wrap-signature.json`, `dek-commitment.json`, `hpke/` (RFC 9180) |
| Sealed value proposals | CRYPTO §5.3; AUTH §14-5 | `sealed-value.ts` | `programs/programs-proposal.ts` | `rotation-proposals.ts` | `sealed-value.json` |
| Chain entries, consensus rules, history | CRYPTO §6.1–§6.4 | `chain-canonical.ts`, `chain-sign.ts`, `chain-verify.ts`, `chain-history.ts`, `chain-device.ts`, `member-scope.ts` | `do/chain-accept.ts`, `do/chain-commit.ts`, `authz.ts` | `chain-sync.ts`, `chain-append.ts` | `chain-entries.json` |
| Checkpoints and value snapshots | CRYPTO §6.2 `checkpoint`, §6.3; AUTH §16-2 | `values-digest.ts` | `checkpoint-accept.ts` | `checkpoint.ts`, `checkpoint-integrity.ts` | `checkpoint-digest.json` |
| Local floor | CRYPTO §6.3 | — | — | `floor.ts`, `floor-check.ts`, `floor-log.ts` | — (unit tests in `apps/cli/test/`) |
| Head declarations and gossip | CRYPTO §6.6; AUTH §16-1 | `head-attestation.ts` | `attestation-accept.ts` | `attestation.ts` | `head-attestation.json` |
| Invites (link key, issuance and joint acceptance signatures) | CRYPTO §6.5; AUTH §15 | `invite-link.ts`, `invite-accept-sign.ts` | `handlers/handlers-invites.ts`, `invite-domain.ts` | `invite-create.ts`, `invite-accept.ts`, `invite-link.ts` | `invite-link.json`, `invite-accept-signature.json` |
| Reserve-key wrap ledger (recovery code, passkey PRF, guardians, handoff) | CRYPTO §8; AUTH §13 | `recovery.ts`, `master-wrap.ts` | `key-wrap-domain.ts`, `handlers/handlers-key-wraps.ts` | `key-recover.ts`, `recovery.ts`, `guardian.ts`, `handoff.ts` | `recovery-wrap.json`, `master-key-wrap.json` |
| Mirrors and export | CRYPTO §9.2; AUTH §11-6, §11-7 | — | `programs/programs-mirror.ts`, `programs/programs-export.ts`, `do/do-mirror.ts` | `mirror.ts`, `project-export.ts` | — |
| Server key and workload leases | CRYPTO §9, §9.1; AUTH §14 | `lease-wrap.ts` | `server-key.ts`, `programs/programs-lease.ts` | `ci-run.ts`, `lease-client.ts` | `lease-wrap.json` |
| Key fingerprints and word display | CRYPTO §3 | `keys.ts`, `fingerprint-words.ts` | — | `fp-words.ts`, `known-fingerprints.ts` | keys and fingerprints from `chain-entries.json`, `dek-wrap.json` |
| Audit-head cumulative hash | AUDIT §5.1, §6 | `audit-head.ts` | `audit-store.ts` | `audit-reconcile.ts` | `audit-head.json` |

The vectors README lists what each file pins and the conventions behind the
negative cases: [packages/crypto/test-vectors/README.md](../packages/crypto/test-vectors/README.md).

## 4. Re-verifying the test vectors yourself

The implementation under test uses WebCrypto and panva `hpke`. How
independent the expected values are depends on the file:

- Python 3 with pyca/cryptography computes most of them
  (`packages/crypto/test-vectors/tools/generate_reference.py`).
- The HPKE Seal direction, which panva cannot derandomize, comes from hpke-js
  in four `.mjs` generators (dek-wrap, lease-wrap, sealed-value,
  master-key-wrap). That is a different HPKE implementation and a different
  X25519, but its AES-GCM and HKDF run on WebCrypto, and
  `generate-master-key-wrap.mjs` also computes HKDF, AES-GCM and SHA-256 with
  Bun's WebCrypto.
- `verify_reference.mjs` is independent code (it does not import
  `@maruhi/crypto`), but it runs on the shipping primitive stack: WebCrypto
  under Bun and panva `hpke`. It re-checks the vectors and the code paths,
  not the primitives.

The HPKE layer is also checked against the official RFC 9180 vectors in
`packages/crypto/test/checks/rfc9180.ts`.

With Bun (version in `.bun-version`) and `python3` with `cryptography`
installed:

```sh
cd packages/crypto/test-vectors/tools
bun install --frozen-lockfile
bun run verify        # the independent reference verifier (CI step 7b)
bun run regen-check   # regenerate in a scratch copy and compare (CI step 7c)
bun run delta -- --base origin/main   # the crypto review aid (CI step 7d)
```

What the CI steps in `.github/workflows/ci.yml` prove, and what they do not:

- **7b** runs `verify_reference.mjs`: every vector checks out on the reference
  stack. It says nothing about whether a vector matches the spec.
- **7c** runs `regen-check.mjs`: the committed vectors are exactly what the
  generator in the same commit produces (formatting ignored). So a vector
  change is only as trustworthy as the generator diff next to it.
- **7d** runs `vector-delta.mjs` on pull requests and writes the report of
  section 5 into the job summary. It approves nothing.
- **Step 11** runs the implementation against the vectors in workerd, a
  browser and Bun (`bun run --filter @maruhi/crypto test:workerd`,
  `test:browser`, `test:bun`); `bun run test` at the root runs the Node
  configuration.

The strongest independent check is the one these steps cannot make: read
`generate_reference.py` against CRYPTO_SPEC (field order, domain strings, the
§2.1 encoding), or write your own verifier from the spec and run it over the
JSON files. The spec-side list of vector cases is CRYPTO_SPEC §11.

## 5. Reading a crypto PR with the R0–R3 review aid

Changes to `packages/crypto` require human review, with the spec revised first
and the vectors committed before the code (CRYPTO_SPEC header, §11;
CLAUDE.md). The review aid sorts a change into a risk class against the
merge-base. The rules err only upward; a class lower than the change deserves
is a bug in the rules. Full rules and the report's contents:
[test-vectors README, "Reviewing a crypto change"](../packages/crypto/test-vectors/README.md).

| Class | Meaning | What to read |
|---|---|---|
| R0 | comments / docs only | the cosmetic file list |
| R1 | deletion / narrowing (positives removed, a `SUPPORTED_*` set shrunk, encodings untouched) | each `src` diff, and that each removal is intended |
| R2 | logic change keeping the encodings | the logic against CRYPTO_SPEC, and every outcome change |
| R3 | new signed bytes, primitive, domain string, suite or dependency, or a surviving vector whose bytes changed (not rebased) | a full crypto review |

Two merged PRs show the shape. Removing layout v2 (PR #329) reports R1:
13 vector entries removed and a supported set shrunk. Moving environment
deletion onto the chain (PR #336) reports R3: two surviving vectors changed
bytes, one changed its expected outcome, and a negative was removed while the
surface it tested remains. Reproduce both:

```sh
cd packages/crypto/test-vectors/tools
bun run delta -- --base 04bef88 --head cddd176   # PR #329 → R1
bun run delta -- --base 46868ba --head 3e464dc   # PR #336 → R3
```

In #336 the R3 names the new chain op itself: `new chain op(s)`
(`delete_environment`, read from the `ChainOperation` union's `op:`
declarations and the vectors' `op` values) and `new field order(s)`
(`delete_environment: ["environment_id"]`, from `payload_field_order` in
`chain-entries.json`), next to the two changed fixtures. Chain-entry signed
bytes begin with the bare suite (`maruhi/v1`), so their shape is reported as
`<suite> ×N`. A chain-op change still deserves a direct read of
`chain-canonical.ts` (payload encoding), `chain-verify.ts` and CRYPTO_SPEC
§6.2: the aid names what is new, not whether it is right.

The aid covers `packages/crypto` only; for CRYPTO_SPEC it reports only whether
the file changed. Check the spec diff against the vector delta yourself.

## 6. Reproducible builds and provenance

What exists today:

- Releases are built from source in CI (`.github/workflows/release.yml`,
  `apps/cli/scripts/build-binaries.ts`): binaries for five targets plus
  `checksums.txt`, smoke-tested on real runners. Third-party actions are
  pinned by commit SHA, Bun by `.bun-version` (CI installs the official zip
  verified against a SHA-256 pinned in `.github/actions/install-bun/action.yml`,
  never from an Actions cache; the npm publish job's Node.js is pinned the
  same way in `release.yml`, and so is the Chrome Headless Shell the gate's
  browser tests run, in `ci.yml`), dependencies by
  `bun install --frozen-lockfile`.
- The npm package is published with `npm publish --provenance` through
  trusted publishing (OIDC, no long-lived token).
- `packaging/install.sh` refuses to install without a SHA-256 match against
  `checksums.txt`. That file is unsigned: integrity rests on TLS to
  github.com, and the script says so rather than claim signature verification.

What does not exist yet (ROADMAP H5 and the Phase 2 CLI-distribution item):

- No signed build provenance or artifact attestation on the release binaries
  (also open as C-3 in [AUDIT_REVIEW_2026-09-26](AUDIT_REVIEW_2026-09-26.md)).
- No reproducible build. Whether `bun build --compile` is deterministic has
  not been tested, and there is no rebuild script or double-build check. You
  can rebuild with `bun run --filter @maruhi/cli build:binaries`, but a
  byte-identical result is not established.
- macOS binaries are not notarized ([RELEASING.md](RELEASING.md)).
- There is no stable release yet; the project is in its pre-release period
  until v0.1.0 ([README](../README.md), "Install").

## 7. Known limitations and residual risks

These are stated in the specs; a finding that only restates one of them is
not new, but a way to widen one is.

- **No availability guarantee**: refusal, deletion, delay (CRYPTO §14.3-1).
- **Plaintext correctness**: a legitimate writer's wrong value is accepted
  (§14.3-2); declared types are advisory (§14.3-7).
- **First sync without floor or anchor**: a server can serve an internally
  consistent old view (§14.3-3). Hiding an environment deletion is such a
  rollback: detectable through the floor, the anchors and head declarations,
  with the same residue for a client that has neither a floor nor an anchor (§6.3 "Chain-deleted environments",
  §14.2-12).
- **Split view** is not guaranteed to be detected; head gossip can be
  defeated by omission (§14.3-4).
- **Collusion residue**: a key that once held member rights, plus the server,
  can inject inside that membership interval; the forward-direction cases are
  listed with their detection limits (§14.3-5).
- **No un-reading**: a former member keeps what they decrypted; revocation
  relies on rotating the upstream credential (§1 principle 5, §14.3-6).
- **Guardian recovery collusion** and **reserve-key exposure** during a
  restore (§14.3-8, §14.3-10).
- **Invite link interception** on the channel it travels over (§14.3-9).
- **Revoked devices keep API tokens** until expiry or explicit revocation
  (§14.2-11).
- **CLI login phishing** in the shape of device-code phishing
  (AUTH_SPEC §4-3).
- **The audit log** is server-written; only notarized prefixes are
  tamper-evident (AUDIT_SPEC §6).
- **Metadata is plaintext** to the server (§14.2-9, open item #3).
- **The terminal gate** stops pipes, CI and known agents, but an unknown agent
  or local process that allocates a PTY passes (ADR-0016 decision 7, ADR-0018
  revision 1 item 4). `maruhi run` hands values to its child by design; its
  output redaction is exact-match and misses transformed output and an unknown
  agent on a PTY ([pf4-design §12](notes/pf4-design.md)).
- **The dashboard is a display, not a verifier** (ADR-0018): its chain view
  folds the server's report without checking it, and a scope it cannot read
  folds to an empty listed scope, rendered "no environments", the same row a
  scope emptied by `delete_environment` gets
  (`apps/web/src/dashboard/chain-view-state.ts`, `reportedScope`). Use
  `maruhi project verify` for a verified member set.
- **The R0–R3 review aid** classes the removal of a keyed-map member like the
  removal of a top-level fixture, never a narrowing by itself: a lone `keys`
  entry is R2, and a derived chain removed with its negatives reaches R1 or R2
  through its own entries, not R3. The removal is listed in the report, and
  the aid approves nothing ([vectors README](../packages/crypto/test-vectors/README.md),
  "Reviewing a crypto change").
- **Open findings** from earlier reviews, including the chain-economics
  performance and scalability items, are tracked in
  [AUDIT_REVIEW_2026-09-26](AUDIT_REVIEW_2026-09-26.md); an earlier full review
  is [SECURITY_REVIEW_2026-08-14](SECURITY_REVIEW_2026-08-14.md).

The consolidated list lives in [THREAT_MODEL.md](THREAT_MODEL.md) (ROADMAP
H5).

## 8. Reporting

Do not put vulnerability details in a public issue. Report through GitHub
Private Vulnerability Reporting — the channel, scope and disclosure process
are in [SECURITY.md](../SECURITY.md).
