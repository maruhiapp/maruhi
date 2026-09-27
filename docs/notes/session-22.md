# Session 22 memo (Phase 2 planning + R1–R3 design exploration + spec drafting)

Date: 2026-08-12. Prerequisite: main with PR #55 + the LICENSE set (ADR-0003 settled) merged.
Branch: `claude/maruhi-phase-2-features-yzi01b`.
Scope: the plan ruling for Phase 2 "feature development" (owner-approved), the R1–R3 design exploration
(4 rounds — each round produced an upward-compatible option), and the resulting spec drafting (CRYPTO_SPEC 0.5-draft /
AUTH_SPEC 0.9-draft / AUDIT_SPEC 0.7-draft). **The publication-side tasks (SECURITY.md,
threat model, Deploy button, maruhi.dev, trademark) are not started (owner ruling)**.

## 1. The approved plan (Wave structure and PR splits)

- **Wave 1 (no ruling needed, start immediately, direct dogfooding benefit)**:
  PR-1 `maruhi env rotate` (the rotation CLI; the server-side decrypt path is implemented,
  including resuming an interrupted re-encryption push) / PR-2 the parity check `maruhi env diff`
  (comparing verified statements from 2 metadata-only pulls) /
  PR-3 release foundation (tag-driven CI, bun compile binaries, checksums,
  npm provenance) / PR-4 install script + brew tap
- **Wave 2 (after this spec PR is approved)**:
  A = workload leases (A1 server-key foundation + grant/revoke CLI + server-bound
  wraps, A2 OIDC verification + the lease endpoint + audit, A3 the CLI's CI mode +
  the setup-maruhi action) / B = team sharing (B1a invite API + acceptance, B1b member-management
  CLI + backfill + remove → forced all-environment rotation, B2 rotation-needed detection) /
  C1 = the audit read API + `maruhi audit`
- **Wave 3**: D = head gossip + the environment manifest (CRYPTO_SPEC undecided #12;
  design doc → ruling → spec → vectors → implementation) / W = the Web dashboard
  (starting from W0 screen design) / G = the docs site (Blume)
- Dependencies: B1b depends on PR-1 (rotate). B2's revoke_server variant activates after A is
  implemented. W2 (the audit UI) depends on C1. PR-3/4 are prerequisite parts for A3 (CLI installation in CI)

## 2. Conclusions of the R1–R3 design exploration (key points of the 4 rounds)

### R1: CI integration = workload leases (OIDC)

- **Push-style GH secrets sync rejected**: (1) the GH secrets write API requires a libsodium
  sealed box = a new dependency violating the absolute crypto-primitive rule, (2) keeping a PAT
  resident on the server (a server compromise's blast radius extends to repo-secrets writes),
  (3) a plaintext copy into GitHub, (4) the server decrypting every value
- **Adopted = the OIDC lease form**: a CI job generates an ephemeral X25519 key → presents an OIDC token to
  the lease endpoint → the server opens its own-bound wrap and re-wraps the DEK to the ephemeral key
  (**values are never decrypted**). Zero stored material on the GitHub side. CI verifies chain + value signatures +
  commitments (pinning genesis in the CI configuration) = even a compromised server injecting fake values is
  detectable. Also serves as the foundation for Phase 3 (agent leases)
- **The trust policy is chain-bound** (grant_server payload's lease_policy).
  Pinned in the **generic issuer form** (issuer_url + audience + claim exact-match constraints), and
  v1 enables GitHub only. Consensus rules pin only the structure; evaluation semantics live on the AUTH_SPEC side
  → adding GitLab / CircleCI / k8s etc. needs no chain-format change (no grandfathering).
  **Now, before publication, is the last window to settle the payload format** (resolves §6.2's 2026-08-03 note)
- The re-grant rule is **two-layered**: disclosure scope = widen-only (narrowing goes through revoke + all-environment
  rotation), while lease_policy = freely revisable (it is an ACL and does not change the known-DEK set)
- Adjacent: server-key uniqueness (`duplicate-server-key`) is also made a consensus rule in the same window.
  The grant CLI requires an explicit environment (the least-disclosure default) + a server-key-FP verification
  ceremony. The push form stays shelved as an add-on with a libsodium exception ruling when real demand
  (third-party actions needing `${{ secrets.X }}`) appears

### R2: Invites = unified (no public-key directory)

- **Directory rejected**: a structure of "unconsented addition" where knowing a user_id lets you
  add_member without their agreement + a new trust object. An already-shared chain already
  plays the role of a verified directory
- **Adopted**: a single mechanism "invite → accept → add_member" for both registered and
  unregistered users. Acceptance carries a signature over the invite token's hash (demoting link
  interception from "a silent key substitution" to "a noisy race"). **FP confirmation is mutual** (one-directional
  leaves the reverse-phishing path where a fake invite has the victim join an attacker-owned
  project and push real secrets — the attacker is a legitimate owner of their own project, so
  chain verification raises no alarm)
- **Invite-link anchor**: the link's URL fragment (invisible to the server) embeds
  genesis + the inviter's verified head + the inviter's FP → rewinds and fork distributions
  aimed at the new member (no floor, first sync = §14.3-3's dominant residual) become detectable
  via the invite path. **The repository anchor** (a non-secret anchor file committed to git) is
  the same idea for CI — both are partial realizations of undecided #4
- The FP word display is 12 BIP39 English words (128-bit preserved. A shortened code lets the attacker
  choose one of the compared keys = weaker against second-preimage search = rejected. Locale-independent)

### R3: Audit reading = visibility classes

- Restricting the chain-mirror family to admins is **security theater** (every member already
  verifies the same facts via chain sync). The line-drawing principle =
  "**monitoring information about people's actions, or operation of the disclosure mechanism**"
- Class 1 (all members): chain.* / meta-operation family / var.version_pushed /
  **server.*** (everyone has a stake in knowing disclosure exercises) / rotation-needed flags /
  rows where oneself is the actor. Class 2 (admin+): var.read / dek.* / invite.* /
  cross-cutting search of others' rows
- server.lease_denied is recorded under the same fixed-window cap as login_failed (making probes visible)

### Main rejected options (recorded for reconsideration)

Proxy re-encryption (a nonstandard primitive) / pre-leased pools or CI-resident keys
(reintroducing static credentials) / embedding key material in invite links (a link leak = a key leak) /
TOFU by default (contradicts ADR-0014's fingerprint-confirmation ceremony) / shortened confirmation codes /
eventifying audit reads or aggregate-only views (breaks Q4 incident response)

## 3. The drafted spec revisions (this branch; merge constitutes owner approval)

- **CRYPTO_SPEC 0.5-draft**: §3 FP word display / §6.2 lease_policy extension +
  `duplicate-server-key` / §6.3 two-layered re-grant + out-of-band anchors /
  §6.5 invite-acceptance signature (resolves undecided #9) / §7・§9 resolving the line on server-bound wraps /
  §9.1 workload leases / §11 vector supplement / §13 #4 partial realization / §14.3-3 addition
- **AUTH_SPEC 0.9-draft**: §4 serverKeyFingerprintHex / §11-1 references to invites /
  §12-4・§12-6 server-key-bound wraps (the complete decryption set + backfill right after grant) /
  §14 the lease API / §15 the invite API
- **AUDIT_SPEC 0.7-draft**: §3.2 invite.* (same D1 batch) / §3.5 the lease-family
  events (value_decrypted reserved) / §4.1 variant updates / §6 visibility classes
  (resolves undecided #1) / §7 the read API's shape
- Rate limits and cap values are draft values (adjusted in review). Implementation test vectors are
  committed after spec approval and before implementation (the §11 list)

## 4. Handoff for implementation (a handoff to other sessions)

- **This spec PR's approval (merge) is Wave 2's prerequisite**. Wave 1 (PR-1–4) can start without
  depending on the spec
- Reading order for each implementation session: this note → CLAUDE.md → CRYPTO_SPEC
  (§6.2 / §6.3 / §6.5 / §9.1) → AUTH_SPEC (§12 / §14 / §15) →
  AUDIT_SPEC (§3.5 / §6 / §7) → ROADMAP
- The crypto-side changes (lease-wrap / invite-accept-signature / dek-wrap extension /
  chain-entries regeneration) are **test-vectors-first + mandatory human review**
- Human tasks (owner): creating the brew-tap repository (PR-4), confirming publish
  permission on the npm org (PR-3), registering the OAuth App for the dogfooding environment
  (session-19 §6 — continuing)
- Kept undecided: #12 (head gossip + the environment manifest — starting from a design doc at the head of
  Wave 3), #10 (the server-key rotation procedure — the lease spec was drafted not to
  depend on it), audit var.read aggregation (#4 — after dogfooding measurements)
