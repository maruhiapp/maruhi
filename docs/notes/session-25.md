# Session 25 notes (Phase 2 Wave 2 A3 — CLI CI mode + setup-maruhi action)

Date: 2026-08-17. Prerequisites: main with Wave 2's A1 (PR #63) / A2 (PR #65) /
replay first-binding (PR #67) / B1a (#68) / B1b (#69) / B2 (#70) / C1 (#71)
merged.
Scope: A3 = the CI client for workload leases (`maruhi ci run`) + the in-repo
setup-maruhi action. The final piece of Wave 2 and the finishing of ROADMAP
Phase 2 "GitHub Actions sync". Per CRYPTO_SPEC §9.1 / AUTH_SPEC §14 /
session-24 §8 / security review A-5, **no spec changes in this session**
(client implementation only. Crypto layer, wire shapes, and vectors unchanged).

## 1. Command shape: `maruhi ci run -- <cmd>` (new group `ci`)

Shapes considered and the judgment:

- **Adopted: `maruhi ci run` (group `ci` + subcommand `run`)**. CI mode is not
  a variant of `run` — its **whole premise structure is different**: auth =
  OIDC only (never touches a maruhi token, keychain, or session context —
  AUTH_SPEC §14-1), config = explicit flags only (no config-file dependence —
  §2), floor & pinning = none (disposable runner), verification material =
  bundled in the lease response (no other API called — §14-2). The declaration
  (the required-flag set, the existence of `--audience` / `--anchor`) is also
  entirely different
- **Rejected: `run --ci`**. A form where one flag inverts "which other flags
  are required / forbidden" re-imports into the argument layer the
  "reject options that don't apply to this operation" mechanism that ADR-0016
  decision 6 abolished by going to nested subcommands. With separate
  declarations, no mechanism is needed
- **Rejected: `lease run`**. "Lease" is protocol vocabulary; the user's
  vocabulary is "run it in CI". The grant side (admins) already having
  lease-policy in its vocabulary is a different audience
- It's a group because Phase 3's agent lease (ROADMAP) and future workload
  commands are expected to share the same premise structure (OIDC,
  non-interactive, no keychain). v1 has only one leaf: `run`

## 2. Carrying configuration: explicit flags only (no env vars or config files)

`--server <url>` / `--project <genesis>` / `--env <id>` are required;
`--audience <value>` (default = the server's normalized origin — the
recommended value in AUTH_SPEC §14-1) and `--anchor <path>` (§4) are optional.

- **Why flags**: all 4 values are non-sensitive, and their home is the workflow
  YAML = **repository content that goes through code review**. §9.1's
  verification duty (1) requires "pinning the genesis into the workload
  configuration in advance", and making `--project` (project ID = genesis hash
  — CRYPTO_SPEC §6.4) be written in the YAML puts that "pinning" in the most
  visible place (diff review). Flags are greppable, and a workflow's appearance
  = its runtime values
- **Rejected: a config file**. CI runners have no persistent config, and
  writing a config inside the job just adds one more "on-disk state" while
  hiding the genesis pinning from review. Depending on the existing config
  (`~/.config/maruhi`) would also tangle with the "no login / keychain"
  discipline (the accident surface of silently falling back to
  defaultProject)
- **Rejected: MARUHI_* env-var fallback**. With env, the workflow's appearance
  loses where the value came from (it can be injected from a parent step, a
  composite action, or runner config). Since the point of pinning genesis is
  "the value was reviewed", it's not a default path. Even if a future setup
  action adds an env-exporting form, flag-explicit stays the default
- **Exception = runner-supplied env**: `ACTIONS_ID_TOKEN_REQUEST_URL` /
  `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are the OIDC issuance endpoint supplied by
  the GitHub Actions runner, not user configuration. Reads go through
  `CliIo.envVar` (the Effect service boundary) — the anticipated "extend
  CliServices" turned out unnecessary: `CliIo` already provides envVar
  (production = process.env, tests = a swapped Map), so the discipline of not
  reading `process.env` directly is already satisfied

## 3. Handling the OIDC token and ephemeral key

- **The ephemeral X25519 key is generated in memory per invocation** (WebCrypto,
  private key non-extractable). It appears neither on disk nor in responses and
  dies with the process (§9.1)
- **The token is issued immediately before the lease request** (session-24 §8
  SHOULD — minimizes the first-use window). GET `ACTIONS_ID_TOKEN_REQUEST_URL`
  with `&audience=` appended, Bearer is `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. If
  the env vars are absent, it fails before any communication, naming "outside
  GitHub Actions or missing `permissions: id-token: write`"
- **The token is wrapped in `Redacted` as a bearer credential**. It's unwrapped
  at only two points: (a) reading claims (base64url decode + JSON.parse —
  signature verification is the server's job; the client only reads its own
  token's iss / sub / aud. No JWT library is added), (b) assembling the lease
  request payload (registered in redacted.test.ts's inventory). Never appears
  in logs, errors, or diagnostics
- **claims_digest uses `computeLeaseClaimsDigest`** (A-5-1 — using the builder
  directly bypasses the empty-field guard). A token whose `aud` is an array
  with ≠1 elements is rejected client-side too (same check as the server's
  `ambiguous-audience` — the digest wouldn't be uniquely determined)
- **1 invocation = 1 token = 1 ephemeral key**. The lease endpoint is
  per-environment and `ci run` is per-environment, so §14-1's MUST (when
  leasing multiple environments on one token, present the same key on every
  request) is satisfied by construction. To use multiple environments in one
  job, run `ci run` per environment = a fresh token + fresh key per
  environment (GitHub is a runtime-issuing type so this shape is allowed).
  There is no path that reuses a token across calls
- **`token-replayed` auto-retries once with a fresh token** (session-24 §8 MAY
  — cap 1). The same ephemeral key is presented (a fresh token is unbound, so
  it binds to your key. There's no reason to change the key, and generation
  cost would be wasted). If it's still `token-replayed` after retrying, the
  command fails with guidance treating it as a sign of token leakage
- **429 is not auto-retried**: the window is a fixed 1 hour (§14-3) and a
  in-job retry only spends the window. It shows `retryAfterSeconds` and fails;
  the retry decision is delegated to the CI side (re-run)
- **503 fails with reason-specific guidance** (§14-3's 2 reasons +
  server-wraps-missing): `oidc-jwks-unavailable` = transient (advise re-running
  the job), `server-key-unconfigured` = a deploy-config gap (point at
  SELF_HOSTING.md), `server-wraps-missing` = granted but re-wraps incomplete
  (point at admin rotate / backfill). The wording distinguishes all of these
  from credential abnormalities (don't conflate with 401 — conveying §14-3's
  intent in separating the categories)

## 4. Implementing the verification duties (CRYPTO_SPEC §9.1 (1)–(4))

The lease response is self-contained (AUTH_SPEC §14-2) — it doesn't fetch
verification material from other endpoints. The implementation reuses existing
client-verification parts:

- **(1) Chain verification**: extracted `verifyChainSnapshot` from `sync.ts`
  (full re-verification + genesis hash = the pinned `--project` value +
  declared-head vs derived-head consistency) so both `syncProject` (fetch +
  verify) and the lease response (verify the bundled chain) go through the
  same implementation. The response's `projectId` / `currentEpoch` declared
  values are also checked against verified derived values (declared values are
  not trusted — the existing posture)
- **(2) Repository anchor (SHOULD)**: **implemented**. The producing side =
  `maruhi project anchor` (a member prints anchor JSON to stdout from a
  verified view and commits it to the repository); the checking side =
  `ci run --anchor <path>` (genesis match, inclusion of the pinned head,
  per-environment epoch non-regression). The second half of the SHOULD —
  "offer an update on rotate / push success" — is deferred (detection safety is
  monotonic in anchor freshness; an update offer is a UX improvement and
  doesn't change the property. Operationally: re-run `project anchor` after
  rotating and commit — noted in the action's README). `--anchor` itself is
  also optional (SHOULD) but is included in the README template
- **(3) DEK commitment matching**: a DEK unwrapped by `unwrapLeaseDek` is not
  used until it passes `verifyDekCommitment` (the chain-derived
  (environment, epoch) commitment) (§5.2). No DEK-length check is invented
  twice at the unwrap layer (A-5-2 — a malicious server Sealing something
  other than 32 bytes is caught by the commitment match). Lease wraps carry
  **no** §5.1 registration signature (server-generated, response-scoped — the
  wire type `LeasedDek` distinguishes them structurally), so deks.ts's
  signature-verification stage doesn't apply; the lease-specific unwrap layer
  carries the epoch-cap (≤ chain-derived current epoch), duplicate rejection,
  and commitment-existence checks
- **(4) Value-signature / meta-statement verification**: values.ts's
  verification skeleton (`verifyAllCommon` — environment statement → active
  set → tombstone → name check) is exported as the lease entry point
  `verifyLeaseDistribution`. One difference from pull: **a future head
  (declared seq > the bundled chain's head) is rejected immediately without
  re-syncing**. The chain is bundled in the same response, so no honest
  explanation of "my chain is just stale" exists (the response would be
  self-contradictory)
- **No floor**: the runner is disposable and floor persistence means nothing
  (the floor-less first-sync class of §14.3-3). Its main mitigation is (2)'s
  anchor

## 5. Implementation layout

- `apps/cli/src/oidc-github.ts` — OIDC token fetch (CliIo.envVar + fetch) and
  claims readout (the 1 Redacted-unwrap site)
- `apps/cli/src/lease-client.ts` — verify, unwrap, decrypt the lease response
  (§4's (1)(3)(4) + anchor check). The product is `DecryptedVariable[]` (the
  same type as run)
- `apps/cli/src/ci-run.ts` — orchestration (key generation → token →
  issue[1 retry on token-replayed]→ verify → `runOp`). The injection
  boundary is the same as run: `buildInjectionEnv` / `ProcessRunner` (the
  diskless invariant)
- `apps/cli/src/anchor.ts` — generate / parse / check the anchor format (JSON)
- The argument layer follows ADR-0016's format (declarations + GROUP_CONFIGS +
  COMMAND_SPECS + cli-formatter). `ci run` shares `run`'s `--` discipline
  (commandAfterTerminator)
- `failure.ts` gains mappings for the 3 Lease errors (reason codes only — no
  token values or external identifiers carried)
- agent-gate is untouched: `ci run` is value injection, not value display (the
  same sanctioned consumption path as run). The isAgent gates stay at 9 places

## 6. setup-maruhi action

- Lives at `actions/setup-maruhi/` (composite). Referenced as `uses:
  maruhiapp/maruhi/actions/setup-maruhi@<ref>` (an action's checkout includes
  the whole repository, so `packaging/install.sh`'s verification logic —
  mandatory SHA-256 check of checksums.txt, never writing to the install
  destination before verification — is reused as-is). Marketplace publication
  happens together with Phase 2's going-public (for now: in-repo + README)
- inputs: `version` (a tag. Required during the pre-release period — for the
  same reason as install.sh, no `latest` resolution exists). The install
  destination is the runner's tool directory, appended to `$GITHUB_PATH`
- The README (English) documents that `permissions: id-token: write` is
  required and shows a `maruhi ci run` workflow example (with the anchor)

## 7. Test approach

lease endpoint = MockServer impersonation (responses built from real crypto
fixtures, dynamically `wrapLeaseDek`ing to the request's `ephemeralPubHex`).
OIDC issuance = a separate MockServer path (signature is a dummy — the client
doesn't verify it); env reads = the test layer's `setEnvVar`. What the
negatives pin: tampered chain / genesis mismatch / commitment mismatch (poison
wrap) / bad value signature / claims_digest mismatch (reuse of a wrap meant
for another job context) / token-replayed (recovers in 1, gives up at 2,
ephemeral-key identity and fresh-token issuance) / 503's 2 reasons / 429 /
missing OIDC env / anchor violations (head not included, epoch regression).
Server-side decisions are already pinned by apps/server/test/lease.test.ts and
aren't duplicated (focus on client behavior).

## 8. Handoff

- The anchor-update offer (on rotate / push success — the second half of
  CRYPTO_SPEC §6.3 (b)'s SHOULD) is unimplemented. Operational practice is
  manually re-running `maruhi project anchor`. A candidate for an independent
  UX-improvement PR
- Marketplace publication and tag operation (`v1` major tag) for setup-maruhi
  is decided together with Phase 2 going-public
- Supporting pre-issuing issuers (GitLab / k8s): the structure lets you swap
  only the token-supply path (env / file) while the `ci run` verify/unwrap
  layer stays reusable (oidc-github.ts's separation is the substitution point)
