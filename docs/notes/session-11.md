# Session 11 notes (CLI MVP: login / key management / §6.3 sync checks / §5.1 distribution-time verification / pull / run / push / environment management)

Date: 2026-08-03. Prerequisites: PR #22 (§6.2 member-key uniqueness — merge = owner approval),
#23 (ROADMAP), #24 (empty `deks: []` → 400) confirmed merged before starting.
Scope: all task-specified items 1–7 (foundation / login / key management / sync checks /
pull + distribution-time verification / run / push + environment management) implemented in a
single PR (#25).
**PR #25 merged 2026-08-03** (merge commit `2430e47`. See §6).
Commits are in layer order (crypto → foundation → login & key management → sync, pull, run →
push & environment → wiring → tests).

## 1. What was done

1. **crypto**: serialization API for the master private key (`exportEncryptionPrivateKey` =
   hpke `SerializePrivateKey` / `exportSigningPrivateSeed` = via WebCrypto JWK,
   `KeyExportFailed` error kind, core's Effect mapping followed).
   No new cryptographic operations introduced (serialization with existing parts only — the
   implementation premise of CRYPTO_SPEC §3's "CLI: OS keychain"). **Change to packages/crypto
   requires human review (stated in the PR description)**
2. **CLI foundation**: introduced gunshi 0.37.1 + @types/bun 1.3.14 (selection rationale in the
   commit message). Effect service boundaries for Keychain / ConfigStore / CliIo / ProcessRunner,
   a typed client via `HttpApiClient.make(maruhiApi)`, and a unified mapping of typed errors →
   user-facing messages (failure.ts, including the bare-413 branch)
3. **Commands**: login / logout / key (generate|show) / project (init|verify) /
   env create / pull [--show] / push <NAME> / run -- <cmd> / config (get|set)
4. **Tests**: 53 CLI cases (419 total — at implementation time; the final count including review-loop
   and pre-merge additions is 16 files / 462 cases — §6). Wire-level HTTP
   mocks + real crypto fixtures. A live E2E (real bin.ts + mock) measured §6.3
   verification actually running and behavior with no keychain
5. **docs**: this memo

## 2. Ruling details (multi-option comparison → proceeded on recommendation; confirmation = PR review approval → finalized by PR #25 merge)

### 2-1. OS keychain = Bun.secrets (zero deps)

| Option | Evaluation |
|---|---|
| **Bun.secrets (adopted)** | the CLI runs on the Bun runtime (ADR-0004) so Bun APIs are allowed. Covers macOS Keychain / Linux libsecret (Secret Service) / Windows Credential Manager with a single API and **adds zero dependencies** (doesn't grow the supply chain). v1 support range = Bun.secrets' support range |
| keytar | archived (maintenance ended). Rejected |
| @napi-rs/keyring | equivalent functionality but adds a native-binary dependency. Unneeded as long as Bun.secrets suffices |
| In-CLI custom implementation (calling security / secret-tool) | self-maintained platform branching. Rejected |

- **Keychain-absent environments** (headless Linux etc.): no plaintext fallback is implemented since
  it would violate the invariant. Writes fall to a "no keychain" guidance error after a 30-second
  timeout (§3 measured finding). For tokens only, a **read-only path via the `MARUHI_TOKEN`
  env var** exists (for CI; userId resolves via `GET /auth/me`).
  **`MARUHI_TOKEN` requires `MARUHI_TOKEN_ORIGIN` (target server origin) and is only sent when it
  matches the resolved origin** (don't leak a Bearer token to a different origin reached via
  `--server` — a Security Agent HIGH from the review loop).
  No env-var path for the master private key is **created** (don't add paths putting key material
  in the process environment in v1 — handoff: design when CI pull/run becomes needed)

### 2-2. Master private-key storage format

One JSON entry (`{suite, encPubHex, encSkHex, sigPubHex, sigSkSeedHex}`,
lowercase hex). Keychain name is `master::<origin>::<userId>`; token is
`token::<origin>` (scoped by server origin; using multiple self-hosted servers
works naturally). The sig private key is an RFC 8032 seed (32B) — matches
importSigningKeyPair's existing contract. Imported non-extractable (extractable=false) at use time.

### 2-3. Local chain cache = none (full fetch + full re-verification every time)

The chain is signed public data, and at v1 scale (acceptance-policy cap of 10,000 entries,
tens in real operation) full re-verification is simplest and safest. If differential
verification is ever introduced, follow session-10 §5's caveat on key-index rebuilding
(restoring from the verified members Map).

### 2-4. Non-secret config = `~/.config/maruhi/config.json`

Resolved in order `MARUHI_CONFIG_DIR` → `XDG_CONFIG_HOME` → `~/.config` (macOS is
unified on XDG too; Windows %APPDATA% support lands with distribution Phase 2). Keys are
server / githubClientId / defaultProject / defaultEnvironment only
(allowlist — there's structurally no path to write a secret). dir 0700 / file 0600.

### 2-5. pull's user-visible behavior = metadata display + explicit `--show`

Default is sync + verify + metadata only (variable name, version, epoch, byte length).
`--show` value display is **rejected when an AI agent is detected (gunshi/agent)**, while
`maruhi run` is allowed (a real rejection target is easier to pin in tests than a
detection-mechanism-only option). File output doesn't exist as an option due to the
diskless invariant.

### 2-6. Self-hosted GitHub client_id = given via CLI config (ruled)

v1 uses `maruhi config set githubClientId <id>` (or `--github-client-id`).
Works with no server/spec changes. **Long-term, a server public-config endpoint
(client_id is public information) has the UX edge** but it requires an AUTH_SPEC revision +
server implementation, so it was escalated for ruling (PR #25's ruling-needed 1).
**→ 2026-08-03 owner ruling: finalized as "A (CLI config) for now, B (public-config
endpoint) in the next independent PR"** (see §5 handoff).

### 2-7. Test strategy = wire-level HTTP mock + real crypto (adopted after spawn comparison)

| Option | Evaluation |
|---|---|
| **HTTP mock (adopted)** | (i) the server's fake-github is a vitest-pool-workers fetch swap and unusable under a wrangler dev spawn (login flows can't be checked under spawn). (ii) The CLI's core = client verification (§5.1 / §6.3) requires "a server returning malicious responses", which a real server can't produce (negative cases like forged signatures, swapped chains, swapped ciphertexts). (iii) Responses are built with real crypto and the wire shape matches api-schema |
| wrangler dev spawn (web e2e precedent) | strongest contract alignment with the real server, but needs D1 migrations applied beforehand and can't check login or adversarial-response cases. **Real-server integration is handed off as a future integration test (smoke)** |

- The keychain is abstracted at an Effect service boundary; tests use an in-memory implementation
  (CI has no OS keychain — task instruction). Real-keychain integration waits for local manual
  verification
- Variable IDs adopt client-assigned randomness (`v` + 12 bytes of hex): making display name = ID
  collides with rename and tombstone (no ID reuse — §12-1). Name → ID resolution happens on the
  pull endpoint (there's no dedicated list API. PR ruling-needed 3 = every push emits a var.read
  audit row, i.e. audit noise)

### 2-8. CAS retry on chain appends = implementation deferred (handoff)

No v1 CLI command appends to the chain beyond genesis (add_member / rotate etc.).
Implementing it early as a sync-library function would have no real use and would trip fallow's
unused-export detection (which also catches test-only exports — session-07 §3), so it's deferred
to a future session that owns an append command (allowed by the task).

## 3. Sticking points & environment findings

- **Effect v4 beta catch-family API**: `catchAll` doesn't exist; it's `Effect.catch`
  (an alias export of `catch_`). An HttpApiClient method's union return value can't be
  `.pipe`d directly, so a helper taking `Effect.Effect<A, unknown, R>` (push.ts's
  classifyAttempt) unifies it + classifies with instanceof
- **Where undeclared statuses (bare 413) surface**: HttpApiClient returns undeclared statuses as
  `HttpClientError` (reason DecodeError, `error.response.status` readable). failure.ts's branch
  relies on this (pinned in tests)
- **`Bun.secrets` writes block with no response on headless Linux without a keyring daemon**
  (measured on this VM; reads return null immediately). They fall to a 30-second timeout +
  guidance error, and because **the pending native call keeps the event loop alive after
  interruption so the process never exits**, bin.ts calls `process.exit` explicitly
- **Adding @types/bun requires the DOM lib** (WebCrypto types in crypto sources).
  apps/cli's tsconfig is `lib: [ES2023, DOM]` + `types: [bun]` (core's precedent)
- **gunshi's mock-free integration point**: injecting an Effect Layer into `runCli(argv, layer)`
  lets tests exercise gunshi's real wiring (positional / rest / flags). gunshi's default renderer
  emits a header line (harmless)
- **fallow's unused-export catches test-only exports** (re-confirming session-07
  §3): all test support lives in test/support/, and src exports only what has a
  consumer inside src
- Added the 3 cli / server test-support clone groups to the fallow dupes baseline
  (§2-7's independent judgment. The existing 1 internal-clone group in data-store.ts is inherited).
  **→ 2026-08-03 owner ruling: keep this PR on the baseline allowance, and do the shared-fixture
  extraction (into packages/crypto/test/) as a small independent PR after merge**
  (see §5 handoff)

## 4. Known constraints / v1 tolerances

- **Real OS-keychain integration is unverified** (this environment has no keyring daemon).
  Local manual verification on macOS / desktop Linux is needed (steps: login →
  key generate → project init → env create → push → pull → run)
- push's variable resolution uses pull, so a var.read appears in the audit log (PR ruling-needed 3)
- pull doesn't use the server-declared currentEpoch for verification (unneeded — the DEK index is
  looked up by each variable's declared epoch, and the source of truth is the chain-derived value.
  push's CAS is the final defense)
- Value display (pull --show) to a terminal can remain in shell history / scrollback
  (terminal display itself is within the diskless invariant's allowance. Limited to explicit
  human operation)
- `maruhi run`'s env vars pass to the child as process environment (/proc/PID/environ is readable
  by the same uid — intrinsic to env-var injection, per the task's design)

## 5. Handoff to the next session

### 3 ruled follow-up PRs (2026-08-03 owner ruling. Independent of each other, any order)

1. **Server public-config endpoint (client_id distribution — PR #25 ruling-needed 1 ruled as
   "A for now, B in the next independent PR")**: an unauthenticated public endpoint
   (e.g. `GET /auth/config`) returns githubClientId and login resolves it automatically.
   Involves an AUTH_SPEC §4 revision + server implementation. Design points: (i) start the response
   with client_id only (add setup-wizard requirements when needed), (ii) the larger unauthenticated
   surface is tolerable because client_id is public information, (iii) after introduction, config's
   githubClientId stays as an override (for GHES & testing)
2. **Shared extraction of test-support fixtures (PR #25 ruling-needed 2 ruled as "keep this PR on
   the baseline allowance, then do B as a small independent PR after merge")**: extract the 3 clone
   groups of cli / server test support (chain assembly, op builders, unwrapResult family — ~75
   lines) into a shared module under `packages/crypto/test/`, and shrink the dupes baseline by
   removing those 3 groups. Cautions: (i) strictly a mechanical extraction with zero behavior change,
   (ii) don't move the server-test-only `unwrapAndDecrypt` (uses the declared AAD as-is) into the
   shared side, (iii) changes under packages/crypto require human review
3. **Metadata-only mode for pull (PR #25 ruling-needed 3 ruled as "A for now, G in the next
   independent PR")**: add a metadata-only mode to bulk pull (doesn't return values or DEKs) and
   document in AUTH_SPEC §12-7 / AUDIT_SPEC semantics that it doesn't record `var.read`
   ("don't record reading what wasn't read"). Authorization is the same level as pull
   (read × reader). The CLI switches push's name resolution to this mode (also resolves the
   review finding that "push double-fetches the DEK set via pull and listMine")

### Other handoffs

- **Chain-append commands (add_member / remove_member / rotate_epoch / change_role)**:
  implement append + ChainHeadConflict (409 CAS) retry loop together with the commands (§2-8).
  remove_member is a big one involving §7's all-environment rotate + re-wrap + re-encrypt
- **pull / run in CI & keychain-absent environments**: no supply path for the master private key
  (MARUHI_TOKEN is tokens only). Consider together with recovery-code (§8) implementation or a
  dedicated machine-key design
- **Integration smoke against the real server** (wrangler dev spawn + D1 application): insurance
  against mock contract drift. Needs the web e2e precedent + D1 migration application
- **§6.3 head gossip is Phase 2** (still untouched). Bundling a declared head into write requests
  involves a wire revision
- Windows config path (%APPDATA%) and CLI distribution (npm / brew) are Phase 2
- session-07 §5's untouched items (recovery-blob rate limits etc.) continue
- **Where client-verification logic lives**: the §5.1 / §6.3 checks in sync.ts / deks.ts / pull.ts
  will want sharing when the Web dashboard is implemented. Consider promoting to packages/core then
  (not crypto primitives, so core is fine)
- **Spec-side discussion items (from the review-loop 3 record)**: (1) chain binding of values /
  DEKs — a §5.1 signature is attribution, not value authenticity, so a server colluding with a
  key-holder from chain history can inject fake DEKs / values at real epochs (a known v1 limit).
  (2) cryptographic binding of variable names — names are plaintext metadata that don't enter the
  AAD, so the server can re-pair name↔ciphertext correspondences (the CLI mitigates with a
  denylist of execution-control variable names). Both involve CRYPTO_SPEC revisions — consider
  filing as open items
- **Auto re-sync on epoch-exceeded errors**: even an honest server can hit epoch-exceeded from the
  race "a rotation lands between sync and pull" (re-running resolves it; the message says so).
  A UX improvement that auto re-syncs once and retries is future work

## 6. Review→fix loops (inside PR #25. 3 parallel review perspectives → fixes)

Added "no path lets plaintext / key material leak to disk, logs, or errors" as an explicit review
perspective, and ran 3 perspectives in parallel (security & crypto / correctness & concurrency /
tests & contract).

### Loop 1 key findings and responses (commit 6cc97e6)

1. **Phantom epochs (security [med], correctness [med], tests [high] detected the same root
   independently)**: no client check that distributed wraps' / declared AAD's epoch is "≤ the
   chain-derived current epoch" let a colluding server + a key-holder from chain history (including
   removed ex-members) inject fake values with a self-made DEK at an epoch with no rotate_epoch on
   the chain. → added ceiling checks to deks.ts / pull.ts, and pinned with tests: rejection of
   a wrap / variable at epoch 3 (chain at 2) + "even if the server falsely declares currentEpoch=5,
   push's retry uses the chain-derived value (2)"
2. **defects turning into usage errors (exit 2) (correctness [med]. measured)**: added
   catchDefect to execute (internal error = exit 1). Pinned in tests
3. Security [low] × 5: http limited to loopback / explicit suite pinning on deks & master-key
   records / injection rejection of execution-control env var names (PATH, LD_*, NODE_OPTIONS,
   etc.) / MARUHI_TOKEN's origin non-scoping documented (→ the ruling at the time; a later
   pre-merge fix implemented origin binding via `MARUHI_TOKEN_ORIGIN` — below)
4. Correctness [low] family: push re-resolving create conflicts, dropping useless transitions after
   the final attempt, immediate reporting of epoch contradictions, keygen self-verification before
   save, token revocation on login save failure (anti-orphaning), atomic config writes & corruption
   recovery, RFC-compliant 400 handling in device flow, moving ID verification ahead of network
5. Test [med]–[low] family: §5.1 FP mismatch, duplicate epochs, cross-environment ciphertext,
   old-key signature verification of a deleted→re-added member (key-history 2 binding), logout 401,
   MARUHI_TOKEN precedence, asserts that plaintext values / tokens / private-key material never
   print, turning crypto exports into functional verification (HPKE open / sign-verify) + vector
   pinning

### Loop 2 (re-verification of the fixes)

All 3 perspectives confirmed **zero remaining [high] / [med] findings** (security = phantom-epoch
check strictly bounds the acceptance interval to [1, chainEpoch] with no gaps / correctness =
transition coverage, catchDefect placement, and atomic writes verified with measurements / tests =
traced that the added tests actually catch the flagged mutations). Remaining [low] items also
handled: denylist expansion (JAVA_TOOL_OPTIONS, RUBYOPT, GIT_* etc. + case-folding comparison =
Windows case-insensitivity countermeasure), epoch-exceeded error wording (notes that an honest
server can hit it on a rotation race — auto re-sync handed off), clearer post-revocation message in
login, a VersionConflict re-resolution test on create, an unknown-suite record rejection test, and
making the fixture token a real format.

### Loop 3 (final check)

All 3 perspectives: zero blocking findings. Items left on record (not adopted):
- **[info] Residual fake-DEK injection at real epochs** (security): a malicious server +
  key-holder collusion from chain history can self-sign a self-made DEK at a real epoch
  e ≤ chainEpoch under §5.1 and inject fake values. A known limit of the v1 design where values
  are unsigned (§5.1 is attribution, not value authenticity). The fundamental fix is chain binding
  of values / DEKs — a spec-level discussion item → §5 handoff
- **[info] Variable-name ↔ variableId binding is unauthenticated**: names are plaintext metadata
  outside the AAD, so the server can re-pair name↔ciphertext correspondences (the denylist is a
  mitigation). Hand off cryptographic name binding (or a push-time name-snapshot check) as a
  spec-side discussion item
- Head gossip unimplemented (Phase 2) = explicit note that v1 doesn't defend split view
- keygen concurrent-run TOCTOU (negligible harm for an interactive command), .tmp orphans on
  config-save crashes, the interval=0 floor clamp (judged bounded by deadline → the ruling at the
  time; a later pre-merge fix implemented a fixed floor — below), temp-directory cleanup, and
  inconsistent key-pair import in device flow (implementation-dependent)

### Pre-merge fixes (after Autopilot. Bugbot / Security Agent / reviewer findings)

Implemented as responses to review comments after marking ready (all inside PR #25):

- **Origin binding for `MARUHI_TOKEN` (Security Agent HIGH)**: requires `MARUHI_TOKEN_ORIGIN`
  and only sends when it matches the resolved origin (reflected in §2-1).
  Overrode loop 1's "documentation only" ruling
- **Fixed floor on device-flow polling interval (RFC 8628 default 5 seconds)**: the server-declared
  interval (incl. 0) isn't used as-is. Re-ruling of the interval=0 clamp deferred in loop 3
- **URL validation for `--github-base-url`**: https required (http allowed on loopback only)
- **Expanded execution-control env-var rejection**: added BUN_OPTIONS (Security Agent HIGH) and
  TLS-family entries to the denylist. Restricted env names to POSIX identifiers, structurally
  rejecting bash function import names (`BASH_FUNC_*%%`) etc., and rejecting case-differing
  collisions
- **Control-character sanitization of terminal output**: strips control chars from server-derived
  strings (login output, key show's userId, etc.) (display.ts, `\p{Cc}`-based to satisfy oxlint's
  no-control-regex)
- **Terminal-injection countermeasures for `pull --show` values (Security Agent Medium)**:
  applies ANSI / OSC control-sequence sanitization to value display too
- **Additional fixes to login / logout / push**: handling of unspecified env, logout's deletion
  order, push's final-attempt handling (3 reviewer findings), a precise error for project init's
  empty-org array (Bugbot Low), removed the run-bypass guidance from the agent-rejection message,
  plus 3 more Bugbot Medium findings

Timeline: loop 1 = 1 high, 3 med, many low → loop 2 = 6 low → loop 3 = zero
(blocking) → pre-merge fixes (above). Final quality gate = `bun run check`
all green (16 test files / 462 tests) + live E2E green (re-verified by measurement on main
post-merge). **Merged 2026-08-03** (merge commit `2430e47`).
