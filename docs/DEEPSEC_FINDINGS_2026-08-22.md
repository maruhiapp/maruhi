# deepsec open items (2026-08-22 full review) — closed

> **2026-08-24 addendum 2 (closed)**: A local re-run of scan / process / revalidate
> settled the 17 points in this document. fixed 16 records, false-positive 2 (M3 / B11),
> 2 unresolved points (the remainder of M2, M4). For the current open items see
> [`DEEPSEC_FINDINGS_2026-08-24.md`](./DEEPSEC_FINDINGS_2026-08-24.md).
> The rest is kept as history.

> **2026-08-24 addendum**: The remaining 18 records (17 points) are all implemented in
> the fix PR containing this addendum. See the commit history (`fix …deepsec…`) and the
> PR description for what each point received. The deepsec re-run (revalidation) is
> not done — the Cloud environment has no credentials — so close this out with a local
> re-scan ("rules for working in Cloud" 6).


## Positioning

deepsec's generated data lives under `.deepsec/data/` and is gitignored, so it does not
carry over to Cloud environments or other chats. This document is the handoff for
tracking revalidated findings.

- Scope: 116 files
- `process` run: `20260822050846-d58d658d7e9901fe`
- `revalidate` run: `20260822054606-13d8b765ba4462b8`
- Model: Claude Opus 5, thinking `medium`
- Revalidation result: true-positive 20, false-positive 3
- As of 2026-08-24: the 2 duplicate records of empty `claimConstraints` fixed in code
- Remaining: true-positive **18 records, 17 points**
  - MEDIUM 5 records
  - BUG 13 records
  - M3 and B11 are duplicates of the same `/auth/device/exchange` problem

Because deepsec has not been re-run after the fixes, even the 2 already-fixed records
still show as true-positive in the locally generated report.

## Rules for working in Cloud

1. Put one point, or only closely related same-shape ones, in one PR. Before starting,
   read the current code, the spec, and the ADR; do not implement the scanner's
   suggestion as-is.
2. For `packages/crypto`'s B12 and B13, prepare the human review and the test vectors
   first. Do not add a crypto operation that is not in `docs/CRYPTO_SPEC.md`.
3. M4, B8, and B9 touch Drizzle — keep the repository-service boundary. If a schema
   change is needed, follow the drizzle migration procedure.
4. Do not add plaintext secrets, key material, or external provider IDs to logs or to
   append-only audit actors. Do not place attack PoCs in the repository.
5. User-facing text is English. When done, pass `bun run check` on the pinned Bun
   (`.bun-version`. Currently 1.4.0).
6. The Cloud environment has no local Claude Max auth. Fixes and ordinary tests can be
   done in Cloud, but deepsec revalidation runs locally unless separate credentials
   are provided.

## Already fixed (not counted in the remaining 18)

### F0. Empty `claimConstraints` fails open

The original finding was 2 duplicate records against `apps/server/src/lease-policy.ts`
and `packages/api-schema/src/lease-api.ts`.

Implemented:

- The CLI rejects each policy element's `claimConstraints` unless present and non-empty
- The server treats an existing chain with an empty element as a mismatch
- AUTH_SPEC records the fail-closed evaluation semantics
- Regression tests added for both CLI and workerd
- The CRYPTO_SPEC chain shapes and `packages/crypto` are unchanged

## MEDIUM (5 records)

### M1. GitHub Actions OIDC bearer token sent to an unverified URL

- Location: `apps/cli/src/oidc-github.ts:34,78-86`
- deepsec slug: `ssrf`
- Status: confirmed, confidence low
- Problem: takes `ACTIONS_ID_TOKEN_REQUEST_URL` as a string and sends the bearer
  token with the default redirect follow. `https:`, host, and redirects are not
  checked.
- Recommendation: parse the URL, verify `https:` and an allowed host, and use
  `redirect: "manual"`. Decide the host rules for GitHub Hosted Runners and GHES
  before implementing.

### M2. `maruhi run` execution-control env denylist has gaps

- Location: `apps/cli/src/run.ts:33,58-59,106`
- deepsec slug: `other-execution-control-env-injection`
- Status: confirmed, confidence medium
- Problem: a secret's variable name and value can overwrite the child process
  environment. The current denylist does not reject `HOME`, `PROMPT_COMMAND`,
  `NODE_REPL_EXTERNAL_MODULE`, `PYTHONINSPECT`, Windows `PATHEXT` / `COMSPEC` /
  `SYSTEMROOT`, etc.
- Recommendation: add the missing names and prefixes, with regression tests for POSIX
  and Windows. Decide prefix rejection for `NODE_` / `PYTHON_` / `BUN_` after checking
  compatibility.

### M3. Unauthenticated device exchange consumes the GitHub OAuth App's shared quota

- Location: `apps/server/src/auth.package/github.ts:110,115,190-192`
- Related: B11 `packages/api-schema/src/auth-api.ts`
- deepsec slug: `rate-limit-bypass`
- Status: confirmed, confidence medium
- Problem: unauthenticated `/auth/device/exchange` calls GitHub's check-token API for
  every formally valid token. Depleting the shared quota stops CLI login for all
  users.
- Note: token prefix / length checks and the WAF recommendation in
  `docs/SELF_HOSTING.md` already exist, but the default deployment enforces no rate
  limit.
- Needs decision: first decide whether to bind exchange to a short-lived maruhi-side
  device code, or make Cloudflare Rate Limiting part of the default config. Handle in
  the same PR as B11.

### M4. `auth.login_failed`'s global cap blinds the audit log

- Location: `apps/server/src/db.package/audit.ts:81-82,271-285`
- deepsec slug: `other-audit-suppression`
- Status: confirmed, confidence medium
- Problem: the 100-per-hour cap is shared across all actors, so once anonymous failures
  exhaust it, later targeted failures are not recorded.
- Needs decision: either split by coarse origin in separate limiter state, or leave an
  aggregate event like `auth.login_failed_suppressed` when the cap is reached. Do not
  take the option of writing external provider IDs or IPs into the append-only actor.
  Also confirm whether AUDIT_SPEC needs a revision.

### M5. The lease endpoint can create a Durable Object for any valid project ID

- Location: `apps/server/src/handlers-lease.ts:96,119-121`
- deepsec slug: `rate-limit-bypass`
- Status: confirmed, confidence medium
- Problem: with a valid GitHub OIDC token, a DO can be created for many different
  64-hex project IDs. Each DO's constructor creates a table, and there is no
  collection path.
- Note: `ProjectIdSchema` format checking already exists. The original
  recommendation's "validate projectId" is not needed.
- Recommendation: design a request-level rate limit before `projectStub` is called.
  A per-project counter inside the DO cannot stop new DO creation.

## BUG (13 records)

### B1. CLI hits RangeError on a malformed audit timestamp

- Location: `apps/cli/src/audit.ts:188,264,348,412`
- deepsec slug: `other-unhandled-exception`
- Status: confirmed, confidence medium
- Problem: the server's unbounded `serverTs` is passed to `Date#toISOString`, so the
  `maruhi audit` family exits with a defect instead of an Effect typed error.
- Recommendation: validate finite / Date range in the wire schema, or make the
  formatter total. Same shape as B4 and B5 — decide a common policy before fixing.

### B2. Config load treats non-ENOENT read errors as empty config

- Location: `apps/cli/src/config.ts:98-103`
- deepsec slug: `other-error-swallowing`
- Status: confirmed, confidence high
- Problem: EACCES, EISDIR, and EIO are also converted to `{}`. `config set` may
  replace existing config without warning.
- Recommendation: treat only ENOENT as first-run; convert the rest to a typed
  `CliError`.

### B3. No upper bound on device flow's `expires_in` and `interval`

- Location: `apps/cli/src/device-flow.ts:110-135`
- deepsec slug: `other-logic-bug`
- Status: confirmed, confidence medium
- Problem: a hostile or misconfigured endpoint returning very large values makes it
  sleep for a long time before the deadline check.
- Recommendation: confirm the real values in RFC 8628 and GHES, set caps, and check
  the deadline before sleeping.

### B4. CLI hits RangeError on an invite timestamp

- Location: `apps/cli/src/invite.ts:254,267-268,734`
- deepsec slug: `other-unhandled-defect`
- Status: confirmed, confidence high
- Problem: if the server's `createdAtMs` / `expiresAtMs` is outside the Date range,
  invite create / list exits with a defect.
- Recommendation: use the same boundary check or total formatter as B1.

### B5. `maruhi key show` hits RangeError on a malformed timestamp

- Location: `apps/cli/src/keygen.ts:159,171-172`
- deepsec slug: `other-unhandled-defect`
- Status: confirmed, confidence high
- Problem: if recovery status's `updatedAtMs` is outside the Date range, even local
  key display exits non-zero.
- Recommendation: use the same boundary check as B1; make recovery status a degraded
  display.

### B6. A write can still complete after the keychain write timeout

- Location: `apps/cli/src/live.ts:40-51`
- deepsec slug: `other-race-condition`
- Status: confirmed, confidence medium
- Problem: an Effect timeout cannot cancel the in-flight `Bun.secrets.set` Promise.
  The key may be saved after the CLI reports failure, tripping the overwrite guard
  next time.
- Recommendation: on timeout, state explicitly that the write "may have been saved"
  and show confirmation / recovery steps. A post-timeout read can also block, so
  verify Bun keychain behavior before implementing.

### B7. The push success display uses the server echo, not the locally signed value

- Location: `apps/cli/src/push.ts:951-953`
- deepsec slug: `other-trust-boundary`
- Status: confirmed, confidence medium
- Problem: the displayed variable ID / version / epoch come back from the server
  response. Meanwhile the floor update correctly uses locally computed values.
- Recommendation: return the locally signed values, and make a differing server echo
  a typed error.

### B8. An audit read UPDATEs every NULL row in D1

- Location: `apps/server/src/db.package/audit.ts:180,185,250-252`
- deepsec slug: `other-write-amplification`
- Status: confirmed, confidence medium
- Problem: if a fetched page has one NULL `row_id`, it updates every NULL row in the
  table. It can race with multiple readers or an old worker mid-rollback.
- Recommendation: restrict the UPDATE to just the seq / rows observed in the page, and
  pin the update count per read in a workerd + D1 test.

### B9. The recovery fetch counter has a read-modify-write race

- Location: `apps/server/src/db.package/repos.ts:579,594,607,614,618`
- deepsec slug: `other-race-condition`
- Status: confirmed, BUG after revalidation
- Problem: concurrent requests read the same count, so even when several succeed the
  count goes up by only 1. The invite counter has the same shape.
- Recommendation: run the conditional relative UPDATE and `RETURNING` in one
  statement. Build the concurrent workerd test first; decide by diff size whether the
  invite counter goes in the same PR.

### B10. A member user ID / server fingerprint collision makes the wrap count unsatisfiable

- Location: `apps/server/src/dek-wraps.ts:46,56,129,231`
- deepsec slug: `other-logic-bug`
- Status: confirmed, confidence medium
- Problem: the expected count counts members and server grants separately, but the
  storage key does not include the recipient class. On an ID collision this becomes
  duplicate or missing, stopping environment creation and rotation.
- Recommendation: derive the expected count from the deduplicated union of member IDs
  and in-scope server fingerprints. Do not change the internal user ID format without
  checking AUTH_SPEC and existing-chain compatibility.

### B11. `/auth/device/exchange` has no request rate limit

- Location: `packages/api-schema/src/auth-api.ts:151,159-162`
- deepsec slug: `rate-limit-bypass`
- Status: confirmed, BUG after revalidation
- Problem and handling: same root cause as M3. Close it in the same PR and treat the
  two findings as duplicates.

### B12. The verifier throws TypeError on an unknown chain `op`

- Location: `packages/crypto/src/internal.package/chain-verify.ts:102,247-248,551`
- deepsec slug: `other-uncaught-exception`
- Status: confirmed, confidence high
- Problem: calls `PAYLOAD_SHAPES[entry.op]` without checking membership. This violates
  the public verifier's contract that "invalid input returns `invalid-payload`, never
  throws".
- Reachability: current production APIs narrow the op via `ChainEntrySchema` first, so
  this is a defense-in-depth contract gap; no direct exploit path has been confirmed.
- Constraint: a `packages/crypto` change. Receives human review, and the unknown-op
  test vector is added before the implementation.

### B13. The value-sign context does not reject an empty `variableId`

- Location: `packages/crypto/src/internal.package/value-sign.ts:100,107,116`
- deepsec slug: `other-missing-validation`
- Status: confirmed, confidence high
- Problem: project / environment / writer are checked non-empty but the variable ID
  alone is missed. The API schema rejects empty, so this is not a forgery path from
  outside — it is missing defense against caller bugs.
- Constraint: a `packages/crypto` change. Add the same expectation as `meta-sign.ts`
  to the test vectors first, implement after human review.

## Out of scope

The following 3, which became false-positive on revalidation, do not count as open
items:

- `requestOrigin()` and the Host header
- `invalidValueMessage`'s substring check
- `computeVariablesDigest`'s UTF-16 / UTF-8 duplicate check

If any are taken up as future hardening, keep them separate from deepsec
true-positive fixes.

## Recommended order of attack

1. B2, B3, B7. Localized, with few spec decisions.
2. B1, B4, B5. Decide the common boundary policy for server timestamps, fix as the
   same shape.
3. M1, M2. Come with compatibility tests against the external runtime and the child
   process environment.
4. B8, B9, B10. Put D1 / wrap-invariant regression tests in place first.
5. M3 + B11, M4, M5, B6. Make the operational or architectural decision first.
6. B12, B13. Separate crypto PRs; test vectors first, human review mandatory.
