# deepsec re-check (run 2026-08-24)

The result of revalidating the 17 points (18 records) of `DEEPSEC_FINDINGS_2026-08-22.md`
against the fixed code. This document replaces the previous one (the previous one is
kept as history).

> **Closed (revalidated 2026-08-25)**: deepsec was run against the fixed code, and of
> the 8 points, **7 came back `fixed`** (R1 / R2 / R3 / R5 / R6 / R7+R8 / R9).
> **Only R4 remains a true-positive** — the "remaining limitation" the document
> described, "coverage within the same `auth_method`", is exactly what was flagged
> (severity was lowered MEDIUM → BUG, and the bucketing and suppression markers were
> acknowledged as effective).
> run: `process 20260825002935-0e1bfd164a1a9165` / `revalidate 20260825003446-4a6d6d6964b0c376`
> (13 files re-investigated, $11.44).
>
> This revalidation also produced **4 new** true-positives. Together with the
> remainder of R4 they are tracked in
> [`DEEPSEC_FINDINGS_2026-08-25.md`](./DEEPSEC_FINDINGS_2026-08-25.md).
> Two of them (the unlabeled display of `chain_seq`, the missing `MARUHI_` prefix) sit
> **immediately adjacent** to this PR's R1 / R3 — the same evasion survived one step
> outside the namespace.

> **Addressed (2026-08-24)**: all 8 open points (9 records) have been implemented.
> Each section ends with an added "Handling". The spec-side changes are AUDIT_SPEC
> §3.1 (R4/R5/R6) and §7 (R1), plus `docs/SELF_HOSTING.md` (R7). `bun run check`
> passes on the pinned Bun (1798 tests).
>
> There are 2 things deliberately **not done**. Both were judged "implementable, but
> doing so does not achieve the goal":
>
> - **Making R7's state single-use**: expiring the state cookie on the failure path
>   too was proposed, but the attacker can supply **both** the cookie and the query
>   themselves (a double-submit scheme with no server-side state), so it does not
>   remove even one request of the flagged attack. On top of that, Effect HttpApi
>   typed errors cannot carry `Set-Cookie`, so the endpoint contract would have to
>   change. The frequency cap is covered by rate limiting (that is the effective
>   handling)
> - **Fully closing R2's window**: `Bun.secrets` has neither compare-and-swap nor
>   create-if-absent; the OS keychain side has no atomic conditional write. An
>   advisory lockfile creates stale locks after a crash, producing false "another
>   process is running" reports and risking blocking key generation — the only
>   entry point. Instead the window was shrunk to the minimum and a last-writer win
>   now gets **detected and failed** (see R2's handling below)

## Positioning

- Scope: 117 tracked files. Of them, `process` re-investigated the **28 candidate
  files** changed since the previous run (`--reinvestigate 1 --manifest`)
- `revalidate` re-judged all 36 findings with `--force` (23 previous + 13 new)
- Model: `claude-opus-5`, thinking `medium`, Claude Agent SDK (local Claude Max auth)
- runs: `scan` `20260824210853-11619b9ebaa8d28c` /
  `process` `20260824211944-bd46bee94341b7ef` /
  `revalidate` `20260824212808-ef2f7b748c056ad0`
- Cost: process $12.13, revalidate $7.61 (total $19.74)

### Re-judgment tally

| Verdict | Count |
|---|---|
| fixed | 16 |
| false-positive | 8 |
| duplicate | 3 |
| **true-positive (open items)** | **9 records / 8 points** |

The `process` scope was narrowed to "candidate files changed since the previous run".
The 89 unchanged files keep their 2026-08-22 analysis results and were not re-checked
by this model run. A full re-investigation (the previous full pass was $39.61) is
separate.

## Outcome of the previous 17 points

`fixed` = the fix was confirmed by revalidation. `FP` = the fix made the finding stop
holding, or it was a false positive from the start.

| Previous ID | Outcome |
|---|---|
| F0 empty `claimConstraints` (2 records) | fixed |
| M1 OIDC issuer URL verification | fixed |
| M2 `maruhi run` env denylist | **partially fixed**. Some names remain → R3 below |
| M3 / B11 device exchange rate limit | FP (resolved by `DEVICE_EXCHANGE_RATE_LIMIT`) |
| M4 `auth.login_failed` global cap | **unresolved** (design trade-off) → R4 below |
| M5 lease DO creation | fixed |
| B1 / B4 / B5 timestamp RangeError | fixed |
| B2 config read failure | fixed |
| B3 device flow cap | fixed |
| B6 keychain write timeout | fixed (but a different TOCTOU is new → R2) |
| B7 push display now uses local values | fixed |
| B8 audit read write amplification | fixed (but the counting query's scan cost → R5) |
| B9 recovery fetch counter race | fixed |
| B10 wrap expected-count collision | fixed |
| B12 unknown chain `op` | fixed |
| B13 value-sign empty `variableId` | fixed |

The previous 3 false-positives (`requestOrigin()`'s Host header, `invalidValueMessage`,
`computeVariablesDigest`) remain false-positive this time as well.

## Open items (true-positive 9 records / 8 points)

Of the 6 new points, 3 (R5, R7, R9) flag code added by the 8/22 fixes.

### R1. `maruhi audit verify` cannot detect forged `chain.*` rows of unknown names — MEDIUM (new)

- Location: `apps/cli/src/audit.ts` (`auditVerifyOp`)
- slug: `other-incomplete-tamper-detection` / confidence medium
- Problem: it fetches `CHAIN_MIRROR_EVENTS` (the 8 names of `MIRROR_EVENT_NAME`) one
  by one via server-side `event=` filters. A `chain.*` outside the set (e.g.
  `chain.role_granted`) fabricated by the server is never fetched, and lands in
  neither `problems` nor `aheadRows`. The result: it prints "Mirror bijection
  verification OK" and exits 0.
- Impact: unrelated to key material or plaintext. But it is a coverage hole in the
  AUDIT_SPEC §6 mitigation itself — "cross-checking an untrusted audit log against
  the chain". `list`'s per-row display would catch them via `startsWith("chain.")`,
  but `verify` is the side that claims completeness.
- Recommendation: drop the event filter (or add `event_prefix=chain.` server-side).
  Treat rows that start with `chain.` but are not in `CHAIN_MIRROR_EVENTS` as
  verification failures.
- **Handling**: added `eventPrefix` (prefix match) to the read API (AUDIT_SPEC §7
  revision), and verify now fetches the whole `chain.` namespace in a single paging
  pass instead of iterating known names. Rows whose event name is not in the mapping
  fail verification as "unknown chain op". The prefix match is implemented as
  `substr(event, 1, ?) = ?`, not LIKE, so it carries no wildcard semantics (a test
  pins that `%` or `_hain.` do not match everything).
  `CHAIN_MIRROR_EVENT_PREFIX` is exported from `@maruhi/core`, and the CLI's literal
  `startsWith("chain.")` was replaced too.

### R2. TOCTOU between the master-key overwrite guard and the keychain write — BUG (new)

- Location: `apps/cli/src/keygen.ts` (`keyGenerateOp`. L53 check → L118 write)
- slug: `other-race-condition` / confidence medium
- Problem: `ensureNoStoredMasterKey` only reads and takes no lock. With 6 WebCrypto
  calls and the `importMasterKeys` self-check in between, the window is tens of ms.
  `keychain.set` (`Bun.secrets.set`) is an unconditional put with no CAS, and the
  entry name is deterministic via `masterKeyEntryName(origin, userId)`. Two
  concurrent `maruhi key generate` runs on the same account both observe
  `existing === null`, and last-writer wins erases one side's key. The "existing keys
  are never overwritten" declared at the top of the file is advisory in effect.
- Scope of impact (narrowed by revalidation): both runs start from a no-key-in-use
  state, so values do not become undecryptable. The real harm is that
  `issueRecoveryAfterKeygen` (which runs **after** the write and races the same way)
  can register a recovery blob for the discarded key. `key show` would print
  "registered", but the key that code restores is not the live keychain key, and the
  restore is rejected by the same overwrite guard. Unreachable for a remote attacker
  (key-owner privileges are the precondition).
- Recommendation: add create-if-absent / CAS to `KeychainShape`, or hold an advisory
  lockfile keyed by the entry name (containing no secret value) across all of
  `keyGenerateOp`. Re-checking just before the write only narrows the window.
- **Handling**: added `storeMasterKeyGuarded` (`session.ts`) and routed both the
  keygen and recover store paths through it. It **re-confirms absence immediately
  before** the write and **reads back right after to verify the record is its own**.
  The window shrinks to the adjacent "re-check → write" pair (previously spanned 6
  WebCrypto calls plus a re-import self-check), and the side overwritten by a later
  writer **fails instead of silently continuing** — it lands before recovery-code
  issuance (`issueRecoveryAfterKeygen`), so the inconsistency of "a recovery blob
  registered for a discarded key" cannot happen. The window itself remains because
  there is no CAS (see the note at the top). Even if another process's entire write
  lands inside the remaining window, it falls to the side where the surviving key and
  its recovery blob match.

### R3. `maruhi run`'s execution-control denylist still has gaps — MEDIUM (rest of M2)

- Location: `apps/cli/src/run.ts` (`DENIED_ENV_NAMES` / `DENIED_ENV_PREFIXES`)
- slug: `other-env-injection-denylist-gap` / confidence medium
- Problem: still unrejected after the 8/22 expansion: `LESSOPEN` / `LESSCLOSE`
  (executed via `|cmd %s`), `PAGER` / `MANPAGER` / `EDITOR` / `VISUAL` / `BROWSER`,
  `SSH_ASKPASS` / `SUDO_ASKPASS`, `LUA_INIT`, `GLIBC_TUNABLES`, `LOCPATH`, `NLSPATH`,
  `TERMINFO`, `MALLOC_CONF`. A member with write permission can plant a value under a
  variable **name** from the list above, and it can execute in the environment of
  another member who runs `maruhi run -- <cmd>`.
- Note: variable names are plaintext metadata not bound to the AAD (per the in-file
  comment), so a malicious server can also relabel existing ciphertext under a
  different name.
- Recommendation: add the above to `DENIED_ENV_NAMES`. A denylist cannot close this
  class, so the main line of work is the cryptographic binding of variable names
  (the session-11 carryover). Requiring `--allow-name` to inject names absent from
  the parent environment is also under consideration.
- **Handling**: added all the flagged names plus closely related execution-control
  names (`LESSOPEN` / `LESSCLOSE` / `PAGER` / `MANPAGER` / `EDITOR` / `VISUAL` /
  `BROWSER` / `SSH_ASKPASS` / `SUDO_ASKPASS` / `LUA_INIT` / `LUA_PATH` / `LUA_CPATH` /
  `PSMODULEPATH` / `GLIBC_TUNABLES` / `MALLOC_CONF` / `LOCPATH` / `NLSPATH` /
  `TERMINFO` / `TERMCAP`). With a regression test including case-insensitive
  comparison (Windows non-distinction). M2's ruling against blanket prefix rejection
  is kept as-is. So is the point that cryptographic name binding is the real fix
  (a denylist cannot close this class).

### R4. `auth.login_failed`'s global cap still blinds the audit log — MEDIUM (M4 unresolved)

- Location: `apps/server/src/db.package/audit.ts` (`appendLoginFailed`)
- slug: `other-audit-evasion` / confidence medium
- Problem: the 100-per-hour cap is a single global bucket with no actor / IP / tenant
  dimension. An attacker can cheaply fill the window with formally valid bogus tokens
  (R7's callback was outright unlimited), after which authentication failures across
  the whole deployment are silently dropped. `auth.login_failed_suppressed` records
  only that suppression occurred — neither count nor breakdown — so both attribution
  and counting of targeted credential stuffing are lost.
- Note: `auth.login_failed_suppressed` was added on 8/22, but no dimensioning was.
  The tension between write-amplification prevention and audit completeness is
  currently resolved entirely toward the former.
- Recommendation: bucket on a coarse key (`authMethod` + /24 or /64 hash of
  `CF-Connecting-IP`, or per target user when known). At minimum, carry the
  suppressed count and a per-reason breakdown on `auth.login_failed_suppressed`, and
  emit the marker "once per window per bucket". As before, do not take the option of
  writing external provider IDs or raw IPs into the append-only actor.
- **Handling**: changed the cap to count in **per-`auth_method` buckets** (AUDIT_SPEC
  §3.1 revision). A test pins that exhausting the device-flow side keeps recording
  Web OAuth failures. The suppression marker changed from "one line per window" to
  "one line each time the suppressed count reaches a power of 10 (1, 10, 100…)", with
  `authMethod` and `suppressedCount` on the payload — writes are logarithmically
  bounded in the count, and the scale of suppression is readable from the row density
  and the last count. A separate **per-origin** count (IP / its prefix hash) was not
  taken: AUDIT_SPEC §3.1 already holds an explicit ruling against "carrying origin
  identifiers in extra limiter state", and nothing in this finding overturns it.
  Coverage within the same `auth_method` remains as a limitation (visible via the
  suppressed count, but not eliminated).

### R5. `appendLoginFailed` scans the entire history of login_failed — BUG (new)

- Location: `apps/server/src/db.package/audit.ts` (the counting query)
- slug: `other-unbounded-scan` / confidence medium
- Problem: for `event IN (...) AND server_ts >= now - 1h`, the only usable index is
  `uae_event` (`(event, seq)`. `schema.ts:236`); there is no `(event, server_ts)`.
  SQLite seeks to the event, then scans all of that event's rows applying `server_ts`
  as a filter. Audit rows are append-only and never deleted (`schema.ts:204-206`) —
  asymptotically ~876k rows/year. The scan cost per auth failure grows without bound.
- Impact: because this path exists to damp floods, the mitigation becomes an
  amplifier. A sustained invalid-credential flood raises the per-request cost and
  degrades every tenant on the shared D1.
- Recommendation: add a composite `(event, server_ts)` index on `user_audit_events`
  for a range seek. Or, instead of deriving the window counter from the append-only
  log, hold it in a dedicated counter row like `recovery_wraps.fetch_window_start` /
  `fetch_count`.
- **Handling**: took the latter (a dedicated counter row). Added the
  `login_failed_windows` table (one row per bucket. migration
  `20260824214725_simple_legion`) and removed the audit-log scan **entirely**. With an
  index, the scan becomes a range seek but still re-reads the in-window rows each
  time as the window grows to its cap — a counter row is a single primary-key seek,
  and R4's bucketing rides on the same statement. Window reset / increment / cap
  judgment is one conditional UPSERT + `RETURNING` (same shape as the recovery-fetch
  count = the B9 fix). The verdict derives from "recorded is at the cap and
  suppressed ≥ 1" = suppressed (within a window, recorded grows to its bound before
  suppressed grows, so the last allowed request at exactly the cap is not
  misjudged).

### R6. Token rotation silently discards the old token and leaves no revocation — BUG (new)

- Location: `apps/server/src/db.package/repos.ts` (`replaceForUserAndName`)
- slug: `other-audit-gap` / confidence medium
- Problem: one batch that deletes the row matching `(user_id, name)` and inserts a
  new row, with `auth.token_created` as the only record. There is no
  `auth.token_revoked` corresponding to the implicit revocation, so
  `GET /auth/audit/events` lacks a termination record for "a credential that stopped
  working".
- Impact: `deviceExchange` is reachable by anyone holding a valid GitHub OAuth token
  for that account, and `tokenName` is attacker-chosen (`auth-api.ts:171-173`). An
  attacker who steals a GitHub identity can name an existing CLI token (default
  `device-flow`), invalidating the victim's credential while leaving no reason in the
  audit log.
- Note: the code comments say this is deliberate, since learning the old token id
  needs a preceding SELECT. It is flagged because it is incomplete against the audit
  goal of visualizing takeovers.
- Recommendation: use the same `.delete(...).returning({ id })` as `revokeById`
  (L435-447) to post `auth.token_revoked`. Or carry `rotated: true` and the displaced
  token id on the `auth.token_created` payload so the event can be reconstructed.
- **Handling**: took the latter (carrying it on the issuance row). Posting
  `auth.token_revoked` would overturn AUDIT_SPEC §3.1's existing ruling ("rotation is
  replacement, distinct from explicit revocation"), so it was not taken. Added
  `replacedTokenId` to the `auth.token_created` payload (the key itself does not
  appear on fresh issuance) and revised AUDIT_SPEC §3.1. The id is picked **from
  within the SQL of the audit append placed before the delete statement** (since
  `json_patch` follows RFC 7386 merge semantics where NULL-valued keys are removed,
  the payload shape stays the same as before on fresh issuance) — adding a preceding
  SELECT would disagree with the row actually deleted under a concurrent rotation
  between the read and the batch. The delete + insert + audit atomic batch is kept
  as-is.

### R7. The OAuth callback triggers GitHub token exchange without limit / state is reusable — MEDIUM (new)

- Location: `apps/server/src/handlers-auth.ts` (`githubCallback`)
- Another record of the same point: `packages/api-schema/src/auth-api.ts` (the
  `githubCallback` error set is only `[AuthFlowError]`. confidence high)
- slug: `expensive-api-abuse`
- Problem: `ipRateLimitAllowed` is called in only two places — `handlers-auth.ts:206`
  (deviceExchange) and `handlers-lease.ts:114` — and not in `githubCallback`. The
  limiter bindings in `wrangler.jsonc` are also only `DEVICE_EXCHANGE_RATE_LIMIT` and
  `LEASE_RATE_LIMIT`. The only gate, the state comparison, is no throttle because the
  attacker controls both cookie and query
  (`curl -H 'Cookie: __Host-maruhi_oauth_state=X' '.../callback?state=X&code=junk'`).
  On top of that, the state cookie is expired only on the success path (L189-193), so
  one state can be reused for its 10-minute Max-Age. Each iteration consumes one
  `github.exchangeCode` → outbound to GitHub's token endpoint.
- Impact: the 8/22 fix closed the device-exchange side, but the same "deplete the
  OAuth App's shared quota, stopping login for all users" path remains on the
  callback. Availability only. The 512-character length cap (`auth-api.ts:143-146`)
  bounds payload size, not frequency.
- Recommendation: add an `OAUTH_CALLBACK_RATE_LIMIT` binding and place
  `ipRateLimitAllowed` before `github.exchangeCode`. Declare `AuthRateLimitedError`
  in the endpoint's error set. Also expire the state cookie on the failure path so
  state becomes single-use.
- **Handling**: added `OAUTH_CALLBACK_RATE_LIMIT` (30/min/IP — the same value
  `docs/SELF_HOSTING.md` recommended for the callback) to `wrangler.jsonc` and `Env`,
  and placed `ipRateLimitAllowed` at the **very start** of `githubCallback` (before
  the state comparison — this also bounds the audit-write amplification from
  `recordLoginFailed` on state mismatch). Declared `AuthRateLimitedError` in the
  error set. Corrected `SELF_HOSTING.md`'s statement that "the WAF is the only means
  for the callback". Single-use state was not adopted (reason in the note at the
  top).

### R8. (Same point as R7. The record on the `packages/api-schema/src/auth-api.ts` side)

Closed by the same change as R7 (the 2 records are treated as duplicates).

### R9. Embedded-IPv4 octet parsing is loose via `Number()` — BUG (new)

- Location: `apps/server/src/worker-env.ts` (`groupsOfPiece`)
- slug: `other-lenient-parsing` / confidence medium
- Problem: after `piece.split(".").map(Number)` it only checks
  `Number.isInteger(o) && 0 <= o <= 255`, so coercion goes through first. `""` → 0,
  `0x10` → 16, `1e2` → 100, leading/trailing whitespace passes, `1.2.3.` normalizes
  to 1.2.3.0, and `::ffff:0x1.2.3.4` is accepted. The hex-group side (L103) is
  strict, so the looseness is only on the embedded-IPv4 path.
- Impact: the only caller is `rateLimitKeyOf` ← `ipRateLimitAllowed`, and the input
  is `cf-connecting-ip`, which the Cloudflare edge always overwrites (absent under
  wrangler dev / tests, where it fails open). So there is no attacker-reachable path
  and no rate-limit bypass. The real harm is different malformed notations falling
  into the same bucket, or failing to fall back to the raw string.
- Recommendation: validate each octet with a strict decimal regex
  (`/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/`) before coercion, and allow an embedded
  IPv4 piece only at the end of the address.
- Note: the scanner also flagged L37 / L102 of the same file as `insecure-crypto`,
  a false positive (IPv6 detection and hex-group validation; no crypto involved).
- **Handling**: a strict decimal regex (rejecting leading zeros, empty, hex,
  exponent notation, whitespace) now runs before `Number()`, and an embedded IPv4
  piece is allowed **only as the last piece of the address** (RFC 4291 §2.2 (3).
  `1.2.3.4::` and `::ffff:1.2.3.4:0` are rejected). Malformed notations still fall
  back to the raw-string key as before (they do not turn into a different bucket).

## Out of scope (false-positive)

Items judged false-positive this time and not counted as open items:

- The 3 carried over from last time: `requestOrigin()` and the Host header,
  `invalidValueMessage`'s substring check, `computeVariablesDigest`'s UTF-16 / UTF-8
  duplicate check
- The device-flow token POST following redirects (`untrusted-redirect-following`)
- `commandAfterTerminator`'s stray-count negative value (`effect-cli.ts`)
- `recoveryStatus` not guarded by `ensureKeyMaterialAccess` (`auth-api.ts`)

## Order of attack (executed)

Implemented in the order R7+R8 → R5 → R4 → R6 → R9 → R3 → R1 → R2 (the only change
from the original recommended order is folding R4 into the same counter-row change
as R5 — bucketing and cap judgment ride on the same statement, so splitting them
would rewrite the same code twice).

## Notes for the next deepsec run

The 8 points in this document are implemented, but deepsec revalidation has **not yet
been run**. Next time, run `scan` → `process --reinvestigate` → `revalidate --force`
and confirm these come back `fixed` before closing. Files changed this time:

- `apps/server/src/`: `handlers-auth.ts` / `handlers-audit.ts` / `worker-env.ts` /
  `chain-do.ts` / `programs-audit.ts` / `audit-store.ts` /
  `db.package/{audit,repos,schema}.ts` / `wrangler.jsonc` / drizzle migration
- `apps/cli/src/`: `audit.ts` / `run.ts` / `keygen.ts` / `recovery.ts` / `session.ts`
- `packages/`: `api-schema/src/{audit,auth}-api.ts` / `core/src/audit.ts`
- docs: `AUDIT_SPEC.md` (§3.1 / §7) / `SELF_HOSTING.md`

## Working rules (carried over from last time)

1. Put one point, or only closely related same-shape ones, in one PR. Before
   starting, read the current code, the spec, and the ADR; do not implement the
   scanner's suggestion as-is.
2. R5 and R6 touch Drizzle — keep the repository-service boundary. Schema changes
   (including index additions) follow the drizzle migration procedure.
3. Do not add plaintext secrets, key material, or external provider IDs to logs or to
   append-only audit actors. Do not place attack PoCs in the repository.
4. User-facing text is English. When done, pass `bun run check` on the pinned Bun
   (`.bun-version`).
5. deepsec revalidation requires local Claude Max auth. In a Cloud environment, go as
   far as the fix and ordinary tests.
