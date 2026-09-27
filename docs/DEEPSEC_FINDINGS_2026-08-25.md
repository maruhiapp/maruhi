# deepsec open items (2026-08-25 revalidation)

The true-positives that remained, or newly appeared, in the run that verified the fixes
for the 8 points of `DEEPSEC_FINDINGS_2026-08-24.md`. The previous document is closed
by this run (7 points fixed, only R4 remains).

## Positioning

- Scope: 117 tracked files. `process` covered the 13 candidate files changed by the
  08-24 fixes (`--reinvestigate 2 --manifest`); `revalidate` re-judged all 26 findings
  on those 13 files with `--force`
- Model: `claude-opus-5`, thinking `medium`, Claude Agent SDK (local auth)
- runs: `scan 20260825002713-ed6224238ec2c19a` /
  `process 20260825002935-0e1bfd164a1a9165` /
  `revalidate 20260825003446-4a6d6d6964b0c376`
- Cost: process $8.26, revalidate $3.18 (total $11.44)
- Verdicts: fixed 13, false-positive 3, duplicate 5, **true-positive 5**

## 2026-08-27 additional revalidation of S1 / S3 / S4

- Scope: the 7 candidate files implementing S1 / S3 / S4 (manifest). The 6 files with
  matcher candidates were re-investigated under `--reinvestigate 3`, and the 12
  findings on that manifest were revalidated with `--force`
- Model: `claude-opus-5`, thinking `medium`, Claude Agent SDK (local auth)
- runs: `scan 20260827132550-694fee0d3217c8cc` /
  `process 20260827132600-6cba472eba489f0d` /
  `revalidate 20260827133028-743b76363689b140`
- Cost: process $3.63, revalidate $1.24 (total **$4.87**)
- Outcome of the 3 targets: **S1 / S3 / S4 are all `fixed`**
- process detected 2 new items (S7 / S8). In addition, `maruhi run`'s credential
  inheritance — a false-positive last time — was re-judged true-positive (BUG) as S6
- Currently unresolved: **5 items: S2 / S5 / S6 / S7 / S8**

## 2026-08-27 additional revalidation of S2 / S5–S8

- Scope: 10 candidate files implementing them (manifest). The 8 files with matcher
  candidates were re-investigated under `--reinvestigate 4`, and the 26 findings on
  that manifest were revalidated with `--force`
- Model: `claude-opus-5`, thinking `medium`, Claude Agent SDK (local auth)
- runs: `scan 20260827140524-349506fcf80b67f7` /
  `process 20260827140543-400e1c0d37c9c1bf` /
  `revalidate 20260827141220-055396ecda27491f`
- Cost: process $4.96, revalidate $2.90 (total **$7.86**)
- Outcome of the 5 targets: **S2 / S5 / S6 / S7 / S8 are all `fixed`**
- process detected 3 new items (S9 / S10 / S11). S9 / S10 are already implemented on
  the same branch; S11 is being ruled on separately as a self-hosting account
  admission / project-quota policy

## 2026-08-27 S9 / S10 supplement and final revalidation

- 1st run: `scan 20260827142502-5f2e610abc385fdd` /
  `process 20260827142505-0b1b8b09e2b3f974` /
  `revalidate 20260827142831-98a1fb82adbb859f`
- 2nd run: `scan 20260827143142-d939917e2ceb7dfc` /
  `process 20260827143144-8b605f1ef9c06c78` /
  `revalidate 20260827143508-61f94c1f58e5af7b`
- Final revalidate after the supplemental fix: `20260827144100-13a228b53f0c0734`
- Cost: process $2.82, revalidate $3.03 (total **$5.85**)
- S9 / S10 and the supplemental S12 / S13 are all `fixed`
- The final report's true-positives are **just S11 (MEDIUM)**

The 104 files unchanged in the 2026-08-25 run keep their 08-22 / 08-24 analysis
results (they were not re-checked by the 08-25 model run).

## Open items (5 true-positives)

Of the 4 new ones, **S1 and S3 sit immediately adjacent to the 08-24 fixes** — the
same evasion survived one step outside the addressed area. S2 and S4 correspond to
known carryovers (the ADR-0016 decision 7 carryover / B9's "the invite counter has the
same shape").

> **Status (2026-08-27)**: S1–S10 / S12 / S13 are implemented and deepsec-revalidated.
> Only **S11** is unimplemented.

### S1. `chain_seq` is displayed unlabeled even on rows outside `chain.*` — BUG (new)

- Location: `apps/cli/src/audit.ts` (`trailerParts` / `renderListEvent` / `fetchAllMirrorRows`)
- slug: `other-trust-label-bypass` / confidence medium
- Problem: the trust-label computation (`renderListEvent`) and verify's fetch
  (`fetchAllMirrorRows`) both branch **on the event-name prefix**, while
  `trailerParts` emits `chain_seq=N` for **any row** carrying `chainSeq`. When
  `trust === null` it becomes a bare coordinate with no label. Only
  `chainMirrorEvent` legitimately sets `chainSeq` (the server merely echoes it), so a
  row named `member.add` or `chainx.grant` carrying `chain_seq=7` **cannot exist on an
  honest server** = an indicator of forgery — yet the CLI silently renders it as an
  ordinary coordinate, and verify fetches none of it since it is outside the
  namespace.
- Relationship to 08-24's R1: R1 closed "names **inside** the namespace that are not
  in the mapping". This finding is the same evasion surviving **one step outside the
  namespace**.
- Scope of impact (narrowed by revalidation): verify's OK message states its range
  ("chain entries 1..N ↔ chain.* mirror rows"), so the text does not lie. It requires
  both a malicious server and an operator who reads a bare coordinate as verified
  provenance. BUG-equivalent.
- Recommendation: move the labeling trigger from the event-name prefix to **the
  presence of `chainSeq`**. A row that has `chainSeq` but for which trust cannot be
  computed gets
  `(mirror=unverified — event name is outside the chain.* namespace)` explicitly, and
  is counted as an integrity violation. On the verify side, fetch non-`chain.` rows
  that carry `chain_seq` and report them as forgery evidence.
- **Addressed** (2026-08-25): the list's trust judgment looks at the presence of
  `chainSeq` before the event name. Outside the namespace it explicitly shows
  `mirror=unverified (chain_seq is invalid outside the chain.* namespace)` and turns
  it into a warning + exit 1. `trailerParts` itself also got a fallback that does not
  display a `chain_seq` whose trust is null unlabeled. The D1 paths (invites / self)
  carry no legitimate chain provenance, so receiving the same shape gets the explicit
  label + exit 1. In addition to the existing `eventPrefix=chain.` filter, verify now
  fetches all pages of the new `chainSeqPresent=true` filter, unions them by row_id,
  and then reports out-of-namespace claims as forgery. If the same row_id returns
  different contents across the 2 queries, that too aborts as a self-contradictory
  server response. So that it also reaches non-admin verify, `chain_seq IS NOT NULL`
  became AUDIT_SPEC §6 class 1 (only the chain.* mirrors set this column under honest
  writers, so no legitimate class-2 row is disclosed). Regression tests were added
  for the CLI's list / verify / D1 display and for workerd's presence filter / reader
  visibility.
- **Revalidation** (2026-08-27): `fixed`. Confirmed that the display side judges the
  presence of `chainSeq` before the name, that the verify side inspects the union of
  the `chain.` namespace and `chain_seq IS NOT NULL`, and that non-chain rows become
  warning + exit 1. The append boundary also rejects a non-`chain.*` `chain_seq` as a
  defect.

### S2. Recovery-code display has no TTY check — MEDIUM (new)

- Location: `apps/cli/src/recovery.ts` (`issueRecoveryCodeOp` / `recoverMasterKeyOp`)
- slug: `other-key-material-to-disk` / confidence medium
- Problem: the display gate is a single layer of `io.agentProfile().isAgent` (a
  fail-open deny-list), writing a 256-bit code to stderr. stderr is redirectable just
  like stdout, and `maruhi key recovery 2> code.txt`, `> out 2>&1`, `script` / `tee`,
  and CI runners that capture both streams all persist the code to disk or build
  logs. The save-confirmation prompt comes **after** the display, and `promptLine`
  falls back to `readPipedLine()` on non-TTY, so it does not enforce interactivity.
- Asymmetry: value display (`showValues` → `ensureValueDisplayAllowed`) has the
  fail-closed "both stdin and stdout are terminals" as its primary boundary. The
  more sensitive recovery code (it opens the master secret key) sits behind a single
  deny-list layer — the direction is reversed.
- Knownness: ADR-0016 decision 7 **deliberately** kept recovery on the deny-list, and
  its carryover lists this class as a next ruling candidate under "under unknown
  agents it does not get the primary boundary's protection". So this is not an
  oversight but a **deferral**.
- Needs decision: the "redirect axis" is a different concern the ADR never actually
  addressed. Decide whether a TTY check can be added without breaking non-TTY CI
  issuance (or whether issuance and display should be split) before implementing.
  Present to a human as an ADR-0016 revision.
- **Addressed** (2026-08-27): ADR-0016 decision 7 was revised — recovery-code display
  and input are allowed only when all of stdin / stdout / stderr are TTYs. The
  known-agent check is the second layer. Issuance fails closed before recovery
  status / PUT, restore before the blob GET, and per-channel non-TTY tests (including
  `2>`) pin that no code display, prompt, or server reach happens. The path that
  silently skips issuance after keygen under a known agent was kept as-is, since it
  displays no code.
- **Revalidation** (2026-08-27): `fixed`. Confirmed both entry points (issuance /
  input) check all three channels for TTY, and reject before server access and before
  key material is unwrapped.

### S3. The denylist does not cover maruhi's own auth env — MEDIUM (new)

- Location: `apps/cli/src/run.ts` (`DENIED_ENV_NAMES` / `DENIED_ENV_PREFIXES`)
- slug: `other-env-hijack` / confidence medium
- Problem: `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN` are not on the denylist. Variable
  names are plaintext metadata a collaborating member with write permission can
  choose, so a malicious member can create a `MARUHI_TOKEN` holding their own PAT as
  the value. If the victim runs `maruhi run -- make deploy` and that makefile calls
  `maruhi pull` (very common in CI), `resolveSession` sees the env token **before the
  keychain**, so the nested `maruhi` authenticates as the attacker. The attacker can
  also set `MARUHI_TOKEN_ORIGIN`, so `sessionFromEnvToken`'s origin binding does not
  help.
- Impact: nested reads return the attacker's project values, and the victim's
  pipeline treats them as its own secrets. Nested writes go into the attacker's
  account.
- Recommendation: add `MARUHI_` to `DENIED_ENV_PREFIXES` (at minimum put
  `MARUHI_TOKEN` and `MARUHI_TOKEN_ORIGIN` in `DENIED_ENV_NAMES`). A one-liner riding
  the existing prefix mechanism.
- **Addressed** (2026-08-25): added `MARUHI_` to `DENIED_ENV_PREFIXES`. A blanket
  prefix rather than enumerated names was chosen because it is **a namespace maruhi
  itself reserves** — no "legitimate variable" can in principle be caught in it —
  while with individual names the same hole would reopen when a future `MARUHI_*` is
  added (this does not contradict M2's ruling against blanket rejection of NODE_ /
  PYTHON_ / BUN_, since the namespace owner differs). At this point the inheritance
  of a real `MARUHI_TOKEN` from the parent environment was left alone (excluded
  later under S6). With a regression test (confirmed it fails when the fix is
  reverted).
- **Revalidation** (2026-08-27): the S3 body is `fixed`. The path where a stored
  variable takes a `MARUHI_*` name to hijack a nested maruhi is closed. However, the
  **inheritance itself** when the parent environment holds a real `MARUHI_TOKEN` is
  separately tracked as S6, a true-positive.

### S4. Invite pending cap / issue window is check-then-act — BUG (new)

- Location: `apps/server/src/db.package/repos.ts` (`InviteRepo.create`)
- slug: `rate-limit-bypass` / confidence medium
- Problem: the two admission controls — pending count and the 1-hour window — are
  evaluated with a plain SELECT, then the insert happens in an unrelated `db.batch`.
  The counts are not in the insert's WHERE; there is no CAS, conditional
  INSERT…SELECT, or counter row. N concurrent POSTs all observe the same under-limit
  and all insert, so `MAX_PENDING_INVITES_PER_PROJECT` (100) and
  `INVITE_ISSUE_WINDOW_LIMIT` (30/h) can each be exceeded by the degree of
  concurrency.
- Knownness: the JSDoc says "best effort" and points at the recovery fetch count as
  a peer example, but **that one was fixed into a single conditional UPDATE under
  B9**, so they are no longer peers.
- Scope of impact: execution requires an authenticated project admin (or a leaked
  admin PAT), and 30/hour can be issued legitimately anyway. It stays a one-burst
  cap overrun and crosses no privilege or confidentiality boundary. BUG-equivalent.
- Recommendation: fold it into the same shape as `recordFetch`. Either make the
  insert an `INSERT … SELECT` that re-evaluates both counts in the WHERE and treats
  0 rows as a refusal, or run a per-project counter row — the same shape as
  `login_failed_windows` — in a single conditional UPSERT + `RETURNING`. Keep
  `invite.created` in the same batch with the same `changes() = 1` guard as
  `acceptCas` / `revokeCas`.
- **Addressed** (2026-08-25): without changing the schema, the caps, or the
  judgment order, the pending count and the lookback count are re-evaluated in
  correlated subqueries of the same `INSERT … SELECT … WHERE`. If `RETURNING` yields
  1 row the creation succeeded; on 0 rows it re-reads pending then lookback — in spec
  order — to derive the typed 429. `invite.created` sits in the same D1 batch as the
  immediately following `changes() = 1`-guarded INSERT…SELECT, made 1:1 with the
  creation winner. With both the pending cap and the issue window set to 1 remaining
  slot, 8 concurrent POSTs were sent and workerd pinned: 1 success, 7 rejections,
  stored count exactly at the cap, 1 audit row — for each limit. Also confirmed both
  tests fail with 8 successes when the condition is temporarily removed.
- **Revalidation** (2026-08-27): `fixed`. Confirmed both the pending and lookback
  caps are re-evaluated in a single `INSERT … SELECT … WHERE`, and that `RETURNING`
  plus the `changes() = 1` audit agree with the creation winner.

### S5. The `auth.login_failed` cap is still shared per `auth_method` — BUG (R4 remainder)

- Location: `apps/server/src/db.package/audit.ts` (`appendLoginFailed`)
- slug: `other-audit-suppression` / confidence medium
- Status: R4 in 08-24 implemented `auth_method` bucketing + observability of the
  suppressed count, but **coverage within the same method remains** (exactly the
  "remaining limitation" noted at implementation time). The revalidation
  acknowledged the effect of bucketing and the power-of-ten markers, lowered the
  severity MEDIUM → BUG, and kept the remainder as a true-positive.
- The remainder, concretely: the 100/hour frame is shared deployment-wide per
  method. The rate limits added under R7 (callback 30/min, device exchange 10/min)
  **damp bursts but cannot prevent a single IP from reaching 100 within an hour**
  (about 4 minutes on the OAuth side). Once the frame saturates, the individual rows
  of a targeted attack on that method get dropped. What is destroyed is not the
  row's existence but **the per-attempt `reason`** (the marker retains the volume.
  `auth.login_failed` has no actor user_id, so it never appeared on the
  subject-axis reads anyway; what is lost is operator-view information).
- Needs decision: give it a dimension the attacker cannot share with the victim. The
  options that fit §1-2's identifier rules are (a) bucket failures attributable to a
  resolved account by `auth_method` + internal `user_id`, dropping only
  pre-resolution failures into the shared frame, and (b) keep a (small) shared frame
  and a per-account frame separately. At minimum, put a per-reason histogram on the
  marker. **Per-origin** dimensions are explicitly denied by AUDIT_SPEC §3.1, so that
  option is not taken.
- **Addressed** (2026-08-27): current failures are pre-authentication and carry no
  target user_id — the only classifications an individual row carries are
  `auth_method` and `reason` — so their cross product was made the independent
  bucket. The marker payload now also carries reason, so a flood of one reason does
  not blind a different reason of the same method. A workerd test was added showing
  that saturating the `state-mismatch` frame still leaves `code-exchange-failed` as
  individual rows, and that suppression markers carry reason and count. No IP or
  provider ID was added to either the counter key or the audit actor.
- **Revalidation** (2026-08-27): `fixed`. Confirmed independent counting by the
  `auth_method + reason` JSON key, and that the marker carries reason too, so a
  flood of one reason does not lose the attempt classification.

### S6. `maruhi run` passes the parent environment's maruhi API token to the child — BUG (re-judged)

- Location: `apps/cli/src/live.ts` (`makeBunProcessRunner`) / `apps/cli/src/run.ts`
- slug: `other-credential-inheritance` / confidence high
- Status: judged false-positive on 2026-08-25, changed to true-positive
  (MEDIUM → BUG) by the 08-27 revalidation
- Problem: the child env is `{ ...process.env, ...extraEnv }`, so keychain-less / CI
  `MARUHI_TOKEN` and `MARUHI_TOKEN_ORIGIN` pass through as-is. S3's `MARUHI_`
  denylist only prevents **a stored variable taking that name**; it does nothing
  about inheritance from the parent environment. A malicious dependency under
  `maruhi run -- npm test` reads not only the injected values but a PAT that stays
  usable afterwards, and can perform reads / writes within the token's scope after
  the run ends.
- Recommendation: remove maruhi credential variables from the parent-environment
  copy given to the child. At least `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN`; exclude
  future auth-related `MARUHI_*` at the same boundary.
- Needs decision: whether nested `maruhi` is explicitly supported. Stripping makes
  existing workflows that call maruhi again inside `maruhi run -- make deploy` lose
  authentication, so rule first on compatibility versus the security boundary of
  "only consumed values are passed to the child".
- **Addressed** (2026-08-27): added "children do not inherit `MARUHI_*`" to
  ADR-0016. `buildChildEnvironment` removes the `MARUHI_` prefix case-insensitively
  from both the parent environment and extraEnv, while general environment and
  injected values are preserved. A keychain-less / CI nested maruhi no longer
  implicitly uses the parent's PAT; maruhi operations that are needed happen outside
  the run — that is the line drawn.
- **Revalidation** (2026-08-27): `fixed`. Confirmed production `Bun.spawn` uses the
  filtered env, excluding `MARUHI_*` — including future ones — from both the parent
  and extraEnv.

### S7. The per-user API-token cap is check-then-act — BUG (new)

- Location: `apps/server/src/auth.package/token.ts` (`issueToken`) /
  `apps/server/src/db.package/repos.ts` (`countByUserExcludingName` /
  `replaceForUserAndName`)
- slug: `other-race-condition` / confidence high
- Problem: it SELECTs the user's other-name token count, compares against the cap of
  100, then inserts on a different D1 round-trip. Concurrent device exchanges under
  different token names all observe the same under-limit and insert, exceeding the
  cap by the degree of concurrency. `UNIQUE(user_id, name)` does not help because
  the names differ. The same race as the invite cap fixed in S4.
- Recommendation: make `replaceForUserAndName`'s insert
  `INSERT … SELECT … WHERE (count(user_id, name <> requested) < 100)`, mapping a
  `RETURNING` of 0 rows to `TokenLimitReachedError`. Restrict the prior count to
  deriving the refusal reason; give admission to the single statement. Add a
  concurrent different-name issuance test.
- **Addressed** (2026-08-27): inside the repo it now runs "atomic rotation of an
  existing same name → conditional `INSERT … SELECT … WHERE count < 100` for a new
  name → re-rotation on a same-name race", and the service layer's prior count was
  removed. Same-name requests are still allowed at the cap, keeping R6's audit that
  puts the actually displaced old id on `replacedTokenId`. With 1 slot left, 8
  concurrent different-name requests were sent and pinned: 1 success, 7
  TokenLimit, 100 stored rows, 2 creation audit rows (initial + winner).
- **Revalidation** (2026-08-27): `fixed`. Confirmed the quota is evaluated in the
  new INSERT's correlated subquery, and that no independent count remains in the
  service layer.

### S8. `TokenRepo.revokeById`'s DELETE has no user-ownership predicate — BUG (new)

- Location: `apps/server/src/db.package/repos.ts` (`revokeById`)
- slug: `other-missing-ownership-predicate` / confidence medium
- Problem: `revokeById(id, userId, nowMs)` uses userId only for the audit actor; the
  DELETE runs on the token id alone. The only current caller passes a `record.id` /
  `record.userId` resolved by hashing the presented token, so **there is no exploit
  path today**. But if a future admin API takes a token id, it becomes a latent
  authorization gap: delete another user's token while the audit actor is recorded
  as the calling user.
- Recommendation: make the DELETE's WHERE `id = ? AND user_id = ?`. With the
  existing `RETURNING` + 0-row early return, a non-owned id fails closed into a
  no-op with no audit row, and the current path's behavior and cost do not change.
- **Addressed** (2026-08-27): changed the DELETE to `id AND user_id`. A regression
  test calling the repo directly with a different userId confirmed the token remains
  and `auth.token_revoked` does not grow.
- **Revalidation** (2026-08-27): `fixed`. A non-owned id is RETURNING 0 rows → a
  no-op with no audit row.

### S9. The invite link's raw token goes to stdout, persistable by redirect — BUG (new)

- Location: `apps/cli/src/invite.ts` (`inviteCreateOp`)
- slug: `secrets-exposure` / confidence low
- Problem: the link containing a single-use token is written to stdout, so
  `maruhi invite create > file` or CI capture leaves the credential on disk / in
  logs. Previously only known agents were refused; non-TTY and unknown harnesses
  passed. The token has a 7-day expiry plus a post-acceptance FP check, so this is
  not a direct membership bypass, but it does violate the diskless invariant.
- **Addressed** (2026-08-27): ADR-0016 decision 7 was further revised and invite
  link display also moved to the 3-channel stdin / stdout / stderr TTY boundary.
  The agent check is the second layer. Per-channel non-TTY tests refuse before the
  issuance POST and pin that no raw token is output.
- **Revalidation** (2026-08-27): `fixed`. Confirmed non-TTY including a stdout
  redirect fails closed before the HTTP call and outputs no raw token.

### S10. The env denylist lacks same-shape names for shell autoload / TLS trust — BUG (new)

- Location: `apps/cli/src/run.ts` (`DENIED_ENV_NAMES`)
- slug: `other-incomplete-denylist` / confidence medium
- Problem: same class as the already-denied `BASH_ENV` / `ZDOTDIR` /
  `NODE_EXTRA_CA_CERTS`, but `FPATH` / `KSH_ENV` / `SSL_CERT_FILE` / `SSL_CERT_DIR` /
  `CURL_CA_BUNDLE` / `REQUESTS_CA_BUNDLE` / `AWS_CA_BUNDLE` / `PYTHONUSERBASE` /
  `PYTHONWARNINGS` are not denied. A collaborating member can swap the autoload path
  or the TLS trust root.
- **Addressed** (2026-08-27): the 9 names above were added as known
  execution-control names and included in the same case-insensitive regression test
  as R3. Cryptographic binding of variable names remains the real fix, and the
  denylist stays best-effort. `NPM_CONFIG_` is not denied wholesale; only the
  execution-control keys `USERCONFIG` / `GLOBALCONFIG` / `SCRIPT_SHELL` /
  `NODE_OPTIONS` / `NODE_GYP` / `INIT_MODULE` / `EDITOR` / `VIEWER` and TLS-trust
  ones are denied individually. `NPM_CONFIG__AUTH` / `_AUTHTOKEN` for registry
  credentials and `NPM_CONFIG_REGISTRY` for private registries stay allowed.
- **Revalidation** (2026-08-27): `fixed`. Since the same re-investigation surfaced
  additional same-shape names as S13, those were added to the same denylist as a
  supplement.

### S11. Self-hosting auto-registers any GitHub account, and project creation has no global quota — MEDIUM (new)

- Location: `apps/server/src/handlers-auth.ts` (`githubCallback` / `deviceExchange`) /
  the project-creation path
- slug: `other-open-registration` / confidence medium
- Problem: after GitHub verification it calls `getOrCreateUser` unconditionally,
  creating a user + personal org even for unknown accounts. The device flow also
  issues a `* × admin` PAT. With no operator allowlist / signup invite / org
  restriction and no cap on a registered user's project count, anyone can register
  on a public self-host with a throwaway GitHub account and grow DOs and D1 rows
  per project.
- Recommendation: apply operator-controlled admission (`ALLOWED_GITHUB_USER_IDS` or
  similar, or a mandatory signup invite after the first user) fail-closed before
  user creation in auth. Separately, add a per-user/org project quota and a rate
  limit on project init.
- Status: **unimplemented**. It is a product/auth policy deciding self-host first
  owner creation, pre-auth acceptance of invitees, and migration of existing
  deploys at once — kept separate from the localized fixes S2/S5–S10.

### S12. invite list silently skips the issuance-pin check for unknown ids — BUG (new)

- Location: `apps/cli/src/invite.ts` (`inviteListOp`)
- slug: `other-logic-bug` / confidence high
- Problem: when the server returns an id that is not in the local issuance pin,
  `issuedPinOf` is undefined and the role / token_hash check is silently skipped.
  Issuance from another device is legitimate, so it cannot be a failure — but
  "checked and passed" and "no check material" look identical in the output.
- **Addressed & revalidated** (2026-08-27): each pinless row now states
  `The token_hash / role cross-check was not performed` explicitly. Not counted as
  an integrity failure; exit 0 is kept. `fixed` in the final revalidate.

### S13. The denylist lacks runtime hooks that need no filesystem — MEDIUM (new)

- Location: `apps/cli/src/run.ts` (`DENIED_ENV_NAMES` / `DENIED_ENV_PREFIXES`)
- slug: `other-env-injection-denylist-gap` / confidence medium
- Problem: `PYTHONBREAKPOINT` / `PYTHONEXECUTABLE` / `JDK_JAVA_OPTIONS` /
  `DOTNET_STARTUP_HOOKS` / `GEM_HOME` / `GEM_PATH` / `HOSTALIASES` and `CORECLR_*` /
  `COR_*` are not denied. Same class as the already-denied runtime hooks.
- **Addressed & revalidated** (2026-08-27): the individual names and 2 prefixes
  above were added and included in the case-insensitive regression test. `fixed` in
  the final revalidate.

## Out of scope (false-positive)

- `requestOrigin()` and the Host header (third time as false-positive)
- `recoveryStatus`'s missing `ensureKeyMaterialAccess`

## Recommended order of attack

1. ~~**S3**~~ — addressed (above). Same class as 08-24's R3, so it went in the same PR.
2. ~~**S1**~~ — addressed (above). Extended R1's namespace check to the presence of chain_seq.
3. ~~**S4**~~ — addressed (above). Folded into conditional INSERT + changes() audit.
4. ~~**S8**~~ — addressed. Repo ownership predicate + non-owned no-op test.
5. ~~**S7**~~ — addressed. Conditional issuance + concurrent different-name token test.
6. ~~**S6**~~ — addressed. `MARUHI_*` excluded from the child environment.
7. ~~**S5 / S2**~~ — addressed. AUDIT_SPEC §3.1 / ADR-0016 decision 7 revised.
8. ~~**S9 / S10**~~ — addressed. Invite-link TTY boundary / denylist same-shape names added.
9. ~~**S12 / S13**~~ — addressed. Explicit no-pin-check marker / runtime-hook denylist supplement.
10. **S11**. Rule on the product/auth policy for operator admission and project
    quota first.

## Working rules (continued)

1. Put one point, or only closely related same-shape ones, in one PR. Before
   starting, read the current code, the spec, and the ADR; do not implement the
   scanner's suggestion as-is.
2. S7 / S8 touch Drizzle — keep the repository-service boundary. If a schema change
   is needed, follow the drizzle migration procedure.
3. Do not add plaintext secrets, key material, or external provider IDs to logs or
   to append-only audit actors.
4. User-facing text is English. When done, pass `bun run check` on the pinned Bun
   (`.bun-version`).
5. deepsec revalidation requires local Claude Max auth.
