# Session 18 memo (recovery code — productizing CRYPTO_SPEC §8. A remaining Phase 1 item)

Date: 2026-08-09. Prerequisite: started from main with PR #37 (ADR-0014) merged.
Scope: ROADMAP Phase 1's "recovery code (including loss-prevention UX such as save confirmation
and storage reminders — the first step of ADR-0014 ruling 4)". Since the crypto layer (§8's wrap / unwrap +
test vectors) was implemented in PR #12, this session covers **only the server storage / distribution
side (drafting AUTH_SPEC §13) + CLI UX**, and `packages/crypto` is untouched
(no crypto-spec change).

## 1. What was done

1. **Drafted AUTH_SPEC §13 (the recovery-blob API)**: in the form where merging the
   implementation PR constitutes owner approval (§5.1 = the PR #21 precedent). Key points:
   - At most one blob per user. Reissue = a replacing upsert (the old wrap disappears the moment
     the new one is accepted. No dedicated delete endpoint)
   - **Token conditions for key-material management operations**: register / reissue / fetch require
     a session principal or a token containing `*` × admin scope (the default device-flow token
     qualifies). Blocks wrap substitution by a stolen scope-limited token =
     an availability attack (same shape as §12-6's overwrite ban) and blocks fetching of the watch-listed blob
   - **Fetch rate limit (a CRYPTO_SPEC §8 requirement)**: a fixed window of 5 per hour.
     The count lives alongside the blob row (fetch_window_start / fetch_count); 404s are not counted;
     reissue resets the window. A best-effort auxiliary line (not a crypto boundary)
   - `GET /auth/recovery/status` returns only registration existence + update time (for reminders.
     Exempt from the scope condition and the rate limit)
2. **api-schema**: recoveryPut / recoveryGet / recoveryStatus +
   RecoveryWrapNotFound (404) / RecoveryRateLimited (429, retryAfterSeconds).
   ciphertext is hex of 16 B–16 KiB (acceptance policy §13-4)
3. **server**: D1 `recovery_wraps` (a drizzle migration), RecoveryRepo
   (upsert / find / recordFetch), 3 handlers in handlers-auth.
   A stored suite other than `maruhi/v1` is a defect (not silently distributed)
4. **CLI**:
   - `recovery-code.ts`: Base32 (RFC 4648) 52 symbols = 4 chars × 13 groups.
     The decode side absorbs lowercase / spaces / hyphens, but **does not guess-substitute
     out-of-alphabet characters (0/1/8/9) — it rejects** (a mis-substitution would become a silent decryption
     failure with no traceable cause). Includes a trailing-4-bit zero-padding check
   - The blob serialization format (§8's "settled at CLI implementation time") = the JSON of the keychain's
     StoredMasterKey record. The restoring side stores it only after passing importMasterKeys'
     self-verification
   - Auto-issuance after `key generate`: display → **save confirmation (re-enter the
     last group, up to 3 tries)**. Registration precedes confirmation (build the state where
     reissue can retry even if confirmation fails). Key generation succeeds even if
     confirmation or registration fails, and `maruhi key recovery` is suggested
   - `key recovery` (issue / reissue; if already registered it states "the old code is invalidated") /
     `key recover` (restore: authenticated fetch → code entry → local decrypt →
     keychain store. **Code-entry retries are local** and do not consume the rate-limit
     window. Refuses to overwrite an existing key)
   - **Agent environments**: the code is key material, so display is refused (the same
     line as agent.ts). `key generate` skips issuance and points to a human terminal (key generation
     itself succeeds); standalone `key recovery` is refused
   - Storage reminders: a recovery row in `key show` (prompts issuance if unregistered);
     after login, guidance to the state-dependent next step (recover / generate / recovery)
     (a status-check failure must not turn a successful login into a failure — explicit degradation)
   - Added `promptLine` (interactive single-line input) to CliIo. The live implementation uses
     raw-mode non-echo input (secret: true) on a TTY and a plain line read on non-TTY

## 2. Implementation details

- **Rate-limit design**: read → conditional update in 2 statements; concurrent requests can
  slightly over-count (noted in the spec). Its position is "an auxiliary line on top of the
  authentication + high-entropy-code double defense + buying detection time", so D1 atomic batching
  was judged not worth the complexity
- **Why the status handler is not subject to 403**: it carries no blob, and the CLI calls it on every
  authentication as the premise of the reminders
- **fallow handling**: keygen / recover's "refuse to overwrite an existing key" prologue was
  clone-detected, so it was extracted into `session.ts`'s `ensureNoStoredMasterKey`.
  The raw-mode input's character handling touched the CRAP threshold (the untested live layer), so it was
  split via a character-set Set + fewer branches
- **Server-test caveat**: reissuing a same-named device-flow token revokes the old one on rotation
  (§6), so tests needing a different principal for the same user register via a session

## 3. Out of scope (handoffs)

- **Audit events** (auth.recovery_blob_fetched / auth.recovery_code_reissued =
  AUDIT_SPEC §3.1): not recorded because the D1-side audit-log foundation (§3.1–§3.2's storage) is
  unimplemented. Implemented together with the foundation (noted in AUTH_SPEC §13-5)
- Richer storage UX such as a printable template is future work (v1 is code display + save confirmation +
  reminders). Sealed backup / passkey PRF remain per ADR-0014 / ROADMAP future
- The rest of session-11 §5 (the public-settings endpoint / the pull metadata-only mode),
  the chain-append commands, and the crypto test/checks organization candidate (session-17 §4) remain
  valid and untouched

## 4. Self-review and fixes (the 2nd commit)

A post-first-commit review produced 5 findings on the CLI interaction layer. None on the
server layer or Base32. All fixed:

1. **Code display moved to stderr** (most important): the inconsistency of the display block on
   stdout while prompts were on stderr meant `key generate > log` left key material in a
   plaintext file and showed only the save confirmation with no code on screen. The issuance
   ceremony (replacement warning, the code, guidance, confirmation complete) was moved wholesale to stderr
2. **Sharing the line reader on non-TTY**: creating and closing a readline per prompt
   dropped buffered next lines when the closed instance discarded them, so a second or later line
   vanished across multiple prompts (such as re-entering the restore code). Replaced with a single-buffer
   `makeStdinLineReader` that retains unconsumed input (an already-ended stream is detected via
   `readableEnded` — 'end' fires only once)
3. **Offline behavior of `key show`**: the regression where a recoveryStatus failure took down
   the whole command was changed to degrade with an explicit "could not check" line
   (the core duty = showing the local key still succeeds)
4. **Hardening raw-mode input**: not settling on end/error (a hang), Ctrl+D being
   concatenated as invisible input, and arrow-key escape sequences silently corrupting input were
   fixed (escape sequences are ignored through the terminating letter, control chars ignored, Ctrl+D = abort)
5. **Silent catch in login guidance**: `Effect.catch(() => Effect.void)` violates
   CLAUDE.md's "do not swallow errors silently in catch". Changed to a form that prints one line
   saying it was skipped (the command's success is unaffected)

live.ts's input primitives were "exposed for testing" (the repos.ts isUniqueConflict
precedent), and live-io.test.ts gained 7 unit tests (line carry-over, CRLF,
EOF without newline, EOF hang, Backspace, escape sequences, Ctrl+C/D).

Two more items were folded in from the bot review on the PR:

6. **The unknown-suite check moved before fetch counting** (Bugbot; Cursor Autofix also
   pushed the identical fix — integrated via rebase): a defect response that never reaches distribution
   must not consume the fixed window. Added a regression test that creates an unknown-suite row via
   direct D1 update (500 + fetch_count unchanged)
7. **A CSRF header for blob fetch (Security Agent)**: `GET /auth/recovery` is
   a GET carrying state (the fetch count), and a Lax session cookie is sent even on
   cross-site top-level navigation — a third-party site could consume the victim's fetch window (5/h).
   Session principals now require the same `x-maruhi-csrf: 1` as write operations
   (noted in AUTH_SPEC §13-2. Bearer principals are out of scope)

Rulings on the pullfrog review (3 design confirmations + 2 nits, no blockers):

8. **Added an agent refusal to `key recover` too (symmetrizing the boundary)**: the code is
   key material, and a path where it is typed into agent-mediated stdin (input is
   readable from the agent's session layer) is not built either. Same line as the issuance (display)
   side: restoration happens on a human interactive terminal. It also cannot reach
   the blob fetch (a watch-listed event)
9. **`key generate`'s non-interactive / offline contract (codified as intentional)**: the issuance
   ceremony (code display + save confirmation) assumes an interactive terminal. Non-interactive / offline
   exits 1, but **the key generation itself has succeeded**, and the error message
   points to resuming with `maruhi key recovery` (re-running's "already exists" is
   correct as a key-overwrite refusal). Auto-skipping confirmation on non-TTY was not adopted —
   reporting an unconfirmed issuance as success mass-produces the "registered but not saved" state.
   There is no legitimate flow that generates a master key in CI
10. **Typing the interruption check (nit)**: the string match on
    `error.message === "interrupted"` became an instanceof check against the `PromptInterruptedError` class
11. **The unaudited window (confirmation only)**: while no audit records of key-material
    operations exist until the D1 audit foundation lands, it stays handed off per §13-5. This PR's
    merge = the record that the owner explicitly accepted this window. The other nit (the order of
    suite check vs counting) was handled in §4-6 (the review was at 1316cc9, so already known)

## 5. Test results

- server (vitest-pool-workers): all pass including recovery.test.ts's 15 tests (2 authorization
  principals / scope-condition 403 / replacement / rate limit and window reset / 404 not counted /
  unknown suite = 500 + window not consumed / session GET's CSRF 403 + window not consumed / status /
  Schema 400 / 401)
- cli (Vitest): recovery.test.ts's 14 tests (Base32 roundtrip + rejections, a roundtrip where the issued →
  displayed code actually decrypts, save-confirmation failure, agent skip /
  issuance refusal / input refusal, restore success, wrong code ×3, 404, 429, overwrite refusal) +
  live-io.test.ts's 7 + login guidance 3 + key show recovery row 3.
  Existing tests followed the new flow
- `bun run check` (oxfmt / oxlint / tsc / ImportLint / fallow audit / React
  Doctor / all tests) green
