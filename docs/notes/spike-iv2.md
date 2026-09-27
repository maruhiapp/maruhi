# K0 spike: IV2's backing source (the GitHub signing-keys API / `gh ssh-key add`) — items for the owner to verify on their own machine

Status: 2026-09-13 — K0 of IV (supplement 21). **From this environment (Claude Code's remote execution environment), `api.github.com`'s user-family paths are blocked by the proxy and could not be measured** (403 "sessions are bound to their configured repositories"). K5 was implemented from GitHub's public documentation, and the tests are pinned against a fake server (`githubSigningKeysHandler` in `test/support/invite.ts`). This note is the list of "what the implementation assumed" and "what the owner should verify on their own machine", and the wording gets corrected based on the results (the remainder of supplement 21-5).

## 0. What the implementation assumed (unverified — documentary knowledge)

| Item | The implementation's assumption | Source | Verification status |
|---|---|---|---|
| The endpoint | `GET https://api.github.com/users/{login}/ssh_signing_keys` (unauthenticated, public info) | GitHub REST API docs, "List SSH signing keys for a user" | **Unverified** |
| The response shape | A JSON array. Each element is `{ id, key, title, created_at }`, and `key` is an `ssh-ed25519 AAAA…` OpenSSH public-key line (with or without a comment field) | Same | **Unverified** (the implementation reads no field other than `key`. Types other than `ssh-ed25519` are skipped) |
| A nonexistent login | 404 | Same | **Unverified** |
| The unauthenticated cap | 60 requests / hour / IP (excess returns 403 or 429) | GitHub docs, "Rate limits for the REST API" | **Unverified** (the implementation returns to the ceremony treating 403 / 429 as "unfetchable (rate limited)") |
| Bun fetch under `HTTPS_PROXY` | Effect's `FetchHttpClient` = Bun's fetch. Bun reads the proxy environment variables (confirmed via the startup warning "Proxy environment variables detected") | Bun docs | **Unverified** (in this environment the proxy **blocked** the call = the blocked behavior (transport error → back to the ceremony) is measured) |
| `gh ssh-key add` | `gh ssh-key add - --type signing --title "maruhi <fp>"` reads the key from stdin. The required scope is `admin:ssh_signing_key` (`gh auth refresh -s admin:ssh_signing_key`) | the gh manual | **Unverified** (gh is absent in this environment. Tests fake the ProcessRunner) |
| When blocked / offline | a 10-second timeout → "unfetchable" → back to the ceremony (note) | — | **Verified** (unit tests: transport failure, 500, malformed shapes) |

## 1. Items for the owner to verify on their own machine (checklist)

1. **The response shape**: `curl -s https://api.github.com/users/<your login>/ssh_signing_keys` — that it is an array, that `key` is an `ssh-ed25519 …` line, and whether a comment field (separate from `title`) is attached. → If it is, `parseOpenSshEd25519PublicKey` ignores the third and later fields, so no problem (the vector `invite-link.json`'s `openssh.parse` has a positive case with a comment)
2. **404**: that a nonexistent login returns 404 (the implementation maps it to `no-user`)
3. **The cap**: the response on the 61st consecutive request (403 / 429) and the `retry-after` / `x-ratelimit-reset` headers. → The implementation returns to the ceremony without waiting. `member add` is rare, so the cap is not expected to be hit — but a shared IP like CI's could hit it. In that case, does the wording "github.com answered 403 (rate limited)" fit the actual behavior
4. **The proxy**: on a machine with `HTTPS_PROXY` set, does `maruhi member add --github <login>` reach GitHub (does Bun's fetch use the proxy). If unreachable, confirm it returns to the ceremony with the note "could not reach github.com (…)"
5. **`maruhi key publish --gh`**: run it on a machine that has completed `gh auth login` → under GitHub's Settings → SSH and GPG keys, `maruhi <fp>` should appear as a **Signing key**. Whether the insufficient-scope failure text (the implementation guides to `gh auth refresh -s admin:ssh_signing_key`) matches gh's actual error
6. **The round trip**: on 2 accounts, `invite create --github` → `invite accept --from` → `member add` passing **with no prompts** (satisfaction form 4). Also the two-option fallback when one side is unregistered (`member add`), and the accepter-side fallback (the 12 words), once each
7. **Key regeneration**: on an account that redid `key generate`, a stale registration stays and the match misses → drops to the ceremony — is the guidance text ("If an older key of yours from maruhi is registered there, remove it") sufficient

## 2. Places the results will correct

- The wording of `describeBackingFallback` / `fetchSigningKeys` in `apps/cli/src/github-signing-keys.ts` (the cap, the malformed shape)
- The guidance on gh failure in `apps/cli/src/key-publish.ts`
- `apps/site/docs/invite-a-teammate.mdx` (the "Before you start" steps, the `--gh` prerequisite)
- Supplement 21-5 (the implementation record): "unverified" → "verified"
