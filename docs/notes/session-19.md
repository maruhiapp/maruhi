# Session 19 memo (verifying the one-shot wrangler deploy + the self-host first-time setup wizard)

Date: 2026-08-10. Prerequisite: started from main with PR #38 (session 18) merged.
Scope: the last 2 remaining ROADMAP Phase 1 items (the final implementation before dogfooding).

## 1. Verifying the one-shot wrangler deploy (the ADR-0012 self-host path)

The real deployment that spike B (2026-08-01) left as "not done for lack of credentials" was
carried through to the end on a verification CF account (the `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` env vars).
**It works with plain wrangler alone** (the only fix was the explicit settings below):

1. `wrangler d1 create maruhi` → write the database_id into wrangler.jsonc
2. `wrangler d1 migrations apply maruhi --remote` — **drizzle-kit v1's folder format
   (`drizzle/<name>/migration.sql`) applied as-is via `migrations_pattern`**
   (officially supported since wrangler 4.118+. Also verified locally with `--local`)
3. `wrangler secret put GITHUB_CLIENT_SECRET` (a dummy value for verification)
4. `wrangler deploy` → `https://maruhi-server.maruhi.workers.dev`
   - Bundle 1754 KiB / gzip 355 KiB (within the script limit), **Worker Startup Time
     35 ms** (the actual measurement answering spike B's "cold start unmeasured")
   - The cron (session cleanup) was registered at the same time
5. Connectivity: unknown path 404 / auth-required 401 JSON / `GET /auth/github/start`
   correctly derives redirect_uri from the request origin — all confirmed

The wrangler.jsonc fix: set `workers_dev: true` / `preview_urls: false` explicitly
(preview URLs only multiply OAuth callback origins, so disabled).
Added `deploy` / `db:migrate` scripts and wrangler 4.118.0 (devDependency) to
apps/server — the version is pinned identical to vitest-pool-workers' transitive dep, no double copy.
Wrangler invocations during verification used `WRANGLER_SEND_METRICS=false` ("say nothing").

**The verification deploy is left running** (the foundation for the next phase's dogfooding):
account `maruhi` (66174a06…), D1 `maruhi` = `85cb9161-4aa4-4129-adce-d97e14d2ec55`,
URL above. Since the committed wrangler.jsonc keeps a placeholder ID per the distribution policy,
**when the owner redeploys, replace database_id with this real ID before
`bun run deploy`** (for client_id/secret see §3's remaining tasks).

**The Deploy to Cloudflare button is unverified**: the button assumes a public Git repository
(repo publication = Phase 2). At publication time, verify the monorepo subdirectory specification and D1's
auto-provisioning (rewriting database_id) (noted in ROADMAP Phase 2).

## 2. The self-host first-time setup wizard (design decision and implementation)

The ROADMAP design question of "a CLI command or a document":

- **The source of truth for the setup procedure is `docs/SELF_HOSTING.md` (a verified runbook)**. Reasons:
  (i) every setup step (d1 create / migrations / secret put / deploy) is a
  wrangler operation needing CF credentials, and the maruhi CLI should not hold CF
  credentials (the CLI is a secrets client, not an IaC tool),
  (ii) ADR-0014 ruling 5 — "self-hosting is an advanced-users path" — a copy-pasteable
  verified runbook is minimal and sufficient, (iii) the two-stage structure of deploy → OAuth App creation (the callback
  URL needs the deploy URL) → redeploy does not go away even as an interactive wizard
- **A server-side runtime registration API ("a web registration form on first access") is
  rejected**: an unauthenticated first-registration surface becomes a path where "whoever arrives first right after deploy
  registers their own OAuth App and hijacks the instance". Preventing that requires distributing a separate bootstrap
  secret — more complex and weaker than the current form of pinning via vars/secret at deploy time. Codified in AUTH_SPEC §3 (spec first; merge = owner approval)
- Following that decision, the line in AUTH_SPEC §3 "a first-access setup wizard
  (included in the CLI / server)" was revised to the actual form (a runbook + the mechanism below)

The implemented mechanism (the two pieces backing the document):

1. **The public config endpoint `GET /auth/config` (AUTH_SPEC §4)**: returns
   `{ githubClientId }` unauthenticated. **This implements session 11's owner ruling B ("a
   public config endpoint in the next independent PR")**; per the ruling's design points, the response carries only
   client_id, and config's `githubClientId` remains as an override path (for GHES and tests).
   CLI login resolution order: `--github-client-id` → config → `/auth/config`.
   With this, a self-hoster's CLI setup needs just the single item `maruhi config set server <url>`
2. **Unconfigured detection**: if client_id is still the placeholder
   (`replace-with-your-github-oauth-app-client-id`) or empty,
   `/auth/config` and `/auth/github/start` return 503 `SetupIncomplete`
   (reason: `github-oauth-unconfigured`). Redirecting to GitHub while unconfigured would land on GitHub's
   error page with no traceable cause, so it fails closed and guides to the doc. The placeholder
   string is kept in sync between wrangler.jsonc and handlers-auth.ts (noted in comments on both).
   The 503 behavior was also verified live on the deployed verification environment
   (client_id unset)

Key points of `docs/SELF_HOSTING.md`: every step is a command actually run this time (verified).
In the GitHub OAuth App creation, **checking "Enable Device Flow" is mandatory** (CLI login uses the
device flow; a missed check is the most frequent stumbling point and is also listed in troubleshooting).
client_secret rotation, custom domains (following the callback URL), and the update procedure are also covered.

## 3. Tests and quality

- server (vitest-pool-workers) +4: `/auth/config` 200 (unauthenticated) / placeholder 503
  (env is swapped directly into `worker.fetch` — SELF has fixed bindings) /
  empty string 503 / `githubStart`'s fail-closed 503. The test `GITHUB_CLIENT_ID` is
  overridden to a "configured dummy" in vitest.config's bindings (previously the placeholder
  flowed in verbatim)
- cli (Vitest) +4: auto-resolution makes login succeed (/auth/config is called once) /
  a config value present → no server query (ruling (iii)'s override precedence) /
  503 → setup-guide guidance + exit 1 / auto-fetch failure (equivalent to an old server's 404)
  is guided to the `config set githubClientId` escape hatch
- `bun run check` green (920 tests)

## 4. Self-review and fixes (2nd commit)

1. **The unconfigured check passed `undefined` through (a defense gap)**: on the Env type
   `GITHUB_CLIENT_ID` is a string, but a deploy where the self-hoster removed the var can make it
   undefined at runtime. Passed through, `/auth/config` becomes a Schema-encode defect (500) and
   `/auth/github/start` flies to GitHub with a `client_id=undefined` URL.
   `ensureGitHubOAuthConfigured` now accepts `string | undefined` and fails to 503;
   a regression test for a missing var was added
2. **Config verification under the pinned wrangler (4.118)**: the real deploy was done with bunx's
   4.120, so `bun run deploy:dry-run` (= 4.118) was used to confirm the new wrangler.jsonc
   (including `migrations_pattern` / `preview_urls`) parses and bundles, closing
   the gap against the version self-hosters will use
3. nit: the section reference in a handlers-auth.ts comment (nonexistent §3-3 → §3)

Folded in from the pullfrog review on PR #39 (1 IMPORTANT + 2 nits) (3rd commit):

4. **A missing client_secret registration is also a fail-closed target (IMPORTANT)**: the guard
   looked only at client_id, so a server that replaced client_id but forgot `wrangler secret put`
   would pass detection and fall into an opaque token-exchange failure (GitHub 401 → AuthFlow 400),
   while SELF_HOSTING step 7's `/auth/config` 200 gave false reassurance.
   The guard was widened to accept both client_id + client_secret and also
   applied to `deviceExchange` (SetupIncomplete added to api-schema's error list). AUTH_SPEC §3's
   self-diagnosis condition now mentions secret, and SELF_HOSTING's verification step was updated to
   the semantics "200 = both registered" (`wrangler secret list` also added to troubleshooting).
   A regression test for a missing secret was added (503 on /auth/config and deviceExchange)
5. nit: fixed api.ts's docstring "deviceExchange is the only unauthenticated call" to match the
   post-authConfig reality
6. nit: added to SELF_HOSTING's update section a caution about the collision between local edits of
   wrangler.jsonc (database_id / client_id) and `git pull` (committing to a fork recommended)

## 5. Out of scope (handoffs)

- **Human tasks when dogfooding starts**: creating the GitHub OAuth App (SELF_HOSTING.md
  steps 5–7) and registering client_id/secret on the verification deploy. On the CLI side, only the
  database_id swap noted in §1
- Deploy to Cloudflare button verification goes to Phase 2 (at publication) (§1)
- Audit events (the D1 side of auth.*) still come together with the D1 audit foundation (session-18 §3)
- Of session-11 §5's ruled follow-up PRs, 1 (the public config endpoint) is done in this session.
  **Only 3 remains (the pull metadata-only mode)** (2 was completed in session 17-1)
- The chain-append commands and the crypto test/checks organization candidate (session-17 §4) remain valid and untouched
