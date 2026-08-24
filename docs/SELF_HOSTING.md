# maruhi self-hosting guide

How to run the maruhi server on your own Cloudflare account. The path is
plain wrangler only (the self-hosting path in ADR-0012; Alchemy is not required).
It takes about 10 minutes; the only maruhi-specific work is creating a GitHub
OAuth App.

This guide is the source of truth for first-time setup (AUTH_SPEC §3. ADR-0014:
self-hosting is an advanced path, and the verified copy-pasteable runbook is the
minimal form). The steps were verified with a real deploy on 2026-08-10
(session 19) against wrangler 4.120.
The 2026-08-11 revision (folding migrations into step 3, and making client_id a
Workers Secret — AUTH_SPEC §3-2) is waiting on re-verification against a real
deploy.

## What comes up

- **Workers**: `maruhi-server` (the API server. Effect HttpApi)
- **Durable Objects**: `ProjectChainDO` (per-project membership chain,
  encrypted data, and audit log. SQLite-backed — available on the Workers free
  plan)
- **D1**: `maruhi` (auth metadata: users, sessions, tokens, and so on)
- **cron**: daily cleanup of expired session rows

Plaintext secrets are stored nowhere (E2EE — the server keeps ciphertext only).

## Prerequisites

- A Cloudflare account (the free plan is enough)
- A GitHub account (authentication is GitHub OAuth only — AUTH_SPEC)
- Bun 1.4.0 (pinned in the repository `engines`. wrangler is a dependency)

## Steps

### 1. Clone the repository and authenticate to Cloudflare

```sh
git clone <this-repository> && cd maruhi
bun install
cd apps/server
bunx wrangler login   # authorize in the browser (in CI: CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID)
```

If you do not want wrangler to send telemetry, set `WRANGLER_SEND_METRICS=false`
in the environment (maruhi itself implements no telemetry — [CLAUDE.md](../CLAUDE.md) "say nothing"; Japanese).

### 2. Create the D1 database

```sh
bunx wrangler d1 create maruhi
```

Write the printed `database_id` (UUID) into `wrangler.jsonc` at
`d1_databases[0].database_id` (placeholder `00000000-…`).

### 3. First deploy (apply migrations + pin the URL)

```sh
bun run deploy   # = bun run db:migrate && wrangler deploy
```

The deploy script always applies D1 migrations first (it refers to the binding
name `DB`, so it still works if you rename the database) and then deploys.
drizzle's folder layout (`drizzle/<name>/migration.sql`) is picked up by wrangler
as-is via `migrations_pattern` in `wrangler.jsonc`.

Note the printed `https://maruhi-server.<your-subdomain>.workers.dev`
(below, `<deploy-url>` means this entire URL, including `https://`).
The GitHub OAuth callback URL is derived from this deploy URL, so **deploy before
you create the OAuth App** (OAuth is not configured yet at this point, so auth
endpoints return 503 `SetupIncomplete` — that is expected).

### 4. Create a GitHub OAuth App

Create one at https://github.com/settings/applications/new:

| Field | Value |
|---|---|
| Application name | Anything (example: `maruhi (self-hosted)`) |
| Homepage URL | The deploy URL from step 3 |
| Authorization callback URL | `<deploy-url>/auth/github/callback` |
| **Enable Device Flow** | **Must be checked** (CLI login is device flow — leaving this off is the most common stuck point) |

After creating it, copy the client_id and issue a client_secret with
"Generate a new client secret".

### 5. Register client_id / client_secret

Register both as Workers Secrets (**do not write them into the repository or
config files**. client_id is public information, but routing registration through
secrets means you never have to edit `wrangler.jsonc` and redeploy —
AUTH_SPEC §3-2):

```sh
bunx wrangler secret put GITHUB_CLIENT_ID       # paste at the prompt
bunx wrangler secret put GITHUB_CLIENT_SECRET   # same
```

`secret put` takes effect immediately (no redeploy).

### 6. Smoke-check

```sh
curl <deploy-url>/auth/config
# → {"githubClientId":"<your-client-id>"} means setup is complete
#   (200 means both client_id and client_secret are registered)
# → 503 {"_tag":"SetupIncomplete",...} means a secret put from step 5 was skipped
#   (list registered secrets with `bunx wrangler secret list` — values are not shown)
```

### 7. Connect from the CLI

```sh
maruhi config set server <deploy-url>
maruhi login          # client_id is resolved from the server (GET /auth/config)
maruhi key generate   # first time only: generate the master key + issue a recovery code (on a human's machine)
```

From there: `maruhi project init` → `maruhi env create` → `maruhi push` / `maruhi run`.

## Server key setup (optional — required for `maruhi server grant`)

Needed only if you use server-side key wrap (CRYPTO_SPEC §9 — the owner of a
project explicitly runs `maruhi server grant` to disclose that environment's DEK
to the server). Skip this entire section if you do not (everything else still
works with the secret unset, and the server remains a ciphertext store).

### Register the key material (IKM)

Generate 32 bytes of randomness as hex (64 characters) and register it as a
Workers Secret:

```sh
openssl rand -hex 32 | bunx wrangler secret put SERVER_ENC_KEY_IKM
```

The server derives an X25519 keypair from this IKM deterministically (RFC 9180
DeriveKeyPair). The IKM is private-key material, so **do not keep a local copy**
(pipe it straight into registration; do not leave it in shell history or a file).

### Record the fingerprint (the comparison baseline)

After registration, read the server-key fingerprint (FP) and store it somewhere
safe:

```sh
curl <deploy-url>/auth/config
# → {"githubClientId":"...","serverKeyFingerprintHex":"<32-char hex>","serverEncPubHex":"<64-char hex>"}
```

Before disclosing anything, `maruhi server grant` shows the FP of the key the
server distributes as a 12-word phrase and asks the owner to confirm it
(CRYPTO_SPEC §9 confirmation ritual). That comparison baseline is this recorded
value (non-interactive runs pass `--expect-fingerprint <32-char hex>`).
The point of this step is to record it right after deploy, while the path is
still trustworthy.

> **Caution**: do not take a fresh value from `/auth/config` at grant time and
> pass it straight to `--expect-fingerprint`. That turns the check into
> "the server's claim versus the server's claim" (self-referential) and the
> ritual becomes meaningless.
> Fetching it right after deploy is intended as a trust-on-first-use anchor,
> which is a different act from re-fetching it at grant time. The only value you
> may pass is one you recorded out of band.

### Changing the IKM = changing the server key

Putting a new `SERVER_ENC_KEY_IKM` changes the server key itself (wraps addressed
to the old key will not open under the new one, and the FP changes too). If you
change it while any project already has a grant, re-run `maruhi server revoke` →
`maruhi server grant` on each of those projects (revoke forces a rotation of
every environment — CRYPTO_SPEC §7).

## Recommended hardening (optional): rate-limit unauthenticated endpoints

Of maruhi's unauthenticated surface, the following three are the ones where a
third party can trigger work that costs money (the other unauthenticated surfaces
`/auth/config` / `/auth/github/start` are self-contained lightweight responses).
All three already have server-side defenses (input size caps, format pre-checks,
a fixed window per project, and a TTL cache for JWKS).

**Since 2026-08-24 the default `wrangler.jsonc` also ships per-source-IP Workers
Rate Limiting bindings** for all three paths in the table below — the same limits
it recommends — so a default deploy now enforces them by itself (Cloudflare's
docs list no plan requirement for the binding at the time of writing; if your
deploy rejects the `ratelimits` section, remove it — the server falls back to the
old no-limit behavior). These bindings are per-colo and memory-backed (best
effort): a distributed flood spread across colos can still exceed the nominal
number, so the WAF rules below remain the stronger, globally-counted option.
Deployments that predate the `ratelimits` section keep the old behavior until
they redeploy with the updated config — the server treats a missing binding as
"no limit".

`/auth/github/callback` gained its binding later than the other two (it was
initially left to the WAF alone as a browser navigation path). It is not
redundant: the callback consumes the *same* per-OAuth-App quota as device
exchange, and its `state` check is a cookie-vs-query comparison with no
server-side state, so a non-browser caller supplies both halves itself and always
passes it.

If legitimate traffic arrives through shared egress IPs — a large CI matrix on
shared runners funneling many lease calls through one address, or a whole team
logging in behind one office NAT — the per-IP defaults can throttle it (429).
The per-colo counting already makes the effective ceiling looser than the
nominal number, but if you still hit it, raise the `limit` values in
`wrangler.jsonc` (or remove the binding entries) to match your traffic shape;
the server fails open when a binding is absent.

Add the following in the dashboard under Security → WAF → Rate limiting rules.
**The Free plan allows only one rule, so in that case pick
`/auth/device/exchange`** (it is the only surface in the table where exhausting
the quota stops login for the **entire deployment**, not merely degrades one
caller):

| Path | Recommended limit | Why |
|---|---|---|
| `/auth/device/exchange` | 10 requests / min / IP | Each request makes an outbound call to GitHub's check-token API, and that quota is per OAuth App. A flood of well-formed tokens can exhaust the quota and fail legitimate user logins (device exchange) (malformed tokens already get an immediate 400 from the server) |
| `/auth/github/callback` | 30 requests / min / IP | Each request can trigger one GitHub code exchange (the legitimate flow is at most 3 calls including `/user` and `/user/emails` after success), and the server cannot validate the code contents so format checks cannot block it. **This is the browser interactive login path, so loosen it relative to device/exchange to allow shared egress such as office NAT** |
| `/projects/*/environments/*/lease` | 60 requests / min / IP | The server-side window (300 calls / hour) is per project and does not care who is calling. A modest per-IP cap that does not interfere with normal CI retries absorbs a single source running wild or being abusive (the external call here — fetching the issuer's JWKS — is already TTL-cached with a cooldown, and does not happen on every request) |

CLI / CI paths (device/exchange and lease) have spread-out source IPs and easy
retries, so per-IP limits almost never get in the way of normal operation.
callback is the exception: concurrent logins behind shared egress can bunch up,
so do not go below the recommended value above.

## Updates (version upgrades)

```sh
git pull
bun install
cd apps/server
bun run deploy   # apply migrations → deploy (always this order, automatic)
```

Commit the local edit to `wrangler.jsonc` from step 2 (`database_id`) to your
own fork (if upstream changes this file, `git pull` will collide with an
uncommitted edit. If you do not commit it, re-apply the edit after pull).
client_id / client_secret live in Workers Secrets, so updates do not touch them.

**Config-carrying updates**: some fixes ship as `wrangler.jsonc` changes, not
just code — the 2026-08-24 per-IP rate limits are one (the server treats a
missing `ratelimits` binding as "no limit" and logs a one-time warning). Such
fixes take effect only after you redeploy with the updated `wrangler.jsonc`,
so pull the config file too, not just the code.

**One-time migration when crossing the environment-manifest release (2026-08-18,
PR-M1)**: environments created before this release have no environment manifest
yet, and the update order matters. Do it in this order:

1. **Update the server first** (`git pull` + `bun run deploy` as above).
2. Initialize every existing environment once, from an **updated** CLI on a
   project member's machine: `maruhi env rotate --init-manifest` (once per
   environment; environments created after the update need nothing).
3. Update the CLIs and CI workflows everywhere else.

The server must go first: `--init-manifest` sends the manifest as a new request
field, and a pre-manifest server does not store it (an updated CLI against an
old server cannot complete the migration — in the worst case the CLI records a
manifest the server never saved). Note this order will change in an upcoming
release that bundles a boundary checkpoint entry into creation/rotation: from
that release on, CLIs/CI must be updated **before** the migration rotate. This
section will be revised then.

**Failure direction after the strict-acceptance release (2026-08-19)**: the
server now rejects unknown fields in security-critical write requests
(chain appends, environment creation/rotation, value pushes and metadata
operations, DEK wrap registration, recovery blob registration, lease claims,
invitations) with an HTTP 400 schema error instead of silently dropping them.
This fixes the failure direction of future version skew: when a newer CLI sends
a field an older (strict-aware) server does not know, the request fails closed
with 400 (the CLI reports an HTTP 400 and suggests checking that the CLI and
server versions match) rather than being accepted with the new field silently
discarded. If you see such a 400 right after upgrading a CLI, update the server
first, then retry.

**One-time migration when crossing the 2026-08-11 revision**: the old steps put
client_id in `wrangler.jsonc` as `vars.GITHUB_CLIENT_ID`. Instances stood up
with those old steps must register client_id as a Workers Secret with
`bunx wrangler secret put GITHUB_CLIENT_ID` **before** updating to code from
this revision and deploying (the new `wrangler.jsonc` has no vars, so deploying
without the secret makes auth endpoints return 503 `SetupIncomplete`. A secret
put still recovers immediately — no redeploy). When resolving a `git pull` merge
conflict, **delete** your fork's `vars.GITHUB_CLIENT_ID` block rather than
keeping it (take upstream) — if vars remain, every deploy overwrites the
already-registered secret of the same name with the vars value and the migration
is undone (interactive deploys ask for confirmation, but non-interactive deploys
**continue after a warning only** — they do not error unless `--strict` is set,
so do not miss the warning).

## Troubleshooting

- **`/auth/config` / `/auth/github/start` / `/auth/device/exchange` return 503
  `SetupIncomplete`**: either `GITHUB_CLIENT_ID` or `GITHUB_CLIENT_SECRET` is
  unregistered (a missed `wrangler secret put` — step 5. If this happened after
  updating an instance stood up with the old steps, see the migration in
  "Updates"). List registered secrets with `bunx wrangler secret list` (values
  are not shown)
- **CLI login, GitHub returns `device_flow_disabled`**: "Enable Device Flow" is
  unchecked on the OAuth App (step 4)
- **Browser login lands on a GitHub error page**: callback URL mismatch.
  Confirm the OAuth App Authorization callback URL is exactly
  `<deploy-url>/auth/github/callback` (full match on http/https, trailing slash,
  and subdomain)
- **`bun run deploy` migration apply returns `couldn't find DB`**:
  `database_id` was not filled in (step 2)
- **`/auth/config` has no `serverKeyFingerprintHex` /
  `maruhi server grant` says "The server has no deployment keypair configured"**:
  `SERVER_ENC_KEY_IKM` is unregistered, or the value is not 64 hex characters
  (a malformed value is treated as unset — this is not a 503).
  Pipe the output of `openssl rand -hex 32` straight into `wrangler secret put`
  (watch for stray newlines or quotes)

## Notes

- **Rotating client_secret**: issue a new secret on the GitHub side →
  `wrangler secret put GITHUB_CLIENT_SECRET` (put takes effect immediately; no
  redeploy) → delete the old secret on the GitHub side
- **Custom domain**: you may add `routes` to `wrangler.jsonc`. The OAuth callback
  is derived from the request origin, so **update the GitHub OAuth App callback
  URL to the same domain**
- **Deploy to Cloudflare button**: planned for the README after the repository
  goes public (Phase 2). Prerequisite work for the button (folding migrations
  into deploy, referring to the binding name, and putting client_id in a secret
  so post-deploy setup is just secret put ×2) is done.
  Three points remain unverified and can only be verified against a public
  repository, so they will be checked at public release:
  (1) whether the button's monorepo support detects `apps/server/wrangler.jsonc`
  from the repository-root URL and auto-provisions D1. (2) whether the button's
  build pipeline runs the `apps/server` `deploy` script (including migrations) —
  if it falls back to a plain `wrangler deploy`, the app is published with
  migrations unapplied and every endpoint that touches the DB returns 500.
  The setup page will likely need the deploy command overridden. (3) whether the
  button's provisioning replaces the committed placeholder
  `database_id` (`00000000-…`) with the real ID —
  Cloudflare's docs recommend documenting a default and "update the config with
  the ID of the newly created resource", but wrangler's own auto-provisioning
  uses a filled-in database_id as-is, so if the button does not replace it the
  deploy fails with an API error against a UUID that does not exist (in that
  case the placeholder has to be removed)
- For the API spec including non-auth endpoints see `docs/AUTH_SPEC.md` (Japanese); for the
  crypto spec see `docs/CRYPTO_SPEC.md` (Japanese)
