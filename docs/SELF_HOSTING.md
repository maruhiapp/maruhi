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
bun run deploy   # = bun run db:migrate && (web dashboard build) && wrangler deploy
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
| Enable Device Flow | **Leave unchecked** (recommended). maruhi does not use it: CLI login goes through the same browser OAuth flow as web login (AUTH_SPEC §4), so enabling it only widens the OAuth App's surface |

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
# → {"githubClientId":"<your-client-id>","signupPolicy":"open"} means setup is complete
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

## Sign-up policy (optional — who may create accounts)

**The default is `open` and matches the behavior maruhi has always had: anyone
who can reach your deployment URL and complete GitHub login gets an account.
If that is what you want (typical for a personal or small-team deployment),
skip this entire section — there is nothing to configure.**

The server reads a deployment-wide `signupPolicy` (AUTH_SPEC §3) with three
values:

| Value | Meaning |
|---|---|
| `open` (default) | Anyone can sign up. No settings row needed |
| `invite` | New accounts require a sign-up invite code (below). Existing accounts are unaffected |
| `closed` | No new accounts at all. Existing accounts are unaffected |

The gate only blocks **account creation**: sign-in for existing users, token
verification, project invites, and recovery are never affected. A denied sign-up
creates no rows and is recorded as an `auth.signup_denied` audit event (visible
in D1 — the operator's view).

### Changing the policy

The policy lives in the `deployment_settings` D1 table. There is deliberately no
admin UI or settings endpoint — change it with wrangler (takes effect
immediately, no redeploy):

```sh
cd apps/server
bunx wrangler d1 execute maruhi --remote --command \
  "INSERT INTO deployment_settings (key, value, updated_at) VALUES ('signup_policy', 'invite', unixepoch() * 1000) \
   ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;"
```

Verify with `curl <deploy-url>/auth/config` — the response reports the effective
`signupPolicy`. **A mistyped value is treated as `closed` (fail-closed)**: a typo
never silently opens sign-ups, but it does deny new accounts until you fix it,
so always check `/auth/config` after changing the value.

### Issuing sign-up invite codes (`invite` mode)

Codes are single-use, expire after 7 days by default, and only permit account
creation (they carry no project, org, or role). Only the SHA-256 hash is stored;
the raw code is shown once at issuance. Issue one with the bundled script:

```sh
cd apps/server
bun run scripts/issue-signup-invite.ts --origin <deploy-url> [--days 7]
```

The script prints the code, the sign-up link to send to the invitee
(`<deploy-url>/auth/github/start?signup_code=…` — the link carries the code),
and the `wrangler d1 execute` command that registers the hash. Send the code or
link over a private channel. The invitee signs up in the browser first, then
runs `maruhi login`.

Notes:

- A code is consumed in the same transaction that creates the account — a failed
  sign-up never burns a code, and signing in as an **existing** user never
  consumes one.
- Under `open`, presented codes are ignored (not consumed).
- Inviting someone to a **project** (`maruhi invite create`) is separate: under
  `invite` they also need a sign-up invite code (sent separately) before they
  can accept.
- To revoke an unused code, delete its row (the issuance script prints the
  command).

## Tenant quotas (project count and per-project storage guard)

**The defaults are far above realistic use, and nothing needs configuring.
Read this section if you want to know what the server refuses and why, or if
you run a large multi-tenant deployment and want to change the values.**

The server enforces two deployment-wide acceptance limits on top of the
per-project limits in AUTH_SPEC §12-8 (environments, variables, versions, …).
Both are **server acceptance policy, not part of the cryptographic protocol**:
they are plain constants in `apps/server/src/policy.ts`, raising or lowering
them never invalidates existing chains, and a change takes effect on the next
deploy. Exceeding a limit always fails with a typed error — nothing degrades
silently.

| Limit | Default | Constant | Error |
|---|---|---|---|
| Active projects per organization | 100 | `MAX_ACTIVE_PROJECTS_PER_ORG` | 429 `ProjectLimit` on `POST /projects` |
| Per-project Durable Object storage | warn at 8 GB, reject at 9 GB | `DO_STORAGE_WARN_BYTES` / `DO_STORAGE_REJECT_BYTES` | 422 `DataLimitExceeded` with `resource: "project-storage-bytes"` |

### Projects per organization

- Counts every `projects` row of the organization (there is no project deletion
  API yet, so every project ever created is "active"). Today every user has
  exactly one personal organization, so in practice this is **100 projects per
  user**.
- Only a **new** project creation is refused. Re-running `maruhi project init`
  for a project that already exists (for example to repair a crash between the
  chain commit and the D1 row insert — AUTH_SPEC §11-3) always succeeds, even
  when the organization is at the limit.
- The check is best-effort: two `init` calls racing at exactly the limit can
  both succeed. This is an acceptance policy, not a security boundary.

### Per-project storage guard (why 9 GB)

Each project lives in one Durable Object whose SQLite database has a hard
platform ceiling of **10 GB**. At that ceiling SQLite returns `SQLITE_FULL`:
the project stays readable but **every write fails, including the deletes that
would free space**. The guard exists so a project never gets there. It reads the
measured database size (`databaseSize`) on every write that adds content and:

- at **8 GB** logs one static warning line per Durable Object instance (no
  project id, no user id — see "Operational logs" below) and keeps accepting
  writes;
- at **9 GB** rejects writes that add content — pushing values, creating,
  renaming or re-declaring variables, creating or renaming environments,
  registering DEK wraps, adding members, granting server access and changing
  the schema policy — with 422 `DataLimitExceeded` (`project-storage-bytes`).

What **keeps working** above 9 GB, by design (AUTH_SPEC §12-8 lists these
explicitly): all reads (`maruhi pull` / `maruhi run`, chain fetch, audit log —
members can always take their values out), all deletions (environments,
variables, DEK wraps — the way back under the threshold), member removal,
server-access revocation, role changes, epoch rotation, workload leases, head
attestations and periodic checkpoints. The 1 GB between the rejection threshold
and the platform floor absorbs the bookkeeping those operations still write.
One read is guarded as if it were a write: fetching the **audit head**
(`GET /projects/:id/audit-head`, and checkpoints that notarize it) lazily
materializes a hash column proportional to the audit log, so it is refused above
9 GB only while that column lags behind the log; once current, it reads freely.

The audit log is append-only and never pruned (AUDIT_SPEC §5.3), so on a busy
project the dominant growth is `var.read` rows from pulls. The guard is the
safety net for that growth; there is no per-tenant audit quota.

**Changing the thresholds**: edit the two constants and redeploy. Keep
`DO_STORAGE_REJECT_BYTES` below 10 GB — the guard is the only thing standing
between a project and the unrecoverable-by-tenant `SQLITE_FULL` state. The
values are decimal gigabytes (10^9 bytes), which is conservative under either
reading of the platform's "10 GB".

### Operational logs

The warning and rejection lines are **static messages**: they carry no project
id (a project id is effectively a capability — AUTH_SPEC §11-2) and no user
id. To find out which project is affected, use the Durable Object id in the
Workers Logs / `wrangler tail` event envelope: it is `idFromName(projectId)`,
so you can compute it for a project a tenant reports and compare, but the log
line itself never reveals the project. Alerting on these lines is part of the
hosted operations work (H3); the log line is the hook it will attach to.

## Recommended hardening (optional): rate-limit unauthenticated endpoints

Of maruhi's unauthenticated surface, the following four are the ones where a
third party can trigger work that costs money or drain a shared quota (the other
unauthenticated surfaces stay lightweight: `/auth/github/start` without a
`signup_code` and `/auth/cli/verify` are self-contained responses with no
database access; `/auth/config` performs one indexed D1 point read for the
`signupPolicy` advisory; a start request carrying a `signup_code` performs one
D1 read and has its own default per-IP binding, `SIGNUP_START_RATE_LIMIT` at
10/min).
All four already have server-side defenses (input size caps, stateless MAC
verification before any lookup, a fixed window per project, and a TTL cache for
JWKS).

**Since 2026-08-24 the default `wrangler.jsonc` also ships per-source-IP Workers
Rate Limiting bindings** for all paths in the table below — the same limits
it recommends — so a default deploy now enforces them by itself (Cloudflare's
docs list no plan requirement for the binding at the time of writing; if your
deploy rejects the `ratelimits` section, remove it — the server falls back to the
old no-limit behavior). These bindings are per-colo and memory-backed (best
effort): a distributed flood spread across colos can still exceed the nominal
number, so the WAF rules below remain the stronger, globally-counted option.
Deployments that predate the `ratelimits` section keep the old behavior until
they redeploy with the updated config — the server treats a missing binding as
"no limit".

`/auth/github/callback` gained its binding later than the others (it was
initially left to the WAF alone as a browser navigation path). It is not
redundant: each callback can trigger a GitHub code exchange against the
per-OAuth-App quota, and its `state` check is a cookie-vs-query comparison with
no server-side state, so a non-browser caller supplies both halves itself and
always passes it.

If legitimate traffic arrives through shared egress IPs — a large CI matrix on
shared runners funneling many lease calls through one address, or a whole team
logging in behind one office NAT — the per-IP defaults can throttle it (429).
The per-colo counting already makes the effective ceiling looser than the
nominal number, but if you still hit it, raise the `limit` values in
`wrangler.jsonc` (or remove the binding entries) to match your traffic shape;
the server fails open when a binding is absent.

Add the following in the dashboard under Security → WAF → Rate limiting rules.
**The Free plan allows only one rule, so in that case pick
`/auth/github/callback`** (it is the surface in the table where exhausting the
per-OAuth-App code-exchange quota stops login for the **entire deployment**, not
merely degrades one caller):

| Path | Recommended limit | Why |
|---|---|---|
| `/auth/cli/start` | 10 requests / min / IP | Unauthenticated and recordless (nothing is stored — AUTH_SPEC §4-1), so the cost is pure CPU: each request computes two HMACs. A per-IP cap keeps a flood from turning that into a Workers bill |
| `/auth/cli/poll` | 30 requests / min / IP | Unauthenticated; the legitimate CLI polls at a 5-second floor (12/min), so 30/min leaves room for several concurrent flows behind one address. Fabricated credentials are rejected by a stateless MAC check before any database lookup, and the limit is enforced before even that |
| `/auth/github/callback` | 30 requests / min / IP | Each request can trigger one GitHub code exchange (the legitimate flow is at most 3 calls including `/user` and `/user/emails` after success), and the server cannot validate the code contents so format checks cannot block it. **This is the browser login path — both web login and the CLI flow's browser leg — so loosen it relative to start to allow shared egress such as office NAT** |
| `/projects/*/environments/*/lease` | 60 requests / min / IP | The server-side window (300 calls / hour) is per project and does not care who is calling. A modest per-IP cap that does not interfere with normal CI retries absorbs a single source running wild or being abusive (the external call here — fetching the issuer's JWKS — is already TTL-cached with a cooldown, and does not happen on every request) |

CLI / CI paths (cli/start, cli/poll and lease) have spread-out source IPs and
easy retries, so per-IP limits almost never get in the way of normal operation.
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

**One-time migration when crossing the boundary-checkpoint release (2026-08-27;
also covers the 2026-08-18 environment-manifest release if you skipped it)**:
from this release on, environment creation and rotation bundle a `checkpoint`
chain entry that notarizes the environment's manifest and value state, and the
verification of distributed manifests is bound to these checkpoints. The update
order matters. Do it in this order:

1. **Update the server first** (`git pull` + `bun run deploy` as above). The
   updated server requires the bundled checkpoint, so environment creation and
   rotation from not-yet-updated CLIs fail closed with an HTTP 400 until step 2
   (reads, pushes and metadata operations keep working).
2. **Update the CLIs and CI workflows everywhere.** Not-yet-updated CLIs also
   fail closed when they *read* a chain that already contains a `checkpoint`
   entry (unknown operation) — another reason to complete this step promptly
   after step 1.
3. Rotate every existing environment once, from an updated CLI on a project
   member's machine: `maruhi env rotate` (use `--init-manifest` for
   environments that predate the 2026-08-18 manifest release; once per
   environment). This establishes each environment's first checkpoint —
   environments created after the update need nothing.

The server must go first: the checkpoint (and, for pre-manifest environments,
the manifest) is sent as a new request field, and an old server does not store
it — an updated CLI against an old server cannot complete the migration.
Between steps 1 and 3, verification of existing environments continues on the
pre-checkpoint rules (their chains carry no checkpoint yet); each environment
picks up checkpoint-bound verification at its first post-update rotation.

**Periodic checkpoints and the audit head (2026-08-28 release)**: this release
adds standalone (periodic) checkpoints — `maruhi project checkpoint`, plus an
automatic one after each completed rotation — and audit-head notarization
backed by `GET /projects/:id/audit-head`. Two version-skew notes:

- **Update the server before the CLIs** (same direction as always). A new CLI
  against an old server fails closed: the standalone checkpoint append is
  rejected by the old server (HTTP 422 `CompositeRequired`), and the audit-head
  fetch does not exist there — the explicit command reports the error, and the
  automatic post-rotation issuance reports it as a warning while the rotation
  itself still succeeds. Nothing is silently dropped.
- **The audit-head initialization migration is automatic.** The cumulative
  audit-head hash column (AUDIT_SPEC §5.1) is derived lazily: the first
  audit-head read or checkpoint acceptance after the update recomputes it from
  the project's existing audit rows. No operator action is needed; on projects
  with very large audit logs the first such request does a one-time full pass
  over the rows.

**Bounded audit-head materialization — `AuditHeadNotReady` (2026-08-28
release, after the periodic checkpoints above)**: the lazy materialization
above is now bounded per call (10,000 rows). When a project's backlog exceeds
that — in practice only the one-time first pass over a very large existing
audit log — the audit-head read and checkpoint acceptance respond with a
retryable HTTP 503 (`AuditHeadNotReady`) instead of holding the request until
the full pass completes. Progress is saved server-side, so every attempt
advances and retrying converges. Update-order impact:

- **Old CLI × new server**: an old CLI does not understand the new typed 503
  and reports it as a generic error. This can only happen on that first
  materialization of a very large log, and re-running the command resolves it
  (the server keeps advancing on every attempt). No data is at risk.
- **New CLI × old server**: unchanged behavior — the old server never sends
  `AuditHeadNotReady`, and the new CLI's retry handling simply never triggers.

**Checkpoint snapshot distribution (2026-08-28 release, after the periodic
checkpoints above)**: this release makes servers bundle the checkpoint-time
value snapshot into value-bearing reads (bulk pull and workload leases), and
makes clients verify it (value non-regression — CRYPTO_SPEC §6.3 rule 2).
**Update the server first — this is mandatory here, not just recommended.**
The client rule is fail-closed by design: a client at this release **rejects
every value-bearing pull and lease of an environment whose chain carries a
checkpoint when the response lacks the snapshot** (omission would let a
malicious server skip rollback detection, so the client cannot tell an old
server from an attacking one). Since every environment created after the
boundary-checkpoint release carries a checkpoint from birth, a new CLI or CI
workload against an old server fails closed on **all** such environments —
`maruhi pull`, `maruhi run` and `maruhi ci run` stop working until the server
is updated. The error message names the omission and suggests the server
update. The reverse direction is safe: an old client simply ignores the new
response field. No data migration is involved for checkpoints accepted at or
after the boundary-checkpoint release — every acceptance path has stored the
snapshot atomically with the chain append since then (and no earlier server
accepted checkpoints at all), so the server distributes rows it already has.
Should a server ever lack the stored row for an on-chain checkpoint anyway
(e.g., after restoring Durable Object storage from a backup that does not
match the distributed chain), a project member re-establishes a distributable
baseline by issuing a fresh checkpoint: `maruhi project checkpoint`.

**Head attestations / split-view gossip (2026-08-28 release, PR-M4)**: this
release adds signed head attestations (CRYPTO_SPEC §6.6): after every
successful chain sync, a CLI submits a signed "I verified the chain up to this
head" statement (`PUT /projects/:id/head-attestation`), and servers bundle the
current members' latest attestations into chain reads so members cross-check
each other's verified heads. This makes a server that shows different chains to
different members (a split view) detectable, with non-repudiable evidence.
Version-skew notes — **update the server before the CLIs** (same direction as
always), but note this feature degrades gracefully in both directions:

- **New CLI against an old server**: the attestation submission fails (the
  endpoint does not exist there) and the CLI prints a one-line note per
  command — the command itself still succeeds. Chain responses from an old
  server carry no `attestations` field; the CLI treats that as an empty set
  and does **not** reject (omission of gossip is a normative non-guarantee of
  CRYPTO_SPEC §6.3 — an omission-rejecting branch would break old-server
  interop without adding detection). Cross-checking becomes effective once the
  server is updated and members have submitted attestations.
- **Old CLI against a new server**: the extra response field is ignored and
  nothing changes.
- The Durable Object migration (two new tables for attestation rows and their
  per-member rate windows) is automatic on first access. No operator action.

**API token lifetimes (2026-08-30 release, W3a)**: this release gives API
tokens a default lifetime of 90 days (fixed at issuance; expired tokens are
rejected with 401 like revoked ones), adds token management endpoints
(`GET /auth/tokens`, `DELETE /auth/tokens/:tokenId`), and lets `maruhi login`
request a longer lifetime with `--token-ttl-days` (up to 365). Version-skew
notes — **update the server before the CLIs** (same direction as always), and
this feature degrades gracefully in both directions:

- **Existing tokens**: the bundled D1 migration re-anchors previously
  unlimited tokens to *apply time + 90 days*, so nothing stops working at the
  update itself — re-login (`maruhi login`) within 90 days rotates each token
  onto its own fresh lifetime. If you deploy the new code without applying the
  migration (the standard `bun run deploy` applies it automatically), the
  server treats legacy no-expiry tokens as already expired (fail-closed);
  re-login recovers.
- **New CLI against an old server**: `maruhi login` still works. The old
  server does not report an expiry, so the CLI prints a note instead of an
  expiry date, and `--token-ttl-days` has no effect there (the exchange
  request is deliberately tolerant of unknown fields, so the old server
  ignores it and issues an unlimited token).
- **Provisioning unattended runtimes (`MARUHI_TOKEN`)**: on runtimes without
  lease support (anything but GitHub Actions today), the CLI authenticates
  with the `MARUHI_TOKEN` env var, bound to the target server with
  `MARUHI_TOKEN_ORIGIN`. To obtain a value, run
  `maruhi login --token-name <name> --token-ttl-days <days> --show-token` on
  an interactive workstation terminal: the issued token is printed once (and
  stored in the OS keychain as usual). The display is refused on pipes, in
  CI, and in AI-agent environments (same fail-closed gate as value display),
  so provision from a human terminal and clear your scrollback afterwards.
  Then run a plain `maruhi login` once more: the keychain holds one token per
  server, so the provisioning login also made the new token this machine's
  active token — the extra login gives your workstation a token of its own
  (the provisioned one stays valid **because it has a distinct name**;
  re-login rotates only the default-name token), keeping audit attribution
  per environment and letting you revoke either one without cutting off the
  other. Do not skip the `--token-name` in the provisioning step: a token
  provisioned under the default name would be revoked by that same plain
  re-login (the CLI's on-screen note tells these two cases apart).
  Starting 14 days before a token expires, every CLI command warns on stderr
  with the expiry date and the re-issuance procedure (in CI this lands in the
  job log, so the operator sees it before the 401). When the token expires,
  CLI commands in that runtime fail with 401 and name the same procedure.
  Prefer `maruhi ci run` (leases) where available — leases are short-lived
  and need no stored token.
- **Old CLI against a new server**: the extra `expiresAtMs` response field is
  ignored; the issued token simply expires after 90 days, and the old CLI
  reports the eventual 401 as a revoked token — re-login recovers.
- **Adjusting the default**: the 90-day default is an acceptance-policy
  constant (`DEFAULT_TOKEN_TTL_DAYS` in `packages/api-schema`), not a
  consensus rule — self-hosted deployments may change it.

**Value-free schemas / statement layout v2 (2026-08-31 release, S2)**: this
release adds server-side acceptance for variable-statement layout v2 —
schema fields (type / required / description) and the `declared` state
(declared-but-no-value variables), gated by a per-project `schemaPolicy`
setting (`GET`/`PUT /projects/:id/schema-policy`). **The gate defaults to
`disabled`, so updating the server changes nothing by itself**: v2 writes are
rejected until a project admin enables them, and v1 acceptance, distribution
and verification are unchanged. Enabling schemas for a project must follow
this order (AUTH_SPEC §12-11):

1. **Update the server first** (`git pull` + `bun run deploy` as above). The
   Durable Object migration (layout columns + the settings table) is
   automatic on first access; no operator action.
2. **Update the CLIs and CI workflows everywhere** — every member of the
   project, not just the one who wants schemas. A not-yet-updated CLI cannot
   read v2 statements: it rejects `declared` statements at decode time
   (unknown status — an explicit error) and rejects schema-carrying active
   statements at signature verification (a warning indistinguishable from
   tampering). The `disabled` default exists precisely so that one upgraded
   member's write cannot break the other members' verification.
3. **Enable per project**: `PUT /projects/:id/schema-policy` with
   `{"schemaPolicy": "enabled"}` (or `"locked"` to additionally require a
   declared type on every new variable), as a project admin with an
   admin-scoped token. The change is auditable
   (`project.schema_policy_changed`).

Reverting is safe: setting the policy back to `disabled` stops **new** v2
adoption only — statements already written in v2 stay stored, distributed and
verifiable, and variables that are already v2 keep their full lifecycle
(rename, schema re-issue, deletion, and activation of declared variables).

**CLI side of the same series (S3)**: the updated CLI is the "step 2" client —
it verifies and displays layout-v2 statements (`maruhi schema`), writes schema
fields and value-free declarations (`maruhi schema set`), activates a declared
variable on its first `maruhi push`, and makes `maruhi run` / `maruhi ci run`
fail fast (before starting the child process) when a variable declared as
required has no value yet. None of this changes behavior for projects whose
`schemaPolicy` is `disabled` or for servers that predate the S2 release:
enabling schemas remains the explicit per-project step 3 above.

**Deleting a variable (S4)**: `maruhi var rm <NAME>` deletes a variable —
declared (no value) or active (every stored value version is deleted
immediately). Deletion is terminal: a deleted variable cannot be restored,
and its variable ID is never reused (the *name* can be reused by a new
variable). The command asks you to re-type the variable name as an explicit
confirmation; in a non-interactive environment (scripts, CI) it refuses
unless `--force` is passed. A mistaken *required* declaration does not need
deletion to unbreak `maruhi run`: `maruhi schema set <NAME> --optional`
downgrades the contract and `run` proceeds (declarations default to required,
so a typo in a variable name fails `run` loudly rather than silently — that
is the intended failure direction).

**Bootstrapping a schema from a .env file (S4)**: `maruhi schema import
<file>` reads a `.env` / `.env.example` file locally, proposes one schema
candidate per variable (name, inferred type, required, a description from the
preceding comment) and asks for per-variable approval — values are observed
for type inference only and are **never sent** unless you explicitly choose
to push one (which end-to-end encrypts it, like any `maruhi push`). The
per-variable approval is the point of the ceremony, so there is no `--yes`
and the command refuses non-interactive environments and AI agents. On
completion it offers (and never defaults to) deleting the source file.

**Schema snapshot and code cross-check (S5)**: three read-only companions
close out the schema series. All three read only metadata (no values, no
DEKs, no `var.read` audit rows), need no master key, and work with a
`MARUHI_TOKEN` session — so they run in CI and in AI-agent environments.

- `maruhi schema export` prints the environment's schema as a JSON Schema
  subset to stdout. Commit it to your repository
  (`maruhi schema export > maruhi-schema.json`) so editors, agents and docs
  tooling can consume the contract without maruhi access. **The snapshot is a
  generated artifact, not an authority**: it is neither signed nor accepted
  by the server, the store stays the source of truth, and the file says so in
  its `$comment`. Anything with maruhi access should read `maruhi schema`
  instead of the file. One snapshot covers one environment; export each
  environment you want committed.
- `maruhi schema verify-snapshot <file>` regenerates the snapshot from the
  store and fails (exit 1) on any divergence — run it in CI to keep the
  committed file honest. A hand-edited or stale snapshot survives at most
  until the next CI run (the same exposure class as any other file in your
  repository). The divergence report names variables and fields only; it
  never prints description contents.
- `maruhi schema lint <path>...` scans source files for literal
  environment-variable references (`process.env.X`, `os.environ["X"]`,
  `os.Getenv("X")`, `ENV["X"]`, `env::var("X")` and similar) and cross-checks
  them against the declared schema. Code reading a name the store does not
  declare fails the run (exit 1) — declare it with `maruhi schema set`, or
  exclude runtime variables maruhi does not manage with `--ignore NODE_ENV`
  (repeatable). Declared names the scanned code never reads are reported but
  do not fail the run (they may be read dynamically or by another
  repository). The scan is best-effort by design: dynamic access and
  unsupported languages are not seen, so an empty report is not a guarantee.

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

- **`/auth/config` / `/auth/github/start` / `/auth/cli/start` return 503
  `SetupIncomplete`**: either `GITHUB_CLIENT_ID` or `GITHUB_CLIENT_SECRET` is
  unregistered (a missed `wrangler secret put` — step 5. If this happened after
  updating an instance stood up with the old steps, see the migration in
  "Updates"). List registered secrets with `bunx wrangler secret list` (values
  are not shown)
- **CLI login's verification link shows "This sign-in link can't be used"**:
  the link expired (flows last 15 minutes), was already used, or was edited in
  transit. Run `maruhi login` again for a fresh link
- **Browser login lands on a GitHub error page**: callback URL mismatch.
  Confirm the OAuth App Authorization callback URL is exactly
  `<deploy-url>/auth/github/callback` (full match on http/https, trailing slash,
  and subdomain)
- **`bun run deploy` migration apply returns `couldn't find DB`**:
  `database_id` was not filled in (step 2)
- **`maruhi project init` says the organization already holds the maximum
  number of projects (429 `ProjectLimit`)**: the per-organization project
  limit (default 100 — "Tenant quotas"). Existing projects are unaffected;
  raise `MAX_ACTIVE_PROJECTS_PER_ORG` in `apps/server/src/policy.ts` and
  redeploy if the deployment legitimately needs more
- **Pushes / creates fail with `DataLimitExceeded` and
  `resource: "project-storage-bytes"` while pulls still work**: the project's
  Durable Object storage crossed the 9 GB guard ("Tenant quotas"). This is
  working as intended — have the project admins delete environments,
  variables or DEK wraps they no longer need (deletes are accepted above the
  threshold), then retry
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
