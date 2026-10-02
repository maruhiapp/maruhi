# maruhi self-hosting guide

How to run the maruhi server on your own Cloudflare account. The path is
the plain `cf` CLI only (the self-hosting path in ADR-0012; Alchemy is not
required).
It takes about 10 minutes; the only maruhi-specific work is creating a GitHub
OAuth App.

This guide is the source of truth for first-time setup (AUTH_SPEC §3. ADR-0014:
self-hosting is an advanced path, and the verified copy-pasteable runbook is the
minimal form). The steps were verified with a real deploy on 2026-08-10
(session 19) against wrangler 4.120; the commands were re-expressed against cf
1.0.0-beta (2026-09-30) without a fresh real deploy — see the PR for the
verification level of each command.
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
- Bun 1.4.2 (pinned in the repository `engines`. `cf` is a dependency)

## Steps

### 1. Clone the repository and authenticate to Cloudflare

```sh
git clone <this-repository> && cd maruhi
bun install
cd apps/server
bunx cf auth login   # authorize in the browser (in CI: CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID)
```

If you do not want cf to send telemetry, set `CF_SEND_TELEMETRY=false`
in the environment (maruhi itself implements no telemetry — [CLAUDE.md](../CLAUDE.md) "say nothing"; Japanese).

### 2. Create the D1 database

```sh
bunx cf d1 create --name maruhi
```

Write the printed database UUID into `cloudflare.config.ts` at the `DB`
binding's `id` (placeholder `00000000-0000-4000-8000-…`).

### 3. First deploy (apply migrations + pin the URL)

```sh
bun run deploy   # = bun run db:migrate && (web dashboard build) && cf deploy
```

The deploy script always applies D1 migrations first (it resolves the database
ID from `cloudflare.config.ts`, so it still works if you rename the database)
and then deploys. drizzle's folder layout (`drizzle/<name>/migration.sql`) is
passed to `cf d1 migrations apply` via its `--dir` / `--pattern` flags.

Note the printed `https://maruhi-server.<your-subdomain>.workers.dev`
(below, `<deploy-url>` means this entire URL, including `https://`).
The GitHub OAuth callback URL is derived from this deploy URL, so **deploy before
you create the OAuth App** (OAuth is not configured yet at this point, so auth
endpoints return 503 `SetupIncomplete` — that is expected).

Optional: the dashboard's social-preview image tag (`og:image`) needs an absolute
URL, which is baked in at build time and defaults to the hosted service. To point
it at your own deployment, set `MARUHI_WEB_ORIGIN=<deploy-url>` in the environment
when you run `bun run deploy` (it only affects link previews; nothing else reads it).

### 4. Create a GitHub OAuth App

Create one at https://github.com/settings/applications/new:

| Field | Value |
|---|---|
| Application name | Anything (example: `maruhi (self-hosted)`) |
| Homepage URL | The deploy URL from step 3 |
| Redirect URI (older forms call it "Authorization callback URL") | `<deploy-url>/auth/github/callback` — register **exactly one** and leave "Allow wildcard matching" unchecked (the callback origin is fixed per deployment) |
| Enable Device Flow | **Leave unchecked** (recommended). maruhi does not use it: CLI login goes through the same browser OAuth flow as web login (AUTH_SPEC §4), so enabling it only widens the OAuth App's surface |
| Expire user access tokens (newer forms) | Either setting works. maruhi uses the GitHub access token once, immediately, to read your identity and then discards it — it never stores the token or reads `refresh_token` — so leaving expiry **on** is the safer default |

After creating it, copy the client_id and issue a client_secret with
"Generate a new client secret".

### 5. Register client_id / client_secret

Register both as Workers Secrets (**do not write them into the repository or
config files**. client_id is public information, but routing registration through
secrets means you never have to edit `cloudflare.config.ts` and redeploy —
AUTH_SPEC §3-2):

```sh
bunx wrangler secret put GITHUB_CLIENT_ID
bunx wrangler secret put GITHUB_CLIENT_SECRET
```

(Secret registration stays on `wrangler secret put`, which reads the value on
stdin — cf's `workers secrets update` only accepts the value inline via
`--text`, which puts it on the process argv and in shell history. wrangler
remains an installed devDependency for this path until cf can take secrets
from stdin.) The update takes effect immediately (no redeploy).

### 6. Smoke-check

```sh
curl <deploy-url>/auth/config
# → {"githubClientId":"<your-client-id>","signupPolicy":"open"} means setup is complete
#   (200 means both client_id and client_secret are registered)
# → 503 {"_tag":"SetupIncomplete",...} means a secret put from step 5 was skipped
#   (list registered secrets with `bunx cf workers secrets list` — values are not shown)
```

### 7. Connect from the CLI

```sh
maruhi config set server <deploy-url>
maruhi login          # approve the request in your browser (the CLI shows a confirmation code)
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
admin UI or settings endpoint — change it with `cf` (takes effect
immediately, no redeploy):

```sh
cd apps/server
bunx cf d1 query $(bun scripts/d1-id.ts) --sql \
  "INSERT INTO deployment_settings (key, value, updated_at) VALUES ('signup_policy', 'invite', unixepoch() * 1000) \
   ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;"
```

(`cf d1` subcommands take the database ID, not its name — `bun scripts/d1-id.ts`
prints the ID configured in `cloudflare.config.ts`.)

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
and the `cf d1 query` command that registers the hash. Send the code or
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
the project stays readable, and while the platform still lets a bare `DELETE`
through, every maruhi deletion also **inserts** rows in the same transaction
(the tombstone statement and the audit events), so **maruhi's own deletes fail
too** — a project at the ceiling cannot free space by itself, and the operator
has no tool to reach into Durable Object storage either. The guard exists so a
project never gets there. It reads the measured database size (`databaseSize`)
on every write that adds content and:

- at **8 GB** logs one static warning line per Durable Object instance (no
  project id, no user id — see "Operational logs" below) and keeps accepting
  writes. The size is also observed (never rejected) on value pulls and
  workload leases — the reads that append audit rows — so a pull-heavy project
  whose growth is almost entirely `var.read` still produces the warning before
  it reaches the rejection threshold;
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
safety net for that growth; there is no per-tenant audit quota. Two of the
operations that stay open above 9 GB are not constant-size: pulls keep adding
`var.read` rows (one row per value pull of an environment, listing the
variables it returned — AUDIT_SPEC §3.3), and removing a member or revoking server access writes one
`rotation.recommended` row per variable (including deleted ones) that the
departing party could have read — proportional to the project's variable
history rather than a fixed number. Both are deliberate (exit path and
security remediation) and sized well inside the 1 GB headroom for realistic
projects; the warning band exists to give you time before they matter.

Deleting really does bring the measured size down: Durable Object SQLite
reclaims pages on `DELETE` (verified in workerd — `databaseSize` shrinks back
after a delete; `VACUUM` is not available to the application, so this relies on
platform behavior).

**Changing the thresholds**: edit the two constants and redeploy. Keep
`DO_STORAGE_REJECT_BYTES` below 10 GB — the guard is the only thing standing
between a project and the unrecoverable-by-tenant `SQLITE_FULL` state. The
values are decimal gigabytes (10^9 bytes), which is conservative under either
reading of the platform's "10 GB".

### Operational logs

The warning and rejection lines are **static messages**: they carry no project
id (a project id is effectively a capability — AUTH_SPEC §11-2) and no user
id. To find out which project is affected, use the Durable Object id in the
Workers Logs / `wrangler tail` event envelope (cf has no tail command in the
beta — wrangler remains installed for this): it is `idFromName(projectId)`,
so you can compute it for a project a tenant reports and compare, but the log
line itself never reveals the project. The hourly operations job (see
"Backups and operations" below) additionally reports the **number** of projects
in the warning and rejection bands as an aggregate signal; the log line remains
the place to look for the affected Durable Object.

## Backups and operations (optional)

**Nothing in this section is required.** A plain `cf deploy` keeps
working exactly as before; the features below are opt-in for operators who want
backups and alerting. Enabling them never changes what tenants can do — the
product API and its acceptance rules are untouched.

### What you get for free

- **D1 Time Travel** — point-in-time recovery for the last 30 days (7 days on
  the Free plan) is always on, at no cost:
  `bunx cf d1 time-travel get-bookmark $(bun scripts/d1-id.ts) --timestamp <RFC3339>`
  returns a bookmark,
  `bunx cf d1 time-travel restore $(bun scripts/d1-id.ts) --bookmark <bookmark>`
  restores it
  **in place** (destructive; in-flight queries are cancelled).
- **Durable Object durability** — project contents live in replicated
  Durable Object storage. There is no platform-provided export or PITR for it,
  which is why the application-level snapshot below exists.

### Recommended: periodic D1 export

Run `bun scripts/d1-export.ts --output <file>` on a schedule
(it blocks other requests to the database while it runs, so pick a quiet
hour), encrypt the dump with a key you control (e.g. `age`), and keep it
outside the Workers account. The export contains only what D1 contains: user
rows, session and token **hashes**, and the authentication audit log — no
secret values, which never reach the server in plaintext. The reference
workflow used for the hosted service is
`.github/workflows/ops-backup.yml` (disabled unless the repository variable
`OPS_BACKUP_ENABLED` is `true`). The API token it needs is **D1: Edit** plus
**Workers R2 Storage: Edit** (account scope): `d1 export` fails with
`Authentication error [10000]` under D1: Read, and `r2 object put` returns 403
under the bucket-scoped "Workers R2 Storage Bucket Item" permission. Prefer an
*Account* API token over a user token for CI, and allow a few minutes for
permission edits to propagate.

#### Restoring a D1 export

A D1 export writes each table as `CREATE TABLE` followed by its
`INSERT`s, in table-creation order — so child tables (e.g. `api_tokens`, which
references `users`) appear **before** their parents, and the leading
`PRAGMA defer_foreign_keys=TRUE` is not honoured by the import path. Importing
the dump as-is fails with `no such table: main.users`. Reorder it first:

```sh
age -d -i <keyfile> -o d1.sql d1/<timestamp>.sql.age       # decrypt (operator machine)
bun scripts/reorder-d1-dump.ts d1.sql d1.ordered.sql       # from apps/server
bunx cf d1 create --name maruhi-restored                   # a NEW database — never import over a live one
bun scripts/d1-import.ts <new-database-id> --file d1.ordered.sql
rm d1.sql d1.ordered.sql                                    # the decrypted dump is operator data — do not keep it around
```

The script puts every `CREATE TABLE` first, then the `INSERT`s in foreign-key
order (parents before children), then the indexes, and drops `BEGIN`/`COMMIT`.
Compare per-table `select count(*)` against the source afterwards (a few tables
per statement — D1 caps the number of terms in a compound `SELECT`), then point
the `DB` binding's `id` in `cloudflare.config.ts` at the new database and
redeploy.

### Optional: project snapshots to R2 and trip-wire alerts

The server ships an hourly cron job (the second entry in `triggers.crons`)
that does two things **only when the corresponding binding or secret is
configured**, and is otherwise a no-op:

1. **Snapshots of every project Durable Object to an R2 bucket** — binding
   `OPS_BACKUP_BUCKET`. Each project is written as one gzip-compressed NDJSON
   object under `do/<durable-object-id>/<timestamp>.ndjson.gz`. The key uses
   the Durable Object id (the one-way image of the project id), never the
   project id itself. Contents are exactly what the Durable Object holds:
   ciphertext, the membership chain, wrapped DEKs, metadata statements and the
   audit log — the operator learns nothing from the copy that the Durable
   Object did not already reveal, and no extra encryption layer is applied
   (R2 encrypts at rest; keep the bucket private). Unchanged projects are
   skipped for up to 7 days; retention is your bucket's lifecycle rule.
2. **Trip-wire alerts** — secret `OPS_ALERT_WEBHOOK_URL`. The job evaluates a
   fixed set of aggregate signals (GitHub token requests per hour, CLI login
   flow capacity reached, sign-up denials, login-failure suppression markers,
   projects in the storage warning / rejection bands, stale or failing
   snapshots) and POSTs a JSON body `{ service, at, events, text }` to the URL
   on every state change. The body carries **signal names and numbers only** —
   no project ids, user ids or tokens. Without the secret, firing signals are
   written to Workers Logs as static lines instead.

To enable both on your deployment:

```sh
# 1. Create the bucket (requires R2 to be enabled on the account) and a retention rule
#    (the bucket also comes with a default 7-day "abort incomplete multipart" rule)
bunx cf r2 buckets create-by-name maruhi-ops-backup
bunx cf r2 buckets lifecycle update maruhi-ops-backup --rules '[{"id":"retain-35d","enabled":true,"expire_objects":{"days":35},"abort_multipart_uploads":{"days":1}}]' -f
bunx cf r2 buckets domains managed list maruhi-ops-backup            # must say public access is disabled

# 2. Deploy the `hosted` mode, which adds the R2 binding, Workers Logs and a
#    higher CPU limit for large snapshots (see `case "hosted"` in
#    cloudflare.config.ts; put your D1 database ID there and register the same
#    secrets with --mode hosted).
#    Note: the hosted mode publishes a separate Worker, `maruhi-server-hosted`
#    (named explicitly in cloudflare.config.ts) — the restore worker binds to that name.
#    Workers Logs is enabled there with invocation logs turned OFF: the default
#    invocation log records request URLs, which carry project ids (capabilities)
#    and OAuth codes — keep `observability.logs.invocationLogs: false` and
#    `observability.redactQueryString: true` (drops query strings from any
#    URL that does reach logs or traces)
bunx wrangler secret put GITHUB_CLIENT_ID --env hosted
bunx wrangler secret put GITHUB_CLIENT_SECRET --env hosted
bunx wrangler secret put OPS_ALERT_WEBHOOK_URL --env hosted   # optional
bun run db:migrate:hosted
bunx cf deploy --mode hosted
```

The hourly job records its progress in the D1 tables `ops_backups`,
`ops_counters` and `ops_state`. They are operator state, not audit log: the
audit log (`AUDIT_SPEC.md`) never receives operational events.

### Restoring a project snapshot

Restores are an operator-only path with **no HTTP surface**: a separate,
temporary Worker (the `restore` mode of `cloudflare.config.ts`) polls the
bucket for job files and writes the result back to the bucket. It can only
write into an **empty** Durable Object — there is no path that overwrites a
live project.

```sh
# Deploy the restore worker only for the duration of the operation
bunx cf deploy --mode restore
# Ask for a restore (target "drill" restores into a scratch namespace for rehearsals)
echo '{"objectKey":"do/<id>/<timestamp>.ndjson.gz","target":"production"}' > job.json
bunx cf r2 objects put restore/jobs/job-1.json --bucket-name maruhi-ops-backup --file job.json --content-type application/json
# Within a minute the job is claimed (moved to restore/running/) and the result appears;
# compare it with the snapshot's trailer line. A job left under restore/running/ with no
# result means the worker died mid-restore: check the target DO before resubmitting
bunx cf r2 objects get restore/results/job-1.json --bucket-name maruhi-ops-backup --text
# Remove the restore worker again
bunx cf workers delete maruhi-restore --force
```

The result reports the restored chain head, the audit head hash and per-table
row counts; the snapshot's last line (its trailer) carries the same values for
comparison (`bunx cf r2 objects get <objectKey> --bucket-name maruhi-ops-backup | gunzip | tail -1`).
The trailer's `auditHeadHashHex` is `null` when the snapshot was taken before
the audit-head column had been materialized; in that case compare the restored
value with the live project's `GET /projects/:id/audit-head` (or recompute it
from the audit rows — `maruhi audit reconcile` does the same computation).
The snapshot's schema version must match the deployed server —
deploy the matching version first if it does not.

### Migrating a project from another maruhi (export / import)

A project is portable by construction: its id is the genesis hash, its
membership is a signed chain every client verifies, its values are
ciphertexts, and its audit log lives in the same Durable Object. Moving one
from the hosted service (or any other deployment) to yours is an **export
by the project's owner** and an **import by you, the operator**, over the
restore path above (AUTH_SPEC §11-6; the design is
`docs/notes/pf3-design.md`).

**1. The owner exports** (any machine logged in to the source deployment;
chain role owner):

```sh
maruhi project export --server https://my.maruhi.app --project <project-id> --out acme.ndjson.gz
```

This writes two files: the snapshot (`acme.ndjson.gz` — the same gzip NDJSON
the backup job produces, fetched page by page; ciphertext, the chain, wrapped
DEKs, statements and the audit log, never a plaintext) and the identities
companion (`acme.ndjson.gz.identities.json` — the current members' GitHub
ids, keyed by the user ids the chain names). The command prints the chain
head and the row counts, cross-checked against the verified chain; the
source records `project.exported` in the project's audit log. Export after
the last write: a member whose client verified a newer head than the file
carries refuses the destination (CRYPTO_SPEC §6.3).

**Before you import.** The restore path runs in the *production* Durable
Object and reads the snapshot from the ops bucket, so the deployment that
receives the project must be the `hosted` mode of `cloudflare.config.ts`
(the R2 binding plus your own D1 id — see "Optional: project snapshots to
R2" above); the plain `maruhi-server` worker has no bucket binding and
answers every import job with `no-bucket`. The `restore` mode's `DB`
binding must point at the same D1 id as your `hosted` mode (edit both ids
in `cloudflare.config.ts` before deploying either). And import only from an
owner you trust: the identities file decides which GitHub accounts become
which chain members — the worker confirms every listed id against the
restored chain (a non-member is refused, and only an owner's export attaches
a project), but it cannot tell whether the GitHub id next to a member's
chain id is really that person.

**2. You import** with the restore worker, adding `identitiesKey` to the job:

```sh
bunx cf r2 objects put import/acme.ndjson.gz --bucket-name maruhi-ops-backup --file acme.ndjson.gz
bunx cf r2 objects put import/acme.identities.json --bucket-name maruhi-ops-backup --file acme.ndjson.gz.identities.json --content-type application/json
bunx cf deploy --mode restore
echo '{"objectKey":"import/acme.ndjson.gz","target":"production","identitiesKey":"import/acme.identities.json"}' > job.json
bunx cf r2 objects put restore/jobs/import-acme.json --bucket-name maruhi-ops-backup --file job.json --content-type application/json
bunx cf r2 objects get restore/results/import-acme.json --bucket-name maruhi-ops-backup --text
bunx cf workers delete maruhi-restore --force
```

The job restores the Durable Object exactly like a snapshot restore (only
into an empty one; compare the result with the trailer the owner's command
printed) and then provisions D1 in one atomic batch: a `users` row **with
the chain's user id** and the matching `linked_identities` row for every
member, a personal org for each, the `projects` row under the exporting
owner's org, and the membership projection. The result's `identities`
field reports `provisioned` with the counts, or a static refusal:
`identity-conflict` (a GitHub id in the file is already linked to a
different account on your deployment — that person logged in before the
import; remove that account and resubmit the same job: the restored
project is kept and only the D1 step reruns, and that result reads
`"status": "failed", "code": "not-empty"` for the Durable Object half with
`"identities": { "kind": "provisioned", … }` for the D1 half),
`user-id-taken`, `project-exists` (the project row here belongs to someone
other than the exporting owner), `exporter-missing`, `identity-not-member`
/ `exporter-not-owner` (the file names an id the snapshot's chain does not
confirm), `identities-missing` / `identities-malformed`, `db-unavailable`
(the restore mode has no `DB` binding), `db-error` (D1 refused the batch —
resubmit). Look at the identities file before placing the job: it decides
which GitHub accounts become which chain members.

Every refusal above is asked **before the Durable Object is touched**: the
worker verifies the snapshot's chain itself (a file whose chain the server
would not load is `"code": "snapshot-chain-invalid"`), confirms the
companion against it, and classifies D1 read-only; a refused job reads
`"status": "failed", "code": "import-refused"` with the reason under
`identities`, and your deployment is exactly as it was. To see what an
import would do without doing it, submit the same job with
`"target": "drill"`: the result's `identities` reads `"kind": "rehearsed"`
with the counts (members to create, members already here, whether the
project row exists) and nothing is provisioned.

**3. After the import** — what the file does not carry:

- **Logins**: every member runs `maruhi login --server <your url>`; their
  GitHub login resolves to the chain's user id, so their devices, roles and
  scopes are what the chain says. Sessions and API tokens are not carried
  (issue new ones)
- **The server key**: the source server's `grant_server` wraps are useless
  here (your server has its own key). The owner runs
  `maruhi server revoke <source fingerprint>` and `maruhi server grant` for
  yours, then `maruhi env rotate` on the environments the source key could
  open (the source operator still holds wraps of those epochs — rotation
  retires them). CI leases work once the grant exists
- **Recovery and reserve keys**: the recovery ledger and guardian shares
  live in the source's D1; members set recovery up again
  (`maruhi key recovery`, `maruhi key reserve`, `maruhi guardian add`)
- **Pending invitations and device-add requests** are gone (re-invite);
  the advisory device registry rebuilds itself on each login
- **Ops state** (backup records, counters) starts fresh

**Switching over, and a newer export.** Once members use the destination,
make the source read-only rather than leaving two writable copies: the owner
marks the source project as a mirror of the destination
(`maruhi mirror mark --server <source url> --project <id> --source <your url>`)
— the source then refuses writes, keeps serving reads, and can be synced
from the destination as a fallback (see "Running a mirror" below). The
reverse order works too: if writes continued on the source after the
export, do not re-import — the Durable Object refuses a second restore
(`not-empty`). Mark the *imported* project as a mirror of the source
(`maruhi mirror mark --server <your url> --project <id> --source <source url>`),
run `maruhi mirror sync --server <source url> --mirror <your url> --project <id>`
to bring the newer state in, then `maruhi mirror promote --server <your url>`
to make it the primary. A re-run of the import job on the same deployment
provisions only the members added since (the project row and the existing
accounts are kept), so a member who joined after the first import can be
brought in with a fresh identities companion.

The hosted service keeps the project until the owner asks for its removal;
the audit log on both sides shows the export.

### Running a mirror (a read replica for when the primary is down)

A mirror is a second deployment — yours — that holds a verified copy of a
project and answers `maruhi run`, `maruhi pull`, `ci run` and `ci sync`
when the primary cannot. It accepts no writes (pushes and chain changes wait
for the primary), serves CI leases under its own server key once the owner
grants it, and can be promoted to the primary by the owner if the primary is
gone for good (AUTH_SPEC §11-7, CRYPTO_SPEC §9.2; design
`docs/notes/pf2-design.md`).

**1. Bootstrap** = the migration above, minus the switch: the owner exports
the project, you import it into your deployment with the identities
companion, members log in there once (`maruhi login --server <mirror>`),
and the owner marks the project as a mirror of the primary:

```sh
maruhi mirror mark --server https://mirror.example.com --project <project-id> --source https://my.maruhi.app
```

From this point the project on your deployment refuses writes
(`Forbidden (mirror-read-only)`) and shows the mark in `maruhi mirror status`.

**2. Keep it current** — any admin runs, by hand or from a cron:

```sh
maruhi mirror sync --server https://my.maruhi.app --mirror https://mirror.example.com --project <project-id>
```

The command exports the project from the primary (your session there; the
export needs the owner role) and uploads the pages to the mirror (your
session there — from a cron, `MARUHI_TOKEN` / `MARUHI_TOKEN_ORIGIN` for the
primary and `MARUHI_MIRROR_TOKEN` for the mirror). The mirror accepts a
replica only if it extends what it already holds; the result names both
heads and how many of the mirror's own audit rows (the reads and leases it
served) were re-appended after the replica's. When the primary's chain
head, audit seq and attestation mark are the ones the last sync brought,
the command uploads nothing and says the mirror is current — a cron can run
it every few minutes. `maruhi mirror status` compares the two at any time
(and reports the mirror's head alone while the primary is down). Across a
sync the mirror keeps its own lease windows and rate limits, merges the
primary's first-come token bindings into its own, and keeps the audit rows
of the reads and leases it served.

**3. Use it**: members set `maruhi config set mirror https://mirror.example.com`
(or pass `--mirror` to `run` / `pull`; CI workflows pass `--mirror` to
`ci run` / `ci sync`). The command warns when no session for the mirror is
stored on that machine: log in there now (`maruhi login --server <mirror>`)
and rehearse with `maruhi pull --server <mirror>` — a login is not possible
once the primary is the reason you need the mirror. The primary is always
tried first; when it does not answer (no response, no answer within 30
seconds, a 500, a gateway error) the read is retried against the mirror
and the CLI says so on stderr. Before the retry the CLI reads the mirror's
mark: a copy that was promoted, or that mirrors another deployment, is not
read (a promoted copy is a primary — point `config set server` at it).
Everything is verified as usual — a mirror that is behind what the member
already verified is refused, not silently used. An answer of the primary
about the read (a 403, a 404) is never retried.

**4. CI leases from the mirror**: the owner grants the mirror's server key
on the primary — `maruhi server grant --key-from https://mirror.example.com
--environments <ids> --lease-policy <file>` (the same fingerprint ceremony,
against the mirror's `/auth/config`) — and the next sync brings the grant
and the wraps to the mirror. The mirror's lease policy is its own (a
distinct audience is fine: `ci run --mirror <url>` requests a second OIDC
token with the mirror's origin as audience unless `--audience` is given).

**5. Promotion**: if the primary will not come back, the owner runs
`maruhi mirror promote --server https://mirror.example.com --project <id>`
(the mark is removed; the mirror accepts writes) and members set
`config set server` to it. The command probes the primary first and refuses
while it still answers — promoting beside a live primary leaves two
writable copies; mark the primary as a mirror of the new one first, take it
down, or pass `--force`. A stale old primary can never be synced over the
promoted one. If the primary was **compromised** rather than lost, also
revoke its server key on the promoted project (`maruhi server revoke
<fingerprint>`) and rotate the environments that key could open
(`maruhi env rotate`): the wraps it holds are retired by the rotation, not
by the promotion.

What a mirror does not do: it does not forward writes, it is as fresh as its
last sync, and the identities of members added after the bootstrap are not
carried (re-run the identities step of the import for them).

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

**Since 2026-08-24 the default deploy config also ships per-source-IP Workers
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
`cloudflare.config.ts` (or remove the binding entries) to match your traffic
shape; the server fails open when a binding is absent.

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

Commit the local edit to `cloudflare.config.ts` from step 2 (the database ID)
to your own fork (if upstream changes this file, `git pull` will collide with
an uncommitted edit. If you do not commit it, re-apply the edit after pull).
client_id / client_secret live in Workers Secrets, so updates do not touch them.

**Config-carrying updates**: some changes ship as `cloudflare.config.ts`
changes (bindings such as the per-IP rate limits), not just code. They take
effect only after you redeploy with the updated config, so pull the config
too, not just the code.

Update the server before the CLIs: a CLI assumes a server of the same release
or newer.

## Troubleshooting

- **`/auth/config` / `/auth/github/start` / `/auth/cli/start` return 503
  `SetupIncomplete`**: either `GITHUB_CLIENT_ID` or `GITHUB_CLIENT_SECRET` is
  unregistered (a missed `wrangler secret put` — step 5. If this
  happened after updating an instance stood up with the old steps, see the
  migration in "Updates"). List registered secrets with
  `bunx cf workers secrets list` (values are not shown)
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
  Pass the output of `openssl rand -hex 32` to `wrangler secret put
  SERVER_ENC_KEY_IKM` (watch for stray newlines or quotes)

## Notes

- **Rotating client_secret**: issue a new secret on the GitHub side →
  `wrangler secret put GITHUB_CLIENT_SECRET`
  (takes effect immediately; no redeploy) → delete the old secret on the
  GitHub side
- **Custom domain**: you may add `domains` to `cloudflare.config.ts` (the
  hosted mode uses it for `my.maruhi.app`). The OAuth callback is derived
  from the request origin, so **update the GitHub OAuth App callback URL to
  the same domain**
- **Deploy to Cloudflare button**: planned for the README after the repository
  goes public (Phase 2). Prerequisite work for the button (folding migrations
  into deploy, resolving the database ID from the deploy config, and putting
  client_id in a secret so post-deploy setup is just two secret updates) is
  done — with one re-verification item: whether the button understands
  `cloudflare.config.ts` (it predates cf and was designed around wrangler
  configs).
  Three points remain unverified and can only be verified against a public
  repository, so they will be checked at public release:
  (1) whether the button's monorepo support detects
  `apps/server/cloudflare.config.ts` from the repository-root URL and
  auto-provisions D1. (2) whether the button's build pipeline runs the
  `apps/server` `deploy` script (including migrations) — if it falls back to
  a plain `cf deploy`, the app is published with migrations unapplied and
  every endpoint that touches the DB returns 500.
  The setup page will likely need the deploy command overridden. (3) whether
  the button's provisioning replaces the committed placeholder
  database ID (`00000000-0000-4000-8000-…`) with the real ID —
  Cloudflare's docs recommend documenting a default and "update the config
  with the ID of the newly created resource", so if the button does not
  replace it the deploy fails with an API error against a UUID that does not
  exist (in that case the placeholder has to be removed)
- For the API spec including non-auth endpoints see `docs/AUTH_SPEC.md` (Japanese); for the
  crypto spec see `docs/CRYPTO_SPEC.md` (Japanese)
