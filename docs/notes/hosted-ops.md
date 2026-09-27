# hosted-ops — H3: design of the operations foundation (monitoring/alerts / backup / restore drill)

Status: drafted 2026-09-02 (bundled with the H3 implementation PR #137). **The restore drill (§5-3 / O7) was performed on the real system on 2026-09-03 — matching cross-checks complete H3** (the drill record is §5-3, measured values are in §4-2 / §1, and human-task completion dates are in §7). Lowers hosted-design.md §5 (ruling DC) into "implementable form".
Internal document. **An operator-side-only** stage; the product's wire and acceptance surfaces (AUTH_SPEC / AUDIT_SPEC) are unchanged.
The record of design exploration (candidates, superior-alternative search, rejected options, primary-source verification) lives in this document (no separate session note is created).

Premises (established facts — hosted-design.md §5-1 / session-47 ruling DC):

- The telemetry ban (CLAUDE.md "unspoken") prohibits **client → external** transmission. The
  operator's servers sending their own observation to the operator's own endpoint is out of
  scope (DC-1). However, the content sent must contain no **request-derived identifiers**
  (project ID = capability [AUTH_SPEC §11-2], user IDs, tokens, key material, plaintext) —
  static messages + aggregate values only (DC-2)
- Do not write operational events into the audit log (a product feature) (DC-3). No
  operator-facing admin API or admin UI is built. No dedicated health endpoint is built
  (DC-6 — external monitoring uses `GET /auth/config`). A tenant-facing API for DO backup
  stays a rejected option
- DO contents are ciphertext, chains, audit, wrapped DEKs, meta statements, manifests, and
  checkpoints (all tables of `PROJECT_DO_TABLES`) — no plaintext secrets exist (E2EE). Placing
  them in a backup destination increases what the operator can read by nothing

## 1. Primary-source verification (2026-09-02 — official Cloudflare docs. Distinguished from draft values)

| item | primary source (verified 2026-09-02) | use in this design |
|---|---|---|
| R2: single-object cap | single PUT 4.995 GiB / multipart 4.995 TiB · min part 5 MiB (except the last) · max 10,000 parts · key length 1,024 bytes · metadata 8 KiB. Concurrent writes to the same object 1/second (429 on excess) (r2/platform/limits — 2026-06-08 edition) | DO snapshots use a single `put` below 16 MiB, multipart otherwise (16 MiB parts, draft value → 640 parts even at 10 GB) |
| R2: pricing / free tier | Standard: $0.015/GB-month · Class A $4.50/million · Class B $0.36/million · egress free. Free tier 10 GB-month · Class A 1 million/month · Class B 10 million/month (r2/pricing). Lifecycle rules (delete / IA transition / abort incomplete multipart) via wrangler `r2 bucket lifecycle add --expire-days / --abort-multipart-days` (r2/buckets/object-lifecycles) | Retention is done by **bucket lifecycle rules** (the app never deletes — §4-2). Enabling R2 requires contracting R2 on the operator account (registering a payment method) = a human task (§7). **On the real system (wrangler 4.128)**: `lifecycle add` requires the rule name as a positional argument (`lifecycle add <bucket> <name> --expire-days …`). Buckets come with a default "Default Multipart Abort Rule" (7 days) |
| Workers: cron CPU / duration | Paid: CPU 15 min for cron interval ≥ 1 hour / 30 s below that, wall clock 15 min. Free: CPU 10 ms. Memory 128 MB / isolate. Subrequests Paid 10,000 / invocation (Free 50). cron count Paid 250 / account (Free 5) (workers/platform/limits) | The backup sweep runs on an **hourly cron**, but each run is cut off at a wall-clock budget of 10 min (draft value) and continues via cursor. On the Free plan the backup binding is absent → no-op (within CPU 10 ms — a single D1 read) |
| DO: limits | SQLite 10 GB / object (Paid). Row / string / BLOB 2 MB. Statement 100 KB · bound parameters 100 / query · columns 100 / table. CPU 30 s / request (up to 5 min via `limits.cpu_ms`). alarm wall clock 15 min. Free is SQLite DOs only · 5 GB / account (durable-objects/platform/limits — 2026-06-01 edition) | Restore INSERTs do `floor(100 / column count)` rows per statement (max 16 columns → 6 rows). Backup CPU for large DOs is relaxed via `limits.cpu_ms` (hosted only, 300,000) — the upper-bound discussion is §4-2 |
| DO: SQL cursor | a cursor resumed across an `await` "may observe rows inserted, updated, or deleted after creation" (storage-api docs). `.raw()` for column-ordered arrays, `.columnNames` for names | Backup row reads use **rowid keyset + LIMIT, synchronously `toArray()` one statement at a time** — no cursor survives an await (every table has a rowid — no `WITHOUT ROWID`) |
| Workers RPC | serialized RPC message cap 32 MiB. Large data goes over byte streams (rpc docs) | For DO backup the DO itself writes to R2; RPC return values are aggregates only (§2-D) |
| D1: Time Travel | Paid 30 days / Free 7 days. `wrangler d1 time-travel info <db> [--timestamp]` yields a bookmark; `restore <db> --timestamp\|--bookmark` is **in-place and destructive** (overwrites. In-flight queries are interrupted. Prior bookmarks survive a restore). No extra cost (d1/reference/time-travel) | First resort for accidental deletion / logical corruption. Ops runbook §5-1 |
| D1: export / import | `wrangler d1 export <db> --remote --output=<file> [--table] [--no-schema] [--no-data]`. SQL dump (CREATE + INSERT). **Other requests are blocked during export**. Virtual tables unsupported. Import is `wrangler d1 execute <db> --remote --file=<sql>` (5 GiB cap, `BEGIN/COMMIT` stripped) (d1/best-practices/import-export-data) | Periodic export runs on a GitHub Actions cron at a low-traffic time (02:41 UTC, draft value) (§4-1). **Measured (2026-09-03 · D1 295 KB)**: export step 3 s (blocking ≤ 1–2 s). Import **fails unless the dump's statement order is rearranged** (export lists CREATE → INSERT per table, and `PRAGMA defer_foreign_keys` does not work on the import path — `scripts/reorder-d1-dump.ts`, §5-1 (3)). The API token needs **D1: Edit** (with Read, export fails with `Authentication error [10000]`) |
| D1: size observation | `wrangler d1 info <db> --json` (JSON carries **`database_size`** bytes — wrangler 4.124 renamed the API's `file_size` on output. Older versions say `file_size`. Corrected in the PR #137 review) | The D1-total tripwire (5 GB) is evaluated inside the export workflow (§3 row 1) |
| Workers Logs | enabled via wrangler `observability.enabled`. Retention Paid 7 days / Free 3 days. 256 KB per entry. Paid includes 20M events/month, excess $0.60/million. `head_sampling_rate` for head sampling. No built-in alerting mechanism is documented (workers/observability/logs/workers-logs) | Enabled in the hosted environment (`head_sampling_rate` 1). However **`observability.logs.invocation_logs: false` is mandatory** — the default Fetch invocation log embeds the request URL (path + query), so `/projects/:id` (a capability) and `/auth/github/callback?code=…` would sit in the log store for the retention period (found in the PR #137 Cursor security review. CI 8c checks this). What remains is console static lines only, which carry no per-request identifiers, so even full volume does not accumulate capabilities. **Logpush containing request logs is also not enabled** — §5-1. **Additional finding in the 2026-09-03 drill**: Effect `HttpRouter.toWebHandler`'s default HTTP logger emits `"Sent HTTP response" {"http.url":"/projects/<id>"}` on the console path — even with invocation logs off, capabilities were still reaching the log store. Stopped with `disableLogger: true` (index.ts). After the fix, real Workers Logs data confirmed zero log lines on the normal path |
| Workers Analytics Engine | binding `analytics_engine_datasets` · `writeDataPoint` (250 points per call · blob total 16 KB) · retention 3 months · reads via SQL API (`/accounts/{id}/analytics_engine/sql` + Account Analytics Read token) (analytics-engine/get-started, /limits) | **Not adopted** (§2-A — reads require an API token, so threshold evaluation cannot close inside the worker) |
| Cloudflare Notifications | the notification-type list has **no** Workers / DO / D1 / R2 entries (Health Checks requires Pro or above) (notifications/notification-available — 2026-04-24 edition) | Do not depend on platform notifications. Send to an operator webhook ourselves (§2-B) |
| wrangler: named environments | `durable_objects` / `d1_databases` / `r2_buckets` / `ratelimits` / `vars` are **non-inherited** (re-declared per environment). `triggers` / `assets` / `migrations` / `limits` / `observability` are inherited (wrangler config-schema description + configuration docs). A DO binding's `script_name` can bind to another Worker's DO namespace | Hosted-specific bindings live under `env.hosted` (§2-F). The restore worker binds to the production namespace via `script_name` (§2-E) |
| GitHub: token requests | 2,000/hour/App (secondary. No remaining-observation API — session-48 §1) | Self-counting (§3 row 3). Threshold 1,600/hour (80%), draft value |

## 2. Rulings (enumerate candidates → search for superior alternatives / silver bullets → select)

### 2-A. Source of counting (GitHub token requests / login-flow row creation cap reached / signup denials)

Candidates:

- (a) `writeDataPoint` to Workers Analytics Engine
- (b) existing static log lines + queries on the Workers Logs / Logpush side
- (c) self-built counter rows in D1 (fixed windows. Precedents: `login_failed_windows` / the DO's `lease_windows`)
- (d) platform-standard metrics (GraphQL / dashboard)
- (e) estimation from existing audit rows (`auth.login_succeeded` + `auth.login_failed`)

Exploration: (a) can honor write-side discipline (no identifiers), but **reads would give the
worker an Account Analytics Read API token**, so threshold evaluation cannot close inside the
worker (token = a new secret + an external call). (b) is the same (Logs' query API). (d) cannot
observe token requests (a GitHub-side quota) (§3-4 addendum — self-counting is the only means of
observation). (e) is least accurate exactly during floods because `auth.login_failed` is
truncated at a fixed-window cap (100/hour/bucket), and reconstruction from the suppression
markers' powers of 10 is only an approximation. **(c) is the superior alternative**: both write
(1 UPSERT) and read (1 SELECT) close inside D1, it needs no new secret, external call, or
binding, and it works unconfigured on self-host. From the discipline of not writing the same
signal on two paths, (a)(b) are not used alongside.

**Adopt (c)**: D1 table `ops_counters(metric, window_start, count)` — one-hour fixed windows,
`INSERT … ON CONFLICT DO UPDATE SET count = count + 1`. Two write points:

- `github_token_requests`: **decorates the call site** of `GitHubApi.exchangeCode`
  (`countingGitHubApi` — one place in index.ts's buildServices). Both the web OAuth callback
  and the CLI handoff go through the same implementation, so handlers are untouched. Counts 1
  regardless of success (GitHub counts requests). **Does not change acceptance-surface behavior
  (rejection, delay)** — counting only
- `cli_flow_capacity`: the point where `CliFlowRepo.createOrMatch` returns `"capacity"`
  (handlers-auth-cli.ts — just before the uniform error page). Detection of an event that does
  not occur in normal operation (AUTH_SPEC §4-1 (4) (iii))

Signup-denial counting **builds no new counter**: the `auth.signup_denied` row (+ the
`auth.signup_denied_suppressed` marker) that AUDIT_SPEC §3.1 prescribes with "H3's tripwires
count this row" is counted by window from D1 `user_audit_events` (index `uae_event(event,
seq)`). Likewise the `auth.login_failed_suppressed` marker becomes the signal for auth-surface
floods. These are reads of records already in D1 and add no new write path (do not write
operational concerns into audit — DC-3).

Counter-increment failures are not swallowed: a static one-liner (`console.warn`) is left and
acceptance processing continues (counting is observation and does not take priority over
availability of the login path).

### 2-B. Threshold evaluation and the notification path

Candidates:

- (a) evaluate in the worker's `scheduled` (hourly cron) and POST to an operator webhook
  (Workers Secret `OPS_ALERT_WEBHOOK_URL`)
- (b) a GitHub Actions cron reads D1 via `wrangler d1 execute` and evaluates (notification =
  the GitHub notification of a workflow failure)
- (c) Cloudflare Notifications (platform notifications)
- (d) Analytics Engine / Logs dashboards (a human looks)

Exploration: (c) drops out — the primary source lists no Workers-family notification types.
(d) produces no notifications. (b) was attractive in that "the D1 export workflow already holds
an API token" and adds no secret to the worker — examined as a **silver-bullet candidate**. But
(1) the bulk of evaluation inputs (backup status, the DO-total census — §2-C) exists only
inside the worker, and getting it out would require an additional read path, (2) GitHub Actions
cron runs can be delayed minutes to tens of minutes or dropped (known Actions behavior), (3)
workflow-failure notification has only the single "failure" kind and no resolved notification,
(4) it does not work for self-host operators. (a) closes evaluation inside the worker, and a
single webhook destination (Slack / Discord / PagerDuty / email relays all offer endpoints) is
general. **Adopt (a)**. However, only D1 total cannot be measured from inside the worker
(`file_size` is wrangler / REST API), so the export workflow evaluates it via `wrangler d1 info`
(a limited application of b — same signal on a single path: the worker side does not handle D1
total).

Notification form: POST JSON to `OPS_ALERT_WEBHOOK_URL` (unset = nothing is sent. **Disabled by
default**). The body carries **a static signal name + aggregate value + threshold + state
(firing / resolved)** only. No identifiers ride. Evaluation state is kept in D1 `ops_state`, and
**notification fires on transition (inactive → active / active → inactive)**; while a signal
stays active it is re-notified every 24 hours (draft value). Even with no webhook configured,
an active signal leaves a static line in Workers Logs (the self-host hook). Send failures are
not swallowed: a static line + retry next time (state is not updated = resent at the next
evaluation).

### 2-C. Connecting H2's warning lines (storage-guard.ts) to a signal

Candidates:

- (a) on warning-line firing, write a flag row from the DO to D1 (the DO holds `env.DB`)
- (b) query Workers Logs and count "which DO ids emitted it"
- (c) when the backup sweep visits each DO, have it evaluate with the same meter
  (`StorageMeter.databaseSizeBytes`) and the same pure function (`storageGuardDecision`), and
  **aggregate the counts of projects in the warning / rejection bands as a census**

Exploration: (a) adds a D1 write to the hot path of the acceptance route and adds failure
semantics (does it stop acceptance?). The "once per DO instance lifetime" discipline also
weakens what the count means (restarts re-fire). (b) needs an API token (rejected for the same
reason as §2-A). (c) **builds no new write path** and can emit hosted-design §5-2's "number of
projects at warning threshold" signal directly as a gauge. The sweep runs hourly but each
project's visit interval is up to 24 hours (under §2-D's skip rule, size is still read every
time) — immediacy is carried by the existing warning line ("did it fire", in Workers Logs) and
the census carries the count. **Adopt (c)**. storage-guard.ts's wording and once-discipline are
unchanged (the only connection point is sharing the meter and the decision function).

### 2-D. DO → R2 backup: unit, full/incremental, trigger, naming, retention, duration

Candidates (transfer principal):

- (a) the worker pulls chunks from the DO over RPC and writes to R2
- (b) **the DO itself, under permit, reads its own SQLite and streams (multipart) to the R2
  binding**
- (c) self-scheduled backup via DO alarms (each DO wakes itself daily)

Candidates (unit): full snapshot / incremental by watermarks on audit seq and chain seq.

Exploration: (a) drops out on the RPC 32 MiB cap and on "consistency across chunks" (a permit
cannot be held across RPC). (c) was a **superior-alternative candidate** because it removes the
need to enumerate D1 `projects` and manage the sweep's budget, but was declined because (1)
every DO (including inactive ones) would wake daily and incur DO billing, (2) a path for each
DO to write back backup success/census to an aggregation point (D1) would be needed, (3) alarm
setup enters the acceptance path of DO creation (init) and touches "no change to the product's
acceptance surface". With (b), reads and writes are consistent inside the permit (same-task
serialization — the invariant at the top of chain-do.ts), and data goes straight DO → R2.
**Adopt (b)**.

Incremental is **not taken**: tracking deletions (environment-delete cascades, wrap deletions,
tombstones) would be needed and the verification surface for restore correctness grows. Instead
a **skip rule** keeps cost down — skip the backup when `(auditMaxSeq, chainHeadSeq,
attestationMark)` equal their last-success values **and** the last success was within 7 days
(every change is accompanied by an audit row / chain row. The exception is the head-declaration
upsert, which writes neither a chain row nor an audit row [AUTH_SPEC §16-1], so the third
component `head_attestations`' `MAX(accepted_at)` was added [PR #137 review]. The remaining
exception is mutable lease-window / binding rows — reproducible operational state, the
non-portable items of §4-2). Re-backing-up at least every 7 days prevents "unchanged content
whose backup vanishes" via lifecycle deletion (35 days).

The cost of consistency = permit hold time: requests to the project in question wait during the
backup. Duration scales with size; at beta scale (KB–MB) it is milliseconds to seconds. The
upper bound (9 GB) does not fit in one cron run per §4-2, so DOs exceeding
`OPS_BACKUP_MAX_BYTES` (draft value 2 GB) are **not backed up and are surfaced on the signal as
`oversize`** (never silently dropped. A human decides whether to raise the threshold or rely on
platform durability).

Trigger: **add one hourly cron** to the existing `scheduled` handler (wrangler.jsonc
`triggers.crons`) and branch on `controller.cron`. The sweep enumerates D1 `projects` in
ascending id order, resumes from the `ops_state` cursor, and is cut off at a 10-minute wall
clock (draft value).

Object naming: `do/<doIdHex>/<takenAt ISO>.ndjson.gz` — `doIdHex` is `ctx.id.toString()` (the
image of `idFromName(projectId)` — one-way. The same identifier as AUTH_SPEC §12-8's
operator-side identification means). **Project IDs are not placed in keys, metadata, or the
manifest**. Contents (NDJSON gzip): a header first (format / schemaVersion / takenAt /
doIdHex), then a column-name row + rows per table, and a trailer at the end (per-table row
counts · chainHeadSeq · auditMaxSeq · audit-head hex [only when the column is current — no
materialization write is done] · databaseSize). A missing trailer = a partial-failure backup
that the restore side rejects.

Retention: bucket lifecycle rules (`--expire-days 35` [draft value] · `--abort-multipart-days
1`). The app side never deletes (a design that does not give the worker delete permission — the
R2 binding uses only put/get).

Encryption: R2 performs encryption at rest by default. **No additional app-layer encryption
(e.g. AES-GCM under an operator key) is applied** — it would run afoul of CLAUDE.md "do not
implement cryptographic operations absent from the spec" (CRYPTO_SPEC is the single source of
truth). The content is E2EE ciphertext + public metadata, identical in form to what sits in the
DO (the operator can read nothing more). The bucket is private, accessible by the dedicated API
token only. Whether an extra layer is needed is §7 O8 — **2026-09-03 owner ruling: unnecessary,
permanently** (an attacker who can reach R2 can reach the DO itself, so protecting only the
backups adds no defensive line). Revisit when R2 access paths grow.

### 2-E. Restore path (operator-only, non-HTTP, non-permanent)

Candidates:

- (a) a dedicated worker entry that restores into a DO of a different class name (no HTTP)
- (b) a one-off script from `wrangler`
- (c) deploy to a restore-dedicated environment (a separate worker name)
- (d) an operator-facing restore endpoint (authenticated HTTP) on the production worker

Exploration: (d) is ruling DC's rejected option (an operator-facing admin API) itself — excluded.
(b) has no means of reaching a DO from wrangler (only a worker's fetch / cron / alarm / RPC can
touch a DO). (a) and (c) point the same way; the problem is "how to start a worker that has no
HTTP" — **cron + R2 job files** is the answer: the restore worker enumerates `restore/jobs/` on
a per-minute cron, executes the job (the backup object's key and target), and writes the result
to `restore/results/`. The operator places jobs with `wrangler r2 object put` and reads results
with `get`. Zero HTTP surface, startup requires only write permission to R2 (= the operator),
and the restore worker exists only while work runs (`wrangler deploy -c wrangler.restore.jsonc`,
then `wrangler delete` when done — non-permanent). **Adopt the composition of (a)+(c)**.

The restore receiver is the production DO class's RPC `opsRestore(objectKey)` (an
internal-worker RPC — not called from HTTP handlers), and **writes only to an empty DO
(chain_entries empty)**. No path exists that overwrites existing content (non-empty is rejected
with `not-empty`). A partial restore (a mid-way crash) is detectable via the rule "chain_entries
is written last", and on re-run the non-chain tables are cleared first and the restore is
restarted (a DO with no chain is uninitialized from the product's perspective). The schema
version is required to match the backup's (a mismatch is `schema-mismatch` — the operator
deploys the matching version, then restores).

The restore worker binds to the production namespace via `script_name: maruhi-server-hosted`
(wrangler named environments publish a separate Worker `<name>-<env>` — the substance of
`wrangler deploy --env hosted`. CI 8c cross-checks env.hosted's effective name) (target
`production`), and additionally holds its own DO class `RestoreDrillDO` (extends ProjectChainDO;
the namespace lives on the restore worker's side), so **drills do not touch the production
namespace** — they restore into the drill namespace and verify there (target `drill`). The DO
name is derived from the backup's chain genesis (seq 1's `entry_hash_hex` = project ID), so job
files carry no project ID either.

Verification: the restore RPC returns `{ chainHeadSeq, chainHeadHashHex, auditMaxSeq,
auditHeadHashHex, rowCounts }`, which is copied to the result file. The operator cross-checks it
against the backup's trailer (an automated test pins the same cross-check against a real DO — §6).

### 2-F. Making bindings optional (without breaking the self-host path)

Candidates:

- (a) add the R2 binding to the top-level wrangler.jsonc (leave it to wrangler's automatic
  provisioning)
- (b) put hosted-specific bindings under a `env.hosted` named environment; the operator deploys
  with `wrangler deploy --env hosted`
- (c) a separate file `wrangler.hosted.jsonc` (full duplication)
- (d) synthesize the config from base + overlay with a generation script
- (e) hit R2's S3 API with a Secret (access key) and no binding

Exploration: (a) drops out because a single `wrangler deploy` on an account without an R2
contract (payment-method registration) **breaks** (the Deploy-button path is identical). (e)
means implementing SigV4 signing in the worker = approaching off-spec cryptography, and gives
the worker long-lived credentials (bindings carry no credentials). (c) duplicates everything
and drifts. (d) is a self-built tool. (b) is wrangler's standard mechanism, where re-declaring
the non-inherited keys (`durable_objects` / `d1_databases` / `ratelimits` / `r2_buckets`) =
partial duplication is the price. **Adopt (b)**. Drift is blocked by running
`scripts/check-hosted-config.ts` (verifies that the hosted environment's bindings include the
top level) alongside CI 8c (dry-run). At runtime, **absence of `env.OPS_BACKUP_BUCKET` /
`env.OPS_ALERT_WEBHOOK_URL` = disabled** (not fail-open but "feature absent" — not silent; the
sweep leaves a static line "no binding, not backing up" [once per isolate]). When Alchemy v2
(gap 10) happens, the `env.hosted` contents move as-is into Alchemy declarations.

### 2-G. Periodic D1 export: principal, encryption, storage

Candidates: (a) GitHub Actions cron + `wrangler d1 export`, (b) a manual procedure on the
operator's terminal, (c) a worker reads D1 and writes to R2.

Exploration: (c) is a self-built dump iterating every D1 table inside the worker
(re-implementing what Time Travel and `wrangler d1 export` already do). (b) gets forgotten.
(a) can use `wrangler` in CI (the Deploy dry-run precedent). **Adopt (a)** —
`.github/workflows/ops-backup.yml` (daily 02:41 UTC, draft value + manual dispatch). Artifacts
are encrypted to an `age` public key (recipient in GitHub Variables; the secret key lives only
on the operator's terminal) and put to `d1/<timestamp>.sql.age` in the same R2 bucket via
`wrangler r2 object put`. Artifacts are **not** placed in GitHub Actions artifacts (on a public
repository, artifacts can be fetched by third parties). The workflow runs only when
`vars.OPS_BACKUP_ENABLED == 'true'` (so forks do not fail needlessly). The same workflow
compares `wrangler d1 info --json`'s `file_size` against 5 GB and fails (the D1-total
tripwire — §2-B). The `age` secret key, the API token, and artifacts are not placed in the
repository.

API-token permissions (**corrected by measurement on 2026-09-03** — the draft was "D1 Read +
R2 Write"): **D1: Edit** and **Workers R2 Storage: Edit** (both account-scoped). `d1 export`
with Read yields `Authentication error [10000]` (creating the export job counts as a write),
and `r2 object put` with bucket-scoped "Workers R2 Storage Bucket Item: Edit" yields 403
(wrangler's REST path requires account-level permission. Bucket-scoped permissions are for the
S3-compatible API). For operator CI use an **Account API token not tied to a user** (unaffected
by the issuer leaving or permission changes). Permission changes can take a few minutes to
propagate (a 403 right after editing means wait).

## 3. Monitoring-signal catalog (the implementation form of hosted-design §5-2)

| # | target | signal (source) | collection path | threshold (draft) | notification | false positives and response (1-line runbook) |
|---|---|---|---|---|---|---|
| 1 | D1 total (gap 4) | `wrangler d1 info --json`'s `file_size` | ops-backup workflow (daily) | job fails at ≥ 5 GB | GitHub failure notification (email) | no false positives (measured). Response: check the dominant terms of `user_audit_events` → separate into a dedicated audit D1 (§3-3 reservation — schema-identical so mechanical. Procedure: create a new DB → add a `D1_AUDIT` binding → a PR switching D1AuditRepo's write target) |
| 2 | DO total guard | the backup sweep's census (`storageGuardDecision` evaluated on each DO) | hourly cron → D1 `ops_backups.storage_level` → evaluation | warn ≥ 1 / reject ≥ 1 | webhook | no false positives. Response: cross-check the DO id in the Workers Logs warning line against `ops_backups.do_id_hex` → guide the tenant toward deletion (the SELF_HOSTING explanation) |
| 3 | GitHub token requests | `ops_counters.github_token_requests` (the exchangeCode call site) | hourly evaluation (last completed window + in-flight window) | ≥ 1,600/hour (80% of 2,000) | webhook | legitimately rises on signup concentration (right after invitation-code distribution). Response: slow the invitation-code issuance pace (hosted-design §3-4 (1)). Throttling is gap 9's territory (out of this task) |
| 4 | login-flow row creation cap reached | `ops_counters.cli_flow_capacity` (createOrMatch = capacity) | same | ≥ 1 | webhook | does not occur in normal operation (AUTH_SPEC §4-1 (4) (iii)). Response: check `cli_login_flows` unconsumed rows in D1 → if abnormal parallelism, narrow the source with the WAF |
| 5 | signup denials | `auth.signup_denied` (+ `_suppressed`) rows in `user_audit_events` | hourly evaluation | ≥ 20/hour, or suppressed ≥ 1 | webhook | rises on good-faith wasted attempts under invite-gating. Response: look at the distribution of denial reasons in D1 → revisit guidance wording / invitation distribution |
| 6 | auth-surface flood | `auth.login_failed_suppressed` markers (AUDIT_SPEC §3.1) | hourly evaluation | ≥ 1 | webhook | Response: read alongside the 429 rate (dashboard) → strengthen WAF rate limits (SELF_HOSTING recommended values) |
| 7 | backup lag | `ops_backups`: number of projects exceeding **re-backup interval (7 days) + 1 day** since last success · number of projects with ≥ 3 consecutive failures · `oversize` | hourly evaluation | each ≥ 1 | webhook | the lag threshold is derived from the re-backup interval (placed independently, dormant projects that keep being skipped would look permanently late — PR #137 review). Consecutive failures: read the static line (failure code) in Workers Logs. oversize: the decision to raise the threshold (§4-2) |
| 8 | availability | external monitoring (`GET /auth/config` returning 200 — an existing unauthenticated, stateless surface) | external service (human task) | page on 3 consecutive failures | the external service's notification | no dedicated health endpoint is built (DC-6) |
| 9 | error rate | 5xx rate on the Workers dashboard · DO errors (platform-standard metrics) | a human looks (beta scale) | baseline deviation | — | no self-collection (same signal on a single path) |

Notifications go over a single webhook (§2-B). Every signal is "a static signal name + aggregate
value" and carries no identifiers.

## 4. Backup design

### 4-1. D1

- **Time Travel** (Paid 30-day PITR — always on, no extra cost) is the first recovery resort
  (mis-operation, logical corruption)
- **Periodic export** (§2-G): once daily, `age`-encrypted, to R2 `d1/`, kept 35 days by
  lifecycle (draft value). Since D1 blocks other requests during export (primary source), it is
  placed at a low-traffic time. What is included is D1's own contents (users, session/token
  **hashes**, audit — no raw secret values ever existed)
- Key locations: `age` recipient (public key) = GitHub Variables; secret key = operator
  terminal (OS keychain etc.). The API token (D1: Edit + Workers R2 Storage: Edit — §2-G's
  measured correction) = GitHub Secrets
- Measured (manual dispatch on 2026-09-03 — D1 295 KB · 219 rows): whole job 25 s (dependency
  install 10 s · `age` install 10–24 s · **export 3 s** · encryption < 1 s · R2 upload 2 s ·
  tripwire 2 s). Artifact 16.6 KB. The 02:41 UTC draft time carries no meaning at this scale
  (the blocking is unobservable), so it is kept as-is — revisit once the user base's time-zone
  distribution is known

### 4-2. DO → R2

- Unit = one project DO = one object (full snapshot. §2-D's skip rule)
- Coverage = all `PROJECT_DO_TABLES` tables (`schema_meta` excluded; the version is written to
  the header)
- Reads = under permit, rowid keyset, one statement at a time, synchronous (no cursor survives
  an await)
- Writes = NDJSON → gzip (`CompressionStream`) → multipart with 16 MiB parts (single put below
  16 MiB)
- Cost estimate (draft values. R2 pricing in §1): at the upper bound of 1,000 projects · 1 MB
  average · changed daily: 1,000 Class A writes/day = 30k/month (3% of the 1M free tier),
  storage 35 GB ($0.5/month). With the skip rule, the effective figure is a fraction of this
- Duration upper bound (a 9 GB DO): if JSON encoding + gzip runs at 50–100 MB/s (draft estimate
  — measured in the drill), that is 90–180 s of CPU; upload is 16 MiB × 563 parts. Inside the
  DO CPU cap (default 30 s → hosted raises it via `limits.cpu_ms` 300,000) and cron's 15-minute
  wall clock, but the permit hold = the tenant wait lasts the same duration. Hence DOs
  exceeding `OPS_BACKUP_MAX_BYTES` (draft value 2 GB) are not backed up and surface `oversize`
  on the signal (§3 row 7)
- **Drill measurements (2026-09-03 — §5-3)**: the dogfooding DO (`databaseSize` 188 KB · 17
  tables 47 rows) produced a 5,293-byte backup (after gzip. Single `put`). For the hourly `:23`
  cron, `last_success_at` / cursor updates landed at `:23:56.3–.9` every time (4 consecutive) =
  **cron start delay ≈ 56 s, sweep body < 1 s**. The skip rule did not back up on the two rounds
  with unchanged seq (03:23 / 04:23), and re-backed up on the round where seq advanced (02:23)
  — confirmed by R2 object count (2) and `last_attempt_at` ≠ `last_success_at`. **The 9 GB
  upper bound, multipart, and DO subrequest accounting are not observable at this scale** (the
  unconfirmed item of §8 (a) stays unconfirmed). No basis was obtained for changing
  `OPS_BACKUP_MAX_BYTES` 2 GB, so it is **kept as-is**. When to revisit: when a real tenant's
  `databaseSize` reaches the hundreds-of-MB range — measure that DO's backup duration (permit
  hold) from Workers Logs / the `last_attempt_at` delta first
- Partial-application windows: (i) a crash mid-multipart → the incomplete upload is aborted by
  the lifecycle (1 day) and `ops_backups` records a failure (retried next round), (ii) mixing of
  old and new backups → objects are timestamped and **never overwritten** (the latest success
  key is `ops_backups.last_object_key`), (iii) a rollback deploy → match-check the backup
  header's schemaVersion against the restore target's version (§2-E), (iv) DO eviction
  mid-backup → the RPC fails and is recorded as a failure
- Non-portable / regenerable rows (recover naturally on the tenant side after restore):
  `head_attestations` (re-submitted on next sync), `lease_windows` / `lease_bindings` (windows
  recover with time; bindings expire at deadline. A restore **revives old bindings** but only
  ever acts on the side of rejecting in-window token re-presentation [the safe side]),
  `attestation_windows` (same). `audit_head_hashes` is a derived value but is included in the
  backup (the post-restore `ensureHeadCurrent` is read-only if the column is current)

### 4-3. Bounding the shared resources the backup and census consume (walkthrough (a))

| resource | bounding |
|---|---|
| cron wall clock / CPU | cut off at 10 min per run (draft value) · cursor continuation. At most 2,000 projects visited per run (inside the 10,000 subrequests) |
| DO permit | one backup = one permit hold (size-proportional). Bounded above by `OPS_BACKUP_MAX_BYTES` |
| D1 reads/writes | one `ops_backups` upsert per project + enumeration pages of 100 rows. `ops_counters` is one UPSERT per login |
| R2 | put / multipart only (list / delete permissions unused). Retention via lifecycle |
| GitHub quota | untouched (counted only) |

## 5. Restore design and drill procedure (runbook — execution on the real system is a human task)

### 5-1. D1

1. Determine the blast radius (from when it broke). Get a bookmark with
   `wrangler d1 time-travel info maruhi --env hosted --timestamp=<RFC3339>`
2. `wrangler d1 time-travel restore maruhi --env hosted --bookmark=<bookmark>` (in-place,
   destructive. In-flight queries are interrupted)
3. Outside Time Travel's range (over 30 days) / loss of D1 itself: create a new DB with
   `wrangler d1 create`, decrypt the export with `age -d -i <keyfile>`, then **reorder the
   statement order with `bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>`** and run
   `wrangler d1 execute <db> --remote --file=<out.sql> -y` (split above 5 GiB). Why reordering
   is needed (measured 2026-09-03): the export lists a CREATE TABLE → INSERT block per table,
   so INSERTs for child tables (`api_tokens` etc.) come before the parent table (`users`). The
   leading `PRAGMA defer_foreign_keys=TRUE` does not work on the import path — as-is it stops
   at `no such table: main.users`, and merely moving CREATEs forward stops at `FOREIGN KEY
   constraint failed`. The script orders all CREATE TABLEs → INSERTs in parent→child foreign-key
   dependency order → CREATE INDEXes, dropping BEGIN/COMMIT. Delete the decrypted SQL after the
   work. Then swap `env.hosted`'s `database_id` and redeploy. Row-count cross-checks use
   `select count(*)` per table (D1's compound SELECT has a small term cap — putting every table
   in a single UNION ALL fails with `too many terms` — do 4 tables at a time)

### 5-2. DO

1. From the restore target's project ID, get the `idFromName` image (hex)
   (`ops_backups.do_id_hex` — D1). The latest success key is `ops_backups.last_object_key`
2. Deploy the restore worker: `wrangler deploy -c wrangler.restore.jsonc` (binds to the
   production namespace via `script_name`)
3. Place a job file: `wrangler r2 object put <bucket>/restore/jobs/<name>.json --file job.json
   --remote`; `job.json` = `{ "objectKey": "do/<hex>/<ts>.ndjson.gz", "target": "production" }`
   (drills use `"drill"`)
4. Within a minute the cron picks it up (before execution it is moved to
   `restore/running/<name>.json` as a claim — so the per-minute cron does not run the same job
   twice), writes the result (`ok` + verification values, or a failure code) to
   `restore/results/<name>.json`, and clears running/. Read it with `wrangler r2 object get
   <bucket>/restore/results/<name>.json --pipe --remote`. If there is no result and the job
   remains in `restore/running/`, the worker crashed mid-run = check the target DO's state
   (empty, or a chain entered) before resubmitting
5. Verify: cross-check the result's `chainHeadSeq / chainHeadHashHex / auditMaxSeq /
   auditHeadHashHex / rows` against the backup's trailer (`wrangler r2 object get … --pipe |
   gunzip | tail -1`). The trailer's `auditHeadHashHex` is non-null only when the cumulative
   hash column was current at backup time (backup performs no materialization write). On null,
   record the value the restore side returned after extending the column, and cross-check it
   against the tenant-side `GET /audit-head`. On a production restore, additionally ask the
   tenant to run `maruhi project verify` / `audit verify` (restore does not recreate the
   starting point of "since the attestation" tamper detection — the backup carries the head
   column)
6. Clean up: `wrangler delete -c wrangler.restore.jsonc` (do not leave the restore worker). DOs
   in the drill namespace disappear along with the class when the restore worker is deleted

### 5-3. Drill (once before invite-only beta = H3's completion condition)

1. Confirm the backup sweep completed one round in the hosted environment (`ops_backups` has a
   success row for every project)
2. Restore the operator's own dogfooding project with `target: "drill"` and confirm the §5-2
   (5) cross-checks match
3. D1: decrypt the latest export and import it into a **different** new D1 (production
   untouched), then cross-check row counts via `sqlite3`-equivalent queries against
   production's `wrangler d1 execute --command "select count(*) …"`
4. Measure durations (export blocking time, the 9 GB upper-bound estimate) and update this
   document's draft values (`OPS_BACKUP_MAX_BYTES`, the time of day)
5. Append the execution date and results to the hosted-design.md §9 H3 row

#### Execution record (2026-09-03 — operator account `maruhi` · hosted origin `https://my.maruhi.app`)

Target: the operator's dogfooding project (env `dev` · 5 variables · dummy values. DO id image
`1fe4a507…`). The drill had Claude (Cursor) execute wrangler on the operator's terminal while
the owner handled browser operations (GitHub OAuth, CLI approvals) and token issuance (an
accompanied session). Order: hosted deploy (`signupPolicy` default `open`) → operator-account
signup → **flip `signup_policy` to `invite`** (the UPSERT SQL in SELF_HOSTING.md — `updated_at`
required) → CLI login → create the project. From then on `https://my.maruhi.app` is
invite-gated (confirmed via `/auth/config`).

| step | result | duration / measurement |
|---|---|---|
| (1) one sweep round | `ops_backups` 1 row (all projects) · `storage_level=admit` · 0 failures · cursor at end. Two generations — 01:23Z (right after init · 1,453 B) and 02:23Z (after push · 5,293 B); 03:23Z / 04:23Z skipped | cron start +56 s · body < 1 s |
| (2) DO drill restore | `wrangler deploy -c wrangler.restore.jsonc` → `restore/jobs/drill-2026-09-03.json` (`target: "drill"`) → `status: "ok"` in `restore/results/`. **All 17 tables' row counts · chainHeadSeq 3 · chainHeadHashHex `17274a51…` · auditMaxSeq 17 matched the trailer**. The trailer's `auditHeadHashHex` was null (the §5-2 (5) case) → the restore side's `5522999b…` was cross-checked three ways against h_17 recomputed tenant-side from audit rows and production `GET /audit-head`'s declared value — **all three matched**. No `running/` leftovers. Cleaned up with `wrangler delete` | job submitted 03:45:13Z → result by 03:46:14Z (cron 1 min + a few seconds) |
| (3) D1 restore | decrypted the manually dispatched ops-backup export (`d1/2026-09-03T03-16-06Z.sql.age` · 16.6 KB) with `age -d` → created a fresh `maruhi-drill` → **plain import failed twice** (`no such table: main.users` → CREATEs-first then `FOREIGN KEY constraint failed`) → reordered parent→child with `scripts/reorder-d1-dump.ts` and succeeded (90 statements · 219 rows). **All 21 tables' `count(*)` matched production**. Cleaned up with `wrangler d1 delete maruhi-drill` | import 3 s |
| (4) measurements | reflected into §4-1 / §4-2 / §1. No draft values changed (insufficient evidence — the 9 GB upper bound is unobservable at this scale) | — |
| (5) records | updated the hosted-design.md §9 H3 row and the ROADMAP.md H3 row (this PR) | — |

Defects and discrepancies found by the drill (fixed in this PR):

- **Effect HTTP logger leaving capabilities in logs** (§1 Workers Logs row) — `disableLogger:
  true`
- `r2 bucket lifecycle add` requires a rule name (§1 R2 row · SELF_HOSTING.md)
- Actions-token permissions are D1: Edit + Workers R2 Storage: Edit (§2-G · ops-backup.yml ·
  SELF_HOSTING.md)
- D1 import statement order (§5-1 (3) · SELF_HOSTING.md · new `scripts/reorder-d1-dump.ts` —
  the pure-function part `.lib.ts` pinned by `test/reorder-d1-dump.test.ts`)
- Added in the PR #139 pullfrog review: the single-origin invariant (`workers_dev: false` +
  `routes`) added to CI 8c's checks, a regression test that capabilities do not appear in logs
  (`test/log-hygiene.test.ts` — fails if the Effect logger is restored), and a static one-liner
  emitted only on 500s to replace the failure-kind logs `disableLogger` removes (index.ts)
- Direct INSERTs into `deployment_settings` need `updated_at` NOT NULL — the SELF_HOSTING.md
  SQL is correct (made a runbook)
- GitHub's OAuth App registration form changed (multiple Redirect URIs, "Expire user access
  tokens") — SELF_HOSTING.md §4

Operational observations (no changes — proposals):

- The normal-path hourly job emits not a single line to Workers Logs (records live only in D1).
  A static one-liner "sweep 1 round · n items · m skips" would make health checks from outside
  easier (it carries no identifiers, so it does not violate DC-2)
- `maruhi login`'s flow deadline (10 min) is short for accompanied operation (a person receives
  the URL over a separate channel) — no problem for solo operation
- The CLI's `key generate` judged the Cursor terminal an AI-agent environment and skipped the
  recovery code (as ADR-0016 decision 7 intends). Fine for drill keys, but the operator's real
  key must be made on a human's terminal

## 6. Mapping to implementation

| layer | change |
|---|---|
| D1 schema (drizzle) | `ops_counters(metric, window_start, count)` / `ops_backups(project_id, do_id_hex, last_success_at, last_object_key, last_bytes, last_audit_seq, last_chain_seq, storage_level, last_attempt_at, consecutive_failures, last_failure_code)` / `ops_state(key, value, updated_at)` (sweep cursor · alert state) |
| db.package | `OpsRepo` (counter increments / window aggregation · backup records / lag aggregation · state kv · window aggregation of `auth.*` rows · full enumeration of `projects`) |
| ops-policy.ts | draft values for thresholds and budgets (not an acceptance policy — self-host changes them freely) |
| ops-signals.ts | `countingGitHubApi` (the exchangeCode decoration) · `noteCliFlowCapacity` |
| ops-alerts.ts | hourly evaluation + webhook + state transitions |
| do-snapshot.ts | DO side: table enumeration · NDJSON gzip stream · multipart · restore parser · emptiness check |
| chain-do.ts | RPC `opsBackup(input)` / `opsRestore(objectKey)` (under permit, not callable from HTTP). `Env` gains `OPS_BACKUP_BUCKET?` / `OPS_ALERT_WEBHOOK_URL?` |
| ops-backup.ts | the sweep (enumeration · skip decision · census · recording · budget) |
| index.ts | `scheduled` branches by cron (daily = session cleanup, hourly = evaluation + sweep) |
| restore-worker.ts + wrangler.restore.jsonc | the restore worker (cron + R2 jobs. `RestoreDrillDO`) |
| wrangler.jsonc | the hourly cron added, `env.hosted` (R2 / observability / limits + re-declaration of non-inherited keys) |
| scripts/check-hosted-config.ts | drift check of `env.hosted` (CI 8c) |
| .github/workflows/ops-backup.yml | D1 export + age + R2 + D1-total evaluation |
| docs | SELF_HOSTING.md (English: Backups / Optional operations bindings), hosted-design §8 gaps 4·5 / §9 H3, ROADMAP |
| tests | `ops-backup.test.ts` (real DO: fixture → backup → restore into an empty DO → head / audit-head [`ensureHeadCurrent`] / row match / no seq gaps. Skip rules. Census. not-empty rejection. Missing-trailer rejection), `ops-alerts.test.ts` (counters · evaluation · transitions · no identifiers in the webhook body), `ops-restore.test.ts` (job processing) |

## 7. Human tasks (not executed — enumeration. Completion dates filled in during the 2026-09-03 accompanied session)

| # | task | stage | status |
|---|---|---|---|
| O1 | Set up the Workers Paid operator account (L6) — cron CPU 15 min · DO 10 GB · Time Travel 30 days all assume Paid | before H3 deploy | **Done 2026-09-03** (operator account `maruhi`. The existing `maruhi-server` [2026-08-10 trial deploy · D1 0 rows · 0 DOs] was confirmed empty and operations started fresh under the hosted name) |
| O2 | Enable R2 (register a payment method) and create the bucket: `wrangler r2 bucket create maruhi-ops-backup`, lifecycle `lifecycle add maruhi-ops-backup retain-35d --expire-days 35 --abort-multipart-days 1` (**the rule name is a required positional argument**). No public access (`dev-url get` shows disabled · no custom domain) | same | **Done 2026-09-03** |
| O3 | Fill `env.hosted`'s `database_id` and bucket name with real values, `wrangler secret put OPS_ALERT_WEBHOOK_URL --env hosted` (the webhook endpoint = a chat / email-relay contract). `wrangler deploy --env hosted`. **Caution**: a named environment creates a separate Worker `maruhi-server-hosted` (= a separate DO namespace). If project DOs are already running under the top-level name `maruhi-server` on the operator account, switching to hosted does not carry their data (migrate them via backup → the restore worker, or operate under the hosted name from the start). Check whether an existing deploy exists before the first deploy (PR #137 review). **Once, right after deploying**, visually confirm in Workers Logs that invocation logs have actually stopped (Invocation logs OFF in the dashboard's Logs settings, or no line containing `http.url` appears in the logs after a few minutes) — CI 8c only sees the config file's values. **Serving domains** (owner ruling 2026-09-03): product origin = `my.maruhi.app` (`routes` + `custom_domain`; `workers_dev: false` on hosted), apex `maruhi.app` = LP + docs [`/docs` — L1 revision 2026-09-03. The original "`maruhi.dev` = docs" was retracted; `maruhi.dev` 301s]. The dashboard's origin is the TCB, so it is separated from the LP. After the first user (the operator) signs up, flip `deployment_settings.signup_policy` to `invite` (the SELF_HOSTING.md SQL) | same | **Done 2026-09-03** (Secrets: GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / SERVER_ENC_KEY_IKM / OPS_ALERT_WEBHOOK_URL [Slack]. Right after the operator account's signup [00:4x UTC · under `open`], at 00:49 UTC `signup_policy` was **flipped to `invite`** and confirmed via `GET /auth/config` showing `signupPolicy=invite` [the window it was open was about 1 hour · the only user created is the operator's 1 = `users` 1 row]. Visual Logs inspection **found and fixed the Effect HTTP logger leak** — §1) |
| O4 | GitHub: Secrets `CLOUDFLARE_API_TOKEN` (**an Account API token — D1: Edit + Workers R2 Storage: Edit**. The draft's "D1 Read + R2 Write" proved insufficient on the real system — §2-G) / `CLOUDFLARE_ACCOUNT_ID`, Variables `OPS_BACKUP_ENABLED=true` / `OPS_BACKUP_BUCKET` / `OPS_BACKUP_AGE_RECIPIENT`. The `age-keygen` secret key goes to the operator terminal's keychain. Run once manually via `workflow_dispatch` and confirm success | same | **Done 2026-09-03** (succeeded on the 3rd manual run — the two permission-insufficiency measurements are in §2-G) |
| O5 | Contract an external monitoring service (monitor `GET /auth/config` at the shortest interval, notify on consecutive failures) — Better Stack Uptime adopted. No dedicated health endpoint is built | before invite-only beta | **Done 2026-09-03** (Better Stack Uptime monitor: `GET https://my.maruhi.app/auth/config` · **30 s interval** [the plan's shortest. Dropping to free makes it 180 s] · expects 200 · confirmation period 180 s [= ~6 consecutive failures · notifies in the same 3 minutes as the runbook's "1 min × 3"] · recovery period 180 s · 4 regions [eu/us/as/au] · notification by email. Added TLS-expiry 7-days-before and domain-expiry 14-days-before notifications. Load ≈ 8 req/min, a single point D1 read, outside rate limits. No APM like Sentry is **installed** — the client side is "unspoken", and on the Worker side request-derived identifiers would reach a third party [violates DC-2]. Error rate is the Workers dashboard [§3 row 9]) |
| O6 | The operations GitHub OAuth App (L7 — the production callback URL). "Enable Device Flow" stays disabled. In the **2026-09 form** Redirect URIs (multiple allowed · wildcard restriction) and "Expire user access tokens" were added — Redirect URI is the single `https://my.maruhi.app/auth/github/callback` · wildcard off; Expire may be on (the server uses the access_token immediately and discards it, never reading the refresh_token) | before H3 deploy | **Done 2026-09-03** (under the org `maruhiapp`) |
| O7 | Perform the restore drill (§5-3) and reflect measured values. **H3's completion condition** | before invite-only beta | **Done 2026-09-03** (the §5-3 execution record — DO and D1 both cross-check-matched) |
| O8 | Ruling on whether app-layer encryption of backups (operator key) is needed — if yes, present it as a CRYPTO_SPEC revision (§2-D). **Decision materials (organized 2026-09-03)**: (a) the backup's contents are the same E2EE ciphertext + public metadata as the DO — the operator can read nothing more. (b) R2 has at-rest encryption + a private bucket + account-level permissions only. (c) Adding a layer adds key management (storage, rotation, distribution to the restore worker of the operator key) and becomes a cryptographic operation outside CRYPTO_SPEC. (d) The threat is "an R2-bucket permission leak hands ciphertext + chain + audit (metadata) to a third party" — plaintext never escapes but member composition, variable names, and operation history do. (e) The D1 export is already `age`-encrypted under the operator key, making it asymmetric (because D1 transits GitHub Actions runners = a third-party environment. DO backup completes entirely inside Cloudflare). **Owner ruling 2026-09-03: unnecessary — not to be added in the future**. An attacker who can reach R2 can reach the DO itself, so protecting only the backups adds no defensive line. Revisit when R2 access paths grow (external integrations, replication to other accounts, etc.) | optional | **Ruled 2026-09-03 (unnecessary · permanent)** |
| O9 | Alchemy v2 (ADR-0012 / gap 10) — an independent PR that moves the `env.hosted` contents and the apex site (O10's `maruhi-site`) into Alchemy declarations | after the DP series (web-design-pass.md §1-6) | open |
| O10 | **First deploy of the apex site (DP2)**. **Order**: because DP2's PR links `apps/web`'s top (`my.maruhi.app/`) and the README to `https://maruhi.app`, execute it **after the merge and before the next production Worker deploy (`wrangler deploy --env hosted`)** (until then the product side's link target is undelivered = not a 404 but DNS-unresolved. No impact on secrecy). Procedure: at the repository root `bun install && bun run --filter @maruhi/site deploy` (= `blume build` + `scripts/postbuild.ts` + `wrangler deploy` — `apps/site/wrangler.jsonc`, Worker name `maruhi-site`, Static Assets only, no Worker code). With `routes`' `custom_domain: true`, wrangler automatically creates `maruhi.app`'s DNS records and certificate (the zone lives in the operator's CF account. Remove any existing apex A / AAAA / CNAME first). Post-deploy visual checks: `curl -sI https://maruhi.app/` shows `content-security-policy` (`script-src 'self' 'sha256-…'` · `style-src 'self' 'sha256-…'`) and `strict-transport-security`; `/docs` opens; `/fonts/OFL-Archivo.txt` is readable; browser DevTools' Network shows zero requests to external origins. Preview URLs are disabled (`workers_dev: false` / `preview_urls: false`), so pre-verification uses `bun run --filter @maruhi/site build && bun run --filter @maruhi/site preview` (local wrangler dev, `http://localhost:8789`) | after DP2 merges | open |
| O11 | **`maruhi.dev` → `maruhi.app` 301** (a zone redirect rule — no Worker is placed): in the `maruhi.dev` zone, Rules → Redirect Rules → Create rule. Expression = `(http.host eq "maruhi.dev") or (http.host eq "www.maruhi.dev")`, Type = Dynamic, Expression = `concat("https://maruhi.app", http.request.uri.path)`, Status = 301, Preserve query string = on. Redirect rules need proxied DNS records, so place **proxied (orange-cloud) A records `192.0.2.1`** (dummy) on `maruhi.dev` (apex) and `www`. Verify: `curl -sI https://maruhi.dev/docs` returns `301` + `location: https://maruhi.app/docs` | after O10 | open |
| O12 | **Visit counting is server-side only** (web-design-pass.md §1-5 — no script injection): use the `maruhi.app` zone's Analytics & Logs → Traffic (HTTP request aggregation). If enabling Web Analytics, do **not** choose "Automatic setup" (automatic beacon injection) and do not place the JS snippet either (`_headers`' CSP `script-src 'self' + hashes` would reject the external beacon — being rejected is as designed). Workers Static Assets responses get no beacon injected, so Web Analytics numbers will not grow = expected | after O10 (optional) | open |

## 8. Post-implementation second-round zero-based exploration (walkthrough — convergence record. 2026-09-02)

(a) **Shared resources**: the §4-3 table. Points additionally verified / corrected —
- `ops_counters` rows accumulate per window, so rows older than 7 days are deleted at evaluation
  time (bounded). `ops_state` has fixed keys only. Webhook sends are 1 POST per evaluation (not
  one per signal)
- R2 multipart **requires all parts except the last to be the same size** (primary source). A
  "send when accumulated" shape over the compression stream's output would produce varying part
  lengths and fail on complete, so it was changed to cut out exactly partBytes at a time (a
  2-part multipart of 5 MiB parts is pinned in miniflare, the real-R2-compatible runner)
- Whether R2 calls inside a DO count against the DO's subrequest cap is **unconfirmed** — the
  primary sources do not say (640 parts even at 10 GB — inside Workers Paid's 10,000). The
  2026-09-03 drill used a 188 KB DO (single put, 1 subrequest) and never passed through
  multipart, so it stays **unconfirmed**. The multipart path first runs for real when a real
  tenant's DO exceeds 16 MiB — confirm it via that round's `ops_backups.last_failure_code`
  (`upload-failed` / `rpc-failed`) and the static Workers Logs lines
- Free-plan cron has CPU 10 ms: the hourly job without bindings only reads a few D1 rows (I/O
  waits do not count as CPU). If an environment still exceeds it, removing the second
  `triggers.crons` entry suffices (stated in SELF_HOSTING — backup and evaluation disappear)

(b) **Readings that must keep holding**: the existing daily cron (session cleanup) branches by
cron string, unchanged (execution environments where the expected cron string never arrives —
tests' `createScheduledController()` passes an empty cron — **choose the daily processing** =
preserving the existing test contract). The DO's acceptance path only shares the permit;
decision order and rejection vocabulary are unchanged (pinned by storage-guard.test.ts).
Self-host deploys keep the top-level config unchanged (only one cron added); CI 8b's dry-run is
as before, plus 8c's hosted / restore dry-run and drift check. The `GitHubApi` decoration is a
single place in index.ts; the handlers (web callback / CLI callback) do not change how they
call exchangeCode.

(c) **Partial-application windows**: §4-2. Additionally —
- "The product's init arrives at the same name mid-restore" = re-initialization by a legitimate
  owner holding the same genesis; if a chain row lands before the restore completes, the
  restore is rejected `not-empty` (falls on the do-not-overwrite side — since the operator has
  no means of deleting an initialized DO, coordinate with the tenant to wait for
  re-initialization, or abandon the restore and take re-initialization)
- Backup is **at-least-once**: if the cron dies after the DO's upload completes but before the
  D1 record lands, the next round sees no record and re-backs up (objects are timestamped —
  duplicates are simply never overwritten, and the lifecycle deletes them)
- A restore that fails mid-way clears all tables back to empty. Even if the clear is lost (DO
  eviction), chain_entries is the last table so it falls to the "uninitialized" side, and a
  re-run clears the non-chain remnants before restarting (both trailer-missing and schema-
  mismatch are pinned by tests)
- The backup trailer's audit head is "non-null only when the column is current". Post-restore
  cross-checks assume that premise (§5-2 (5)). An earlier idea had the backup side extend the
  column, but the backup staying read-only (a backup must not trigger a materialization write
  on a 9 GB-scale DO) won out

(d) **Signal validity per growth pattern**: pull-dominated (only var.read grows) — the audit
seq advances, so it is not skipped; it is re-backed up and the census reads size (a test pins
"not skipped after pulls"). Revocation-dominated (remove / rotation.recommended) — same.
Signup-dominated (only D1 grows) — the DO is unchanged and skipped; D1 total is watched by the
workflow; the denial count comes from `user_audit_events` (a test pins window aggregation of
signup_denied rows). Dormant projects — re-backed up every 7 days, ahead of lifecycle deletion
(35 days).

Second round (changing the generation rule): searched for "shapes that emit no signal" — (i)
transitions while the webhook endpoint is down do not advance state, so they are resent next
time (pinned by test). (ii) Evaluation is hourly, so a firing → resolved round trip inside an
hour is never observed (accepted as the tripwire's granularity — short-lived floods are left by
the suppression-marker rows). (iii) If days pass where the sweep runs out of budget before
reaching the end, late-list projects show up in `backup_stale_projects`, which itself becomes
the signal "the budget is insufficient for the scale".

Converged when no new proposals emerged (summarized in the implementation PR body).

## 9. Out of scope and handoffs

- Alchemy v2 (O9) · incidents / the status page (H4 / H5) · SECURITY.md · the threat model
- Throttling of GitHub token requests (gap 9's open-beta opening condition)
- Tenant-facing export (hosted-design §10) — the backup format (NDJSON gzip) is **independent**
  of the tenant-facing transport form; do not assume reuse (purpose and authorization differ —
  DC's rejected option)
- Separating the dedicated audit D1 (gap 4) is reserved in §3 row 1 as the procedure for when
  the monitoring threshold is reached
- The CI web e2e S9 flake (PR #135) is a separate PR
