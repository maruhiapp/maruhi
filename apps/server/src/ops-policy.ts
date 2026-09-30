// Draft values for the operations foundation —
// docs/notes/hosted-ops.md §3 / §4.
//
// These are **not acceptance policy** (operator-side thresholds and
// budgets that do not affect the product's wire or acceptance
// surface). Self-hosted deployments may change them freely. Values
// are revised after measurements from the invite-only beta (the
// restore exercise — hosted-ops.md §5-3).

/** The ops counters' fixed window (1 hour — same granularity as GitHub's secondary rate limit). */
export const OPS_COUNTER_WINDOW_MS = 60 * 60 * 1000;

/** Retention of counter rows (windows older than this are deleted at evaluation — bounding). */
export const OPS_COUNTER_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

/** hosted-ops §3 row 3: the warning threshold for GitHub token requests / hour (80% of 2,000). */
export const OPS_GITHUB_TOKEN_REQUESTS_PER_HOUR_THRESHOLD = 1600;

/** hosted-ops §3 row 5: the warning threshold for signup refusals / hour. */
export const OPS_SIGNUP_DENIED_PER_HOUR_THRESHOLD = 20;

/** hosted-ops §3 row 7: projects with at least this many consecutive failures become a signal. */
export const OPS_BACKUP_CONSECUTIVE_FAILURES_THRESHOLD = 3;

/** hosted-ops §2-B: the re-notification interval for signals that stay active. */
export const OPS_ALERT_RENOTIFY_MS = 24 * 60 * 60 * 1000;

/**
 * hosted-ops §2-D: even when content is unchanged (audit seq and
 * chain seq equal the last success), re-evacuate once this much time
 * has passed since the last success (ahead of the 35-day lifecycle
 * deletion).
 */
export const OPS_BACKUP_REFRESH_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * hosted-ops §3 row 7: projects whose last success is older than
 * this count as "evacuation behind". It is **derived** from the
 * re-evacuation interval + one day of slack (drafted independently, a
 * dormant project whose content never changes and is always skipped
 * would permanently look "behind" inside the re-evacuation interval).
 * The cost of later detection (a sweep budget shortage surfaces in 8
 * days at the earliest) is accepted per §8 (b) second pass (iii), and
 * is revised against the exercise's measurements (§5-3).
 */
export const OPS_BACKUP_STALE_MS = OPS_BACKUP_REFRESH_MS + 24 * 60 * 60 * 1000;

/**
 * hosted-ops §4-2: a DO exceeding this is not evacuated and
 * signals `oversize` (holding the permit bounds tenant wait and the
 * cron's wall clock. Revised after measurement).
 */
export const OPS_BACKUP_MAX_BYTES = 2_000_000_000;

/** hosted-ops §4-3: one sweep's wall-clock budget (inside the 15-minute cron cap). */
export const OPS_SWEEP_BUDGET_MS = 10 * 60 * 1000;

/** hosted-ops §4-3: the cap on projects visited per sweep (inside the subrequest cap). */
export const OPS_SWEEP_MAX_PROJECTS = 2000;

/** The sweep's `projects` enumeration page (one D1 query). */
export const OPS_SWEEP_PAGE_SIZE = 100;

/** hosted-ops §1: the R2 multipart part length (inside the 5 MiB minimum; 640 parts even for 10 GB). */
export const OPS_SNAPSHOT_PART_BYTES = 16 * 1024 * 1024;

/** The row-read page for evacuation (rowid keyset — reads one statement at a time, synchronously). */
export const OPS_SNAPSHOT_ROW_PAGE = 500;

/** The row count per restore transaction (DO SQLite's 100 bound parameters per statement are chunked separately). */
export const OPS_RESTORE_BATCH_ROWS = 1000;

/**
 * The hourly cron string (**keep in sync manually** with
 * cloudflare.config.ts's `triggers` — the same paired note as
 * worker-env.ts's IP_RATE_LIMIT_PERIOD_SECONDS). The scheduled
 * handler branches on this string to the ops jobs (evacuation sweep +
 * evaluation); the rest is session cleanup (daily).
 */
export const OPS_HOURLY_CRON = "23 * * * *";
