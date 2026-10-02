// Server acceptance policy for CRYPTO_SPEC §6.4.
//
// These are not the "consensus rules of chain validity": because the §6.1 field
// limits (consensus rules) bound the canonical size of a spec-conforming entry
// to at most about 516 KiB, this acceptance policy never rejects a
// spec-conforming entry (it cannot cause a chain split). Raising a value does
// not affect the validity of past chains.

import { OIDC_CLOCK_SKEW_MS } from "./oidc.package/index.ts";

/** §6.4: acceptance limit on the canonical byte string (entry_bytes) of one entry. */
export const MAX_ENTRY_CANONICAL_BYTES = 1 * 1024 * 1024;

/** §6.4: acceptance limit on the number of entries in a whole chain. */
export const MAX_CHAIN_ENTRIES = 10_000;

/** §6.4: acceptance limit on cumulative canonical bytes across a whole chain. */
export const MAX_CHAIN_TOTAL_CANONICAL_BYTES = 32 * 1024 * 1024;

/**
 * Raw body limit at the HTTP boundary (implementation detail; the spec only
 * defines limits in terms of canonical byte strings). Set larger than the
 * canonical limit in anticipation of inflation from JSON escaping (nearly 6x
 * in the worst case). Excess is rejected with a bare 413 before JSON parsing
 * (a first line of defense against memory DoS).
 *
 * Basis for 8 MiB: with the registration signature (CRYPTO_SPEC §5.1) added,
 * one wrap is about 500 bytes on the wire, and registering exactly the count
 * limit (10,000 in §12-8) of wraps reaches about 5 MB. So that a count-overflow
 * 422 (dek-wraps-per-request) is not masked and made unreachable by a transport
 * 413, set a value that lets a maximum-count request reach schema validation
 * (assumes ULID-length user_id; at the theoretical extreme — a 1024-byte
 * user_id — the 413 can still bind first, as before — see the AUTH_SPEC §12-8
 * note).
 */
export const MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Data-plane acceptance policy (AUTH_SPEC §12-8; not a consensus rule — raising
// it in self-hosting is free). The 256-character display-name limit is enforced
// by the api-schema Schema (unlike values, it has no dedicated validation
// layer).
// ---------------------------------------------------------------------------

/** §12-8: acceptance limit on a value's ciphertext (ct || tag). */
export const MAX_VALUE_CIPHERTEXT_BYTES = 64 * 1024;

/** §12-8: active environments per project. */
export const MAX_ACTIVE_ENVIRONMENTS = 100;

/** §12-8: environment rows per project (including tombstones; resource protection for ID incineration). */
export const MAX_ENVIRONMENT_ROWS = 1_000;

/** §12-8: active variables per environment. */
export const MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT = 1_000;

/** §12-8: variable rows per environment (including tombstones). */
export const MAX_VARIABLE_ROWS_PER_ENVIRONMENT = 5_000;

/** §12-8: versions per variable. */
export const MAX_VERSIONS_PER_VARIABLE = 1_000;

/**
 * §12-7 (VH): the ciphertext byte budget of one version value range page. A
 * page stops before the version that would exceed it (always at least one
 * version), so a page of 64 KiB values stays near 1 MiB instead of the
 * 100-version cap's ~6.4 MiB (~12.8 MiB as hex). The client pages on.
 */
export const MAX_VERSION_VALUES_PAGE_BYTES = 1024 * 1024;

/**
 * §12-8: limit on the schema description (variables — layout v2) in Unicode
 * code points. Together with the rejection of control characters (newlines
 * included), excess is rejected with 422 (deliberately a different class from
 * the display-name Schema 400 — this one has a dedicated acceptance check).
 * Doubles as DoS suppression and suppression of the injection surface of data
 * reaching agents (ruling CW).
 */
export const MAX_SCHEMA_DESCRIPTION_CODEPOINTS = 1_024;

/** §12-8: cumulative ciphertext bytes per project (amount currently stored; freed by deletion). */
export const MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES = 1024 * 1024 * 1024;

/**
 * §12-8: DEK wraps per request. Set at or above the member-count bound that the
 * chain acceptance policy (10,000 entries) enforces, keeping it compatible
 * with the exact-match requirement on initial registration (§12-6).
 */
export const MAX_DEK_WRAPS_PER_REQUEST = 10_000;

/**
 * §12-8: DEK wrap rows per project (amount currently stored; freed by
 * environment deletion and wrap deletion). A per-request limit alone does not
 * bound accumulation over repeated requests, so this is set three orders of
 * magnitude above realistic usage (members × environments × epochs). The check
 * runs on every wrap-insertion path (DEK registration, environment creation).
 */
export const MAX_PROJECT_DEK_WRAP_ROWS = 1_000_000;

/**
 * §12-8 / CRYPTO_SPEC §6.4: pending proposals per project (four-eyes — PF1).
 * Expired proposals (past `expires_at_ms` on the server clock) are not counted.
 * Freed by withdraw / application. Not a consensus rule (raising it in
 * self-hosting is free).
 */
export const MAX_PENDING_PROPOSALS = 32;

/**
 * CRYPTO_SPEC §6.4: upper bound on `propose`'s `expires_at_ms` = server clock
 * at acceptance + this value (30 days). Without a bound, a far-future deadline
 * could occupy a pending slot and expiry-based exclusion would be ineffective.
 * Not a consensus rule (the §6.2 structural checks only impose a non-negative
 * safe integer).
 */
export const MAX_PROPOSAL_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * §12-8 / CRYPTO_SPEC §6.4: live devices per member (per project — 2026-09-19
 * DK). Counted at `add_device` acceptance against the derived state before
 * acceptance (revoked devices are not counted = freed by `revoke_device` /
 * `remove_member`). Not a consensus rule.
 */
export const MAX_DEVICES_PER_MEMBER = 16;

/**
 * AUDIT_SPEC §7 dismissal operation: dismissal targets per request. Set equal
 * to the per-request DEK wrap limit (the theoretical bound on dismissal
 * targets — the number of flag targets (variable × environment) — is bounded to
 * the same scale).
 */
export const MAX_ROTATION_DISMISSALS_PER_REQUEST = 10_000;

// ---------------------------------------------------------------------------
// Tenant quotas (AUTH_SPEC §11-3 / §12-8; hosted-design.md §3-3). Same
// character as §12-8 = acceptance policy, not a consensus rule (adjustment in
// self-hosting is free — docs/SELF_HOSTING.md "Tenant quotas"). The values are
// draft values, to be adjusted after beta measurements (open-beta release
// condition — hosted-design.md §2-1).
// ---------------------------------------------------------------------------

/**
 * §11-3: active projects per org. "Active" = in v1, all `projects` rows of the
 * org (no delete API exists; revisit tombstone exclusion when deletion is
 * introduced — same section). Since the org-creation API is unimplemented,
 * v1's effective unit is the personal org ≈ per user. The check runs at the
 * init acceptance point (handlers-membership.ts) — after org-authorization
 * verification, before DO init. Even when the limit is reached, the DO is
 * queried report-only, so the §11-3 repair path (already-initialized + missing
 * rows) stays open.
 */
export const MAX_ACTIVE_PROJECTS_PER_ORG = 100;

/**
 * §12-8 DO storage total guard warning threshold (operational log — static
 * message only, once per DO instance). The unit is decimal GB (10^9 bytes): a
 * conservative interpretation that keeps the rejection threshold below the
 * platform floor "10 GB" whether that floor is read in decimal or binary units.
 */
export const DO_STORAGE_WARN_BYTES = 8_000_000_000;

/**
 * §12-8 DO storage total guard rejection threshold. In a DO whose measured
 * `databaseSize` is at or above this value, the content-growth surfaces (value
 * push, variable/environment creation, renames, DEK registration,
 * add_member / grant_server) are rejected with 422 `project-storage-bytes`.
 * Reads, deletions, revocations, rotations, leases, attestations, and
 * checkpoints are still accepted under rejection (explicit enumeration in the
 * same section — storage-guard.ts). This is the only line of defense against
 * reaching 10 GB SQLITE_FULL (a floor where reads work but writes fail —
 * maruhi's delete operations also involve INSERTs, so they fail at the floor
 * and a tenant cannot recover on its own); if the threshold is moved, keep it
 * below the floor.
 */
export const DO_STORAGE_REJECT_BYTES = 9_000_000_000;

/**
 * AUTH_SPEC §11-5: server-fixed page for project listing (D1 candidate order,
 * ascending project_id). Bounds the DO membership checks per call to this
 * count (holding the breakwater against the Workers subrequest limit on the
 * contract side). No client-specified limit — do not create a knob that would
 * move the acceptance-policy value upward.
 */
export const PROJECT_LIST_PAGE_SIZE = 100;

// ---------------------------------------------------------------------------
// Workload-lease acceptance policy (AUTH_SPEC §14-3 / AUDIT_SPEC §3.5). Same
// character as §12-8 = not a consensus rule (raising it in self-hosting is
// free). The 16 KiB limit on oidcToken is enforced by the api-schema Schema
// (same reason as display names — it has no dedicated validation layer).
// ---------------------------------------------------------------------------

/** §14-3: length of a lease's fixed window (1 hour). Shared by issuance and denial records. */
export const LEASE_WINDOW_MS = 60 * 60 * 1000;

/**
 * §14-3: lease issuance count per fixed window (per project). The check runs
 * **after authorization** — placed earlier, even unauthorized callers would get
 * a 429, leaking the project's existence (§11-2). Placed after authorization,
 * only a principal satisfying "allowed issuer's valid signature × on-chain
 * lease_policy match" can consume the window.
 *
 * **Blast radius**: because the window shares one `lease_windows` row across
 * the whole project (= DO), this 300 issues/hour is the **total across all
 * environments × all workload identities** of the project. In a setup where a
 * monorepo keeps prod / staging / dev in one project and several repos' CI draw
 * from it, one active (or runaway) job that exhausts the window leaves the
 * whole project's CI unable to lease for up to an hour. It does not affect
 * existence concealment (the window is unreachable without authorization), but
 * availability-wise it can be a noisy neighbor. v1 takes the simple form per
 * §14-3's "per project" wording — splitting the window by environment ID or
 * claims_digest requires a spec-granularity change, so it is deferred (raising
 * the limit in self-hosting is free per §14-3).
 */
export const MAX_LEASES_PER_WINDOW = 300;

/**
 * AUDIT_SPEC §3.5: recorded rows per fixed window for server.lease_denied.
 * Same discipline as auth.login_failed (excess goes unrecorded — cuts off
 * audit-log inflation by probing).
 */
export const MAX_LEASE_DENIED_ROWS_PER_WINDOW = 100;

/** AUTH_SPEC §16-1: length of the head-attestation fixed window (1 hour). */
export const ATTESTATION_WINDOW_MS = 60 * 60 * 1000;

/**
 * AUTH_SPEC §16-1: head-attestation submissions per fixed window (per member —
 * draft value 60). The check runs **after the membership check** (§11-2 — only
 * chain-derived members can consume the window, so a 429 does not leak the
 * project's existence to non-members) and **before signature verification**
 * (bounding the Ed25519 verification work by rate). Window consumption does not
 * depend on acceptance (one count per processed submission — repeated
 * rejections also consume the window).
 */
export const MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW = 60;

/**
 * §14-1 first-come binding (2026-08-15 ruling — docs/notes/session-24.md):
 * retention margin for binding rows. A row's lifetime is "the token's exp +
 * this margin", and the margin must be **at least the clock skew of time
 * validation** (a mandatory spec requirement): if the binding row for a token
 * that time validation could still accept expires first, replay succeeds during
 * that gap — a precedent of the same-shape inconsistency was pointed out in the
 * 2026 PyPI trusted publishing audit (JWT verification leeway 30 s >
 * replay-cache lifetime 5 s). Deriving it from the skew satisfies this
 * invariant structurally (the 2x is extra margin for drift in GC run times).
 */
export const LEASE_BINDING_RETENTION_MARGIN_MS = 2 * OIDC_CLOCK_SKEW_MS;

/**
 * Sealed value proposals (AUTH_SPEC §14-5 / CRYPTO_SPEC §5.3 — 2026-10-02
 * PF7b). Pending = stored, unexpired, unresolved; the cap is judged after
 * authorization (the mint path is the lease's), so it leaks nothing to a
 * caller that did not match an on-chain lease policy.
 */
export const MAX_PENDING_ROTATION_PROPOSALS = 32;

/** §14-5: `expiresAtMs` at most this far ahead of the server clock at acceptance (30 days — the four-eyes proposal's bound). */
export const MAX_ROTATION_PROPOSAL_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * §14-5: the per-project fixed window of mints (the same hour-long window
 * as leases, under its own `kind` — a job that re-leases in a retry loop
 * must not be able to fill the proposal store or the audit log by
 * re-minting; 60 is far above a weekly rotation cron's need).
 */
export const MAX_ROTATION_PROPOSALS_PER_WINDOW = 60;

/**
 * §11-6 (PF3): one export page carries at most this many rows (the DO
 * reads them in one synchronous statement under the permit — the same
 * discipline as the evacuation's rowid keyset).
 */
export const MAX_EXPORT_PAGE_ROWS = 2000;

/** §11-6: one export page's line text is cut at this many bytes (a page ends after the row that crosses it). */
export const MAX_EXPORT_PAGE_BYTES = 4 * 1024 * 1024;

/**
 * §11-6: the per-project fixed window of exports (first pages — the
 * same hour-long window as leases, under its own `kind`). Twenty whole
 * exports an hour is far above a migration's need and bounds the audit
 * rows and the read load an owner's credential can produce.
 */
export const MAX_EXPORTS_PER_WINDOW = 20;

/**
 * §11-7: a replication page may exceed the export's byte bound by one line
 * (the export ends a page after the line that crosses it); the slack admits
 * the largest line a snapshot carries (a 64 KiB ciphertext row in hex plus
 * its envelope).
 */
export const MAX_MIRROR_PAGE_SLACK_BYTES = 256 * 1024;
