// The DO storage-total guard (AUTH_SPEC §12-8; hosted-design.md
// §3-3 / §8 gap 3).
//
// The project DO's measured SQLite size (`SqlStorage.databaseSize`)
// is gated by two thresholds — warn / reject (policy.ts; draft values
// 8 GB / 9 GB) — so it never reaches the 10 GB SQLITE_FULL floor
// (every insert fails — maruhi's value reads too, with their audit
// row: the floor refuses them rather than serving an unrecorded read).
// The platform still passes a bare DELETE
// at the floor, but maruhi's delete operations carry tombstone,
// deletion-statement, and audit-row INSERTs in the same task, so they
// fail at the floor = the tenant cannot recover on its own. This is
// the sole line of defense covering the audit log's indefinite
// retention (AUDIT_SPEC §5.3). The fact that deletion shrinks
// databaseSize (workerd-measured — equivalent of auto-vacuum; VACUUM
// cannot be issued from the app) is the basis for "freed by
// deletion".
//
// - The check is a pure function (storageGuardDecision — generating
//   8–9 GB for real is unrealistic, so unit tests pass the
//   thresholds as arguments; the same shape as quotas.ts's
//   *Exceeded)
// - The measurement is fetched via the StorageMeter service (tests
//   inject a fixed-size meter and pin the wiring of the acceptance
//   paths — which surfaces get rejected, which still pass under
//   rejection — against the real programs)
// - The surfaces the refusal bites on = the project-content growth
//   surfaces (§12-8's enumeration): value push, variable create /
//   activation / rename / schema re-issue, environment rename,
//   environment-create composite, DEK-wrap registration, add_member
//   / grant_server, and the schemaPolicy change which needs no
//   evacuation / release / remediation yet stacks an audit row. The
//   sealed value proposal mint and its pre-flight refuse at the same
//   level in the workload vocabulary (programs-proposal.ts —
//   `storage-limit`).
//   Reads (including the bulk pull, the version value range and the
//   export that carry an audit append — the evacuation paths),
//   deletions (the release means),
//   revocation / permission-narrowing, rotation composites, leases,
//   head declarations, standalone checkpoints, and dismiss do
//   **not** call it (the surfaces that keep accepting under
//   rejection — same section). The sole exception is a read that
//   requires materializing the audit-head derived column
//   (ensureStorageAdmitsAuditHeadExtension — below). The
//   enumeration of which callers invoke ensure* is the contract,
//   and storage-guard.test.ts pins both directions
// - The check position is after the membership, role, existence
//   (environment / variable), and layout-support-range checks
//   (§11-2 — no project state to non-members; existence is the
//   member-facing 404, and the support range is ruling CR, which
//   puts the honest "update required" error first), and before the
//   semantic checks like CAS / signature verification / quantity
//   policy (resource protection takes priority over semantics)
// - The warning (8 GB) goes to the ops log (aggregation and alerting
//   are picked up by ops-alerts.ts's storage_warn_projects /
//   storage_reject_projects from the storageLevel that ops-backup
//   records). **Static messages only** (§11-5 / hosted-design.md
//   §5-1 — no request-derived identifiers like the project ID =
//   capability). Once each per warn band / reject band within a DO
//   instance's lifetime (firing on every acceptance would make the
//   log a write counter). Operator-side identification goes through
//   the Workers Logs event envelope (the Durable Object id = the
//   image of idFromName).
//   **The observation point sits not only on the growth surfaces but
//   also on the read surfaces that write audit rows (with-values
//   pull, version value range, export, lease)** (observeStorageLevel — it does not refuse): a
//   pull-dominated project crosses the threshold without any
//   growth-surface write, so watching the growth surfaces alone
//   would never warn

import { Context, Effect, Layer } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { DataRejectedError } from "./data/data-plane.ts";
import { rejectData } from "./data/data-plane.ts";
import { DO_STORAGE_REJECT_BYTES, DO_STORAGE_WARN_BYTES } from "./policy.ts";

/** The decision for a measured size (admit < warn < reject). */
export type StorageGuardDecision = "admit" | "warn" | "reject";

export interface StorageGuardThresholds {
  readonly warnBytes: number;
  readonly rejectBytes: number;
}

/** The draft values in policy.ts (§12-8 — decimal GB). */
const STORAGE_GUARD_THRESHOLDS: StorageGuardThresholds = {
  warnBytes: DO_STORAGE_WARN_BYTES,
  rejectBytes: DO_STORAGE_REJECT_BYTES,
};

/**
 * §12-8: the pure function measured size → decision. Thresholds are
 * inclusive (a measurement equal to the rejection threshold is a
 * reject — tips toward the side approaching the floor).
 */
export function storageGuardDecision(
  databaseSizeBytes: number,
  thresholds: StorageGuardThresholds = STORAGE_GUARD_THRESHOLDS,
): StorageGuardDecision {
  if (databaseSizeBytes >= thresholds.rejectBytes) {
    return "reject";
  }
  if (databaseSizeBytes >= thresholds.warnBytes) {
    return "warn";
  }
  return "admit";
}

/** The ops-log bands (once each per DO instance). */
type StorageGuardLogLevel = "warn" | "reject";

interface StorageMeterShape {
  /** The DO SQLite's measured size in bytes. The instantaneous value of SqlStorage.databaseSize (no I/O). */
  readonly databaseSizeBytes: () => number;
  /**
   * Records a once-only ops-log firing. true on the first call
   * (the caller emits the log), false when already emitted. Bound
   * to the DO instance's lifetime (memory); reset on eviction →
   * restart (at most once per restart — dense enough as monitoring
   * input).
   */
  readonly noteLogged: (level: StorageGuardLogLevel) => boolean;
}

/**
 * The measurement fetch point (the tests' injection point).
 * chain-do.ts composes it over the DO's SqlStorage, and
 * storage-guard.test.ts checks the real programs' wiring with a
 * fixed-size meter.
 */
export class StorageMeter extends Context.Service<StorageMeter, StorageMeterShape>()(
  "StorageMeter",
) {}

/** The meter's substance (the construction shared by the SqlStorage version and the tests' fixed-size version). */
export function makeStorageMeter(databaseSizeBytes: () => number): StorageMeterShape {
  const logged = new Set<StorageGuardLogLevel>();
  return {
    databaseSizeBytes,
    noteLogged: (level) => {
      if (logged.has(level)) {
        return false;
      }
      logged.add(level);
      return true;
    },
  };
}

export const storageMeterLayer = (sql: SqlStorage): Layer.Layer<StorageMeter> =>
  Layer.sync(StorageMeter, () => makeStorageMeter(() => sql.databaseSize));

/**
 * Measure → decide → ops log (observation only — does not refuse).
 * Returns the decision.
 *
 * It is the front half of the growth-surface guard
 * (ensureStorageAdmitsGrowth), and is also called by **read
 * surfaces that do not refuse but write audit rows** (with-values
 * pull's and version value range's var.read, export's
 * project.exported, lease's server.* — §12-8's enumeration (a)(e)):
 * a project whose dominant growth term is var.read (pull-dominated
 * projects, as SELF_HOSTING describes) can pass 8 GB → 9 GB with no
 * growth-surface write, so placing the warning observation point
 * only on growth surfaces would break the "the warning band buys
 * the operator response time" design for pull-dominated projects.
 * databaseSize is instantaneous and carries no I/O, so placing it
 * on pull's hot path costs nothing.
 */
export const observeStorageLevel: Effect.Effect<StorageGuardDecision, never, StorageMeter> =
  Effect.gen(function* () {
    const meter = yield* StorageMeter;
    const decision = storageGuardDecision(meter.databaseSizeBytes());
    if (decision === "warn" && meter.noteLogged("warn")) {
      // Static message only (no variable values like project ID or
      // size — the size is the monitoring system's domain; this is
      // the one line stating "it was reached")
      yield* Effect.logWarning(
        "project storage crossed the warning threshold (AUTH_SPEC §12-8 DO storage guard); growth writes are still accepted until the rejection threshold",
      );
    }
    if (decision === "reject" && meter.noteLogged("reject")) {
      yield* Effect.logError(
        "project storage reached the rejection threshold (AUTH_SPEC §12-8 DO storage guard); growth writes are rejected until space is freed — reads, deletions, revocations and rotations remain accepted",
      );
    }
    return decision;
  });

/**
 * The guard the acceptance programs of content-growth surfaces
 * call (§12-8). A reject decision refuses with limit-exceeded
 * (resource `project-storage-bytes`, limit = the rejection
 * threshold); a warn accepts while emitting one ops-log entry
 * (observeStorageLevel). The enumeration of surfaces that do not
 * call it (reads, deletions, revocations, rotations, etc.) is in
 * the header comment and the spec's explicit enumeration.
 */
export const ensureStorageAdmitsGrowth: Effect.Effect<void, DataRejectedError, StorageMeter> =
  Effect.gen(function* () {
    if ((yield* observeStorageLevel) !== "reject") {
      return;
    }
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "project-storage-bytes",
      limit: DO_STORAGE_REJECT_BYTES,
    });
  });

/**
 * The guard for paths that read the audit-head derived column
 * (AUDIT_SPEC §5.1 — lazy materialization) (`GET /audit-head`,
 * checkpoint notarization with a non-empty audit_head_hash).
 * Read-shaped, but when the column is short of MAX(seq),
 * materializing it carries **a write proportional to the audit
 * row count** (one hash row + index per row — tens of percent of
 * the audit table), and could eat the 1 GB of slack between the
 * rejection threshold and the floor single-handedly (the first
 * materialization of a project that reached 9 GB unnotarized).
 * So it is judged as a growth surface **only when materialization
 * is needed** — with the column up to date it is a pure read and
 * passes even under rejection (§12-8's enumeration (a) exception
 * note). The same line stops the export's materialization (null
 * trailer head — programs-export.ts) and a restore's head storage
 * (chain-do.ts): no path extends the column at or above it.
 */
export const ensureStorageAdmitsAuditHeadExtension: Effect.Effect<
  void,
  DataRejectedError,
  StorageMeter | AuditStore
> = Effect.gen(function* () {
  const audit = yield* AuditStore;
  if (audit.headColumnBehindSync()) {
    yield* ensureStorageAdmitsGrowth;
  }
});
