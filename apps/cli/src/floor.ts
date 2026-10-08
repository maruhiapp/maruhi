// The local floor's semantics (CRYPTO_SPEC §6.3).
//
// The floor = **the monotonic join (join-semilattice) of the facts that
// have passed verification so far**, not "the snapshot of the last
// successful pull" (3-D). The storage form is an append-only observation
// log + fold (3-E — floor-log.ts, with the fold in floor-log-fold.ts);
// this module holds only the lattice's types and the join operations.
// The on-disk merge and the in-process merge share **one and the same
// join implementation** (session-31 §3 — structurally removing the
// breeding ground where a duplicated "`>=` last-wins" implementation
// overwrote same-version different-hash evidence).
//
// Epoch observations join as two typed coordinates kept apart (the §6.3
// norm):
//   (i) the pull baseline of value rule (c) (pullEpoch) — advanced only
//       by observations established atomically with value-floor coverage
//       (never advanced by a chain sync alone)
//   (ii) the environment-level epoch observation (observedEpoch) — used
//       for manifest rule (c) baselines and rollback detection; joined
//       regardless of provenance
//
// Facts incomparable at the same coordinate (same version, different
// hash) have no defined join = **typed conflict**, preserving the
// evidence of both observations (rule (b) becomes the merge semantics
// itself). Using or updating a floor holding a conflict is refused by
// the caller.
//
// Every coordinate is a semilattice with a bottom (0 / "" / no record),
// expressing partial observations (metadata-only pulls' environment
// level, push-only variable floors) without impossible states — a check
// rule over bottom structurally never fires (zero false detections).
//
// **No plaintext values, key material, variable names, or environment
// names are written** (keys are all IDs; the content is only hashes,
// sequence numbers, and op kinds — compatible with the diskless
// invariant).

import { dirname, join } from "node:path";

import {
  type EnvironmentId,
  isVariableId,
  type ProjectId,
  type UserId,
  type VariableId,
} from "@maruhi/core";
import { Context, type Effect } from "effect";

import type { CliError } from "./errors.ts";

/** The last verified chain head (a §6.3 floor's stored item). */
export interface ChainHeadFloor {
  readonly seq: number;
  readonly hashHex: string;
}

/**
 * One variable's floor (active = latest value + latest statement,
 * deleted = tombstone, declared = layout v3's no-value-set declaration —
 * CRYPTO_SPEC §4.2).
 *
 * declared holds the meta side only (the value floor stays empty until
 * activation — session-46 §8 round 1). Rule (c)'s "a variable absent
 * from the floor counts as version 0" applies naturally to the first
 * pull after activation (no value-side baseline is fabricated).
 */
export type VariableFloor =
  | {
      readonly status: "active";
      readonly version: number;
      /** That version's epoch (§4.1 monotonicity / rule (c) check material). */
      readonly epoch: number;
      /** The latest version's value signed-bytes hash (rule (b)'s comparison target). */
      readonly valueSigHashHex: string;
      readonly metaVersion: number;
      /** The latest metaVersion's signed-bytes hash (the meta floor is for rollback detection only — §14.3-5). */
      readonly metaSigHashHex: string;
    }
  | {
      readonly status: "declared";
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    }
  | {
      readonly status: "deleted";
      readonly metaVersion: number;
      readonly metaSigHashHex: string;
    };

/**
 * The environment manifest's floor (CRYPTO_SPEC §6.3 — manifest_version
 * / its epoch / signed_bytes hash). Detection material for rule (a)
 * regression, (b) same-version difference, and (c) manifest application
 * (an old-epoch injection on an advanced manifestVersion).
 */
export interface ManifestFloor {
  readonly manifestVersion: number;
  /** The epoch that manifest baked in (material for rule (c)'s manifest application). */
  readonly epoch: number;
  readonly manifestSigHashHex: string;
}

/**
 * One environment's floor. Each coordinate is an independently-joined
 * semilattice, and bottom (pullEpoch / observedEpoch / metaVersion = 0)
 * means "no observation at that coordinate yet".
 */
export interface EnvironmentFloor {
  /**
   * Rule (c)'s baseline: advanced only by an observation established
   * atomically with value-floor coverage (a verified pull, an
   * environment-creation acceptance confirmation [empty variable set]).
   * **A chain sync alone must never advance it** (the §6.3 norm — both
   * edges: misrejecting a legitimate old-epoch value right after a
   * rotation, and losing detection through a missing baseline).
   * 0 = not established.
   */
  readonly pullEpoch: number;
  /**
   * The environment-level epoch observation (§6.3's coordinate (ii)).
   * Used for manifest rule (c)'s baseline and joined regardless of
   * provenance (metadata-only pull, acceptance confirmation, pull with
   * values). Having no path that could misreject a value, it advances
   * more broadly than the pull baseline. 0 = unobserved.
   */
  readonly observedEpoch: number;
  /** The environment-meta statement's floor (rollback detection only — forward injection is not guaranteed, §14.3-5). 0 = unobserved. */
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  /** The environment manifest's floor (§6.3). Absent = no manifest observation. */
  readonly manifest?: ManifestFloor;
  /** Keys are variableIds (names are never written). */
  readonly variables: Readonly<Record<string, VariableFloor>>;
}

/**
 * Two incomparable observations at the same coordinate (join undefined)
 * = a typed equivocation conflict. Preserves the evidence of both
 * observations (version and hash) — evidence loss via overwrite is
 * inexpressible under the storage form (append-only log), and fold
 * surfaces it in this shape (§6.3).
 */
export interface FloorConflict {
  readonly kind:
    | "chain-head"
    | "value"
    | "variable-meta"
    | "environment-meta"
    | "manifest"
    | "undeletion";
  readonly environmentId: EnvironmentId | null;
  readonly variableId: VariableId | null;
  /** Observation 1 (seq / version / metaVersion / manifestVersion and its signed-bytes hash). */
  readonly firstVersion: number;
  readonly firstHashHex: string;
  /** Observation 2. */
  readonly secondVersion: number;
  readonly secondHashHex: string;
}

/** The op kind of a security-critical mutation's intent record (§6.3 recording discipline (ii)). */
export type FloorIntentOp =
  | "create_environment"
  | "rotate_epoch"
  | "meta-op"
  | "delete_environment";

/** An intent's resolution (the effect-check result of §12-10 (3)). */
export type FloorIntentOutcome =
  | "accepted"
  | "accepted-superseded"
  | "rejected"
  | "not-accepted"
  | "superseded";

/**
 * The pre-send intent record (3-F — journal-before-send). Non-sensitive
 * coordinates only: op kind, environment ID, manifest_version +
 * signed_bytes hash, declared head, and the effect-check's matching
 * material (compound = the DEK commitment, meta op = the variable ID).
 * An intent is not a verified fact and does not enter the join's lattice
 * — fold surfaces an unresolved intent as "needs reconciliation".
 * A deletion issues no manifest, so its intent is the separate shape
 * {@link DeletionFloorIntent}.
 */
export type FloorIntent = ManifestFloorIntent | DeletionFloorIntent;

/** An intent of a mutation that issues a manifest (environment creation / rotation composites, meta operations). */
export interface ManifestFloorIntent {
  readonly id: string;
  readonly op: Exclude<FloorIntentOp, "delete_environment">;
  readonly environmentId: EnvironmentId;
  /** The epoch the compound establishes (create = 1 / rotate = new_epoch). A meta op = the current epoch at issuance. */
  readonly epoch: number;
  /** The compound's effect-check material (the §5.2 commitment of one's own entry on the chain). A meta op = null. */
  readonly dekCommitmentHex: string | null;
  /** The matching coordinate of a meta op (variable creation). A compound, or a meta op on the environment's own statement (env rename), = null. */
  readonly variableId: VariableId | null;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly declaredHead: ChainHeadFloor;
}

/**
 * The intent of an environment deletion composite (2026-10-07 — CRYPTO_SPEC
 * §6.2 delete_environment): no manifest is issued, so the matching material
 * is only the entry itself — the delete_environment of this environment in
 * the slot after the declared head (the CAS fixes where it can land).
 */
export interface DeletionFloorIntent {
  readonly id: string;
  readonly op: "delete_environment";
  readonly environmentId: EnvironmentId;
  readonly declaredHead: ChainHeadFloor;
}

/** An intent record's input (the id is assigned by the store). */
export type FloorIntentInput = Omit<ManifestFloorIntent, "id"> | Omit<DeletionFloorIntent, "id">;

/** One project's floor = the observation log's fold result (a derived value). */
export interface ProjectFloor {
  /** null = no head observation yet (e.g. an intents-only log). */
  readonly chainHead: ChainHeadFloor | null;
  /** Keys are environmentIds. */
  readonly environments: Readonly<Record<string, EnvironmentFloor>>;
  /** The evidence of same-coordinate conflicts (survives being folded into a snapshot — §6.3). */
  readonly conflicts: readonly FloorConflict[];
  /** Unresolved intents (needs reconciliation — resolved before the next mutation on the same environment or any success report). */
  readonly intents: readonly FloorIntent[];
}

/**
 * The evidence record of a contradicting head attestation (CRYPTO_SPEC
 * §6.6 reconciliation (a) / §14.2-5). Stores the attestation in full
 * (including the signature — the non-repudiable material that passed
 * §6.6 verification) paired with the digest of one's own chain view.
 * **Not entered into the floor's join lattice**: an attestation is
 * another member's signed declaration, not "one's own verified
 * observation", and flowing it into the lattice would let one member's
 * false head attestation (leaked key) cause every command's permanent
 * refusal. Stored in an append-only evidence file (floor-log.ts —
 * <projectId>.attestation-evidence.jsonl). Contains no plaintext values
 * or key material (IDs, hashes, signatures only).
 */
export interface AttestationEvidenceRecord {
  /** The distributed attestation itself (already passed §6.6 verification — the signature is the evidence's body). */
  readonly attestation: {
    readonly suite: string;
    readonly attesterUserId: UserId;
    readonly attesterKeyFingerprintHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
  /** The digest of one's own view (verified chain) at reconciliation time. */
  readonly localView: {
    readonly headSeq: number;
    readonly headHashHex: string;
    /** One's own view's entry hash at the attested seq position (empty = the attested seq is ahead of one's own head). */
    readonly entryHashAtAttestedSeq: string;
  };
  /** The detection trigger (mismatch = a difference at seq ≤ one's own head, unresolved = still unresolved after a bounded resync). */
  readonly kind: "head-mismatch" | "unresolved-after-resync";
  /** The local detection time (for forensics — non-sensitive local state, never distributed). */
  readonly detectedAtMs: number;
}

/** The result of loading the floor log (fail-open — the caller emits per-state warnings). */
export interface FloorLoadResult {
  readonly floor: ProjectFloor | null;
  /** missing = first sync (no floor), corrupt = corrupted (treated as first run but warned distinctly). */
  readonly state: "loaded" | "missing" | "corrupt";
  /**
   * The number of non-empty lines that failed to decode and were skipped
   * (the trace of torn-line self-healing). When non-zero the caller
   * warns — partial corruption is not silently turned into "less
   * detection material" (the same visibility level as the
   * whole-corruption corrupt warning).
   */
  readonly droppedRecords: number;
}

/** The atomic commit on pull success (rule (c) baseline + variable floor + chain head in one record). */
export interface PullCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly environment: EnvironmentFloor;
}

/** The commit on push acceptance (promotes one's own signed latest version to the floor). */
export interface PushCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly variable: VariableFloor;
}

/**
 * The environment-level commit of a metadata-only pull (session-31 §3).
 * Fabricates no value floor and never advances the pull baseline (rule
 * (c)) — only the environment meta floor, manifest floor, the
 * environment-level epoch observation (coordinate (ii)), and the chain
 * head advance.
 */
export interface MetadataCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  /** The chain-derived current epoch (coordinate (ii) — joined regardless of provenance). */
  readonly observedEpoch: number;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly manifest: ManifestFloor;
}

/**
 * Floor promotion of one's own manifest whose acceptance is confirmed
 * (session-31 §3). pullEpoch and the variable floor are not moved. The
 * environment-level epoch observation is joined at the manifest's epoch
 * (a verified observation — coordinate (ii)).
 */
export interface ManifestCommit {
  readonly chainHead: ChainHeadFloor;
  readonly environmentId: EnvironmentId;
  readonly manifest: ManifestFloor;
}

/**
 * Load / commit boundary for the local floor log (§6.3). Every commit is
 * "append (through fsync-equivalent durability — 3-E′) → fold", and a
 * fold that detects a same-coordinate conflict fails with a typed error
 * (the evidence remains in the log).
 */
export interface FloorStoreShape {
  readonly load: (projectId: ProjectId) => Effect.Effect<FloorLoadResult, CliError>;
  /** Head advancement on a successful chain sync (rule (c)'s baseline is not moved). */
  readonly commitHead: (
    projectId: ProjectId,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /** The floor commit of a verified pull. Returns the folded (= persisted to the log) environment floor. */
  readonly commitPull: (
    projectId: ProjectId,
    commit: PullCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /** Variable-floor advancement of an accepted push (rule (c)'s baseline pullEpoch is not moved). */
  readonly commitPush: (
    projectId: ProjectId,
    commit: PushCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /** The environment-level commit of a metadata-only pull (no value floor is fabricated). */
  readonly commitMetadata: (
    projectId: ProjectId,
    commit: MetadataCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /** Floor promotion of an acceptance-confirmed manifest. */
  readonly commitManifest: (
    projectId: ProjectId,
    commit: ManifestCommit,
  ) => Effect.Effect<EnvironmentFloor, CliError>;
  /**
   * The pre-send intent of a security-critical mutation (3-F). Sending
   * may proceed only after the append's durability (fsync-equivalent) —
   * on failure nothing is sent (fail-closed). Returns the assigned
   * intent id.
   */
  readonly appendIntent: (
    projectId: ProjectId,
    intent: FloorIntentInput,
  ) => Effect.Effect<string, CliError>;
  /** Appending the resolution record that closes an intent with the effect-check's result. */
  readonly resolveIntent: (
    projectId: ProjectId,
    intentId: string,
    outcome: FloorIntentOutcome,
  ) => Effect.Effect<void, CliError>;
  /**
   * The head of the previously submitted head attestation (the decision
   * material for CRYPTO_SPEC §6.3's head-gossip "submit if advanced past
   * the previous attestation"). A separate class not entered into the
   * floor's join lattice: it is one's own send record, not a verified
   * observation, and the consequence of losing it is only "a
   * resubmission of the same seq (idempotent 204 on the server side)" —
   * it bears no safety. missing / corrupt = null (best-effort).
   */
  readonly loadAttestedHead: (
    projectId: ProjectId,
  ) => Effect.Effect<ChainHeadFloor | null, CliError>;
  /** Updating the previous attestation after a successful submission (overwritable non-sensitive local state). */
  readonly saveAttestedHead: (
    projectId: ProjectId,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * Appending evidence of a contradicting head attestation (§6.6
   * reconciliation (a) — append-only JSONL, format is
   * AttestationEvidenceRecord). Returns the destination path (a lead-in
   * for the warning message).
   */
  readonly appendAttestationEvidence: (
    projectId: ProjectId,
    evidence: AttestationEvidenceRecord,
  ) => Effect.Effect<string, CliError>;
  /**
   * The project IDs with a floor record (reads only file names — never
   * the contents or the format). There is one floor per config-file
   * location, so projects of other servers / accounts mix in. Never used
   * as decision material (only information supplementing the range of
   * `device add`'s "nowhere to be found" — DK K13-7).
   */
  readonly listProjectIds: () => Effect.Effect<readonly ProjectId[], CliError>;
}

export class FloorStore extends Context.Service<FloorStore, FloorStoreShape>()("cli/FloorStore") {}

/** The floor directory (sibling of the config: <config.json's parent>/floor). */
export function floorDirOf(configPath: string): string {
  return join(dirname(configPath), "floor");
}

/**
 * Own-property lookup for floor records. `constructor` / `prototype` are
 * legitimate IDs under §12-1, so a plain bracket lookup would resolve "an
 * ID absent from the record" to an Object.prototype inherited property
 * (a function) and misbehave. Every dynamic key lookup on a floor record
 * must go through this.
 */
export function floorRecordGet<T>(
  record: Readonly<Record<string, T>> | undefined,
  key: string,
): T | undefined {
  return record !== undefined && Object.hasOwn(record, key) ? record[key] : undefined;
}

/** An environment floor with every coordinate at bottom (the join pedestal for partial observations). */
export function emptyEnvironmentFloor(): EnvironmentFloor {
  return { pullEpoch: 0, observedEpoch: 0, metaVersion: 0, metaSigHashHex: "", variables: {} };
}

/** The receptacle for same-coordinate conflicts detected during a join. */
export type ConflictSink = (conflict: FloorConflict) => void;

// The join's conflict paths need the record keys' brand back (a Record's
// string index erases it); the decode side already enforced the §12-1
// form (floor-log-decode.ts's keysAreIds), so an out-of-form key is an
// internal inconsistency, not untrusted input to validate
export function floorKeyAsVariableId(key: string): VariableId {
  if (!isVariableId(key)) {
    throw new Error(`floor record has a variable key out of the id form: ${key}`);
  }
  return key;
}

interface VersionedEvidence {
  readonly version: number;
  readonly hashHex: string;
}

/**
 * Same version, different hash = join undefined. The evidence flows to
 * the sink, and the representative is **the lexicographically larger
 * hash** (commutative and idempotent — a deterministic representative
 * independent of fold order. Since the conflict's existence itself is
 * the refusal-to-use condition, the representative's choice does not
 * affect detection).
 */
function joinVersioned<T extends VersionedEvidence>(
  a: T,
  b: T,
  conflict: (first: VersionedEvidence, second: VersionedEvidence) => FloorConflict,
  sink: ConflictSink,
): T {
  if (a.version !== b.version) {
    return a.version > b.version ? a : b;
  }
  if (a.hashHex === b.hashHex) {
    return a;
  }
  sink(conflict(a, b));
  return a.hashHex > b.hashHex ? a : b;
}

/** Joining chain heads (seq advancement only. Same seq, different hash = evidence of a fork). */
export function joinChainHead(
  existing: ChainHeadFloor | null,
  incoming: ChainHeadFloor,
  sink: ConflictSink,
): ChainHeadFloor {
  if (existing === null) {
    return incoming;
  }
  const joined = joinVersioned(
    { version: existing.seq, hashHex: existing.hashHex },
    { version: incoming.seq, hashHex: incoming.hashHex },
    (first, second) => ({
      kind: "chain-head",
      environmentId: null,
      variableId: null,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return { seq: joined.version, hashHex: joined.hashHex };
}

function metaConflict(
  kind: "variable-meta" | "environment-meta",
  environmentId: EnvironmentId,
  variableId: VariableId | null,
): (first: VersionedEvidence, second: VersionedEvidence) => FloorConflict {
  return (first, second) => ({
    kind,
    environmentId,
    variableId,
    firstVersion: first.version,
    firstHashHex: first.hashHex,
    secondVersion: second.version,
    secondHashHex: second.hashHex,
  });
}

interface MetaSide {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

function joinMetaSide(
  environmentId: EnvironmentId,
  variableId: VariableId | null,
  a: MetaSide,
  b: MetaSide,
  sink: ConflictSink,
): MetaSide {
  const joined = joinVersioned(
    { version: a.metaVersion, hashHex: a.metaSigHashHex },
    { version: b.metaVersion, hashHex: b.metaSigHashHex },
    metaConflict(
      variableId === null ? "environment-meta" : "variable-meta",
      environmentId,
      variableId,
    ),
    sink,
  );
  return { metaVersion: joined.version, metaSigHashHex: joined.hashHex };
}

/** Joining deleted (terminal) with live (active | declared): a live observation after deletion = evidence of undeletion. */
function joinDeletedWithLive(
  environmentId: EnvironmentId,
  variableId: VariableId,
  deleted: Extract<VariableFloor, { status: "deleted" }>,
  live: Extract<VariableFloor, { status: "active" | "declared" }>,
  sink: ConflictSink,
): VariableFloor {
  if (live.metaVersion > deleted.metaVersion) {
    // deleted is a terminal state (§4.2) — an active / declared
    // observation at a metaVersion beyond it has no legitimate path
    // (evidence of unauthorized resurrection; a transition to declared is
    // also forbidden — ruling CS). The representative stays deleted
    sink({
      kind: "undeletion",
      environmentId,
      variableId,
      firstVersion: deleted.metaVersion,
      firstHashHex: deleted.metaSigHashHex,
      secondVersion: live.metaVersion,
      secondHashHex: live.metaSigHashHex,
    });
  } else if (live.metaVersion === deleted.metaVersion) {
    // A different status at the same metaVersion always means different signed bytes = rule (b)
    sink({
      kind: "variable-meta",
      environmentId,
      variableId,
      firstVersion: deleted.metaVersion,
      firstHashHex: deleted.metaSigHashHex,
      secondVersion: live.metaVersion,
      secondHashHex: live.metaSigHashHex,
    });
  }
  return deleted;
}

/**
 * Joining two live (active | declared) floors: the value side (version —
 * only active has it) and the meta side (metaVersion) join independently.
 * A declared value observation does not exist (§4.2 — the value floor is
 * empty until activation), and an active value observation is never
 * invalidated by a declared observation (no legitimate active → declared
 * transition exists — ruling CS), so when either side is active the
 * representative is active (value side retained).
 */
function joinLiveVariableFloor(
  environmentId: EnvironmentId,
  variableId: VariableId,
  existing: Extract<VariableFloor, { status: "active" | "declared" }>,
  incoming: Extract<VariableFloor, { status: "active" | "declared" }>,
  sink: ConflictSink,
): VariableFloor {
  const meta = joinMetaSide(environmentId, variableId, existing, incoming, sink);
  if (existing.status === "declared" || incoming.status === "declared") {
    // At most one side is active: the value observation comes from that side only (declared has no value side)
    const active =
      existing.status === "active" ? existing : incoming.status === "active" ? incoming : null;
    if (active === null) {
      return { status: "declared", ...meta };
    }
    return {
      status: "active",
      version: active.version,
      epoch: active.epoch,
      valueSigHashHex: active.valueSigHashHex,
      ...meta,
    };
  }
  const value = joinVersioned(
    { version: existing.version, hashHex: existing.valueSigHashHex, epoch: existing.epoch },
    { version: incoming.version, hashHex: incoming.valueSigHashHex, epoch: incoming.epoch },
    (first, second) => ({
      kind: "value",
      environmentId,
      variableId,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return {
    status: "active",
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.hashHex,
    ...meta,
  };
}

/**
 * Joining variable floors. deleted is a terminal state (never
 * overwritten by active / declared); live pairs go through
 * joinLiveVariableFloor. Both inputs are observations that passed §6.3
 * verification, so every same-coordinate difference is evidence of
 * equivocation.
 */
function joinVariableFloor(
  environmentId: EnvironmentId,
  variableId: VariableId,
  existing: VariableFloor | undefined,
  incoming: VariableFloor,
  sink: ConflictSink,
): VariableFloor {
  if (existing === undefined) {
    return incoming;
  }
  // Only one side deleted: regardless of metaVersion ordering, deleted
  // (terminal) is the representative. If the live side advanced past the
  // deleted it is undeletion; if the same version it is rule (b) evidence
  // — joinDeletedWithLive flows it to the sink
  if (existing.status === "deleted") {
    if (incoming.status === "deleted") {
      const meta = joinMetaSide(environmentId, variableId, existing, incoming, sink);
      return { status: "deleted", ...meta };
    }
    return joinDeletedWithLive(environmentId, variableId, existing, incoming, sink);
  }
  if (incoming.status === "deleted") {
    return joinDeletedWithLive(environmentId, variableId, incoming, existing, sink);
  }
  return joinLiveVariableFloor(environmentId, variableId, existing, incoming, sink);
}

/** Joining manifest floors (manifestVersion advancement only. Same version, different hash = evidence of a fork). */
function joinManifestFloor(
  environmentId: EnvironmentId,
  existing: ManifestFloor | undefined,
  incoming: ManifestFloor | undefined,
  sink: ConflictSink,
): ManifestFloor | undefined {
  if (existing === undefined || incoming === undefined) {
    return existing ?? incoming;
  }
  const joined = joinVersioned(
    {
      version: existing.manifestVersion,
      hashHex: existing.manifestSigHashHex,
      epoch: existing.epoch,
    },
    {
      version: incoming.manifestVersion,
      hashHex: incoming.manifestSigHashHex,
      epoch: incoming.epoch,
    },
    (first, second) => ({
      kind: "manifest",
      environmentId,
      variableId: null,
      firstVersion: first.version,
      firstHashHex: first.hashHex,
      secondVersion: second.version,
      secondHashHex: second.hashHex,
    }),
    sink,
  );
  return {
    manifestVersion: joined.version,
    epoch: joined.epoch,
    manifestSigHashHex: joined.hashHex,
  };
}

/**
 * Joining environment floors (each coordinate independently):
 * pullEpoch / observedEpoch take the max, meta / manifest join by
 * version advancement + evidencing same-version differences, variables
 * take a monotonic union.
 */
export function joinEnvironmentFloor(
  environmentId: EnvironmentId,
  existing: EnvironmentFloor | undefined,
  incoming: EnvironmentFloor,
  sink: ConflictSink,
): EnvironmentFloor {
  if (existing === undefined) {
    return incoming;
  }
  const meta =
    existing.metaVersion === 0
      ? { metaVersion: incoming.metaVersion, metaSigHashHex: incoming.metaSigHashHex }
      : incoming.metaVersion === 0
        ? { metaVersion: existing.metaVersion, metaSigHashHex: existing.metaSigHashHex }
        : joinMetaSide(environmentId, null, existing, incoming, sink);
  const manifest = joinManifestFloor(environmentId, existing.manifest, incoming.manifest, sink);
  // union: a legitimate floor's variable keys never disappear (a deletion
  // also stays as a tombstone record), so a variable present on only one
  // side is kept
  const variables: Record<string, VariableFloor> = { ...existing.variables };
  for (const [key, variable] of Object.entries(incoming.variables)) {
    // A variables map's keys satisfy §12-1's form by construction (the
    // decode side's keysAreIds refuses an out-of-form key —
    // floor-log-decode.ts). A Record's string index erases the brand,
    // so the conflict paths take it back through the same guard; an
    // out-of-form key at this point is an internal inconsistency
    const variableId = floorKeyAsVariableId(key);
    variables[variableId] = joinVariableFloor(
      environmentId,
      variableId,
      floorRecordGet(existing.variables, variableId),
      variable,
      sink,
    );
  }
  return {
    pullEpoch: Math.max(existing.pullEpoch, incoming.pullEpoch),
    observedEpoch: Math.max(existing.observedEpoch, incoming.observedEpoch),
    ...meta,
    ...(manifest === undefined ? {} : { manifest }),
    variables,
  };
}
