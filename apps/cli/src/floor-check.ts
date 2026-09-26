// The local floor's detection rules ((a)(b)(c) of CRYPTO_SPEC §6.3) and the
// norm for update ordering.
//
// Everything checked has already passed the §6.3 signature verification of
// distributed data (values.ts). A disagreement with the floor is "a
// contradiction between properly signed data", so a detection is
// non-repudiable evidence of server equivocation or forgery (by a key inside
// its membership interval) — no false-positive concern — and every case is
// therefore refused (the strong side of §6.3's "reject vs warn").
//
// - Rule (a): chain shortening, rollback of version / metaVersion / epoch,
//   unauthorized undeletion
// - Rule (b): differing signed bytes for the same version / metaVersion as
//   the floor (evidence of content replacement or a fork)
// - Rule (c): rejecting a distribution whose epoch, on a version newer than
//   the floor's version, is below that environment's pull-time epoch baseline
//   (pullEpoch) (detecting "old-epoch injection into an advanced version" by
//   a deleted member's key — §14.3-5). The baseline uses the last successful
//   pull's value and is never advanced by a chain sync alone (both edges:
//   false rejection and loss of detection).
//
// **A meta-statement's floor detects rollback only**: meta carries no epoch
// anchor (§4.2), so an injected advanced metaVersion is not detected even
// with a floor (§14.3-5 — the most important non-guarantee; do not put a
// check here that could be mistaken for "detected").

import type { MetaVarType } from "@maruhi/crypto";
import { Effect } from "effect";

import type { CliError } from "./errors.ts";
import { isServerRejection } from "./failure.ts";
import {
  type ChainHeadFloor,
  type EnvironmentFloor,
  type FloorConflict,
  type FloorIntent,
  type FloorIntentInput,
  type FloorIntentOutcome,
  floorRecordGet,
  type FloorStoreShape,
  joinEnvironmentFloor,
  type ManifestFloor,
  type MetadataCommit,
  type ProjectFloor,
  type VariableFloor,
} from "./floor.ts";
import type { VerifiedManifest } from "./manifest.ts";
import type { VerifiedProject } from "./sync.ts";
import type { VerifiedPulledValue } from "./values.ts";

/** Evidence material of a verified meta-statement, including deleted / declared (variables only — §4.2 layout v2). */
export interface VerifiedMetaEvidence {
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  /** The distributed author signature and attribution (self-contained evidence — §14.2-5). */
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/** A verified tombstone (a deleted statement). */
export interface VerifiedTombstone extends VerifiedMetaEvidence {
  readonly variableId: string;
  /** A verified deleted statement's name (keeps the immediately preceding active name — §4.2). */
  readonly name: string;
}

/** The input of a floor check (a digest of a pull response that passed all §6.3 verification). */
export interface VerifiedPullSnapshot {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedPulledValue[];
  /**
   * Verified declared statements (valueless — §4.2 layout v2 / §12-7's
   * declaredVariables). In a value-bearing response, declared variables not
   * being distributed a value is legitimate (declared is the only legitimate
   * valueless state — CRYPTO_SPEC §6.3).
   */
  readonly declared: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  /**
   * The verified manifest (§4.3). null only when the migration path
   * (--init-manifest) permitted the omission — on the normal path values.ts
   * has already refused an omission before the floor check.
   */
  readonly manifest: VerifiedManifest | null;
}

/**
 * The verified digest of a metadata-only pull (§12-7). Since it carries no
 * values, the floor check is limited to the meta level (the meta part of
 * rules (a)(b) + omission and undeletion) — value rollback, equivocation,
 * and rule (c) cannot be checked from this shape (never pretend they were
 * checked: the value-level floor check belongs to value-bearing pulls).
 */
export interface VerifiedMetadataSnapshot {
  readonly environment: VerifiedMetaEvidence;
  /** Verified statements of all non-deleted variables (active and declared mixed — §12-7). */
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  /** The verified manifest (omission already refused by values.ts — no migration tolerance on a metadata-only pull). */
  readonly manifest: VerifiedManifest;
}

/**
 * The schema column of layout v2 (from a verified statement — CRYPTO_SPEC
 * §4.2). The type is a **declaration** and agreement with the value is not
 * guaranteed (§14.3-7 — display and validation are advisory).
 */
export interface VerifiedSchemaFields {
  readonly varType: MetaVarType;
  readonly required: boolean;
  readonly description: string;
}

/**
 * A verified variable statement (one variable of a metadata-only pull — both
 * active and declared flow, §12-7; the status field discriminates).
 */
export interface VerifiedVariableStatement extends VerifiedMetaEvidence {
  readonly variableId: string;
  /** The verified statement's name (name resolution trusts nothing else — §12-2). */
  readonly name: string;
  /** The wire's layoutVersion (omitted = 1 — §12-2). */
  readonly layoutVersion: number;
  /** The schema column of layout v2 (null for a v1 statement). */
  readonly schema: VerifiedSchemaFields | null;
}

/** Evidence material of a distributed value side (coordinates, hashes, declared head, signature and attribution). */
export interface PulledValueEvidence {
  readonly version: number;
  readonly epoch: number;
  readonly valueSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  /** The distributed writer signature and attribution (self-contained evidence — §14.2-5). */
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/** The floor-side (previously verified) meta record. */
export interface FloorMetaEvidence {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/** An active variable floor (the basis of value-side evidence comparison). */
export type ActiveVariableFloor = Extract<VariableFloor, { status: "active" }>;

/** An inconsistency detected by the floor check (material for refusal + evidence display — formatted by floor-evidence.ts). */
export type FloorViolation =
  | {
      readonly kind: "chain-shortened";
      readonly floorHead: ChainHeadFloor;
      readonly syncedHead: ChainHeadFloor;
    }
  | {
      readonly kind: "chain-diverged";
      readonly floorHead: ChainHeadFloor;
      readonly actualHashHex: string;
      readonly syncedHead: ChainHeadFloor;
    }
  | {
      readonly kind: "variable-omitted";
      readonly variableId: string;
      readonly floor: VariableFloor;
    }
  | {
      readonly kind: "value-rollback";
      readonly variableId: string;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "value-equivocation";
      readonly variableId: string;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "value-epoch-regression";
      readonly variableId: string;
      readonly floor: ActiveVariableFloor;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "stale-epoch-injection";
      readonly variableId: string;
      /** The rule (c) baseline (the chain-derived current epoch at the last successful pull). */
      readonly baselineEpoch: number;
      readonly floorVersion: number;
      readonly pulled: PulledValueEvidence;
    }
  | {
      readonly kind: "meta-rollback";
      readonly target: "variable" | "environment";
      readonly variableId: string | null;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "meta-equivocation";
      readonly target: "variable" | "environment";
      readonly variableId: string | null;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "deletion-revoked";
      readonly variableId: string;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "tombstone-mismatch";
      readonly variableId: string;
      readonly floor: FloorMetaEvidence;
      readonly pulled: VerifiedMetaEvidence;
    }
  | {
      readonly kind: "manifest-rollback";
      readonly floor: ManifestFloor;
      readonly pulled: VerifiedManifest;
    }
  | {
      readonly kind: "manifest-equivocation";
      readonly floor: ManifestFloor;
      readonly pulled: VerifiedManifest;
    }
  | {
      // The shape where no manifest is distributed after a manifest floor was
      // established (even under --init-manifest's omission tolerance, an
      // omission against an established floor is evidence of suppression)
      readonly kind: "manifest-omitted";
      readonly floor: ManifestFloor;
    }
  | {
      // Rule (c) applied to manifests (§6.3): a distribution whose manifest is
      // newer than the floor's manifest_version but whose epoch is below the
      // pull-time epoch baseline
      readonly kind: "stale-manifest-injection";
      readonly baselineEpoch: number;
      readonly floorManifestVersion: number;
      readonly pulled: VerifiedManifest;
    };

/** Kind labels for rejection messages (evidence formatting lives in floor-evidence.ts). */
export function floorViolationLabel(violation: FloorViolation): string {
  switch (violation.kind) {
    case "chain-shortened":
      return "chain shortening (a rollback)";
    case "chain-diverged":
      return "distribution of a branch diverging from the verified chain head (immediate evidence of equivocation)";
    case "variable-omitted":
      return "omission of a verified variable (selective response truncation)";
    case "value-rollback":
      return "a value-version rollback";
    case "value-equivocation":
      return "different signed bytes served for the same version (evidence of equivocation)";
    case "value-epoch-regression":
      return "an epoch regression (a §4.1 monotonicity violation)";
    case "stale-epoch-injection":
      return "an advanced version below the pull-time epoch baseline (evidence of forward injection with an old epoch key)";
    case "meta-rollback":
      return "a meta-statement rollback";
    case "meta-equivocation":
      return "different signed bytes served for the same metaVersion (evidence of equivocation)";
    case "deletion-revoked":
      return "an unauthorized undeletion";
    case "tombstone-mismatch":
      return "replacement of a deleted variable's tombstone";
    case "manifest-rollback":
      return "an environment-manifest rollback";
    case "manifest-equivocation":
      return "different signed bytes served for the same manifestVersion (evidence of equivocation)";
    case "manifest-omitted":
      return "omission of the environment manifest after one was verified (manifest suppression)";
    case "stale-manifest-injection":
      return "an advanced manifestVersion below the epoch baseline (evidence of forward meta injection with an old epoch key)";
  }
}

/**
 * The chain floor check (the chain part of rule (a)). Requires the synced,
 * verified chain to be an extension that contains the head recorded in the
 * floor: (1) shortening (headSeq regression), (2) hash mismatch at the
 * floor's seq position (= a different branch not containing the floor's head
 * — via the prev_hash chain, matching at the floor's seq means matching every
 * entry at or below it). seq advancing past the floor is normal (other
 * members' appends).
 */
export function checkChainFloor(
  floor: ProjectFloor,
  verified: VerifiedProject,
): FloorViolation | null {
  const floorHead = floor.chainHead;
  if (floorHead === null) {
    // A floor with no head observation yet (e.g. an intents-only log) — nothing to check
    return null;
  }
  const syncedHead: ChainHeadFloor = {
    seq: verified.state.headSeq,
    hashHex: verified.state.headHashHex,
  };
  if (verified.state.headSeq < floorHead.seq) {
    return { kind: "chain-shortened", floorHead, syncedHead };
  }
  const actualHashHex = verified.history.entryHashAt(floorHead.seq);
  if (actualHashHex !== floorHead.hashHex) {
    return {
      kind: "chain-diverged",
      floorHead,
      actualHashHex: actualHashHex ?? "",
      syncedHead,
    };
  }
  return null;
}

function valueEvidenceOf(value: VerifiedPulledValue): PulledValueEvidence {
  return {
    version: value.version,
    epoch: value.epoch,
    valueSigHashHex: value.signedBytesHashHex,
    chainHeadSeq: value.valueChainHeadSeq,
    chainHeadHashHex: value.valueChainHeadHashHex,
    signatureHex: value.valueSignatureHex,
    writerUserId: value.writerUserId,
    writerKeyFingerprintHex: value.writerKeyFingerprintHex,
  };
}

function metaEvidenceOf(value: VerifiedPulledValue): VerifiedMetaEvidence {
  return {
    status: "active",
    metaVersion: value.metaVersion,
    metaSigHashHex: value.metaSignedBytesHashHex,
    chainHeadSeq: value.metaChainHeadSeq,
    chainHeadHashHex: value.metaChainHeadHashHex,
    signatureHex: value.metaSignatureHex,
    authorUserId: value.authorUserId,
    authorKeyFingerprintHex: value.authorKeyFingerprintHex,
  };
}

/** The floor check of variable meta (regression = (a); a difference at the same metaVersion = (b). Advancement is not guaranteed). */
function checkMetaAgainstFloor(
  target: "variable" | "environment",
  variableId: string | null,
  floor: FloorMetaEvidence,
  pulled: VerifiedMetaEvidence,
): FloorViolation | null {
  if (pulled.metaVersion < floor.metaVersion) {
    return { kind: "meta-rollback", target, variableId, floor, pulled };
  }
  if (pulled.metaVersion === floor.metaVersion && pulled.metaSigHashHex !== floor.metaSigHashHex) {
    return { kind: "meta-equivocation", target, variableId, floor, pulled };
  }
  return null;
}

/**
 * The manifest floor check (the manifest part of rules (a)(b) + omission
 * after establishment). If the floor has no manifest record (a floor from
 * before manifests were introduced) there is nothing to check — establishing
 * the record is the job of the floor commit after verification succeeds.
 */
function checkManifestAgainstFloor(
  floor: EnvironmentFloor,
  manifest: VerifiedManifest | null,
): FloorViolation | null {
  const manifestFloor = floor.manifest;
  if (manifestFloor === undefined) {
    return null;
  }
  if (manifest === null) {
    // An omission against an established manifest floor is evidence of
    // suppression even under the migration path's (--init-manifest) tolerance
    // (an initialized environment's manifest does not disappear)
    return { kind: "manifest-omitted", floor: manifestFloor };
  }
  if (manifest.manifestVersion < manifestFloor.manifestVersion) {
    return { kind: "manifest-rollback", floor: manifestFloor, pulled: manifest };
  }
  if (
    manifest.manifestVersion === manifestFloor.manifestVersion &&
    manifest.signedBytesHashHex !== manifestFloor.manifestSigHashHex
  ) {
    // Since every signed field including epoch goes into the signed bytes, a
    // content difference at the same manifestVersion is covered by this one
    // check (§4.3's full enumeration of signed fields)
    return { kind: "manifest-equivocation", floor: manifestFloor, pulled: manifest };
  }
  return null;
}

/**
 * Rule (c) applied to manifests (§6.3): a distribution whose manifest is
 * newer than the floor's manifest_version but whose epoch is below the
 * baseline is evidence of an advanced manifestVersion injected with an
 * old-epoch key. Without a manifest floor it is the same as version 0 (same
 * shape as a value's "variable not in the floor" — a legitimate first
 * manifest after introduction has epoch = the current epoch at issuance ≥
 * the baseline).
 *
 * The baseline is the maximum of the pull-time epoch floor, **the floor
 * manifest's own epoch**, and **the environment-level epoch observation
 * (§6.3 coordinate (ii) — the observedEpoch that is joined regardless of
 * origin)**: manifest-chain epochs are non-decreasing (§4.3's
 * epoch-regressed — verified), so once the floor knows a verified epoch E, a
 * legitimate manifest with a newer manifestVersion can only have epoch ≥ E
 * (transitive). Using pullEpoch alone as the baseline lets a burn-in older
 * than the epoch the floor knows slip through in shapes like right after a
 * rotate (commitManifest advances but pullEpoch does not move until a pull)
 * or a bounded resync (pullEpoch is the pre-response view). observedEpoch has
 * no path that falsely rejects a value, so it can join this baseline
 * unconditionally (it is not used for the value rule (c) — the coordinate's
 * type splits them).
 */
function checkManifestEpochBaseline(
  floor: EnvironmentFloor,
  manifest: VerifiedManifest | null,
): FloorViolation | null {
  if (manifest === null) {
    return null;
  }
  const floorVersion = floor.manifest?.manifestVersion ?? 0;
  const baselineEpoch = Math.max(floor.pullEpoch, floor.observedEpoch, floor.manifest?.epoch ?? 0);
  if (manifest.manifestVersion > floorVersion && manifest.epoch < baselineEpoch) {
    return {
      kind: "stale-manifest-injection",
      baselineEpoch,
      floorManifestVersion: floorVersion,
      pulled: manifest,
    };
  }
  return null;
}

/** The check of an active floor × an active distributed value (the value and variable-meta parts of rules (a)(b)). */
function checkActiveVariable(
  floor: ActiveVariableFloor,
  value: VerifiedPulledValue,
): FloorViolation | null {
  const variableId = value.variableId;
  const pulled = valueEvidenceOf(value);
  if (value.version < floor.version) {
    return { kind: "value-rollback", variableId, floor, pulled };
  }
  if (value.version === floor.version && value.signedBytesHashHex !== floor.valueSigHashHex) {
    // Since every signed field including epoch goes into the signed bytes, a
    // content difference at the same version is covered by this one check
    // (§4.1's full enumeration of signed fields)
    return { kind: "value-equivocation", variableId, floor, pulled };
  }
  if (value.version > floor.version && value.epoch < floor.epoch) {
    // §4.1's epoch monotonicity (transitive — required regardless of gaps in version numbers)
    return { kind: "value-epoch-regression", variableId, floor, pulled };
  }
  return checkMetaAgainstFloor("variable", variableId, floor, metaEvidenceOf(value));
}

/** The meta-level check of a variable the floor records as active (3 branches: active / tombstone / omitted). */
function checkFloorActiveMeta(
  variableId: string,
  floor: ActiveVariableFloor,
  active: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return checkMetaAgainstFloor("variable", variableId, floor, active);
  }
  if (tombstone !== undefined) {
    // A deleted whose metaVersion advanced past the floor's is a legitimate
    // deletion. A different status at the same metaVersion means different
    // signed bytes = (b) evidence. A regression is (a)
    return checkMetaAgainstFloor("variable", variableId, floor, tombstone);
  }
  return { kind: "variable-omitted", variableId, floor };
}

/** The check of a variable the floor records as active (value level + meta level). */
function checkFloorActive(
  variableId: string,
  floor: ActiveVariableFloor,
  active: VerifiedPulledValue | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    return checkActiveVariable(floor, active);
  }
  return checkFloorActiveMeta(variableId, floor, undefined, tombstone);
}

/**
 * The check of a variable the floor records as declared (meta level only —
 * declared has no value floor, §4.2). Legitimate successors = activation
 * (active, advanced metaVersion) / schema re-issuance (advanced while still
 * declared) / deletion (tombstone). Regression or a same-version difference
 * is rule (a)/(b); omission is variable-omitted.
 */
function checkFloorDeclared(
  variableId: string,
  floor: Extract<VariableFloor, { status: "declared" }>,
  meta: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  const evidence = meta ?? tombstone;
  if (evidence === undefined) {
    return { kind: "variable-omitted", variableId, floor };
  }
  return checkMetaAgainstFloor("variable", variableId, floor, evidence);
}

/** The check of a variable the floor records as deleted (deletion is a terminal state — §4.2 / session-15 §2-2). */
function checkFloorDeleted(
  variableId: string,
  floor: Extract<VariableFloor, { status: "deleted" }>,
  active: VerifiedMetaEvidence | undefined,
  tombstone: VerifiedTombstone | undefined,
): FloorViolation | null {
  if (active !== undefined) {
    // Unauthorized undeletion (rule (a)). No legitimate path re-activates a
    // deleted variable (both server acceptance and predecessor verification
    // refuse it — session-15 §2-2)
    return { kind: "deletion-revoked", variableId, floor, pulled: active };
  }
  if (tombstone === undefined) {
    return { kind: "variable-omitted", variableId, floor };
  }
  if (
    tombstone.metaVersion !== floor.metaVersion ||
    tombstone.metaSigHashHex !== floor.metaSigHashHex
  ) {
    // deleted is a terminal state with no legitimate successor statement, so
    // an exact match with the floor is required (regression = (a), difference
    // = (b), advancement = a post-deletion forgery)
    return { kind: "tombstone-mismatch", variableId, floor, pulled: tombstone };
  }
  return null;
}

/**
 * The shared skeleton of the environment meta check + the per-variable check
 * of everything in the floor (omission / regression / difference /
 * undeletion). Only the active-side check is swapped by shape (value-bearing
 * / metadata-only). values.ts has already refused an active / deleted pair
 * on the same ID.
 */
function checkFloorCommon<T extends { readonly variableId: string }>(
  floor: EnvironmentFloor,
  environment: VerifiedMetaEvidence,
  activeList: readonly T[],
  /**
   * The verified declared set of a value-bearing pull (§12-7's
   * declaredVariables). A metadata-only pull mixes declared into activeList
   * (§12-7), so an empty list is passed.
   */
  declaredList: readonly VerifiedVariableStatement[],
  tombstoneList: readonly VerifiedTombstone[],
  checkActive: (
    variableId: string,
    variableFloor: ActiveVariableFloor,
    active: T | undefined,
    tombstone: VerifiedTombstone | undefined,
  ) => FloorViolation | null,
  toMeta: (active: T) => VerifiedMetaEvidence,
): FloorViolation | null {
  const actives = new Map(activeList.map((value) => [value.variableId, value]));
  const declared = new Map(declaredList.map((statement) => [statement.variableId, statement]));
  const tombstones = new Map(tombstoneList.map((tombstone) => [tombstone.variableId, tombstone]));
  const environmentViolation = checkMetaAgainstFloor(
    "environment",
    null,
    { metaVersion: floor.metaVersion, metaSigHashHex: floor.metaSigHashHex },
    environment,
  );
  if (environmentViolation !== null) {
    return environmentViolation;
  }
  for (const [variableId, variableFloor] of Object.entries(floor.variables)) {
    const active = actives.get(variableId);
    // For the meta-level check of a declared / deleted floor, a declared
    // distribution can also serve as evidence. An active floor requires the
    // value to exist (no legitimate active → declared transition exists —
    // §4.2), so no declared distribution is passed: on the value-bearing
    // path, checkActive refuses it as variable-omitted (a missing value —
    // §6.3's value-distribution requirement)
    const meta = active === undefined ? declared.get(variableId) : toMeta(active);
    const violation =
      variableFloor.status === "active"
        ? checkActive(variableId, variableFloor, active, tombstones.get(variableId))
        : variableFloor.status === "declared"
          ? checkFloorDeclared(variableId, variableFloor, meta, tombstones.get(variableId))
          : checkFloorDeleted(variableId, variableFloor, meta, tombstones.get(variableId));
    if (violation !== null) {
      return violation;
    }
  }
  return null;
}

/**
 * The floor check for one environment (rules (a)(b)(c)). No floor (first
 * run) means nothing to check — what is not guaranteed in that case is
 * §14.3-3 (first-sync client). Returns the first inconsistency found (all
 * are refusal conditions, so no enumeration is needed).
 */
export function checkEnvironmentPull(
  floor: EnvironmentFloor | null,
  snapshot: VerifiedPullSnapshot,
): FloorViolation | null {
  if (floor === null) {
    return null;
  }
  const violation = checkFloorCommon(
    floor,
    snapshot.environment,
    snapshot.variables,
    snapshot.declared,
    snapshot.tombstones,
    checkFloorActive,
    metaEvidenceOf,
  );
  if (violation !== null) {
    return violation;
  }
  // Rules (a)(b) on the manifest floor + omission after establishment + rule (c) applied to manifests
  const manifestViolation =
    checkManifestAgainstFloor(floor, snapshot.manifest) ??
    checkManifestEpochBaseline(floor, snapshot.manifest);
  if (manifestViolation !== null) {
    return manifestViolation;
  }
  // Rule (c): a distribution whose version is newer than the floor's (a
  // variable not in the floor counts as version 0 — a variable legitimately
  // created since the last pull can only have been written at the
  // then-current epoch or later) and whose epoch is below the pull-time epoch
  // baseline is evidence of forward injection. "At or above" the baseline is
  // accepted (a legitimate old-epoch value right after a rotation, before
  // re-encryption completes — §12-7)
  for (const value of snapshot.variables) {
    const variableFloor = floorRecordGet(floor.variables, value.variableId);
    const floorVersion = variableFloor?.status === "active" ? variableFloor.version : 0;
    if (value.version > floorVersion && value.epoch < floor.pullEpoch) {
      return {
        kind: "stale-epoch-injection",
        variableId: value.variableId,
        baselineEpoch: floor.pullEpoch,
        floorVersion,
        pulled: valueEvidenceOf(value),
      };
    }
  }
  return null;
}

/**
 * The floor check of a metadata-only pull (§12-7): the meta part of rules
 * (a)(b) (regression of environment / variable statements, a difference at
 * the same metaVersion), omission of a verified variable, unauthorized
 * undeletion, and tombstone replacement. Since this shape carries no values,
 * the value-level checks and rule (c) are out of scope. The
 * **environment-level floor commit** after the checks pass (chain head,
 * environment meta floor, manifest floor, and coordinate (ii) only — never
 * fabricating a value floor, never advancing the pull baseline) is done by
 * the caller (enforceMetadataFloor).
 */
export function checkEnvironmentMetadataPull(
  floor: EnvironmentFloor | null,
  snapshot: VerifiedMetadataSnapshot,
): FloorViolation | null {
  if (floor === null) {
    return null;
  }
  const violation = checkFloorCommon(
    floor,
    snapshot.environment,
    snapshot.variables,
    // A metadata-only pull mixes declared into variables (§12-7) — there is no separate list
    [],
    snapshot.tombstones,
    checkFloorActiveMeta,
    (statement) => statement,
  );
  if (violation !== null) {
    return violation;
  }
  // The manifest is distributed even in metadata-only mode (§12-7 — meta
  // verification completeness is the same level), so rules (a)(b) and rule
  // (c) applied to manifests are checked here too (the value-level rule (c)
  // and the floor commit remaining the domain of value-bearing pulls is
  // unchanged)
  return (
    checkManifestAgainstFloor(floor, snapshot.manifest) ??
    checkManifestEpochBaseline(floor, snapshot.manifest)
  );
}

/**
 * Assembles the next environment floor from a pull response that passed
 * verification (§6.3's update order: the checks run against the previous
 * baseline, and advancing the rule (c) baseline = this run's chain-derived
 * current epoch is committed atomically with the variable floors after
 * verification succeeds — written by the caller via commitPull).
 */
export function buildEnvironmentFloor(
  chainCurrentEpoch: number,
  snapshot: VerifiedPullSnapshot,
): EnvironmentFloor {
  const variables: Record<string, VariableFloor> = {};
  for (const value of snapshot.variables) {
    variables[value.variableId] = {
      status: "active",
      version: value.version,
      epoch: value.epoch,
      valueSigHashHex: value.signedBytesHashHex,
      metaVersion: value.metaVersion,
      metaSigHashHex: value.metaSignedBytesHashHex,
    };
  }
  for (const declared of snapshot.declared) {
    // declared advances only on the meta side (the value floor stays empty until activation — §4.2 / session-46 §8)
    variables[declared.variableId] = {
      status: "declared",
      metaVersion: declared.metaVersion,
      metaSigHashHex: declared.metaSigHashHex,
    };
  }
  for (const tombstone of snapshot.tombstones) {
    variables[tombstone.variableId] = {
      status: "deleted",
      metaVersion: tombstone.metaVersion,
      metaSigHashHex: tombstone.metaSigHashHex,
    };
  }
  return {
    pullEpoch: chainCurrentEpoch,
    // The environment-level epoch observation (coordinate (ii)) is established from the same verified observation
    observedEpoch: chainCurrentEpoch,
    metaVersion: snapshot.environment.metaVersion,
    metaSigHashHex: snapshot.environment.metaSigHashHex,
    ...(snapshot.manifest === null
      ? {}
      : {
          manifest: {
            manifestVersion: snapshot.manifest.manifestVersion,
            epoch: snapshot.manifest.epoch,
            manifestSigHashHex: snapshot.manifest.signedBytesHashHex,
          },
        }),
    variables,
  };
}

/**
 * The environment floor handle for one command run. When several pulls
 * happen inside one process (push's retry loop), the floor the previous pull
 * committed becomes the baseline of the next check. The in-process cache
 * syncs on every commit to **the environment floor the store folded (= the
 * state persisted to the log)**, not a mere send-snapshot: so that detection
 * material a concurrent CLI's append-only-log join took in (unions, deleted
 * terminal states, newer versions / pullEpochs) is not missed by later checks
 * in the same command. The on-disk floor only ever gets §6.3-verified records
 * written by this CLI, so adopting the fold result as the check baseline is
 * sound (an attacker who can write local state is outside the floor's scope).
 *
 * Intents (3-F) are environment-scoped and this is their window: it holds the
 * intents unresolved at openProject time plus the ones this process appended,
 * and a path that passed the effect confirmation (§12-10 (3)) closes them via
 * resolution.
 */
export interface FloorHandle {
  /** The current environment floor (before the first pull, the snapshot read at openProject). */
  readonly current: () => EnvironmentFloor | null;
  /** This environment's unresolved intents (awaiting reconciliation — §6.3 record discipline (ii)). */
  readonly unresolvedIntents: () => readonly FloorIntent[];
  /** The atomic commit of a verified pull (rule (c) baseline + variable floors + head in one record). */
  readonly commitPull: (
    environment: EnvironmentFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /** The variable-floor advance of an accepted push (pullEpoch does not move). */
  readonly commitPush: (
    variableId: string,
    variable: VariableFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * The environment-level commit of a metadata-only pull (never fabricates a
   * value floor, never advances the pull baseline; environment meta floor,
   * manifest floor, and coordinate (ii) only).
   */
  readonly commitMetadata: (
    commit: Omit<MetadataCommit, "chainHead" | "environmentId">,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * Floor promotion of a self-issued manifest confirmed as accepted
   * (pullEpoch and variable floors do not move). Skipping it would leave the
   * post-acceptance floor at the old manifestVersion and open a window where
   * rule (a) cannot detect a server that keeps distributing the old version.
   */
  readonly commitManifest: (
    manifest: ManifestFloor,
    head: ChainHeadFloor,
  ) => Effect.Effect<void, CliError>;
  /**
   * The pre-send intent (3-F) of a security-critical mutation. The send
   * never happens before persistence (fsync equivalent) succeeds
   * (fail-closed). The return value is the intent id used for resolution.
   */
  readonly appendIntent: (input: FloorIntentInput) => Effect.Effect<string, CliError>;
  /** Closes an intent with the effect-confirmation result (an unknown / resolved id is a no-op — idempotent). */
  readonly resolveIntent: (
    intentId: string,
    outcome: FloorIntentOutcome,
  ) => Effect.Effect<void, CliError>;
}

/**
 * An `Effect.tapError` callback that closes an intent (3-F) as rejected when
 * the send failed with a rejection in the server's own error body (= the
 * effect never happened — decided). A transport-layer failure (lost
 * response) stays unresolved — the next reconciliation opportunity (chain
 * sync / metadata-only pull) resolves it. A failed resolution append may be
 * swallowed: the direction where an intent stays open is the safe side (it
 * just leaves something to reconcile).
 */
export function rejectIntentOnServerRejection(
  floor: FloorHandle,
  intentId: string,
): (error: unknown) => Effect.Effect<void> {
  return (error) =>
    isServerRejection(error)
      ? Effect.ignore(floor.resolveIntent(intentId, "rejected"))
      : Effect.void;
}

/** Builds an environment floor handle over the floor store. */
export function makeFloorHandle(input: {
  readonly store: FloorStoreShape;
  readonly projectId: string;
  readonly environmentId: string;
  readonly initial: EnvironmentFloor | null;
  /** This environment's unresolved intents as of openProject (surfaced by the fold — 3-F). */
  readonly intents?: readonly FloorIntent[];
}): FloorHandle {
  let current = input.initial;
  const intents = new Map((input.intents ?? []).map((intent) => [intent.id, intent]));
  const adopt = (merged: EnvironmentFloor): void => {
    current = merged;
  };
  return {
    current: () => current,
    unresolvedIntents: () => [...intents.values()],
    commitPull: (environment, head) =>
      input.store
        .commitPull(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          environment,
        })
        .pipe(Effect.map(adopt)),
    commitPush: (variableId, variable, head) =>
      input.store
        .commitPush(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          variableId,
          variable,
        })
        .pipe(Effect.map(adopt)),
    commitMetadata: (commit, head) =>
      input.store
        .commitMetadata(input.projectId, {
          chainHead: head,
          environmentId: input.environmentId,
          ...commit,
        })
        .pipe(Effect.map(adopt)),
    commitManifest: (manifest, head) =>
      Effect.suspend(() => {
        // The in-process baseline advances **first, regardless of whether the
        // disk write succeeds**: the fact that we know the manifestVersion we
        // got accepted remains detection material for later scans in the same
        // run even if the write fails (detecting a server that keeps
        // distributing the old version after acceptance). The advance uses
        // the same join implementation as the disk side (no separate
        // "`>=` last-wins" implementation). If the join detects a conflict
        // (same version, different hash), the advance is **not adopted**:
        // making the side that discarded evidence the check baseline would
        // let the rest of a run whose disk write fell to a warning on I/O
        // failure proceed without seeing equivocation (when the disk write
        // succeeds, the fold turns later commits into typed errors on the
        // same conflict)
        if (current !== null) {
          const conflicts: FloorConflict[] = [];
          const joined = joinEnvironmentFloor(
            input.environmentId,
            current,
            {
              pullEpoch: 0,
              observedEpoch: manifest.epoch,
              metaVersion: 0,
              metaSigHashHex: "",
              manifest,
              variables: {},
            },
            (conflict) => conflicts.push(conflict),
          );
          if (conflicts.length === 0) {
            current = joined;
          }
        }
        return input.store
          .commitManifest(input.projectId, {
            chainHead: head,
            environmentId: input.environmentId,
            manifest,
          })
          .pipe(Effect.map(adopt));
      }),
    appendIntent: (intentInput) =>
      input.store.appendIntent(input.projectId, intentInput).pipe(
        Effect.tap((id) =>
          Effect.sync(() => {
            intents.set(id, { id, ...intentInput });
          }),
        ),
      ),
    resolveIntent: (intentId, outcome) =>
      Effect.suspend(() => {
        if (!intents.has(intentId)) {
          return Effect.void;
        }
        intents.delete(intentId);
        return input.store.resolveIntent(input.projectId, intentId, outcome);
      }),
  };
}
