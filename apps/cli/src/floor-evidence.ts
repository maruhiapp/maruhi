// Reporting UX of fork evidence (CRYPTO_SPEC §6.3 / §14.2-5).
//
// A floor-check mismatch is "a contradiction between data that both
// passed §6.3 signature verification", so both coordinates, the
// signed-bytes hashes, and the declared heads are output in a form a
// human can present to a third party (two valid signatures with
// different content at the same coordinate = non-repudiable evidence
// of server equivocation or key compromise — §14.2-5). **No plaintext
// values or key material is included** (everything is identified by
// ID and hash — the diskless invariant).

import { displayText } from "./display.ts";
import type { FloorViolation } from "./floor-check.ts";
import { floorViolationLabel } from "./floor-check.ts";
import type { AttestationEvidenceRecord, FloorConflict } from "./floor.ts";

/** Coordinates included in the evidence (all IDs — no names: a name itself can be the disputed object). */
export interface FloorEvidenceCoordinates {
  readonly projectId: string;
  readonly environmentId?: string;
}

function headText(seq: number, hashHex: string): string {
  return `seq=${seq} hash=${hashHex}`;
}

function coordinateLine(coordinates: FloorEvidenceCoordinates, variableId?: string | null): string {
  const parts = [`project=${coordinates.projectId}`];
  if (coordinates.environmentId !== undefined) {
    parts.push(`environment=${coordinates.environmentId}`);
  }
  if (variableId !== undefined && variableId !== null) {
    parts.push(`variable=${variableId}`);
  }
  return `  coordinates: ${parts.join(" ")}`;
}

function floorVariableLines(violation: Extract<FloorViolation, { kind: "variable-omitted" }>) {
  const floor = violation.floor;
  return floor.status === "active"
    ? [
        `  floor record (previously verified): status=active version=${floor.version} epoch=${floor.epoch}`,
        `    value_signed_bytes_hash=${floor.valueSigHashHex}`,
        `    metaVersion=${floor.metaVersion} meta_signed_bytes_hash=${floor.metaSigHashHex}`,
      ]
    : [
        // declared / deleted are meta-side only (no value floor — floor.ts)
        `  floor record (previously verified): status=${floor.status} metaVersion=${floor.metaVersion}`,
        `    meta_signed_bytes_hash=${floor.metaSigHashHex}`,
      ];
}

type ValueViolation = Extract<
  FloorViolation,
  { kind: "value-rollback" | "value-equivocation" | "value-epoch-regression" }
>;

function pulledValueLines(pulled: {
  readonly version: number;
  readonly epoch: number;
  readonly valueSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}): readonly string[] {
  return [
    `  this distribution: version=${pulled.version} epoch=${pulled.epoch}`,
    `    value_signed_bytes_hash=${pulled.valueSigHashHex}`,
    `    declared head: ${headText(pulled.chainHeadSeq, pulled.chainHeadHashHex)}`,
    // user_id is a free-form string on the wire with only a length constraint — neutralize before emitting to the terminal
    `    writer signature: writer=${displayText(pulled.writerUserId)} fp=${pulled.writerKeyFingerprintHex}`,
    `    signature=${pulled.signatureHex}`,
  ];
}

function valueEvidenceLines(violation: ValueViolation): readonly string[] {
  return [
    `  floor record (previously verified): version=${violation.floor.version} epoch=${violation.floor.epoch}`,
    `    value_signed_bytes_hash=${violation.floor.valueSigHashHex}`,
    ...pulledValueLines(violation.pulled),
  ];
}

type MetaViolation = Extract<
  FloorViolation,
  { kind: "meta-rollback" | "meta-equivocation" | "deletion-revoked" | "tombstone-mismatch" }
>;

function metaEvidenceLines(violation: MetaViolation): readonly string[] {
  return [
    `  floor record (previously verified): metaVersion=${violation.floor.metaVersion}`,
    `    meta_signed_bytes_hash=${violation.floor.metaSigHashHex}`,
    `  this distribution: status=${violation.pulled.status} metaVersion=${violation.pulled.metaVersion}`,
    `    meta_signed_bytes_hash=${violation.pulled.metaSigHashHex}`,
    `    declared head: ${headText(violation.pulled.chainHeadSeq, violation.pulled.chainHeadHashHex)}`,
    // user_id is a free-form string on the wire with only a length constraint — neutralize before emitting to the terminal
    `    author signature: author=${displayText(violation.pulled.authorUserId)} fp=${violation.pulled.authorKeyFingerprintHex}`,
    `    signature=${violation.pulled.signatureHex}`,
  ];
}

type ManifestViolation = Extract<
  FloorViolation,
  {
    kind: "manifest-rollback" | "manifest-equivocation" | "stale-manifest-injection";
  }
>;

function pulledManifestLines(pulled: {
  readonly manifestVersion: number;
  readonly epoch: number;
  readonly signedBytesHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}): readonly string[] {
  return [
    `  this distribution: manifestVersion=${pulled.manifestVersion} epoch=${pulled.epoch}`,
    `    manifest_signed_bytes_hash=${pulled.signedBytesHashHex}`,
    `    declared head: ${headText(pulled.chainHeadSeq, pulled.chainHeadHashHex)}`,
    // user_id is a free-form string on the wire with only a length constraint — neutralize before emitting to the terminal
    `    issuer signature: issuer=${displayText(pulled.issuerUserId)} fp=${pulled.issuerKeyFingerprintHex}`,
    `    signature=${pulled.signatureHex}`,
  ];
}

function manifestEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: ManifestViolation,
): readonly string[] {
  if (violation.kind === "stale-manifest-injection") {
    return [
      coordinateLine(coordinates),
      `  rule (c) baseline: epoch baseline=${violation.baselineEpoch} (the larger of the pull-time chain-derived epoch and the verified floor manifest's own epoch — manifest epochs never decrease across versions)`,
      `  floor record manifestVersion=${violation.floorManifestVersion} (0 = no floor record)`,
      ...pulledManifestLines(violation.pulled),
    ];
  }
  return [
    coordinateLine(coordinates),
    `  floor record (previously verified): manifestVersion=${violation.floor.manifestVersion} epoch=${violation.floor.epoch}`,
    `    manifest_signed_bytes_hash=${violation.floor.manifestSigHashHex}`,
    ...pulledManifestLines(violation.pulled),
  ];
}

type ChainViolation = Extract<FloorViolation, { kind: "chain-shortened" | "chain-diverged" }>;

function chainEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: ChainViolation,
): readonly string[] {
  const divergedLine =
    violation.kind === "chain-diverged"
      ? [
          `  this chain's entry hash at that seq: ${violation.actualHashHex === "" ? "(absent)" : violation.actualHashHex}`,
        ]
      : [];
  return [
    coordinateLine(coordinates),
    `  floor record (previously verified head): ${headText(violation.floorHead.seq, violation.floorHead.hashHex)}`,
    ...divergedLine,
    `  this sync's head: ${headText(violation.syncedHead.seq, violation.syncedHead.hashHex)}`,
  ];
}

function variableEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: Exclude<FloorViolation, ChainViolation | ManifestViolation>,
): readonly string[] {
  if (violation.kind === "variable-omitted") {
    return [coordinateLine(coordinates, violation.variableId), ...floorVariableLines(violation)];
  }
  if (violation.kind === "stale-epoch-injection") {
    return [
      coordinateLine(coordinates, violation.variableId),
      `  rule (c) baseline: pull-time epoch baseline=${violation.baselineEpoch} (the chain-derived current epoch at the last successful pull)`,
      `  floor record version=${violation.floorVersion} (0 = no floor record)`,
      ...pulledValueLines(violation.pulled),
    ];
  }
  if (
    violation.kind === "value-rollback" ||
    violation.kind === "value-equivocation" ||
    violation.kind === "value-epoch-regression"
  ) {
    return [coordinateLine(coordinates, violation.variableId), ...valueEvidenceLines(violation)];
  }
  // The four meta kinds (a violation of an environment meta has variableId = null — the coordinate rows go to the environment)
  return [coordinateLine(coordinates, violation.variableId), ...metaEvidenceLines(violation)];
}

function evidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: FloorViolation,
): readonly string[] {
  if (violation.kind === "chain-shortened" || violation.kind === "chain-diverged") {
    return chainEvidenceLines(coordinates, violation);
  }
  if (
    violation.kind === "manifest-rollback" ||
    violation.kind === "manifest-equivocation" ||
    violation.kind === "stale-manifest-injection"
  ) {
    return manifestEvidenceLines(coordinates, violation);
  }
  return variableEvidenceLines(coordinates, violation);
}

/**
 * Formats a floor-check mismatch into multi-line text: a refusal
 * message + presentable evidence (coordinates, both signed-bytes
 * hashes, declared heads).
 */
export function formatFloorViolation(
  coordinates: FloorEvidenceCoordinates,
  violation: FloorViolation,
): string {
  return [
    `The local floor check detected an inconsistency: ${floorViolationLabel(violation)}`,
    ...evidenceLines(coordinates, violation),
    "  This is a contradiction between previously verified signed data and this distribution — evidence of server equivocation or a leaked signing key (CRYPTO_SPEC §14.2-5). Preserve this output and the local floor file, and present them to the project administrators",
  ].join("\n");
}

function conflictLabel(conflict: FloorConflict): string {
  switch (conflict.kind) {
    case "chain-head":
      return "two verified chain heads at the same seq with different hashes (a fork)";
    case "value":
      return "two verified values for the same version with different signed bytes";
    case "variable-meta":
      return "two verified variable statements for the same metaVersion with different signed bytes";
    case "environment-meta":
      return "two verified environment statements for the same metaVersion with different signed bytes";
    case "manifest":
      return "two verified environment manifests for the same manifestVersion with different signed bytes";
    case "undeletion":
      return "a verified statement past a verified deletion (deletion is terminal — an unauthorized undeletion)";
  }
}

function conflictLines(conflict: FloorConflict): readonly string[] {
  const parts: string[] = [];
  if (conflict.environmentId !== null) {
    parts.push(`environment=${conflict.environmentId}`);
  }
  if (conflict.variableId !== null) {
    parts.push(`variable=${conflict.variableId}`);
  }
  return [
    `  [${conflict.kind}] ${conflictLabel(conflict)}`,
    ...(parts.length > 0 ? [`    coordinates: ${parts.join(" ")}`] : []),
    `    observation A: version=${conflict.firstVersion} signed_bytes_hash=${conflict.firstHashHex}`,
    `    observation B: version=${conflict.secondVersion} signed_bytes_hash=${conflict.secondHashHex}`,
  ];
}

function attestationEvidenceLines(record: AttestationEvidenceRecord): readonly string[] {
  const { attestation, localView } = record;
  return [
    record.kind === "head-mismatch"
      ? "  [head-mismatch] a verified member attestation names a different entry hash at a seq within this view"
      : "  [unresolved-after-resync] a verified member attestation names a head beyond this view that one bounded re-sync could not resolve as an extension",
    // user_id is a free-form string on the wire with only a length constraint — neutralize before emitting to the terminal
    `    attester: ${displayText(attestation.attesterUserId)} fp=${attestation.attesterKeyFingerprintHex}`,
    `    attested head: ${headText(attestation.chainHeadSeq, attestation.chainHeadHashHex)}`,
    `    attestation signature: ${attestation.signatureHex}`,
    `    this view's head: ${headText(localView.headSeq, localView.headHashHex)}`,
    `    this view's entry hash at the attested seq: ${localView.entryHashAtAttestedSeq === "" ? "(beyond this view)" : localView.entryHashAtAttestedSeq}`,
  ];
}

/**
 * Warning message for a contradictory-head declaration (CRYPTO_SPEC
 * §6.6 check (a)). The declaration already passed §6.6 signature
 * verification, so a contradiction with our view is non-repudiable
 * evidence of "server equivocation (split view) or attester key
 * compromise" (§14.2-5). The evidence body is already saved to the
 * append-only evidence file (the path is shown as the route).
 */
export function formatAttestationEvidence(
  projectId: string,
  records: readonly AttestationEvidenceRecord[],
  evidencePath: string,
): string {
  return [
    `Head-attestation cross-check detected a contradiction with this sync's chain (project=${projectId}):`,
    ...records.flatMap(attestationEvidenceLines),
    `  Each attestation above passed CRYPTO_SPEC §6.6 verification (a current member's signature over a chain position), so the contradiction is evidence of server equivocation (a split view) or a leaked member signing key (§14.2-5). Aborting this command without using this sync's results. The evidence (attestation + this view's chain digest) has been preserved append-only at ${evidencePath} — present it and this output to the project administrators, and confirm the chain head with other members out of band`,
  ].join("\n");
}

/**
 * Refusal message for a same-coordinate conflict (join undefined —
 * CRYPTO_SPEC §6.3 rule (b)'s merge semantics) detected by the
 * observation log's fold. Both observations are facts that passed
 * §6.3 verification, and the contradiction is non-repudiable evidence
 * of equivocation or key compromise — the log is append-only, so the
 * evidence itself does not disappear (only preservation is guided).
 */
export function formatFloorConflicts(
  projectId: string,
  conflicts: readonly FloorConflict[],
): string {
  return [
    `The local floor observation log contains verified observations that contradict each other (project=${projectId}):`,
    ...conflicts.flatMap(conflictLines),
    `  Both observations passed CRYPTO_SPEC §6.3 verification — this is evidence of server equivocation or a leaked signing key (§14.2-5). The append-only floor log preserves both records: floor/${projectId}.jsonl in the config directory. Present it to the project administrators. Every command for this project will refuse to run until this is resolved out of band. Refusing to use or advance this floor`,
  ].join("\n");
}
