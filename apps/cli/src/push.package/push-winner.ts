import { type VariableId } from "@maruhi/core";

import type { VerifiedPulledValue } from "../values-verify.ts";

function winnerValueRegression(
  variableId: VariableId,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (currentVersion < known.version || winner.version < known.version) {
    return `The 409 response / re-fetch for variable ${variableId} (version ${Math.min(currentVersion, winner.version)}) is older than the verified latest (version ${known.version}) — evidence of a version rollback`;
  }
  if (winner.version === known.version && winner.signedBytesHashHex !== known.signedBytesHashHex) {
    return `Variable ${variableId} version ${winner.version} was served with signed bytes different from the verified value (evidence of server equivocation)`;
  }
  if (winner.version > known.version && winner.epoch < known.epoch) {
    return `Variable ${variableId} version ${winner.version} has an epoch (${winner.epoch}) that regressed from the verified predecessor version's (${known.epoch}) — an epoch-monotonicity violation (§4.1)`;
  }
  if (
    winner.version === known.version + 1 &&
    winner.prevValueSigHashHex !== known.signedBytesHashHex
  ) {
    return `Variable ${variableId} version ${winner.version} has a prev that does not match the verified predecessor version's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

function winnerMetaRegression(
  variableId: VariableId,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
): string | null {
  if (winner.metaVersion < known.metaVersion) {
    return `The re-fetched statement for variable ${variableId} (metaVersion ${winner.metaVersion}) is older than the verified latest (metaVersion ${known.metaVersion}) — evidence of a metadata rollback`;
  }
  if (
    winner.metaVersion === known.metaVersion &&
    winner.metaSignedBytesHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} was served with signed bytes different from the verified statement (evidence of server equivocation)`;
  }
  if (
    winner.metaVersion === known.metaVersion + 1 &&
    winner.prevMetaSigHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} has a prev that does not match the verified predecessor metaVersion's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

function winnerRegression(
  variableId: VariableId,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  return (
    winnerValueRegression(variableId, known, winner, currentVersion) ??
    winnerMetaRegression(variableId, known, winner)
  );
}

export function winnerInconsistency(
  variableId: VariableId,
  known: VerifiedPulledValue | null,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (winner.version < currentVersion) {
    return `The re-fetched pull's latest version (${winner.version}) is older than the known latest version (${currentVersion}) — inconsistent (the server response contradicts itself)`;
  }
  return known === null ? null : winnerRegression(variableId, known, winner, currentVersion);
}
