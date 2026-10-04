// The 409 winner's consistency checks (AUTH_SPEC §12-5): regression from
// the verified known latest, equivocation at the same coordinates, and
// the adjacent prev-chain match — the value side and the meta side.

import type { VerifiedPulledValue } from "./values-verify.ts";

/**
 * The winner's consistency check against the verified known latest (the
 * value that passed this session's §6.3 verification): regression,
 * equivocation, and chain integrity. On an honest server latest_version is
 * monotonically increasing (no per-version-row deletion; a variable
 * deletion is tombstone + delete-all-rows = 404 from then on), so every
 * regression is evidence of a rollback or equivocation — no false
 * rejection.
 */
function winnerValueRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (currentVersion < known.version || winner.version < known.version) {
    // A regression from this session's verified latest = evidence of a
    // rollback. Adopting it and re-pointing prev would chain my own
    // signature onto a rolled-back branch
    return `The 409 response / re-fetch for variable ${variableId} (version ${Math.min(currentVersion, winner.version)}) is older than the verified latest (version ${known.version}) — evidence of a version rollback`;
  }
  if (winner.version === known.version && winner.signedBytesHashHex !== known.signedBytesHashHex) {
    // Two valid signatures with different content at the same coordinates = cryptographic evidence of equivocation
    return `Variable ${variableId} version ${winner.version} was served with signed bytes different from the verified value (evidence of server equivocation)`;
  }
  // Epoch monotonicity (§4.1) is transitive, so once the winner is newer
  // than the verified latest, epoch non-decrease is required regardless of
  // version-number gaps (review loop 2 [low] — closes an old-epoch
  // injection that bypasses the adjacent check via version-number choice).
  // An honest server is epoch-non-decreasing in acceptance order, so no
  // false rejection
  if (winner.version > known.version && winner.epoch < known.epoch) {
    return `Variable ${variableId} version ${winner.version} has an epoch (${winner.epoch}) that regressed from the verified predecessor version's (${known.epoch}) — an epoch-monotonicity violation (§4.1)`;
  }
  // When the adjacent predecessor is held, §6.3-6's prev-existence match
  // can be checked for free (review loop 1 [medium] — the exception to
  // pull's latest-only constraint)
  if (
    winner.version === known.version + 1 &&
    winner.prevValueSigHashHex !== known.signedBytesHashHex
  ) {
    return `Variable ${variableId} version ${winner.version} has a prev that does not match the verified predecessor version's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

/**
 * The meta-side same-shape rollback / fork check (§12-5's meta-retry
 * discipline; the PR-3 extension of the value side's
 * winnerValueRegression): refuses a regression from the verified latest
 * metaVersion and different signed bytes at the same metaVersion =
 * equivocation. On an honest server latest_meta_version is also
 * monotonically increasing (no per-statement-row deletion), so no false
 * rejection.
 */
function winnerMetaRegression(
  variableId: string,
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
  // When the adjacent predecessor is held, the prev-chain match can be
  // checked for free (the same shape as winnerValueRegression's §6.3-6
  // check — review ② [minor])
  if (
    winner.metaVersion === known.metaVersion + 1 &&
    winner.prevMetaSigHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} has a prev that does not match the verified predecessor metaVersion's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

function winnerRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  return (
    winnerValueRegression(variableId, known, winner, currentVersion) ??
    winnerMetaRegression(variableId, known, winner)
  );
}

/**
 * The consistency check of a 409 winner (§12-5). null = adoptable,
 * non-null = the reason to refuse.
 *
 * The checks are 2-layered: (1) consistency across responses (the
 * re-fetched latest being older than a version known to exist = the server
 * contradicting itself), (2) regression from the verified known latest,
 * different signed bytes at the same coordinates, and a mismatched
 * adjacent prev. **Rotation re-encryption (env-rotate.ts) also goes
 * through this check**: re-pointing prev at the winner is the same shape
 * as the push path, and letting just one side chain-sign onto a diverged
 * history would open a hole that relies on the floor (a SHOULD, absent on
 * first sync).
 *
 * `currentVersion` comes from different places per path (push = the 409's
 * claim; rotation = the 409's claim or **a version I got accepted**), so
 * the wording is unified as "the known latest".
 */
export function winnerInconsistency(
  variableId: string,
  known: VerifiedPulledValue | null,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (winner.version < currentVersion) {
    // Only values older than the latest the 409 claimed are distributed = an inconsistency across responses
    return `The re-fetched pull's latest version (${winner.version}) is older than the known latest version (${currentVersion}) — inconsistent (the server response contradicts itself)`;
  }
  return known === null ? null : winnerRegression(variableId, known, winner, currentVersion);
}
