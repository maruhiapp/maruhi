// Checks for CRYPTO_SPEC §5.2 (the epoch DEK commitment).
// Beyond the dek-commitment.json-driven positive / negative cases, this pins at
// implementation level the cross-check against the chain vectors
// (environment_deks of chain-entries.json) and re-wrap invariance
// (backfill / repair re-registration — the commitment is invariant even when
// HPKE Seal randomness changes the wrap).

import {
  buildDekCommitmentBytes,
  computeDekCommitment,
  type DekCommitmentContext,
  generateEncryptionKeyPair,
  SUITE_ID,
  unwrapDek,
  verifyDekCommitment,
  wrapDek,
} from "../../src/index.ts";
import dekCommitmentVectors from "../../test-vectors/dek-commitment.json" with { type: "json" };
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
import { vectorEntries, vectorEnvironmentDeks } from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

import { testEnvironmentId, testProjectId, testUserId } from "../support/fixture.ts";;

const baseVector = dekCommitmentVectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("dek-commitment.json: basic vector missing");
}
const base = baseVector;

function contextOf(vector: {
  readonly suite: string;
  readonly project_id: string;
  readonly environment_id: string;
  readonly epoch: number;
}): DekCommitmentContext {
  return {
    suite: vector.suite,
    projectId: testProjectId(vector.project_id),
    environmentId: testEnvironmentId(vector.environment_id),
    epoch: vector.epoch,
  };
}

async function vectorChecks(c: Checks): Promise<void> {
  for (const vector of dekCommitmentVectors.vectors) {
    const context = contextOf(vector);
    const dek = fromHex(vector.dek_hex);
    c.push(
      `dek-commitment: ${vector.name} preimage`,
      toHex(buildDekCommitmentBytes(context, dek)) === vector.preimage_hex,
    );
    const computed = await computeDekCommitment({ context, dek });
    c.push(
      `dek-commitment: ${vector.name} commitment`,
      computed.ok && computed.value === vector.commitment_hex,
    );
    const verified = await verifyDekCommitment({
      context,
      dek,
      expectedCommitmentHex: vector.commitment_hex,
    });
    c.push(`dek-commitment: ${vector.name} verify`, verified.ok);
  }
}

async function negativeChecks(c: Checks): Promise<void> {
  for (const negative of dekCommitmentVectors.negative) {
    const context = contextOf(negative.context);
    const dek = fromHex(negative.context.dek_hex.toLowerCase());
    // The commitment computed under the modified context must match the vector's
    // computed value, and verification against the basic commitment (the value
    // the chain would carry) must fail with DekCommitmentMismatch.
    // uppercase-hex is reinterpreted as pinning that "this implementation cannot
    // generate an uppercase-hex preimage" (encodeHex is the only generation
    // point) — identical DEK bytes yield the lowercase-preimage commitment
    if (negative.name === "uppercase-hex") {
      const computed = await computeDekCommitment({ context, dek });
      c.push(
        `dek-commitment negative: ${negative.name}`,
        computed.ok &&
          computed.value !== negative.computed_commitment_hex &&
          computed.value === negative.expected_commitment_hex,
      );
      continue;
    }
    const computed = await computeDekCommitment({ context, dek });
    const verified = await verifyDekCommitment({
      context,
      dek,
      expectedCommitmentHex: negative.expected_commitment_hex,
    });
    c.push(
      `dek-commitment negative: ${negative.name}`,
      computed.ok &&
        computed.value === negative.computed_commitment_hex &&
        !verified.ok &&
        verified.error.kind === "DekCommitmentMismatch",
    );
  }
}

/** Cross-check against the chain vectors: the published value in a create/rotate payload = the value recomputed from the dummy DEK. */
async function chainCrossChecks(c: Checks): Promise<void> {
  const genesis = vectorEntries[0];
  if (genesis === undefined) {
    c.push("dek-commitment: chain cross-check setup", false, "genesis missing");
    return;
  }
  const projectId = testProjectId(genesis.entry_hash_hex); // project ID = genesis hash (§6.4)
  for (const entry of vectorEntries) {
    if (entry.op !== "create_environment" && entry.op !== "rotate_epoch") {
      continue;
    }
    const environmentId = testEnvironmentId(String(entry.payload["environment_id"]));
    const epoch = entry.op === "create_environment" ? 1 : Number(entry.payload["new_epoch"]);
    const info = vectorEnvironmentDeks[environmentId]?.[String(epoch)];
    if (info === undefined) {
      c.push(`dek-commitment: chain seq ${entry.seq}`, false, "environment dek missing");
      continue;
    }
    const verified = await verifyDekCommitment({
      context: { suite: SUITE_ID, projectId, environmentId, epoch },
      dek: fromHex(info.dek_hex),
      expectedCommitmentHex: String(entry.payload["dek_commitment_hex"]),
    });
    c.push(`dek-commitment: chain seq ${entry.seq} payload matches DEK`, verified.ok);
  }
}

/**
 * Re-wrap invariance (§5.2 / rewrap_invariance in dek-commitment.json): re-wrapping
 * the same DEK to a new recipient (backfill / repair re-registration — HPKE Seal
 * is randomized) still leaves the unwrapped DEK verifying against the same
 * commitment.
 */
async function rewrapInvarianceChecks(c: Checks): Promise<void> {
  const invariance = dekCommitmentVectors.rewrap_invariance;
  const dek = fromHex(invariance.dek_hex);
  const context = contextOf(base);
  const recipient = await generateEncryptionKeyPair();
  const wrapContext = {
    projectId: testProjectId(base.project_id),
    environmentId: testEnvironmentId(base.environment_id),
    epoch: base.epoch,
    recipientUserId: testUserId("user-backfilled-0006"),
  };
  const wrapped = await wrapDek({
    recipientPublicKey: recipient.publicKey,
    dek,
    context: wrapContext,
  });
  if (!wrapped.ok) {
    c.push("dek-commitment: rewrap invariance", false, "wrap failed");
    return;
  }
  const unwrapped = await unwrapDek({
    recipientKeyPair: recipient,
    wrapped: wrapped.value,
    context: wrapContext,
  });
  if (!unwrapped.ok) {
    c.push("dek-commitment: rewrap invariance", false, "unwrap failed");
    return;
  }
  // The new wrap's ciphertext differs from the fixed vector's wrap (Seal
  // randomness), yet the commitment verification succeeds (the preimage has no
  // wrap-related fields)
  const differs = toHex(wrapped.value.ciphertext) !== dekWrapVectors.vectors[0]?.ciphertext_hex;
  const verified = await verifyDekCommitment({
    context,
    dek: unwrapped.value,
    expectedCommitmentHex: invariance.commitment_hex,
  });
  c.push("dek-commitment: rewrap invariance", differs && verified.ok);
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const context = contextOf(base);
  const dek = fromHex(base.dek_hex);
  const shortDek = await computeDekCommitment({ context, dek: dek.slice(0, 16) });
  c.push(
    "dek-commitment invalid input: short dek",
    !shortDek.ok && shortDek.error.kind === "InvalidInput",
  );
  const badEpoch = await computeDekCommitment({ context: { ...context, epoch: 0 }, dek });
  c.push(
    "dek-commitment invalid input: epoch below 1",
    !badEpoch.ok && badEpoch.error.kind === "InvalidInput",
  );
  const uppercaseExpected = await verifyDekCommitment({
    context,
    dek,
    expectedCommitmentHex: base.commitment_hex.toUpperCase(),
  });
  c.push(
    "dek-commitment invalid input: uppercase expected commitment",
    !uppercaseExpected.ok && uppercaseExpected.error.kind === "InvalidInput",
  );
}

export async function dekCommitmentChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorChecks(c);
  await negativeChecks(c);
  await chainCrossChecks(c);
  await rewrapInvarianceChecks(c);
  await invalidInputChecks(c);
  return c.results;
}
