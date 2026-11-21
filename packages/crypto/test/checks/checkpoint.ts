import type { ChainEntry, ChainHistoryIndex, UnsignedChainEntry } from "../../src/index.ts";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  type EnvValuesDigestEntry,
  importSigningKeyPair,
  signChainEntry,
  verifyChainWithHistory,
} from "../../src/index.ts";
import { testEnvironmentId, testUserId, testVariableId } from "../support/fixture.ts";
import {
  toTypedEntry,
  typedEntries,
  vectorExtendedChains,
  vectorKeys,
  vectorValuesDigests,
} from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex } from "./support.ts";

function typedDigestEntries(
  entries: (typeof vectorValuesDigests)[number]["entries"],
): EnvValuesDigestEntry[] {
  return entries.map((entry) => ({
    variableId: testVariableId(entry.variable_id),
    version: Number(entry.version),
    valueSigHashHex: entry.value_sig_hash_hex,
  }));
}

async function valuesDigestVectorChecks(c: Checks): Promise<void> {
  for (const digestCase of vectorValuesDigests) {
    const computed = await computeEnvValuesDigest(
      "maruhi/v1",
      typedDigestEntries(digestCase.entries),
    );
    c.push(
      `checkpoint values-digest ${digestCase.name}`,
      computed.ok && computed.value === digestCase.values_digest_hex,
      computed.ok ? undefined : JSON.stringify(computed.error),
    );
    const reversed = await computeEnvValuesDigest(
      "maruhi/v1",
      typedDigestEntries(digestCase.entries.toReversed()),
    );
    c.push(
      `checkpoint values-digest ${digestCase.name}: order-independent input`,
      reversed.ok && reversed.value === digestCase.values_digest_hex,
    );
  }
  const single = vectorValuesDigests.find((digestCase) => digestCase.name === "single-entry");
  if (single !== undefined && single.entries.length === 1) {
    const duplicated = await computeEnvValuesDigest(
      "maruhi/v1",
      typedDigestEntries([...single.entries, ...single.entries]),
    );
    c.push(
      "checkpoint values-digest: duplicate variable id rejected",
      !duplicated.ok && duplicated.error.kind === "InvalidInput",
    );
  }
}

async function valuesDigestInvalidInputChecks(c: Checks): Promise<void> {
  const validEntry: EnvValuesDigestEntry = {
    variableId: testVariableId("var-a-0001"),
    version: 1,
    valueSigHashHex: "ab".repeat(32),
  };
  const badEntries: readonly { readonly name: string; readonly entry: EnvValuesDigestEntry }[] = [
    { name: "version zero", entry: { ...validEntry, version: 0 } },
    { name: "fractional version", entry: { ...validEntry, version: 1.5 } },
    {
      name: "unsafe integer version",
      entry: { ...validEntry, version: Number.MAX_SAFE_INTEGER + 1 },
    },
    {
      name: "uppercase value sig hash",
      entry: { ...validEntry, valueSigHashHex: "AB".repeat(32) },
    },
    { name: "empty variable id", entry: { ...validEntry, variableId: testVariableId("") } },
  ];
  for (const bad of badEntries) {
    const result = await computeEnvValuesDigest("maruhi/v1", [bad.entry]);
    c.push(
      `checkpoint values-digest invalid input: ${bad.name}`,
      !result.ok && result.error.kind === "InvalidInput",
    );
  }
  const emptySuite = await computeEnvValuesDigest("", []);
  c.push(
    "checkpoint values-digest invalid input: empty suite",
    !emptySuite.ok && emptySuite.error.kind === "InvalidInput",
  );
}

async function baselineView() {
  const extended = vectorExtendedChains["checkpoint-baseline"];
  if (extended === undefined) {
    throw new Error("checkpoint-baseline extended chain missing");
  }
  const entries = [
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
  ];
  const result = await verifyChainWithHistory(entries);
  if (!result.ok) {
    throw new Error("checkpoint-baseline chain failed verification");
  }
  return { extended, entries, ...result.value };
}

function tupleChecks(c: Checks, history: ChainHistoryIndex): void {
  const dev = history.checkpointTupleFor("env-dev-0002", 3);
  c.push("checkpoint history: unique tuple for env-dev", dev?.kind === "unique" && dev.seq === 13);
  const prod = history.checkpointTupleFor("env-prod-0001", 2);
  c.push(
    "checkpoint history: re-attested tuple stays unique",
    prod?.kind === "unique" && prod.seq === 13 && prod.epoch === 2,
  );
  c.push(
    "checkpoint history: uncovered manifest version is undefined",
    history.checkpointTupleFor("env-prod-0001", 1) === undefined,
  );
  c.push(
    "checkpoint history: unknown environment is undefined",
    history.checkpointTupleFor("env-ghost-9999", 1) === undefined,
  );
  c.push(
    "checkpoint history: non-integer manifest version is undefined",
    history.checkpointTupleFor("env-prod-0001", 2.5) === undefined &&
      history.checkpointTupleFor("env-prod-0001", 0) === undefined,
  );
}

async function signAs(userId: string, entry: UnsignedChainEntry): Promise<ChainEntry> {
  const keys = vectorKeys[userId];
  if (keys === undefined) {
    throw new Error(`chain vector keys for ${userId} missing`);
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    throw new Error("signing key import failed");
  }
  const signed = await signChainEntry({ entry, signingKey: pair.value.privateKey });
  if (!signed.ok) {
    throw new Error("chain entry signing failed");
  }
  return signed.value;
}

async function equivocationChecks(c: Checks): Promise<void> {
  const view = await baselineView();
  const admin = vectorKeys["user-admin-0003"];
  const head14 = view.entries[view.entries.length - 1];
  if (admin === undefined || head14 === undefined) {
    c.push("checkpoint history: setup", false, "fixture missing");
    return;
  }
  const baseTuple = view.state.checkpoints.get(testEnvironmentId("env-prod-0001"));
  if (baseTuple === undefined) {
    c.push("checkpoint history: setup", false, "baseline tuple missing");
    return;
  }
  const forged = await signAs("user-admin-0003", {
    suite: "maruhi/v1",
    seq: 15,
    prevHashHex: await computeChainEntryHash(head14),
    actor: { userId: testUserId("user-admin-0003"), keyFingerprintHex: admin.key_fingerprint_hex },
    timestampMs: head14.timestampMs + 1000,
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: testEnvironmentId("env-prod-0001"),
          epoch: 2,
          manifestVersion: 2,
          manifestSigHashHex: "ef".repeat(32),
          valuesDigestHex: baseTuple.valuesDigestHex,
        },
      ],
      auditHeadHashHex: "",
    },
  });
  const result = await verifyChainWithHistory([...view.entries, forged]);
  if (!result.ok) {
    c.push("checkpoint history: equivocating append verifies", false, JSON.stringify(result.error));
    return;
  }
  c.push("checkpoint history: equivocating append verifies", true);
  c.push(
    "checkpoint history: conflicting tuple lookup",
    result.value.history.checkpointTupleFor("env-prod-0001", 2)?.kind === "conflicting",
  );
  c.push(
    "checkpoint history: unrelated tuple stays unique",
    result.value.history.checkpointTupleFor("env-dev-0002", 3)?.kind === "unique",
  );
}

async function derivedStateChecks(c: Checks): Promise<void> {
  const view = await baselineView();
  const fromState = view.state.checkpoints.get(testEnvironmentId("env-prod-0001"));
  const fromHistory = view.history.latestCheckpointFor("env-prod-0001");
  c.push(
    "checkpoint history: latest checkpoint mirrors chain state",
    fromState !== undefined &&
      fromHistory !== undefined &&
      fromState.seq === fromHistory.seq &&
      fromState.valuesDigestHex === fromHistory.valuesDigestHex &&
      fromHistory.seq === 14,
  );
  c.push(
    "checkpoint history: latest checkpoint absent for uncovered environment",
    view.history.latestCheckpointFor("env-stage-0003") === undefined &&
      view.state.checkpoints.get(testEnvironmentId("env-stage-0003")) === undefined,
  );
  const canonical = await verifyChainWithHistory(typedEntries);
  c.push(
    "checkpoint history: canonical chain has no tuples",
    canonical.ok &&
      canonical.value.state.checkpoints.size === 0 &&
      canonical.value.history.checkpointTupleFor("env-prod-0001", 2) === undefined &&
      canonical.value.history.latestCheckpointFor("env-prod-0001") === undefined,
  );
}

export async function checkpointChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await valuesDigestVectorChecks(c);
  await valuesDigestInvalidInputChecks(c);
  const view = await baselineView();
  tupleChecks(c, view.history);
  await derivedStateChecks(c);
  await equivocationChecks(c);
  return c.results;
}
