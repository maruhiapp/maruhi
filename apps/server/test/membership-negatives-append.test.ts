import type { ChainEntry } from "@maruhi/crypto";
import { resignEntryAt } from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { signerOf } from "./support/data-crypto.ts";
import {
  appendEntry,
  registerMembershipScenario,
  remapProposalRef,
  replayNegativePrefix,
  replayVectorChain,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

function registerCheckpointAppendGuardTest(negative: (typeof vectorAuthzNegatives)[number]): void {
  const schemaRejected = [
    "checkpoint-manifest-hash-uppercase-hex",
    "checkpoint-values-digest-bad-length",
    "checkpoint-format-precedes-role",
  ].includes(negative.name);
  if (!schemaRejected) {
    return;
  }
  it(`rejects ${negative.name} at the wire schema (400)`, async () => {
    await replayVectorChain(1);
    const response = await appendEntry(
      vectorProjectId,
      negative.entry.prev_hash_hex,
      toWireEntry(negative.entry),
    );
    expect(response.status).toBe(400);
  });
}

const UNSIGNABLE_STRUCTURE_NEGATIVES: ReadonlySet<string> = new Set(["propose-expires-negative"]);

const WIRE_SCHEMA_REJECTED: ReadonlySet<string> = new Set([
  "scope-kind-unknown",
  "policy-ops-rotate",
  "policy-ops-unknown-op",
  "propose-inner-op-unknown",
  "propose-inner-op-nested",
  "propose-inner-shape-precedes-role",
  "approve-hash-uppercase",
  "approve-hash-bad-length",
  "add-device-role-cap-unknown",
  "add-device-enc-pub-bad-length",
  "add-device-sig-pub-uppercase-hex",
  "add-device-format-precedes-actor",
  "revoke-device-fp-bad-length",
  "policy-ops-add-device",
  "policy-ops-revoke-device",
  "policy-ops-delete-environment",
]);

type AuthzNegative = (typeof vectorAuthzNegatives)[number];

async function appendUnsignedAtHead(negative: AuthzNegative): Promise<Response> {
  const { head } = await replayNegativePrefix(negative);
  return appendEntry(vectorProjectId, head.hashHex, {
    ...toWireEntry(negative.entry),
    seq: head.seq + 1,
    prevHashHex: head.hashHex,
  });
}

function registerStructureBeforeSignatureTest(negative: AuthzNegative): void {
  it(`rejects ${negative.name} with 422 (${negative.expected_reason}) before the signature`, async () => {
    const response = await appendUnsignedAtHead(negative);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe(negative.expected_reason);
  });
}

function registerWireSchemaRejectTest(negative: AuthzNegative): void {
  it(`rejects ${negative.name} at the wire schema (400)`, async () => {
    const response = await appendUnsignedAtHead(negative);
    expect(response.status).toBe(400);
  });
}

function registerConsensusRejectTest(negative: AuthzNegative): void {
  const expectsConcealment = negative.expected_reason === "actor-not-member";
  const label = expectsConcealment
    ? `rejects ${negative.name} with 404 (§11-2 concealment)`
    : `rejects ${negative.name} with 422 (${negative.expected_reason})`;
  it(label, async () => {
    const { head } = await replayNegativePrefix(negative);
    const base = remapProposalRef(toWireEntry(negative.entry));
    const { entry } = await resignEntryAt(base, head.seq + 1, head.hashHex, signerOf(base));
    const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
    if (expectsConcealment) {
      expect(response.status).toBe(404);
      return;
    }
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe(negative.expected_reason);
    expect(body.seq).toBe(entry.seq);
  });
}

const EXPECTED_PARTITION = {
  checkpoint: 24,
  composite: 42,
  structureBeforeSignature: 1,
  wireSchema: 16,
  consensus: 174,
} as const;

type PartitionBucket = keyof typeof EXPECTED_PARTITION;

function bucketOf(negative: AuthzNegative): PartitionBucket {
  const op = negative.entry.op;
  if (op === "checkpoint") {
    return "checkpoint";
  }
  if (op === "create_environment" || op === "rotate_epoch" || op === "delete_environment") {
    return "composite";
  }
  if (UNSIGNABLE_STRUCTURE_NEGATIVES.has(negative.name)) {
    return "structureBeforeSignature";
  }
  return WIRE_SCHEMA_REJECTED.has(negative.name) ? "wireSchema" : "consensus";
}

const REGISTER_BY_BUCKET: Record<PartitionBucket, (negative: AuthzNegative) => void> = {
  checkpoint: registerCheckpointAppendGuardTest,
  composite: () => undefined,
  structureBeforeSignature: registerStructureBeforeSignatureTest,
  wireSchema: registerWireSchemaRejectTest,
  consensus: registerConsensusRejectTest,
};

describe("server-side verification (§6.4) — authorization negative vectors (via generic append)", () => {
  const partition: Record<PartitionBucket, number> = {
    checkpoint: 0,
    composite: 0,
    structureBeforeSignature: 0,
    wireSchema: 0,
    consensus: 0,
  };
  for (const negative of vectorAuthzNegatives) {
    const bucket = bucketOf(negative);
    partition[bucket] += 1;
    REGISTER_BY_BUCKET[bucket](negative);
  }

  it("partitions the authz negatives as expected (K5 — four-eyes ops, DK K3 — device ops included; all replayed)", () => {
    expect(partition).toEqual(EXPECTED_PARTITION);
    expect(Object.values(partition).reduce((a, b) => a + b, 0)).toBe(vectorAuthzNegatives.length);
  });

  it("rejects a tampered payload with 422 (bad-signature)", async () => {
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    const entry2 = vectorEntries[1];
    if (genesis === undefined || entry2 === undefined) throw new Error("missing vectors");
    const wire = toWireEntry(entry2);
    if (wire.op !== "add_member") throw new Error("vector entry 2 should be add_member");
    const tampered: ChainEntry = {
      ...wire,
      payload: { ...wire.payload, role: "admin" },
    };
    const response = await appendEntry(vectorProjectId, genesis.entry_hash_hex, tampered);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("bad-signature");
  });
});
