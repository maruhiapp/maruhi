// Server-side verification (CRYPTO_SPEC §6.4 = verifyChain re-run) —
// rejection tests for the authorization negative vectors that go
// through generic append (including the checkpoint wire-schema
// rejections). Negatives via the composite endpoint live in
// membership-negatives-composite.test.ts.
// The shared fixture and vector-replay helpers are in
// support/membership-scenario.ts (for the split's motivation see the
// top of the scenario module).

import type { ChainEntry } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { resignEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  registerMembershipScenario,
  remapProposalRef,
  replayNegativePrefix,
  replayVectorChain,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

/**
 * Generic-append tests for the checkpoint op: a fixed-length-hex
 * format violation is rejected first at 400 by api-schema's hex
 * Schema (the same division of labor as the create-env-commitment-*
 * composite expectations). The other consensus-rule negatives (role /
 * audit role / unknown / epoch / regression and the check order) are
 * pinned reason-by-reason by the crypto layer's 4-runtime tests, and
 * their prerequisite chain (the checkpoint-baseline derived chain —
 * dummy tuple content) cannot pass §16-2's content match and cannot
 * be replayed through the API, so they are not repeated here. The
 * API's acceptance surface (2 authorization levels, 5 content-match
 * reasons, atomicity, snapshot storage) is pinned with real data by
 * data-checkpoint.test.ts.
 */
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

/**
 * Among ES / PF1's (2026-09-14) structural negatives, the ones where
 * api-schema's closed-set literals (scope_kind / ops / inner op),
 * fixed-length hex (proposal_hash_hex), or the inner payload's
 * required fields reject at 400 before verifyChain (the same division
 * as the create-env-commitment-* / checkpoint-* hex Schemas).
 * `invalid-payload` as a consensus rule is pinned reason-by-reason by
 * the crypto layer's 4-runtime tests
 */
/**
 * Among the structural negatives, shapes the test-time signing API
 * (signChainEntry) does not accept (a negative expires_at_ms is
 * outside §2.1's encoding). Since structural checks precede signature
 * verification, sending it unresigned still settles the reason code
 * at the structural stage (invalid-payload)
 */
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
  // Device keys (DK): closed-set literals (role_cap / ops) and
  // fixed-length hex (public key, FP) are rejected by api-schema at
  // 400 first. Since K3 (2026-09-20) the prerequisite chain (device-
  // derived) is replayed and these are pinned on the normal path
  "add-device-role-cap-unknown",
  "add-device-enc-pub-bad-length",
  "add-device-sig-pub-uppercase-hex",
  "add-device-format-precedes-actor",
  "revoke-device-fp-bad-length",
  "policy-ops-add-device",
  "policy-ops-revoke-device",
]);

type AuthzNegative = (typeof vectorAuthzNegatives)[number];

/** Replay the prerequisite chain, then send the original with only seq / prev re-pointed at the real head (not re-signed). */
async function appendUnsignedAtHead(negative: AuthzNegative): Promise<Response> {
  const { head } = await replayNegativePrefix(negative);
  return appendEntry(vectorProjectId, head.hashHex, {
    ...toWireEntry(negative.entry),
    seq: head.seq + 1,
    prevHashHex: head.hashHex,
  });
}

/**
 * A shape the signing API refuses (negative expires_at_ms) cannot be
 * re-signed. Since structural checks precede signature verification
 * (the §6.3 verification stage order), sending the original settles
 * the reason code at the structural stage
 */
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

/** Rejection at a consensus rule (verifyChain) — re-sign at the real head and send; pin the reason code and seq. */
function registerConsensusRejectTest(negative: AuthzNegative): void {
  // For a non-member actor, §11-2's existence hiding (404) acts before verifyChain
  const expectsConcealment = negative.expected_reason === "actor-not-member";
  const label = expectsConcealment
    ? `rejects ${negative.name} with 404 (§11-2 concealment)`
    : `rejects ${negative.name} with 422 (${negative.expected_reason})`;
  it(label, async () => {
    const { head } = await replayNegativePrefix(negative);
    // Re-sign at the real head (absorbing the shift from inserted
    // boundary checkpoints — same as the composite side). approve /
    // withdraw references are re-pointed at the real hash from
    // replay
    const { entry } = await resignEntryAt(
      remapProposalRef(toWireEntry(negative.entry)),
      head.seq + 1,
      head.hashHex,
    );
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

/**
 * Splitting the authz negatives (pullfrog round 3): pin each branch's
 * count exactly so the suite cannot quietly empty as the judgment
 * widens. K5 (2026-09-16) removed the acceptance guard and returned
 * four-eyes-op negatives and negatives whose prerequisite chains
 * include four-eyes ops all to the normal paths (a consensus-rule 422
 * / wire-schema 400 / pre-signature structural stage) (the K2-10
 * breakdown of `skipped` 58 + `fourEyesGuard` 7 = 65: consensus +57,
 * wireSchema +7, structureBeforeSignature +1).
 *
 * 2026-09-20 DK K2 (authz negatives +57): the device-op negatives
 * (41) plus negatives that write a device op into ops (2) had an
 * acceptance guard (`deviceOpsGuard` 43); the rest whose prerequisite
 * is a device-derived chain (10) were `skipped`. **K3 (2026-09-20)
 * removed the acceptance guard and returned both branches to the
 * normal paths** (design record dk-design.md §8 K3-12 — the same
 * procedure as ES K2-10 → K5): a device-derived chain is replayed by
 * `replayNegativePrefix` via generic append (the acceptance itself
 * pins §6.2's permissive side). Breakdown: consensus 104 + 36
 * (consensus rules on device ops) + 10 (device-derived-chain
 * prerequisites) = 150, wireSchema 8 + 7 (closed-set literals and
 * fixed-length hex on device ops) = 15
 */
const EXPECTED_PARTITION = {
  checkpoint: 21,
  composite: 27,
  structureBeforeSignature: 1,
  wireSchema: 15,
  consensus: 150,
} as const;

type PartitionBucket = keyof typeof EXPECTED_PARTITION;

/**
 * A negative's branch (the judgment order is fixed): checkpoint →
 * composite (create / rotate) → the four-eyes (PF1) 4 ops and
 * four-eyes-derived chains are replayed and accepted by the server
 * since K5; the device-key (DK) 2 ops and device-derived chains since
 * K3 (propose's acceptance policy does not reject fixed-timestamp
 * vectors — expires_at_ms stays within its upper bound, and an
 * expired proposal is merely excluded from the pending-count
 * computation. Design record es-design.md §11 K5-C)
 */
function bucketOf(negative: AuthzNegative): PartitionBucket {
  const op = negative.entry.op;
  if (op === "checkpoint") {
    return "checkpoint";
  }
  if (op === "create_environment" || op === "rotate_epoch") {
    return "composite";
  }
  if (UNSIGNABLE_STRUCTURE_NEGATIVES.has(negative.name)) {
    return "structureBeforeSignature";
  }
  return WIRE_SCHEMA_REJECTED.has(negative.name) ? "wireSchema" : "consensus";
}

/** Registration per branch (composites go to membership-negatives-composite.test.ts; skipped exists only in the crypto layer). */
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
    // Reconstructing the vector negative "tampered-payload-role":
    // rewrite entry 2's payload role while keeping the original
    // signature → rejected at signature verification
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
