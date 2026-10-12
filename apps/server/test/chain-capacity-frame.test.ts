// The chain's byte cap against the DO RPC frame (CRYPTO_SPEC §6.4 / AUTH_SPEC
// §14-2 — 2026-10-12 Sc-3a): a chain filled to the 12 MiB cap with the
// entries of the highest serialized-to-canonical ratio still answers its
// fetch inside one RPC result, a lease of a full environment on it answers
// even though the response is larger than one frame (the chain and the
// values are separate RPC results), and one more byte is a typed 422.
// Real workerd via @cloudflare/vitest-plugin; the fixture lives in
// support/data-scenario.ts.

import type { ChainOperation } from "@maruhi/crypto";
import { canonicalChainEntryBytes } from "@maruhi/crypto";
import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENVIRONMENT_CIPHERTEXT_BYTES,
  MAX_VALUE_CIPHERTEXT_BYTES,
} from "../src/policy.ts";
import { rotateEpochOperation, signEntryAt } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
} from "./support/data-fixture.ts";
import {
  cloneVariableRows,
  declareVariableOk,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import {
  type LeaseBody,
  readyProject,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { evictProjectDo, queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** workerd refuses a DO RPC result serialized above this. */
const RPC_FRAME_BYTES = 32 * 1024 * 1024;
const BLOAT_ENV = "env-bloat-0001";
const COMMITMENT = "7a".repeat(32);
const MAX_REASON_BYTES = 1024;
const TUPLE_LESS_CHECKPOINT: ChainOperation = {
  op: "checkpoint",
  payload: { environments: [], auditHeadHashHex: "" },
};

async function canonicalSizeAt(seq: number, operation: ChainOperation): Promise<number> {
  const { entry } = await signEntryAt({
    seq,
    prevHashHex: "00".repeat(32),
    actorUserId: OWNER,
    operation,
  });
  return canonicalChainEntryBytes(entry).length;
}

const checkpointSizes = new Map<number, number>();

/** A tuple-less checkpoint's canonical size at `seq` (it varies only with the digit count). */
async function checkpointSizeAt(seq: number): Promise<number> {
  const digits = String(seq).length;
  const known = checkpointSizes.get(digits);
  if (known !== undefined) {
    return known;
  }
  const size = await canonicalSizeAt(seq, TUPLE_LESS_CHECKPOINT);
  checkpointSizes.set(digits, size);
  return size;
}

async function storedChainBytes(): Promise<{ readonly entries: number; readonly bytes: number }> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n, SUM(canonical_bytes) AS bytes FROM chain_entries",
  );
  return { entries: Number(rows[0]?.["n"]), bytes: Number(rows[0]?.["bytes"]) };
}

/**
 * Appends valid `rotate_epoch` entries of BLOAT_ENV straight into DO storage
 * (verified again on the DO's next load) until the room left is exactly a
 * tuple-less checkpoint at the next seq. A rotation with a 1,024-byte reason
 * is ~1.1× its canonical size on the wire — near the worst ratio an entry of
 * that size has (CRYPTO_SPEC §6.4) — so the filled chain is a worst case for
 * the frame.
 */
async function fillChainToCheckpointRoom(): Promise<void> {
  let used = (await storedChainBytes()).bytes;
  let epoch = 1;
  const rows: { seq: number; json: string; hash: string; bytes: number }[] = [];
  for (;;) {
    const seq = fixture.head.seq + 1;
    const left = MAX_CHAIN_TOTAL_CANONICAL_BYTES - used - (await checkpointSizeAt(seq + 1));
    const bare = await canonicalSizeAt(
      seq,
      rotateEpochOperation(BLOAT_ENV, epoch + 1, COMMITMENT, ""),
    );
    const last = left - bare <= MAX_REASON_BYTES;
    // The last entry takes exactly what is left; the one before leaves it room
    const reasonBytes = last ? left - bare : Math.min(MAX_REASON_BYTES, left - 2 * bare - 1);
    expect(reasonBytes).toBeGreaterThanOrEqual(0);
    epoch += 1;
    const { entry, hash } = await signEntryAt({
      seq,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: rotateEpochOperation(BLOAT_ENV, epoch, COMMITMENT, "r".repeat(reasonBytes)),
    });
    const bytes = canonicalChainEntryBytes(entry).length;
    rows.push({ seq, json: JSON.stringify(entry), hash, bytes });
    used += bytes;
    fixture.head = { seq, hashHex: hash };
    if (last) {
      break;
    }
  }
  const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
  await runInDurableObject(stub, (_instance, state) => {
    for (const row of rows) {
      state.storage.sql.exec(
        "INSERT INTO chain_entries (seq, entry_json, entry_hash_hex, canonical_bytes) VALUES (?, ?, ?, ?)",
        row.seq,
        row.json,
        row.hash,
        row.bytes,
      );
    }
  });
  // Rows written outside an append do not show through the parsed-chain cache
  await evictProjectDo(projectId);
}

describe("the chain cap against the RPC frame (CRYPTO_SPEC §6.4 / AUTH_SPEC §14-2 — Sc-3a)", () => {
  it("a chain at the 12 MiB cap fits one RPC result; a full environment's lease on it exceeds one frame and still answers; one more entry is a typed 422", async () => {
    await readyProject();
    await createEnvironmentOk(fixture, BLOAT_ENV, "Bloat");
    // The environment at its 8 MiB cap (VAR's own value tops it up — reads
    // are never refused for that cap) plus declared statements with long
    // descriptions: the lease's values half alone stays inside one frame
    await declareVariableOk({
      variableId: "var-declared-0001",
      name: "DECLARED",
      schema: { description: "d".repeat(1024) },
    });
    await cloneVariableRows({
      source: VAR,
      count: MAX_ENVIRONMENT_CIPHERTEXT_BYTES / MAX_VALUE_CIPHERTEXT_BYTES,
      prefix: "var-full",
      valueBytes: MAX_VALUE_CIPHERTEXT_BYTES,
    });
    await cloneVariableRows({ source: "var-declared-0001", count: 3000, prefix: "var-decl" });

    await fillChainToCheckpointRoom();
    // The cap is reachable under the entry cap with these entries
    expect((await storedChainBytes()).entries).toBeLessThan(MAX_CHAIN_ENTRIES);
    // The last room goes to an ordinary append, landing on the cap exactly
    await appendOperation(fixture, OWNER, TUPLE_LESS_CHECKPOINT);
    const stored = await storedChainBytes();
    expect(stored.bytes).toBe(MAX_CHAIN_TOTAL_CANONICAL_BYTES);

    const fetched = await requestJson("GET", "/chain", token(MEMBER));
    expect(fetched.status).toBe(200);
    const fetchedBody = await fetched.text();
    expect(fetchedBody.length).toBeGreaterThan(MAX_CHAIN_TOTAL_CANONICAL_BYTES);
    expect(fetchedBody.length).toBeLessThan(RPC_FRAME_BYTES / 2);

    const { publicKeyHex } = await workloadKeyPair();
    const lease = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: publicKeyHex,
    });
    expect(lease.status).toBe(200);
    const leaseText = await lease.text();
    expect(leaseText.length).toBeGreaterThan(RPC_FRAME_BYTES + 2 * 1024 * 1024);
    const leaseBody = JSON.parse(leaseText) as LeaseBody;
    expect(leaseBody.chain.length).toBe(stored.entries);
    expect(leaseBody.headSeq).toBe(stored.entries);
    expect(leaseBody.headHashHex).toBe(fixture.head.hashHex);
    const chainText = JSON.stringify(leaseBody.chain);
    expect(chainText.length).toBeLessThan(RPC_FRAME_BYTES / 2);
    expect(leaseText.length - chainText.length).toBeLessThan(RPC_FRAME_BYTES);

    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: TUPLE_LESS_CHECKPOINT,
    });
    const refused = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
    });
    expect(refused.status).toBe(422);
    await expect(refused.json()).resolves.toEqual({
      _tag: "ChainCapacityExceeded",
      maxEntries: MAX_CHAIN_ENTRIES,
      maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
    });
  }, 300_000);
});
