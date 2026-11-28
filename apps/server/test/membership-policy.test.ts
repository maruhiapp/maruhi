import type { ChainEntry } from "@maruhi/crypto";
import { testKeyFingerprintHex, testUserId } from "@maruhi/crypto/test-support";
import { signEntryAt } from "@maruhi/test-kit";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { chainCapacityExceeded } from "../src/do/chain-accept.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
  MAX_REQUEST_BODY_BYTES,
} from "../src/policy.ts";
import { BASE, JSON_HEADERS } from "./support/auth.ts";
import { vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { identityOf } from "./support/data-crypto.ts";
import {
  appendEntry,
  initChain,
  registerMembershipScenario,
  replayVectorChain,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

describe("admission policy (§6.4 size limits)", () => {
  it("rejects an entry whose canonical bytes exceed 1 MiB with 413", async () => {
    await replayVectorChain(1);
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const oversized: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "remove_member",
      actor: {
        userId: testUserId("user-owner-0001"),
        keyFingerprintHex: testKeyFingerprintHex("ab".repeat(16)),
      },
      payload: { targetUserId: testUserId("u".repeat(1_200_000)) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const response = await appendEntry(vectorProjectId, genesis.entry_hash_hex, oversized);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects a raw request body over the transport cap with a plain 413", async () => {
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: `{"entry":"${"x".repeat(MAX_REQUEST_BODY_BYTES + 1024)}"}`,
    });
    expect(response.status).toBe(413);
  });

  it("enforces the transport cap on the measured stream, not the Content-Length header", async () => {
    const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
    const chunkCount = Math.ceil((MAX_REQUEST_BODY_BYTES + 1024 * 1024) / chunk.length);
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= chunkCount) {
          controller.close();
          return;
        }
        sent += 1;
        controller.enqueue(chunk);
      },
    });
    const response = await SELF.fetch(`${BASE}/projects`, {
      method: "POST",
      headers: JSON_HEADERS,
      body,
    });
    expect(response.status).toBe(413);
  });

  it("rejects an oversized genesis at init with 413 (worker-side pre-check)", async () => {
    const oversizedGenesis: ChainEntry = {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "0".repeat(64),
      op: "genesis",
      actor: {
        userId: testUserId("u".repeat(600_000)),
        keyFingerprintHex: testKeyFingerprintHex("ab".repeat(16)),
      },
      payload: { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const second: ChainEntry = {
      ...oversizedGenesis,
      actor: {
        ...oversizedGenesis.actor,
        userId: testUserId("u".repeat(600_000) + "v".repeat(500_000)),
      },
    };
    const response = await initChain(second);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects an append once cumulative canonical bytes would exceed the cap", async () => {
    await replayVectorChain(2);
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE chain_entries SET canonical_bytes = ? WHERE seq = 1",
        MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      );
    });
    await evictDurableObject(stub);
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entries");
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actor: identityOf("user-owner-0001"),
      operation: { op: "remove_member", payload: { targetUserId: testUserId("user-member-0002") } },
    });
    const response = await appendEntry(vectorProjectId, entry2.entry_hash_hex, entry);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { maxTotalBytes: number };
    expect(body.maxTotalBytes).toBe(MAX_CHAIN_TOTAL_CANONICAL_BYTES);
  });

  it("caps the total entry count (§6.4 receipt policy, unit-level)", () => {
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES, 0, 10)).toBe(true);
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES - 1, 0, 10)).toBe(false);
    expect(chainCapacityExceeded(1, MAX_CHAIN_TOTAL_CANONICAL_BYTES, 1)).toBe(true);
  });
});
