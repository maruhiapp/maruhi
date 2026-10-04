// Integration tests for the membership log admission policy (CRYPTO_SPEC §6.4
// size limits). Shared fixtures and vector replay helpers live in
// support/membership-scenario.ts (see that scenario module's header for why it
// was split out).

import type { ChainEntry } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { chainCapacityExceeded } from "../src/do/chain-accept.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
  MAX_REQUEST_BODY_BYTES,
} from "../src/policy.ts";
import { BASE, JSON_HEADERS } from "./support/auth.ts";
import { vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { signEntryAt } from "./support/data-crypto.ts";
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
    // A giant entry that violates the §6.1 field limit (1024 B) but can still
    // be canonicalized. The admission-policy check (1 MiB) runs before
    // verifyChain, so it becomes 413 (the op is one the generic append accepts
    // — rotate_epoch goes through a compound path, so build it from a
    // remove_member with a huge targetUserId)
    const oversized: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "remove_member",
      actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(16) },
      payload: { targetUserId: "u".repeat(1_200_000) },
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
    // Even a stream body that does not declare Content-Length
    // (chunked-equivalent) must hit the cap by actual measurement and become
    // 413 (prevents bypass via header spoofing or omission)
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
      actor: { userId: "u".repeat(600_000), keyFingerprintHex: "ab".repeat(16) },
      payload: { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    // Inflate actor.userId by another field's worth to push canonicalization
    // past 1 MiB
    const second: ChainEntry = {
      ...oversizedGenesis,
      actor: { ...oversizedGenesis.actor, userId: "u".repeat(600_000) + "v".repeat(500_000) },
    };
    // The size pre-check runs before the actor match (403) — resource
    // protection comes first
    const response = await initChain(second);
    expect(response.status).toBe(413);
    const body = (await response.json()) as { limitBytes: number };
    expect(body.limitBytes).toBe(MAX_ENTRY_CANONICAL_BYTES);
  });

  it("rejects an append once cumulative canonical bytes would exceed the cap", async () => {
    // Build a valid 2-entry chain, then raise only the cumulative byte count
    // to the cap (§11-2 means membership determination = chain derivation
    // runs before the admission check, so the stored chain itself must remain
    // verifiable)
    await replayVectorChain(2);
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE chain_entries SET canonical_bytes = ? WHERE seq = 1",
        MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      );
    });
    // Directly rewriting a stored row (outside the append-only invariant)
    // does not show up in the instance's incremental-load cache, so evict the
    // DO — equivalent to a restart — to force a full reload
    await evictDurableObject(stub);
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entries");
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });
    const response = await appendEntry(vectorProjectId, entry2.entry_hash_hex, entry);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { maxTotalBytes: number };
    expect(body.maxTotalBytes).toBe(MAX_CHAIN_TOTAL_CANONICAL_BYTES);
  });

  it("caps the total entry count (§6.4 receipt policy, unit-level)", () => {
    // Generating 10,000 valid chain entries is impractical, so verify the
    // decision function directly (the cumulative-bytes test exercises the
    // same branch of the plumbing)
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES, 0, 10)).toBe(true);
    expect(chainCapacityExceeded(MAX_CHAIN_ENTRIES - 1, 0, 10)).toBe(false);
    expect(chainCapacityExceeded(1, MAX_CHAIN_TOTAL_CANONICAL_BYTES, 1)).toBe(true);
  });
});
