// Integration tests for the membership log's chain-API authorization
// (AUTH_SPEC §11) + GET /chain + CAS (the CRYPTO_SPEC §6.4 optimistic
// lock).
// The shared fixture and vector-replay helpers live in
// support/membership-scenario.ts (for the split's motivation see the
// top of the scenario module).

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  loginSession,
  seedUser,
  sessionHeaders,
} from "./support/auth.ts";
import {
  toWireEntry,
  vectorAuthzNegatives,
  vectorEntries,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { resignEntryAt, signEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  getChain,
  initChain,
  registerMembershipScenario,
  replayVectorChain,
  submitComposite,
  tokenFor,
} from "./support/membership-scenario.ts";

registerMembershipScenario();

describe("chain-API authorization (AUTH_SPEC §11)", () => {
  it("rejects unauthenticated requests with 401", async () => {
    const genesis = vectorEntries[0];
    const entry2 = vectorEntries[1];
    if (genesis === undefined || entry2 === undefined) throw new Error("missing vectors");
    const get = await SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain`);
    expect(get.status).toBe(401);
    const init = await initChain(toWireEntry(genesis), { headers: {} });
    expect(init.status).toBe(401);
    const append = await appendEntry(vectorProjectId, "0".repeat(64), toWireEntry(entry2), {});
    expect(append.status).toBe(401);
  });

  it("conceals the project from authenticated non-members with 404 (§11-2)", async () => {
    await replayVectorChain(1);
    await seedUser("user-stranger-0009", 9009);
    const strangerToken = await cliToken(9009);

    const get = await getChain(vectorProjectId, bearer(strangerToken));
    expect(get.status).toBe(404);

    // Signatures are rejected at membership before verification (no current-head info is returned either)
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const forged: ChainEntry = {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: genesis.entry_hash_hex,
      op: "remove_member",
      actor: { userId: "user-stranger-0009", keyFingerprintHex: "ab".repeat(16) },
      payload: { targetUserId: "user-owner-0001" },
      timestampMs: 1754006400000,
      signatureHex: "12".repeat(64),
    };
    const append = await appendEntry(
      vectorProjectId,
      "f".repeat(64),
      forged,
      bearer(strangerToken),
    );
    expect(append.status).toBe(404);
  });

  it("removed members are concealed too: the §11-2 mapping of actor-not-member (via composite)", async () => {
    // user-member-0002 is removed at seq 5. Later writes (rotate goes
    // through the composite) are rejected not by chain verification
    // (422) but by the membership judgment's 404 (existence hiding)
    const nonmember = vectorAuthzNegatives.find((n) => n.name === "authz-nonmember-actor");
    if (nonmember === undefined) throw new Error("missing authz-nonmember-actor vector");
    const { head } = await replayVectorChain(nonmember.entry.seq - 1);
    const { entry } = await resignEntryAt(toWireEntry(nonmember.entry), head.seq + 1, head.hashHex);
    if (entry.op !== "rotate_epoch") throw new Error("expected a rotate_epoch negative");
    const response = await submitComposite(entry, ["user-owner-0001", "user-admin-0003"]);
    expect(response.status).toBe(404);
  });

  it("rejects an append whose entry actor differs from the principal (403 actor-mismatch §11-1)", async () => {
    await replayVectorChain(4);
    const entry5 = vectorEntries[4];
    if (entry5 === undefined) throw new Error("missing vector entry 5");
    // entry5 (remove_member)'s actor is user-owner-0001. Sending it
    // under a member token does not match
    const response = await appendEntry(
      vectorProjectId,
      entry5.prev_hash_hex,
      toWireEntry(entry5),
      bearer(tokenFor("user-member-0002")),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("enforces token scopes: read scope can get but cannot append (§9-2)", async () => {
    await replayVectorChain(1);
    const readOnly: readonly TokenScope[] = [{ project: vectorProjectId, permission: "read" }];
    const readToken = await cliToken(9001, readOnly);

    const get = await getChain(vectorProjectId, bearer(readToken));
    expect(get.status).toBe(200);

    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const append = await appendEntry(
      vectorProjectId,
      entry2.prev_hash_hex,
      toWireEntry(entry2),
      bearer(readToken),
    );
    expect(append.status).toBe(403);
    const body = (await append.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("conceals projects outside the token's scope with 404 (§11-2)", async () => {
    await replayVectorChain(1);
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scopedToken = await cliToken(9001, otherScope);
    const response = await getChain(vectorProjectId, bearer(scopedToken));
    expect(response.status).toBe(404);
  });

  it("conceals everything from an empty-scope token (§11-2)", async () => {
    await replayVectorChain(1);
    const emptyScopeToken = await cliToken(9001, []);
    const response = await getChain(vectorProjectId, bearer(emptyScopeToken));
    expect(response.status).toBe(404);
  });

  it("distinguishes write from admin ops (the §6 op→required-permission table)", async () => {
    // seq 3 (create_environment) and seq 4 (rotate_epoch) are write
    // requirements via the composite endpoint and pass under a
    // write-scope token. Under the same write scope, remove_member (an
    // admin requirement, via generic append) is a 403 — this test
    // distinguishes a regression that would crush every op to write
    // (or admin)
    await replayVectorChain(2);
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const memberWrite = await cliToken(9002, writeScope);
    const vector3 = vectorEntries[2];
    const vector4 = vectorEntries[3];
    if (vector3 === undefined || vector4 === undefined) throw new Error("missing vectors");
    const entry3 = toWireEntry(vector3);
    if (entry3.op !== "create_environment") {
      throw new Error("unexpected vector ops");
    }
    const members = ["user-owner-0001", "user-member-0002"];
    const created = await submitComposite(entry3, members, {
      ...JSON_HEADERS,
      ...bearer(memberWrite),
    });
    expect(created.status).toBe(200);
    // Since the creation composite's boundary checkpoint (H+2)
    // advances the head, the rotate is re-signed at the real head (op
    // / payload / actor stay the vector's)
    const createdHead = (await created.json()) as { headSeq: number; headHashHex: string };
    const { entry: entry4 } = await resignEntryAt(
      toWireEntry(vector4),
      createdHead.headSeq + 1,
      createdHead.headHashHex,
    );
    if (entry4.op !== "rotate_epoch") {
      throw new Error("unexpected vector ops");
    }
    const rotated = await submitComposite(entry4, members, {
      ...JSON_HEADERS,
      ...bearer(memberWrite),
    });
    expect(rotated.status).toBe(200);

    // seq 5 is remove_member (admin required), actor user-owner-0001
    const ownerWrite = await cliToken(9001, writeScope);
    const entry5 = vectorEntries[4];
    if (entry5 === undefined) throw new Error("missing vector entry 5");
    const removal = await appendEntry(
      vectorProjectId,
      entry5.prev_hash_hex,
      toWireEntry(entry5),
      bearer(ownerWrite),
    );
    expect(removal.status).toBe(403);
    const body = (await removal.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("requires admin scope for init (genesis = project creation)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await cliToken(9001, writeScope);
    const response = await initChain(toWireEntry(genesis), { headers: bearer(ownerWrite) });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-permission");
  });

  it("rejects session-principal init even with the CSRF header (the §5 capability restriction)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const session = await loginSession(9001);

    // Chain appends and init are §5's explicit rejection surface:
    // uniformly 403 session-not-allowed regardless of the CSRF header
    // (the capability judgment precedes the CSRF check)
    const headers = sessionHeaders(session);
    const withoutCsrf: Record<string, string> = { cookie: headers["cookie"] ?? "" };
    const rejected = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...withoutCsrf },
    });
    expect(rejected.status).toBe(403);
    expect(((await rejected.json()) as { reason: string }).reason).toBe("session-not-allowed");

    const withCsrf = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...headers },
    });
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");

    // The same body is accepted under a token principal (proving the rejection was due to the session principal)
    const accepted = await initChain(toWireEntry(genesis), {
      headers: { ...JSON_HEADERS, ...bearer(await cliToken(9001)) },
    });
    expect(accepted.status).toBe(200);
  });
});

describe("GET /projects/:projectId/chain", () => {
  it("returns 404 for a project that was never initialized", async () => {
    const response = await getChain("ab".repeat(32));
    expect(response.status).toBe(404);
  });

  it("returns 400 for a malformed project id", async () => {
    const response = await getChain("not-a-project-id");
    expect(response.status).toBe(400);
  });

  it("allows every chain-derived member including reader to fetch (§6.2)", async () => {
    await replayVectorChain(6);
    // At seq 5 user-admin-0003 is added as a reader and change_role'd
    // at seq 6. At any point, a chain-derived member can fetch
    const response = await getChain(vectorProjectId, bearer(tokenFor("user-admin-0003")));
    expect(response.status).toBe(200);
  });
});

describe("CAS (the §6.4 optimistic lock)", () => {
  it("rejects an append whose parent head is stale and reports the current head", async () => {
    await replayVectorChain(2);
    const entry2 = vectorEntries[1];
    const genesis = vectorEntries[0];
    if (entry2 === undefined || genesis === undefined) {
      throw new Error("missing vector entries");
    }
    // CAS is checked with a test-time-signed remove_member (seq 3, an
    // op subject to generic append) (vector seq 3 is create_environment
    // and goes through the composite — covered by data tests)
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });

    // Setting the parent to the genesis hash (a head one step stale) is rejected and returns the current head
    const stale = await appendEntry(vectorProjectId, genesis.entry_hash_hex, entry);
    expect(stale.status).toBe(409);
    const body = (await stale.json()) as { currentHeadSeq: number; currentHeadHashHex: string };
    expect(body.currentHeadSeq).toBe(2);
    expect(body.currentHeadHashHex).toBe(entry2.entry_hash_hex);

    // Retrying with the correct parent is accepted (the client's re-sync/retry flow)
    const retried = await appendEntry(vectorProjectId, entry2.entry_hash_hex, entry);
    expect(retried.status).toBe(200);
  });

  it("rejects a malformed parentHeadHashHex with 400 (schema — before CAS semantics)", async () => {
    await replayVectorChain(2);
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entries");
    const { entry } = await signEntryAt({
      seq: 3,
      prevHashHex: entry2.entry_hash_hex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
    });
    // The format of the CAS comparison target is pinned as Sha256Hex
    // (64 lowercase hex chars): a malformed one never reaches the 409
    // (with current-head info) and falls at the schema boundary's 400
    for (const bad of ["ab".repeat(31), "AB".repeat(32), "not-hex"]) {
      const response = await appendEntry(vectorProjectId, bad, entry);
      expect(response.status).toBe(400);
    }
  });

  it("rejects an append to an uninitialized project with 404", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await appendEntry("cd".repeat(32), "0".repeat(64), toWireEntry(entry2));
    expect(response.status).toBe(404);
  });
});
