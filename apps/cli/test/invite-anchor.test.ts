// Integration tests for the invite-link anchor's machine cross-check
// (CRYPTO_SPEC §6.3 out-of-band anchor (a) / §6.5 — attachProject /
// project verify in context.ts).
//
// Properties pinned down:
//  1. On the first sync after add_member, the pinned "head inclusion +
//     inviter-FP membership" is machine-checked; on success verifiedAtSeq
//     is persisted (the check keeps running afterwards)
//  2. Head not included (rollback, fork distribution), inviter FP
//     mismatch, or inviter sig-key mismatch (forged link / forged chain)
//     are refused as hard evidence (the anchor always carries both the FP
//     and the sig key)
//  3. A corrupt pin file is fail-open (warn and continue without the
//     check — the same line drawn as the floor)

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let inviter: TestUser;
let acceptor: TestUser;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

function chainHandler(built: BuiltChain): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

/** The accepted chain (genesis → the acceptor's add_member) and the acceptor's session. */
async function memberEnv(built: BuiltChain): Promise<TestEnv> {
  const server = await MockServer.start([chainHandler(built)]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, acceptor);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return env;
}

async function seedAnchor(
  env: TestEnv,
  projectId: string,
  anchor: Readonly<Record<string, unknown>>,
): Promise<void> {
  await mkdir(env.pinsDir, { recursive: true });
  await writeFile(
    join(env.pinsDir, `${projectId}.json`),
    JSON.stringify({ v: 1, anchor, issued: {} }),
  );
}

describe("the invite-link anchor's machine cross-check (first sync — §6.3 (a) / §6.5)", () => {
  it("succeeds when head inclusion + inviter-FP membership agree, persisting verifiedAtSeq", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 1,
      headHashHex: built.hashes[0],
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Invite-link anchor check passed");

    const pins = JSON.parse(
      await readFile(join(env.pinsDir, `${built.projectId}.json`), "utf8"),
    ) as { anchor: { verifiedAtSeq: number | null } };
    expect(pins.anchor.verifiedAtSeq).toBe(2);

    // The second time doesn't repeat the success message (the check
    // itself runs every time)
    env.logs.length = 0;
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).not.toContain("Invite-link anchor check passed");
  });

  it("refuses a chain not containing the pinned head (rollback, fork distribution)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 2,
      // A hash differing from the real seq 2 = the history the inviter
      // saw is not part of the distribution
      headHashHex: "9a".repeat(32),
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "does not contain the verified head pinned in the invite link (seq=2)",
    );
  });

  it("refuses a chain where the inviter FP disagrees with the membership at the pinned head", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 1,
      headHashHex: built.hashes[0],
      inviterUserId: inviter.userId,
      // The shape where the link's ie= / is= point at a different key
      // (forged link / forged chain)
      inviterKeyFingerprintHex: "7b".repeat(16),
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the chain member at the pinned head");
  });

  it("refuses a chain where the inviter's sig key (is=) disagrees with the key enrolled at the pinned head", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 1,
      headHashHex: built.hashes[0],
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      // The FP matches but the sig key differs (both FP and key are
      // cross-checked — a disguise of only one never passes)
      inviterSigPubHex: "7b".repeat(32),
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "the link's inviter signing key (is=) does not match the chain member's key at the pinned head",
    );
  });

  it("a corrupt pin file is fail-open (warn + continue without the anchor check)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${built.projectId}.json`), "{broken");

    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("cannot read the invite-pin file (it is corrupt)");
  });
});
