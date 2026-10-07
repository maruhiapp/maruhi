// Tests for pull (§5.1 distribution-time verification + §12-7 all-epoch DEKs)
// and run (memory injection), and for the AI-agent-detection boundary
// (value display is refused / run is allowed).

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  removeMemberOp,
  statementFor,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainHandler,
  ENV_ID,
  fixture,
  genesisHead,
  pullEntry,
  pullHandler,
  servers,
  startEnv,
} from "./support/pull-run.ts";
import { MockServer, onRequest } from "./support/server.ts";

describe("distribution-time verification of meta statements (§4.2 / §6.3)", () => {
  it("refuses a statement-signature bit-flip before decryption", async () => {
    const statement = fixture.entryAlpha.statement;
    const flipped = `${statement.signatureHex.slice(0, -1)}${
      statement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: { ...statement, signatureHex: flipped } }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("meta statement failed");
  });

  it("refuses a name swap (a statement with only its name replaced) (the carriage form of a name-swap)", async () => {
    // Keep the signature honest but rewrite only the name field = rejected by the byte-exact signature
    const swapped = { ...fixture.entryAlpha.statement, name: "DEBUG_ENDPOINT" };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: swapped }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });

  it("refuses a statement transplanted from another variable (variableId mismatch)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: fixture.entryBeta.statement }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "statement coordinates that do not match the requested context",
    );
  });

  it("refuses a false author claim (the signature stays someone else's) (the §4.2 attribution)", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const lying = {
      ...fixture.entryAlpha.statement,
      authorUserId: stranger.userId,
      authorKeyFingerprintHex: stranger.fingerprintHex,
    };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, statement: lying }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=author-unknown");
  });

  it("refuses tampered environment-statement distribution", async () => {
    // Signature bit-flip
    const flipped = `${fixture.envStatement.signatureHex.slice(0, -1)}${
      fixture.envStatement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ statement: { ...fixture.envStatement, signatureHex: flipped } }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("meta statement failed");
    // A status-deleted environment statement cannot be signed at all (an
    // environment deletion is the chain op delete_environment — CRYPTO_SPEC
    // §4.2 / §6.2); a chain-deleted environment is refused before any pull
    // (env-rename-rm.test.ts)
  });

  it("a deleted variable's tombstone is verified; co-listing it with active (the carriage form of unauthorized resurrection) is refused", async () => {
    // Happy path: a distribution of only a deleted statement is accepted and never surfaces in values
    const tombstone = await statementFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      variableId: "v-deleted",
      name: "RETIRED_KEY",
      author: fixture.owner,
      head: genesisHead(fixture.built.projectId),
      status: "deleted",
      metaVersion: 2,
    });
    const ok = await startEnv([chainHandler(), pullHandler({ deletedVariables: [tombstone] })]);
    expect(await runCli(["pull"], ok.layer)).toBe(0);
    expect(ok.logs.join("\n")).not.toContain("RETIRED_KEY");

    // The same variableId distributed as both active and deleted = refusal
    const revived = { ...tombstone, variableId: fixture.entryAlpha.variableId };
    const conflict = await startEnv([chainHandler(), pullHandler({ deletedVariables: [revived] })]);
    expect(await runCli(["pull"], conflict.layer)).toBe(1);
    expect(conflict.errors.join("\n")).toContain(
      "served as both live (active or declared) and deleted",
    );

    // A tampered tombstone signature is refused too (as long as it is distributed, it is verified)
    const flipped = `${tombstone.signatureHex.slice(0, -1)}${
      tombstone.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ deletedVariables: [{ ...tombstone, signatureHex: flipped }] }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("meta statement failed");
  });

  it("distributing a non-NFC name is warned (SHOULD — §12-1; processing continues)", async () => {
    const nfdName = "CAFE\u0301_URL";
    expect(nfdName.normalize("NFC")).not.toBe(nfdName);
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vnfd",
      version: 1,
      plaintext: "v",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vnfd", nfdName, value)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("not NFC-normalized");
  });

  it("a removed author's statement verifies under a during-membership head (the §6.3-1 counterpart)", async () => {
    // author (oldKeys) is removed at seq 4. A statement declaring head seq 3
    // (during membership) verifies under the key of that time against the whole post-removal chain
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vh",
      version: 1,
      plaintext: "historic",
      writer: oldKeys,
      head: headOf(built, 3),
    });
    const historicEnvStatement = await environmentStatementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: oldKeys,
      head: headOf(built, 3),
    });
    const historicStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vh",
      name: "HISTORIC",
      author: oldKeys,
      head: headOf(built, 3),
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: historicEnvStatement,
      variables: [{ variableId: "vh", statement: historicStatement, value }],
      deletedVariables: [],
      deks: [wrap],
      // The manifest issuer is a current member (owner) — the author's removal
      // is independent of whether the manifest may be issued (the §4.3 issuer-membership check applies only to the issuer itself)
      manifest: await manifestFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, 4),
        envStatement: historicEnvStatement,
        statements: [historicStatement],
      }),
      schemaPolicy: "enabled" as const,
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
          attestations: [],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("HISTORIC");
  });

  it("refuses a statement whose removed author declared a post-removal head", async () => {
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vf",
      version: 1,
      plaintext: "v",
      writer: owner,
      head: headOf(built, 3),
    });
    // Of meta forward-injections, "declaring a post-removal head" is rejected
    // by the membership check (§6.3-3. A forward injection declaring a
    // during-membership head has no epoch anchor and is undetected in v1 — §14.3-5)
    const forgedStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vf",
      name: "FORGED_NAME",
      author: oldKeys,
      head: headOf(built, 4),
      metaVersion: 2,
    });
    const envStatement = await environmentStatementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: owner,
      head: headOf(built, 1),
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: envStatement,
      variables: [{ variableId: "vf", statement: forgedStatement, value }],
      deletedVariables: [],
      deks: [wrap],
      manifest: await manifestFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, built.entries.length),
        envStatement,
        statements: [forgedStatement],
      }),
      schemaPolicy: "enabled" as const,
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
          attestations: [],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=author-not-member-at-head");
  });

  it("a statement's future head is accepted via bounded resync too (reusing the same mechanism as values — §6.3-2b)", async () => {
    // Old view = up to seq 2. The statement declares seq 3 (the rotate) as
    // head. First verification is chain-head-future → the resync reveals the extension; re-verification accepts
    const { built } = fixture;
    const futureStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: fixture.owner,
      head: headOf(built, 3),
    });
    const shortChain = built.entries.slice(0, 2);
    let chainCalls = 0;
    const progressiveChain = onRequest("GET", `/projects/${built.projectId}/chain`, () => {
      chainCalls += 1;
      const entries = chainCalls === 1 ? shortChain : built.entries;
      return {
        status: 200,
        json: {
          projectId: built.projectId,
          entries,
          headSeq: entries.length,
          headHashHex: built.hashes[entries.length - 1],
          attestations: [],
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: futureStatement }],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("ALPHA");
  });
});
