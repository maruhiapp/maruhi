import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  generateIdentity,
  genesisOp,
  headOf,
  removeMemberOp,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
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
    const stranger = await generateIdentity("user-stranger-9999");
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
    const flipped = `${fixture.envStatement.signatureHex.slice(0, -1)}${
      fixture.envStatement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ statement: { ...fixture.envStatement, signatureHex: flipped } }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("meta statement failed");
  });

  it("a deleted variable's tombstone is verified; co-listing it with active (the carriage form of unauthorized resurrection) is refused", async () => {
    const tombstone = await distributedVariableStatement({
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

    const revived = { ...tombstone, variableId: fixture.entryAlpha.variableId };
    const conflict = await startEnv([chainHandler(), pullHandler({ deletedVariables: [revived] })]);
    expect(await runCli(["pull"], conflict.layer)).toBe(1);
    expect(conflict.errors.join("\n")).toContain(
      "served as both live (active or declared) and deleted",
    );

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
    const value = await distributedValue({
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
    const oldKeys = await generateIdentity("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await distributedWrap({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await distributedValue({
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
    const historicEnvStatement = await distributedEnvironmentStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: oldKeys,
      head: headOf(built, 3),
    });
    const historicStatement = await distributedVariableStatement({
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
      manifest: await distributedManifest({
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
    const oldKeys = await generateIdentity("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await distributedWrap({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await distributedValue({
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
    const forgedStatement = await distributedVariableStatement({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vf",
      name: "FORGED_NAME",
      author: oldKeys,
      head: headOf(built, 4),
      metaVersion: 2,
    });
    const envStatement = await distributedEnvironmentStatement({
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
      manifest: await distributedManifest({
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
    const { built } = fixture;
    const futureStatement = await distributedVariableStatement({
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
