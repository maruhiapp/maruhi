import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedManifest,
  distributedVariableStatement,
  distributedWrap,
  generateIdentity,
  genesisOp,
  headOf,
  removeMemberOp,
  rotateEpochOp,
  valueSignedBytesHashOf,
  type WireDistributedVariableStatement,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  chainBase,
  chainRotated,
  chainRotatedTwice,
  dek1,
  dek2,
  ENV_ID,
  envStatement,
  makeServer,
  owner,
  servers,
  startEnv,
  variableAt,
} from "./support/env-rotate.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import { type MockHandler, MockServer, offSpec, onRequest } from "./support/server.ts";

describe("maruhi env rotate", () => {
  it("if the 409's winner chains into a diverged history, it aborts without re-pointing prev (§12-5)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const forked = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-forked",
      headSeq: 3,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = forked;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "divergence"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("chaining onto a diverged history");
    expect(errors).toContain("the omission cannot be detected");
    expect(errors).toContain("This is evidence that re-running will not resolve");
    expect(env.logs.join("\n")).not.toContain("Partial completion");
  });

  it("a conflict on the final pass is also verified via re-fetch (never misreports unfinished when the winner is on the current epoch)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(stale.value, owner.userId),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call === 2) {
          variables[0] = winner;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
    expect(env.errors.join("\n")).not.toContain("has not completed");
  });

  it("a concurrent deletion (404) mid-re-encryption warns and continues (never takes the remaining variables down with it)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DOOMED",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "doomed-value",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const tombstone = await distributedVariableStatement({
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      variableId: "vaa",
      name: "DOOMED",
      author: owner,
      head: headOf(chainBase, 1),
      status: "deleted",
      metaVersion: 2,
    });
    const deletedVariables: WireDistributedVariableStatement[] = [];
    const state = makeServer({
      built: chainBase,
      variables,
      deletedVariables,
      deks: [
        await distributedWrap({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (call, variableId) => {
        if (call !== 0) {
          return undefined;
        }
        variables.splice(
          variables.findIndex((variable) => variable.variableId === variableId),
          1,
        );
        deletedVariables.push(tombstone);
        return { status: 404, json: { _tag: "VariableNotFound", variableId } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "deletion race"], env.layer)).toBe(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    expect(env.errors.join("\n")).toContain("deleted concurrently by another member");
    expect(env.errors.join("\n")).toContain("rejected with 404");
  });

  it("on a server that keeps returning 404 while still distributing the variable, the 404 surfaces as the partial-completion cause", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await distributedWrap({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (_call, variableId) => ({
        status: 404,
        json: { _tag: "VariableNotFound", variableId },
      }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "persistent 404"], env.layer)).toBe(
      1,
    );
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(errors).toContain(
      "re-encryption did not complete: Re-encryption of variable API_KEY was rejected with 404 (possible concurrent deletion)",
    );
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
  });

  it("a response distributing only values older than the 409's claim is never adopted as the winner — it aborts (§12-5)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) =>
        call === 0
          ? { status: 409, json: { _tag: "VersionConflict", currentVersion: 9 } }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "self-contradiction"], env.layer),
    ).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("known latest version");
  });

  it("a re-encryption left with an unresolved conflict warns as a partial completion and exits non-zero", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "conflict"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.some((line) => line.startsWith("Done:"))).toBe(false);
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    const errors = env.errors.join("\n");
    expect(errors).toContain("has not completed");
    expect(errors).toContain("DEKs older than epoch 2");
  });

  it("on the resume path too, the guard is re-applied against the advanced verified view (the case where self was deleted mid-pull)", async () => {
    const runner = await generateIdentity("user-member-3333");
    const granted = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(runner, "member") },
      { actor: runner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: runner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: owner, operation: removeMemberOp(runner) },
    ]);
    const futureEnvStatement = await distributedEnvironmentStatement({
      projectId: granted.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: owner,
      head: headOf(granted, 5),
    });
    const variables = [
      await variableAt({
        built: granted,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${granted.projectId}/chain`, () => {
        const count = chainCalls === 0 ? 4 : 5;
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId: granted.projectId,
            entries: granted.entries.slice(0, count),
            headSeq: count,
            headHashHex: granted.hashes[count - 1],
            attestations: [],
          },
        };
      }),
      onRequest("GET", `/projects/${granted.projectId}/environments/${ENV_ID}/pull`, async () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 2,
          statement: futureEnvStatement,
          variables,
          deletedVariables: [],
          deks: [],
          manifest: await distributedManifest({
            projectId: granted.projectId,
            environmentId: ENV_ID,
            epoch: 2,
            issuer: owner,
            head: headOf(granted, 5),
            envStatement: futureEnvStatement,
            statements: variables.map((variable) => variable.statement),
          }),
          schemaPolicy: "enabled" as const,
        },
      })),
      (request) => {
        if (request.method === "POST") {
          pushPaths.push(request.path);
        }
        return null;
      },
    ];
    const server = await MockServer.start(handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, runner);
    await seedConfig(env, { server: server.origin, defaultProject: granted.projectId });

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not a chain-derived member");
    expect(pushPaths).toHaveLength(0);
  });

  it("the server's EpochConflict claim never decides the cause — it defers to the rescan's chain verification", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "claim"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("concurrent rotation");
    expect(errors).toContain("the server's response contradicts the chain");
    expect(errors).toContain("re-running will not resolve this");
  });

  it("even with an EpochConflict claim, if every variable is in place on the rescan it completes (the warning stays)", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(stale.value, owner.userId),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = winner;
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
    const errors = env.errors.join("\n");
    expect(errors).toContain("the server's response contradicts the chain");
    expect(errors).not.toContain("re-running will not resolve this");
  });

  it("when an EpochConflict-claimed variable resolves, the rest get ordinary partial-completion guidance", async () => {
    const staleA = await variableAt({
      built: chainRotated,
      variableId: "vaa",
      name: "DATABASE_URL",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "postgres://example",
      headSeq: 2,
    });
    const winnerA = await variableAt({
      built: chainRotated,
      variableId: "vaa",
      name: "DATABASE_URL",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "postgres://example",
      headSeq: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(staleA.value, owner.userId),
    });
    const variables = [
      staleA,
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (_call, variableId) => {
        if (variableId === "vaa") {
          variables[0] = winnerA;
          return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
        }
        return offSpec({ status: 502, bodyText: "bad gateway" });
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("The reported variable is not in the rescanned incomplete set");
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    expect(errors).toContain("resume from the remainder without advancing the epoch");
  });

  it("when the chain has actually advanced on an EpochConflict, it is treated as a concurrent rotation, not a contradiction", async () => {
    const rotatedTwice = chainRotatedTwice;
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const deks = [
      await distributedWrap({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
      await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${chainBase.projectId}/chain`, () => {
        const built = chainCalls === 0 ? chainRotated : rotatedTwice;
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId: chainBase.projectId,
            entries: built.entries,
            headSeq: built.entries.length,
            headHashHex: built.hashes[built.hashes.length - 1],
            attestations: [],
          },
        };
      }),
      onRequest(
        "GET",
        `/projects/${chainBase.projectId}/environments/${ENV_ID}/pull`,
        async () => ({
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 2,
            statement: envStatement,
            variables,
            deletedVariables: [],
            deks,
            manifest: await distributedManifest({
              projectId: chainBase.projectId,
              environmentId: ENV_ID,
              epoch: 2,
              issuer: owner,
              head: headOf(chainRotated, 3),
              envStatement,
              statements: variables.map((variable) => variable.statement),
            }),
            schemaPolicy: "enabled" as const,
          },
        }),
      ),
      (request) => {
        if (request.method !== "POST" || !request.path.endsWith("/versions")) {
          return null;
        }
        pushPaths.push(request.path);
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    ];
    const env = await startEnv(handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("concurrent rotation");
    expect(errors).not.toContain("the server's response contradicts the chain");
    expect(pushPaths).toHaveLength(1);
  });
});
