import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  genesisOp,
  grantServerOp,
  valueHashOf,
  wrapDekFor,
} from "./support/crypto.ts";
import {
  chainBase,
  chainRotated,
  chainRotatedTwice,
  dek1,
  dek2,
  dek3,
  ENV_ID,
  makeServer,
  owner,
  reader,
  servers,
  startEnv,
  variableAt,
} from "./support/env-rotate.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import { MockServer } from "./support/server.ts";

describe("maruhi env rotate", () => {
  it("a response pushing back an already-accepted write of ours is detected as a rollback without relying on the floor", async () => {
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
    const other = await variableAt({
      built: chainRotated,
      variableId: "vcc",
      name: "OTHER",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "other-value",
      headSeq: 2,
    });
    const variables = [stale, other];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (_call, variableId) => {
        if (variableId === "vbb") {
          return {
            status: 200,
            json: { variableId, version: 2, epoch: 2 },
          };
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);
    env.failFloorPushCommits();

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "older than the known latest version (2) — inconsistent",
    );
  });

  it("the same SHOULD warning is not displayed twice across passes", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "ÁPI_KEY",
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "duplicates"], env.layer)).toBe(1);
    const nfcWarnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(nfcWarnings).toHaveLength(1);
  });

  it("one variable's permanent failure never takes other variables' re-encryption down with it", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "POISON",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "poison-value",
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
      await variableAt({
        built: chainBase,
        variableId: "vcc",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (_call, variableId) =>
        variableId === "vaa" ? { status: 502, bodyText: "bad gateway" } : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "poison variable"], env.layer)).toBe(
      1,
    );
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vbb", "vcc"]);
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
  });

  it("even on a pass aborted because no pushable target remained, the cause is reported without collapsing to conflict", async () => {
    const undecryptable = await variableAt({
      built: chainRotatedTwice,
      variableId: "vaa",
      name: "OLD_ONE",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "unreadable-here",
      headSeq: 2,
    });
    const stale = await variableAt({
      built: chainRotatedTwice,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 1,
      plaintext: "key-abc",
      headSeq: 3,
    });
    const winner = await variableAt({
      built: chainRotatedTwice,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek3,
      epoch: 3,
      version: 2,
      plaintext: "key-def",
      headSeq: 4,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [undecryptable, stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      onPush: (call) => {
        if (call === 1) {
          variables[1] = winner;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No DEK for epoch 1");
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
  });

  it("even on the final pass (the non-decrypting pass), an unopenable value is collected as a cause from wrap presence alone", async () => {
    const variables = [
      await variableAt({
        built: chainRotatedTwice,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotatedTwice,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No DEK for epoch 1");
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("2 variables incomplete");
  });

  it("when resume is impossible for lack of the current epoch's DEK, it guides toward the --new-epoch escape", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner })],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "member removal"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("Cannot resume the incomplete re-encryption");
    expect(errors).toContain("run with --new-epoch");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("a permanently failing variable's reason is kept as a warning even when it never reaches the cause field", async () => {
    const common = { built: chainBase, dek: dek1, epoch: 1, version: 1, headSeq: 2 } as const;
    const variables = [
      await variableAt({ ...common, variableId: "vaa", name: "TRANSIENT", plaintext: "a" }),
      await variableAt({ ...common, variableId: "vbb", name: "TOO_BIG", plaintext: "b" }),
    ];
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (_call, variableId) =>
        variableId === "vaa"
          ? { status: 502, bodyText: "bad gateway" }
          : { status: 413, json: { _tag: "ValueTooLarge", limitBytes: 8 } },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mixed failures"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("Failed to re-encrypt variable TRANSIENT");
    expect(errors).toContain("Failed to re-encrypt variable TOO_BIG");
  });

  it("when not a single current value can be opened, it never recommends the unsatisfiable --new-epoch", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({ built: chainRotated, variables, deks: [], currentEpoch: 2 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "member removal"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain("You cannot open any current value");
    expect(errors).not.toContain("run with --new-epoch");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("options not applicable to the operation and misspellings are refused, never silently dropped", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epochs"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag");
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--name", "n"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("Unknown flag");
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch=false"], env.layer),
    ).toBe(0);
    expect(env.logs.join("\n")).toContain("epoch 1 → 2");
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch", "false"], env.layer),
    ).toBe(0);
    expect(env.errors.join("\n")).not.toContain("Unexpected extra arguments");
    const beforeSwap = server.requests.length;
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--environment-id", "other-env"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--environment-id is a positional argument");
    expect(server.requests.length).toBe(beforeSwap);
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--project", chainBase.projectId],
        env.layer,
      ),
    ).toBe(0);
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("when the target environment sits inside a grant_server's disclosure scope, the complete set includes the server-addressed wrap and rotates (§12-4 / §7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID]) },
    ]);
    const grantEntry = built.entries[2];
    if (grantEntry?.op !== "grant_server") throw new Error("grant entry missing");
    const state = makeServer({
      built,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "with grant"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0] as {
      deks: readonly {
        recipientClass?: string;
        recipientUserId: string;
        recipientEncPubHex: string;
      }[];
    };
    expect(body.deks).toHaveLength(2);
    const serverWrap = body.deks.find((wrap) => wrap.recipientClass === "server");
    expect(serverWrap?.recipientUserId).toBe(grantEntry.payload.serverKeyFingerprintHex);
    expect(serverWrap?.recipientEncPubHex).toBe(grantEntry.payload.serverEncPubHex);
  });

  it("a grant_server disclosing only a different environment never stops this environment's revocation rotation (§7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp(["other-env"]) },
    ]);
    const state = makeServer({
      built,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "member removal"], env.layer)).toBe(
      0,
    );
    expect(state.rotateBodies).toHaveLength(1);
  });

  it("a reader cannot rotate (member or above — §6.2). Refused before any value fetch", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(reader, "reader") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = makeServer({ built, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, reader);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "test"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reader");
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
  });

  it("a run with nothing unfinished and no --reason only checks and writes nothing", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Check complete");
    expect(env.logs.join("\n")).toContain("To create a new epoch, pass --reason");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a --new-epoch run without --reason is refused before any request (leaves no var.read)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the rotation reason with --reason");
    expect(server.requests).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("an empty --reason fails instead of collapsing into 'check only' (never makes a successful exit that did nothing despite a request)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    for (const empty of [["--reason", ""], ["--reason="]]) {
      expect(await runCli(["env", "rotate", ENV_ID, ...empty], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for flag --reason");
      expect(env.logs.join("\n")).not.toContain("Check complete");
    }
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "  "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unacceptable value for flag --reason");
    expect(state.rotateBodies).toHaveLength(0);
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a rotation onto an environment absent from the chain is refused (create_environment never observed)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", "staging", "--reason", "test"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on the chain");
    expect(state.rotateBodies).toHaveLength(0);
  });
});
