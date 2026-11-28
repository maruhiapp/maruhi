import {
  buildChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  distributedWrap,
  genesisOp,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  chainBase,
  chainRotated,
  chainRotatedTwice,
  dek1,
  dek2,
  dek3,
  ENV_ID,
  loadFloor,
  makeServer,
  owner,
  servers,
  startEnv,
  variableAt,
} from "./support/env-rotate.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import { MockServer, offSpec } from "./support/server.ts";

describe("maruhi env rotate", () => {
  it("--new-epoch advances the epoch even with an undecryptable value (revocation wins — §7)", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotated,
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
      built: chainRotated,
      variables,
      deks: [
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "member removal", "--new-epoch"],
        env.layer,
      ),
    ).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Some values cannot be re-encrypted");
    expect(env.logs.join("\n")).toContain("Partial completion");
  });

  it("even when the composite send fails, if it was accepted it reports 'the epoch advanced'", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
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
      onRotateAfterAccept: () => offSpec({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "lost response"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("this rotation itself was accepted");
    expect(errors).toContain("resume re-encryption without advancing the epoch");
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    expect(floor?.intents).toEqual([]);
  });

  it("if not even one value can be re-encrypted, the epoch never advances (an idle spin is no revocation)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({ built: chainBase, variables, deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "idle spin"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No values can be re-encrypted");
    expect(errors).toContain("nothing is actually revoked");
  });

  it("if what advanced behind the send failure was another member's rotation, it says so", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => offSpec({ status: 502, bodyText: "bad gateway" }),
      chainAfterRotateAttempt: chainRotated,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "other member"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("another member's rotation");
    expect(errors).toContain("this run's entry was not accepted");
    expect(errors).not.toContain("this rotation itself was accepted");
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest?.manifestVersion ?? 1).toBeLessThanOrEqual(1);
    expect(floor?.intents).toEqual([]);
  });

  it("even when another member has advanced further after the acceptance, our share's acceptance is not missed", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotateAfterAccept: () => offSpec({ status: 502, bodyText: "bad gateway" }),
      appendRotateAfterAccept: { epoch: 3, dek: dek3 },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "overtaken"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("this rotation itself was accepted");
    expect(errors).toContain("resume re-encryption without advancing the epoch");
    expect(errors).not.toContain("was not accepted");
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    expect(floor?.intents).toEqual([]);
  });

  it("when the post-acceptance check sees an overtake by another rotate right after the 200, our manifest still stays as the minimum floor (M1-A4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      appendRotateAfterAccept: { epoch: 3, dek: dek3 },
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "post-acceptance overtake"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("possibly a concurrent rotation right after acceptance");
    expect(errors).toContain(
      "This rotation itself was accepted and its manifest was recorded in the local floor",
    );
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    expect(floor?.intents).toEqual([]);
  });

  it("a 404 from a concurrent delete_environment the view missed is reported as the deletion, not as a blocking server", async () => {
    const chainDeleted = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: deleteEnvironmentOp(ENV_ID) },
    ]);
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => ({
        status: 404,
        json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID },
      }),
      chainAfterRotateAttempt: chainDeleted,
    });
    const env = await startEnv(state.handlers, owner);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "raced"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Environment ${ENV_ID} is deleted (delete_environment at chain seq 3)`,
    );
    expect(errors).not.toContain("malicious server");
  });

  it("a rotate onto a deleted environment (404) is treated as a definite rejection — it never suggests re-running", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => ({
        status: 404,
        json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID },
      }),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    const chainCallsBefore = server.requests.filter((request) =>
      request.path.endsWith("/chain"),
    ).length;
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "deleted"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: Rotation for environment ${ENV_ID} was rejected with 404, yet the re-synced verified chain shows it as live (no delete_environment entry). A malicious server may be selectively blocking rotation — aborting instead of silently skipping (CRYPTO_SPEC §7)`,
      ]),
    );
    expect(errors).not.toContain("safe to simply re-run");
    expect(errors).not.toContain("was accepted");
    const chainCalls = server.requests.filter((request) => request.path.endsWith("/chain")).length;
    expect(chainCalls - chainCallsBefore).toBe(2);
  });

  it("when acceptance cannot be confirmed, it explicitly states the epoch may have advanced", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => offSpec({ status: 502, bodyText: "bad gateway" }),
      onChain: (call) =>
        call === 0 ? undefined : offSpec({ status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "unverifiable"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("may already have advanced to epoch 2");
    expect(errors).toContain("Restore connectivity and re-run");
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest?.manifestVersion ?? 1).toBeLessThanOrEqual(1);
    expect(floor?.intents).toHaveLength(1);
    expect(floor?.intents[0]).toMatchObject({
      op: "rotate_epoch",
      environmentId: ENV_ID,
      epoch: 2,
    });
  });

  it("when the composite send fails and it was never accepted, it conveys 'you can re-run as-is'", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => offSpec({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "undelivered"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not show it as accepted yet");
    expect(errors).toContain("safe to simply re-run");
    const floor = await loadFloor(env);
    expect(floor?.intents).toHaveLength(1);
  });

  it("when the intent (3-F) append fails, the composite is never sent (journal-before-send is fail-closed)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
    });
    const env = await startEnv(state.handlers, owner);
    env.failFloorIntentAppends();

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "journal"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("a value that cannot be opened despite holding the wrap aborts immediately as a suspected swap", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "CORRUPT",
        dek: dek1,
        epoch: 2,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 3,
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
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "normal"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("possibly replaced by the server");
    expect(errors).not.toContain("run with --new-epoch");
    expect(errors).not.toContain("a member holding wraps");
  });

  it("an unopenable value appearing mid-pass is also never demoted to partial completion — it aborts as evidence", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const tampered = await variableAt({
      built: chainBase,
      variableId: "vtamper",
      name: "TAMPERED",
      dek: dek3,
      epoch: 1,
      version: 1,
      plaintext: "unreadable-here",
      headSeq: 2,
    });
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
      onRotateAccepted: () => {
        variables.push(tampered);
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mid-pass"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("below the checkpoint baseline epoch");
    expect(errors).toContain("This is evidence that re-running will not resolve");
    expect(errors).not.toContain("resume from the remainder");
    expect(errors).not.toContain("may include unconfirmed ones");
  });

  it("even with one undecryptable value, resume re-encrypts the openable share (the epoch has already advanced)", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotated,
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
        await distributedWrap({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await distributedWrap({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3 });
    const errors = env.errors.join("\n");
    expect(errors).toContain("Some values cannot be re-encrypted");
    expect(errors).toContain("No DEK for epoch 1");
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    expect(
      env.errors.filter((line) => line.includes("Some values cannot be re-encrypted")),
    ).toHaveLength(1);
  });

  it("a winner re-picked after a non-409 failure also gets the consistency check (preventing a chain into a diverged prev)", async () => {
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
        return offSpec({ status: 502, bodyText: "bad gateway" });
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("chaining onto a diverged history");
  });

  it("on a floorless run it warns that a variable dropped from the response cannot be detected", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
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
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "no floor"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("the omission cannot be detected");

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "with floor"], env.layer)).toBe(0);
    const secondRunErrors = env.errors.filter((line) =>
      line.includes("the omission cannot be detected"),
    );
    expect(secondRunErrors).toHaveLength(1);
  });
});
