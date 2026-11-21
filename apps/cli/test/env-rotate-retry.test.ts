import type { ChainEntry } from "@maruhi/crypto";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  decryptWire,
  headOf,
  manifestFor,
  valueHashOf,
  wrapDekFor,
  type WireRotateBody,
} from "./support/crypto.ts";
import {
  chainBase,
  chainRotated,
  dek1,
  dek2,
  ENV_ID,
  envStatement,
  loadFloor,
  makeServer,
  newEpochDekOf,
  owner,
  startEnv,
  variableAt,
} from "./support/env-rotate.ts";
import { type MockHandler, onRequest } from "./support/server.ts";

describe("maruhi env rotate", () => {
  it("a reasonless re-run is a request to resume only (already re-encrypted variables are excluded and it exits successfully)", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek2,
        epoch: 2,
        version: 2,
        plaintext: "postgres://example",
        headSeq: 3,
      }),
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("resume push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(dek2, pushed.value)).toBe("key-abc");
    expect(pushed.sameValueAs).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("the requested rotation was not performed");
    expect(errors).toContain("with incomplete re-encryption. Resuming this re-encryption");
    expect(errors).not.toContain("The requested rotation will not be performed");
  });

  it("completion check: a variable made in the window between the first pull and composite acceptance gets 422 → re-pull puts it in the target set and it completes only after re-encryption", async () => {
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
    const late = await variableAt({
      built: chainBase,
      variableId: "vlate",
      name: "LATE_VAR",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "late-value",
      headSeq: 2,
    });
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
      onRotate: (call) => {
        if (call === 0) {
          variables.push(late);
          return {
            status: 422,
            json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
          };
        }
        return undefined;
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "window"], env.layer)).toBe(0);
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vlate"]);
    expect(state.rotateBodies).toHaveLength(2);
    const body = state.rotateBodies[1];
    if (body === undefined) throw new Error("rotate retry missing");
    expect(body.checkpoint.payload.environments[0]?.valuesDigestHex).not.toBe(
      state.rotateBodies[0]?.checkpoint.payload.environments[0]?.valuesDigestHex,
    );
    const newDek = await newEpochDekOf(body);
    const pushedLate = state.pushes.find((push) => push.variableId === "vlate");
    if (pushedLate === undefined) throw new Error("late push missing");
    expect(pushedLate.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(newDek, pushedLate.value)).toBe("late-value");
  });

  it("--new-epoch creates a new epoch even with an unfinished re-encryption (for §7's all-environment rotation)", async () => {
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "member removal", "--new-epoch"],
        env.layer,
      ),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3, version: 2 });
    expect(pushed.sameValueAs).toBe(1);
    expect(env.logs.join("\n")).toContain("epoch 2 → 3");
  });

  it("the resume path does not require --reason (never blocks recovery over a field that is not recorded)", async () => {
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
  });

  it("ChainHeadConflict (409) re-syncs, re-signs the entry, and retries (§12-4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainBase.entries.length,
                currentHeadHashHex: chainBase.hashes[chainBase.hashes.length - 1],
              },
            }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "conflict test"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const [first, second] = state.rotateBodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    expect(second.deks).toEqual(first.deks);
  });

  it("an AuditHeadNotReady (503) is retried like a conflict; after five attempts the wording names both causes", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => ({ status: 503, json: { _tag: "AuditHeadNotReady" } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "busy test"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(5);
    expect(env.errors.join("\n")).toContain(
      "The rotation kept being rejected with retryable conflicts (a chain-head conflict, or audit-head materialization in progress) after 5 attempts. Wait a moment and re-run — server-side progress is preserved",
    );
  });

  it("CheckpointStateMismatch (422) retries bounded, restarting from a verified pull (§12-4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: (call) =>
        call === 0
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "value-conflict test"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const [first, second] = state.rotateBodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    expect(second.entry.payload.dekCommitmentHex).not.toBe(first.entry.payload.dekCommitmentHex);
    expect(second.checkpoint.payload.environments[0]?.valuesDigestHex).toBe(
      first.checkpoint.payload.environments[0]?.valuesDigestHex,
    );
    expect(env.logs).toEqual(
      expect.arrayContaining([
        `A concurrent push advanced environment ${ENV_ID}'s values — re-pulling and retrying the rotation (attempt 2 of 3)`,
      ]),
    );
    const floor = await loadFloor(env);
    expect(floor?.intents).toEqual([]);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({ epoch: 2 });
  });

  it("when CheckpointStateMismatch does not resolve, it aborts bounded and guides toward a re-run (§12-4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      onRotate: () => ({
        status: 422,
        json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
      }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "value-conflict test"], env.layer),
    ).toBe(1);
    expect(state.rotateBodies).toHaveLength(3);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: A concurrent push advanced environment ${ENV_ID}'s values while the rotation was in flight (the server reports values-digest-mismatch). Re-run \`maruhi env rotate\` to rebuild the checkpoint from the refreshed state`,
      ]),
    );
    const floor = await loadFloor(env);
    expect(floor?.intents).toEqual([]);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 1,
    });
  });

  it("a server that drops the accepted boundary checkpoint from chain distribution is detected by the post-acceptance rescan's strict verification (PR-F4 cross-layer)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
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
      dropCheckpointFromChain: true,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "checkpoint hiding"], env.layer),
    ).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
  });

  it("detecting another member's concurrent rotation mid-CAS-retry aborts without using the generated DEK", async () => {
    const projectId = chainBase.projectId;
    const entries: ChainEntry[] = [...chainBase.entries];
    const hashes: string[] = [...chainBase.hashes];
    let chainCalls = 0;
    const rotateBodies: WireRotateBody[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${projectId}/chain`, () => {
        if (chainCalls > 0 && entries.length === chainBase.entries.length) {
          entries.push(...chainRotated.entries.slice(chainBase.entries.length));
          hashes.push(...chainRotated.hashes.slice(chainBase.hashes.length));
        }
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
            attestations: [],
          },
        };
      }),
      onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, async () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 1,
          statement: envStatement,
          variables: [],
          deletedVariables: [],
          deks: [],
          manifest: await manifestFor({
            projectId,
            environmentId: ENV_ID,
            epoch: 1,
            issuer: owner,
            head: headOf(chainBase, 2),
            envStatement,
            statements: [],
          }),
          schemaPolicy: "enabled" as const,
        },
      })),
      onRequest("POST", `/projects/${projectId}/environments/${ENV_ID}/rotate`, (request) => {
        rotateBodies.push(request.body as WireRotateBody);
        return {
          status: 409,
          json: {
            _tag: "ChainHeadConflict",
            currentHeadSeq: chainRotated.entries.length,
            currentHeadHashHex: chainRotated.hashes[chainRotated.hashes.length - 1],
          },
        };
      }),
    ];
    const env = await startEnv(handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "concurrent"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("concurrent rotation");
    expect(rotateBodies).toHaveLength(1);
  });

  it("a re-encryption VersionConflict verifies the actual state via re-fetch; if the winner is already on the current epoch, re-encryption is treated as unneeded", async () => {
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
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = winner;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
  });
});
