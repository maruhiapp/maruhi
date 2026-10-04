// Tests for epoch rotation (`maruhi env rotate`).
//
// Pillars verified:
//  3. **Interruption recovery**: a state interrupted after the composite was
//     accepted but before re-encryption finished (= the epoch advanced yet a
//     latest value's epoch is below the current epoch) is detected on re-run,
//     and the remainder alone is re-encrypted without advancing the epoch (idempotent resume)
//  4. The branches: CAS conflict · concurrent rotation · partial completion · authorization
//
// The mock server mimics the real server's state transitions (appends accepted
// entries to the chain, puts the composite's wraps into the distribution set,
// and reflects pushes into latest values) — so "crash on run 1 → resume on
// run 2" can be exercised end-to-end on a single fixture.

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  removeMemberOp,
  buildChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  rotateEpochOp,
  statementFor,
  valueHashOf,
  type WireDistributedVariableStatement,
  wrapDekFor,
} from "./support/crypto.ts";
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
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

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
    // The winner's prev not pointing at the verified version-1 signed-bytes
    // hash = a diverged history (evidence of equivocation). Our signature
    // never chains into it. Also pins at the same time that the consistency
    // check runs before the "re-encryption unneeded" shortcut, and that the
    // current-epoch winner never trips the floor's rule (c)
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
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
    // Even on abort, collected warnings are not lost (the no-floor proviso matters most exactly on abort)
    expect(errors).toContain("the omission cannot be detected");
    // Cryptographic evidence is not "a failure a re-run fixes": never collapse
    // it into partial completion + resume guidance — it surfaces as an
    // immediate abort that prompts investigation (same treatment as the push path)
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
      // Right after the final pass's (3rd) conflict, another member's current-epoch write settles
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
    // The deletion is a tombstone (status deleted · metaVersion + 1) + deletion of all versions (§12-5)
    const tombstone = await statementFor({
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
      onPush: (call, variableId) => {
        if (call !== 0) {
          return undefined;
        }
        // Another member deleted it right before the re-encryption
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
    // The deleted variable drops out of the target set; the rest are re-encrypted
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    expect(env.errors.join("\n")).toContain("deleted concurrently by another member");
    // The 404 is recorded as the abort's cause, and at completion it becomes a
    // "happened but resolved" warning (the partial-completion cause never morphs into "conflict with a concurrent push")
    expect(env.errors.join("\n")).toContain("rejected with 404");
  });

  it("on a server that keeps returning 404 while still distributing the variable, the 404 surfaces as the partial-completion cause", async () => {
    // "Refuses with 404 yet keeps distributing it as active on pull" = neither
    // deletion nor conflict. Without recording the cause, the partial-
    // completion report morphs into the default wording (conflict with a
    // concurrent push) and the operator chases a nonexistent conflict
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // Claims "latest is version 9" yet distributes only version 1 on re-fetch
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // 409 every time. Even on re-fetch the latest value stays on the old epoch = re-encryption never completes
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "conflict"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    // Never ends with a "completed" face (the summary itself declares partial completion)
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.some((line) => line.startsWith("Done:"))).toBe(false);
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    const errors = env.errors.join("\n");
    expect(errors).toContain("has not completed");
    // Explicitly states that old-epoch DEK holders can still read the current values
    expect(errors).toContain("DEKs older than epoch 2");
  });

  it("on the resume path too, the guard is re-applied against the advanced verified view (the case where self was deleted mid-pull)", async () => {
    // The 4th entry removes the runner (member). The first sync sees only 3
    // entries, and the environment statement declares seq 4 (a future head),
    // so a bounded resync runs. The resume path only pushes and never builds
    // the wrap set, so grant_server does not stop the resume. The guard's
    // re-application itself is pinned on membership · role
    const runner = await makeTestUser("user-member-3333");
    const granted = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(runner, "member") },
      { actor: runner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: runner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: owner, operation: removeMemberOp(runner) },
    ]);
    const futureEnvStatement = await environmentStatementFor({
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
        // First serves 4 entries without the removal (runner is a member · epoch 2); the resync serves 5
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
          manifest: await manifestFor({
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
    // Even on the resume path it never proceeds to writing
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // The chain stays at epoch 2, yet the server claims an epoch conflict every time
      onPush: () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "claim"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // Never swallows the claim whole and reports "another member rotated
    // concurrently". As long as the chain-derived current epoch is unchanged, this is a contradictory response
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
    // Behind the claim, another member wrote everything on **the same epoch**
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
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    // What decides re-encryption's completion is the verified actual state,
    // not the server's self-claim. The in-place fact is never covered over by
    // a "contradictory response" abort
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
    const errors = env.errors.join("\n");
    // The contradictory claim itself stays as an investigation target (but no abort)
    expect(errors).toContain("the server's response contradicts the chain");
    expect(errors).not.toContain("re-running will not resolve this");
  });

  it("when an EpochConflict-claimed variable resolves, the rest get ordinary partial-completion guidance", async () => {
    // The claimed vaa is resolved because another member wrote it out on the
    // current epoch. What remains is only vbb for a different reason (502) —
    // declaring "a re-run will not resolve this" here would leave a re-
    // runnable state with neither resume guidance nor a remaining count
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
      prevValueSigHashHex: await valueHashOf(staleA.value, owner.userId),
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (_call, variableId) => {
        if (variableId === "vaa") {
          // Simultaneously with the claim, another member's current-epoch write settles
          variables[0] = winnerA;
          return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
        }
        return { status: 502, bodyText: "bad gateway" };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // The contradictory claim itself stays as an investigation target (but no abort)
    // Never says "confirmed everything is in place": all the rescan shows is
    // that nothing is left in the unfinished set — whether it was written on
    // the current epoch or deleted is unknown
    expect(errors).toContain("The reported variable is not in the rescanned incomplete set");
    // An abort would never reach the partial-completion reporting path = neither the remaining count nor the resume guidance comes out
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
      await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
      await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${chainBase.projectId}/chain`, () => {
        // The first sync is epoch 2. Mid-re-encryption, another member advances to epoch 3
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
            manifest: await manifestFor({
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
    // The forced resync confirmed the chain actually advanced, so this is not
    // a server contradiction (a benign race is not mistaken for foul play)
    expect(errors).toContain("concurrent rotation");
    expect(errors).not.toContain("the server's response contradicts the chain");
    expect(pushPaths).toHaveLength(1);
  });
});
