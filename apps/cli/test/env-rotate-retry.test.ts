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

import type { ChainEntry } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { headOf, manifestFor, valueHashOf, wrapDekFor } from "./support/crypto.ts";
import {
  chainBase,
  chainRotated,
  decryptWire,
  dek1,
  dek2,
  ENV_ID,
  envStatement,
  loadFloor,
  makeServer,
  newEpochDekOf,
  owner,
  type RotateBody,
  startEnv,
  variableAt,
} from "./support/env-rotate.ts";
import { type MockHandler, onRequest } from "./support/server.ts";

describe("maruhi env rotate", () => {
  it("a reasonless re-run is a request to resume only (already re-encrypted variables are excluded and it exits successfully)", async () => {
    const variables = [
      // Already re-encrypted to epoch 2 (declared head = the rotate entry itself)
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

    // The partial-completion guidance says "re-run to resume from the
    // remainder without advancing the epoch". A run per that guidance (no
    // reason) is a request to resume only, so it exits successfully once
    // nothing is left (only a --reason'd run gets exit 1)
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("resume push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(dek2, pushed.value)).toBe("key-abc");
    // The re-encryption push declares the lineage (sameValueAs = the previous
    // version — AUTH_SPEC §12-5 — so it is not counted as resolving the
    // rotation-needed flag — AUDIT_SPEC §4.1-5)
    expect(pushed.sameValueAs).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("the requested rotation was not performed");
    // Never tell a run that requested nothing "switched without running the request"
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
    // In the window between the first pull and the composite's acceptance,
    // another member creates a variable on the old epoch. The real server
    // rejects such a concurrent creation with 422 via the acceptance-time
    // match (§12-4 — the boundary checkpoint's values_digest), so the post-
    // re-pull retry lands it in the target set (an accepted checkpoint's
    // snapshot always covers the distribution set — the premise of rule 2)
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
    // vlate, created in the window, also enters the retry's target set and completes only after re-encryption
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vlate"]);
    expect(state.rotateBodies).toHaveLength(2);
    const body = state.rotateBodies[1];
    if (body === undefined) throw new Error("rotate retry missing");
    // The retry's boundary checkpoint notarizes the value set including vlate
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
    // Not a resume but a rotation: an epoch-3 entry is made, and old-epoch
    // values go straight to epoch 3 without passing through the middle epoch
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3, version: 2 });
    // A forced rotation's re-encryption push also declares the lineage (§12-5)
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
    // Re-signed (timestamp · signature change), but the generated DEK's
    // commitment and the wrap set are reused as-is for the same epoch
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    expect(second.deks).toEqual(first.deks);
  });

  it("CheckpointStateMismatch (422) retries bounded, restarting from a verified pull (§12-4)", async () => {
    // A 422 from the boundary checkpoint's values_digest match = a concurrent
    // push after the declared head was fixed. Re-signing does not resolve it
    // (the value set must be re-fetched), so the retry restarts from a
    // verified pull rather than the composite-send re-sign loop (session-33 §5 F-2)
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
    // A retry restarts from a pull = a new DEK is generated (the previous
    // attempt's composite was never accepted and the epoch never advanced — safe to discard)
    expect(second.entry.payload.dekCommitmentHex).not.toBe(first.entry.payload.dekCommitmentHex);
    // The boundary checkpoint is bundled on the retry too (the value set is unchanged, so the digest is identical)
    expect(second.checkpoint.payload.environments[0]?.valuesDigestHex).toBe(
      first.checkpoint.payload.environments[0]?.valuesDigestHex,
    );
    expect(env.logs.join("\n")).toContain("re-pulling and retrying the rotation");
    // The intent discipline (3-F) × bounded retries (F-2) cross-layer (PR-F4):
    // attempt 1's intent is closed by the 422 (definite rejection), attempt
    // 2's intent is closed by the acceptance check — the retry loop never leaves an unresolved intent behind
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
    // Abort after the bound (3 attempts) — never pulls forever
    expect(state.rotateBodies).toHaveLength(3);
    const errors = env.errors.join("\n");
    expect(errors).toContain("values-digest-mismatch");
    expect(errors).toContain("Re-run `maruhi env rotate` to rebuild the checkpoint");
    // The intent discipline (3-F) × bounded retries cross-layer (PR-F4): 422
    // is a definite rejection (isServerRejection), so all 3 attempts' intents
    // close as rejected — no unresolved intent piles up and the floor never
    // advances (no match obligation left for the next run). The floor stays at
    // mv1 distributed by the first pull (pins the correct post-abort floor
    // state itself — a loose inequality would also let a vanished manifest through)
    const floor = await loadFloor(env);
    expect(floor?.intents).toEqual([]);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 1,
    });
  });

  it("a server that drops the accepted boundary checkpoint from chain distribution is detected by the post-acceptance rescan's strict verification (PR-F4 cross-layer)", async () => {
    // The end-to-end pinning of the 2-G' consequence: the manifest issued
    // with the composite (epoch = new_epoch · declared head = before the
    // append) verifies only on an exact match against the boundary-checkpoint
    // tuple (no H+1 exception exists — §4.3 (2)). A server that hides the
    // accepted checkpoint from chain distribution (the chain itself stays
    // valid under the consensus rule) is detected when the post-acceptance
    // rescan pull's manifest verification falls to strict and fails with
    // epoch-not-current-at-head — pinning that no path exists for "checkpoint
    // hiding" to revert to an H+1-equivalent loose acceptance
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
    // The composite itself is accepted (detection happens in the post-acceptance rescan pull's distribution-time verification)
    expect(state.rotateBodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
    // The acceptance check (self commitment matching on the chain) holds
    // independently of the checkpoint's presence, so the floor's
    // self-issued-manifest promotion (M1-A4) itself does happen
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
    const rotateBodies: RotateBody[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${projectId}/chain`, () => {
        // From the second sync on, the other member's rotate_epoch is stacked
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
        rotateBodies.push(request.body as RotateBody);
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
    // Stops the moment the concurrent rotation is detected (never resends to the bound)
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
    // The "winner another member wrote on the new epoch" visible on the
    // re-fetch after the 409. An honest concurrent writer chains prev into the verified version 1
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
        // Returns the 409 after settling the state where the concurrent push's winner won
        variables[0] = winner;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    // The winner was accepted on the current epoch = re-encryption unneeded. Never goes to overwrite
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("1 variable already re-encrypted by concurrent updates");
  });
});
