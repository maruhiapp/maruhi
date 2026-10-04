// Tests for epoch rotation (`maruhi env rotate`).
//
// Pillars verified:
//  1. The composite request (§12-4): a rotate_epoch entry (new_epoch = current
//     + 1 · reason · the new epoch's commitment — §5.2 / §6.2) + a complete
//     wrap set matching the current member set exactly. Each wrap carries a
//     §5.1 signature, and the DEK the recipient opens matches the entry's commitment
//  2. Re-encryption of current values (§7 / §4.1): the latest value of every
//     active variable is re-encrypted under the new DEK and sent via a normal
//     push signed by the runner as writer
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

import { computeEnvValuesDigest, SUITE_ID, verifyDekCommitment } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  addScopedMemberOp,
  buildChain,
  createEnvironmentOp,
  genesisOp,
  makeTestUser,
  valueHashOf,
  wrapDekFor,
} from "./support/crypto.ts";
import {
  chainBase,
  decryptWire,
  dek1,
  ENV_ID,
  makeServer,
  newEpochDekOf,
  owner,
  startEnv,
  variableAt,
  verifyAndUnwrap,
} from "./support/env-rotate.ts";

describe("maruhi env rotate", () => {
  it("composite request: sends a rotate_epoch entry (with commitment) + the complete wrap set, and re-encrypts current values under the new DEK", async () => {
    const member = await makeTestUser("user-member-3333");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const head = built.hashes[built.hashes.length - 1] ?? "";
    const variables = [
      await variableAt({
        built,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 3,
      }),
      await variableAt({
        built,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 2,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const state = makeServer({
      built,
      variables,
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

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "preventive rotation upon member removal"],
        env.layer,
      ),
    ).toBe(0);

    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate was not called");
    // Parent-head CAS + the entry sits right after the current head (seq = head + 1), actor = the caller
    expect(body.parentHeadHashHex).toBe(head);
    expect(body.entry.op).toBe("rotate_epoch");
    expect(body.entry.seq).toBe(built.entries.length + 1);
    expect(body.entry.prevHashHex).toBe(head);
    expect(body.entry.actor.userId).toBe(owner.userId);
    // new_epoch = current epoch + 1; reason lands on the chain (§6.2)
    expect(body.entry.payload.environmentId).toBe(ENV_ID);
    expect(body.entry.payload.newEpoch).toBe(2);
    expect(body.entry.payload.reason).toBe("preventive rotation upon member removal");
    // Wrap targets = exactly the verified current member set (§6.3)
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    expect(body.deks.every((wrap) => wrap.epoch === 2)).toBe(true);
    // Every recipient gets the same new DEK, matching the entry's commitment (§5.2)
    const deks: string[] = [];
    for (const wrap of body.deks) {
      const unwrapped = await verifyAndUnwrap({
        wrap,
        recipient: wrap.recipientUserId === owner.userId ? owner : member,
        signer: owner,
      });
      deks.push(Buffer.from(unwrapped).toString("hex"));
    }
    expect(new Set(deks).size).toBe(1);
    const newDek = await newEpochDekOf(body);
    const matched = await verifyDekCommitment({
      context: { suite: "maruhi/v1", projectId: built.projectId, environmentId: ENV_ID, epoch: 2 },
      dek: newDek,
      expectedCommitmentHex: body.entry.payload.dekCommitmentHex,
    });
    expect(matched.ok).toBe(true);
    // Re-encryption: every active variable is pushed at the new epoch, next version
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vbb"]);
    const pushedA = state.pushes.find((push) => push.variableId === "vaa");
    const pushedB = state.pushes.find((push) => push.variableId === "vbb");
    if (pushedA === undefined || pushedB === undefined) throw new Error("missing pushes");
    expect(pushedA.value.aad).toMatchObject({ epoch: 2, version: 2, variableId: "vaa" });
    expect(pushedB.value.aad).toMatchObject({ epoch: 2, version: 3, variableId: "vbb" });
    // Plaintext is preserved (decryptable under the new DEK)
    expect(await decryptWire(newDek, pushedA.value)).toBe("postgres://example");
    expect(await decryptWire(newDek, pushedB.value)).toBe("key-abc");
    // prev is the signed-bytes hash of the verified immediately-prior version (the §4.1 chain)
    expect(pushedA.value.prevValueSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(env.logs.join("\n")).toContain("epoch 1 → 2");
    expect(env.logs.join("\n")).toContain("re-encrypted 2 variables");
  });

  it("the complete wrap set = R(E): a current member whose scope excludes the environment gets no new-DEK wrap (ES K4 — CRYPTO_SPEC §6.2 / §6.3)", async () => {
    const insider = await makeTestUser("user-insider-7777");
    const outsider = await makeTestUser("user-outsider-8888");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp("env-other", dek1) },
      { actor: owner, operation: addScopedMemberOp(insider, "reader", [ENV_ID]) },
      { actor: owner, operation: addScopedMemberOp(outsider, "member", ["env-other"]) },
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
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "scope test"], env.layer)).toBe(0);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate was not called");
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, insider.userId].toSorted(),
    );

    // An out-of-scope environment is refused before communication (before a value-carrying pull = a var.read record — §6.3)
    const outsiderEnv = await startEnv(state.handlers, outsider);
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "scope test"], outsiderEnv.layer),
    ).toBe(1);
    expect(outsiderEnv.errors.join("\n")).toContain("outside your environment scope");
    expect(state.rotateBodies).toHaveLength(1);
  });

  it("trigger (i): issues a periodic checkpoint for the environment after rotate + re-encryption complete (CRYPTO_SPEC §6.3 — PR-M2)", async () => {
    const auditHead = "ab".repeat(32);
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
      standaloneCheckpoint: { auditHeadHashHex: auditHead },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "periodic"], env.layer)).toBe(0);
    // The tail = the periodic checkpoint after re-encryption completes (standalone, after the boundary's H+2)
    const tail = state.chainEntries[state.chainEntries.length - 1];
    if (tail === undefined || tail.op !== "checkpoint") {
      throw new Error("the post-rotation periodic checkpoint was not appended");
    }
    expect(tail.payload.environments).toHaveLength(1);
    const tuple = tail.payload.environments[0];
    if (tuple === undefined) throw new Error("missing tuple");
    expect(tuple.environmentId).toBe(ENV_ID);
    // The notarized subject = the data state **after** re-encryption completed (new-epoch values)
    expect(tuple.epoch).toBe(2);
    const reencrypted = state.pushes.find((push) => push.variableId === "vaa");
    if (reencrypted === undefined) throw new Error("missing re-encrypted push");
    const digest = await computeEnvValuesDigest(SUITE_ID, [
      {
        variableId: "vaa",
        version: reencrypted.value.aad.version,
        valueSigHashHex: await valueHashOf(reencrypted.value, owner.userId),
      },
    ]);
    if (!digest.ok) throw new Error("digest failed");
    expect(tuple.valuesDigestHex).toBe(digest.value);
    // Effective permission admin (the mock's /auth/me = admin scope), so it notarizes the audit head
    expect(tail.payload.auditHeadHashHex).toBe(auditHead);
    expect(env.logs.join("\n")).toContain("post-rotation periodic checkpoint");
  });

  it("interruption recovery: from a state that crashed after the composite was accepted, resumes the remaining re-encryption without advancing the epoch", async () => {
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
    // The server falls on the second variable's push (= a crash mid-re-encryption)
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
      // Only vbb keeps failing throughout run 1 (never recovers even on in-pass retries)
      onPush: (call, variableId) =>
        variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    // Run 1: the rotation was accepted, but re-encryption interrupts at 1 variable
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "first run"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.pushes).toHaveLength(1);
    const first = state.rotateBodies[0];
    if (first === undefined) throw new Error("rotate was not called");
    const newDek = await newEpochDekOf(first);

    // Run 2 (same config, same local floor): the epoch stays 2, and only the
    // remaining 1 variable is re-encrypted. rotate is **never called** (never
    // advances the epoch twice). Because --reason was passed = a rotation was
    // requested, a run that switched to resuming must not exit successfully
    // (a script must not mistake it for "a new epoch was made")
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "re-run"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.pushes).toHaveLength(2);
    const resumed = state.pushes[1];
    if (resumed === undefined) throw new Error("resume push missing");
    expect(resumed.variableId).toBe("vbb");
    expect(resumed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(newDek, resumed.value)).toBe("key-abc");
    // That it resumed is made explicit (also that the --reason is never recorded on the chain)
    expect(env.errors.join("\n")).toContain("with incomplete re-encryption");
    expect(env.logs.join("\n")).toContain("resumed re-encryption");
    // A resume is not "the requested rotation": the completion report never
    // hides the fact that no new epoch was made (blocks the shape where a run
    // after member removal looks successful)
    expect(env.logs.join("\n")).toContain("No new epoch was created");
    expect(env.errors.join("\n")).toContain("the requested rotation was not performed");
    // On a run that had a request, state explicitly "switched without running the request"
    expect(env.errors.join("\n")).toContain("The requested rotation will not be performed");
  });

  it("trigger (i): a periodic checkpoint is also issued when re-encryption completes on the resume path", async () => {
    const auditHead = "cd".repeat(32);
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
      // Only vbb keeps failing throughout run 1 = a crash mid-re-encryption.
      // Run 1 never reaches full completion, so no periodic checkpoint is issued
      onPush: (call, variableId) =>
        variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
      standaloneCheckpoint: { auditHeadHashHex: auditHead },
    });
    const env = await startEnv(state.handlers, owner);

    // Run 1: rotate was accepted but re-encryption interrupted — the chain's
    // tail gains no checkpoint (only the 2 entries: rotate + boundary checkpoint)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "first run"], env.layer)).toBe(1);
    const afterCrash = state.chainEntries.length;
    expect(state.chainEntries[afterCrash - 1]?.op).toBe("checkpoint"); // the boundary's (H+2)
    expect(state.chainEntries[afterCrash - 2]?.op).toBe("rotate_epoch");

    // Run 2 (no reason = the guided resume): re-encrypts the remaining 1
    // variable and **completes** → the environment's periodic checkpoint is
    // issued at the completion boundary
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.chainEntries.length).toBe(afterCrash + 1);
    const tail = state.chainEntries[state.chainEntries.length - 1];
    if (tail === undefined || tail.op !== "checkpoint") {
      throw new Error("the post-resume periodic checkpoint was not appended");
    }
    expect(tail.payload.environments).toHaveLength(1);
    const tuple = tail.payload.environments[0];
    if (tuple === undefined) throw new Error("missing tuple");
    expect(tuple.environmentId).toBe(ENV_ID);
    // The notarized subject = the data state **after** re-encryption completed (both variables on the new epoch)
    expect(tuple.epoch).toBe(2);
    const pushedA = state.pushes.find((push) => push.variableId === "vaa");
    const pushedB = state.pushes.find((push) => push.variableId === "vbb");
    if (pushedA === undefined || pushedB === undefined) throw new Error("missing pushes");
    const digest = await computeEnvValuesDigest(SUITE_ID, [
      {
        variableId: "vaa",
        version: pushedA.value.aad.version,
        valueSigHashHex: await valueHashOf(pushedA.value, owner.userId),
      },
      {
        variableId: "vbb",
        version: pushedB.value.aad.version,
        valueSigHashHex: await valueHashOf(pushedB.value, owner.userId),
      },
    ]);
    if (!digest.ok) throw new Error("digest failed");
    expect(tuple.valuesDigestHex).toBe(digest.value);
    expect(tail.payload.auditHeadHashHex).toBe(auditHead);
    expect(env.logs.join("\n")).toContain("post-rotation periodic checkpoint");
  });

  it("a post-rotation push failure reports the fact that the epoch advanced as a partial completion", async () => {
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
      onPush: () => ({ status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "first run"], env.layer)).toBe(1);
    // The composite was accepted = the epoch did advance. Never end on the raw
    // error alone — convey "the epoch advanced and re-encryption remains" plus the means to resume
    expect(state.rotateBodies).toHaveLength(1);
    // All passes were spent (= each pass's rescan did run), so the remaining
    // count is measured. Says neither "interrupted" nor "includes unverified"
    expect(env.logs.join("\n")).toContain("Partial completion");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    expect(env.logs.join("\n")).not.toContain("may include unconfirmed ones");
    const errors = env.errors.join("\n");
    expect(errors).toContain("re-encryption did not complete");
    expect(errors).not.toContain("re-encryption was interrupted");
    expect(errors).toContain("resume from the remainder without advancing the epoch");
  });

  it("the partial-completion cause shows the latest failure (a resolved transient failure must not hide the real cause)", async () => {
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
      // Pass 1 is a transient 503; from then on it keeps returning 404 (= the cause blocking it now)
      onPush: (call, variableId) =>
        call === 0
          ? { status: 503, bodyText: "unavailable" }
          : { status: 404, json: { _tag: "VariableNotFound", variableId } },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "cause freshness"], env.layer)).toBe(
      1,
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "re-encryption did not complete: Re-encryption of variable DATABASE_URL was rejected with 404 (possible concurrent deletion)",
    );
    expect(errors).not.toContain("re-encryption did not complete: Failed to re-encrypt");
  });

  it("a resolved transient failure is not kept as the cause (an unresolved conflict is reported as a conflict)", async () => {
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
      // vaa is a 502 only on pass 1 (succeeds on pass 2). vbb keeps conflicting to the end
      onPush: (call, variableId) => {
        if (variableId === "vaa") {
          return call === 0 ? { status: 502, bodyText: "bad gateway" } : undefined;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mixed"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // Only the conflicting share remains, so the cause is conflict. Raising
    // the resolved 502 would mislead the investigation toward verification
    // failure / floor violation
    expect(errors).toContain("conflicts with concurrent pushes did not resolve");
    expect(errors).not.toContain("re-encryption did not complete");
    // The fact that a now-resolved failure happened is kept as a warning
    expect(errors).toContain("There were failures during re-encryption");
  });

  it("only when the pass-end rescan was never reached is the remaining count reported as 'includes unverified'", async () => {
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
      onPush: () => ({ status: 503, bodyText: "unavailable" }),
      // Let the first pull through, then fail the pass-end rescan (= the actual state cannot be checked)
      onPull: (call) => (call === 0 ? undefined : { status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "rescan failure"], env.layer)).toBe(
      1,
    );
    // The conflicting share may have been resolved by another member, so it is never asserted
    expect(env.logs.join("\n")).toContain("1 variable incomplete (may include unconfirmed ones)");
    expect(env.errors.join("\n")).toContain("re-encryption was interrupted");
  });
});
