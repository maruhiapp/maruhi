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
import { wrapDekFor } from "./support/crypto.ts";
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
import { MockServer } from "./support/server.ts";

describe("maruhi env rotate", () => {
  it("--new-epoch advances the epoch even with an undecryptable value (revocation wins — §7)", async () => {
    // The member-removal run. If one unopenable value stopped the epoch from
    // advancing at all, the removed member's old DEK would stay valid for **every** variable
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
      // No wrap addressed to self at epoch 1
      deks: [await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner })],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "member removal", "--new-epoch"],
        env.layer,
      ),
    ).toBe(1);
    // **The epoch did advance** (the revocation itself is achieved)
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    // Openable values go to the new epoch; unopenable ones are reported unfinished
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Some values cannot be re-encrypted");
    expect(env.logs.join("\n")).toContain("Partial completion");
  });

  it("even when the composite send fails, if it was accepted it reports 'the epoch advanced'", async () => {
    // A lost response (502 / timeout). The DO accepted it, yet the client only
    // sees the transport error — ending on the raw error would read as
    // "nothing happened" and hide the most dangerous state: an epoch advanced
    // with 0 re-encryptions
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
      // Accepts it (appended to the chain), but the response returns 502
      onRotateAfterAccept: () => ({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "lost response"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("this rotation itself was accepted");
    expect(errors).toContain("resume re-encryption without advancing the epoch");
    // M1-A4: the moment the self commitment is confirmed matching on the
    // chain, the floor (the self-issued manifest) has advanced even if the
    // command exits with an error
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    // With the effect confirmed, the intent (3-F) is closed too
    expect(floor?.intents).toEqual([]);
  });

  it("if not even one value can be re-encrypted, the epoch never advances (an idle spin is no revocation)", async () => {
    // A member with not a single wrap addressed to them (or a response that
    // drops every wrap). Advancing only the epoch here would leave every
    // current value under the old epoch's DEK, and the chain would carry just
    // a "rotated" record with no revocation achieved
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
    // The epoch has reached the target value, but what landed is another
    // member's DEK commitment — our revocation rotation was never accepted
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
      // The send is a 502. Behind it, another member has already rotated to epoch 2
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
      chainAfterRotateAttempt: chainRotated,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "other member"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("another member's rotation");
    expect(errors).toContain("this run's entry was not accepted");
    // Never reads as our share having been accepted
    expect(errors).not.toContain("this rotation itself was accepted");
    // M1-A4: the commitment on the chain differs = the floor never advances
    // (no self-issued manifest recorded). Since non-acceptance is confirmed,
    // the intent closes as not-accepted
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest?.manifestVersion ?? 1).toBeLessThanOrEqual(1);
    expect(floor?.intents).toEqual([]);
  });

  it("even when another member has advanced further after the acceptance, our share's acceptance is not missed", async () => {
    // Between acceptance → lost response → confirmation, another member
    // rotates further. Judging by current-epoch match would misreport "not
    // accepted", but commitments for every epoch remain, so our share is distinguishable
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
      // Accepts it (our entry lands on the chain) but the response is 502.
      // After that another member advances further to epoch 3
      onRotateAfterAccept: () => ({ status: 502, bodyText: "bad gateway" }),
      appendRotateAfterAccept: { epoch: 3, dek: dek3 },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "overtaken"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("this rotation itself was accepted");
    expect(errors).toContain("resume re-encryption without advancing the epoch");
    expect(errors).not.toContain("was not accepted");
    // M1-A4: even when overtaken, our manifest (v2) stays as the minimum floor
    const floor = await loadFloor(env);
    expect(floor?.environments[ENV_ID]?.manifest).toMatchObject({
      manifestVersion: 2,
      epoch: 2,
    });
    expect(floor?.intents).toEqual([]);
  });

  it("when the post-acceptance check sees an overtake by another rotate right after the 200, our manifest still stays as the minimum floor (M1-A4)", async () => {
    // The 200 returned (acceptance is certain), but the shape where another
    // member advanced to epoch 3 before the post-acceptance check's resync.
    // The command errors out on current epoch (3) ≠ target (2), yet the epoch-
    // 2 commitment on the chain is ours, so the floor advances
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

  it("a rotate onto a deleted environment (404) is treated as a definite rejection — it never suggests re-running", async () => {
    // Rejected in the server's own error body = acceptance is definitively
    // known. No acceptance-check probe (a second chain fetch) is needed, and
    // "you can re-run as-is" must never be added to §7's interruption message
    // (a 404 is definitive and recurs)
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
    // §7's dedicated message comes out (never collapsed into the generic "environment not found")
    expect(errors).toContain("may be selectively blocking rotation");
    expect(errors).not.toContain("safe to simply re-run");
    expect(errors).not.toContain("was accepted");
    // No chain re-fetch for the acceptance check (only the first sync's one)
    const chainCalls = server.requests.filter((request) => request.path.endsWith("/chain")).length;
    expect(chainCalls - chainCallsBefore).toBe(1);
  });

  it("when acceptance cannot be confirmed, it explicitly states the epoch may have advanced", async () => {
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
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
      // The chain re-fetch for confirmation also fails (the connectivity failure persists)
      onChain: (call) => (call === 0 ? undefined : { status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "unverifiable"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("may already have advanced to epoch 2");
    expect(errors).toContain("Restore connectivity and re-run");
    // M1-A4: a probe failure = acceptance-unknown — the fact that acceptance
    // was never confirmed is never written to the floor (no advance). The
    // confirmation-obligation record (the intent — 3-F) stays unresolved and
    // the next run's match (the chain sync) resolves it
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
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "undelivered"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // The chain still sits at the declared head = a request in transit could
    // land later, so it never asserts "not accepted" (send-pending)
    expect(errors).toContain("does not show it as accepted yet");
    expect(errors).toContain("safe to simply re-run");
    // The intent (3-F) is left unresolved rather than settled — the match
    // after the chain moves settles accepted / rejected
    const floor = await loadFloor(env);
    expect(floor?.intents).toHaveLength(1);
  });

  it("when the intent (3-F) append fails, the composite is never sent (journal-before-send is fail-closed)", async () => {
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
    });
    const env = await startEnv(state.handlers, owner);
    env.failFloorIntentAppends();

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "journal"], env.layer)).toBe(1);
    // A security-critical mutation is never fired without a confirmation-obligation record
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("a value that cannot be opened despite holding the wrap aborts immediately as a suspected swap", async () => {
    // A wrap addressed to self exists yet decryption fails = a ciphertext swap
    // or an inconsistency with the verified view. It must never be collapsed
    // into a benign "waiting for a wrap" with guidance to step over it via
    // --new-epoch (it aborts immediately, same as pull / run).
    // The shape: a current-epoch value, but the encryption key differs (= AEAD authentication fails)
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
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "normal"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("possibly replaced by the server");
    // Never treated as a benign gap = no means to step over it is offered
    expect(errors).not.toContain("run with --new-epoch");
    expect(errors).not.toContain("a member holding wraps");
  });

  it("an unopenable value appearing mid-pass is also never demoted to partial completion — it aborts as evidence", async () => {
    // The case above is at the first pull (before rotation), so failing it
    // only loses "a run that never started". The dangerous case is it
    // appearing **after the epoch advanced** — treating it like a rescan's
    // transient failure morphs it into "a partial completion including
    // unverified — re-run to resume" (the sign of a swap swallowed by guidance for a re-run that returns the same result forever)
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
    // An old-epoch value absent from the first pull that appears only after
    // the composite's acceptance (= the pass-end rescan). The signature is
    // sound, but it is an old-epoch "creation" absent from the boundary
    // checkpoint's snapshot, and rule 2 (CRYPTO_SPEC §6.3 — PR-M3) rejects the
    // whole pull as evidence of backdated creation
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
      onRotateAccepted: () => {
        variables.push(tampered);
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "mid-pass"], env.layer)).toBe(1);
    // Unlike the first-pull case, the rotation itself did happen here
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    // Rejected as evidence of rule-2 backdated creation (PR-M3)
    expect(errors).toContain("below the checkpoint baseline epoch");
    expect(errors).toContain("This is evidence that re-running will not resolve");
    // Never demoted into "a re-run will clear it" style guidance
    expect(errors).not.toContain("resume from the remainder");
    expect(errors).not.toContain("may include unconfirmed ones");
  });

  it("even with one undecryptable value, resume re-encrypts the openable share (the epoch has already advanced)", async () => {
    // A member in the §12-7 transitional state: holds the epoch-2 wrap but not
    // epoch 1's (added after the rotation / the epoch-1 re-wrap is unregistered)
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
      // No wrap addressed to self at epoch 1 (only epochs 2 / 3)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
    });
    const env = await startEnv(state.handlers, owner);

    // The 1 unopenable value is reported unfinished, but the 1 openable one is pushed
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3 });
    const errors = env.errors.join("\n");
    expect(errors).toContain("Some values cannot be re-encrypted");
    expect(errors).toContain("No DEK for epoch 1");
    // The cause never morphs into the default wording (conflict)
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
    // The same variable's warning appears only once (if the wording split
    // between the resume path and the pass-end rescan, dedupeWarnings would
    // let both through as distinct)
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
    // The "on the current epoch but prev does not connect" successor visible on the rescan after the 502
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
      // A transient failure rather than a 409 (this variable never enters the conflicted set)
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = forked;
        return { status: 502, bodyText: "bad gateway" };
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
    });
    const env = await startEnv(state.handlers, owner);

    // First sync (no floor): the target set's only provenance is the server
    // response, so a consistent omission cannot be detected. On a revocation-
    // purpose rotation this is never kept silent
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "no floor"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("the omission cannot be detected");

    // It does not appear on run 2 (with floor)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "with floor"], env.layer)).toBe(0);
    const secondRunErrors = env.errors.filter((line) =>
      line.includes("the omission cannot be detected"),
    );
    expect(secondRunErrors).toHaveLength(1);
  });
});
