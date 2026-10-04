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
      // vcc is made to conflict and carried into pass 2. vbb's accepted write
      // (version 2) is never reflected — the rescan keeps distributing it at
      // version 1 = a push-back
      onPush: (_call, variableId) => {
        if (variableId === "vbb") {
          // It accepts but never persists (the shape where the server swallows our write)
          return {
            status: 200,
            json: { variableId, version: 2, epoch: 2 },
          };
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);
    // Fail only the floor commit of the accepted push: the floor is a SHOULD,
    // and this pins that the detection works even when it cannot be written (corruption · permission)
    env.failFloorPushCommits();

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    // Even without a floor, regressing from a version we signed is evidence of a rollback
    expect(env.errors.join("\n")).toContain(
      "older than the known latest version (2) — inconsistent",
    );
  });

  it("the same SHOULD warning is not displayed twice across passes", async () => {
    // A non-NFC name (uncomposed Á) warns on every pull — still one line across 3 passes
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
      // Only the leading 1 variable always fails (since the order is stable,
      // aborting would leave the following variables unreachable on any re-run)
      onPush: (_call, variableId) =>
        variableId === "vaa" ? { status: 502, bodyText: "bad gateway" } : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "poison variable"], env.layer)).toBe(
      1,
    );
    // The 2 following variables did move to the new epoch (the partial completion is the poison variable only)
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vbb", "vcc"]);
    expect(env.logs.join("\n")).toContain("1 variable incomplete");
  });

  it("even on a pass aborted because no pushable target remained, the cause is reported without collapsing to conflict", async () => {
    // The conflicting vbb is written out by another member on pass 2, leaving
    // only the unopenable vaa. The pass aborts via stalledOnUndecryptable
    // because no pushable target remains — but collapsing the cause to the
    // default wording (conflict) here would have the operator chase a
    // nonexistent concurrent writer (the shape that runs to the final pass is the next test's job)
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
      // No wrap addressed to self at epoch 1 (= vaa cannot be opened)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      // vbb keeps conflicting, but another member writes it out on the current epoch after pass 2
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
    // The pushable target (vbb) keeps conflicting to the end, so no abort
    // happens and the passes run out. The final pass's rescan **never
    // decrypts** (it makes no plaintext that will never be pushed), so
    // targets comes back empty — but wrap presence for self is known from a
    // Map lookup alone. Skipping this would leave the unopenable vaa behind
    // while the cause morphs into the conflict default wording
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
      // No wrap addressed to self at epoch 1 (= vaa cannot be opened)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      // vbb keeps conflicting to the end (= a push target remains on every pass, so it never aborts)
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    // No push is accepted (409 on every pass). vbb remains as "a pushable
    // target" every pass, so no abort happens and it reaches the final pass's
    // decryption-free rescan
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("No DEK for epoch 1");
    expect(errors).not.toContain("conflicts with concurrent pushes did not resolve");
    expect(env.logs.join("\n")).toContain("2 variables incomplete");
  });

  it("when resume is impossible for lack of the current epoch's DEK, it guides toward the --new-epoch escape", async () => {
    // A member who joined after the interrupted rotation: no wrap for the
    // current epoch (2) addressed to them yet. Resume is impossible, but
    // --new-epoch works (they make a new DEK themselves, so the current
    // epoch's DEK is unneeded) — without this guidance the revocation deadlocks
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
    // Only 1 item is raised as the cause. Dropping the second onward would
    // leave a permanently failing variable's reason (a too-large value, say)
    // never surfaced on any run, left behind on the old epoch forever
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
    // Both reasons remain with variable names (even though only one reaches the cause field)
    expect(errors).toContain("Failed to re-encrypt variable TRANSIENT");
    expect(errors).toContain("Failed to re-encrypt variable TOO_BIG");
  });

  it("when not a single current value can be opened, it never recommends the unsatisfiable --new-epoch", async () => {
    // With not a single wrap addressed to self, even proceeding to
    // --new-epoch is rejected by ensureRotationIsUseful. Recommending it would
    // bounce the user between two contradictory errors
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
    // Mistakes in the invocation itself (undeclared options · a value for a
    // boolean · extra positional args · a positional arg written as an option)
    // are owned by the check shared across all commands (args.test.ts). Here
    // we pin the env-specific applicability and that rotate fails the same way
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // A misspelling (left alone, the intent "always a new epoch" silently falls to the weaker resume path)
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epochs"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Unknown flag");
    // A create-only option passed to rotate is also refused (the env-specific check)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--name", "n"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("Unknown flag");
    // A value for a boolean: effect/cli **interprets** both the
    // inline form (`=false`) and the space-separated form (`--new-epoch
    // false`) as the boolean's value, so these are not mistakes — they are normal runs read as written
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch=false"], env.layer),
    ).toBe(0);
    expect(env.logs.join("\n")).toContain("epoch 1 → 2");
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch", "false"], env.layer),
    ).toBe(0);
    // The value is not dropped into an extra positional arg — it is consumed as the flag's value
    expect(env.errors.join("\n")).not.toContain("Unexpected extra arguments");
    // Writing the positional arg's name as an option is refused without
    // discarding the value (blocks the shape where `env rotate dev
    // --environment-id other` rotates dev). An environment ID is unique
    // across all chain history (§6.2), so a mix-up is permanent
    const beforeSwap = server.requests.length;
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--environment-id", "other-env"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--environment-id is a positional argument");
    // The mix-up check runs before any communication (never leaves a var.read under the wrong ID)
    expect(server.requests.length).toBe(beforeSwap);
    // Declared options that are not operation-only (--project etc.) are not
    // refused. The allowed set is derived from the argument table, so a
    // hand-written list never falls out of sync and rejects them (pins that
    // they **succeed**, not merely "are not refused" — so a loosened check
    // surfacing as a failure of the rotation itself is still noticed)
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--project", chainBase.projectId],
        env.layer,
      ),
    ).toBe(0);
    // On the refused examples no HTTP happens at all (only the 2 normal-run examples communicate)
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
    // The complete set = the current members (owner) + the server key of an
    // in-scope grant (§7's re-wrap obligation — without the re-wrap the lease path stops)
    expect(body.deks).toHaveLength(2);
    const serverWrap = body.deks.find((wrap) => wrap.recipientClass === "server");
    expect(serverWrap?.recipientUserId).toBe(grantEntry.payload.serverKeyFingerprintHex);
    expect(serverWrap?.recipientEncPubHex).toBe(grantEntry.payload.serverEncPubHex);
  });

  it("a grant_server disclosing only a different environment never stops this environment's revocation rotation (§7)", async () => {
    // Epochs advance independently per environment (§3). If a grant
    // disclosing only dev blocked prod's rotation, the sole means needed for
    // member removal would stall on another environment's setting — the
    // judgment uses scope (§6.2's "subset of target environments")
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
    // It never even reaches a pull (a var.read record)
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
  });

  it("a run with nothing unfinished and no --reason only checks and writes nothing", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // The landing point of the re-run the partial-completion guidance
    // recommends. Requiring --reason here would demand a reason from the user
    // who re-ran as guided — and specifying one would trigger a second rotation
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Check complete");
    expect(env.logs.join("\n")).toContain("To create a new epoch, pass --reason");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("a --new-epoch run without --reason fails before fetching values (leaves no var.read)", async () => {
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
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // --new-epoch always signs an entry = a reason is mandatory. Never goes to
    // fetch every variable's ciphertext for an unsatisfiable argument check
    // and leaves a per-variable var.read in the audit log (the same discipline as ensureRotatable)
    // A usage mistake (the missing reason) is a usage error (2) — so the same
    // `--reason` mistake never splits by exit code
    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the rotation reason with --reason");
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("an empty --reason fails instead of collapsing into 'check only' (never makes a successful exit that did nothing despite a request)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // The `--reason "$UNSET_VAR"` shape. Treating it as unspecified would
    // leave the member-removal script believing "a new epoch was made" while
    // nothing was sent. An empty string is failed as a usage error (2) by the
    // shared argument check (a value indistinguishable from "unspecified"
    // never falls back to the default — ADR-0016 decision 2's NonBlank declaration)
    for (const empty of [["--reason", ""], ["--reason="]]) {
      expect(await runCli(["env", "rotate", ENV_ID, ...empty], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("Unacceptable value for flag --reason");
      expect(env.logs.join("\n")).not.toContain("Check complete");
    }
    // A whitespace-only value is also failed as empty by the shared check
    // (the unset form of `"$VAR"` can become `""` or `" "`)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "  "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Unacceptable value for flag --reason");
    expect(state.rotateBodies).toHaveLength(0);
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("the path that creates a new epoch requires --reason (also with --new-epoch given)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--reason");
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
