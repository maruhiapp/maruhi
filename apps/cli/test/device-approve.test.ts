import { readFile } from "node:fs/promises";

import { HandoffApprovalSchema, HandoffLookupSchema } from "@maruhi/api-schema";
import { fingerprintToWords } from "@maruhi/crypto";
import {
  buildChain,
  createEnvironmentOp,
  type GeneratedIdentity,
  genesisOp,
  grantServerOp,
  hexBytes,
} from "@maruhi/test-kit";
import { Effect, Exit, Schema } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { ownDevicesPathOf } from "../src/own-devices.ts";
import {
  ENV_ID,
  FAR_FUTURE_MS,
  owner,
  dev2,
  reserve,
  member,
  dek,
  addDeviceOp,
  type ServerState,
  makeServer,
  startEnv,
  requestRowOf,
  readOwnDevices,
  recordOwnDevice,
  chainWithEnvironment,
} from "./support/device.ts";
import { makeTestEnv } from "./support/env.ts";

function addsOf(
  state: ServerState,
  device: GeneratedIdentity,
): { readonly projectId: string; readonly roleCap: string }[] {
  return state.appendedTo.flatMap(({ projectId, entry }) =>
    entry.op === "add_device" && entry.payload.encPubHex === device.encPubHex
      ? [{ projectId, roleCap: entry.payload.roleCap }]
      : [],
  );
}

describe("maruhi device approve", () => {
  it("a backfill failure guides toward a sibling device's pull, not a re-run of the approval (DK K11-5)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      dekRegisterStatus: 500,
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`${built.projectId}: backfill of environment ${ENV_ID} failed (`);
    expect(errors).toContain(
      `A registered device of yours whose cap covers environment ${ENV_ID} and that holds its keys fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    expect(errors).not.toContain("Re-run `maruhi device approve`");
  });

  it("ceremony gate: refuses before fetching the request list in an agent environment / non-device (K4-6 counterexample 3)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to approve a device: an AI agent environment was detected",
    );
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to approve a device: stdin is not an interactive terminal",
    );
    expect(state.paths().filter((path) => path.includes("/auth/devices"))).toEqual([]);
    expect(state.appended).toEqual([]);
  });

  it("compares the full-length FP and proceeds add_device → backfill → local record → registry PUT → request cancellation", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex.toUpperCase()], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    const entry = state.appended[0]!;
    expect(entry.op).toBe("add_device");
    expect(entry.actor).toEqual({ userId: owner.userId, keyFingerprintHex: owner.fingerprintHex });
    expect(entry.payload).toEqual({
      encPubHex: dev2.encPubHex,
      sigPubHex: dev2.sigPubHex,
      roleCap: "owner",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.registered).toHaveLength(1);
    expect(
      state.registered[0]?.deks.map((wrap) => [
        wrap["recipientUserId"],
        wrap["recipientEncPubHex"],
        wrap["epoch"],
      ]),
    ).toEqual([[owner.userId, dev2.encPubHex, 1]]);
    const recorded = await readOwnDevices(env, server.origin);
    const row = recorded.find((candidate) => candidate.keyFingerprintHex === dev2.fingerprintHex);
    expect(row).toMatchObject({
      source: "approved",
      label: "laptop",
      addedByFingerprintHex: owner.fingerprintHex,
      revokedAtMs: null,
    });
    expect(state.registryPuts).toEqual([
      {
        fp: dev2.fingerprintHex,
        body: { encPubHex: dev2.encPubHex, sigPubHex: dev2.sigPubHex, label: "laptop" },
      },
    ]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
    const paths = state.paths();
    expect(paths.indexOf(`PUT /auth/devices/${dev2.fingerprintHex}`)).toBeGreaterThan(
      paths.lastIndexOf(`POST /projects/${built.projectId}/chain/entries`),
    );
    const approveLogs = env.logs.join("\n");
    expect(approveLogs).toContain("registered the device (backfilled 1 DEK wrap");
    expect(approveLogs).toContain(
      "Compare them with the screen of the machine you are adding, never with a fingerprint sent to you: a request can be placed by anyone holding an account-wide admin API token of yours",
    );
    expect(approveLogs.indexOf("fp words:")).toBeLessThan(
      approveLogs.indexOf("Compare them with the screen"),
    );
  });

  it("refuses a key whose enc public key a grant has named as its server key, before appending (CRYPTO_SPEC §6.2 key uniqueness)", async () => {
    const grant = await grantServerOp([ENV_ID], [], dev2.encPubHex);
    if (grant.op !== "grant_server") {
      throw new Error("grantServerOp built another operation");
    }
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: grant },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `The key's enc public key is server key ${grant.payload.serverKeyFingerprintHex}, which a grant has named, so no device may hold it (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2)`,
    );
    expect(state.appended).toEqual([]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });

  it("the 12 words can also be compared; `--cap` / `--env` become the device's cap (K4-6)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    const words = await fingerprintToWords(hexBytes(dev2.fingerprintHex));
    if (!words.ok) throw new Error("words");
    expect(
      await runCli(
        ["device", "approve", words.value.join(" "), "--cap", "reader", "--env", ENV_ID],
        env.layer,
      ),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended[0]?.payload).toMatchObject({
      roleCap: "reader",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_ID],
    });
    expect(env.logs.join("\n")).toContain(`cap reader/${ENV_ID}`);
  });

  it("ignores a request row whose claimed FP disagrees with the public key; fails when no request matches (a server injection)", async () => {
    const built = await chainWithEnvironment();
    const forged = { ...requestRowOf(dev2), keyFingerprintHex: "00".repeat(16) };
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [forged],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", "00".repeat(16)], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "claims fingerprint 00000000000000000000000000000000 but its public keys compute to",
    );
    expect(errors).toContain("No pending device-add request matches that fingerprint");
    expect(state.appended).toEqual([]);
    expect(await runCli(["device", "approve", dev2.fingerprintHex.slice(0, 16)], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain(
      "must be the full 32-character fingerprint or its 12 words",
    );
  });
  it("even when every project is skipped (this device unregistered, etc.), exit code is 1 and the request is kept", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, member);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("skipped — you are not a member of this project");
    expect(errors).toContain("the device was not registered on any project");
    expect(state.appended).toEqual([]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });

  it("a project where this device is not on the chain is skipped, and guides toward the sync path rather than request-less approval (DK K10-5)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(reserve)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "approve", reserve.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `skipped — this machine's key is not one of your registered devices here, so it cannot register devices here. A device of yours that is registered here adds the new device (and this machine) when it runs a keyed command on this project at a terminal (\`maruhi pull --project ${built.projectId}\`, for instance)`,
    );
    expect(errors).not.toContain("approve this machine first");
    expect(state.appendedTo).toEqual([]);
  });

  it("when the key at hand is not on the chain, the guidance separates approving the pending request from the sync path (DK K10-5)", async () => {
    const built = await chainWithEnvironment();
    const { server } = await makeServer({ built, withEnvironment: true });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "If `maruhi device add` is still waiting on this machine, approve it from a registered device with `maruhi device approve`. If this device is registered on other projects of yours, a device of yours that is registered here adds it when it runs a keyed command on this project at a terminal",
    );
    expect(errors).not.toContain("run `maruhi device approve` for this machine");
  });

  it("when several requests exist for the same key, it never silently picks one — it shows the labels and stops", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2, "laptop"), requestRowOf(dev2, "desk")],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `2 pending device-add requests carry the same key fingerprint ${dev2.fingerprintHex} (labels: laptop, desk)`,
    );
    expect(state.appended).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });

  it("if it lands on no project, no local record, registry PUT, or request cancellation runs (re-runnable)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--env", "env-missing"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not exist on this project's chain");
    expect(errors).toContain(
      "the device was not registered on any project, so nothing was recorded and the request was left in place",
    );
    expect(state.appended).toEqual([]);
    expect((await readOwnDevices(env, server.origin)).map((row) => row.source)).toEqual([
      "observed",
    ]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });

  it("a registry-PUT 429 does not cancel the request (DK K9-1); a re-run after rows were cleared converges via already → PUT → cancellation", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      registryPutStatuses: [429],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.registryPuts).toHaveLength(1);
    expect(state.requestCancels).toEqual([]);
    const note = env.errors.join("\n");
    expect(note).toContain("the device registry is full (32 rows)");
    expect(note).toContain(
      "will not see the completion signal. The request is left in place until",
    );
    expect(note).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap owner --all-envs\` before then to list it`,
    );
    expect(note).toContain("unlisted in your device registry");
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.registryPuts.map((put) => put.fp)).toEqual([
      dev2.fingerprintHex,
      dev2.fingerprintHex,
    ]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
    expect(env.logs.join("\n")).toContain("already registered");
  });

  it("a PUT failure other than 429 (a transient 500) also keeps the request and shows the same re-run guidance (DK K9-2)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      registryPutStatuses: [500],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.requestCancels).toEqual([]);
    const note = env.errors.join("\n");
    expect(note).toContain("could not update the device registry (");
    expect(note).toContain("the device is registered on the chains above regardless");
    expect(note).toContain(
      "will not see the completion signal. The request is left in place until",
    );
    expect(note).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap owner --all-envs\` before then to list it`,
    );
    expect(note).not.toContain("registry is full");
  });

  it("the re-issue in the PUT-failure Note carries this run's cap and --project (DK K10-1)", async () => {
    const built = await chainWithEnvironment();
    const { server } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      registryPutStatuses: [500],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(
        [
          "device",
          "approve",
          dev2.fingerprintHex,
          "--cap",
          "member",
          "--env",
          ENV_ID,
          "--project",
          built.projectId,
        ],
        env.layer,
      ),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap member --env ${ENV_ID} --project ${built.projectId}\` before then to list it`,
    );
  });

  it("re-running for a key already on the chain under a different cap refuses without appending or recording, keeps the request, and emits the same-cap command (DK K10-1)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "member", environmentIds: [ENV_ID] }),
      },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Device ${dev2.fingerprintHex} is already registered with cap member/${ENV_ID} on ${built.projectId}, and this approval asks for owner/all: a device's cap is set when it is first approved and cannot be changed later, so this approval appended nothing, recorded nothing and left the request in place`,
    );
    expect(errors).toContain(
      `Re-run it with that cap: \`maruhi device approve ${dev2.fingerprintHex} --cap member --env ${ENV_ID}\`.`,
    );
    expect(errors).toContain(
      "To give the device another cap, revoke it, then run `maruhi device add --replace` on that machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device with the cap you want",
    );
    expect(errors).not.toContain("re-add it instead");
    expect(state.appendedTo).toEqual([]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
    const before = (await readOwnDevices(env, server.origin)).find(
      (row) => row.keyFingerprintHex === dev2.fingerprintHex,
    );
    expect(before).toMatchObject({ source: "observed", roleCap: "member" });
    expect(
      await runCli(
        ["device", "approve", dev2.fingerprintHex, "--cap", "member", "--env", ENV_ID],
        env.layer,
      ),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appendedTo).toEqual([]);
    const after = (await readOwnDevices(env, server.origin)).find(
      (row) => row.keyFingerprintHex === dev2.fingerprintHex,
    );
    expect(after).toMatchObject({
      source: "approved",
      roleCap: "member",
      scope: { kind: "listed", environmentIds: [ENV_ID] },
    });
    expect(state.registryPuts.map((put) => put.fp)).toEqual([dev2.fingerprintHex]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
  });

  it("even if unregistered on another project, a disagreement with any chain's cap appends this run's cap nowhere (DK K10-4's 2 phases)", async () => {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2, { roleCap: "member" }) },
    ]);
    const p2 = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(owner) },
    ]);
    const { server, state } = await makeServer({
      built: p1,
      withEnvironment: false,
      requests: [requestRowOf(dev2)],
      extraProjects: [p2],
    });
    const env = await startEnv(server.origin, p1.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Device ${dev2.fingerprintHex} is already registered with cap member/all on ${p1.projectId}`,
    );
    expect(addsOf(state, dev2).map((add) => add.roleCap)).not.toContain("owner");
    expect(
      (await readOwnDevices(env, server.origin)).find(
        (row) => row.keyFingerprintHex === dev2.fingerprintHex,
      )?.source,
    ).not.toBe("approved");
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--cap", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(addsOf(state, dev2)).toEqual([{ projectId: p2.projectId, roleCap: "member" }]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
  });

  it("if the key's on-chain caps already differ per project, guides toward re-issuing one by one via --project (DK K10-2)", async () => {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2, { roleCap: "member" }) },
    ]);
    const p2 = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(owner) },
      { actor: reserve, operation: addDeviceOp(dev2, { roleCap: "admin" }) },
    ]);
    const { server, state } = await makeServer({
      built: p1,
      withEnvironment: false,
      requests: [requestRowOf(dev2)],
      extraProjects: [p2],
    });
    const env = await startEnv(server.origin, p1.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--cap", "member"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("member/all on ");
    expect(errors).toContain("admin/all on ");
    expect(errors).toContain(
      "Its cap differs between those projects, so re-run it once per project with `--project <id>` and the cap shown for that project.",
    );
    expect(addsOf(state, dev2)).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });
});

describe("the removal of the old device path (wire types)", () => {
  it('HandoffApprovalSchema rejects source "device" / blob, and HandoffLookupSchema\'s roles take only the fragment', async () => {
    const approval = {
      source: "device",
      shareIndex: 0,
      approverKeyFingerprintHex: "22".repeat(16),
      encHex: "aa".repeat(32),
      ciphertextHex: "bb".repeat(48),
    };
    const rejected = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(HandoffApprovalSchema)(approval),
    );
    expect(Exit.isFailure(rejected)).toBe(true);
    const lookup = {
      wardUserId: "user-ward",
      wardLogin: null,
      expiresAtMs: FAR_FUTURE_MS,
      roles: ["device"],
    };
    const rejectedLookup = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(HandoffLookupSchema)(lookup),
    );
    expect(Exit.isFailure(rejectedLookup)).toBe(true);
    const env = await makeTestEnv();
    await recordOwnDevice(env, "https://example.test", reserve, "reserve");
    const json = await readFile(ownDevicesPathOf(env.configPath), "utf8");
    expect(json).toContain(reserve.encPubHex);
    expect(json).not.toContain(reserve.encSkHex);
    expect(json).not.toContain(reserve.sigSkSeedHex);
  });
});
