import { verifyChainWithHistory, wrapRecipientsOf } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
  testEnvironmentId,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import {
  ENV_ID,
  FAR_FUTURE_MS,
  owner,
  dev2,
  reserve,
  member,
  dek,
  addDeviceOp,
  revokeDeviceOp,
  makeServer,
  startEnv,
  readOwnDevices,
  recordOwnDevice,
  chainWithEnvironment,
} from "./support/device.ts";
import { type MockHandler, onEndpoint } from "./support/server.ts";

function inviteHandler(built: BuiltChain): MockHandler {
  return onEndpoint("invites.issue", { projectId: built.projectId }, () => ({
    status: 200,
    json: { expiresAtMs: FAR_FUTURE_MS },
  }));
}

describe("first-sync device registration (device-sync — K4-3 / K4-4 / K4-9)", () => {
  for (const source of ["reserve", "approved", "observed"] as const) {
    it(`a local-record provenance ${source} absent from the chain gets add_device + backfill, and the registry is never read`, async () => {
      const built = await chainWithEnvironment();
      const { server, state } = await makeServer({
        built,
        withEnvironment: true,
        extra: [inviteHandler(built)],
        registryRows: [
          {
            keyFingerprintHex: dev2.fingerprintHex,
            encPubHex: dev2.encPubHex,
            sigPubHex: dev2.sigPubHex,
            label: "planted",
            createdAtMs: 1,
          },
        ],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      const device = source === "reserve" ? reserve : dev2;
      await recordOwnDevice(env, server.origin, device, source);
      expect(
        await runCli(["invite", "create", "--role", "member"], env.layer),
        env.errors.join("\n"),
      ).toBe(0);
      expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
      expect(state.appended[0]?.payload).toMatchObject({
        encPubHex: device.encPubHex,
        sigPubHex: device.sigPubHex,
        roleCap: "owner",
        scopeKind: "all",
      });
      expect(state.registered[0]?.deks.map((wrap) => wrap["recipientEncPubHex"])).toEqual([
        device.encPubHex,
      ]);
      expect(env.errors.join("\n")).toContain(
        `registered your device ${device.fingerprintHex} (${source}`,
      );
      expect(env.errors.join("\n")).toContain(`with cap owner/all on project ${built.projectId}`);
      expect(state.paths().filter((path) => path.startsWith("GET /auth/devices"))).toEqual([]);
      expect(env.errors.join("\n")).not.toContain("no reserve key is registered");
    });
  }

  it("a failed backfill for a registered device guides toward pull, not the next sync (DK K11-5)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      extra: [inviteHandler(built)],
      dekRegisterStatus: 500,
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved");
    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `; the backfill failed for 1 environment (${ENV_ID}) — a registered device of yours whose cap covers it fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    expect(errors).not.toContain("retried on the next sync");
  });

  it("in an agent environment / non-device, registration from the record does not run (the ceremony gate — K4-37)", async () => {
    for (const mode of ["agent", "non-tty"] as const) {
      const built = await chainWithEnvironment();
      const { server, state } = await makeServer({
        built,
        withEnvironment: true,
        extra: [inviteHandler(built)],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      await recordOwnDevice(env, server.origin, dev2, "approved");
      if (mode === "agent") {
        env.setAgent({ isAgent: true, name: "test-agent" });
      } else {
        env.setTerminal({ stdin: false });
      }
      await runCli(["invite", "create", "--role", "member"], env.layer);
      expect(state.appended).toEqual([]);
      expect(state.registered).toEqual([]);
      const errors = env.errors.join("\n");
      expect(errors).toContain(
        `1 device key recorded on this machine (${dev2.fingerprintHex}) is not registered on project`,
      );
      expect(errors).toContain(
        mode === "agent"
          ? "an AI agent environment was detected (test-agent)"
          : "stdin is not an interactive terminal",
      );
      expect(errors).toContain(`for example \`maruhi pull --project ${built.projectId}\``);
    }
  });

  it("a device recorded as revoked is never appended, and neither is a device present only in the registry (negative)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      extra: [inviteHandler(built)],
      registryRows: [
        {
          keyFingerprintHex: reserve.fingerprintHex,
          encPubHex: reserve.encPubHex,
          sigPubHex: reserve.sigPubHex,
          label: "planted",
          createdAtMs: 1,
        },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved", 1_700_000_000_000);
    expect(
      await runCli(["invite", "create", "--role", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toEqual([]);
    expect(state.registered).toEqual([]);
    expect(env.errors.join("\n")).toContain(
      "no reserve key is registered for you on this project (only this device's key). Run `maruhi key recovery`",
    );
  });

  it("when a device recorded as revoked is valid on the chain, it guides toward revocation or re-adding — not the unachievable 'approve it again' (DK K10-5)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [inviteHandler(built)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved", 1_700_000_000_000);
    expect(
      await runCli(["invite", "create", "--role", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `device ${dev2.fingerprintHex} was revoked from this machine's records but is active on project ${built.projectId}`,
    );
    expect(errors).toContain(
      "It is not re-added to other projects from here (a revoked record is never cleared by syncing). If it should not be active, revoke it with",
    );
    expect(errors).toContain(
      "if that machine should be on more projects, revoke it, then run `maruhi device add --replace` on that machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device",
    );
    expect(errors).not.toContain("approve it explicitly");
    expect(state.appendedTo).toEqual([]);
  });

  it("a device observed on the chain is recorded with provenance (whose device appended it at which seq); an observed revocation is transcribed into the record", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: owner, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [inviteHandler(built)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, reserve, "reserve");
    expect(
      await runCli(["invite", "create", "--role", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const recorded = await readOwnDevices(env, server.origin);
    expect(recorded.find((row) => row.keyFingerprintHex === dev2.fingerprintHex)).toMatchObject({
      source: "observed",
      addedByFingerprintHex: owner.fingerprintHex,
      observedProjectId: built.projectId,
      revokedAtMs: null,
    });
    expect(recorded.find((row) => row.keyFingerprintHex === owner.fingerprintHex)).toMatchObject({
      source: "observed",
      addedByFingerprintHex: null,
    });
    expect(
      recorded.find((row) => row.keyFingerprintHex === reserve.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `observed your device ${dev2.fingerprintHex} (cap owner/all) on project ${built.projectId}: added by device ${owner.fingerprintHex} at seq 2`,
    );
    expect(errors).toContain(
      `device ${reserve.fingerprintHex} is revoked on project ${built.projectId}; marked as revoked`,
    );
    expect(errors).not.toContain(`observed your device ${owner.fingerprintHex}`);
    expect(state.appended).toEqual([]);
  });
});

describe("the complete wrap set's recipients over a real chain (R(E) — the device expansion)", () => {
  it("counts each (person, device) pair whose effective scope contains E", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "member", environmentIds: ["env-b"] }),
      },
      { actor: owner, operation: addMemberOp(member, "member", ["env-a"]) },
    ]);
    const verified = await verifyChainWithHistory(built.entries);
    if (!verified.ok) throw new Error("chain");
    const { state } = verified.value;
    expect(wrapRecipientsOf(state, testEnvironmentId("env-a"))).toHaveLength(2);
    expect(wrapRecipientsOf(state, testEnvironmentId("env-b"))).toHaveLength(2);
  });
});
