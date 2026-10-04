// Integration tests for `maruhi device add / approve / list / revoke` and the
// first-sync device registration (CRYPTO_SPEC §3 / §6.2 / §7, AUTH_SPEC §13-11
// — 2026-09-19 DK K4. Design doc dk-design.md §9).
// Device ops are signed / verified with real crypto; the server is a wire-level mock.
//
// Pinned properties:
//  2. The first sync (the keyed prelude) appends only the local record's 3
//     provenances (reserve / approved / observed) to the chain, and never reads
//     or writes the registry (`GET /auth/devices`) (K4-3). A revoked record is
//     never appended. Devices observed on the chain are recorded with provenance (K4-4)
//  3. The expected count of the complete wrap set uses the same predicate as
//     the server (effective scope × devices, storage-key granularity)

import { verifyChainWithHistory } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { type VerifiedProject } from "../src/chain-sync.ts";
import { runCli } from "../src/cli.ts";
import { expectedWrapRecipientCount } from "../src/dek-wrap.ts";
import {
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
} from "./support/crypto.ts";
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
import { type MockHandler, onRequest } from "./support/server.ts";

/** The issuance POST of a command that passes through the keyed prelude (invite create). */
function inviteHandler(built: BuiltChain): MockHandler {
  return onRequest("POST", `/projects/${built.projectId}/invites`, () => ({
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
      // A command passing through the keyed prelude (invite create) — registration runs as a side effect of the sync
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
      // Emits the appended cap at the point the record's cap is in force (DK K10-3)
      expect(env.errors.join("\n")).toContain(`with cap owner/all on project ${built.projectId}`);
      // The registry is never an input to the decision: it is not even read (a device present only in the registry is never appended)
      expect(state.paths().filter((path) => path.startsWith("GET /auth/devices"))).toEqual([]);
      // The no-reserve-key warning (K4-9) only when "your devices are just this
      // one and the record holds no reserve key": reserve has a record, and
      // approved / observed end up with 2 devices after registration
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
      // The planted row (an unsigned file) — the provenance poses as approved
      await recordOwnDevice(env, server.origin, dev2, "approved");
      if (mode === "agent") {
        env.setAgent({ isAgent: true, name: "test-agent" });
      } else {
        env.setTerminal({ stdin: false });
      }
      // The keyed prelude (the first sync) runs, but registration is skipped
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
      // The prelude is one command per project, so emit a command aimed at this project (DK K10-5)
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
    // Only this device, no reserve-key record → the K4-9 warning
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
    // reserve was previously recorded here (active) — the chain's revocation is transcribed into the record
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
    // Your own device is recorded too (no Note is shown)
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
    // A revoked device is never re-registered
    expect(state.appended).toEqual([]);
  });
});

describe("the expected count of the complete wrap set (the server's same predicate — the R(E) device expansion)", () => {
  it("counts (person, device) pairs whose effective scope contains E plus grants, at storage-key granularity", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      // owner's second device has a cap holding env-b only
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "member", environmentIds: ["env-b"] }),
      },
      // member's scope is env-a only (1 device, no cap)
      { actor: owner, operation: addScopedMemberOp(member, "member", ["env-a"]) },
    ]);
    const verified = await verifyChainWithHistory(built.entries);
    if (!verified.ok) throw new Error("chain");
    const view = { state: verified.value.state } as VerifiedProject;
    // env-a: owner's 1st device (all) + member = 2. owner's 2nd device does not hold env-a
    expect(expectedWrapRecipientCount(view, "env-a")).toBe(2);
    // env-b: owner's 1st + 2nd devices = 2. member is out of scope
    expect(expectedWrapRecipientCount(view, "env-b")).toBe(2);
  });
});
