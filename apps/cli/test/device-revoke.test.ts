// Integration tests for `maruhi device add / approve / list / revoke` and the
// first-sync device registration (CRYPTO_SPEC §3 / §6.2 / §7, AUTH_SPEC §13-11
// — 2026-09-19 DK K4. Design doc dk-design.md §9).
// Device ops are signed / verified with real crypto; the server is a wire-level mock.
//
// Pinned properties:
//  4. `device revoke` settles by FP, and the last device cannot be revoked (last-device-protected)

import { verifyChainWithHistory } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import type { VerifiedProject } from "../src/chain-sync.ts";
import { runCli } from "../src/cli.ts";
import { rotationMandates } from "../src/rotation-sweep.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
  rotateEpochOp,
} from "./support/crypto.ts";
import {
  ENV_ID,
  owner,
  dev2,
  reserve,
  dek,
  addDeviceOp,
  revokeDeviceOp,
  type ServerState,
  makeServer,
  startEnv,
  readOwnDevices,
  recordOwnDevice,
  chainWithEnvironment,
  registryRowOf,
} from "./support/device.ts";
import type { TestEnv } from "./support/env.ts";

describe("the sweep's fifth kind: the device-revoked obligation (rotation-sweep — K4-8)", () => {
  it("makes the obligation out of the revoked device's effective scope just before revocation (seq−1) — at seq the device is gone, so it must not collapse to ALL", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "owner", environmentIds: ["env-a"] }),
      },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const verified = await verifyChainWithHistory(built.entries);
    if (!verified.ok) throw new Error("chain");
    const view = {
      state: verified.value.state,
      history: verified.value.history,
      applied: built.entries.map((entry, index) => ({
        seq: index + 1,
        operation: { op: entry.op, payload: entry.payload },
        actorUserId: entry.actor.userId,
        viaProposalSeq: null,
      })),
    } as unknown as VerifiedProject;
    const mandates = rotationMandates(view);
    expect(mandates).toEqual([
      {
        kind: "device-revoked",
        target: owner.userId,
        seq: 5,
        environmentIds: ["env-a"],
        deviceFingerprintsHex: [dev2.fingerprintHex],
      },
    ]);
  });
  it("a partially converged obligation (env-a rotated · env-b not) still warns only env-b as unconverged on later syncs (carryover)", async () => {
    // Revoke dev2 (owner / all) → only env-a has rotated. env-b's obligation remains
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
      {
        actor: owner,
        operation: rotateEpochOp("env-a", 2, crypto.getRandomValues(new Uint8Array(32))),
      },
    ]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("there are unconverged rotation mandates");
    expect(errors).toMatch(
      new RegExp(`device-revoked \\(target=${owner.userId}, seq=5\\): environments env-b —`),
    );
    expect(errors).not.toMatch(/device-revoked[^\n]*environments env-a/);
  });
  it("when the revoked device's effective scope is outside the signing device's scope, that environment is not rotated and is noted as outOfScope", async () => {
    // Signing device dev2 = (owner, listed {}). Revocation target reserve =
    // (owner, all) → obligations env-a / env-b are both outside dev2's scope =
    // cannot rotate (note it and defer to the standing warning)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      { actor: owner, operation: addDeviceOp(dev2, { roleCap: "owner", environmentIds: [] }) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(
      await runCli(["device", "revoke", reserve.fingerprintHex, "--yes"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended.map((entry) => entry.op)).toEqual(["revoke_device"]);
    expect(env.errors.join("\n")).toContain(
      "2 environments with a pending rotation mandate are outside your scope and cannot be rotated by you (env-a, env-b)",
    );
  });
});

describe("maruhi device revoke", () => {
  it("a post-acceptance sweep failure still treats the revocation as successful and never skips the local-record / registry follow-up", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    // The environment's rotation answers 404 while the chain shows it live → the post-acceptance sweep fails
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      environmentsStatus: 500,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "laptop",
          createdAtMs: Date.now(),
        },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "revoke", dev2.fingerprintHex, "--yes"], env.layer)).toBe(1);
    expect(state.appended.map((entry) => entry.op)).toEqual(["revoke_device"]);
    expect(env.logs.join("\n")).toContain(`revoked ${dev2.fingerprintHex}`);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`rotation of environment ${ENV_ID} failed`);
    expect(errors).not.toContain(": revocation failed —");
    // The follow-up runs: the local record is revoked, the registry row is deleted
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === dev2.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    expect(state.registryDeletes).toEqual([dev2.fingerprintHex]);
  });

  it("settles by FP prefix, appends revoke_device, and reflects it in the local record and the registry (--yes)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "old-laptop",
          createdAtMs: 1,
        },
      ],
      tokensStatus: 403,
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved");
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex.slice(0, 8), "--yes"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.appended[0]?.op).toBe("revoke_device");
    expect(state.appended[0]?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [dev2.fingerprintHex],
    });
    expect(state.registryDeletes).toEqual([dev2.fingerprintHex]);
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === dev2.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const logs = env.logs.join("\n");
    expect(logs).toContain(`revoke  ${dev2.fingerprintHex} (cap owner/all)`);
    expect(logs).toContain(`${built.projectId}: revoked ${dev2.fingerprintHex}`);
    // If the token inventory cannot be read, just convey the fact (K4-13)
    expect(env.errors).toEqual(
      expect.arrayContaining([
        "Note: revoking a device does not revoke its API token (AUTH_SPEC §6). This token cannot list tokens; revoke the lost device's token from the web dashboard or with an admin token (`maruhi token revoke <id>`)",
      ]),
    );
    expect(env.prompts).toEqual([]);
  });

  it("the device can also be referenced by the registry display name; the confirmation table shows the FP alongside and waits for yes. Anything but yes sends nothing", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "old-laptop",
          createdAtMs: 1,
        },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    env.setPromptResponses(["no"]);
    expect(await runCli(["device", "revoke", "old-laptop"], env.layer), env.errors.join("\n")).toBe(
      1,
    );
    expect(env.logs.join("\n")).toContain(
      `revoke  ${dev2.fingerprintHex} (cap owner/all) — matched registry label "old-laptop"`,
    );
    expect(env.errors.join("\n")).toContain("Cancelled: nothing was revoked");
    expect(state.appended).toEqual([]);
  });

  it("the last device cannot be revoked (last-device-protected). A short prefix is a usage error", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "revoke", owner.fingerprintHex, "--yes"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "it would revoke the last device (last-device-protected",
    );
    expect(state.appended).toEqual([]);
    expect(await runCli(["device", "revoke", "abc", "--yes"], env.layer)).toBe(2);
  });
});

/** One row of the token inventory (the `GET /auth/tokens` response — K4-13's match target). */
function tokenRow(id: string, name: string): Record<string, unknown> {
  return {
    id,
    name,
    tokenPrefix: "maruhi_pat_Xy",
    scopes: [{ project: "*", permission: "admin" }],
    createdAtMs: 1,
    lastUsedAtMs: null,
    // 2026-01-01 00:00 UTC
    expiresAtMs: 1_767_225_600_000,
  };
}

describe("maruhi device revoke — the token-revocation proposal (K4-13)", () => {
  /** Prepare a chain · registry · local record holding dev2 as a registered device. */
  async function setup(input: {
    readonly registryTokenId?: string;
    readonly tokens: readonly Record<string, unknown>[];
    readonly tokenRevokeStatus?: number;
  }): Promise<{ state: ServerState; env: TestEnv }> {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "old-laptop",
          createdAtMs: 1,
          ...(input.registryTokenId === undefined ? {} : { tokenId: input.registryTokenId }),
        },
      ],
      tokens: input.tokens,
      ...(input.tokenRevokeStatus === undefined
        ? {}
        : { tokenRevokeStatus: input.tokenRevokeStatus }),
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved");
    return { state, env };
  }

  it("matches by the registry's tokenId; with only --yes it issues the proposal and sends no revocation", async () => {
    const { state, env } = await setup({
      registryTokenId: "tok_lost",
      // Even when the name is cli:<label>, a row with a tokenId is matched by tokenId alone
      tokens: [tokenRow("tok_lost", "ci"), tokenRow("tok_other", "cli:old-laptop")],
    });
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex, "--yes"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "The revoked devices' API tokens are still valid (the match is server-reported): tok_lost (ci, expires 2026-01-01 00:00 UTC)",
    );
    expect(logs).not.toContain("tok_other");
    expect(env.errors.join("\n")).toContain("tokens were left as they are");
    expect(state.tokenRevokes).toEqual([]);
    expect(env.prompts).toEqual([]);
  });

  it("when the registry row has no tokenId, matches by the name cli:<label>", async () => {
    const { state, env } = await setup({
      tokens: [tokenRow("tok_named", "cli:old-laptop"), tokenRow("tok_other", "cli:desktop")],
    });
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex, "--yes", "--revoke-token"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "tok_named (cli:old-laptop, expires 2026-01-01 00:00 UTC)",
    );
    expect(env.logs.join("\n")).not.toContain("tok_other");
    expect(state.tokenRevokes).toEqual(["tok_named"]);
  });

  it("--revoke-token sends the matched token's revocation and reports it", async () => {
    const { state, env } = await setup({
      registryTokenId: "tok_lost",
      tokens: [tokenRow("tok_lost", "cli:old-laptop")],
    });
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex, "--yes", "--revoke-token"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.tokenRevokes).toEqual(["tok_lost"]);
    expect(env.logs.join("\n")).toContain(
      "Revoked token tok_lost (cli:old-laptop, expires 2026-01-01 00:00 UTC)",
    );
    expect(env.errors.join("\n")).not.toContain("tokens were left as they are");
  });

  it("interactively, after the revocation confirmation it asks about token revocation; yes sends it", async () => {
    const { state, env } = await setup({
      registryTokenId: "tok_lost",
      tokens: [tokenRow("tok_lost", "cli:old-laptop")],
    });
    env.setPromptResponses(["yes", "yes"]);
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.prompts).toEqual(["Type yes to revoke: ", "Revoke these tokens too? Type yes: "]);
    expect(state.appended.map((entry) => entry.op)).toEqual(["revoke_device"]);
    expect(state.tokenRevokes).toEqual(["tok_lost"]);
  });

  it("declining token revocation interactively sends nothing and guides the later-revocation procedure (the device revocation stays)", async () => {
    const { state, env } = await setup({
      registryTokenId: "tok_lost",
      tokens: [tokenRow("tok_lost", "cli:old-laptop")],
    });
    env.setPromptResponses(["yes", "no"]);
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended.map((entry) => entry.op)).toEqual(["revoke_device"]);
    expect(state.tokenRevokes).toEqual([]);
    expect(env.errors.join("\n")).toContain("revoke them later with `maruhi token revoke <id>`");
  });

  it("a revocation send returning TokenNotFound (already revoked) is not a failure", async () => {
    const { state, env } = await setup({
      registryTokenId: "tok_lost",
      tokens: [tokenRow("tok_lost", "cli:old-laptop")],
      tokenRevokeStatus: 404,
    });
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex, "--yes", "--revoke-token"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.tokenRevokes).toEqual(["tok_lost"]);
  });

  it("when no token can be matched, guides toward token list", async () => {
    const { state, env } = await setup({
      tokens: [tokenRow("tok_other", "cli:desktop")],
    });
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex, "--yes", "--revoke-token"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain("No token could be matched to the revoked devices");
    expect(state.tokenRevokes).toEqual([]);
  });
});

describe("everyday commands on a revoked key, and device list (DK K13-5 / K13-6)", () => {
  /** Revoked on P1, valid on P2 (revocation on only some projects). The key at hand is dev2. */
  async function partlyRevoked(): Promise<{
    readonly env: TestEnv;
    readonly p1: BuiltChain;
    readonly p2: BuiltChain;
  }> {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const p2 = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({ built: p1, withEnvironment: true, extraProjects: [p2] });
    const env = await startEnv(server.origin, p1.projectId, dev2);
    return { env, p1, p2 };
  }

  it("a key revoked on this project gets re-adding (a new key) plus cleanup of the remaining projects — not the unregistered path", async () => {
    const { env } = await partlyRevoked();
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `The key on this machine (${dev2.fingerprintHex}) was revoked on this project's chain (member ${owner.userId}), and a revoked key is never registered again. To use this machine here again, run \`maruhi device add --replace\` on this machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device. If this key is still registered on other projects of yours, revoke it there once the new key is approved (\`maruhi device list\` shows where it is still registered)`,
    );
    expect(errors).not.toContain("has not been registered here yet");
    expect(errors).not.toContain("If `maruhi device add` is still waiting on this machine");
  });

  it("an unregistered key that is not revoked takes the conventional path, without the false option 'or it was revoked'", async () => {
    const built = await chainWithEnvironment();
    const { server } = await makeServer({ built, withEnvironment: true });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "is not one of your active device keys on this project's chain (member user-owner-0001). This device has not been registered here yet. If `maruhi device add` is still waiting on this machine",
    );
    expect(errors).not.toContain("or it was revoked");
    expect(errors).not.toContain("was revoked on this project's chain");
  });

  it("device list marks the revoked project in a row and answers the delegated question (where does the key remain)", async () => {
    const { env, p1, p2 } = await partlyRevoked();
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`${dev2.fingerprintHex}\tthis machine`);
    expect(logs).toContain(`  ${p1.projectId}: revoked (a revoked key is never registered again)`);
    expect(logs).toContain(
      `  ${p2.projectId}: cap=owner/all seq=2 added by ${reserve.fingerprintHex}`,
    );
  });

  it("device list also shows this device's key that is on no chain, and with --project it states the range displayed", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `${dev2.fingerprintHex}\tthis machine\n  (not on any synced project chain)`,
    );
    env.logs.length = 0;
    expect(
      await runCli(["device", "list", "--project", built.projectId], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `${dev2.fingerprintHex}\tthis machine\n  (not on the chain of project ${built.projectId}, the only project shown)`,
    );
  });

  it("device list never says 'absent' for a project that could not be synced (K13-16)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      brokenProjects: [{ built: down, mode: "unavailable" }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `${dev2.fingerprintHex}\tthis machine\n  (not on any synced project chain; 1 project could not be synced)`,
    );
    env.logs.length = 0;
    expect(
      await runCli(["device", "list", "--project", down.projectId], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `${dev2.fingerprintHex}\tthis machine\n  (project ${down.projectId} could not be synced, so whether this key is on its chain is unknown)`,
    );
    expect(logs).not.toContain("the only project shown");
  });

  it("device list does not fail when the project list cannot be fetched — it shows the registry and the record", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      projectsStatus: 500,
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain("Note: your projects could not be listed (");
    expect(env.logs.join("\n")).toContain(
      `${dev2.fingerprintHex}\tthis machine, label "laptop" (server-reported)`,
    );
  });
});
