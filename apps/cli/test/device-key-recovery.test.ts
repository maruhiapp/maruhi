import { encodeHex, wrapMasterSecret } from "@maruhi/crypto";
import { Redacted } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { serializeStoredMasterKey } from "../src/keychain.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
  type TestUser,
} from "./support/crypto.ts";
import {
  ENV_ID,
  owner,
  dev2,
  reserve,
  member,
  dek,
  addDeviceOp,
  revokeDeviceOp,
  type ServerState,
  makeServer,
  startEnv,
  readOwnDevices,
  recordOwnDevice,
  startEnvWithoutKey,
} from "./support/device.ts";
import type { TestEnv } from "./support/env.ts";
import { ledgerHandlerFor, storedMasterRecord, storedReserveRecord } from "./support/ledger.ts";
import { type MockHandler, onRequest } from "./support/server.ts";

async function reserveRotateFixture(options: {
  readonly withEnvironment: boolean;
  readonly dekRegisterStatus?: number;
  readonly retiringOnChain?: boolean;
}): Promise<{
  readonly env: TestEnv;
  readonly state: ServerState;
  readonly origin: string;
  readonly ledgerPuts: unknown[];
  readonly built: BuiltChain;
}> {
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    ...(options.withEnvironment
      ? [{ actor: owner, operation: createEnvironmentOp(ENV_ID, dek) }]
      : []),
    ...(options.retiringOnChain === false
      ? []
      : [
          { actor: owner, operation: addDeviceOp(dev2) },
          { actor: owner, operation: addDeviceOp(reserve) },
        ]),
  ]);
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: owner.userId,
    masterSecretBlob: new TextEncoder().encode(
      serializeStoredMasterKey(storedReserveRecord(reserve)),
    ),
  });
  if (!wrapped.ok) throw new Error("wrap");
  const ledgerPuts: unknown[] = [];
  const { server, state } = await makeServer({
    built,
    withEnvironment: options.withEnvironment,
    ...(options.dekRegisterStatus === undefined
      ? {}
      : { dekRegisterStatus: options.dekRegisterStatus }),
    extra: [
      onRequest("GET", "/auth/recovery", () => ({
        status: 200,
        json: {
          suite: "maruhi/v1",
          nonceHex: encodeHex(wrapped.value.nonce),
          ciphertextHex: encodeHex(wrapped.value.ciphertext),
          updatedAtMs: 1754006400000,
        },
      })),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
      onRequest("PUT", "/auth/recovery", (request) => {
        ledgerPuts.push(request.body);
        return { status: 204 };
      }),
      onRequest("GET", "/auth/key-wraps", () => ({
        status: 200,
        json: {
          recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
          passkeys: [],
          guardianGroups: [],
        },
      })),
    ],
  });
  const env = await startEnv(server.origin, built.projectId, owner);
  await recordOwnDevice(env, server.origin, dev2, "reserve", 1_700_000_001_000);
  await recordOwnDevice(env, server.origin, reserve, "reserve");
  env.setPromptResponses([
    Redacted.value(formatRecoveryCode(Redacted.make(secret))),
    () => {
      const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
      const groups = (line ?? "").trim().split("-");
      return groups[groups.length - 1] ?? "";
    },
  ]);
  return { env, state, origin: server.origin, ledgerPuts, built };
}

describe("maruhi key reserve rotate (re-run — a Bugbot find)", () => {
  it("even if the previous run interrupted at the ledger swap, it revokes the record's old reserve keys together", async () => {
    const { env, state, origin, ledgerPuts } = await reserveRotateFixture({
      withEnvironment: false,
    });
    expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
    expect(ledgerPuts).toHaveLength(1);
    const revoke = state.appended.find((entry) => entry.op === "revoke_device");
    expect(revoke?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [dev2.fingerprintHex, reserve.fingerprintHex].toSorted(),
    });
    const added = state.appended.find((entry) => entry.op === "add_device");
    expect(added).toBeDefined();
    expect(env.logs.join("\n")).toContain(
      `revoking the previous reserve keys ${[dev2.fingerprintHex, reserve.fingerprintHex].toSorted().join(", ")} on the 1 project the server lists for you`,
    );
    const recorded = await readOwnDevices(env, origin);
    const active = recorded.filter((row) => row.source === "reserve" && row.revokedAtMs === null);
    expect(active).toHaveLength(1);
    expect([dev2.fingerprintHex, reserve.fingerprintHex]).not.toContain(
      active[0]?.keyFingerprintHex,
    );
    const keychain = [...env.keychain.values()].join("\n");
    expect(keychain).not.toContain(reserve.encSkHex);
    expect(keychain).toContain(owner.encPubHex);
  });

  it("reports a backfill failure to the new reserve key and names the pull path specifically (DK K11's G9)", async () => {
    const { env, built } = await reserveRotateFixture({
      withEnvironment: true,
      dekRegisterStatus: 500,
      retiringOnChain: false,
    });
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `${built.projectId}: backfill of environment ${ENV_ID} to the new reserve key failed (`,
    );
    expect(errors).toContain(
      `fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
  });
});

describe("maruhi key recovery --replace (replace without opening the ledger — K4-38)", () => {
  it("revokes the old reserve key in the record on every project and registers the new reserve key", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const ledgerPuts: unknown[] = [];
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("GET", "/auth/recovery/status", () => ({
          status: 200,
          json: { registered: true, updatedAtMs: 1754006400000 },
        })),
        onRequest("PUT", "/auth/recovery", (request) => {
          ledgerPuts.push(request.body);
          return { status: 204 };
        }),
        onRequest("GET", "/auth/key-wraps", () => ({
          status: 200,
          json: {
            recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
            passkeys: [],
            guardianGroups: [],
          },
        })),
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, reserve, "reserve");
    env.setPromptResponses([
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);
    expect(await runCli(["key", "recovery", "--replace"], env.layer), env.errors.join("\n")).toBe(
      0,
    );
    expect(state.paths()).not.toContain("GET /auth/recovery");
    expect(ledgerPuts).toHaveLength(1);
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device", "revoke_device"]);
    expect(state.appended[1]?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [reserve.fingerprintHex],
    });
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === reserve.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const active = recorded.filter((row) => row.source === "reserve" && row.revokedAtMs === null);
    expect(active).toHaveLength(1);
    expect(active[0]?.keyFingerprintHex).not.toBe(reserve.fingerprintHex);
    const keychain = [...env.keychain.values()].join("\n");
    expect(keychain).not.toContain(reserve.encSkHex);
    expect(keychain).toContain(owner.encPubHex);
  });
});

describe("maruhi key recover / key recovery — the on-chain judgment of the ledger key (DK K14)", () => {
  const CODE_PROMPT = "Enter your recovery code: ";

  async function recoverFixture(input: {
    readonly ledgerKey: TestUser;
    readonly built: BuiltChain;
    readonly extraProjects?: readonly BuiltChain[];
    readonly brokenProjects?: readonly {
      readonly built: BuiltChain;
      readonly mode: "unavailable";
    }[];
    readonly answers?: readonly string[];
    readonly unlistedProjects?: readonly BuiltChain[];
  }): Promise<{ env: TestEnv; state: ServerState; origin: string }> {
    const ledger = await ledgerHandlerFor(
      ledgerRecordOf(input.ledgerKey),
      owner.userId,
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const { server, state } = await makeServer({
      built: input.built,
      withEnvironment: false,
      extra: [ledger.handler],
      ...(input.extraProjects === undefined ? {} : { extraProjects: input.extraProjects }),
      ...(input.brokenProjects === undefined ? {} : { brokenProjects: input.brokenProjects }),
      ...(input.unlistedProjects === undefined ? {} : { unlistedProjects: input.unlistedProjects }),
    });
    const env = await startEnvWithoutKey(server.origin, input.built.projectId);
    env.setPromptResponses([ledger.code, ...(input.answers ?? [])]);
    return { env, state, origin: server.origin };
  }

  async function recoveryFixture(input: {
    readonly device: TestUser;
    readonly ledgerKey: TestUser;
    readonly built: BuiltChain;
    readonly extraProjects?: readonly BuiltChain[];
    readonly brokenProjects?: readonly {
      readonly built: BuiltChain;
      readonly mode: "unavailable";
    }[];
    readonly unlistedProjects?: readonly BuiltChain[];
    readonly projectsStatus?: number;
    readonly extra?: readonly MockHandler[];
  }): Promise<{ env: TestEnv; state: ServerState; origin: string; ledgerPuts: unknown[] }> {
    const ledger = await ledgerHandlerFor(
      ledgerRecordOf(input.ledgerKey),
      owner.userId,
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const ledgerPuts: unknown[] = [];
    const { server, state } = await makeServer({
      built: input.built,
      withEnvironment: false,
      extra: [
        ledger.handler,
        onRequest("GET", "/auth/recovery/status", () => ({
          status: 200,
          json: { registered: true, updatedAtMs: 1754006400000 },
        })),
        onRequest("PUT", "/auth/recovery", (request) => {
          ledgerPuts.push(request.body);
          return { status: 204 };
        }),
        onRequest("GET", "/auth/key-wraps", () => ({
          status: 200,
          json: {
            recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
            passkeys: [],
            guardianGroups: [],
          },
        })),
        ...(input.extra ?? []),
      ],
      ...(input.extraProjects === undefined ? {} : { extraProjects: input.extraProjects }),
      ...(input.brokenProjects === undefined ? {} : { brokenProjects: input.brokenProjects }),
      ...(input.unlistedProjects === undefined ? {} : { unlistedProjects: input.unlistedProjects }),
      ...(input.projectsStatus === undefined ? {} : { projectsStatus: input.projectsStatus }),
    });
    const env = await startEnv(server.origin, input.built.projectId, input.device);
    env.setPromptResponses([
      ledger.code,
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);
    return { env, state, origin: server.origin, ledgerPuts };
  }

  function ledgerRecordOf(ledgerKey: TestUser) {
    return ledgerKey === reserve ? storedReserveRecord(reserve) : storedMasterRecord(ledgerKey);
  }

  async function reserveRowsOf(env: TestEnv, origin: string): Promise<readonly string[]> {
    return (await readOwnDevices(env, origin))
      .filter((row) => row.source === "reserve" && row.revokedAtMs === null)
      .map((row) => row.keyFingerprintHex);
  }

  it("a key bearing the reserve-key mark and no stopping fact is recorded as a reserve key without asking (DK K16-3 / K16-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env, state, origin } = await recoverFixture({ ledgerKey: reserve, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    expect(env.errors.join("\n")).toContain(
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
    expect(state.appended[0]?.actor.keyFingerprintHex).toBe(reserve.fingerprintHex);
  });

  it("a key without the reserve-key mark is not recorded as a reserve key, even if add_device-issued everywhere (DK K16-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, state, origin } = await recoverFixture({ ledgerKey: dev2, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    expect(env.errors.join("\n")).toContain(
      `Warning: the opened key ${dev2.fingerprintHex} was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one), so it is not used as your reserve key, and it was not recorded as one. Run \`maruhi key recovery\`: it seals a reserve key in its place`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
  });

  it("a key bearing the reserve-key mark is recorded even with an unsyncable project (DK K16-6 — it cannot be a device key)", async () => {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const p2 = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { env, origin } = await recoverFixture({
      ledgerKey: reserve,
      built: p1,
      brokenProjects: [{ built: p2, mode: "unavailable" }],
    });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    expect(env.errors.join("\n")).toContain(
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
  });

  it("a key bearing the reserve-key mark is recorded even when on no chain, and projects it could not be registered on get re-invite guidance (DK K16-6)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { env, state, origin } = await recoverFixture({ ledgerKey: reserve, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `${built.projectId}: the opened key is not registered on this project, so this device could not be added there`,
    );
    expect(errors).toContain(
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
    expect(state.appended).toEqual([]);
  });

  it("a revoked key is not recorded; the revoked projects are named specifically, and it registers where still valid", async () => {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: owner, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const p2 = await buildChain([
      { actor: dev2, operation: genesisOp(dev2) },
      { actor: dev2, operation: addDeviceOp(reserve) },
    ]);
    const { env, state, origin } = await recoverFixture({
      ledgerKey: reserve,
      built: p1,
      extraProjects: [p2],
    });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `${p1.projectId}: the opened key was revoked on this project, so this device could not be added there`,
    );
    expect(errors).toContain(
      `the opened key ${reserve.fingerprintHex} is revoked on 1 project (${p1.projectId}), so it was not recorded as your reserve key. Run \`maruhi key recovery\`: it seals a new reserve key in its place`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
    expect(state.appendedTo.map((row) => [row.projectId, row.entry.op])).toEqual([
      [p2.projectId, "add_device"],
    ]);
  });

  it("the non-interactive refusal is unchanged: stops before taking the ledger, asks nothing, appends nothing", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env, state } = await recoverFixture({ ledgerKey: reserve, built, answers: ["yes"] });
    env.setTerminal({ stdin: false, stdout: true, stderr: true });
    expect(await runCli(["key", "recover"], env.layer)).toBe(1);
    expect(env.prompts).toEqual([]);
    expect(state.paths()).not.toContain("GET /auth/recovery");
    expect(state.appended).toEqual([]);
  });

  it("correcting a wrong row: with an unsyncable project it never says 'nowhere' and never touches the row (K14-19)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
    ]);
    const broken = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { env, origin } = await recoveryFixture({
      device: dev2,
      ledgerKey: owner,
      built,
      brokenProjects: [{ built: broken, mode: "unavailable" }],
    });
    await recordOwnDevice(env, origin, owner, "reserve");
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).not.toContain("is registered nowhere now");
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === owner.fingerprintHex,
    );
    expect(row?.revokedAtMs).toBeNull();
  });

  it("key recovery: a revoked reserve key (not the first key) is segregated and not re-issued", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: dev2, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const { env, origin } = await recoveryFixture({ device: dev2, ledgerKey: reserve, built });
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `The recovery ledger holds key ${reserve.fingerprintHex}, which is revoked on 1 project (${built.projectId}), so it cannot serve as your reserve key. Creating a new reserve key and sealing it instead`,
    );
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("is still registered on");
    expect(errors).not.toContain("reissued the recovery code for your reserve key");
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(reserve.fingerprintHex);
  });

  it("key recovery: a ledger key revoked on only some projects is segregated, and it guides toward revoking where still valid", async () => {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: dev2, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const p3 = await buildChain([
      { actor: dev2, operation: genesisOp(dev2) },
      { actor: dev2, operation: addDeviceOp(reserve) },
    ]);
    const { env } = await recoveryFixture({
      device: dev2,
      ledgerKey: reserve,
      built: p1,
      extraProjects: [p3],
    });
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `The recovery ledger holds key ${reserve.fingerprintHex}, which is revoked on 1 project (${p1.projectId}), so it cannot serve as your reserve key`,
    );
    expect(env.errors.join("\n")).toContain(
      `Note: the key ${reserve.fingerprintHex} is still registered on 1 project (${p3.projectId}); revoke it there too: \`maruhi device revoke ${reserve.fingerprintHex}\``,
    );
  });

  it("key recovery: once a revoked reserve key is segregated, mark this device's old reserve row as revoked (K14-4 4-g — pullfrog's information find)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: owner, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const { env, origin } = await recoveryFixture({ device: owner, ledgerKey: reserve, built });
    await recordOwnDevice(env, origin, reserve, "reserve");
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Note: this machine had recorded ${reserve.fingerprintHex} as your reserve key; it is revoked, so the record now says so`,
    );
    const old = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === reserve.fingerprintHex,
    );
    expect(old?.revokedAtMs).not.toBeNull();
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(reserve.fingerprintHex);
  });

  it("rotate: a ledger key bearing the reserve-key mark is replaced and revoked even with unverifiable projects (DK K16-6 — revisiting K14-15)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const broken = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { env, state, ledgerPuts } = await recoveryFixture({
      device: owner,
      ledgerKey: reserve,
      built,
      brokenProjects: [{ built: broken, mode: "unavailable" }],
    });
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Refused to change anything");
    expect(env.errors.join("\n")).toContain(
      `Note: 1 project (${broken.projectId}) could not be synced, so whether the key ${reserve.fingerprintHex} is revoked there was not checked`,
    );
    expect(ledgerPuts).toHaveLength(1);
    const revoked = state.appendedTo.flatMap(({ entry }) =>
      entry.op === "revoke_device" ? entry.payload.deviceFingerprintsHex : [],
    );
    expect(revoked).toEqual([reserve.fingerprintHex]);
  });

  it("key recovery: uses the reserve key even with unverifiable projects, and names that range in a Note (DK K16-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const broken = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { env } = await recoveryFixture({
      device: owner,
      ledgerKey: reserve,
      built,
      brokenProjects: [{ built: broken, mode: "unavailable" }],
    });
    await runCli(["key", "recovery"], env.layer);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: 1 project (${broken.projectId}) could not be synced, so whether the key ${reserve.fingerprintHex} is revoked there was not checked`,
    );
    expect(env.logs.join("\n")).not.toContain("cannot serve as your reserve key");
  });

  it("rotate: if the project list cannot be fetched, a Note says that no project was checked", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env } = await recoveryFixture({
      device: owner,
      ledgerKey: reserve,
      built,
      projectsStatus: 500,
    });
    await runCli(["key", "reserve", "rotate"], env.layer);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `, so whether the key ${reserve.fingerprintHex} is revoked on any of them was not checked`,
    );
    expect(errors).toContain("Note: your projects could not be listed (");
  });

  it("rotate: if every checked project syncs, no Note about an unchecked range is emitted", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env } = await recoveryFixture({ device: owner, ledgerKey: reserve, built });
    expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).not.toContain("was not checked");
  });

  it("rotate: a ledger key without the reserve-key mark stops changing nothing, even if add_device-issued everywhere on the chain (DK K16-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, state, origin, ledgerPuts } = await recoveryFixture({
      device: owner,
      ledgerKey: dev2,
      built,
    });
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `The recovery ledger holds key ${dev2.fingerprintHex}, which was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one), so it is not used as your reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`maruhi key reserve rotate\``,
    );
    expect(ledgerPuts).toEqual([]);
    expect(state.appendedTo).toEqual([]);
    expect(await reserveRowsOf(env, origin)).toEqual([]);
  });

  it("rotate: a revoked reserve key stops changing nothing, and this device's reserve row gets the revoked mark (DK K16)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: owner, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const { env, state, origin, ledgerPuts } = await recoveryFixture({
      device: owner,
      ledgerKey: reserve,
      built,
    });
    await recordOwnDevice(env, origin, reserve, "reserve");
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `The recovery ledger holds key ${reserve.fingerprintHex}, which is revoked on 1 project (${built.projectId}), so it cannot serve as your reserve key. Run \`maruhi key recovery\` first: it seals a new reserve key in its place. Then re-run \`maruhi key reserve rotate\``,
    );
    expect(errors).toContain(
      `Note: this machine had recorded ${reserve.fingerprintHex} as your reserve key; it is revoked, so the record now says so`,
    );
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === reserve.fingerprintHex,
    );
    expect(row?.revokedAtMs).not.toBeNull();
    expect(ledgerPuts).toEqual([]);
    expect(state.appendedTo).toEqual([]);
  });

  it("key recover: if this device recorded a revoked key as reserve, the row gets the revoked mark (DK K16)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: owner, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const { env, origin } = await recoverFixture({ ledgerKey: reserve, built });
    await recordOwnDevice(env, origin, reserve, "reserve");
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Note: this machine had recorded ${reserve.fingerprintHex} as your reserve key; it is revoked, so the record now says so`,
    );
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === reserve.fingerprintHex,
    );
    expect(row?.revokedAtMs).not.toBeNull();
  });

  it("key recovery: a reserve key whose provenance is add_device everywhere is re-sealed as before and the record is restored", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env, origin, ledgerPuts } = await recoveryFixture({
      device: owner,
      ledgerKey: reserve,
      built,
    });
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(ledgerPuts).toHaveLength(1);
    expect(env.errors.join("\n")).toContain(
      `reissued the recovery code for your reserve key (fingerprint ${reserve.fingerprintHex}); the previous code no longer works`,
    );
    expect(env.logs.join("\n")).not.toContain("Separating");
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
  });

  it("key recovery: a key bearing the reserve-key mark is re-sealed and recorded even with unverifiable projects (DK K16-6 — revisiting K14-13)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const broken = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { env, origin, ledgerPuts } = await recoveryFixture({
      device: owner,
      ledgerKey: reserve,
      built,
      brokenProjects: [{ built: broken, mode: "unavailable" }],
    });
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).not.toContain("could not check");
    expect(ledgerPuts).toHaveLength(1);
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
  });

  it("key recovery: a key without the reserve-key mark is segregated even if add_device-issued everywhere on the chain (DK K16-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, origin, ledgerPuts } = await recoveryFixture({
      device: owner,
      ledgerKey: dev2,
      built,
    });
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `The recovery ledger holds key ${dev2.fingerprintHex}, which was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one), so it is not used as your reserve key. Creating a reserve key and sealing it instead`,
    );
    expect(ledgerPuts).toHaveLength(1);
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(dev2.fingerprintHex);
  });
});
