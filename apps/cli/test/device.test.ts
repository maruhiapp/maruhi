// Integration tests for `maruhi device add / approve / list / revoke` and the
// first-sync device registration (CRYPTO_SPEC §3 / §6.2 / §7, AUTH_SPEC §13-11
// — 2026-09-19 DK K4. Design doc dk-design.md §9).
// Device ops are signed / verified with real crypto; the server is a wire-level mock.
//
// Pinned properties:
//  1. `device approve` puts the ceremony gate (TTY + non-agent) before fetching
//     the request list, and recomputes the FP from the request row's public key
//     to compare (the claimed FP is never used — K4-6). Approval is each
//     project's `add_device` + backfill + local record (approved) + the registry PUT
//  2. The first sync (the keyed prelude) appends only the local record's 3
//     provenances (reserve / approved / observed) to the chain, and never reads
//     or writes the registry (`GET /auth/devices`) (K4-3). A revoked record is
//     never appended. Devices observed on the chain are recorded with provenance (K4-4)
//  3. The expected count of the complete wrap set uses the same predicate as
//     the server (effective scope × devices, storage-key granularity)
//  4. `device revoke` settles by FP, and the last device cannot be revoked (last-device-protected)
//  5. `device add` refuses by default on a device that already has a key
//     (rebuild with `--replace` — K4-18); the signal of approval is the
//     registry, confirmation of completion is the chain (K4-5)
//  6. Approval over the old device path (`source: "device"`) is rejected by
//     the wire type (pinning the removal)

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  DEVICE_ADD_REQUEST_TTL_MS,
  HandoffApprovalSchema,
  HandoffLookupSchema,
} from "@maruhi/api-schema";
import {
  type ChainEntry,
  type ChainOperation,
  computeChainEntryHash,
  computeUserKeyFingerprint,
  encodeHex,
  fingerprintToWords,
  verifyChainWithHistory,
  wrapMasterSecret,
} from "@maruhi/crypto";
import { Effect, Exit, Redacted, Schema } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectedWrapRecipientCount } from "../src/dek-wrap.ts";
import { DEVICE_ADD_WAIT_HINT_AFTER_MS } from "../src/device.ts";
import { masterKeyEntryName, serializeStoredMasterKey, tokenEntryName } from "../src/keychain.ts";
import {
  makeFileOwnDeviceStore,
  type OwnDeviceEntry,
  type OwnDeviceSource,
  ownDevicesPathOf,
} from "../src/own-devices.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
import { rotationMandates } from "../src/rotation-sweep.ts";
import type { VerifiedProject } from "../src/sync.ts";
import { appendableProjectHandlers } from "./support/chain-handler.ts";
import {
  addMemberOp,
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  type TestUser,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { ledgerHandlerFor, storedMasterRecord, storedReserveRecord } from "./support/ledger.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app";
const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

let owner: TestUser;
/** owner's second device (the new device being approved / the device being revoked). */
let dev2: TestUser;
/** owner's reserve key (only the public side lands on the local record). */
let reserve: TestUser;
let member: TestUser;
let dek: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-0001");
  dev2 = await makeTestUser("user-owner-0001");
  reserve = await makeTestUser("user-owner-0001");
  member = await makeTestUser("user-member-0002");
  dek = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** `add_device` (cap-carrying — CRYPTO_SPEC §6.2). actor is a valid device of the same person. */
function addDeviceOp(
  device: TestUser,
  cap: { roleCap: "owner" | "admin" | "member" | "reader"; environmentIds?: readonly string[] } = {
    roleCap: "owner",
  },
): ChainOperation {
  return {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: cap.roleCap,
      scopeKind: cap.environmentIds === undefined ? "all" : "listed",
      scopeEnvironmentIds: cap.environmentIds === undefined ? [] : [...cap.environmentIds],
    },
  };
}

function revokeDeviceOp(target: TestUser, devices: readonly TestUser[]): ChainOperation {
  return {
    op: "revoke_device",
    payload: {
      targetUserId: target.userId,
      deviceFingerprintsHex: devices.map((device) => device.fingerprintHex).toSorted(),
    },
  };
}

interface ServerState {
  readonly handlers: MockHandler[];
  readonly appended: ChainEntry[];
  /** Appends to every project (including `extraProjects`) — with project ids. */
  readonly appendedTo: { readonly projectId: string; readonly entry: ChainEntry }[];
  readonly registered: { environmentId: string; deks: readonly Record<string, unknown>[] }[];
  readonly registry: {
    keyFingerprintHex: string;
    encPubHex: string;
    sigPubHex: string;
    label: string;
    createdAtMs: number;
    /** The issued token's id carried on the registry row (the match key for K4-13's token-revocation proposal). */
    tokenId?: string;
  }[];
  /** Token ids whose revocation was requested via `DELETE /auth/tokens/:tokenId` (in call order). */
  readonly tokenRevokes: string[];
  readonly registryPuts: { fp: string; body: Record<string, unknown> }[];
  readonly registryDeletes: string[];
  readonly requestCancels: string[];
  readonly paths: () => readonly string[];
}

/**
 * A mock of the chain (appendable) + one environment (an epoch-1 wrap for
 * owner) + the device registry + the request list + the project list.
 */
async function makeServer(input: {
  readonly built: BuiltChain;
  readonly withEnvironment: boolean;
  readonly requests?: readonly Record<string, unknown>[];
  readonly registryRows?: readonly ServerState["registry"][number][];
  readonly tokensStatus?: number;
  /** The token rows `GET /auth/tokens` returns (default: empty — `tokensStatus` 403 takes precedence). */
  readonly tokens?: readonly Record<string, unknown>[];
  /** The response code of `DELETE /auth/tokens/:tokenId` (default 204. 404 = TokenNotFound). */
  readonly tokenRevokeStatus?: number;
  /** Extra handlers (MockServer copies the list at startup, so they cannot be pushed later). */
  readonly extra?: readonly MockHandler[];
  /** The environment-list GET's response code (default 200. 500 = fails the post-acceptance sweep). */
  readonly environmentsStatus?: number;
  /**
   * The registry PUT's response codes in call order (429 = the row cap, 500 =
   * a transient failure). Once exhausted, 204 (DK K9-1: the re-run after a failed attempt succeeds).
   */
  readonly registryPutStatuses?: readonly number[];
  /**
   * The `POST /auth/devices/requests` response: the deadline, and whether to
   * raise the signal (the registry row) immediately. Setting `conflict`
   * returns 409 (after the signal was raised).
   */
  readonly requestCreate?: {
    readonly expiresAtMs: number;
    readonly signal: boolean;
    readonly conflict?: "request-exists" | "device-registered";
  };
  /** Other projects the same person belongs to (serves only the chain GET / append and an empty environment list — DK K10). */
  readonly extraProjects?: readonly BuiltChain[];
  /** The DEK-wrap registration (POST) response code (default 204. 500 = the backfill failure — DK K11). */
  readonly dekRegisterStatus?: number;
  /**
   * The response of the GET for DEKs addressed to self (default: 1 row of
   * epoch 1 for owner). Setting `status` fails it with that code (DK K12 —
   * the check that the new device's keys arrived).
   */
  readonly listMine?:
    | { readonly rows: readonly Record<string, unknown>[] }
    | { readonly status: number };
  /** The live request `GET /auth/devices/requests/:fp` returns (the one whose FP matches — default 404). */
  readonly pendingRequests?: readonly Record<string, unknown>[];
  /** The project-list GET's response code (default 200 — DK K13's list failure). */
  readonly projectsStatus?: number;
  /**
   * Projects on the list that cannot be synced (DK K13-3): `unavailable` =
   * the chain GET is 500; `tampered` = the head claim disagrees with the
   * entries (a verification contradiction — `evidence`).
   */
  readonly brokenProjects?: readonly {
    readonly built: BuiltChain;
    readonly mode: "unavailable" | "tampered";
  }[];
  /**
   * Projects the server hides from the list (DK K15): it serves the chain
   * GET / append but does not list them on `GET /projects` (syncable when
   * named via `--project` — to assemble a device that synced before the hiding).
   */
  readonly unlistedProjects?: readonly BuiltChain[];
}): Promise<{ server: MockServer; state: ServerState }> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appended: ChainEntry[] = [];
  const appendedTo: ServerState["appendedTo"] = [];
  const registered: ServerState["registered"] = [];
  const registry: ServerState["registry"] = [...(input.registryRows ?? [])];
  const registryPuts: ServerState["registryPuts"] = [];
  const registryDeletes: string[] = [];
  const requestCancels: string[] = [];
  const tokenRevokes: string[] = [];
  const registryPutStatuses = [...(input.registryPutStatuses ?? [])];
  const ownWrap: WireRecipientDek | null = input.withEnvironment
    ? await wrapDekFor({
        projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek,
        recipient: owner,
        signer: owner,
      })
    : null;
  const envStatement = input.withEnvironment
    ? await environmentStatementFor({
        projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(input.built, 2),
      })
    : null;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appended.push(body.entry);
      appendedTo.push({ projectId, entry: body.entry });
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    onRequest("GET", `/projects/${projectId}/environments`, () =>
      input.environmentsStatus !== undefined && input.environmentsStatus !== 200
        ? { status: input.environmentsStatus, json: { _tag: "Internal" } }
        : {
            status: 200,
            json: {
              environments:
                envStatement === null
                  ? []
                  : [{ environmentId: ENV_ID, currentEpoch: 1, statement: envStatement }],
            },
          },
    ),
    (request: MockRequest) => {
      const base = `/projects/${projectId}/environments/${ENV_ID}/deks`;
      if (request.path !== base) {
        return null;
      }
      if (request.method === "GET") {
        return listMineResponse(input.listMine, ownWrap);
      }
      if (request.method === "POST") {
        if (input.dekRegisterStatus !== undefined) {
          return { status: input.dekRegisterStatus, json: { _tag: "Internal" } };
        }
        const body = request.body as { readonly deks: readonly Record<string, unknown>[] };
        registered.push({ environmentId: ENV_ID, deks: body.deks });
        return { status: 204 };
      }
      return null;
    },
    onRequest("GET", "/projects", () =>
      input.projectsStatus !== undefined && input.projectsStatus !== 200
        ? { status: input.projectsStatus, json: { _tag: "Internal" } }
        : {
            status: 200,
            json: {
              projects: [
                input.built,
                ...(input.extraProjects ?? []),
                ...(input.brokenProjects ?? []).map((broken) => broken.built),
              ].map((built) => ({ projectId: built.projectId, role: "owner" })),
            },
          },
    ),
    ...(input.brokenProjects ?? []).map((broken) =>
      onRequest("GET", `/projects/${broken.built.projectId}/chain`, () =>
        broken.mode === "unavailable"
          ? { status: 500, json: { _tag: "Internal" } }
          : {
              status: 200,
              json: {
                projectId: broken.built.projectId,
                entries: broken.built.entries,
                headSeq: broken.built.entries.length + 1,
                headHashHex: broken.built.hashes[broken.built.hashes.length - 1],
              },
            },
      ),
    ),
    ...[...(input.extraProjects ?? []), ...(input.unlistedProjects ?? [])].flatMap((built) =>
      appendableProjectHandlers(built, (entry) =>
        appendedTo.push({ projectId: built.projectId, entry }),
      ),
    ),
    onRequest("GET", "/auth/devices", () => ({ status: 200, json: { devices: registry } })),
    (request: MockRequest) => {
      const match = /^\/auth\/devices\/([0-9a-f]{32})$/.exec(request.path);
      if (match === null) {
        return null;
      }
      const fp = match[1] ?? "";
      if (request.method === "PUT") {
        registryPuts.push({ fp, body: request.body as Record<string, unknown> });
        const status = registryPutStatuses.shift() ?? 204;
        if (status === 429) {
          return {
            status,
            json: { _tag: "DeviceRegistryLimit", reason: "device-rows", limit: 32 },
          };
        }
        if (status !== 204) {
          return { status, json: { _tag: "Internal" } };
        }
        const body = request.body as { encPubHex: string; sigPubHex: string; label: string };
        registry.push({ keyFingerprintHex: fp, ...body, createdAtMs: Date.now() });
        return { status: 204 };
      }
      if (request.method === "DELETE") {
        registryDeletes.push(fp);
        return { status: 204 };
      }
      return null;
    },
    onRequest("GET", "/auth/devices/requests", () => ({
      status: 200,
      json: { requests: input.requests ?? [] },
    })),
    (request: MockRequest) => {
      const match = /^\/auth\/devices\/requests\/([0-9a-f]{32})$/.exec(request.path);
      if (match === null) {
        return null;
      }
      if (request.method === "DELETE") {
        requestCancels.push(match[1] ?? "");
        return { status: 204 };
      }
      const pending = input.pendingRequests?.find((row) => row["keyFingerprintHex"] === match[1]);
      return pending === undefined
        ? { status: 404, json: { _tag: "DeviceNotFound" } }
        : { status: 200, json: pending };
    },
    onRequest("GET", "/auth/tokens", () =>
      input.tokensStatus === 403
        ? { status: 403, json: { _tag: "Forbidden", reason: "insufficient-scope" } }
        : { status: 200, json: { tokens: input.tokens ?? [] } },
    ),
    (request: MockRequest) => {
      const match = /^\/auth\/tokens\/([^/]+)$/.exec(request.path);
      if (match === null || request.method !== "DELETE") {
        return null;
      }
      tokenRevokes.push(decodeURIComponent(match[1] ?? ""));
      const status = input.tokenRevokeStatus ?? 204;
      return status === 204
        ? { status }
        : { status, json: { _tag: status === 404 ? "TokenNotFound" : "Internal" } };
    },
    async (request: MockRequest) => {
      if (
        request.method !== "POST" ||
        request.path !== "/auth/devices/requests" ||
        input.requestCreate === undefined
      ) {
        return null;
      }
      const body = request.body as { encPubHex: string; sigPubHex: string; label: string };
      if (input.requestCreate.signal) {
        // In place of the registry PUT the approver does last: compute the FP from the request's public key and raise the signal
        const fp = await computeUserKeyFingerprint(
          hexBytes(body.encPubHex),
          hexBytes(body.sigPubHex),
        );
        if (!fp.ok) throw new Error("fp");
        registry.push({ keyFingerprintHex: encodeHex(fp.value), ...body, createdAtMs: Date.now() });
      }
      if (input.requestCreate.conflict !== undefined) {
        return {
          status: 409,
          json: { _tag: "DeviceRegistryConflict", reason: input.requestCreate.conflict },
        };
      }
      return { status: 200, json: { expiresAtMs: input.requestCreate.expiresAtMs } };
    },
    ...(input.extra ?? []),
  ];
  const server = await MockServer.start(handlers);
  servers.push(server);
  return {
    server,
    state: {
      handlers,
      appended,
      appendedTo,
      registered,
      registry,
      registryPuts,
      registryDeletes,
      requestCancels,
      tokenRevokes,
      paths: () => server.requests.map((request) => `${request.method} ${request.path}`),
    },
  };
}

/** The response of the GET for DEKs addressed to self (`makeServer`'s `listMine` — default 1 row of epoch 1 for owner). */
function listMineResponse(
  listMine:
    | { readonly rows: readonly Record<string, unknown>[] }
    | { readonly status: number }
    | undefined,
  ownWrap: WireRecipientDek | null,
): { status: number; json: unknown } {
  if (listMine === undefined) {
    return { status: 200, json: { deks: ownWrap === null ? [] : [ownWrap] } };
  }
  return "status" in listMine
    ? { status: listMine.status, json: { _tag: "Internal" } }
    : { status: 200, json: { deks: listMine.rows } };
}

/** An `add_device` append for a given device key (across all projects — with project id and cap role). */
function addsOf(
  state: ServerState,
  device: TestUser,
): { readonly projectId: string; readonly roleCap: string }[] {
  return state.appendedTo.flatMap(({ projectId, entry }) =>
    entry.op === "add_device" && entry.payload.encPubHex === device.encPubHex
      ? [{ projectId, roleCap: entry.payload.roleCap }]
      : [],
  );
}

async function startEnv(origin: string, projectId: string, user: TestUser): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, origin, user);
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}

function requestRowOf(device: TestUser, label = "laptop"): Record<string, unknown> {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label,
    expiresAtMs: FAR_FUTURE_MS,
  };
}

async function readOwnDevices(env: TestEnv, origin: string): Promise<readonly OwnDeviceEntry[]> {
  const store = makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath));
  const loaded = await Effect.runPromise(store.load(origin, owner.userId));
  return loaded.state === "loaded" ? loaded.devices : [];
}

async function recordOwnDevice(
  env: TestEnv,
  origin: string,
  device: TestUser,
  source: OwnDeviceSource,
  revokedAtMs: number | null = null,
  /** The observed project (the observation row — the shape the writer always writes. DK K15-6). */
  observedProjectId: string | null = null,
): Promise<void> {
  const store = makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath));
  await Effect.runPromise(
    store.record(origin, owner.userId, {
      keyFingerprintHex: device.fingerprintHex,
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: "owner",
      scope: { kind: "all" },
      source,
      label: source === "reserve" ? "reserve" : null,
      addedByFingerprintHex: null,
      observedProjectId,
      recordedAtMs: 1_700_000_000_000,
      revokedAtMs,
    }),
  );
}

/** The issuance POST of a command that passes through the keyed prelude (invite create). */
function inviteHandler(built: BuiltChain): MockHandler {
  return onRequest("POST", `/projects/${built.projectId}/invites`, () => ({
    status: 200,
    json: { expiresAtMs: FAR_FUTURE_MS },
  }));
}

async function chainWithEnvironment(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
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
    // The device lands on the chain and the later stages (record · registry · cancellation) run — pull fills the gap
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
    // owner's device signed and appended the add_device (default cap = owner / all)
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
    // Backfill: env-app's epoch 1 was registered addressed to the new device's enc key
    expect(state.registered).toHaveLength(1);
    expect(
      state.registered[0]?.deks.map((wrap) => [
        wrap["recipientUserId"],
        wrap["recipientEncPubHex"],
        wrap["epoch"],
      ]),
    ).toEqual([[owner.userId, dev2.encPubHex, 1]]);
    // The local record (approved — the approving device's FP is the provenance)
    const recorded = await readOwnDevices(env, server.origin);
    const row = recorded.find((candidate) => candidate.keyFingerprintHex === dev2.fingerprintHex);
    expect(row).toMatchObject({
      source: "approved",
      label: "laptop",
      addedByFingerprintHex: owner.fingerprintHex,
      revokedAtMs: null,
    });
    // The registry PUT (the signal — last) and the request's cancellation
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
    // The FP provenance rule (K7-7): right after the label / 12 words, one
    // sentence saying to compare it with the screen of the machine being
    // added (whoever can place a request holds an account-wide admin token — `ensureKeyMaterialAccess`)
    expect(approveLogs).toContain(
      "Compare them with the screen of the machine you are adding, never with a fingerprint sent to you: a request can be placed by anyone holding an account-wide admin API token of yours",
    );
    expect(approveLogs.indexOf("fp words:")).toBeLessThan(
      approveLogs.indexOf("Compare them with the screen"),
    );
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
    // Prefixes or 11 words are not accepted (§3's no-truncation rule)
    expect(await runCli(["device", "approve", dev2.fingerprintHex.slice(0, 16)], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain(
      "must be the full 32-character fingerprint or its 12 words",
    );
  });
  it("even when every project is skipped (this device unregistered, etc.), exit code is 1 and the request is kept", async () => {
    // session is member (not on the chain) → skipped on the only project
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
    // dev2 is a device key of the same person as owner, but is not on this project's chain
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
    // Never guides toward an unachievable procedure (request-less approval)
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
    // A scope naming a nonexistent environment → failed on the only project (a pre-communication check)
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--env", "env-missing"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not exist on this project's chain");
    expect(errors).toContain(
      "the device was not registered on any project, so nothing was recorded and the request was left in place",
    );
    expect(state.appended).toEqual([]);
    // Only the first-sync observation (this device) is recorded — no approved row is written
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
    // It did land on the chain, so it is not a failure (exit code 0 — K8-5 round 3)
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.registryPuts).toHaveLength(1);
    // The signal could not be raised, so its material (the request) is kept
    expect(state.requestCancels).toEqual([]);
    const note = env.errors.join("\n");
    expect(note).toContain("the device registry is full (32 rows)");
    // The two sentences docs (`devices.mdx`) quotes sit adjacent on both branches (PR #196 pullfrog)
    expect(note).toContain(
      "will not see the completion signal. The request is left in place until",
    );
    // The re-issue command carries the same cap (DK K10-1 — a flagless re-run is the default owner / all)
    expect(note).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap owner --all-envs\` before then to list it`,
    );
    expect(note).toContain("unlisted in your device registry");
    // The approver clears rows and re-runs: every project is already (no append) → PUT → cancellation
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
    // The state where the previous approval (member / env-app) left the request behind on a PUT failure or interruption
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
    // Flagless = the default owner / all (the person who typed the K9 Note flagless — the widening direction)
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Device ${dev2.fingerprintHex} is already registered with cap member/${ENV_ID} on ${built.projectId}, and this approval asks for owner/all: a device's cap is set when it is first approved and cannot be changed later, so this approval appended nothing, recorded nothing and left the request in place`,
    );
    expect(errors).toContain(
      `Re-run it with that cap: \`maruhi device approve ${dev2.fingerprintHex} --cap member --env ${ENV_ID}\`.`,
    );
    // The re-add procedure is spelled in one function (DK K12-7): a revoked key never comes back, so a new key + approval
    expect(errors).toContain(
      "To give the device another cap, revoke it, then run `maruhi device add --replace` on that machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device with the cap you want",
    );
    expect(errors).not.toContain("re-add it instead");
    expect(state.appendedTo).toEqual([]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
    // The record is not overwritten by the approval (the row stays as the sync observation wrote it with the chain's cap)
    const before = (await readOwnDevices(env, server.origin)).find(
      (row) => row.keyFingerprintHex === dev2.fingerprintHex,
    );
    expect(before).toMatchObject({ source: "observed", roleCap: "member" });
    // Re-issuing via the emitted command converges (already → record → PUT → cancellation)
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
    // Present on P1 as member / all. Absent on P2 (genesis's device differs = a different project id)
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
    // An add_device with this run's cap (owner / all) appears on no project
    // (the sync observation → registration may append to P2, but that uses the chain's cap = member)
    expect(addsOf(state, dev2).map((add) => add.roleCap)).not.toContain("owner");
    expect(
      (await readOwnDevices(env, server.origin)).find(
        (row) => row.keyFingerprintHex === dev2.fingerprintHex,
      )?.source,
    ).not.toBe("approved");
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
    // The same-cap re-issue lands as member on both projects and converges
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
    // dev2 is appended nowhere (the sync appending another device [genesis's reserve key] is a different path)
    expect(addsOf(state, dev2)).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });
});

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
    // Environment-list GET is 500 → the post-acceptance sweep (verifying the deleted environment) fails
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
    expect(errors).toContain("the rotation sweep after the revocation failed");
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
    expect(env.errors.join("\n")).toContain("revoking a device does not revoke its API token");
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
    expiresAtMs: null,
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
      "The revoked devices' API tokens are still valid (the match is server-reported): tok_lost (ci, expires never)",
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
    expect(env.logs.join("\n")).toContain("tok_named (cli:old-laptop, expires never)");
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
    expect(env.logs.join("\n")).toContain("Revoked token tok_lost (cli:old-laptop, expires never)");
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

describe("maruhi device add", () => {
  it("a device holding the first key is refused with a 2-way choice (no request is created); --replace swaps after the new key's request (K13-2 / K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    // The genesis key = the first key: the machine cannot tell this very device apart from a pre-DK replica (K13-2)
    expect(env.errors.join("\n")).toContain(
      `This machine's device key (${owner.fingerprintHex}) is your first key on ${built.projectId} (the key you created or joined that project with), and it has no pending device-add request. maruhi cannot tell whether this machine is the device that key belongs to or holds a copy of it from an install before device keys. If this machine is that device, nothing is needed: it is already registered. If it holds a copy, re-run with --replace: it generates a new key for this machine and prints its fingerprint to approve from a registered device (the machine the copy came from keeps its key). Do not pass --replace if this is your only device`,
    );
    // An existing key never goes to create a request (never spends the server's 5-per-hour window)
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );

    // --replace: show the discarded key's standing → generate a new key → request → swap → signal → confirm on the chain
    const before = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(
      await runCli(["device", "add", "--label", "phone", "--replace"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const after = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(after).toBeDefined();
    expect(after).not.toBe(before);
    const requestBody = server.requests.find(
      (request) => request.method === "POST" && request.path === "/auth/devices/requests",
    )?.body as { label: string; encPubHex: string } | undefined;
    expect(requestBody?.label).toBe("phone");
    expect(after).toContain(requestBody?.encPubHex ?? "never");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: replacing this machine's key ${owner.fingerprintHex}, which is registered on ${built.projectId} as your first key there. Once the new key is approved, revoke the previous key where it is still registered unless another machine holds it (\`maruhi device revoke ${owner.fingerprintHex}\` from a registered device)`,
    );
    expect(errors).toContain("replaced the previous key in this machine's keychain (--replace)");
    const logs = env.logs.join("\n");
    expect(logs).toContain("This device's key fingerprint:");
    expect(logs).toContain("fp words:");
    // The chain is the truth: sync after the signal and count the projects it has not landed on yet
    expect(logs).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain)",
    );
    // The shortfall guidance (K7-2): the approver's work is done · the request
    // is spent · registration happens on the next keyed command of a device
    // the cap covers (never says "re-run the approval" or "still working")
    const missingNote = env.errors.find((line) => line.includes("not registered yet on"));
    expect(missingNote).toContain(`not registered yet on ${built.projectId}`);
    expect(missingNote).toContain("skipped or failed on them");
    expect(missingNote).toContain("The request is used up");
    // The prelude is one command per project, so it is "a keyed command aimed at that project" (DK K10-5)
    expect(missingNote).toContain(
      "when it runs a keyed command on that project at a terminal (`maruhi pull --project <id>`, for instance)",
    );
    expect(missingNote).not.toContain("may still be working");
    expect(missingNote).not.toContain("Re-run `maruhi device approve`");
  });

  it("when resuming on a 409 request-exists and the request lookup fails, reports that failure (never misguides as 'revoked')", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => ({
          status: 409,
          json: { _tag: "DeviceRegistryConflict", reason: "request-exists" },
        })),
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // The default mock returns 404 for GET /auth/devices/requests/:fp
    expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("expired before this machine saw the completion signal");
    expect(errors).toContain("DeviceNotFound");
  });

  it("a new key's 409 device-registered (only possible on an FP collision) never waits, never claims 'Approved', and reports in terms of the chain's standing (K13-3 — hole-5 defense)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true, conflict: "device-registered" },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const logs = env.logs.join("\n");
    expect(logs).not.toContain("Approved:");
    expect(logs).not.toContain("The request expires at");
    expect(logs).not.toContain("Waiting for approval");
    expect(env.errors.join("\n")).not.toContain("still waiting (");
    // The new key is on no chain — it says 'nothing is lost' with the scope attached
    expect(env.errors.join("\n")).toContain(
      "has no pending device-add request and is on no project the server lists for you (1 listed), each chain synced and verified, so replacing it loses nothing there",
    );
    // Never goes to look up the request (the new key has no live request)
    expect(
      state.paths().some((path) => /^GET \/auth\/devices\/requests\/[0-9a-f]{32}$/.test(path)),
    ).toBe(false);
  });

  it("a registry row is never used to branch: even with a row, a first key stops at the 2-way choice, and 'in the registry' is not grounds to resume (K13-9)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(owner)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`is your first key on ${built.projectId}`);
    expect(errors).not.toContain("in your device registry — verifying it");
    expect(errors).not.toContain("resuming the wait for its approval");
    expect(env.logs.join("\n")).not.toContain("Approved:");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
  });

  it("when a third of the TTL has passed since the request's creation with no signal, emits 'check the approver's output' exactly once (K7-3)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // Pretend the request was created 6 minutes ago (deadline = creation + 15 min). No signal yet
    const requestedAtMs = Date.now() - DEVICE_ADD_WAIT_HINT_AFTER_MS - 60 * 1000;
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: requestedAtMs + DEVICE_ADD_REQUEST_TTL_MS, signal: false },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // After round 1 (no signal → guidance), place a row equivalent to the approver's PUT: round 2 picks up the signal
    const run = runCli(["device", "add", "--label", "phone"], env.layer);
    const rowPlaced = new Promise<void>((resolve) => {
      const tick = (): void => {
        const stored = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
        const hinted = env.errors.some((line) => line.includes("still waiting ("));
        if (stored !== undefined && hinted) {
          const record = JSON.parse(stored) as { encPubHex: string; sigPubHex: string };
          void computeUserKeyFingerprint(
            hexBytes(record.encPubHex),
            hexBytes(record.sigPubHex),
          ).then((fp) => {
            if (!fp.ok) throw new Error("fp");
            state.registry.push({
              keyFingerprintHex: encodeHex(fp.value),
              encPubHex: record.encPubHex,
              sigPubHex: record.sigPubHex,
              label: "phone",
              createdAtMs: Date.now(),
            });
            resolve();
          });
          return;
        }
        setTimeout(tick, 20);
      };
      tick();
    });
    await rowPlaced;
    expect(await run, env.errors.join("\n")).toBe(0);
    const hints = env.errors.filter((line) => line.includes("still waiting ("));
    expect(hints).toHaveLength(1);
    // Elapsed is measured for real (a resumed wait exceeds the threshold) — here threshold + 1 minute
    expect(hints[0]).toContain("6 minutes since the request");
    expect(hints[0]).toContain("this key is not in your device registry yet");
    expect(hints[0]).toContain(
      "failed on every project, or could not list this device in your device registry, the cause is in its output",
    );
    expect(env.logs.join("\n")).toContain("Approved: this device is registered on 0 projects");
  }, 15_000);

  it("when the request has expired, it ends with the TTL guidance (no signal)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: Date.now() - 1, signal: false },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const expired = env.errors.join("\n");
    expect(expired).toContain(
      "The device-add request expired before this machine saw the completion signal (requests live 15 minutes)",
    );
    // The guidance matches the implementation (K7-1): re-running is refused
    // (K4-21), so it guides toward `--replace` conditioned on the approver
    // having registered nothing. Never says "rebuild with the same key"
    expect(expired).toContain("if it registered nothing, run `maruhi device add --replace`");
    expect(expired).not.toContain("it reuses this key");
    // K9-3's T3: when the approver registered but could not get onto the
    // registry and nobody re-ran before the deadline, the key is on the chain
    // — carrying the branch that never lets `--replace` discard it
    expect(expired).toContain(
      "If it registered this device but could not list it in your device registry, keep this key",
    );
    // The chain's fact at this point (K13-4 — appended while keeping the conditions)
    expect(expired).toContain(
      "On the project chains right now, this key is on no project the server lists for you (1 listed). If the approving device is still working, re-running `maruhi device add` on this machine later shows whether it registered this key, without a new request",
    );
    // The key stays generated (it is discarded only when a human types `--replace`)
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeDefined();
  });
});

/**
 * Scaffolding for the new device dev2's `device add` re-run (the registry row
 * is the signal — no request): the chain is genesis → environment (epoch 1) →
 * rotate (epoch 2) → dev2's `add_device` (cap is an argument).
 * The key at hand is dev2. The response of the GET for DEKs addressed to self is `listMine` (DK K12).
 */
async function deviceAddReachFixture(input: {
  readonly cap?: Parameters<typeof addDeviceOp>[1];
  /** Places dev2's live request (the resume-wait → signal → "Approved" path — DK K13-2). */
  readonly pending?: boolean;
  readonly listMine: (
    projectId: string,
  ) => Promise<{ readonly rows: readonly Record<string, unknown>[] } | { readonly status: number }>;
}): Promise<{ readonly env: TestEnv; readonly state: ServerState; readonly built: BuiltChain }> {
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    { actor: owner, operation: addDeviceOp(dev2, input.cap) },
  ]);
  reachDeks.set(built.projectId, [dek, dek2]);
  const { server, state } = await makeServer({
    built,
    withEnvironment: true,
    registryRows: [registryRowOf(dev2)],
    requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    listMine: await input.listMine(built.projectId),
    pendingRequests: input.pending === true ? [requestRowOf(dev2)] : [],
  });
  const env = await startEnv(server.origin, built.projectId, dev2);
  return { env, state, built };
}

/** The DEK of each epoch of `deviceAddReachFixture`'s chain (per project). */
const reachDeks = new Map<string, readonly Uint8Array[]>();

function registryRowOf(device: TestUser): ServerState["registry"][number] {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label: "laptop",
    createdAtMs: Date.now(),
  };
}

/** A device-addressed distribution row (the new server's shape — with `recipientEncPubHex`, owner's registration signature). */
async function deviceRowsOf(
  projectId: string,
  device: TestUser,
  epochs: readonly number[],
): Promise<Record<string, unknown>[]> {
  const deks = reachDeks.get(projectId) ?? [];
  return Promise.all(
    epochs.map(async (epoch) => ({
      ...(await wrapDekFor({
        projectId,
        environmentId: ENV_ID,
        epoch,
        dek: deks[epoch - 1] ?? new Uint8Array(32),
        recipient: device,
        signer: owner,
      })),
      recipientEncPubHex: device.encPubHex,
    })),
  );
}

function listMineGets(state: ServerState, projectId: string): number {
  return state
    .paths()
    .filter((path) => path === `GET /projects/${projectId}/environments/${ENV_ID}/deks`).length;
}

describe("maruhi device add — key arrival and revocation after the signal (DK K12)", () => {
  it("if an epoch addressed to this device is missing, emits pull's same warning with the real-id path, exits 0, and registers nothing", async () => {
    // Only epoch 1 is addressed to dev2 (the sibling's owner gets 1 and 2 —
    // rows addressed to other devices are not counted). Resume waiting on the
    // live request (no request is created), and check after the signal (the registry row)
    const { env, state, built } = await deviceAddReachFixture({
      pending: true,
      listMine: async (projectId) => ({
        rows: [
          ...(await deviceRowsOf(projectId, dev2, [1])),
          ...(await deviceRowsOf(projectId, owner, [1, 2])),
        ],
      }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 1 project (verified on each project's chain)",
    );
    const warning = env.errors.find((line) => line.includes("no DEK wraps for you exist"));
    expect(warning).toContain(
      `Warning: ${built.projectId}: environment ${ENV_ID}: no DEK wraps for you exist at epochs 2 (inconsistent with the CRYPTO_SPEC §7 all-epoch distribution)`,
    );
    expect(warning).toContain(
      "If this machine was added as a device, the backfill to it may not have completed instead.",
    );
    expect(warning).toContain(
      `A registered device of yours whose cap covers environment ${ENV_ID} and that holds its keys fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    // The new device lacks the missing DEKs, so it does not fill them (the sibling device's pull fills them — K11)
    expect(state.registered).toEqual([]);
    expect(env.errors.join("\n")).toContain("resuming the wait for its approval");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
    expect(env.errors.join("\n")).not.toContain("not registered yet");
  });

  it("when every epoch has arrived, nothing is appended (the check does run — GET is once)", async () => {
    const { env, state, built } = await deviceAddReachFixture({
      listMine: async (projectId) => ({ rows: await deviceRowsOf(projectId, dev2, [1, 2]) }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(listMineGets(state, built.projectId)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).not.toContain("could not check");
  });

  it("does not check environments outside this device's cap (an environment it is not a recipient of is called neither missing nor a check failure)", async () => {
    const { env, state, built } = await deviceAddReachFixture({
      cap: { roleCap: "owner", environmentIds: [] },
      listMine: async () => ({ rows: [] }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(listMineGets(state, built.projectId)).toBe(0);
    // Called neither missing nor a check failure (outside the cap, cannot be opened) — never enters the enumeration
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).not.toContain("could not check");
  });

  it("an environment that could not be checked is not called missing — a Note with the cause, exit code 0", async () => {
    const { env, built } = await deviceAddReachFixture({
      listMine: async () => ({ status: 500 }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).toContain(
      `Note: ${built.projectId}: could not check that the keys of environment ${ENV_ID} reached this device (`,
    );
    expect(errors).toContain(
      `\`maruhi pull --project ${built.projectId} --env ${ENV_ID}\` on this machine reports any missing epochs`,
    );
  });

  it("a key revoked on every project never waits even if the registry row remains, and stops with revocation and re-adding (K13-2 — collecting consultation point (2))", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    // "Approved: … 0 projects" can structurally never appear (there is no path that waits on the registry row as the signal)
    expect(env.logs.join("\n")).not.toContain("Approved:");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) is revoked on ${built.projectId} and registered on no project the server lists for you (1 listed), and it has no pending device-add request. To add this machine back, run \`maruhi device add --replace\` on this machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device — you choose its cap again when approving`,
    );
    expect(errors).not.toContain("not registered yet");
    expect(errors).not.toContain("the approving device skipped or failed");
    expect(errors).not.toContain("loses nothing");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
  });

  it("a key revoked on only some projects says to revoke it on the remaining projects after re-adding (K12-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    // On another project (its genesis key differs → a different id — same person), dev2 is valid
    const other = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extraProjects: [other],
      registryRows: [registryRowOf(dev2)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    // A valid project exists, and there the provenance is add_device → a
    // usable key (exit 0 — K13-2). No approval happened, so it never says "Approved" (K13-3)
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    expect(logs).not.toContain("Approved:");
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Note: this key was revoked on ${built.projectId},`);
    expect(errors).toContain(
      `. This keychain then no longer holds this key, so revoke it on ${other.projectId}, where it is still registered (\`maruhi device revoke ${dev2.fingerprintHex}\` from a registered device)`,
    );
    expect(errors).not.toContain("not registered yet");
  });
});

/** A device without a key (token only — `device add` generates the key). */
async function startEnvWithoutKey(origin: string, projectId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
  );
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}

function requestPosts(state: ServerState): readonly string[] {
  return state.paths().filter((path) => path === "POST /auth/devices/requests");
}

describe("maruhi device add — an existing key's standing on the chain (DK K13)", () => {
  it("a valid key whose provenance is add_device on every project reports registered and exits 0 without creating a request. Appends a note if the registry row is missing (T3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    expect(logs).not.toContain("Approved:");
    expect(env.errors.join("\n")).toContain(
      "Note: this key has no row in your device registry (an approval whose registry write failed leaves it so). The registry only labels devices, so nothing else is needed",
    );
    expect(requestPosts(state)).toEqual([]);

    // No note when the registry has a row (the note is only for a missing row)
    const withRow = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
    });
    const env2 = await startEnv(withRow.server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env2.layer), env2.errors.join("\n")).toBe(0);
    expect(env2.errors.join("\n")).not.toContain("has no row in your device registry");
  });

  it("a project missing on a path where no approval happened is stated in a neutral sentence, not the approver-side script (K13-3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const other = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extraProjects: [other],
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: this key is not registered on ${other.projectId}. A device of yours whose cap covers them registers it on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance), once it has synced a project that has this key`,
    );
    expect(errors).not.toContain("the approving device skipped or failed");
    expect(errors).not.toContain("The request is used up");
  });

  it("hole 1: even with add_device provenance on another project, if it is the first key anywhere, refuse with the 2-way choice (registration via an observation record is no evidence of approval)", async () => {
    // On P1, dev2's key is genesis (the first key); on P2 it was add_device'd from an observation record
    const p1 = await buildChain([{ actor: dev2, operation: genesisOp(dev2) }]);
    const p2 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built: p2,
      withEnvironment: false,
      extraProjects: [p1],
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, p2.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) is your first key on ${p1.projectId} (the key you created or joined that project with)`,
    );
    expect(errors).toContain("If it holds a copy, re-run with --replace");
    expect(errors).not.toContain(`is your first key on ${p2.projectId}`);
    expect(env.logs.join("\n")).not.toContain("This key is registered on");
    expect(requestPosts(state)).toEqual([]);
  });

  it("when everything synced with zero valid placements and the key is nowhere, it says 'nothing is lost' with the list count attached", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `This machine's device key (${dev2.fingerprintHex}) has no pending device-add request and is on no project the server lists for you (1 listed), each chain synced and verified, so replacing it loses nothing there: re-run with --replace — it discards this key, generates a new one and prints its fingerprint to approve from a registered device`,
    );
    expect(env.errors.join("\n")).not.toContain("local records of");
    expect(requestPosts(state)).toEqual([]);
  });

  it("plan B: a project in the floor but absent from the list is only attached as information — it never stops the judgment ('nowhere')", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    const unlisted = "ab".repeat(32);
    await mkdir(env.floorDir, { recursive: true });
    await writeFile(join(env.floorDir, `${unlisted}.jsonl`), "");
    // Things that are not ID-shaped and sidecar files are not counted
    await writeFile(join(env.floorDir, `${"cd".repeat(32)}.attested.json`), "{}");
    await writeFile(join(env.floorDir, "notes.jsonl"), "");
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("so replacing it loses nothing there");
    expect(errors).toContain(
      `. This machine also has local records of 1 project that list does not include (${unlisted}); those records are not separated by server or account, so they may not be yours here — if one is, check it with \`maruhi project verify --project <id>\` before replacing`,
    );
    expect(errors).not.toContain("could not check every project");
  });

  it("when a project cannot be synced, it neither says 'nowhere' nor asserts it. A verification contradiction is a Warning as a tampering sign", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const tampered = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      brokenProjects: [
        { built: down, mode: "unavailable" },
        { built: tampered, mode: "tampered" },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) has no pending device-add request, and maruhi could not check every project it may be registered on: `,
    );
    expect(errors).toContain(`${down.projectId} could not be synced (`);
    expect(errors).toContain(`It is not on ${built.projectId}. `);
    expect(errors).toContain(
      "Nothing is decided from a project that was not checked, so this does not say the key is unused",
    );
    expect(errors).not.toContain("loses nothing");
    const warnings = env.errors.filter((line) => line.startsWith("Warning:"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: ${tampered.projectId}: `);
    expect(warnings[0]).toContain(
      "— a sign of tampering rather than a network error, so nothing about this key is decided from that project",
    );
    expect(requestPosts(state)).toEqual([]);
  });

  it("does not fail when the project list cannot be fetched, and never asserts it as unsyncable (hole 6)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false, projectsStatus: 500 });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "and maruhi could not check every project it may be registered on: your projects could not be listed (",
    );
    expect(errors).not.toContain("loses nothing");
    expect(errors).not.toContain("is revoked on");
  });

  it("after the signal: unsyncable projects are not mixed into 'not registered yet', and a list failure never counts a 0 (K13-3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      brokenProjects: [{ built: down, mode: "unavailable" }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 1 project (verified on each project's chain)",
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Note: ${down.projectId}: could not sync this project (`);
    expect(errors).toContain(
      "so whether this key is registered there is unknown; `maruhi device list` checks again",
    );
    expect(errors).not.toContain("not registered yet");
    expect(errors).not.toContain("Warning:");
    // Resuming a live request never creates a request (never spends the window — and no hole-5 path exists)
    expect(requestPosts(state)).toEqual([]);

    const listDown = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      projectsStatus: 500,
    });
    const env2 = await startEnv(listDown.server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env2.layer), env2.errors.join("\n")).toBe(0);
    const logs2 = env2.logs.join("\n");
    expect(logs2).toContain(
      "Approved: the approving device gave the completion signal (this device is listed in your device registry)",
    );
    expect(logs2).not.toContain("registered on 0 projects");
    expect(env2.errors.join("\n")).toContain("Note: your projects could not be listed (");
  });

  it("when no project can be synced after the signal, it never counts 0 as fact — it attaches the count of what could not be checked (K13-16)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({
      built: await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]),
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      brokenProjects: [{ built, mode: "unavailable" }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    // The list's first entry (genesis is reserve) syncs and dev2 is absent; the second cannot be synced
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain), and 1 project could not be checked",
    );
    expect(env.errors.join("\n")).toContain(
      `Note: ${built.projectId}: could not sync this project (`,
    );
  });

  it("on expiry, appends the chain's fact at this point while keeping the approver-side output's conditions (K13-4)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    // The registry row stays missing (T3 — the approver's PUT dropped), and the request has expired
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      pendingRequests: [{ ...requestRowOf(dev2), expiresAtMs: Date.now() - 1 }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const expired = env.errors.join("\n");
    expect(expired).toContain(
      "If it registered this device but could not list it in your device registry, keep this key",
    );
    expect(expired).toContain(
      `On the project chains right now, this key is registered on ${built.projectId} — keep it; re-running \`maruhi device add\` on this machine confirms that without a new request`,
    );
  });

  it("--replace: when request creation fails (cap · full), nothing is replaced and the old key remains (K13-8)", async () => {
    for (const reason of ["add-requests", "device-rows"] as const) {
      const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
      const { server } = await makeServer({
        built,
        withEnvironment: false,
        extra: [
          onRequest("POST", "/auth/devices/requests", () => ({
            status: 429,
            json: {
              _tag: "DeviceRegistryLimit",
              reason,
              limit: reason === "add-requests" ? 5 : 32,
            },
          })),
        ],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      const entry = masterKeyEntryName(server.origin, owner.userId);
      const before = env.keychain.get(entry);
      expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
      expect(env.keychain.get(entry), reason).toBe(before);
      const errors = env.errors.join("\n");
      expect(errors).toContain(
        "nothing was replaced: the previous key is still in this machine's keychain (--replace replaces it only once the new key's request exists)",
      );
      expect(errors).not.toContain("replaced the previous key in this machine's keychain");
      expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
    }
  });

  it("a keyless device follows the same order 'generate → request → save': a failed request leaves no key (K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => ({
          status: 429,
          json: { _tag: "DeviceRegistryLimit", reason: "add-requests", limit: 5 },
        })),
      ],
    });
    const env = await startEnvWithoutKey(server.origin, built.projectId);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeUndefined();
    expect(env.errors.join("\n")).not.toContain("nothing was replaced");
  });

  it("the guarded replace never overwrites a key another process wrote during request creation, and emits no FP (K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let env: TestEnv | null = null;
    let entry = "";
    // A value written by another process (the guard only compares the value)
    const intruder = "written-by-another-process";
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => {
          // Another process rewrites the keychain while the request is being created
          env?.keychain.set(entry, intruder);
          return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
        }),
      ],
    });
    env = await startEnv(server.origin, built.projectId, owner);
    entry = masterKeyEntryName(server.origin, owner.userId);
    expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
    expect(env.keychain.get(entry)).toBe(intruder);
    expect(env.errors.join("\n")).toContain(
      "Another process wrote this machine's device key while `maruhi device add` was running, so the new key was not stored and the key now in the keychain was left as it is. The request made for the new key is never approved (its fingerprint was not shown) and expires in 15 minutes",
    );
    expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
    expect(env.errors.join("\n")).not.toContain(
      "replaced the previous key in this machine's keychain",
    );
  });

  it("on detecting a concurrent write while a keyless device saves, it states that the request was already created and never emits the key-generate sentence (K13-14)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let env: TestEnv | null = null;
    let entry = "";
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => {
          env?.keychain.set(entry, "written-by-another-process");
          return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
        }),
      ],
    });
    env = await startEnvWithoutKey(server.origin, built.projectId);
    entry = masterKeyEntryName(server.origin, owner.userId);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.keychain.get(entry)).toBe("written-by-another-process");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "Another process wrote this machine's device key while `maruhi device add` was running, so the new key was not stored",
    );
    expect(errors).not.toContain("nothing was left behind");
    expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
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

/**
 * Scaffolding for reserve-key rotate: the state where the previous run
 * interrupted at the ledger swap (the ledger holds N1 = reserve; the original
 * reserve key O = dev2 is marked revoked in the record; both O and N1 are on the chain).
 */
async function reserveRotateFixture(options: {
  readonly withEnvironment: boolean;
  readonly dekRegisterStatus?: number;
  /** Whether to put the old reserve key (dev2 / reserve) on the chain (default true. false = neither revocation nor cleanup happens). */
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
    // The previous interruption: the ledger was swapped to N1 (= reserve) and
    // the original reserve key O (= dev2) was marked revoked in the record,
    // but the chain still carries both O and N1 (no environment — the
    // post-revocation cleanup [rotate] is not examined here)
    const { env, state, origin, ledgerPuts } = await reserveRotateFixture({
      withEnvironment: false,
    });
    expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
    expect(ledgerPuts).toHaveLength(1);
    // revoke_device targets both O and N1 (not N1 alone)
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
    // Local record: O and N1 revoked; only the new key is a valid reserve key
    const recorded = await readOwnDevices(env, origin);
    const active = recorded.filter((row) => row.source === "reserve" && row.revokedAtMs === null);
    expect(active).toHaveLength(1);
    expect([dev2.fingerprintHex, reserve.fingerprintHex]).not.toContain(
      active[0]?.keyFingerprintHex,
    );
    // The reserve key's secret never remains in the keychain
    const keychain = [...env.keychain.values()].join("\n");
    expect(keychain).not.toContain(reserve.encSkHex);
    expect(keychain).toContain(owner.encPubHex);
  });

  it("reports a backfill failure to the new reserve key and names the pull path specifically (DK K11's G9)", async () => {
    // Never putting the old reserve key on the chain = neither revocation nor
    // the post-revocation cleanup (rotate) happens. The exit code is decided
    // by the backfill failure alone (1, same as approval / recovery — the K11-14 ownership ruling)
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
    // The chain: owner's device + the old reserve key (reserve). The ledger cannot be opened (the code is lost)
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
    // The ledger is replaced without being read
    expect(state.paths()).not.toContain("GET /auth/recovery");
    expect(ledgerPuts).toHaveLength(1);
    // The new reserve key's add_device and the old reserve key's revoke_device
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device", "revoke_device"]);
    expect(state.appended[1]?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [reserve.fingerprintHex],
    });
    // The record: the old reserve key revoked, only the new reserve key valid
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === reserve.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const active = recorded.filter((row) => row.source === "reserve" && row.revokedAtMs === null);
    expect(active).toHaveLength(1);
    expect(active[0]?.keyFingerprintHex).not.toBe(reserve.fingerprintHex);
    // The reserve key's secret never remains in the keychain
    const keychain = [...env.keychain.values()].join("\n");
    expect(keychain).not.toContain(reserve.encSkHex);
    expect(keychain).toContain(owner.encPubHex);
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
    // The reserve key's secret never lands on the local record (public side only — K4-1)
    const env = await makeTestEnv();
    await recordOwnDevice(env, "https://example.test", reserve, "reserve");
    const json = await readFile(ownDevicesPathOf(env.configPath), "utf8");
    expect(json).toContain(reserve.encPubHex);
    expect(json).not.toContain(reserve.encSkHex);
    expect(json).not.toContain(reserve.sigSkSeedHex);
  });
});

describe("maruhi key recover / key recovery — the on-chain judgment of the ledger key (DK K14)", () => {
  const CODE_PROMPT = "Enter your recovery code: ";

  /** The scene of typing `key recover` on a keyless device (the ledger = `ledgerKey`). `answers` are responses after the code. */
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

  /** The scene of typing `key recovery` on a device that has device key `device` (the ledger = `ledgerKey`, already registered). */
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
    /** Extra handlers (e.g. the invite-create issuance used for the pre-hiding sync). */
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
        // The ledger rows read by rotate's tail (the old reserve key's passkey / guardian — none)
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

  /**
   * The record sealed into the ledger: the test's `reserve` is a reserve key
   * the CLI generated (marked — DK K16); the others (`owner` etc.) are
   * replicas of pre-DK device keys (unmarked).
   */
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
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key (its ledger record carries the mark maruhi writes when it creates a reserve key)`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
    // Registration is already done before the judgment (the reserve key signs the new device key's add_device)
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
    expect(state.appended[0]?.actor.keyFingerprintHex).toBe(reserve.fingerprintHex);
  });

  it("even with the reserve-key mark, a key that is the first key on the chain is not recorded (a stopping fact outranks the mark — DK K16-2 counterexample 1)", async () => {
    // The marked key is the genesis key (a contradiction only a doctored CLI or an unknown bug can produce)
    const built = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { env, origin } = await recoverFixture({ ledgerKey: reserve, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `the opened key ${reserve.fingerprintHex} is your first key on 1 project (${built.projectId})`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
  });

  it("a key without the reserve-key mark is not recorded as a reserve key, even if add_device-issued everywhere (DK K16-6)", async () => {
    // The ledger = dev2's key (unmarked — not a key this CLI generated as a
    // reserve key). On the chain it is add_device-issued everywhere (the scene
    // where K14's inference would have asked "might be a reserve key")
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, state, origin } = await recoverFixture({ ledgerKey: dev2, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    expect(env.errors.join("\n")).toContain(
      `Warning: the opened key ${dev2.fingerprintHex} was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one), so it was not recorded as your reserve key. If it is the key of a lost or retired device, revoke it now: \`maruhi device revoke ${dev2.fingerprintHex}\`. Then run \`maruhi key recovery\`: it seals a separate reserve key in its place`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
    // Registration happens regardless of the mark (recovery's purpose is registering a new device key — K4-10)
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
  });

  it("does not record the first key (a pre-DK device-key replica) — it guides toward revocation and key recovery", async () => {
    // The ledger = owner's key (the genesis key = the first key). The recovering device has no key
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { env, state, origin } = await recoverFixture({ ledgerKey: owner, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    expect(env.errors.join("\n")).toContain(
      `the opened key ${owner.fingerprintHex} is your first key on 1 project (${built.projectId}) (the key you created or joined that project with), so it is a copy of a device key from an install before device keys, not a reserve key, and it was not recorded as one. If the machine that held it is lost or retired, revoke it now: \`maruhi device revoke ${owner.fingerprintHex}\`. Then run \`maruhi key recovery\`: it seals a separate reserve key in its place`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
    // Registration happens regardless of the judgment (even a replica key adds a new device — K4-10)
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
  });

  it("if the ways it landed are mixed (it is the first key anywhere), it is judged a replica — unchanged even with an unsyncable project", async () => {
    // p1: owner's key is the first key. p2: dev2 created it and add_device'd
    // owner's key (the propagation of a key recorded via observation — fact-
    // check 8). p3: cannot be synced
    const p1 = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const p2 = await buildChain([
      { actor: dev2, operation: genesisOp(dev2) },
      { actor: dev2, operation: addDeviceOp(owner) },
    ]);
    // The unsyncable project (its contents are not distributed — genesis is a different person to split the ID)
    const p3 = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { env, origin } = await recoverFixture({
      ledgerKey: owner,
      built: p1,
      extraProjects: [p2],
      brokenProjects: [{ built: p3, mode: "unavailable" }],
    });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `the opened key ${owner.fingerprintHex} is your first key on 1 project (${p1.projectId}) (the key you created or joined that project with)`,
    );
    expect(errors).not.toContain(`is your first key on 1 project (${p2.projectId})`);
    expect(await reserveRowsOf(env, origin)).toEqual([]);
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
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key (its ledger record carries the mark maruhi writes when it creates a reserve key)`,
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
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key (its ledger record carries the mark maruhi writes when it creates a reserve key)`,
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

  it("key recovery: even on a post-recovery device, a ledger key that is the first key is segregated as a replica", async () => {
    // The device = dev2 (the new key added by recovery). The ledger = owner's key (a pre-DK replica — p1's first key)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, origin, ledgerPuts } = await recoveryFixture({
      device: dev2,
      ledgerKey: owner,
      built,
    });
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `The recovery ledger holds key ${owner.fingerprintHex}, your first key on 1 project (${built.projectId}) (the key you created or joined that project with): a copy of a device key from an install before device keys, not a reserve key. Separating: creating a reserve key and sealing it instead`,
    );
    expect(env.errors.join("\n")).toContain(
      `Note: the key ${owner.fingerprintHex} stays registered as a device key. If no machine of yours holds it any more, revoke it: \`maruhi device revoke ${owner.fingerprintHex}\``,
    );
    expect(ledgerPuts).toHaveLength(1);
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(owner.fingerprintHex);
    expect(env.errors.join("\n")).not.toContain("reissued the recovery code for your reserve key");
  });

  it("key recovery: a replica revoked beforehand as guided is judged a replica on the fact that it was the first key, and segregated (K14-18)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
    ]);
    const { env, origin } = await recoveryFixture({ device: dev2, ledgerKey: owner, built });
    // This device once recorded it as reserve (valid nowhere, so the row is corrected with the revoked mark)
    await recordOwnDevice(env, origin, owner, "reserve");
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Note: this machine had recorded ${owner.fingerprintHex} as your reserve key; it is your first key on ${built.projectId} and is registered nowhere now, so the record now says it is revoked`,
    );
    expect(env.logs.join("\n")).toContain(
      `The recovery ledger holds key ${owner.fingerprintHex}, your first key on 1 project (${built.projectId}) (the key you created or joined that project with): a copy of a device key from an install before device keys, not a reserve key. Separating: creating a reserve key and sealing it instead`,
    );
    expect(env.errors.join("\n")).not.toContain("reissued the recovery code for your reserve key");
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(owner.fingerprintHex);
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
    // With nowhere still valid, it never says 'still registered'
    expect(errors).not.toContain("is still registered on");
    expect(errors).not.toContain("reissued the recovery code for your reserve key");
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(reserve.fingerprintHex);
  });

  it("key recovery: a ledger key revoked on only some projects is segregated, and it guides toward revoking where still valid", async () => {
    // p1: the reserve key is already revoked. p3: dev2 created it and
    // add_device'd the reserve key (on neither is it the first key — the
    // judgment is revoked)
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

  /** After the re-invite: the previous membership's first key, owner, came back as an add_device in the new first key dev2's sync. */
  async function reinvitedChain(): Promise<BuiltChain> {
    return buildChain([
      { actor: member, operation: genesisOp(member) },
      { actor: member, operation: addMemberOp(owner, "owner") },
      { actor: member, operation: removeMemberOp(owner) },
      { actor: member, operation: addMemberOp(dev2, "owner") },
      { actor: dev2, operation: addDeviceOp(owner) },
    ]);
  }

  it("a previous first key that came back as an add_device via re-invite is also judged the first key (K14-1 1-f — key recover)", async () => {
    const built = await reinvitedChain();
    const { env, origin } = await recoverFixture({ ledgerKey: owner, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.prompts).toEqual([CODE_PROMPT]);
    expect(env.errors.join("\n")).toContain(
      `the opened key ${owner.fingerprintHex} is your first key on 1 project (${built.projectId}) (the key you created or joined that project with), so it is a copy of a device key`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
  });

  it("same predicate, so device add on a device holding that key also stops at the 2-way choice (K14-1 1-f)", async () => {
    const built = await reinvitedChain();
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `This machine's device key (${owner.fingerprintHex}) is your first key on ${built.projectId} (the key you created or joined that project with)`,
    );
    expect(requestPosts(state)).toEqual([]);
  });

  it("key reserve rotate: if the ledger key is the first key, stop and correct this device's wrong reserve row into an observation row (K14-4 4-f / 4-g)", async () => {
    // The device = dev2. The ledger = owner's key (a pre-DK replica — the
    // first key). dev2 once recorded it as reserve (the record of an old
    // ledger change's prelude — additional fact-check (c))
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, origin, ledgerPuts } = await recoveryFixture({
      device: dev2,
      ledgerKey: owner,
      built,
    });
    await recordOwnDevice(env, origin, owner, "reserve");
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `The recovery ledger holds key ${owner.fingerprintHex}, your first key on 1 project (${built.projectId}) (the key you created or joined that project with): a copy of a device key from an install before device keys, not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`maruhi key reserve rotate\``,
    );
    expect(errors).toContain(
      `Note: this machine had recorded ${owner.fingerprintHex} as your reserve key; it is your first key on ${built.projectId}, so the record now lists it as an observed device key`,
    );
    // Neither the ledger nor the keys change (the original device is not revoked)
    expect(ledgerPuts).toEqual([]);
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === owner.fingerprintHex,
    );
    expect(row?.source).toBe("observed");
    expect(row?.observedProjectId).toBe(built.projectId);
    expect(row?.revokedAtMs).toBeNull();
    expect(await reserveRowsOf(env, origin)).toEqual([]);
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

  it("a public key that was someone else's first key does not count as this person's first key (K14-1 1-f — narrowed by person)", async () => {
    // The reserve key's public key was once another person's (now removed)
    // add_member key — key uniqueness holds only among current members (§6.2).
    // For this person it is an add_device-provenance key
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      {
        actor: owner,
        operation: {
          op: "add_member",
          payload: {
            targetUserId: "user-other-0009",
            encPubHex: reserve.encPubHex,
            sigPubHex: reserve.sigPubHex,
            role: "member",
            scopeKind: "all",
            scopeEnvironmentIds: [],
          },
        },
      },
      {
        actor: owner,
        operation: { op: "remove_member", payload: { targetUserId: "user-other-0009" } },
      },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env, origin } = await recoverFixture({ ledgerKey: reserve, built });
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    // Not counted as the first key, so no stopping fact exists; the mark is present, so it is recorded
    expect(env.errors.join("\n")).not.toContain("is your first key");
    expect(await reserveRowsOf(env, origin)).toEqual([reserve.fingerprintHex]);
  });

  it("key recover: if this device recorded the first-key-judged key as reserve, correct it (K14-4 4-g)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { env, origin } = await recoverFixture({ ledgerKey: owner, built });
    await recordOwnDevice(env, origin, owner, "reserve");
    expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Note: this machine had recorded ${owner.fingerprintHex} as your reserve key; it is your first key on ${built.projectId}, so the record now lists it as an observed device key`,
    );
    expect(await reserveRowsOf(env, origin)).toEqual([]);
  });

  it("only reserve rows are corrected: observation / approval rows are untouched (K14-4 4-g)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { env, origin } = await recoveryFixture({ device: dev2, ledgerKey: owner, built });
    await recordOwnDevice(env, origin, owner, "observed");
    expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).not.toContain("this machine had recorded");
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === owner.fingerprintHex,
    );
    expect(row?.source).toBe("observed");
    expect(row?.observedProjectId).toBeNull();
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
    // Registration / revocation on unsyncable projects is reported as a failure (exit code 1 — a re-run continues)
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).not.toContain("Refused to change anything");
    expect(ledgerPuts).toHaveLength(1);
    const revoked = state.appendedTo.flatMap(({ entry }) =>
      entry.op === "revoke_device" ? entry.payload.deviceFingerprintsHex : [],
    );
    expect(revoked).toEqual([reserve.fingerprintHex]);
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
      `The recovery ledger holds key ${dev2.fingerprintHex}, which was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one): a copy of a device key from an install before device keys, or a key sealed by another client, not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`maruhi key reserve rotate\``,
    );
    // Neither ledger, chain, nor record changes
    expect(ledgerPuts).toEqual([]);
    expect(state.appendedTo).toEqual([]);
    expect(await reserveRowsOf(env, origin)).toEqual([]);
  });

  it("the gate just before revocation: a replica this device once recorded as reserve is not revoked even by rotate (K14-13)", async () => {
    // The device = dev2. The ledger = a genuine reserve key (add_device). An
    // older CLI had recorded owner's key (the first key — a pre-DK replica) as reserve
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { env, origin, state } = await recoveryFixture({
      device: dev2,
      ledgerKey: reserve,
      built,
    });
    await recordOwnDevice(env, origin, owner, "reserve");
    expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `Warning: not revoking ${owner.fingerprintHex}: it is your first key on 1 project (${built.projectId}) (the key you created or joined that project with), so it is a device key, not a previous reserve key`,
    );
    const revoke = state.appended.find((entry) => entry.op === "revoke_device");
    expect(revoke?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [reserve.fingerprintHex],
    });
    // The opened key and the record rows are checked together in a single sync
    // (the chain fetch before rewriting the ledger is once per project — K14-16)
    const paths = state.paths();
    const beforeSeal = paths.slice(0, paths.indexOf("PUT /auth/recovery"));
    expect(
      beforeSeal.filter((path) => path === `GET /projects/${built.projectId}/chain`),
    ).toHaveLength(1);
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === owner.fingerprintHex,
    );
    expect(row?.source).toBe("observed");
  });

  it("the revocation gate (--replace): even when the judgment is revoke, it never revokes if a project could not be verified (K14-14)", async () => {
    // owner's key (a replica an older CLI recorded as reserve): revoked
    // beforehand on p1 (as guided); on p3 it is valid as an add_device in
    // dev2's sync; the project where it was the first key cannot be synced
    const other = await makeTestUser("user-other-0009");
    const p1 = await buildChain([
      { actor: member, operation: genesisOp(member) },
      { actor: member, operation: addMemberOp(dev2, "owner") },
      { actor: dev2, operation: addDeviceOp(owner) },
      { actor: dev2, operation: addDeviceOp(reserve) },
      { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
    ]);
    const p3 = await buildChain([
      { actor: dev2, operation: genesisOp(dev2) },
      { actor: dev2, operation: addDeviceOp(owner) },
    ]);
    const unseen = await buildChain([{ actor: other, operation: genesisOp(other) }]);
    const { env, origin, state } = await recoveryFixture({
      device: dev2,
      ledgerKey: reserve,
      built: p1,
      extraProjects: [p3],
      brokenProjects: [{ built: unseen, mode: "unavailable" }],
    });
    await recordOwnDevice(env, origin, owner, "reserve");
    // Check the gate via --replace (the escape hatch that never opens the
    // ledger — it proceeds even when unverifiable). rotate stops before the
    // gate if the opened key cannot be verified (K14-15)
    env.setPromptResponses([
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);
    await runCli(["key", "recovery", "--replace"], env.layer);
    expect(env.errors.join("\n")).toContain(
      `Warning: not revoking ${owner.fingerprintHex}: could not check it on 1 project (${unseen.projectId}), so maruhi cannot confirm it is not one of your device keys`,
    );
    const revoked = state.appendedTo.flatMap(({ entry }) =>
      entry.op === "revoke_device" ? entry.payload.deviceFingerprintsHex : [],
    );
    expect(revoked).not.toContain(owner.fingerprintHex);
  });

  it("the revocation gate: a replica already revoked on the project where it was the first key is still not revoked after everything verifies (K14-18)", async () => {
    // owner's key (a pre-DK replica an older CLI recorded as reserve): on p1 it
    // was the first key and is already revoked as guided; on p3 it is valid as
    // an add_device in dev2's sync. Every project is verifiable
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: dev2, operation: addDeviceOp(reserve) },
      { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
    ]);
    const p3 = await buildChain([
      { actor: member, operation: genesisOp(member) },
      { actor: member, operation: addMemberOp(dev2, "owner") },
      { actor: dev2, operation: addDeviceOp(owner) },
    ]);
    const { env, origin, state } = await recoveryFixture({
      device: dev2,
      ledgerKey: reserve,
      built: p1,
      extraProjects: [p3],
    });
    await recordOwnDevice(env, origin, owner, "reserve");
    expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Warning: not revoking ${owner.fingerprintHex}: it is your first key on 1 project (${p1.projectId}) (the key you created or joined that project with), so it is a device key, not a previous reserve key`,
    );
    const revoked = state.appendedTo.flatMap(({ entry }) =>
      entry.op === "revoke_device" ? entry.payload.deviceFingerprintsHex : [],
    );
    expect(revoked).not.toContain(owner.fingerprintHex);
    // The wrong reserve row is corrected into an observation row under p3's
    // standing as valid (K14-4 4-g), and the following rotate's p1 sync
    // rewrites it as a witness by p1's history (the first key) — with the revoked mark (DK K15-12)
    const row = (await readOwnDevices(env, origin)).find(
      (entry) => entry.keyFingerprintHex === owner.fingerprintHex,
    );
    expect(row).toMatchObject({
      source: "observed",
      addedByFingerprintHex: null,
      observedProjectId: p1.projectId,
    });
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
      `The recovery ledger holds key ${dev2.fingerprintHex}, which was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one): a copy of a device key from an install before device keys, or a key sealed by another client, not a reserve key. Separating: creating a reserve key and sealing it instead`,
    );
    expect(ledgerPuts).toHaveLength(1);
    // Only the newly generated reserve key is recorded (not the opened dev2 key)
    const reserves = await reserveRowsOf(env, origin);
    expect(reserves).toHaveLength(1);
    expect(reserves).not.toContain(dev2.fingerprintHex);
  });

  describe("projects the server hid from the list (DK K15)", () => {
    // The typical scene (design doc §20 fact 6 (iv)): a pre-DK user's device
    // M1 (key = owner's key K) approved DK's device D2 (dev2) on p1. D2 synced
    // p1 and observed K (the first key), joined p3 via an invite, and
    // add_device'd K onto p3. The ledger is K (pre-DK). The server hides p1 from the list
    async function hiddenFirstKeyScene(): Promise<{ p1: BuiltChain; p3: BuiltChain }> {
      const p1 = await buildChain([
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: addDeviceOp(dev2) },
      ]);
      const p3 = await buildChain([
        { actor: member, operation: genesisOp(member) },
        { actor: member, operation: addMemberOp(dev2, "owner") },
        { actor: dev2, operation: addDeviceOp(owner) },
      ]);
      return { p1, p3 };
    }

    /** Synced p1 before it was hidden (a command through the keyed prelude — the observation writes K's row). */
    async function syncBeforeHidden(env: TestEnv, p1: BuiltChain): Promise<void> {
      expect(
        await runCli(
          ["invite", "create", "--role", "member", "--project", p1.projectId],
          env.layer,
        ),
        env.errors.join("\n"),
      ).toBe(0);
      env.errors.length = 0;
      env.logs.length = 0;
    }

    function revokedFingerprints(state: ServerState): readonly string[] {
      return state.appendedTo.flatMap(({ entry }) =>
        entry.op === "revoke_device" ? entry.payload.deviceFingerprintsHex : [],
      );
    }

    const recordedFirstKey = (projectId: string) =>
      `was your first key on project ${projectId} (the key you created or joined that project with) when this machine synced that project's verified chain, although the projects the server lists for you now do not show it`;

    it("rotate: a ledger key that was the first key on a hidden project is stopped by this device's observation record; nothing changes", async () => {
      const { p1, p3 } = await hiddenFirstKeyScene();
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1],
        extra: [inviteHandler(p1)],
      });
      await syncBeforeHidden(env, p1);
      // The witness the observation path wrote (provenance observed · no source device · observed project p1)
      const witness = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(witness).toMatchObject({
        source: "observed",
        addedByFingerprintHex: null,
        observedProjectId: p1.projectId,
      });
      expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        `The recovery ledger holds key ${owner.fingerprintHex}. This machine's records show it ${recordedFirstKey(p1.projectId)}: a copy of a device key from an install before device keys, not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`maruhi key reserve rotate\``,
      );
      // Neither ledger, record, nor chain changes (K stays an in-use device key on p3)
      expect(ledgerPuts).toEqual([]);
      expect(revokedFingerprints(state)).toEqual([]);
      expect(await reserveRowsOf(env, origin)).toEqual([]);
      const row = (await readOwnDevices(env, origin)).find(
        (entry) => entry.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(row?.source).toBe("observed");
    });

    it("rotate: even when revoked on a visible project, the witness's 'first key' is stated before 'revoked' (judgment ordering — K15-1 counterexample 3)", async () => {
      // K is revoked on p4 (as guided) · valid on p3 · the first key on p1
      // (hidden). If the witness sat behind `revoked`, the chain judgment
      // would be "revoked" and the revocation gate could pass p3's K
      const { p1, p3 } = await hiddenFirstKeyScene();
      // Separating p3 and genesis (the project ID is the genesis hash)
      const other = await makeTestUser("user-other-0015");
      const p4 = await buildChain([
        { actor: other, operation: genesisOp(other) },
        { actor: other, operation: addMemberOp(dev2, "owner") },
        { actor: dev2, operation: addDeviceOp(owner) },
        { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
      ]);
      expect(p4.projectId).not.toBe(p3.projectId);
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        extraProjects: [p4],
        unlistedProjects: [p1],
        extra: [inviteHandler(p1), inviteHandler(p4)],
      });
      await syncBeforeHidden(env, p1);
      // On p4's sync the witness row gains the revoked mark (the fact of having been the first key stays true past revocation — K15-6)
      await syncBeforeHidden(env, p4);
      const witness = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(witness?.revokedAtMs).not.toBeNull();
      expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
      const errors = env.errors.join("\n");
      expect(errors).toContain(
        `The recovery ledger holds key ${owner.fingerprintHex}. This machine's records show it ${recordedFirstKey(p1.projectId)}`,
      );
      expect(errors).not.toContain("which is revoked on");
      expect(ledgerPuts).toEqual([]);
      expect(revokedFingerprints(state)).toEqual([]);
    });

    it("key recovery: a ledger key that was the first key on a hidden project is segregated as a replica by the witness and never recorded as a reserve key", async () => {
      const { p1, p3 } = await hiddenFirstKeyScene();
      const { env, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1],
        extra: [inviteHandler(p1)],
      });
      await syncBeforeHidden(env, p1);
      expect(await runCli(["key", "recovery"], env.layer), env.errors.join("\n")).toBe(0);
      expect(env.logs.join("\n")).toContain(
        `The recovery ledger holds key ${owner.fingerprintHex}. This machine's records show it ${recordedFirstKey(p1.projectId)}: a copy of a device key from an install before device keys, not a reserve key. Separating: creating a reserve key and sealing it instead`,
      );
      expect(env.errors.join("\n")).toContain(
        `Note: the key ${owner.fingerprintHex} stays registered as a device key. If no machine of yours holds it any more, revoke it: \`maruhi device revoke ${owner.fingerprintHex}\``,
      );
      expect(ledgerPuts).toHaveLength(1);
      // Only the new reserve key is recorded (K stays as the witness row)
      const reserves = await reserveRowsOf(env, origin);
      expect(reserves).toHaveLength(1);
      expect(reserves).not.toContain(owner.fingerprintHex);
    });

    it("key recover: a device that lost only its keychain is not recorded when a witness exists", async () => {
      const { p1, p3 } = await hiddenFirstKeyScene();
      const { env, origin } = await recoverFixture({
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1],
      });
      // The record of this device once syncing p1 and observing K (the config directory remains)
      await recordOwnDevice(env, origin, owner, "observed", null, p1.projectId);
      expect(await runCli(["key", "recover"], env.layer), env.errors.join("\n")).toBe(0);
      expect(env.prompts).toEqual([CODE_PROMPT]);
      expect(env.errors.join("\n")).toContain(
        `Warning: this machine's records show that the opened key ${owner.fingerprintHex} ${recordedFirstKey(p1.projectId)}, so it is a copy of a device key from an install before device keys, not a reserve key, and it was not recorded as one. If the machine that held it is lost or retired, revoke it now: \`maruhi device revoke ${owner.fingerprintHex}\`. Then run \`maruhi key recovery\`: it seals a separate reserve key in its place`,
      );
      expect(await reserveRowsOf(env, origin)).toEqual([]);
    });

    it("on an honest server, unrelated clues (the floor · another server's record · a row with no observed project) never stop the correct reserve-key rotate (K13-7)", async () => {
      const built = await buildChain([
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: addDeviceOp(reserve) },
      ]);
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: owner,
        ledgerKey: reserve,
        built,
      });
      // A project in the floor (not split by server · account) that is absent from the list
      await mkdir(env.floorDir, { recursive: true });
      await writeFile(join(env.floorDir, `${"ab".repeat(32)}.jsonl`), "");
      // In another server's record, the same FP is observed as the first key (they never mix)
      const store = makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath));
      await Effect.runPromise(
        store.record("https://other.example", owner.userId, {
          keyFingerprintHex: reserve.fingerprintHex,
          encPubHex: reserve.encPubHex,
          sigPubHex: reserve.sigPubHex,
          roleCap: "owner",
          scope: { kind: "all" },
          source: "observed",
          label: null,
          addedByFingerprintHex: null,
          observedProjectId: "cd".repeat(32),
          recordedAtMs: 1_700_000_000_000,
          revokedAtMs: null,
        }),
      );
      // Even a this-server observation row is never a witness in the shape with no observed project (K15-6)
      await recordOwnDevice(env, origin, reserve, "observed");
      expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
      expect(ledgerPuts).toHaveLength(1);
      expect(revokedFingerprints(state)).toEqual([reserve.fingerprintHex]);
      expect(env.errors.join("\n")).not.toContain("This machine's records show");
    });

    it("a key first observed as an add_device also becomes a witness once the project where it is the first key is synced later (independent of observation order — K15-11)", async () => {
      // D2 first synced p3 (K is D2's add_device), then p4 (K is revoked —
      // the row carries the revoked mark), then p1 (K is the first key)
      const { p1, p3 } = await hiddenFirstKeyScene();
      const other = await makeTestUser("user-other-0016");
      const p4 = await buildChain([
        { actor: other, operation: genesisOp(other) },
        { actor: other, operation: addMemberOp(dev2, "owner") },
        { actor: dev2, operation: addDeviceOp(owner) },
        { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
      ]);
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1, p4],
        extra: [inviteHandler(p3), inviteHandler(p1), inviteHandler(p4)],
      });
      await syncBeforeHidden(env, p3);
      const first = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(first).toMatchObject({
        addedByFingerprintHex: dev2.fingerprintHex,
        observedProjectId: p3.projectId,
      });
      await syncBeforeHidden(env, p4);
      const marked = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(marked?.revokedAtMs).not.toBeNull();
      await syncBeforeHidden(env, p1);
      const witness = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(witness).toMatchObject({
        source: "observed",
        addedByFingerprintHex: null,
        observedProjectId: p1.projectId,
        recordedAtMs: first?.recordedAtMs,
        // Keep the revoked mark (erasing it would let the revoked key be re-registered onto other projects — K4-3)
        revokedAtMs: marked?.revokedAtMs,
      });
      expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        `The recovery ledger holds key ${owner.fingerprintHex}. This machine's records show it ${recordedFirstKey(p1.projectId)}`,
      );
      expect(ledgerPuts).toEqual([]);
      expect(revokedFingerprints(state)).toEqual([]);
    });

    it("a key already revoked on the project where it was the first key also becomes a witness via that chain's history (the same predicate as the judgment — K15-12)", async () => {
      // On p1, K was the first key but is already revoked as guided (not a valid device of p1). On p3 it is valid
      const p1 = await buildChain([
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: addDeviceOp(dev2) },
        { actor: dev2, operation: revokeDeviceOp(owner, [owner]) },
      ]);
      const { p3 } = await hiddenFirstKeyScene();
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1],
        extra: [inviteHandler(p3), inviteHandler(p1)],
      });
      await syncBeforeHidden(env, p3);
      await syncBeforeHidden(env, p1);
      const witness = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(witness).toMatchObject({
        source: "observed",
        addedByFingerprintHex: null,
        observedProjectId: p1.projectId,
      });
      // The revoked mark the same sync's (b) attached is not erased by the witness rewrite
      expect(witness?.revokedAtMs).not.toBeNull();
      expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        `The recovery ledger holds key ${owner.fingerprintHex}. This machine's records show it ${recordedFirstKey(p1.projectId)}`,
      );
      expect(ledgerPuts).toEqual([]);
      expect(revokedFingerprints(state)).toEqual([]);
    });

    it("an existing witness row is not rewritten by another first-key project's sync (keep the first witness — K15-12)", async () => {
      // K is the first key on both p1 (genesis) and p5 (add_member). D2 synced in the order p3 → p1 → p5
      const { p1, p3 } = await hiddenFirstKeyScene();
      const other = await makeTestUser("user-other-0017");
      const p5 = await buildChain([
        { actor: other, operation: genesisOp(other) },
        { actor: other, operation: addMemberOp(owner, "owner") },
        { actor: owner, operation: addDeviceOp(dev2) },
      ]);
      const { env, origin } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1, p5],
        extra: [inviteHandler(p3), inviteHandler(p1), inviteHandler(p5)],
      });
      await syncBeforeHidden(env, p3);
      await syncBeforeHidden(env, p1);
      await syncBeforeHidden(env, p5);
      const witness = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === owner.fingerprintHex,
      );
      expect(witness).toMatchObject({
        addedByFingerprintHex: null,
        observedProjectId: p1.projectId,
      });
    });

    it("a reserve key observed on a non-approving device (an observation row with a source device) is no witness, and rotate revokes it", async () => {
      // dev2 is not the device that sealed the reserve key: owner's device
      // add_device'd the reserve key and dev2 observed it via a sync
      // (provenance observed · source device = owner's key)
      const built = await buildChain([
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: addDeviceOp(dev2) },
        { actor: owner, operation: addDeviceOp(reserve) },
      ]);
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: reserve,
        built,
        extra: [inviteHandler(built)],
      });
      await syncBeforeHidden(env, built);
      const observed = (await readOwnDevices(env, origin)).find(
        (row) => row.keyFingerprintHex === reserve.fingerprintHex,
      );
      expect(observed).toMatchObject({
        source: "observed",
        addedByFingerprintHex: owner.fingerprintHex,
        observedProjectId: built.projectId,
      });
      expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
      expect(ledgerPuts).toHaveLength(1);
      expect(revokedFingerprints(state)).toEqual([reserve.fingerprintHex]);
    });

    it("the non-interactive refusal is unchanged: even with a witness, rotate stops before taking the ledger and changes nothing", async () => {
      const { p1, p3 } = await hiddenFirstKeyScene();
      const { env, state, origin, ledgerPuts } = await recoveryFixture({
        device: dev2,
        ledgerKey: owner,
        built: p3,
        unlistedProjects: [p1],
      });
      await recordOwnDevice(env, origin, owner, "observed", null, p1.projectId);
      env.setTerminal({ stdin: false, stdout: true, stderr: true });
      expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
      expect(env.prompts).toEqual([]);
      expect(state.paths()).not.toContain("GET /auth/recovery");
      expect(ledgerPuts).toEqual([]);
      expect(state.appendedTo).toEqual([]);
    });
  });
});
