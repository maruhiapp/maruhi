import {
  type ChainEntry,
  type ChainOperation,
  computeChainEntryHash,
  computeUserKeyFingerprint,
  encodeHex,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll } from "vitest";

import { tokenEntryName } from "../../src/keychain.ts";
import {
  makeFileOwnDeviceStore,
  type OwnDeviceEntry,
  type OwnDeviceSource,
  ownDevicesPathOf,
} from "../../src/own-devices.ts";
import { appendableProjectHandlers } from "./chain-handler.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  type TestUser,
  wrapDekFor,
  type WireRecipientDek,
} from "./crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./server.ts";

export const ENV_ID = "env-app";
export const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

export let owner: TestUser;
/** owner's second device (the new device being approved / the device being revoked). */
export let dev2: TestUser;
/** owner's reserve key (only the public side lands on the local record). */
export let reserve: TestUser;
export let member: TestUser;
export let dek: Uint8Array;

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
export function addDeviceOp(
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

export function revokeDeviceOp(target: TestUser, devices: readonly TestUser[]): ChainOperation {
  return {
    op: "revoke_device",
    payload: {
      targetUserId: target.userId,
      deviceFingerprintsHex: devices.map((device) => device.fingerprintHex).toSorted(),
    },
  };
}

export interface ServerState {
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
export async function makeServer(input: {
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
      json: {
        projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
        attestations: [],
      },
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
              schemaPolicy: "enabled",
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
                attestations: [],
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

export async function startEnv(
  origin: string,
  projectId: string,
  user: TestUser,
): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, origin, user);
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}

export function requestRowOf(device: TestUser, label = "laptop"): Record<string, unknown> {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label,
    expiresAtMs: FAR_FUTURE_MS,
  };
}

export async function readOwnDevices(
  env: TestEnv,
  origin: string,
): Promise<readonly OwnDeviceEntry[]> {
  const store = makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath));
  const loaded = await Effect.runPromise(store.load(origin, owner.userId));
  return loaded.state === "loaded" ? loaded.devices : [];
}

export async function recordOwnDevice(
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

export async function chainWithEnvironment(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
}

export function registryRowOf(device: TestUser): ServerState["registry"][number] {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label: "laptop",
    createdAtMs: Date.now(),
  };
}

/** A device without a key (token only — `device add` generates the key). */
export async function startEnvWithoutKey(origin: string, projectId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({
      token: "maruhi_pat_stored",
      userId: owner.userId,
      tokenId: "tok_1",
      expiresAtMs: 4_102_444_800_000,
    }),
  );
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}
