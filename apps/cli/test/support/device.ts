import {
  type ChainEntry,
  type ChainOperation,
  computeUserKeyFingerprint,
  encodeHex,
} from "@maruhi/crypto";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  hexBytes,
  testEnvironmentId,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import type { ApiPayload, ApiReply, ApiSuccess } from "@maruhi/test-kit/api";
import { Effect } from "effect";
import { afterEach, beforeAll } from "vite-plus/test";

import { tokenEntryName } from "../../src/keychain.ts";
import {
  makeFileOwnDeviceStore,
  type OwnDeviceEntry,
  type OwnDeviceSource,
  ownDevicesPathOf,
} from "../../src/own-devices.ts";
import {
  acceptAppendedEntry,
  type AppendInjection,
  appendableProjectHandlers,
  injectedAppendResponse,
  servedChain,
  servedChainResponse,
} from "./chain-handler.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./env.ts";
import { type MockHandler, MockServer, offSpec, type OffSpecReply, onEndpoint } from "./server.ts";

export const ENV_ID = "env-app";
export const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

export let owner: GeneratedIdentity;
export let dev2: GeneratedIdentity;
export let reserve: GeneratedIdentity;
export let member: GeneratedIdentity;
export let dek: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-0001");
  dev2 = await generateIdentity("user-owner-0001");
  reserve = await generateIdentity("user-owner-0001");
  member = await generateIdentity("user-member-0002");
  dek = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

export function addDeviceOp(
  device: GeneratedIdentity,
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
      scopeEnvironmentIds:
        cap.environmentIds === undefined ? [] : cap.environmentIds.map(testEnvironmentId),
    },
  };
}

export function revokeDeviceOp(
  target: GeneratedIdentity,
  devices: readonly GeneratedIdentity[],
): ChainOperation {
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
  readonly appendedTo: { readonly projectId: string; readonly entry: ChainEntry }[];
  readonly registered: { environmentId: string; deks: ApiPayload<"deks.register">["deks"] }[];
  readonly registry: {
    keyFingerprintHex: string;
    encPubHex: string;
    sigPubHex: string;
    label: string;
    createdAtMs: number;
    tokenId?: string;
  }[];
  readonly tokenRevokes: string[];
  readonly registryPuts: { fp: string; body: ApiPayload<"devices.register"> }[];
  readonly registryDeletes: string[];
  readonly requestCancels: string[];
  readonly paths: () => readonly string[];
}

type DeviceRequestRow = ApiSuccess<"devices.requestGet">;

export type TokenRow = ApiSuccess<"auth.listTokens">["tokens"][number];

export type ListMineInjection =
  | { readonly rows: readonly WireRecipientDek[] }
  | { readonly status: number };

export async function makeServer(
  input: AppendInjection & {
    readonly built: BuiltChain;
    readonly withEnvironment: boolean;
    readonly requests?: readonly DeviceRequestRow[];
    readonly registryRows?: readonly ServerState["registry"][number][];
    readonly tokensStatus?: number;
    readonly tokens?: readonly TokenRow[];
    readonly tokenRevokeStatus?: number;
    readonly extra?: readonly MockHandler[];
    readonly environmentsStatus?: number;
    readonly registryPutStatuses?: readonly number[];
    readonly requestCreate?: {
      readonly expiresAtMs: number;
      readonly signal: boolean;
      readonly conflict?: "request-exists" | "device-registered";
    };
    readonly extraProjects?: readonly BuiltChain[];
    readonly dekRegisterStatus?: number;
    readonly listMine?: ListMineInjection;
    readonly pendingRequests?: readonly DeviceRequestRow[];
    readonly projectsStatus?: number;
    readonly brokenProjects?: readonly {
      readonly built: BuiltChain;
      readonly mode: "unavailable" | "tampered";
    }[];
    readonly unlistedProjects?: readonly BuiltChain[];
  },
): Promise<{ server: MockServer; state: ServerState }> {
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
  let appendCalls = 0;
  const ownWrap: WireRecipientDek | null = input.withEnvironment
    ? await distributedWrap({
        projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek,
        recipient: owner,
        signer: owner,
      })
    : null;
  const envStatement = input.withEnvironment
    ? await distributedEnvironmentStatement({
        projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(input.built, 2),
      })
    : null;
  const handlers: MockHandler[] = [
    onEndpoint("membership.get", { projectId }, () =>
      servedChainResponse(projectId, entries, hashes),
    ),
    onEndpoint("membership.append", { projectId }, async (request) => {
      const injected = injectedAppendResponse(input, appendCalls, entries, hashes);
      appendCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      const entry = request.body.entry as ChainEntry;
      appended.push(entry);
      appendedTo.push({ projectId, entry });
      return acceptAppendedEntry(projectId, entries, hashes, entry);
    }),
    onEndpoint("environments.list", { projectId }, () =>
      input.environmentsStatus !== undefined && input.environmentsStatus !== 200
        ? offSpec({ status: input.environmentsStatus, json: { _tag: "Internal" } })
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
    onEndpoint("deks.listMine", { projectId, environmentId: ENV_ID }, () =>
      listMineResponse(input.listMine, ownWrap),
    ),
    onEndpoint("deks.register", { projectId, environmentId: ENV_ID }, (request) => {
      if (input.dekRegisterStatus !== undefined) {
        return offSpec({ status: input.dekRegisterStatus, json: { _tag: "Internal" } });
      }
      registered.push({ environmentId: ENV_ID, deks: request.body.deks });
      return { status: 204 };
    }),
    onEndpoint("membership.list", () =>
      input.projectsStatus !== undefined && input.projectsStatus !== 200
        ? offSpec({ status: input.projectsStatus, json: { _tag: "Internal" } })
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
      onEndpoint("membership.get", { projectId: broken.built.projectId }, () =>
        broken.mode === "unavailable"
          ? offSpec({ status: 500, json: { _tag: "Internal" } })
          : {
              status: 200,
              json: {
                ...servedChain(broken.built.projectId, broken.built.entries, broken.built.hashes),
                headSeq: broken.built.entries.length + 1,
              },
            },
      ),
    ),
    ...[...(input.extraProjects ?? []), ...(input.unlistedProjects ?? [])].flatMap((built) =>
      appendableProjectHandlers(built, (entry) =>
        appendedTo.push({ projectId: built.projectId, entry }),
      ),
    ),
    onEndpoint("devices.list", () => ({ status: 200, json: { devices: registry } })),
    onEndpoint("devices.register", (request) => {
      const { fp } = request.params;
      registryPuts.push({ fp, body: request.body });
      const status = registryPutStatuses.shift() ?? 204;
      if (status === 429) {
        return {
          status,
          json: { _tag: "DeviceRegistryLimit", reason: "device-rows", limit: 32 },
        };
      }
      if (status !== 204) {
        return offSpec({ status, json: { _tag: "Internal" } });
      }
      registry.push({ keyFingerprintHex: fp, ...request.body, createdAtMs: Date.now() });
      return { status: 204 };
    }),
    onEndpoint("devices.remove", (request) => {
      registryDeletes.push(request.params.fp);
      return { status: 204 };
    }),
    onEndpoint("devices.requestList", () => ({
      status: 200,
      json: { requests: input.requests ?? [] },
    })),
    onEndpoint("devices.requestCancel", (request) => {
      requestCancels.push(request.params.fp);
      return { status: 204 };
    }),
    onEndpoint("devices.requestGet", (request) => {
      const pending = input.pendingRequests?.find(
        (row) => row.keyFingerprintHex === request.params.fp,
      );
      return pending === undefined
        ? { status: 404, json: { _tag: "DeviceNotFound" } }
        : { status: 200, json: pending };
    }),
    onEndpoint("auth.listTokens", () =>
      input.tokensStatus === 403
        ? { status: 403, json: { _tag: "Forbidden", reason: "insufficient-scope" } }
        : { status: 200, json: { tokens: input.tokens ?? [] } },
    ),
    onEndpoint("auth.revokeTokenById", (request) => {
      tokenRevokes.push(request.params.tokenId);
      const status = input.tokenRevokeStatus ?? 204;
      if (status === 204) {
        return { status };
      }
      return status === 404
        ? { status, json: { _tag: "TokenNotFound" } }
        : offSpec({ status, json: { _tag: "Internal" } });
    }),
    onEndpoint("devices.requestCreate", async (request) => {
      if (input.requestCreate === undefined) {
        return null;
      }
      const body = request.body;
      if (input.requestCreate.signal) {
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
    }),
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

function listMineResponse(
  listMine: ListMineInjection | undefined,
  ownWrap: WireRecipientDek | null,
): ApiReply<"deks.listMine"> | OffSpecReply {
  if (listMine === undefined) {
    return { status: 200, json: { deks: ownWrap === null ? [] : [ownWrap] } };
  }
  return "status" in listMine
    ? offSpec({ status: listMine.status, json: { _tag: "Internal" } })
    : { status: 200, json: { deks: listMine.rows } };
}

export async function startEnv(
  origin: string,
  projectId: string,
  user: GeneratedIdentity,
): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, origin, user);
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}

export function requestRowOf(device: GeneratedIdentity, label = "laptop"): DeviceRequestRow {
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
  device: GeneratedIdentity,
  source: OwnDeviceSource,
  revokedAtMs: number | null = null,
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

export function registryRowOf(device: GeneratedIdentity): ServerState["registry"][number] {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label: "laptop",
    createdAtMs: Date.now(),
  };
}

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
