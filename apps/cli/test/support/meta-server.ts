import type { ChainEntry } from "@maruhi/crypto";

import { acceptAppendedEntry, deksHandlerOf, servedChainResponse } from "./chain-handler.ts";
import {
  type BuiltChain,
  headOf,
  manifestFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
} from "./crypto.ts";
import type { MockHandler, MockRequest } from "./server.ts";

export interface MetaEnvironmentState {
  envStatement: WireDistributedEnvironmentStatement;
  environmentDeleted: boolean;
  readonly chainEntries: ChainEntry[];
  readonly chainHashes: string[];
  variables: WireDistributedVariableStatement[];
  tombstones: WireDistributedVariableStatement[];
  manifest: WireDistributedManifest | null;
  mutations: {
    kind: "create" | "activate" | "remove" | "rename-environment" | "remove-environment";
    request: MockRequest;
  }[];
}

export interface MetaEnvironmentServerInput {
  readonly chain: BuiltChain;
  readonly owner: TestUser;
  readonly environmentId: string;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly initialVariables?: readonly WireDistributedVariableStatement[];
  readonly initialTombstones?: readonly WireDistributedVariableStatement[];
  readonly wrap?: WireRecipientDek;
  readonly ignoreRemovals?: boolean;
  readonly ignoreEnvironmentMutations?: boolean;
  readonly resurrectDeleted?: boolean;
}

interface MutationBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value?: unknown;
  readonly manifest: WireDistributedManifest;
}

function distributed<T>(record: T, owner: TestUser, kind: "author" | "issuer"): T {
  return {
    ...record,
    [`${kind}UserId`]: owner.userId,
    [`${kind}KeyFingerprintHex`]: owner.fingerprintHex,
  };
}

export function makeMetaEnvironmentServer(input: MetaEnvironmentServerInput): {
  readonly state: MetaEnvironmentState;
  readonly handlers: readonly MockHandler[];
} {
  const state: MetaEnvironmentState = {
    envStatement: input.envStatement,
    environmentDeleted: false,
    chainEntries: [...input.chain.entries],
    chainHashes: [...input.chain.hashes],
    variables: [...(input.initialVariables ?? [])],
    tombstones: [...(input.initialTombstones ?? [])],
    manifest: null,
    mutations: [],
  };
  const list = `/projects/${input.chain.projectId}/environments`;
  const base = `${list}/${input.environmentId}`;
  const notFound = {
    status: 404,
    json: { _tag: "EnvironmentNotFound", environmentId: input.environmentId },
  };
  const activatePattern = new RegExp(`^${base}/variables/([^/]+)/activate$`);
  const removePattern = new RegExp(`^${base}/variables/([^/]+)$`);
  const hidden = (): boolean => state.environmentDeleted && input.resurrectDeleted !== true;

  const acceptStatement = (body: MutationBody): void => {
    const accepted = distributed(body.statement, input.owner, "author");
    state.variables = [
      ...state.variables.filter((entry) => entry.variableId !== accepted.variableId),
      accepted,
    ];
    state.manifest = distributed(body.manifest, input.owner, "issuer");
  };

  const handlers: MockHandler[] = [
    (request) =>
      request.method === "GET" && request.path === `/projects/${input.chain.projectId}/chain`
        ? servedChainResponse(input.chain.projectId, state.chainEntries, state.chainHashes)
        : null,
    ...(input.wrap === undefined
      ? []
      : [deksHandlerOf(input.chain.projectId, input.environmentId, [input.wrap])]),
    async (request) => {
      if (request.method !== "GET" || request.path !== `${base}/pull/metadata`) {
        return null;
      }
      if (hidden()) {
        return notFound;
      }
      const manifest =
        state.manifest ??
        (await manifestFor({
          projectId: input.chain.projectId,
          environmentId: input.environmentId,
          epoch: 1,
          issuer: input.owner,
          head: headOf(input.chain, input.chain.entries.length),
          envStatement: state.envStatement,
          statements: [...state.variables, ...state.tombstones],
        }));
      return {
        status: 200,
        json: {
          environmentId: input.environmentId,
          currentEpoch: 1,
          statement: state.envStatement,
          variables: state.variables,
          deletedVariables: state.tombstones,
          manifest,
          schemaPolicy: "enabled" as const,
        },
      };
    },
    (request) => {
      if (request.method !== "POST" || request.path !== `${base}/variables`) {
        return null;
      }
      state.mutations.push({ kind: "create", request });
      const body = request.body as MutationBody;
      acceptStatement(body);
      return {
        status: 200,
        json: {
          variableId: body.statement.variableId,
          version: body.value === undefined ? 0 : 1,
          epoch: 1,
        },
      };
    },
    (request) => {
      const match = request.path.match(activatePattern);
      if (request.method !== "POST" || match === null) {
        return null;
      }
      state.mutations.push({ kind: "activate", request });
      const body = request.body as MutationBody;
      acceptStatement(body);
      return { status: 200, json: { variableId: match[1], version: 1, epoch: 1 } };
    },
    (request) => {
      const match = request.path.match(removePattern);
      if (request.method !== "DELETE" || match === null) {
        return null;
      }
      state.mutations.push({ kind: "remove", request });
      if (input.ignoreRemovals !== true) {
        const body = request.body as MutationBody;
        const accepted = distributed(body.statement, input.owner, "author");
        state.variables = state.variables.filter(
          (entry) => entry.variableId !== accepted.variableId,
        );
        state.tombstones = [
          ...state.tombstones.filter((entry) => entry.variableId !== accepted.variableId),
          accepted,
        ];
        state.manifest = distributed(body.manifest, input.owner, "issuer");
      }
      return { status: 204, bodyText: "" };
    },
    (request) =>
      request.method === "GET" && request.path === `${base}/pull` && hidden() ? notFound : null,
    (request) =>
      request.method === "GET" && request.path === list
        ? {
            status: 200,
            json: {
              environments: hidden()
                ? []
                : [
                    {
                      environmentId: input.environmentId,
                      currentEpoch: 1,
                      statement: state.envStatement,
                    },
                  ],
              schemaPolicy: "enabled" as const,
            },
          }
        : null,
    (request) => {
      if (request.method !== "PATCH" || request.path !== base) {
        return null;
      }
      if (state.environmentDeleted) {
        return notFound;
      }
      state.mutations.push({ kind: "rename-environment", request });
      if (input.ignoreEnvironmentMutations !== true) {
        const body = request.body as {
          readonly statement: WireDistributedEnvironmentStatement;
          readonly manifest: WireDistributedManifest;
        };
        state.envStatement = distributed(body.statement, input.owner, "author");
        state.manifest = distributed(body.manifest, input.owner, "issuer");
      }
      return { status: 204, bodyText: "" };
    },
    async (request) => {
      if (request.method !== "DELETE" || request.path !== base) {
        return null;
      }
      const body = request.body as {
        readonly parentHeadHashHex: string;
        readonly entry: ChainEntry;
      };
      const headHashHex = state.chainHashes[state.chainHashes.length - 1];
      if (body.parentHeadHashHex !== headHashHex) {
        return {
          status: 409,
          json: {
            _tag: "ChainHeadConflict",
            currentHeadSeq: state.chainEntries.length,
            currentHeadHashHex: headHashHex,
          },
        };
      }
      state.mutations.push({ kind: "remove-environment", request });
      if (input.ignoreEnvironmentMutations !== true) {
        await acceptAppendedEntry(
          input.chain.projectId,
          state.chainEntries,
          state.chainHashes,
          body.entry,
        );
        state.environmentDeleted = true;
        state.variables = [];
        state.tombstones = [];
        state.manifest = null;
      }
      return { status: 204, bodyText: "" };
    },
  ];
  return { state, handlers };
}
