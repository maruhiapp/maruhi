import type { ChainEntry } from "@maruhi/crypto";
import {
  type BuiltChain,
  distributedManifest,
  type GeneratedIdentity,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireEnvironmentManifest,
  type WireRecipientDek,
  type WireVariableMetaStatement,
} from "@maruhi/test-kit";

import {
  acceptAppendedEntry,
  deksHandlerOf,
  lastHashOf,
  servedChainResponse,
} from "./chain-handler.ts";
import { type MockHandler, type MockRequest, onEndpoint } from "./server.ts";

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
  readonly owner: GeneratedIdentity;
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
  readonly statement: WireVariableMetaStatement;
  readonly manifest: WireEnvironmentManifest;
}

function authored<T>(
  statement: T,
  owner: GeneratedIdentity,
): T & { readonly authorUserId: string; readonly authorKeyFingerprintHex: string } {
  return {
    ...statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  };
}

function issued<T>(
  manifest: T,
  owner: GeneratedIdentity,
): T & { readonly issuerUserId: string; readonly issuerKeyFingerprintHex: string } {
  return {
    ...manifest,
    issuerUserId: owner.userId,
    issuerKeyFingerprintHex: owner.fingerprintHex,
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
  const projectId = input.chain.projectId;
  const environmentId = input.environmentId;
  const notFound = {
    status: 404,
    json: { _tag: "EnvironmentNotFound", environmentId },
  } as const;
  const hidden = (): boolean => state.environmentDeleted && input.resurrectDeleted !== true;

  const acceptStatement = (body: MutationBody): void => {
    const accepted = authored(body.statement, input.owner);
    state.variables = [
      ...state.variables.filter((entry) => entry.variableId !== accepted.variableId),
      accepted,
    ];
    state.manifest = issued(body.manifest, input.owner);
  };

  const handlers: MockHandler[] = [
    onEndpoint("membership.get", { projectId }, () =>
      servedChainResponse(projectId, state.chainEntries, state.chainHashes),
    ),
    ...(input.wrap === undefined ? [] : [deksHandlerOf(projectId, environmentId, [input.wrap])]),
    onEndpoint("variables.pullMetadata", { projectId, environmentId }, async () => {
      if (hidden()) {
        return notFound;
      }
      const manifest =
        state.manifest ??
        (await distributedManifest({
          projectId,
          environmentId,
          epoch: 1,
          issuer: input.owner,
          head: headOf(input.chain, input.chain.entries.length),
          envStatement: state.envStatement,
          statements: [...state.variables, ...state.tombstones],
        }));
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: 1,
          statement: state.envStatement,
          variables: state.variables,
          deletedVariables: state.tombstones,
          manifest,
          schemaPolicy: "enabled" as const,
        },
      };
    }),
    onEndpoint("variables.create", { projectId, environmentId }, (request) => {
      state.mutations.push({ kind: "create", request });
      const body = request.body;
      acceptStatement(body);
      return {
        status: 200,
        json: {
          variableId: body.statement.variableId,
          version: "value" in body ? 1 : 0,
          epoch: 1,
        },
      };
    }),
    onEndpoint("variables.activate", { projectId, environmentId }, (request) => {
      state.mutations.push({ kind: "activate", request });
      acceptStatement(request.body);
      return {
        status: 200,
        json: { variableId: request.params.variableId, version: 1, epoch: 1 },
      };
    }),
    onEndpoint("variables.remove", { projectId, environmentId }, (request) => {
      state.mutations.push({ kind: "remove", request });
      if (input.ignoreRemovals !== true) {
        const body = request.body;
        const accepted = authored(body.statement, input.owner);
        state.variables = state.variables.filter(
          (entry) => entry.variableId !== accepted.variableId,
        );
        state.tombstones = [
          ...state.tombstones.filter((entry) => entry.variableId !== accepted.variableId),
          accepted,
        ];
        state.manifest = issued(body.manifest, input.owner);
      }
      return { status: 204 };
    }),
    onEndpoint("variables.pull", { projectId, environmentId }, () => (hidden() ? notFound : null)),
    onEndpoint("environments.list", { projectId }, () => ({
      status: 200,
      json: {
        environments: hidden()
          ? []
          : [{ environmentId, currentEpoch: 1, statement: state.envStatement }],
        schemaPolicy: "enabled" as const,
      },
    })),
    onEndpoint("environments.rename", { projectId, environmentId }, (request) => {
      if (state.environmentDeleted) {
        return notFound;
      }
      state.mutations.push({ kind: "rename-environment", request });
      if (input.ignoreEnvironmentMutations !== true) {
        const body = request.body;
        state.envStatement = authored(body.statement, input.owner);
        state.manifest = issued(body.manifest, input.owner);
      }
      return { status: 204 };
    }),
    onEndpoint("environments.remove", { projectId, environmentId }, async (request) => {
      const body = request.body;
      const headHashHex = lastHashOf(state.chainHashes);
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
          projectId,
          state.chainEntries,
          state.chainHashes,
          body.entry as ChainEntry,
        );
        state.environmentDeleted = true;
        state.variables = [];
        state.tombstones = [];
        state.manifest = null;
      }
      return { status: 204 };
    }),
  ];
  return { state, handlers };
}
