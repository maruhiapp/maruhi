import {
  type BuiltChain,
  distributedManifest,
  type GeneratedIdentity,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
} from "@maruhi/test-kit";

import { chainHandlerOf, deksHandlerOf } from "./chain-handler.ts";
import { type MockHandler, type MockRequest, onEndpoint } from "./server.ts";

export interface StoredVariable {
  readonly variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

export interface ValueEnvironmentState {
  variables: StoredVariable[];
  declared: WireDistributedVariableStatement[];
  manifest: WireDistributedManifest | null;
  writes: { kind: "create" | "version"; request: MockRequest }[];
  history: Map<string, { value: WireDistributedValue; sameValueAs?: number }[]>;
}

export interface ValueEnvironmentServerInput {
  readonly chain: BuiltChain;
  readonly owner: GeneratedIdentity;
  readonly environmentId: string;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly wrap: WireRecipientDek;
  readonly currentEpoch?: number;
  readonly wraps?: readonly WireRecipientDek[];
  readonly initialVariables?: readonly StoredVariable[];
  readonly initialDeclared?: readonly WireDistributedVariableStatement[];
  readonly initialHistory?: ReadonlyMap<string, readonly WireDistributedValue[]>;
  readonly flagsIfCurrent?: (variableId: string, version: number) => number;
  readonly tamperRange?: (values: readonly WireDistributedValue[]) => WireDistributedValue[];
}

export function makeValueEnvironmentServer(input: ValueEnvironmentServerInput): {
  readonly state: ValueEnvironmentState;
  readonly handlers: readonly MockHandler[];
} {
  const state: ValueEnvironmentState = {
    variables: [...(input.initialVariables ?? [])],
    declared: [...(input.initialDeclared ?? [])],
    manifest: null,
    writes: [],
    history: new Map(
      (input.initialVariables ?? []).map((entry) => [
        entry.variableId,
        (input.initialHistory?.get(entry.variableId) ?? [entry.value]).map((value) => ({ value })),
      ]),
    ),
  };
  const projectId = input.chain.projectId;
  const environmentId = input.environmentId;
  const head = headOf(input.chain, input.chain.entries.length);

  const distributedValue = (value: WireEncryptedPayload): WireDistributedValue => ({
    ...value,
    writerUserId: input.owner.userId,
    writerKeyFingerprintHex: input.owner.fingerprintHex,
  });
  const currentEpoch = input.currentEpoch ?? 1;
  const wraps = input.wraps ?? [input.wrap];
  const manifest = async (): Promise<WireDistributedManifest> =>
    state.manifest ??
    distributedManifest({
      projectId: input.chain.projectId,
      environmentId: input.environmentId,
      epoch: currentEpoch,
      issuer: input.owner,
      head,
      envStatement: input.envStatement,
      statements: [...state.variables.map((entry) => entry.statement), ...state.declared],
    });

  const variableNotFound = (variableId: string) =>
    ({ status: 404, json: { _tag: "VariableNotFound", variableId } }) as const;

  const handlers: MockHandler[] = [
    chainHandlerOf(input.chain),
    deksHandlerOf(projectId, environmentId, wraps),
    onEndpoint("variables.pull", { projectId, environmentId }, async () => ({
      status: 200,
      json: {
        environmentId,
        currentEpoch,
        statement: input.envStatement,
        variables: state.variables.map((entry) => ({
          variableId: entry.variableId,
          statement: entry.statement,
          value: entry.value,
        })),
        deletedVariables: [],
        ...(state.declared.length === 0 ? {} : { declaredVariables: state.declared }),
        deks: wraps,
        manifest: await manifest(),
        schemaPolicy: "enabled" as const,
      },
    })),
    onEndpoint("variables.pullMetadata", { projectId, environmentId }, async () => ({
      status: 200,
      json: {
        environmentId,
        currentEpoch,
        statement: input.envStatement,
        variables: [...state.variables.map((entry) => entry.statement), ...state.declared],
        deletedVariables: [],
        manifest: await manifest(),
        schemaPolicy: "enabled" as const,
      },
    })),
    onEndpoint("variables.create", { projectId, environmentId }, (request) => {
      state.writes.push({ kind: "create", request });
      const body = request.body;
      if (!("value" in body)) {
        throw new Error("value-env: this server takes a create with a value only");
      }
      const statement = {
        ...body.statement,
        authorUserId: input.owner.userId,
        authorKeyFingerprintHex: input.owner.fingerprintHex,
      };
      state.variables = [
        ...state.variables.filter((entry) => entry.variableId !== statement.variableId),
        { variableId: statement.variableId, statement, value: distributedValue(body.value) },
      ];
      state.history.set(statement.variableId, [{ value: distributedValue(body.value) }]);
      state.manifest = {
        ...body.manifest,
        issuerUserId: input.owner.userId,
        issuerKeyFingerprintHex: input.owner.fingerprintHex,
      };
      return {
        status: 200,
        json: { variableId: statement.variableId, version: 1, epoch: currentEpoch },
      };
    }),
    onEndpoint("variables.push", { projectId, environmentId }, (request) => {
      const { variableId } = request.params;
      const stored = state.variables.find((entry) => entry.variableId === variableId);
      if (stored === undefined) {
        return variableNotFound(variableId);
      }
      state.writes.push({ kind: "version", request });
      const body = request.body;
      stored.value = distributedValue(body.value);
      state.history.set(variableId, [
        ...(state.history.get(variableId) ?? []),
        {
          value: stored.value,
          ...(body.sameValueAs === undefined ? {} : { sameValueAs: body.sameValueAs }),
        },
      ]);
      return {
        status: 200,
        json: { variableId, version: body.value.aad.version, epoch: currentEpoch },
      };
    }),
    onEndpoint("variables.history", { projectId, environmentId }, (request) => {
      const { variableId } = request.params;
      const versions = state.history.get(variableId);
      if (versions === undefined) {
        return variableNotFound(variableId);
      }
      return {
        status: 200,
        json: {
          variableId,
          versions: versions.map(({ value, sameValueAs }) => ({
            version: value.aad.version,
            epoch: value.aad.epoch,
            writerUserId: value.writerUserId,
            writerKeyFingerprintHex: value.writerKeyFingerprintHex,
            pushedAtMs: 1_790_000_000_000 + value.aad.version * 60_000,
            ...(sameValueAs === undefined ? {} : { sameValueAs }),
            flagsIfCurrent: input.flagsIfCurrent?.(variableId, value.aad.version) ?? 0,
          })),
        },
      };
    }),
    onEndpoint("variables.versionValues", { projectId, environmentId }, (request) => {
      const { variableId } = request.params;
      const versions = state.history.get(variableId);
      if (versions === undefined) {
        return variableNotFound(variableId);
      }
      const fromVersion = Number(request.query["fromVersion"]);
      const selected = versions
        .map((entry) => entry.value)
        .filter((value) => value.aad.version >= fromVersion)
        .slice(0, 100);
      return {
        status: 200,
        json: {
          variableId,
          latestVersion: versions.at(-1)?.value.aad.version ?? 0,
          values: input.tamperRange?.(selected) ?? selected,
        },
      };
    }),
  ];
  return { state, handlers };
}
