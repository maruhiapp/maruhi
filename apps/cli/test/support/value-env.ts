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
import type { MockHandler, MockRequest, MockResponse } from "./server.ts";

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

interface CreateBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value: WireEncryptedPayload;
  readonly manifest: WireDistributedManifest;
}

interface VersionBody {
  readonly value: WireEncryptedPayload;
  readonly sameValueAs?: number;
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
  const base = `/projects/${input.chain.projectId}/environments/${input.environmentId}`;
  const versionPattern = new RegExp(`^${base}/variables/([^/]+)/versions$`);
  const valuesPattern = new RegExp(`^${base}/variables/([^/]+)/versions/values$`);
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

  type Found = {
    readonly variableId: string;
    readonly versions: readonly { value: WireDistributedValue; sameValueAs?: number }[];
  };
  const historyFor = (request: MockRequest, pattern: RegExp): Found | MockResponse | null => {
    const match = request.path.match(pattern);
    if (request.method !== "GET" || match === null) {
      return null;
    }
    const variableId = match[1] ?? "";
    const versions = state.history.get(variableId);
    return versions === undefined
      ? { status: 404, json: { _tag: "VariableNotFound", variableId } }
      : { variableId, versions };
  };

  const handlers: MockHandler[] = [
    chainHandlerOf(input.chain),
    deksHandlerOf(input.chain.projectId, input.environmentId, wraps),
    async (request) => {
      if (request.method !== "GET" || request.path !== `${base}/pull`) {
        return null;
      }
      return {
        status: 200,
        json: {
          environmentId: input.environmentId,
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
      };
    },
    async (request) => {
      if (request.method !== "GET" || request.path !== `${base}/pull/metadata`) {
        return null;
      }
      return {
        status: 200,
        json: {
          environmentId: input.environmentId,
          currentEpoch,
          statement: input.envStatement,
          variables: [...state.variables.map((entry) => entry.statement), ...state.declared],
          deletedVariables: [],
          manifest: await manifest(),
          schemaPolicy: "enabled" as const,
        },
      };
    },
    (request) => {
      if (request.method !== "POST" || request.path !== `${base}/variables`) {
        return null;
      }
      state.writes.push({ kind: "create", request });
      const body = request.body as CreateBody;
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
    },
    (request) => {
      const match = request.path.match(versionPattern);
      if (request.method !== "POST" || match === null) {
        return null;
      }
      const variableId = match[1] ?? "";
      const stored = state.variables.find((entry) => entry.variableId === variableId);
      if (stored === undefined) {
        return { status: 404, json: { _tag: "VariableNotFound" } };
      }
      state.writes.push({ kind: "version", request });
      const body = request.body as VersionBody;
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
    },
    (request) => {
      const found = historyFor(request, versionPattern);
      if (found === null || !("versions" in found)) {
        return found;
      }
      const { variableId, versions } = found;
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
    },
    (request) => {
      const found = historyFor(request, valuesPattern);
      if (found === null || !("versions" in found)) {
        return found;
      }
      const { variableId, versions } = found;
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
    },
  ];
  return { state, handlers };
}
