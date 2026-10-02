// An "honest in-memory environment" with values (for tests): accepts pulls
// with values, metadata-only pulls, variable creation (value attached), and
// new-version pushes to existing variables, advancing the state each time.
// Lets `maruhi sync` tests exercise the pull from the source environment and
// the push to the receipt environment (create, then new versions after that)
// without hand-editing responses per acceptance.
//
// Same stance as meta-server.ts (meta ops only): the client-signed statements,
// values, and manifests are stored verbatim and distributed with author /
// writer / issuer attribution attached. Verification (§6.3) is done by the
// client implementation (this mock only keeps the wire shape consistent).

import { chainHandlerOf, deksHandlerOf } from "./chain-handler.ts";
import {
  type BuiltChain,
  headOf,
  manifestFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
} from "./crypto.ts";
import type { MockHandler, MockRequest, MockResponse } from "./server.ts";

/** One distributed variable (statement + latest version's value). */
export interface StoredVariable {
  readonly variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

/** The environment state the mock advances (exposed for assertions). */
export interface ValueEnvironmentState {
  variables: StoredVariable[];
  /** Valueless declarations (declared — in §12-7 they're distributed separately as declaredVariables). */
  declared: WireDistributedVariableStatement[];
  manifest: WireDistributedManifest | null;
  /** Accepted writes (for assertions — with kind). */
  writes: { kind: "create" | "version"; request: MockRequest }[];
  /**
   * Every stored version per variable, ascending (the version history /
   * value range — AUTH_SPEC §12-7, VH), with the lineage each push declared.
   */
  history: Map<string, { value: WireDistributedValue; sameValueAs?: number }[]>;
}

export interface ValueEnvironmentServerInput {
  readonly chain: BuiltChain;
  readonly owner: TestUser;
  readonly environmentId: string;
  readonly envStatement: WireDistributedEnvironmentStatement;
  /** Self-addressed DEK wrap of the current epoch (epoch 1 unless `currentEpoch` says otherwise). */
  readonly wrap: WireRecipientDek;
  /** The environment's current epoch (default 1 — the chain must carry the matching rotations). */
  readonly currentEpoch?: number;
  /** Every wrap addressed to the device (default: `wrap` alone — a device missing an older epoch's wrap lists only the current one). */
  readonly wraps?: readonly WireRecipientDek[];
  readonly initialVariables?: readonly StoredVariable[];
  readonly initialDeclared?: readonly WireDistributedVariableStatement[];
  /**
   * The full version chain of some variables (ascending — the last entry
   * must be that variable's `initialVariables` value). Without it a
   * variable's history is just its current value.
   */
  readonly initialHistory?: ReadonlyMap<string, readonly WireDistributedValue[]>;
  /** The server-derived flagsIfCurrent per (variable, version) (default 0). */
  readonly flagsIfCurrent?: (variableId: string, version: number) => number;
  /** Rewrites a value-range response before it is sent (forgery tests). */
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

/**
 * Builds a stateful mock environment serving values: pulls reflect every
 * accepted create and every accepted new version, so a command that reads,
 * writes, and reads again (sync's receipt) verifies end to end.
 */
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
    manifestFor({
      projectId: input.chain.projectId,
      environmentId: input.environmentId,
      epoch: currentEpoch,
      issuer: input.owner,
      head,
      envStatement: input.envStatement,
      statements: [...state.variables.map((entry) => entry.statement), ...state.declared],
    });

  // The GET side of the version resource (VH): the matched variable's
  // stored versions, a 404 for an unknown one, or null for another route
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
