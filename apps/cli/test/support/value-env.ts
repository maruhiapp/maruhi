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
import type { MockHandler, MockRequest } from "./server.ts";

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
}

export interface ValueEnvironmentServerInput {
  readonly chain: BuiltChain;
  readonly owner: TestUser;
  readonly environmentId: string;
  readonly envStatement: WireDistributedEnvironmentStatement;
  /** Self-addressed DEK wrap (epoch 1). */
  readonly wrap: WireRecipientDek;
  readonly initialVariables?: readonly StoredVariable[];
  readonly initialDeclared?: readonly WireDistributedVariableStatement[];
}

interface CreateBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value: WireEncryptedPayload;
  readonly manifest: WireDistributedManifest;
}

interface VersionBody {
  readonly value: WireEncryptedPayload;
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
  };
  const base = `/projects/${input.chain.projectId}/environments/${input.environmentId}`;
  const versionPattern = new RegExp(`^${base}/variables/([^/]+)/versions$`);
  const head = headOf(input.chain, input.chain.entries.length);

  const distributedValue = (value: WireEncryptedPayload): WireDistributedValue => ({
    ...value,
    writerUserId: input.owner.userId,
    writerKeyFingerprintHex: input.owner.fingerprintHex,
  });
  const manifest = async (): Promise<WireDistributedManifest> =>
    state.manifest ??
    manifestFor({
      projectId: input.chain.projectId,
      environmentId: input.environmentId,
      epoch: 1,
      issuer: input.owner,
      head,
      envStatement: input.envStatement,
      statements: [...state.variables.map((entry) => entry.statement), ...state.declared],
    });

  const handlers: MockHandler[] = [
    chainHandlerOf(input.chain),
    deksHandlerOf(input.chain.projectId, input.environmentId, [input.wrap]),
    async (request) => {
      if (request.method !== "GET" || request.path !== `${base}/pull`) {
        return null;
      }
      return {
        status: 200,
        json: {
          environmentId: input.environmentId,
          currentEpoch: 1,
          statement: input.envStatement,
          variables: state.variables.map((entry) => ({
            variableId: entry.variableId,
            statement: entry.statement,
            value: entry.value,
          })),
          deletedVariables: [],
          ...(state.declared.length === 0 ? {} : { declaredVariables: state.declared }),
          deks: [input.wrap],
          manifest: await manifest(),
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
          currentEpoch: 1,
          statement: input.envStatement,
          variables: [...state.variables.map((entry) => entry.statement), ...state.declared],
          deletedVariables: [],
          manifest: await manifest(),
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
      state.manifest = {
        ...body.manifest,
        issuerUserId: input.owner.userId,
        issuerKeyFingerprintHex: input.owner.fingerprintHex,
      };
      return {
        status: 200,
        json: { variableId: statement.variableId, version: 1, epoch: 1 },
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
      return {
        status: 200,
        json: { variableId, version: body.value.aad.version, epoch: 1 },
      };
    },
  ];
  return { state, handlers };
}
