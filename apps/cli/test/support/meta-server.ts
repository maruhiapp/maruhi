// Test "honest in-memory environment" handlers that accept meta operations
// (declaration create, activation, removal, and the environment's own rename
// / deletion) and advance the state. Lets the
// schema import (serial registration of many variables — pins down the O(N)
// round trips) and var rm (transition to tombstone + the 1-E′ confirmation)
// tests run without hand-editing the echo base on every acceptance.
//
// Acceptance stores the client-signed statement / manifest verbatim and
// distributes it with author / issuer info (the owner) attached — verification
// (§6.3) is done by the client implementation (this mock only keeps the wire
// shape consistent).

import { chainHandlerOf, deksHandlerOf } from "./chain-handler.ts";
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

/** The environment state the mock advances (exposed for assertions). */
export interface MetaEnvironmentState {
  /** The environment's latest statement (advanced by rename / deletion). */
  envStatement: WireDistributedEnvironmentStatement;
  /** true once a deletion was accepted (the pulls answer 404; the list keeps the tombstone — §12-4). */
  environmentDeleted: boolean;
  variables: WireDistributedVariableStatement[];
  tombstones: WireDistributedVariableStatement[];
  /** The latest accepted manifest (null = still serving the initial form). */
  manifest: WireDistributedManifest | null;
  /** Accepted meta-operation requests (for assertions — with kind). */
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
  /** Self-addressed DEK wrap (needed for activation's value push; omitted = deks not wired). */
  readonly wrap?: WireRecipientDek;
  /** Accepts removals (DELETE) without advancing state (reproduces the 1-E′ failure path). */
  readonly ignoreRemovals?: boolean;
  /** Accepts environment renames / deletions without advancing state (the 1-E′ failure path). */
  readonly ignoreEnvironmentMutations?: boolean;
}

interface MutationBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value?: unknown;
  readonly manifest: WireDistributedManifest;
}

/** Copies into the distributed form with author / issuer info attached (reproduces the server's acceptance behavior). */
function distributed<T>(record: T, owner: TestUser, kind: "author" | "issuer"): T {
  return {
    ...record,
    [`${kind}UserId`]: owner.userId,
    [`${kind}KeyFingerprintHex`]: owner.fingerprintHex,
  };
}

/**
 * Builds a stateful mock environment: metadata pulls reflect every accepted
 * create / activate / remove composite, so multi-variable serial flows
 * (schema import) and deletion confirmation (var rm) verify end to end.
 */
export function makeMetaEnvironmentServer(input: MetaEnvironmentServerInput): {
  readonly state: MetaEnvironmentState;
  readonly handlers: readonly MockHandler[];
} {
  const state: MetaEnvironmentState = {
    envStatement: input.envStatement,
    environmentDeleted: false,
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

  const acceptStatement = (body: MutationBody): void => {
    const accepted = distributed(body.statement, input.owner, "author");
    state.variables = [
      ...state.variables.filter((entry) => entry.variableId !== accepted.variableId),
      accepted,
    ];
    state.manifest = distributed(body.manifest, input.owner, "issuer");
  };

  const handlers: MockHandler[] = [
    // Chain distribution (full length)
    chainHandlerOf(input.chain),
    // Self-addressed DEK (activation's value push; stays 404 if wrap is not wired)
    ...(input.wrap === undefined
      ? []
      : [deksHandlerOf(input.chain.projectId, input.environmentId, [input.wrap])]),
    // Metadata-only pull (§12-7 — declared entries are mixed into variables)
    async (request) => {
      if (request.method !== "GET" || request.path !== `${base}/pull/metadata`) {
        return null;
      }
      if (state.environmentDeleted) {
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
    // Variable creation (value attached / declared — §12-5)
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
    // activation (declared → active — §12-5)
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
    // Removal (transition to tombstone — §12-5)
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
    // The value pull of a deleted environment (§12-4 — 404; a live one is left to other handlers)
    (request) =>
      request.method === "GET" && request.path === `${base}/pull` && state.environmentDeleted
        ? notFound
        : null,
    // The environment list (deleted environments stay listed with their tombstone statement — §12-4)
    (request) =>
      request.method === "GET" && request.path === list
        ? {
            status: 200,
            json: {
              environments: [
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
    // Environment rename (statement + manifest — §12-4)
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
    // Environment deletion (tombstone + cascade — §12-4)
    (request) => {
      if (request.method !== "DELETE" || request.path !== base) {
        return null;
      }
      if (state.environmentDeleted) {
        return notFound;
      }
      state.mutations.push({ kind: "remove-environment", request });
      if (input.ignoreEnvironmentMutations !== true) {
        const body = request.body as { readonly statement: WireDistributedEnvironmentStatement };
        state.envStatement = distributed(body.statement, input.owner, "author");
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
