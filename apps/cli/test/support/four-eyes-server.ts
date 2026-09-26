// Stateful mock for the four-eyes (PF1 K6) CLI tests: chain GET / append POST
// (with CAS injection), /auth/config, invite list, environment list, pull (no
// variables), acceptance of the rotate composite, dek_wraps (self-addressed
// fetch and registration capture). Shared by approval.test.ts /
// approval-propose.test.ts.
// The acceptance side is not verified (the CLI's verified chain is the source
// of truth for derivation — that's what the tests care about).

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";

import { acceptAppendedEntry, servedChainResponse } from "./chain-handler.ts";
import {
  type BuiltChain,
  environmentStatementFor,
  headOf,
  manifestFor,
  type TestUser,
  type WireCheckpointSnapshot,
  type WireDistributedManifest,
  type WireRecipientDek,
} from "./crypto.ts";
import { type MockHandler, type MockResponse, onRequest } from "./server.ts";

export interface FourEyesRotateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & {
    readonly op: "rotate_epoch";
    readonly payload: {
      readonly environmentId: string;
      readonly newEpoch: number;
      readonly reason: string;
      readonly dekCommitmentHex: string;
    };
  };
  readonly deks: readonly WrappedDek[];
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

export interface FourEyesServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: FourEyesRotateBody[];
  readonly registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[];
  readonly counters: { appendAttempts: number };
  /** The current chain (for assertions after appends). */
  readonly entries: ChainEntry[];
  readonly hashes: string[];
}

export async function makeFourEyesServer(input: {
  readonly built: BuiltChain;
  /** environment → current epoch and (actor-addressed) self wraps. */
  readonly environments: Readonly<
    Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>
  >;
  /** The issuer of rotate acceptances and the recipient of self-addressed wraps (= the actor). */
  readonly actor: TestUser;
  /** The author of environment statements (the member as of seq 1 — default: `actor`, same as the genesis creator). */
  readonly author?: TestUser;
  /** The `/auth/config` response (for server-grant tests). */
  readonly authConfig?: Record<string, unknown>;
  /** Invite list rows (for member-add tests). */
  readonly invitations?: readonly Record<string, unknown>[];
  /** Injected response for chain appends (e.g. 409). undefined = accept. */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** When onAppend injects, replaces the subsequent chain with this shape (a concurrent append). */
  readonly chainAfterConflict?: BuiltChain;
}): Promise<FourEyesServerState> {
  const actor = input.actor;
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: FourEyesRotateBody[] = [];
  const registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[] = [];
  const counters = { appendAttempts: 0 };
  const environments = input.environments;
  const manifests = new Map<string, WireDistributedManifest>();
  const checkpointSnapshots = new Map<string, WireCheckpointSnapshot>();
  const listedStatements = await Promise.all(
    Object.keys(environments).map((environmentId) =>
      environmentStatementFor({
        projectId,
        environmentId,
        name: environmentId,
        author: input.author ?? actor,
        head: headOf(input.built, 1),
      }),
    ),
  );
  const environmentRoute = (suffix: string) =>
    new RegExp(`^/projects/${projectId}/environments/([^/]+)/${suffix}$`);

  const handlers: MockHandler[] = [
    onRequest("GET", "/auth/config", () => ({
      status: 200,
      json: input.authConfig ?? { githubClientId: "dummy-client-id" },
    })),
    onRequest("GET", `/projects/${projectId}/chain`, () =>
      servedChainResponse(projectId, entries, hashes),
    ),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const injected = input.onAppend?.(counters.appendAttempts);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        if (input.chainAfterConflict !== undefined) {
          entries.splice(0, entries.length, ...input.chainAfterConflict.entries);
          hashes.splice(0, hashes.length, ...input.chainAfterConflict.hashes);
        }
        return injected;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appendedEntries.push(body.entry);
      return acceptAppendedEntry(projectId, entries, hashes, body.entry);
    },
    onRequest("GET", `/projects/${projectId}/invites`, () => ({
      status: 200,
      json: { invitations: input.invitations ?? [] },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: environments[statement.environmentId]?.currentEpoch ?? 1,
          statement,
        })),
      },
    })),
    async (request) => {
      const match = environmentRoute("pull").exec(request.path);
      if (match === null || request.method !== "GET") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const statement = listedStatements.find((item) => item.environmentId === environmentId);
      let manifest = manifests.get(environmentId);
      if (manifest === undefined && statement !== undefined) {
        manifest = await manifestFor({
          projectId,
          environmentId,
          epoch: environment.currentEpoch,
          issuer: actor,
          head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
          envStatement: statement,
          statements: [],
        });
        manifests.set(environmentId, manifest);
      }
      const checkpointSnapshot = checkpointSnapshots.get(environmentId);
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: environment.currentEpoch,
          statement,
          variables: [],
          deletedVariables: [],
          deks: environment.deks,
          manifest,
          ...(checkpointSnapshot === undefined ? {} : { checkpointSnapshot }),
        },
      };
    },
    async (request) => {
      const match = environmentRoute("rotate").exec(request.path);
      if (match === null || request.method !== "POST") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as FourEyesRotateBody;
      rotateBodies.push(body);
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      checkpointSnapshots.set(environmentId, {
        chainSeq: entries.length,
        entryHashHex: hashes[hashes.length - 1] ?? "",
        values: [],
      });
      environment.currentEpoch = body.entry.payload.newEpoch;
      manifests.set(environmentId, {
        ...body.manifest,
        issuerUserId: actor.userId,
        issuerKeyFingerprintHex: actor.fingerprintHex,
      });
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== actor.userId) {
          continue;
        }
        environment.deks.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signatureHex: wrap.signatureHex,
          signerUserId: actor.userId,
          signerKeyFingerprintHex: actor.fingerprintHex,
        });
      }
      return {
        status: 200,
        json: {
          environmentId,
          currentEpoch: environment.currentEpoch,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
    (request) => {
      const match = environmentRoute("deks").exec(request.path);
      if (match === null) {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      if (request.method === "GET") {
        return { status: 200, json: { deks: environment.deks } };
      }
      if (request.method === "POST") {
        const body = request.body as { readonly deks: readonly WrappedDek[] };
        registerBodies.push({ environmentId, deks: body.deks });
        return { status: 204 };
      }
      return null;
    },
  ];
  return { handlers, appendedEntries, rotateBodies, registerBodies, counters, entries, hashes };
}
