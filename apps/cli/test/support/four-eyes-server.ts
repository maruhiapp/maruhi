import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import {
  type BuiltChain,
  distributedEnvironmentStatement,
  distributedManifest,
  type GeneratedIdentity,
  headOf,
  type WireCheckpointSnapshot,
  type WireDistributedManifest,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import type { ApiPayload, ApiSuccess } from "@maruhi/test-kit/api";

import {
  acceptAppendedEntry,
  type AppendInjection,
  injectedAppendResponse,
  lastHashOf,
  servedChainResponse,
} from "./chain-handler.ts";
import type { WireRotateBody } from "./env-rotate.ts";
import { type MockHandler, onEndpoint } from "./server.ts";

type RegisteredDeks = ApiPayload<"deks.register">["deks"];

export interface FourEyesServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: WireRotateBody[];
  readonly registerBodies: { environmentId: string; deks: RegisteredDeks }[];
  readonly counters: { appendAttempts: number };
  readonly entries: ChainEntry[];
  readonly hashes: string[];
}

export async function makeFourEyesServer(
  input: AppendInjection & {
    readonly built: BuiltChain;
    readonly environments: Readonly<
      Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>
    >;
    readonly actor: GeneratedIdentity;
    readonly author?: GeneratedIdentity;
    readonly authConfig?: ApiSuccess<"auth.authConfig">;
    readonly invitations?: ApiSuccess<"invites.list">["invitations"];
  },
): Promise<FourEyesServerState> {
  const actor = input.actor;
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: WireRotateBody[] = [];
  const registerBodies: { environmentId: string; deks: RegisteredDeks }[] = [];
  const counters = { appendAttempts: 0 };
  const environments = input.environments;
  const manifests = new Map<string, WireDistributedManifest>();
  const checkpointSnapshots = new Map<string, WireCheckpointSnapshot>();
  const listedStatements = await Promise.all(
    Object.keys(environments).map((environmentId) =>
      distributedEnvironmentStatement({
        projectId,
        environmentId,
        name: environmentId,
        author: input.author ?? actor,
        head: headOf(input.built, 1),
      }),
    ),
  );
  const handlers: MockHandler[] = [
    onEndpoint("auth.authConfig", () => ({
      status: 200,
      json: input.authConfig ?? { githubClientId: "dummy-client-id", signupPolicy: "open" },
    })),
    onEndpoint("membership.get", { projectId }, () =>
      servedChainResponse(projectId, entries, hashes),
    ),
    onEndpoint("membership.append", { projectId }, async (request) => {
      const injected = injectedAppendResponse(input, counters.appendAttempts, entries, hashes);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        return injected;
      }
      const entry = request.body.entry as ChainEntry;
      appendedEntries.push(entry);
      return acceptAppendedEntry(projectId, entries, hashes, entry);
    }),
    onEndpoint("invites.list", { projectId }, () => ({
      status: 200,
      json: { invitations: input.invitations ?? [] },
    })),
    onEndpoint("environments.list", { projectId }, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: environments[statement.environmentId]?.currentEpoch ?? 1,
          statement,
        })),
        schemaPolicy: "enabled",
      },
    })),
    onEndpoint("variables.pull", { projectId }, async (request) => {
      const { environmentId } = request.params;
      const environment = environments[environmentId];
      const statement = listedStatements.find((item) => item.environmentId === environmentId);
      if (environment === undefined || statement === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      let manifest = manifests.get(environmentId);
      if (manifest === undefined) {
        manifest = await distributedManifest({
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
          schemaPolicy: "enabled" as const,
        },
      };
    }),
    onEndpoint("environments.rotate", { projectId }, async (request) => {
      const { environmentId } = request.params;
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as WireRotateBody;
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
          recipientEncPubHex: wrap.recipientEncPubHex,
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
          headHashHex: lastHashOf(hashes),
        },
      };
    }),
    onEndpoint("deks.listMine", { projectId }, (request) => {
      const { environmentId } = request.params;
      const environment = environments[environmentId];
      return environment === undefined
        ? { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } }
        : { status: 200, json: { deks: environment.deks } };
    }),
    onEndpoint("deks.register", { projectId }, (request) => {
      const { environmentId } = request.params;
      if (environments[environmentId] === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      registerBodies.push({ environmentId, deks: request.body.deks });
      return { status: 204 };
    }),
  ];
  return { handlers, appendedEntries, rotateBodies, registerBodies, counters, entries, hashes };
}
