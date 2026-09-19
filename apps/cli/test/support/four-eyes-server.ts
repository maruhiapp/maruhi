// 四眼(PF1 K6)の CLI テスト用の状態つきモック: チェーン GET / 追記 POST(CAS 差し込み)・
// /auth/config・招待一覧・環境一覧・pull(変数なし)・rotate 複合の受理・dek_wraps
// (自分宛の取得と登録の捕捉)。approval.test.ts / approval-propose.test.ts が共有する。
// 受理面の検証は行わない(CLI の検証済みチェーンが導出の真実源 — テストの関心)。

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";

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
  /** 現在のチェーン(追記後の検査用)。 */
  readonly entries: ChainEntry[];
  readonly hashes: string[];
}

export async function makeFourEyesServer(input: {
  readonly built: BuiltChain;
  /** 環境 → 現エポックと(実行者宛の)自分宛ラップ。 */
  readonly environments: Readonly<
    Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>
  >;
  /** rotate 受理の issuer と自分宛ラップの受信者(= 実行者)。 */
  readonly actor: TestUser;
  /** 環境ステートメントの author(seq 1 時点のメンバー — 既定 = genesis の作成者と同じ `actor`)。 */
  readonly author?: TestUser;
  /** `/auth/config` の応答(server grant のテスト)。 */
  readonly authConfig?: Record<string, unknown>;
  /** 招待一覧の行(member add のテスト)。 */
  readonly invitations?: readonly Record<string, unknown>[];
  /** チェーン追記への差し込み(409 等)。undefined = 受理。 */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** onAppend の差し込み時に、以後のチェーンをこの形へ差し替える(並行追記)。 */
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
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
    })),
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
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
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
