// `maruhi rotation list|dismiss`(AUDIT_SPEC §4.1 / §7 — Wave 2 B2)と
// 未収束ローテーション義務の常時警告 / project verify 詳細の統合テスト。
//
// 固定する性質:
//  1. list はサーバーの導出ビューを表示し、変数名は検証済みメタステートメント
//     (削除済み変数は tombstone の name — §4.2)から解決する。識別子のみの
//     応答に名前を混ぜない(TCB 規律 — AUDIT_SPEC §7)
//  2. dismiss は単一対 / --all(--env で絞り込み・対単位の畳み込み)を
//     操作エンドポイントへ送り、404(有効フラグなし)は導線つきで報告する
//  3. 未収束のローテーション義務(義務エントリより後に現エポックが始まって
//     いない環境)はコマンドの同期後に常時警告される(収束済みなら出ない)。
//     project verify は同じ導出の詳細を表示する。案内は対象の現在状態に適応し
//     (再追加済みなら破壊的操作の再実行を勧めない)、削除済み環境の検証失敗は
//     注意のみでコマンドを失敗させない(チェーン検証は成功している)

import type { ChainEntry } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let target: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  target = await makeTestUser("user-target-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** 収束済みチェーン(remove の後に rotate 済み — 未収束警告なし)。 */
async function convergedChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: removeMemberOp(target) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
}

/** 未収束チェーン(remove の後に rotate がない — §7 の義務が宙に浮いている)。 */
async function unconvergedChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: addMemberOp(target, "member") },
    { actor: owner, operation: removeMemberOp(target) },
  ]);
}

interface WireFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
}

interface RotationServerState {
  readonly handlers: readonly MockHandler[];
  readonly dismissBodies: {
    readonly targets: readonly { environmentId: string; variableId: string }[];
  }[];
}

/** rotation フロー用のモック: チェーン・環境一覧・メタデータ pull・flags・dismissals。 */
async function makeRotationServer(input: {
  readonly built: BuiltChain;
  readonly flags: readonly WireFlag[];
  readonly currentEpoch?: number;
  /** dismissals への差し込み(undefined = 204 受理)。 */
  readonly onDismiss?: () => { status: number; json?: unknown } | undefined;
  /** メタデータ pull の可否(false = 404 — 名前解決の劣化経路)。 */
  readonly metadataAvailable?: boolean;
  /** 環境一覧 GET の可否(false = 500 — 削除済み環境検証の失敗経路)。 */
  readonly environmentsAvailable?: boolean;
}): Promise<RotationServerState> {
  const projectId = input.built.projectId;
  const currentEpoch = input.currentEpoch ?? 1;
  const dismissBodies: {
    readonly targets: readonly { environmentId: string; variableId: string }[];
  }[] = [];
  const envStatement: WireDistributedEnvironmentStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: headOf(input.built, 1),
  });
  const activeStatement: WireDistributedVariableStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: headOf(input.built, 1),
  });
  const deletedStatement: WireDistributedVariableStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "vdel",
    name: "DELETED_KEY",
    author: owner,
    head: headOf(input.built, 1),
    status: "deleted",
    metaVersion: 2,
  });

  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries: input.built.entries as readonly ChainEntry[],
        headSeq: input.built.entries.length,
        headHashHex: input.built.hashes[input.built.hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () =>
      input.environmentsAvailable === false
        ? { status: 500, json: { message: "injected environments failure" } }
        : {
            status: 200,
            json: {
              environments: [{ environmentId: ENV_ID, currentEpoch, statement: envStatement }],
            },
          },
    ),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull/metadata`, () =>
      input.metadataAvailable === false
        ? { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID } }
        : {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch,
              statement: envStatement,
              variables: [activeStatement],
              deletedVariables: [deletedStatement],
            },
          },
    ),
    onRequest("GET", `/projects/${projectId}/rotation/flags`, () => ({
      status: 200,
      json: { flags: input.flags },
    })),
    (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/rotation/dismissals`
      ) {
        return null;
      }
      const injected = input.onDismiss?.();
      if (injected !== undefined) {
        return injected;
      }
      dismissBodies.push(
        request.body as {
          readonly targets: readonly { environmentId: string; variableId: string }[];
        },
      );
      return { status: 204 };
    },
  ];
  return { handlers, dismissBodies };
}

async function startEnv(state: RotationServerState, projectId: string): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

function flagFor(overrides: Partial<WireFlag> & { readonly variableId: string }): WireFlag {
  return {
    environmentId: ENV_ID,
    basis: "readable",
    targetUserId: target.userId,
    recommendedAtMs: 1_700_000_000_000,
    triggerChainSeq: 4,
    ...overrides,
  };
}

describe("maruhi rotation list", () => {
  it("フラグを表示し、変数名を検証済みステートメント(tombstone 含む)から解決する", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [
        flagFor({ variableId: "va", basis: "read" }),
        flagFor({ variableId: "vdel", basis: "readable" }),
      ],
    });
    const env = await startEnv(state, built.projectId);

    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("要ローテーションフラグ: 2 件");
    // 名前解決: active はステートメント、削除済みは tombstone の name(§4.2)
    expect(logs).toContain("ALPHA(va)");
    expect(logs).toContain("DELETED_KEY(vdel)");
    expect(logs).toContain("確実に取得した(read)");
    expect(logs).toContain("取得可能だった(readable)");
    expect(logs).toContain(`member:${target.userId}`);
    // 解消の導線(push で解消 / 削除済みは dismiss)
    expect(logs).toContain("maruhi rotation dismiss");
    // 収束済みチェーンなので未収束警告は出ない
    expect(env.errors.join("\n")).not.toContain("未収束のローテーション義務");
  });

  it("メタデータを取得できない環境は識別子のまま表示へ劣化する(一覧自体は止めない)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "va", basis: "read" })],
      metadataAvailable: false,
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("va");
    expect(env.logs.join("\n")).not.toContain("ALPHA");
    expect(env.errors.join("\n")).toContain("検証済みメタデータを取得できません");
  });

  it("フラグが無ければその旨だけを表示する", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 2, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("現在有効な要ローテーションフラグはありません");
  });
});

describe("maruhi rotation dismiss", () => {
  it("単一対の取り下げを操作エンドポイントへ送る", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "vdel" })],
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss", "vdel", "--env", ENV_ID], env.layer)).toBe(0);
    expect(state.dismissBodies).toEqual([
      { targets: [{ environmentId: ENV_ID, variableId: "vdel" }] },
    ]);
    expect(env.logs.join("\n")).toContain("1 件の要ローテーションフラグを取り下げました");
  });

  it("--all は現在有効な全フラグを対単位に畳んで取り下げる(--env で絞り込み)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [
        // 同一対の複数フラグ(再削除 — 推奨時刻が異なる)は 1 対に畳む
        flagFor({ variableId: "va" }),
        flagFor({ variableId: "va", recommendedAtMs: 1_700_000_100_000 }),
        flagFor({ variableId: "vdel" }),
        // 別環境のフラグは --env の絞り込みで除外される
        flagFor({ variableId: "vother", environmentId: "env-other" }),
      ],
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss", "--all", "--env", ENV_ID], env.layer)).toBe(0);
    expect(state.dismissBodies).toEqual([
      {
        targets: [
          { environmentId: ENV_ID, variableId: "va" },
          { environmentId: ENV_ID, variableId: "vdel" },
        ],
      },
    ]);
    expect(env.logs.join("\n")).toContain("2 件の要ローテーションフラグを取り下げました");
  });

  it("有効フラグの無い対の 404 は導線つきで報告する(all-or-nothing の中止)", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 2,
      flags: [flagFor({ variableId: "va" })],
      onDismiss: () => ({
        status: 404,
        json: { _tag: "RotationFlagNotFound", environmentId: ENV_ID, variableId: "va" },
      }),
    });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss", "va", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("現在有効なフラグがありません");
    expect(errors).toContain("maruhi rotation list");
  });

  it("対象未指定(--all も対もなし)は使い方を案内する", async () => {
    const built = await convergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 2, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "dismiss"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("取り下げ対象を指定してください");
  });
});

describe("未収束ローテーション義務の常時警告(CRYPTO_SPEC §7 — B2)", () => {
  it("義務エントリより後に現エポックが始まっていない環境を、収束コマンドの案内つきで警告する", async () => {
    const built = await unconvergedChain();
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("未収束のローテーション義務");
    expect(errors).toContain(`member-removed(target=${target.userId}`);
    expect(errors).toContain(ENV_ID);
    // 行動可能な警告(B2 裁定): 収束コマンドを名指しする
    expect(errors).toContain(`maruhi member remove ${target.userId} の再実行`);
  });

  it("巻き戻された義務(対象が再追加済み)には破壊的操作の再実行を案内しない", async () => {
    // remove の後に同一鍵で再追加(ローテーションはまだ)— 義務は残るが、
    // member remove の再実行を案内すると現役メンバーを削除させてしまう
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("未収束のローテーション義務");
    expect(errors).toContain("対象は再追加済みです");
    expect(errors).toContain("maruhi env rotate");
    expect(errors).not.toContain("の再実行で収束します");
  });

  it("降格後に削除された対象へは change-role の再実行を案内しない(現メンバー限定の操作)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      {
        actor: owner,
        operation: {
          op: "change_role",
          payload: { targetUserId: target.userId, newRole: "reader" },
        },
      },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRotationServer({ built, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, built.projectId);
    expect(await runCli(["rotation", "list"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    // 降格義務の行は env rotate へ誘導(change-role は対象不在で再実行不能)
    expect(errors).toContain("role-demoted");
    expect(errors).toContain("対象は削除済みです");
    expect(errors).not.toContain("maruhi member change-role");
    // 削除義務の行は従来どおり member remove の再実行を案内する
    expect(errors).toContain(`maruhi member remove ${target.userId} の再実行`);
  });

  it("project verify は削除済み環境の検証失敗で失敗しない(注意を出して未収束判定だけ保留する)", async () => {
    const built = await unconvergedChain();
    const state = await makeRotationServer({
      built,
      currentEpoch: 1,
      flags: [],
      environmentsAvailable: false,
    });
    const env = await startEnv(state, built.projectId);
    // チェーン検証は成功しているので exit 0(Cursor bot 指摘 — 検証失敗は注意のみ)
    expect(await runCli(["project", "verify", "--project", built.projectId], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Chain verification OK");
    const errors = env.errors.join("\n");
    expect(errors).toContain("確定できません");
    expect(errors).not.toContain("未収束のローテーション義務:");
  });

  it("project verify は同じ導出の詳細を表示する(収束済みなら未収束なし)", async () => {
    const unconverged = await unconvergedChain();
    const state = await makeRotationServer({ built: unconverged, currentEpoch: 1, flags: [] });
    const env = await startEnv(state, unconverged.projectId);
    expect(await runCli(["project", "verify", "--project", unconverged.projectId], env.layer)).toBe(
      0,
    );
    expect(env.errors.join("\n")).toContain("Unconverged rotation mandate: member-removed");

    const converged = await convergedChain();
    const convergedState = await makeRotationServer({
      built: converged,
      currentEpoch: 2,
      flags: [],
    });
    const convergedEnv = await startEnv(convergedState, converged.projectId);
    expect(
      await runCli(["project", "verify", "--project", converged.projectId], convergedEnv.layer),
    ).toBe(0);
    expect(convergedEnv.logs.join("\n")).toContain("Rotation mandates: none unconverged");
  });
});
