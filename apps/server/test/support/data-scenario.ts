// データプレーン統合テストの共有シナリオ(旧 data.test.ts の冒頭ヘルパの分割先)。
//
// fixture / varStatements は ESM の live binding としてエクスポートし、各テスト
// ファイルは registerDataScenario() で beforeEach(リセット + 再シード)を登録
// してから describe を書く。ヘルパの意味論は旧 data.test.ts と同一。

import { beforeEach, expect } from "vitest";

import type {
  WireEncryptedPayload,
  WireEnvironmentManifest,
  WireVariableMetaStatement,
} from "./data-crypto.ts";
import {
  createVariableStatement,
  encryptValue,
  metaSignedBytesHashOf,
  signMetaStatementAs,
  signValueAs,
} from "./data-crypto.ts";
import { makeDek, wrapDekForAll } from "./data-crypto.ts";
import type { DataFixture, EnvManifestState } from "./data-fixture.ts";
import {
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  setupDataProject,
  tokenOf,
} from "./data-fixture.ts";
import { queryProjectDo } from "./project-do.ts";

export const ENV = "env-app-0001";
export const VAR = "var-database-url";

export let fixture: DataFixture;

/** 変数ごとの最新ステートメント + author(rename / 削除の prev 連鎖の材料)。 */
export let varStatements: Map<
  string,
  { statement: WireVariableMetaStatement; authorUserId: string }
>;

/** 各テストファイルの冒頭で 1 回呼ぶ: フィクスチャの beforeEach を登録する。 */
export function registerDataScenario(): void {
  beforeEach(async () => {
    fixture = await setupDataProject();
    varStatements = new Map();
  });
}

export const token = (userId: string): string => tokenOf(fixture.tokens, userId);

/**
 * 変数のメタ操作(作成・rename・削除)に同梱するマニフェスト(§12-5)を、
 * 検証済みステートメントのハッシュから署名して返す(成功時は record で記録を
 * 進める)。issuer は操作の実行者と一致させること(§12-5 (1))。
 */
export async function manifestForStatement(
  statement: WireVariableMetaStatement,
  authorUserId: string,
  environmentId = ENV,
): Promise<{ manifest: WireEnvironmentManifest; record: () => void }> {
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId,
    issuerUserId: authorUserId,
    entry: {
      variableId: statement.variableId,
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, authorUserId),
    },
  });
  return { manifest, record: () => recordManifestState(environmentId, state) };
}

function recordManifestState(environmentId: string, state: EnvManifestState): void {
  fixture.manifests.set(environmentId, state);
}

/** 変数作成に同梱するステートメント(metaVersion 1)を署名し、記録する。 */
export async function variableStatementFor(
  authorUserId: string,
  variableId: string,
  name: string,
  environmentId = ENV,
): Promise<WireVariableMetaStatement> {
  return createVariableStatement({
    authorUserId,
    projectId,
    environmentId,
    variableId,
    name,
    head: fixture.head,
  });
}

/** レイアウト v2 のスキーマ欄(ワイヤ形 — required は boolean)。 */
export interface WireSchemaFields {
  readonly varType: "" | "string" | "number" | "boolean" | "url";
  readonly required: boolean;
  readonly description: string;
}

/** v2 ステートメントの運搬フィールド(layoutVersion 2 + スキーマ欄)。 */
export function v2Fields(schema: Partial<WireSchemaFields> = {}): {
  readonly layoutVersion: number;
  readonly varType: WireSchemaFields["varType"];
  readonly required: boolean;
  readonly description: string;
} {
  return {
    layoutVersion: 2,
    varType: schema.varType ?? "string",
    required: schema.required ?? true,
    description: schema.description ?? "",
  };
}

/** 変数の次ステートメント(rename / スキーマ再発行 / 削除 / activation)を記録済み最新から署名する。 */
export async function nextVariableStatement(input: {
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly authorUserId: string;
  readonly environmentId?: string;
  /** レイアウト v2 の運搬フィールド(v2Fields(...) — 省略 = v1 ステートメント)。 */
  readonly v2?: ReturnType<typeof v2Fields>;
}): Promise<WireVariableMetaStatement> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) {
    throw new Error(`no recorded statement for variable ${input.variableId}`);
  }
  const prevMetaSigHashHex = await metaSignedBytesHashOf(
    projectId,
    last.statement,
    last.authorUserId,
  );
  return signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1" as const,
    environmentId: input.environmentId ?? ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex,
    ...input.v2,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

/** 変数 rename(ステートメント付き PATCH)。204 なら記録を進める。 */
export async function renameVariableRequest(
  variableId: string,
  name: string,
  actorUserId: string,
): Promise<Response> {
  const statement = await nextVariableStatement({
    variableId,
    name,
    status: "active",
    authorUserId: actorUserId,
  });
  const { manifest, record } = await manifestForStatement(statement, actorUserId);
  const response = await requestJson(
    "PATCH",
    `/environments/${ENV}/variables/${variableId}`,
    token(actorUserId),
    { statement, manifest },
  );
  if (response.status === 204) {
    varStatements.set(variableId, { statement, authorUserId: actorUserId });
    record();
  }
  return response;
}

/** 変数削除(status deleted のステートメント付き DELETE)。204 なら記録を進める。 */
export async function deleteVariableRequest(
  variableId: string,
  actorUserId: string,
): Promise<Response> {
  const last = varStatements.get(variableId);
  if (last === undefined) {
    throw new Error(`no recorded statement for variable ${variableId}`);
  }
  const statement = await nextVariableStatement({
    variableId,
    // deleted の name は直前 active 名を保持する(§4.2)
    name: last.statement.name,
    status: "deleted",
    authorUserId: actorUserId,
  });
  const { manifest, record } = await manifestForStatement(statement, actorUserId);
  const response = await requestJson(
    "DELETE",
    `/environments/${ENV}/variables/${variableId}`,
    token(actorUserId),
    { statement, manifest },
  );
  if (response.status === 204) {
    varStatements.set(variableId, { statement, authorUserId: actorUserId });
    record();
  }
  return response;
}

/**
 * Schema 通過のみが必要なテスト(400 / 403 / 404 が署名検証より前に確定)用の
 * 未署名ダミーステートメント(形式のみ有効なゼロ署名)。
 */
export function unsignedVariableStatement(
  variableId: string,
  name: string,
): WireVariableMetaStatement {
  return {
    suite: "maruhi/v1",
    environmentId: ENV,
    variableId,
    name,
    status: "active",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

/**
 * Schema 通過のみが必要なテスト(400 / 403 / 404 が署名検証より前に確定)用の
 * 未署名ダミーマニフェスト(形式のみ有効なゼロ署名)。
 */
export function unsignedManifest(environmentId = ENV): WireEnvironmentManifest {
  return {
    suite: "maruhi/v1",
    environmentId,
    epoch: 1,
    manifestVersion: 1,
    variablesDigestHex: "ab".repeat(32),
    envMetaVersion: 1,
    envMetaSigHashHex: "ab".repeat(32),
    prevManifestSigHashHex: "",
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

/**
 * 受理ポリシー系テスト用のフェイク暗号文(サーバーは中身を復号できない)。
 * 値署名(§12-5)はサーバーが検証するため、フェイクでも呼び出し主体の実鍵で
 * 正しく署名する(writerUserId = リクエストに使う PAT の主体と一致させること)。
 * 宣言ヘッドは現ヘッド(fixture.head)。
 */
export function fakePayload(
  writerUserId: string,
  aad: WireEncryptedPayload["aad"],
  options?: {
    readonly ciphertextBytes?: number;
    readonly prevValueSigHashHex?: string;
  },
): Promise<WireEncryptedPayload> {
  return signValueAs(
    writerUserId,
    {
      suite: "maruhi/v1",
      aad,
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(options?.ciphertextBytes ?? 48),
      // version > 1 の既定 prev はダミー 64 hex(prev 検査より前段 — CAS 等 —
      // で拒否されるテスト用。prev 検査へ到達するテストは実ハッシュを渡す)
      prevValueSigHashHex:
        options?.prevValueSigHashHex ?? (aad.version === 1 ? "" : "cd".repeat(32)),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    },
    fixture.head,
  );
}

/**
 * 署名検証に到達しないことが確定しているテスト(Schema 400 / AAD 422 /
 * 非メンバー 404)用の未署名フェイク。STRANGER はベクター鍵を持たないため
 * 実署名できない — 形式のみ有効なゼロ署名を載せる。
 */
export function unsignedPayload(aad: WireEncryptedPayload["aad"]): WireEncryptedPayload {
  return {
    suite: "maruhi/v1",
    aad,
    nonceHex: "00".repeat(12),
    ciphertextHex: "ab".repeat(48),
    prevValueSigHashHex: aad.version === 1 ? "" : "cd".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

export const aadFor = (
  epoch: number,
  version: number,
  overrides?: Partial<WireEncryptedPayload["aad"]>,
) => ({
  projectId,
  environmentId: ENV,
  epoch,
  variableId: VAR,
  version,
  ...overrides,
});

/** 変数作成(実暗号化 + MEMBER の値署名 + metaVersion 1 のステートメント同梱)。 */
export async function createVariableOk(
  dek: Uint8Array,
  variableId: string,
  name: string,
  plaintext: string,
): Promise<WireEncryptedPayload> {
  const value = await encryptValue(
    dek,
    { projectId, environmentId: ENV, epoch: 1, variableId, version: 1 },
    plaintext,
    { writerUserId: MEMBER, head: fixture.head },
  );
  const statement = await variableStatementFor(MEMBER, variableId, name);
  const { manifest, record } = await manifestForStatement(statement, MEMBER);
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
    statement,
    value,
    manifest,
  });
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toEqual({ variableId, version: 1, epoch: 1 });
  varStatements.set(variableId, { statement, authorUserId: MEMBER });
  record();
  return value;
}

/**
 * レイアウト v2 の作成ステートメント(metaVersion 1 — active = 値同梱 /
 * declared = 値なしの宣言)を署名して返す。
 */
export async function variableStatementV2For(input: {
  readonly authorUserId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "declared";
  readonly schema?: Partial<WireSchemaFields>;
  readonly environmentId?: string;
}): Promise<WireVariableMetaStatement> {
  return signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1" as const,
    environmentId: input.environmentId ?? ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    ...v2Fields(input.schema),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

/** declared 作成(値なしの宣言複合 — §12-5)。204/200 相当の成功時は記録を進める。 */
export async function declareVariableRequest(input: {
  readonly variableId: string;
  readonly name: string;
  readonly actorUserId: string;
  readonly schema?: Partial<WireSchemaFields>;
}): Promise<Response> {
  const statement = await variableStatementV2For({
    authorUserId: input.actorUserId,
    variableId: input.variableId,
    name: input.name,
    status: "declared",
    ...(input.schema === undefined ? {} : { schema: input.schema }),
  });
  const { manifest, record } = await manifestForStatement(statement, input.actorUserId);
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables`,
    token(input.actorUserId),
    {
      statement,
      manifest,
    },
  );
  if (response.status === 200) {
    varStatements.set(input.variableId, { statement, authorUserId: input.actorUserId });
    record();
  }
  return response;
}

/** declared 作成の成功形(§12-5 — 保存バージョン 0)。 */
export async function declareVariableOk(input: {
  readonly variableId: string;
  readonly name: string;
  readonly actorUserId?: string;
  readonly schema?: Partial<WireSchemaFields>;
}): Promise<void> {
  const response = await declareVariableRequest({
    variableId: input.variableId,
    name: input.name,
    actorUserId: input.actorUserId ?? MEMBER,
    ...(input.schema === undefined ? {} : { schema: input.schema }),
  });
  expect(response.status).toBe(200);
  await expect(response.clone().json()).resolves.toMatchObject({
    variableId: input.variableId,
    version: 0,
  });
}

/**
 * activation 複合(§12-5 — declared → active: 値 version 1 + status active の
 * v2 ステートメント + マニフェスト)。200 なら記録を進める。
 */
export async function activateVariableRequest(input: {
  readonly variableId: string;
  readonly actorUserId: string;
  readonly dek: Uint8Array;
  readonly plaintext: string;
  readonly epoch?: number;
  readonly name?: string;
  readonly schema?: Partial<WireSchemaFields>;
  /**
   * 値の version(既定 1 = 正当な activation)。1 以外は negative 用 —
   * 「active 変数へ latest + 1 を送る」迂回形の再現(PR #119 pullfrog 指摘。
   * ヘルパが 1 を固定すると『active 変数を狙えない』という性質が検証できない)。
   */
  readonly version?: number;
  readonly prevValueSigHashHex?: string;
}): Promise<Response> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) {
    throw new Error(`no recorded statement for variable ${input.variableId}`);
  }
  const statement = await nextVariableStatement({
    variableId: input.variableId,
    name: input.name ?? last.statement.name,
    status: "active",
    authorUserId: input.actorUserId,
    v2: v2Fields(input.schema),
  });
  const value = await encryptValue(
    input.dek,
    {
      projectId,
      environmentId: ENV,
      epoch: input.epoch ?? 1,
      variableId: input.variableId,
      version: input.version ?? 1,
    },
    input.plaintext,
    {
      writerUserId: input.actorUserId,
      head: fixture.head,
      ...(input.prevValueSigHashHex === undefined
        ? {}
        : { prevValueSigHashHex: input.prevValueSigHashHex }),
    },
  );
  const { manifest, record } = await manifestForStatement(statement, input.actorUserId);
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables/${input.variableId}/activate`,
    token(input.actorUserId),
    { value, statement, manifest },
  );
  if (response.status === 200) {
    varStatements.set(input.variableId, { statement, authorUserId: input.actorUserId });
    record();
  }
  return response;
}

/** schemaPolicy の設定(PUT — §12-11。既定 actor は OWNER = チェーン role owner)。 */
export async function setSchemaPolicyOk(
  policy: "disabled" | "enabled" | "locked",
  actorUserId = OWNER,
): Promise<void> {
  const response = await requestJson("PUT", "/schema-policy", token(actorUserId), {
    schemaPolicy: policy,
  });
  expect(response.status).toBe(204);
}

/** ダミー DEK の完全ラップ集合(受信者・エポック・署名者は指定可)。 */
export const wrapsFor = (
  environmentId: string,
  recipients: readonly string[],
  epoch = 1,
  signerUserId = OWNER,
) =>
  wrapDekForAll({
    projectId,
    environmentId,
    epoch,
    dek: makeDek(),
    recipientUserIds: recipients,
    signerUserId,
  });

/** チェーン保存行のエントリハッシュ(宣言ヘッドの exact pair 構成用)。 */
export async function hashOf(seq: number): Promise<string> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT entry_hash_hex FROM chain_entries WHERE seq = ?",
    seq,
  );
  return String(rows[0]?.["entry_hash_hex"]);
}
