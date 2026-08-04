// データプレーン API(AUTH_SPEC §12)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// 実データ主義: チェーンはテスト時署名(ベクター固定鍵)、DEK ラップは実 HPKE、
// 値は実 AES-GCM で作り、pull 後にクライアント側復号まで検証する。フェイクの
// 暗号文を使うのは「サーバーは中身を検証できない」ことを利用する受理ポリシー系
// テストのみ(各テストに明記)。

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import {
  buildValueSignedBytes,
  decryptVariable,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importSigningKeyPair,
  unwrapDek,
  verifyChainWithHistory,
  verifyDistributedValue,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { projectBytesExceeded, wrapRowsExceeded } from "../src/data-programs.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_DEK_WRAPS_PER_REQUEST,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_VALUE_CIPHERTEXT_BYTES,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "../src/policy.ts";
import { deviceToken, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  hexBytes,
  makeDek,
  signEntryAt,
  signValueAs,
  signWrapAs,
  unwrapAndDecrypt,
  valueSignedBytesHashOf,
  vectorKeyOf,
  verifyDistributedWrapSignature,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  createEnvironmentWith,
  dataUrl,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
  setupDataProject,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";
import { queryProjectDo } from "./support/project-do.ts";

const ENV = "env-app-0001";
const VAR = "var-database-url";

let fixture: DataFixture;

beforeEach(async () => {
  fixture = await setupDataProject();
});

const token = (userId: string): string => tokenOf(fixture.tokens, userId);

/**
 * 受理ポリシー系テスト用のフェイク暗号文(サーバーは中身を復号できない)。
 * 値署名(§12-5)はサーバーが検証するため、フェイクでも呼び出し主体の実鍵で
 * 正しく署名する(writerUserId = リクエストに使う PAT の主体と一致させること)。
 * 宣言ヘッドは現ヘッド(fixture.head)。
 */
function fakePayload(
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
function unsignedPayload(aad: WireEncryptedPayload["aad"]): WireEncryptedPayload {
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

const aadFor = (
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

/** 変数作成(実暗号化 + MEMBER の値署名。宣言ヘッド = 現ヘッド)。 */
async function createVariableOk(
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
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
    variableId,
    name,
    value,
  });
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toEqual({ variableId, version: 1, epoch: 1 });
  return value;
}

describe("環境管理(§12-4 複合リクエスト)", () => {
  it("creates an environment atomically: chain entry + epoch-1 wrap set + name in one request", async () => {
    const headBefore = fixture.head;
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const created = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(created.status).toBe(200);
    const body = (await created.json()) as {
      environmentId: string;
      currentEpoch: number;
      headSeq: number;
      headHashHex: string;
    };
    expect(body.environmentId).toBe(ENV);
    expect(body.currentEpoch).toBe(1);
    expect(body.headSeq).toBe(headBefore.seq + 1);

    // チェーンに create_environment エントリが追記されている(複合の原子性の片翼)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: { op: string; seq: number }[] };
    expect(chainBody.entries.at(-1)?.op).toBe("create_environment");
    expect(chainBody.entries.at(-1)?.seq).toBe(body.headSeq);

    const list = await requestJson("GET", "/environments", token(READER));
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toEqual({
      environments: [{ environmentId: ENV, name: "App", currentEpoch: 1 }],
    });

    const wraps = await queryProjectDo(
      projectId,
      "SELECT recipient_user_id FROM dek_wraps WHERE environment_id = ? AND epoch = 1 ORDER BY recipient_user_id",
      ENV,
    );
    expect(wraps.map((row) => row["recipient_user_id"])).toEqual([...ALL_MEMBERS].toSorted());
  });

  it("rejects a duplicate environment id with 422 chain-entry-invalid (duplicate-environment)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    // ID の一意性は合意規則へ昇格(旧 409 exists の吸収 — CRYPTO_SPEC §6.2)
    const response = await createEnvironmentWith(fixture, ENV, "App2", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("duplicate-environment");
    expect(body.seq).toBe(fixture.head.seq + 1);
  });

  it("never reuses a deleted environment id (422 duplicate-environment) and hard-deletes its data", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://old");
    const removed = await requestJson("DELETE", `/environments/${ENV}`, token(OWNER));
    expect(removed.status).toBe(204);

    // 変数・バージョン・ラップは即時削除、環境行は tombstone(§12-4)
    for (const table of ["variables", "variable_versions", "dek_wraps"]) {
      const rows = await queryProjectDo(
        projectId,
        `SELECT 1 FROM ${table} WHERE environment_id = ?`,
        ENV,
      );
      expect(rows.length).toBe(0);
    }
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(404);

    // チェーンは削除を観測しないため、再作成は合意規則(履歴全体一意)で拒否される
    // (旧 409 retired の吸収 — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4)
    const recreated = await createEnvironmentWith(fixture, ENV, "App3", []);
    expect(recreated.status).toBe(422);
    const body = (await recreated.json()) as { reason: string };
    expect(body.reason).toBe("duplicate-environment");
  });

  it("rejects create_environment / rotate_epoch on the generic chain append (422 CompositeRequired)", async () => {
    // AUTH_SPEC §6 / §12-4: 複合エンドポイントの原子性を汎用経路で迂回させない
    const { entry: createEntry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: MEMBER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const createResponse = await requestJson("POST", "/chain/entries", token(MEMBER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: createEntry,
    });
    expect(createResponse.status).toBe(422);
    expect((await createResponse.json()) as { op: string }).toMatchObject({
      op: "create_environment",
    });

    const { entry: rotateEntry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: MEMBER,
      operation: {
        op: "rotate_epoch",
        payload: {
          environmentId: ENV,
          newEpoch: 2,
          reason: "bypass",
          dekCommitmentHex: "ab".repeat(32),
        },
      },
    });
    const rotateResponse = await requestJson("POST", "/chain/entries", token(MEMBER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: rotateEntry,
    });
    expect(rotateResponse.status).toBe(422);
    expect((await rotateResponse.json()) as { op: string }).toMatchObject({ op: "rotate_epoch" });

    // どちらもチェーンに追記されていない
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { headSeq: number };
    expect(chainBody.headSeq).toBe(fixture.head.seq);
  });

  it("retries a composite creation after a head CAS conflict (409 ChainHeadConflict → 再署名 → 200)", async () => {
    // §12-4: 親ヘッド CAS 失敗はチェーンエントリの再署名(prev 変更)を要する。
    // 古い親(genesis 相当)で送ると 409 + 現ヘッドが返り、正しい親で再試行できる
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const stale = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: projectId, // genesis ハッシュ = 2 世代前のヘッド
    });
    expect(stale.status).toBe(409);
    const staleBody = (await stale.json()) as {
      currentHeadSeq: number;
      currentHeadHashHex: string;
    };
    expect(staleBody.currentHeadSeq).toBe(fixture.head.seq);
    expect(staleBody.currentHeadHashHex).toBe(fixture.head.hashHex);
    // 何も書かれていない(原子性: CAS 失敗はチェーンにもデータにも痕跡を残さない)
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [] });

    const retried = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
  });

  it("enforces display-name uniqueness on create and rename (409 duplicate-name)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-app-0002",
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const duplicate = await createEnvironmentWith(fixture, "env-app-0002", "App", deks);
    expect(duplicate.status).toBe(409);
    const body = (await duplicate.json()) as { reason: string };
    expect(body.reason).toBe("duplicate-name");

    const second = await createEnvironmentWith(fixture, "env-app-0002", "Staging", deks);
    expect(second.status).toBe(200);
    const renamed = await requestJson("PATCH", "/environments/env-app-0002", token(MEMBER), {
      name: "App",
    });
    expect(renamed.status).toBe(409);
    const ok = await requestJson("PATCH", "/environments/env-app-0002", token(MEMBER), {
      name: "Prod",
    });
    expect(ok.status).toBe(204);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as { environments: { name: string }[] };
    expect(listBody.environments.map((e) => e.name).toSorted()).toEqual(["App", "Prod"]);
  });

  it("requires chain role admin for environment deletion (§12-3)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const asMember = await requestJson("DELETE", `/environments/${ENV}`, token(MEMBER));
    expect(asMember.status).toBe(403);
    const body = (await asMember.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("requires chain role member for creation: reader gets 403 insufficient-role", async () => {
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: READER,
    });
    const response = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: READER,
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("rejects a composite whose entry actor differs from the principal (403 actor-mismatch)", async () => {
    // §12-4: チェーンエントリの actor は呼び出し主体と厳密一致(§11-1 と同じ規律)
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const response = await requestJson("POST", "/environments", token(MEMBER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      name: "App",
      deks,
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("actor-mismatch");
  });

  it("conceals the project from non-members with 404 (§11-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    for (const [method, path] of [
      ["GET", "/environments"],
      ["GET", `/environments/${ENV}/pull`],
      ["GET", `/environments/${ENV}/deks`],
      ["DELETE", `/environments/${ENV}`],
    ] as const) {
      const response = await requestJson(method, path, token(STRANGER));
      expect(response.status).toBe(404);
      const body = (await response.json()) as { projectId: string };
      expect(body.projectId).toBe(projectId);
    }
  });

  it("rejects unauthenticated requests with 401", async () => {
    const response = await SELF.fetch(dataUrl("/environments"));
    expect(response.status).toBe(401);
  });
});

const wrapsFor = (
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

describe("環境作成の DEK ラップ検証(§12-6)", () => {
  it("rejects a wrap set missing a current member (422 recipient-missing)", async () => {
    const deks = await wrapsFor(ENV, [OWNER, MEMBER]);
    const response = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-missing");
  });

  it("rejects an empty wrap set atomically (§12-4: エポック 1 の完全集合の同梱は必須)", async () => {
    // レビューループ 1 の指摘: 空集合はエポック単位の検査をすり抜けて
    // 「誰も DEK を持てない環境」を作れてしまう。個数 = 現メンバー数の明示検査で塞ぐ
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-missing");
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [] });
    // 複合の原子性(§12-4): ラップ検査で落ちた複合はチェーンエントリも追記しない
    // (「コミットメントはあるがラップがない」中間状態を作らない)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { headSeq: number };
    expect(chainBody.headSeq).toBe(fixture.head.seq);
  });

  it("rejects a wrap addressed to a non-member (422 recipient-not-member)", async () => {
    const deks = [
      ...(await wrapsFor(ENV, ALL_MEMBERS)),
      await wrapDekTo({
        projectId,
        environmentId: ENV,
        epoch: 1,
        dek: makeDek(),
        recipientUserId: STRANGER,
        recipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
        signerUserId: OWNER,
      }),
    ];
    const response = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-not-member");
  });

  it("rejects a wrap under a key that differs from the chain (422 recipient-key-mismatch)", async () => {
    const good = await wrapsFor(ENV, [OWNER, MEMBER]);
    const badKey = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserId: READER,
      // チェーン上の READER の鍵ではなく MEMBER の鍵へラップ(ゴーストメンバー相当)
      recipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
      signerUserId: OWNER,
    });
    const response = await createEnvironmentWith(fixture, ENV, "App", [...good, badKey]);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-key-mismatch");
  });

  it("rejects duplicate recipients and out-of-range epochs", async () => {
    const base = await wrapsFor(ENV, ALL_MEMBERS);
    const duplicated = [...base, ...(await wrapsFor(ENV, [OWNER]))];
    const dupResponse = await createEnvironmentWith(fixture, ENV, "App", duplicated);
    expect(dupResponse.status).toBe(422);
    expect(((await dupResponse.json()) as { reason: string }).reason).toBe("duplicate-recipient");

    // 環境作成時の現エポックは常に 1(§12-4)。epoch 2 宛は範囲外
    const epoch2 = await wrapsFor(ENV, ALL_MEMBERS, 2);
    const epochResponse = await createEnvironmentWith(fixture, ENV, "App", epoch2);
    expect(epochResponse.status).toBe(422);
    expect(((await epochResponse.json()) as { reason: string }).reason).toBe("epoch-out-of-range");
  });
});

describe("変数の push→pull→クライアント復号(§12-5 / §12-7)", () => {
  it("round-trips a value end to end: encrypt → create → pull → unwrap DEK → decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      environmentId: string;
      currentEpoch: number;
      variables: { variableId: string; name: string; value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(body.currentEpoch).toBe(1);
    expect(body.variables.length).toBe(1);
    expect(body.deks.length).toBe(1);
    const [variable] = body.variables;
    const [wrappedDek] = body.deks;
    if (variable === undefined || wrappedDek === undefined) throw new Error("missing pull data");
    expect(variable.value.aad).toEqual(aadFor(1, 1));

    // reader のクライアント側復号(E2EE のラウンドトリップ)
    const plaintext = await unwrapAndDecrypt({
      recipientUserId: READER,
      wrapped: wrappedDek,
      projectId,
      environmentId: ENV,
      payload: variable.value,
    });
    expect(plaintext).toBe("postgres://alpha");

    // 新バージョンを push すると pull は最新のみ返す(prev = v1 の signed_bytes
    // ハッシュへ連鎖 — §4.1)
    const v1 = variable.value;
    const v2 = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "postgres://beta",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(push.status).toBe(200);
    await expect(push.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 1 });

    const second = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const secondBody = (await second.json()) as typeof body;
    const latest = secondBody.variables[0];
    const latestDek = secondBody.deks[0];
    if (latest === undefined || latestDek === undefined) throw new Error("missing pull data");
    expect(latest.value.aad.version).toBe(2);
    const decrypted = await unwrapAndDecrypt({
      recipientUserId: READER,
      wrapped: latestDek,
      projectId,
      environmentId: ENV,
      payload: latest.value,
    });
    expect(decrypted).toBe("postgres://beta");
  });

  it("rejects declared AAD components that mismatch the storage coordinates (422 §12-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const cases: readonly [Partial<WireEncryptedPayload["aad"]>, string][] = [
      [{ environmentId: "env-app-0002" }, "environmentId"],
      [{ variableId: "var-other" }, "variableId"],
      [{ projectId: "ab".repeat(32) }, "projectId"],
    ];
    for (const [override, field] of cases) {
      const response = await requestJson(
        "POST",
        `/environments/${ENV}/variables/${VAR}/versions`,
        token(MEMBER),
        { value: await fakePayload(MEMBER, aadFor(1, 2, override)) },
      );
      expect(response.status).toBe(422);
      const body = (await response.json()) as { field: string };
      expect(body.field).toBe(field);
    }
  });

  it("enforces the version CAS: only latest + 1 is accepted (409 §12-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // 既知の version(1)を再申告 → 409 currentVersion 1
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 1)) },
    );
    expect(stale.status).toBe(409);
    // 409 は currentVersion(番号)のみを返す — 勝者の signed_bytes ハッシュは
    // 載せない(未検証値への連鎖署名の禁止 — §12-5)
    const staleBody = (await stale.json()) as Record<string, unknown>;
    expect(staleBody).toMatchObject({ currentVersion: 1 });
    expect(Object.keys(staleBody).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);

    // 飛び番(3)も拒否
    const skipped = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 3)) },
    );
    expect(skipped.status).toBe(409);
    await expect(skipped.json()).resolves.toMatchObject({ currentVersion: 1 });
  });

  it("creation requires version 1 (409 currentVersion 0)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "DATABASE_URL",
      value: await fakePayload(MEMBER, aadFor(1, 2)),
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({ currentVersion: 0 });
  });

  it("serializes concurrent pushes: exactly one winner, no lost or interleaved writes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const prevHash = await valueSignedBytesHashOf(v1, MEMBER);

    const contenders = await Promise.all(
      Array.from({ length: 8 }, (_v, index) =>
        encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
          `postgres://contender-${index}`,
          { writerUserId: MEMBER, head: fixture.head, prevValueSigHashHex: prevHash },
        ),
      ),
    );
    const responses = await Promise.all(
      contenders.map((value) =>
        requestJson("POST", `/environments/${ENV}/variables/${VAR}/versions`, token(MEMBER), {
          value,
        }),
      ),
    );
    const statuses = responses.map((response) => response.status);
    expect(statuses.filter((status) => status === 200).length).toBe(1);
    expect(statuses.filter((status) => status === 409).length).toBe(7);
    for (const response of responses.filter((r) => r.status === 409)) {
      await expect(response.json()).resolves.toMatchObject({ currentVersion: 2 });
    }

    // 欠損・交錯なし: バージョン行は 1,2 のみ、latest は 2、勝者の暗号文が保存されている
    const rows = await queryProjectDo(
      projectId,
      "SELECT version, ciphertext_hex FROM variable_versions WHERE environment_id = ? AND variable_id = ? ORDER BY version",
      ENV,
      VAR,
    );
    expect(rows.map((row) => row["version"])).toEqual([1, 2]);
    const winnerIndex = statuses.indexOf(200);
    expect(rows[1]?.["ciphertext_hex"]).toBe(contenders[winnerIndex]?.ciphertextHex);
    const variableRow = await queryProjectDo(
      projectId,
      "SELECT latest_version FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(variableRow[0]?.["latest_version"]).toBe(2);
  });

  it("accepts concurrent pushes to different variables", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const ids = ["var-a", "var-b", "var-c"];
    const firstVersions = new Map<string, WireEncryptedPayload>();
    for (const id of ids) {
      firstVersions.set(id, await createVariableOk(dek, id, `NAME_${id}`, `value-${id}`));
    }
    const values = await Promise.all(
      ids.map(async (id) => {
        const v1 = firstVersions.get(id);
        if (v1 === undefined) throw new Error("missing first version");
        return encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: id, version: 2 },
          `next-${id}`,
          {
            writerUserId: MEMBER,
            head: fixture.head,
            prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
          },
        );
      }),
    );
    const responses = await Promise.all(
      ids.map((id, index) =>
        requestJson("POST", `/environments/${ENV}/variables/${id}/versions`, token(MEMBER), {
          value: values[index],
        }),
      ),
    );
    expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
  });

  it("rejects pushes from readers with 403 insufficient-role (§6.2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(READER),
      { value: await fakePayload(READER, aadFor(1, 2)) },
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("enforces min(token scope, chain role) (§9-2 / §12-3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // member の read スコープ: pull 可・push 不可(403 insufficient-permission)
    const readScope: readonly TokenScope[] = [{ project: projectId, permission: "read" }];
    const readToken = await deviceToken(9002, readScope);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, readToken);
    expect(pull.status).toBe(200);
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      readToken,
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(push.status).toBe(403);
    expect(((await push.json()) as { reason: string }).reason).toBe("insufficient-permission");

    // reader の write スコープ: スコープが足りてもチェーン role が束縛(403 insufficient-role)
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const readerWrite = await deviceToken(9003, writeScope);
    const readerPush = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      readerWrite,
      { value: await fakePayload(READER, aadFor(1, 2)) },
    );
    expect(readerPush.status).toBe(403);
    expect(((await readerPush.json()) as { reason: string }).reason).toBe("insufficient-role");

    // スコープ外プロジェクトは存在秘匿(404)
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scoped = await deviceToken(9002, otherScope);
    const concealed = await requestJson("GET", `/environments/${ENV}/pull`, scoped);
    expect(concealed.status).toBe(404);

    // 環境削除は admin スコープが必要(write では 403)
    const memberWrite = await deviceToken(9001, writeScope);
    const removal = await requestJson("DELETE", `/environments/${ENV}`, memberWrite);
    expect(removal.status).toBe(403);
    expect(((await removal.json()) as { reason: string }).reason).toBe("insufficient-permission");
  });

  it("handles variable conflicts: duplicate id, retired id, duplicate name, rename", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const duplicate = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "OTHER",
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(duplicate.status).toBe(409);
    expect(((await duplicate.json()) as { reason: string }).reason).toBe("exists");

    const sameName = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: "var-other",
      name: "DATABASE_URL",
      value: await fakePayload(MEMBER, { ...aadFor(1, 1), variableId: "var-other" }),
    });
    expect(sameName.status).toBe(409);
    expect(((await sameName.json()) as { reason: string }).reason).toBe("duplicate-name");

    // 作成側の申告 AAD 不一致(§12-2): body の variableId と aad の不一致は 422
    const createMismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      { variableId: "var-other", name: "OTHER", value: await fakePayload(MEMBER, aadFor(1, 1)) },
    );
    expect(createMismatch.status).toBe(422);
    expect(((await createMismatch.json()) as { field: string }).field).toBe("variableId");

    // 改名も名前一意性の対象(§12-1)
    await createVariableOk(dek, "var-other", "OTHER", "other-value");
    const renameConflict = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/var-other`,
      token(MEMBER),
      { name: "DATABASE_URL" },
    );
    expect(renameConflict.status).toBe(409);
    expect(((await renameConflict.json()) as { reason: string }).reason).toBe("duplicate-name");

    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { name: "DB_URL" },
    );
    expect(renamed.status).toBe(204);

    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
    );
    expect(removed.status).toBe(204);
    const versions = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variable_versions WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(versions.length).toBe(0);

    // 削除済み ID の再利用は拒否(§12-1)
    const retired = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "REBORN",
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(retired.status).toBe(409);
    expect(((await retired.json()) as { reason: string }).reason).toBe("retired");

    // 削除済み変数への push は 404
    const pushDeleted = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(pushDeleted.status).toBe(404);
  });

  it("rejects an oversized ciphertext with 413 (§12-8)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "BIG",
      value: await fakePayload(MEMBER, aadFor(1, 1), {
        ciphertextBytes: MAX_VALUE_CIPHERTEXT_BYTES + 1,
      }),
    });
    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      limitBytes: MAX_VALUE_CIPHERTEXT_BYTES,
    });
  });

  it("caps versions per variable (422 §12-8)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 1,000 回の実 push は非現実的なので latest_version を直接引き上げ、
    // 上限直前の version 行(prev 検査の predecessor)をシードする
    // (数量ポリシーは値署名の後 — 裁定 D — のため署名検証を通る形が要る)
    const seededHash = "aa".repeat(32);
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
          prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
          signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
       VALUES (?, ?, ?, 'maruhi/v1', 1, ?, ?, 48, ?, ?, 1, ?, ?, ?, ?, 0)`,
      ENV,
      VAR,
      MAX_VERSIONS_PER_VARIABLE,
      "00".repeat(12),
      "ab".repeat(48),
      "bb".repeat(32),
      projectId,
      "00".repeat(64),
      seededHash,
      MEMBER,
      vectorKeyOf(MEMBER).key_fingerprint_hex,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      {
        value: await fakePayload(MEMBER, aadFor(1, MAX_VERSIONS_PER_VARIABLE + 1), {
          prevValueSigHashHex: seededHash,
        }),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "versions",
      limit: MAX_VERSIONS_PER_VARIABLE,
    });
  });

  it("caps cumulative project ciphertext bytes (422 §12-8, unit + plumbing)", async () => {
    // 純関数の判定(1 GiB を実生成しない)
    expect(projectBytesExceeded(MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES, 1)).toBe(true);
    expect(projectBytesExceeded(MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES - 10, 10)).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 保存済みバイト数だけを上限相当へ引き上げてプラミングを検証する
    await queryProjectDo(
      projectId,
      "UPDATE variable_versions SET ciphertext_bytes = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
      ENV,
      VAR,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      {
        value: await fakePayload(MEMBER, aadFor(1, 2), {
          prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
        }),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "project-ciphertext-bytes",
      limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
    });
  });
});

/** チェーン保存行のエントリハッシュ(宣言ヘッドの exact pair 構成用)。 */
async function hashOf(seq: number): Promise<string> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT entry_hash_hex FROM chain_entries WHERE seq = ?",
    seq,
  );
  return String(rows[0]?.["entry_hash_hex"]);
}

describe("値署名の受理検証(§12-5 = CRYPTO_SPEC §4.1 / §6.4)", () => {
  /** 拒否時の無副作用の検査: 変数・バージョン・latest・監査のいずれも変わらない。 */
  async function expectNoVersionSideEffects(expectedVersions: readonly number[]): Promise<void> {
    const rows = await queryProjectDo(
      projectId,
      "SELECT version FROM variable_versions WHERE environment_id = ? AND variable_id = ? ORDER BY version",
      ENV,
      VAR,
    );
    expect(rows.map((row) => row["version"])).toEqual([...expectedVersions]);
    const pushedAudits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.version_pushed'",
    );
    expect(pushedAudits[0]?.["n"]).toBe(expectedVersions.length);
  }

  it("rejects a value signed by someone other than the caller (422 signature-invalid)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // OWNER が正しく署名した値を MEMBER が持ち込む → 検証鍵は呼び出し主体
    // (MEMBER)の受理時点チェーン鍵なので失敗する(他人の署名の持ち込み拒否)
    const ownerSigned = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "postgres://beta",
      {
        writerUserId: OWNER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: ownerSigned },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    await expectNoVersionSideEffects([1]);
  });

  it("rejects creation with a tampered signature and writes nothing (作成経由の検証迂回は不可)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "postgres://alpha",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const flipped = `${value.signatureHex.slice(0, -2)}${
      value.signatureHex.endsWith("00") ? "01" : "00"
    }`;
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "DATABASE_URL",
      value: { ...value, signatureHex: flipped },
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    // 変数行・バージョン行・監査(var.created / var.version_pushed)のいずれも残らない
    const variables = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(variables.length).toBe(0);
    const audits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event IN ('var.created', 'var.version_pushed')",
    );
    expect(audits[0]?.["n"]).toBe(0);
  });

  it("rejects unknown declared heads (422 chain-head-unknown): hash mismatch and future seq", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 実在 seq × 不一致 hash(有効署名)— exact pair の存在が受理条件
    const mismatched = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: "cd".repeat(32),
        chainHeadHashHex: "ee".repeat(32),
        chainHeadSeq: fixture.head.seq,
      },
      { seq: fixture.head.seq, hashHex: "ee".repeat(32) },
    );
    const hashMismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: mismatched },
    );
    expect(hashMismatch.status).toBe(422);
    expect(((await hashMismatch.json()) as { reason: string }).reason).toBe("chain-head-unknown");

    // 自チェーンより先の seq(サーバーには存在しない)も chain-head-unknown
    const future = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: "cd".repeat(32),
        chainHeadHashHex: "ee".repeat(32),
        chainHeadSeq: fixture.head.seq + 5,
      },
      { seq: fixture.head.seq + 5, hashHex: "ee".repeat(32) },
    );
    const futureResponse = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: future },
    );
    expect(futureResponse.status).toBe(422);
    expect(((await futureResponse.json()) as { reason: string }).reason).toBe("chain-head-unknown");
    await expectNoVersionSideEffects([1]);
  });

  it("rejects heads whose head-time state mismatches (422 chain-head-state-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const prevHash = await valueSignedBytesHashOf(v1, MEMBER);
    const chain = await requestJson("GET", "/chain", token(READER));
    const entries = ((await chain.json()) as { entries: { seq: number }[] }).entries;
    expect(entries.length).toBe(fixture.head.seq);

    // (a) writer が member になる前のヘッド(seq 1 = genesis)の宣言
    const beforeMembership = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: prevHash,
        chainHeadHashHex: await hashOf(1),
        chainHeadSeq: 1,
      },
      { seq: 1, hashHex: await hashOf(1) },
    );
    const notMember = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: beforeMembership },
    );
    expect(notMember.status).toBe(422);
    expect(((await notMember.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // (b) 環境作成前のヘッド(ベースチェーンの seq 3)の宣言 — エポックが未定義の
    // ヘッドを既定値で補う実装の禁止(§12-5 の 4 後段)
    const beforeCreate = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: prevHash,
        chainHeadHashHex: await hashOf(3),
        chainHeadSeq: 3,
      },
      { seq: 3, hashHex: await hashOf(3) },
    );
    const envNotCreated = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: beforeCreate },
    );
    expect(envNotCreated.status).toBe(422);
    expect(((await envNotCreated.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoVersionSideEffects([1]);
  });

  it("rejects prev-chain mismatches (422 chain-head-state-mismatch): wrong prev and non-empty v1 prev", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // version 2 の prev が保存済み version 1 の signed_bytes ハッシュと不一致
    // (署名は有効 — Ed25519 failure に潰されないことの固定)
    const wrongPrev = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2), { prevValueSigHashHex: "cd".repeat(32) }) },
    );
    expect(wrongPrev.status).toBe(422);
    expect(((await wrongPrev.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // version 1 に非空 prev(署名は有効な形を低水準 API で作る — signValue は
    // 結合違反の署名を拒否するため)
    const context = {
      suite: "maruhi/v1",
      projectId,
      environmentId: ENV,
      epoch: 1,
      variableId: "var-phantom-prev",
      version: 1,
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(48),
      prevValueSigHashHex: "cd".repeat(32),
      writerUserId: MEMBER,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    };
    const keys = vectorKeyOf(MEMBER);
    const pairResult = await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    });
    if (!pairResult.ok) throw new Error("key import failed");
    const rawSignature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        pairResult.value.privateKey,
        buildValueSignedBytes(context) as BufferSource,
      ),
    );
    const v1NonEmptyPrev = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      {
        variableId: "var-phantom-prev",
        name: "PHANTOM",
        value: {
          suite: "maruhi/v1",
          aad: aadFor(1, 1, { variableId: "var-phantom-prev" }),
          nonceHex: context.nonceHex,
          ciphertextHex: context.ciphertextHex,
          prevValueSigHashHex: context.prevValueSigHashHex,
          chainHeadHashHex: context.chainHeadHashHex,
          chainHeadSeq: context.chainHeadSeq,
          signatureHex: encodeHex(rawSignature),
        },
      },
    );
    expect(v1NonEmptyPrev.status).toBe(422);
    expect(((await v1NonEmptyPrev.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoVersionSideEffects([1]);
  });

  it("distributes the writer identity and signature block; client verifies via chain history (§12-7)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const headAtWrite = { ...fixture.head };
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: {
        variableId: string;
        value: WireEncryptedPayload & {
          writerUserId: string;
          writerKeyFingerprintHex: string;
        };
      }[];
    };
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing pulled variable");
    expect(pulled.value.writerUserId).toBe(MEMBER);
    expect(pulled.value.writerKeyFingerprintHex).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(pulled.value.chainHeadSeq).toBe(headAtWrite.seq);
    expect(pulled.value.chainHeadHashHex).toBe(headAtWrite.hashHex);
    expect(pulled.value.prevValueSigHashHex).toBe("");
    // サーバー再計算の signed_bytes ハッシュは配布されない(§12-2)
    expect("signedBytesHashHex" in pulled.value).toBe(false);

    // クライアント検証(§6.3): 取得チェーンの履歴索引に対する期待座標での検証
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedValue({
      history: verified.value.history,
      context: {
        suite: "maruhi/v1",
        projectId,
        environmentId: ENV,
        epoch: pulled.value.aad.epoch,
        variableId: pulled.variableId,
        version: pulled.value.aad.version,
        nonceHex: pulled.value.nonceHex,
        ciphertextHex: pulled.value.ciphertextHex,
        prevValueSigHashHex: pulled.value.prevValueSigHashHex,
        writerUserId: pulled.value.writerUserId,
        chainHeadHashHex: pulled.value.chainHeadHashHex,
        chainHeadSeq: pulled.value.chainHeadSeq,
      },
      writerKeyFingerprintHex: pulled.value.writerKeyFingerprintHex,
      signatureHex: pulled.value.signatureHex,
    });
    expect(result.ok).toBe(true);
  });

  it("keeps distributing a removed writer's stored value, verifiable at its in-tenure head", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // writer(MEMBER)を削除。保存済み値の writer 情報は受理時点のまま配布される
    // (現メンバー集合から再導出しない — 削除済み writer の過去値の検証可能性)
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: {
        variableId: string;
        value: WireEncryptedPayload & {
          writerUserId: string;
          writerKeyFingerprintHex: string;
        };
      }[];
    };
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing pulled variable");
    expect(pulled.value.writerUserId).toBe(MEMBER);

    // 削除後の全チェーンでも、宣言ヘッドが在籍区間内なので検証は通る(§6.3-1/3)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedValue({
      history: verified.value.history,
      context: {
        suite: "maruhi/v1",
        projectId,
        environmentId: ENV,
        epoch: pulled.value.aad.epoch,
        variableId: pulled.variableId,
        version: pulled.value.aad.version,
        nonceHex: pulled.value.nonceHex,
        ciphertextHex: pulled.value.ciphertextHex,
        prevValueSigHashHex: pulled.value.prevValueSigHashHex,
        writerUserId: pulled.value.writerUserId,
        chainHeadHashHex: pulled.value.chainHeadHashHex,
        chainHeadSeq: pulled.value.chainHeadSeq,
      },
      writerKeyFingerprintHex: pulled.value.writerKeyFingerprintHex,
      signatureHex: pulled.value.signatureHex,
    });
    expect(result.ok).toBe(true);

    // 削除済み writer による新規 push(削除後のヘッド宣言)は受理段階で拒否される
    // (呼び出し主体が現メンバーでない → 404 存在秘匿が先に立つ — §11-2)
    const rejected = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(rejected.status).toBe(404);
  });

  it("rejects a re-added member declaring a head from their old tenure (422 chain-head-state-mismatch)", async () => {
    // remove → 別鍵 re-add した主体が旧在籍区間のヘッドを宣言する形は、署名が
    // 有効でも「宣言ヘッド時点の束縛鍵 = 受理時点の鍵」で落ちる(§12-5 の 3)。
    // crypto ベクター key-from-other-tenure のサーバー API レベルの対
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 旧在籍区間(現ヘッド)の hash を控えてから MEMBER を削除
    const oldTenureHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    // 同一 user_id(MEMBER)を新鮮な鍵で re-add する(旧鍵・他メンバー鍵との
    // 重複は §6.2 のメンバー鍵一意性で弾かれるため、新規生成鍵を使う)。
    // 受理時点の MEMBER の束縛鍵は新鍵になり、旧在籍区間のヘッド宣言は落ちる
    const newEncPair = await generateEncryptionKeyPair();
    const newSigPair = await generateSigningKeyPair();
    const rejoin = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "add_member",
        payload: {
          targetUserId: MEMBER,
          encPubHex: encodeHex(await exportEncryptionPublicKey(newEncPair.publicKey)),
          sigPubHex: encodeHex(await exportSigningPublicKey(newSigPair.publicKey)),
          role: "member",
        },
      },
    });
    const rejoined = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: rejoin.entry,
    });
    expect(rejoined.status).toBe(200);
    fixture.head = { seq: rejoin.entry.seq, hashHex: rejoin.hash };
    // 受理時点の MEMBER の束縛鍵は新鍵。サーバーはその鍵で署名検証し署名対象の
    // writer_user_id にも MEMBER を用いる。攻撃者は新鍵で署名した上で旧在籍区間の
    // ヘッドを宣言する(署名は有効 → ヘッド時点の束縛鍵 = 旧鍵 ≠ 受理時点の新鍵で
    // 落ちる)。context を手で組んで新鍵で署名する
    const context = {
      suite: "maruhi/v1" as const,
      projectId,
      environmentId: ENV,
      epoch: 1,
      variableId: VAR,
      version: 2,
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(48),
      prevValueSigHashHex: "cd".repeat(32),
      writerUserId: MEMBER,
      chainHeadHashHex: oldTenureHead.hashHex,
      chainHeadSeq: oldTenureHead.seq,
    };
    const signatureHex = encodeHex(
      new Uint8Array(
        await crypto.subtle.sign(
          "Ed25519",
          newSigPair.privateKey,
          buildValueSignedBytes(context) as BufferSource,
        ),
      ),
    );
    const value = {
      suite: "maruhi/v1" as const,
      aad: aadFor(1, 2),
      nonceHex: context.nonceHex,
      ciphertextHex: context.ciphertextHex,
      prevValueSigHashHex: context.prevValueSigHashHex,
      chainHeadHashHex: context.chainHeadHashHex,
      chainHeadSeq: context.chainHeadSeq,
      signatureHex,
    };
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoVersionSideEffects([1]);
  });

  it("stores the signature block and server-computed hash on the version row (§12-5 の保存行)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const headAtWrite = { ...fixture.head };
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const rows = await queryProjectDo(
      projectId,
      `SELECT prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
              signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint
       FROM variable_versions WHERE environment_id = ? AND variable_id = ? AND version = 1`,
      ENV,
      VAR,
    );
    expect(rows[0]).toEqual({
      prev_value_sig_hash_hex: "",
      chain_head_hash_hex: headAtWrite.hashHex,
      chain_head_seq: headAtWrite.seq,
      signature_hex: v1.signatureHex,
      signed_bytes_hash_hex: await valueSignedBytesHashOf(v1, MEMBER),
      writer_user_id: MEMBER,
      writer_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });
  });
});

describe("エポックとローテーション(§12-4 複合 / §12-5 / §12-6 / CRYPTO_SPEC §7)", () => {
  it("accepts pushes only under the current chain epoch and completes the composite rotation flow", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const varV1 = await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek1, "var-static", "STATIC_KEY", "static-secret");

    // ローテーション前の未来エポック push も拒否
    const early = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(2, 2)) },
    );
    expect(early.status).toBe(409);
    await expect(early.json()).resolves.toMatchObject({ currentEpoch: 1 });

    // ローテーションは複合リクエスト(§12-4): 部分集合の同梱は 422 recipient-missing
    // で、チェーンエントリも追記されない(原子性)
    const dek2 = makeDek();
    const headBefore = fixture.head;
    const partial = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: [OWNER],
      signerUserId: MEMBER,
    });
    const rejected = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: partial,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(rejected.status).toBe(422);
    expect(((await rejected.json()) as { reason: string }).reason).toBe("recipient-missing");
    const chainAfterRejection = await requestJson("GET", "/chain", token(READER));
    expect(((await chainAfterRejection.json()) as { headSeq: number }).headSeq).toBe(
      headBefore.seq,
    );

    // 完全集合の複合ローテーション → エポック 2 へ(チェーン追記 + ラップ登録が原子)
    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const rotation = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: complete,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(rotation.status).toBe(200);
    await expect(rotation.clone().json()).resolves.toMatchObject({
      environmentId: ENV,
      currentEpoch: 2,
      headSeq: headBefore.seq + 1,
    });

    // 旧エポックの push は 409(現エポックを返す — クライアントは再暗号化して再試行)
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ currentEpoch: 2 });

    // 既存 (エポック, 受信者) の上書きは禁止(409 DekWrapExists)
    const overwrite = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: [READER],
        signerUserId: MEMBER,
      }),
    });
    expect(overwrite.status).toBe(409);
    const overwriteBody = (await overwrite.json()) as { epoch: number; recipientUserId: string };
    expect(overwriteBody).toMatchObject({ epoch: 2, recipientUserId: READER });

    // 未来エポック(3)宛の登録は 422 epoch-out-of-range
    const future = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 3,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(future.status).toBe(422);
    expect(((await future.json()) as { reason: string }).reason).toBe("epoch-out-of-range");

    // 新エポックで再暗号化した値を push(var-static は当時のエポックのまま保持 — §7)。
    // 宣言ヘッド = rotate エントリを含む現ヘッド、prev は v1 へ連鎖、エポックは
    // 単調(1 → 2)— ローテーション実行フローの §4.1 の形
    const v2 = await encryptValue(
      dek2,
      { projectId, environmentId: ENV, epoch: 2, variableId: VAR, version: 2 },
      "postgres://rotated",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(varV1, MEMBER),
      },
    );
    const pushed = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(pushed.status).toBe(200);
    await expect(pushed.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 2 });

    // pull: 現エポック 2、最新バージョンのエポックは変数ごとに異なる。全エポックの
    // 自分宛ラップが同梱され、両方のエポックの値をクライアント側で復号できる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      currentEpoch: number;
      variables: { variableId: string; value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(body.currentEpoch).toBe(2);
    expect(body.deks.map((wrap) => wrap.epoch)).toEqual([1, 2]);
    const rotated = body.variables.find((v) => v.variableId === VAR);
    const kept = body.variables.find((v) => v.variableId === "var-static");
    if (rotated === undefined || kept === undefined) throw new Error("missing pulled variables");
    expect(rotated.value.aad.epoch).toBe(2);
    expect(kept.value.aad.epoch).toBe(1);
    const dekByEpoch = new Map(body.deks.map((wrap) => [wrap.epoch, wrap]));
    const wrap1 = dekByEpoch.get(1);
    const wrap2 = dekByEpoch.get(2);
    if (wrap1 === undefined || wrap2 === undefined) throw new Error("missing dek wraps");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap2,
        projectId,
        environmentId: ENV,
        payload: rotated.value,
      }),
    ).resolves.toBe("postgres://rotated");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap1,
        projectId,
        environmentId: ENV,
        payload: kept.value,
      }),
    ).resolves.toBe("static-secret");
  });

  it("rejects a rotation to a deleted environment with 404 (§12-4: §7 の「全環境」は削除済みを含まない)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}`, token(OWNER));
    expect(removed.status).toBe(204);
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(404);
    expect(((await response.json()) as { environmentId: string }).environmentId).toBe(ENV);
  });

  it("rejects a rotation to an environment that was never created with 404", async () => {
    // 環境の存在はチェーン導出 + データ行(複合で原子的に作られる)。未作成の
    // 環境への rotate はデータ行の不在 = 404(unknown-environment の合意規則は
    // crypto 層のベクターが固定する — サーバーではデータ行検査が先に立つ)
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-ghost-9999",
      epoch: 2,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: "env-ghost-9999",
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(404);
  });

  it("rejects an out-of-sequence rotation with 422 chain-entry-invalid (epoch-out-of-sequence)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 3,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    // 現エポック 1 からの rotate は 2 のみ(CRYPTO_SPEC §6.3 — verifyChain が権威)
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("epoch-out-of-sequence");
  });

  it("rejects a rotation whose URL and entry name different environments (422 PayloadMismatch)", async () => {
    // 複合内整合検査(§12-4): 別環境のエントリ × 別環境の URL の組を受理しない
    await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
      urlEnvironmentId: "env-app-0002",
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("environmentId");
  });

  it("rejects composite wraps whose epoch differs from the entry's new epoch (422 epoch-out-of-range)", async () => {
    // §12-4 の複合内整合検査: 同梱ラップの epoch = エントリの new_epoch。
    // エポック 1 宛(登録済みエポック)のラップを rotate 複合に紛れ込ませても拒否
    await createEnvironmentOk(fixture, ENV, "App");
    const headBefore = fixture.head;
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("epoch-out-of-range");
    // 原子性: エントリも追記されない(エポックは 1 のまま)
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as { environments: { currentEpoch: number }[] };
    expect(listBody.environments[0]?.currentEpoch).toBe(1);
  });

  it("retries a composite rotation after a head CAS conflict (§12-4 の再署名リトライ)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const stale = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: projectId, // genesis ハッシュ = 古いヘッド
    });
    expect(stale.status).toBe(409);
    const staleBody = (await stale.json()) as { currentHeadHashHex: string };
    expect(staleBody.currentHeadHashHex).toBe(fixture.head.hashHex);
    // 正しい親ヘッドで作り直したエントリ(再署名)は受理される
    const retried = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
  });
});

describe("DEK 配布と新メンバーのバックフィル(§12-6 / CRYPTO_SPEC §7)", () => {
  it("distributes only the caller's wraps", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { deks: { epoch: number }[] };
    expect(body.deks.length).toBe(1);
    expect(body.deks[0]?.epoch).toBe(1);
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    // 全体では 3 人分あるが、応答には呼び出し主体宛のみ
    expect(rows[0]?.["n"]).toBe(3);
  });

  it("backfills historical epoch DEKs for a newly added member, who can then decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // 新メンバー(テスト時生成の実鍵)を add_member でチェーンに追加
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const encPubHex = encodeHex(await exportEncryptionPublicKey(encPair.publicKey));
    const sigPubHex = encodeHex(await exportSigningPublicKey(sigPair.publicKey));
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: { targetUserId: STRANGER, encPubHex, sigPubHex, role: "member" },
    });

    // 招待者(owner)が既存エポックの DEK を新メンバー宛にラップして登録(§7)
    const backfill = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: STRANGER,
      recipientEncPubHex: encPubHex,
      signerUserId: OWNER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [backfill],
    });
    expect(registered.status).toBe(204);

    // 新メンバーは pull → 自分の鍵で復号できる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(STRANGER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    const unwrapped = await unwrapDek({
      recipientKeyPair: encPair,
      wrapped: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
      context: { projectId, environmentId: ENV, epoch: 1, recipientUserId: STRANGER },
    });
    if (!unwrapped.ok) throw new Error("unwrap failed");
    const decrypted = await decryptVariable({
      dek: unwrapped.value,
      context: pulled.value.aad,
      nonce: hexBytes(pulled.value.nonceHex),
      ciphertext: hexBytes(pulled.value.ciphertextHex),
    });
    if (!decrypted.ok) throw new Error("decrypt failed");
    expect(new TextDecoder().decode(decrypted.value)).toBe("postgres://alpha");
  });

  it("supports session-cookie auth with the CSRF header for data writes (§5)", async () => {
    const session = await loginSession(9001);
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const body = JSON.stringify({
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      name: "App",
      deks,
    });
    // CSRF ヘッダーなしの書き込みは 403
    const headers = sessionHeaders(session);
    const withoutCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, cookie: headers["cookie"] ?? "" },
      body,
    });
    expect(withoutCsrf.status).toBe(403);
    const accepted = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...headers },
      body,
    });
    expect(accepted.status).toBe(200);
  });
});

describe("DEK ラップの修復経路(§12-6: 削除 → 不足分再登録)", () => {
  it("deletes a poisoned wrap as admin and restores it through the append path", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // owner(admin スコープ × チェーン role owner ≥ admin)が READER 宛を削除
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const rows = await queryProjectDo(
      projectId,
      "SELECT recipient_user_id FROM dek_wraps WHERE environment_id = ? ORDER BY recipient_user_id",
      ENV,
    );
    expect(rows.map((row) => row["recipient_user_id"])).toEqual([MEMBER, OWNER].toSorted());
    const emptied = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    await expect(emptied.json()).resolves.toEqual({ deks: [] });

    // 不足分の追記経路(§12-6)で正しいラップを再登録 → READER は再び復号できる
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [reWrap],
    });
    expect(registered.status).toBe(204);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("requires admin token scope and chain role admin (§12-3: 環境削除と同水準)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // member のデフォルト PAT はスコープ admin だがチェーン role が member → 403
    const asMember = await requestJson("DELETE", `/environments/${ENV}/deks`, token(MEMBER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(asMember.status).toBe(403);
    expect(((await asMember.json()) as { reason: string }).reason).toBe("insufficient-role");
    // owner でもトークンスコープが write では 403(insufficient-permission)
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await deviceToken(9001, writeScope);
    const scoped = await requestJson("DELETE", `/environments/${ENV}/deks`, ownerWrite, {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(scoped.status).toBe(403);
    expect(((await scoped.json()) as { reason: string }).reason).toBe("insufficient-permission");
    // 非メンバーにはプロジェクト自体を秘匿(404 — §11-2)
    const concealed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(STRANGER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(concealed.status).toBe(404);
    expect(((await concealed.json()) as { projectId: string }).projectId).toBe(projectId);
  });

  it("rejects missing tuples with 404 atomically and duplicate refs with 422", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 1 件目は存在・2 件目が不存在 → 404(DekWrapNotFound)で、何も消えない
    const partial = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: READER },
        { epoch: 1, recipientUserId: "user-nobody-0404" },
      ],
    });
    expect(partial.status).toBe(404);
    await expect(partial.json()).resolves.toMatchObject({
      epoch: 1,
      recipientUserId: "user-nobody-0404",
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(3);
    // 拒否された削除は監査行(dek.deleted)を一切残さない(検証と書き込みの分離)
    const audits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(audits[0]?.["n"]).toBe(0);
    // 同一タプルの重複列挙は 422(duplicate-recipient)
    const duplicated = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: READER },
        { epoch: 1, recipientUserId: READER },
      ],
    });
    expect(duplicated.status).toBe(422);
    expect(((await duplicated.json()) as { reason: string }).reason).toBe("duplicate-recipient");
  });

  it("treats re-registration after a full epoch deletion as an initial registration (§12-6)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // エポック 1 の全ラップを削除 → 再登録は初回登録として完全一致を要求される
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removed.status).toBe(204);
    const partial = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: ENV,
          epoch: 1,
          dek,
          recipientUserId: OWNER,
          signerUserId: MEMBER,
        }),
      ],
    });
    expect(partial.status).toBe(422);
    expect(((await partial.json()) as { reason: string }).reason).toBe("recipient-missing");
    // 完全集合なら受理され、受信者は再び復号できる
    const complete = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 1,
        dek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(complete.status).toBe(204);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("rejects deletion requests for missing environments, empty lists and oversized lists", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 空列挙は 400(Schema。監査痕跡ゼロの破壊系呼び出し形を許さない — §12-6)
    const empty = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [],
    });
    expect(empty.status).toBe(400);
    // 件数上限は登録側と同じ MAX_DEK_WRAPS_PER_REQUEST(存在検証より先に判定)
    const oversized = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
        epoch: 1,
        recipientUserId: `u${index}`,
      })),
    });
    expect(oversized.status).toBe(422);
    await expect(oversized.json()).resolves.toMatchObject({
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    });
    // tombstone 環境(ラップは物理削除済み)への削除は 404 EnvironmentNotFound
    const removedEnv = await requestJson("DELETE", `/environments/${ENV}`, token(OWNER));
    expect(removedEnv.status).toBe(204);
    const gone = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(gone.status).toBe(404);
    // DekWrapNotFound({epoch, recipientUserId})ではなく EnvironmentNotFound({environmentId})
    const goneBody = (await gone.json()) as { environmentId?: string; epoch?: number };
    expect(goneBody.environmentId).toBe(ENV);
    expect(goneBody.epoch).toBeUndefined();
  });
});

describe("DEK ラップの登録署名(§12-6 / CRYPTO_SPEC §5.1)", () => {
  it("rejects wraps signed by someone other than the caller (422 signature-invalid, 登録 API 経路)", async () => {
    // 登録 API は修復再登録・バックフィル専用に縮退した(§12-6)。修復経路で
    // エポック 1 の全ラップを削除し、OWNER が署名した完全集合を MEMBER が
    // 持ち込む → 呼び出し主体 = 署名者の厳密一致に反するため拒否。
    // 何も挿入されず監査行も残らない
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removed.status).toBe(204);
    const auditsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    const signedByOwner = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: signedByOwner,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = 1",
      ENV,
    );
    expect(rows.length).toBe(0);
    const auditsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    expect(auditsAfter[0]?.["n"]).toBe(auditsBefore[0]?.["n"]);
  });

  it("rejects a transplanted signature on environment creation (422 signature-invalid, 同梱経路)", async () => {
    // 同じ署名者(OWNER)による正しい署名でも、別ラップ(別受信者)の署名の
    // 移植は signed_bytes が異なるため検証に失敗する
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const [first, second, third] = deks;
    if (first === undefined || second === undefined || third === undefined) {
      throw new Error("missing wraps");
    }
    const transplanted = [first, { ...second, signatureHex: first.signatureHex }, third];
    const response = await createEnvironmentWith(fixture, ENV, "App", transplanted);
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    // 環境は作られない(署名検証は書き込みフェーズより前)
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [] });
  });

  it("rejects wraps without a signature (400 Schema, 両経路)", async () => {
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const stripped = deks.map(({ signatureHex: _signatureHex, ...rest }) => rest);
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const created = await requestJson("POST", "/environments", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      name: "App",
      deks: stripped,
    });
    expect(created.status).toBe(400);
    // 登録 API 経路も同じ Schema(WrappedDekSchema)で 400
    await createEnvironmentOk(fixture, ENV, "App");
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: stripped,
    });
    expect(registered.status).toBe(400);
  });

  it("rejects malformed signatures with 400 (Schema: 大文字 hex / 長さ不正 / 非 hex)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const [wrap] = await wrapsFor(ENV, [OWNER], 1, MEMBER);
    if (wrap === undefined) throw new Error("missing wrap");
    for (const signatureHex of [
      wrap.signatureHex.toUpperCase(),
      wrap.signatureHex.slice(2),
      `zz${wrap.signatureHex.slice(2)}`,
    ]) {
      const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
        deks: [{ ...wrap, signatureHex }],
      });
      expect(response.status).toBe(400);
    }
  });

  it("rejects third-party re-submission into a deleted slot (signer mismatch)", async () => {
    // CRYPTO_SPEC §5.1 の名指しシナリオ: 削除済みスロットへ「他人の署名済み
    // ラップ」を第三者が再投入する経路は署名者不一致で塞がる。
    // かつては「MEMBER の鍵一式を流用したソック垢(STRANGER)」の最強形
    // (鍵一致・user_id 不一致)をここで固定していたが、§6.2 のメンバー鍵一意性
    // (2026-08-03)により鍵重複メンバーはチェーン追記の時点で成立しなくなった
    // (下の chain-level テストと membership.test.ts の authz ベクターループが
    // 固定する)。鍵一致のまま signer_user_id だけが異なる署名の拒否は
    // ベクター negative `transplant-signer` が crypto 層で固定し続ける
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [reWrap],
    });
    expect(registered.status).toBe(204);

    // STRANGER(自前の鍵で正規にメンバー化)が MEMBER 署名のラップをそのまま
    // 再投入 → 呼び出し主体 = 署名者の厳密一致(§12-6)に反するため 422
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: encodeHex(await exportEncryptionPublicKey(encPair.publicKey)),
        sigPubHex: encodeHex(await exportSigningPublicKey(sigPair.publicKey)),
        role: "member",
      },
    });
    const removedAgain = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removedAgain.status).toBe(204);
    const replayed = await requestJson("POST", `/environments/${ENV}/deks`, token(STRANGER), {
      deks: [reWrap],
    });
    expect(replayed.status).toBe(422);
    expect(((await replayed.json()) as { reason: string }).reason).toBe("signature-invalid");
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?",
      ENV,
      READER,
    );
    expect(rows.length).toBe(0);
  });

  it("rejects the key-reuse sock puppet at the chain layer (422 duplicate-member-key)", async () => {
    // かつて上のテストが利用していた「MEMBER の鍵一式を流用した STRANGER の
    // add_member」は、§6.2 のメンバー鍵一意性(合意規則)によりチェーン追記の
    // 時点で拒否される(帰属付け替えの根本原因の解消 — 防衛の多層化)。
    // ベクター固定チェーンに対する網羅は membership.test.ts の authz ループ
    // (authz-add-member-duplicate-key ほか 2 件)が担い、ここではデータプレーンの
    // fixture チェーンでも成立することを固定する
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "add_member",
        payload: {
          targetUserId: STRANGER,
          encPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
          sigPubHex: vectorKeyOf(MEMBER).sig_pub_hex,
          role: "member",
        },
      },
    });
    const response = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("duplicate-member-key");
    expect(body.seq).toBe(fixture.head.seq + 1);
  });

  it("accepts the original signer re-registering the identical wrap and signature (§5.1 の意味論の対)", async () => {
    // 署名は帰属であり鮮度証明ではない: 削除後、元署名者自身による同一内容 +
    // 同一署名の再登録は有効(タイムスタンプ・ノンスを含めない設計の positive 側)
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const created = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(created.status).toBe(200);
    const readerWrap = deks.find((wrap) => wrap.recipientUserId === READER);
    if (readerWrap === undefined) throw new Error("missing reader wrap");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const restored = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [readerWrap],
    });
    expect(restored.status).toBe(204);
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    const body = (await mine.json()) as { deks: { signatureHex: string }[] };
    expect(body.deks[0]?.signatureHex).toBe(readerWrap.signatureHex);
  });

  it("rejects an empty registration list with 400 (§12-6: 削除側の空列挙と同じ規律)", async () => {
    // 空の deks: [] はかつて 204 の silent no-op だった(session-08/09 の
    // 申し送り)。呼び出し形として意味のあるユースケースがなく、silent no-op は
    // クライアントバグ(空配列の送信を登録完了と誤認)を隠すため、削除側の
    // 空 wraps 400 と同じ minItems 1 の Schema 検証で拒否する(2026-08-03 統一)
    await createEnvironmentOk(fixture, ENV, "App");
    const before = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [],
    });
    expect(response.status).toBe(400);
    const after = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    expect(after[0]?.["n"]).toBe(before[0]?.["n"]);
  });

  it("distributes the signature and signer identity, verifiable client-side (§12-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    for (const path of [`/environments/${ENV}/deks`, `/environments/${ENV}/pull`] as const) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        deks: {
          suite: string;
          epoch: number;
          encHex: string;
          ciphertextHex: string;
          signatureHex: string;
          signerUserId: string;
          signerKeyFingerprintHex: string;
        }[];
      };
      const wrap = body.deks[0];
      if (wrap === undefined) throw new Error("missing distributed wrap");
      expect(wrap.signerUserId).toBe(OWNER);
      expect(wrap.signerKeyFingerprintHex).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
      // クライアント検証(CRYPTO_SPEC §5.1): 自分の座標 + 署名者のチェーン鍵で検証
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: ENV,
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap,
        }),
      ).resolves.toBe(true);
      // 座標を偽ると検証失敗(クライアント側の移植検出)
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: "env-forged-0001",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap,
        }),
      ).resolves.toBe(false);
      // サーバーが署名者を偽って申告しても検証失敗(signer_user_id も署名対象 —
      // CRYPTO_SPEC §5.1。ベクター transplant-signer の統合レベルの対)
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: ENV,
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap: { ...wrap, signerUserId: MEMBER },
        }),
      ).resolves.toBe(false);
    }
  });

  it("accepts a caller-signed poison wrap: 署名は帰属であり内容検証ではない(§5.1 の意味論)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    // 中身が復号不能なフェイクでも、呼び出し主体(MEMBER)の署名が正しければ
    // 受理される(サーバーはラップの中身を検証できない — E2EE)。ただし帰属は
    // 署名 + dek.registered の FP でサーバー不信のまま MEMBER に固定される
    const poison = await signWrapAs(MEMBER, projectId, ENV, {
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: READER,
      recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [poison],
    });
    expect(registered.status).toBe(204);
    const rows = await queryProjectDo(
      projectId,
      `SELECT signer_user_id FROM dek_wraps
       WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?`,
      ENV,
      READER,
    );
    expect(rows[0]?.["signer_user_id"]).toBe(MEMBER);
  });

  it("attributes repair-path re-registration via the signer fingerprint (削除 → 署名付き再登録 → 突合)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // admin(owner)が毒ラップ想定の READER 宛を削除 → MEMBER が自署名で再登録
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [reWrap],
    });
    expect(registered.status).toBe(204);

    // 保存行の署名者は MEMBER(user_id + FP)
    const rows = await queryProjectDo(
      projectId,
      `SELECT signer_user_id, signer_key_fingerprint FROM dek_wraps
       WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?`,
      ENV,
      READER,
    );
    expect(rows[0]).toEqual({
      signer_user_id: MEMBER,
      signer_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });

    // dek.registered の署名者 FP で帰属を突合できる(AUDIT_SPEC §3.3):
    // 初回登録(環境作成の同梱 = OWNER 署名)→ 再登録(MEMBER 署名)の順
    const audits = await queryProjectDo(
      projectId,
      `SELECT actor_user_id, actor_key_fingerprint FROM audit_events
       WHERE event = 'dek.registered' AND target_user_id = ? ORDER BY seq`,
      READER,
    );
    expect(audits).toEqual([
      {
        actor_user_id: OWNER,
        actor_key_fingerprint: vectorKeyOf(OWNER).key_fingerprint_hex,
      },
      {
        actor_user_id: MEMBER,
        actor_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
      },
    ]);

    // READER は再登録されたラップの署名を検証してから復号できる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: {
        suite: string;
        epoch: number;
        encHex: string;
        ciphertextHex: string;
        signatureHex: string;
        signerUserId: string;
      }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(wrap.signerUserId).toBe(MEMBER);
    await expect(
      verifyDistributedWrapSignature({
        projectId,
        environmentId: ENV,
        recipientUserId: READER,
        recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        wrap,
      }),
    ).resolves.toBe(true);
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });
});

describe("suite の永続化とワイヤ(§12-2 / CRYPTO_SPEC §2 設計原則 4)", () => {
  it("stores the suite on versions and wraps and returns it on every distribution path", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const versionRows = await queryProjectDo(
      projectId,
      "SELECT suite FROM variable_versions WHERE environment_id = ?",
      ENV,
    );
    expect(versionRows.map((row) => row["suite"])).toEqual(["maruhi/v1"]);
    const wrapRows = await queryProjectDo(
      projectId,
      "SELECT DISTINCT suite FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    expect(wrapRows.map((row) => row["suite"])).toEqual(["maruhi/v1"]);

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: { suite: string } }[];
      deks: { suite: string }[];
    };
    expect(body.variables[0]?.value.suite).toBe("maruhi/v1");
    expect(body.deks[0]?.suite).toBe("maruhi/v1");
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    const mineBody = (await mine.json()) as { deks: { suite: string }[] };
    expect(mineBody.deks[0]?.suite).toBe("maruhi/v1");
  });

  it("rejects wraps without a suite or with an unpinned suite (400 Schema)", async () => {
    const base = await wrapsFor(ENV, ALL_MEMBERS);
    const stripped = base.map(({ suite: _suite, ...rest }) => rest);
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const compositeBase = { parentHeadHashHex: fixture.head.hashHex, entry, name: "App" };
    const missing = await requestJson("POST", "/environments", token(OWNER), {
      ...compositeBase,
      deks: stripped,
    });
    expect(missing.status).toBe(400);
    const wrong = await requestJson("POST", "/environments", token(OWNER), {
      ...compositeBase,
      deks: base.map((wrap) => ({ ...wrap, suite: "maruhi/v2" })),
    });
    expect(wrong.status).toBe(400);
  });
});

describe("数量ポリシー(§12-8 の残り: 環境・変数・ラップ件数)", () => {
  // 実生成は非現実的なため、行を SQL で直接シードして判定のプラミングを検証する
  it("caps active environments (422 environments)", async () => {
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO environments (environment_id, name, created_at, deleted_at)
       SELECT 'env-seed-' || n, 'seed-' || n, 0, NULL FROM seq`,
      MAX_ACTIVE_ENVIRONMENTS,
    );
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "environments",
      limit: MAX_ACTIVE_ENVIRONMENTS,
    });
  });

  it("caps environment rows including tombstones (422 environment-rows)", async () => {
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO environments (environment_id, name, created_at, deleted_at)
       SELECT 'env-seed-' || n, 'seed-' || n, 0, 1 FROM seq`,
      MAX_ENVIRONMENT_ROWS,
    );
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "environment-rows",
      limit: MAX_ENVIRONMENT_ROWS,
    });
  });

  it("caps active variables per environment (422 variables)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO variables (environment_id, variable_id, name, latest_version, created_at, deleted_at)
       SELECT ?, 'var-seed-' || n, 'SEED_' || n, 1, 0, NULL FROM seq`,
      MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
      ENV,
    );
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "DATABASE_URL",
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "variables",
      limit: MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
    });
  });

  it("caps variable rows including tombstones (422 variable-rows)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO variables (environment_id, variable_id, name, latest_version, created_at, deleted_at)
       SELECT ?, 'var-seed-' || n, 'SEED_' || n, 1, 0, 1 FROM seq`,
      MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
      ENV,
    );
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "DATABASE_URL",
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "variable-rows",
      limit: MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
    });
  });

  it("caps DEK wraps per request (422 dek-wraps-per-request)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 件数上限は受信者検証・署名検証より先に判定されるため、構造だけ正しいフェイクで足りる
    const deks = Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: `u${index}`,
      recipientEncPubHex: "ab".repeat(32),
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
      signatureHex: "00".repeat(64),
    }));
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    });
  });

  it("caps cumulative dek-wrap rows across every insertion path (422 §12-8, unit + plumbing)", async () => {
    // 純関数の判定(100 万行の実登録は非現実的 — projectBytesExceeded と同じ形)
    expect(wrapRowsExceeded(MAX_PROJECT_DEK_WRAP_ROWS, 1)).toBe(true);
    expect(wrapRowsExceeded(MAX_PROJECT_DEK_WRAP_ROWS - 3, 3)).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // 既存 3 行(エポック 1 の完全集合)+ シードで上限ちょうどまで埋める
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO dek_wraps
         (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       SELECT 'env-wrap-seed', n, 'u-seed', 'maruhi/v1', '', '', '', '', '', '', 0 FROM seq`,
      MAX_PROJECT_DEK_WRAP_ROWS - 3,
    );

    // 経路 1: 複合ローテーション(§12-4)の同梱集合も上限に束縛され、超過なら
    // チェーンエントリごと拒否される(原子性)
    const headBefore = fixture.head;
    const rotation = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(rotation.status).toBe(422);
    await expect(rotation.json()).resolves.toMatchObject({
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);

    // 経路 2: 複合の環境作成(エポック 1 の同梱集合)も同じ上限に束縛される
    const created = await createEnvironmentWith(
      fixture,
      "env-wrap-limit",
      "Limit",
      await wrapsFor("env-wrap-limit", ALL_MEMBERS),
    );
    expect(created.status).toBe(422);
    await expect(created.json()).resolves.toMatchObject({
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });

    // 経路 3: 登録 API(修復再登録 — §12-6)も同じ上限に束縛される
    const removedOne = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removedOne.status).toBe(204);
    // 3 行解放 → 上限まで 3 行の余裕。4 行(シード +1)を足して再び上限超過にする
    await queryProjectDo(
      projectId,
      `INSERT INTO dek_wraps
         (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       VALUES ('env-wrap-seed', 0, 'u-seed-extra', 'maruhi/v1', '', '', '', '', '', '', 0)`,
    );
    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const reRegistered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: complete,
    });
    expect(reRegistered.status).toBe(422);
    await expect(reRegistered.json()).resolves.toMatchObject({
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });

    // 削除(修復経路)は行を解放する: 追加シード分を消せば完全集合が再び通る
    await queryProjectDo(
      projectId,
      "DELETE FROM dek_wraps WHERE recipient_user_id = 'u-seed-extra'",
    );
    const retried = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: complete,
    });
    expect(retried.status).toBe(204);
  });
});

describe("判定順と Schema 境界(§12-3 / §12-2)", () => {
  it("AAD 自己整合検査(422)は存在秘匿(404)に先行する(§12-3 の例外規定)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 非メンバーでも、AAD がリクエスト自身と食い違うなら 422(存在情報を運ばない)。
    // どちらも認可判定で止まり値署名の検証には到達しない(§12-3 の判定順)ため
    // 未署名フェイクで足りる(STRANGER はベクター鍵を持たない)
    const mismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(STRANGER),
      { value: unsignedPayload(aadFor(1, 2, { variableId: "var-other" })) },
    );
    expect(mismatch.status).toBe(422);
    // AAD が自己整合していれば非メンバーには 404(§11-2)
    const consistent = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(STRANGER),
      { value: unsignedPayload(aadFor(1, 2)) },
    );
    expect(consistent.status).toBe(404);
  });

  it("rejects malformed ids and payloads with 400 (Schema)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 不正な environment_id(先頭ハイフン / 65 文字)は 400
    for (const badId of ["-bad", "a".repeat(65)]) {
      const response = await requestJson("GET", `/environments/${badId}/pull`, token(READER));
      expect(response.status).toBe(400);
    }
    // 複合 create のエントリ内 environment_id にも §12-1 の受理ポリシー形式を
    // 強制する(400): 複合化で ID の運搬がチェーンエントリ内へ移り URL 座標を
    // 持たないため、緩い形式を通すと URL param を持つ後続エンドポイント
    // (rotate / rename / delete / pull)から到達不能な環境が生まれる
    for (const badId of ["-bad", "a".repeat(65), "my env/💥"]) {
      const { entry } = await signEntryAt({
        seq: fixture.head.seq + 1,
        prevHashHex: fixture.head.hashHex,
        actorUserId: OWNER,
        operation: {
          op: "create_environment",
          payload: { environmentId: badId, dekCommitmentHex: "ab".repeat(32) },
        },
      });
      const response = await requestJson("POST", "/environments", token(OWNER), {
        parentHeadHashHex: fixture.head.hashHex,
        entry,
        name: `Bad-${badId.length}`,
        deks: [],
      });
      expect(response.status).toBe(400);
    }
    // 不正な EncryptedPayload: suite 不一致 / 大文字 hex nonce / タグ未満の暗号文 /
    // 署名ブロックの形式違反(大文字署名 / prev 長不正 / head hash 長不正 /
    // chainHeadSeq 0)— いずれも Schema の 400(署名検証より前)
    const base = unsignedPayload(aadFor(1, 1));
    const badPayloads = [
      { ...base, suite: "maruhi/v2" },
      { ...base, nonceHex: "AB".repeat(12) },
      { ...base, ciphertextHex: "ab".repeat(15) },
      { ...base, signatureHex: "AB".repeat(64) },
      { ...base, signatureHex: "ab".repeat(63) },
      { ...base, prevValueSigHashHex: "ab".repeat(31) },
      { ...base, chainHeadHashHex: "ab".repeat(31) },
      { ...base, chainHeadSeq: 0 },
    ];
    for (const value of badPayloads) {
      const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
        variableId: VAR,
        name: "DATABASE_URL",
        value,
      });
      expect(response.status).toBe(400);
    }
  });
});
