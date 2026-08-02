// データプレーン API(AUTH_SPEC §12)の統合テスト。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// 実データ主義: チェーンはテスト時署名(ベクター固定鍵)、DEK ラップは実 HPKE、
// 値は実 AES-GCM で作り、pull 後にクライアント側復号まで検証する。フェイクの
// 暗号文を使うのは「サーバーは中身を検証できない」ことを利用する受理ポリシー系
// テストのみ(各テストに明記)。

import type { TokenScope } from "@maruhi/core";
import {
  decryptVariable,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  unwrapDek,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { projectBytesExceeded } from "../src/data-programs.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_DEK_WRAPS_PER_REQUEST,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_VALUE_CIPHERTEXT_BYTES,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "../src/policy.ts";
import { bearer, deviceToken, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  hexBytes,
  makeDek,
  unwrapAndDecrypt,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentWith,
  dataUrl,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
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

/** 受理ポリシー系テスト用のフェイク暗号文(サーバーは中身を検証できない)。 */
function fakePayload(aad: WireEncryptedPayload["aad"], ciphertextBytes = 48): WireEncryptedPayload {
  return {
    suite: "maruhi/v1",
    aad,
    nonceHex: "00".repeat(12),
    ciphertextHex: "ab".repeat(ciphertextBytes),
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

/** 変数作成(実暗号化)。 */
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

describe("環境管理(§12-4)", () => {
  it("creates an environment atomically with the epoch-1 wrap set and lists it", async () => {
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
    });
    const created = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(created.status).toBe(200);
    await expect(created.json()).resolves.toEqual({
      environmentId: ENV,
      name: "App",
      currentEpoch: 1,
    });

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

  it("rejects a duplicate environment id with 409 (exists)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
    });
    const response = await createEnvironmentWith(fixture, ENV, "App2", deks);
    expect(response.status).toBe(409);
    const body = (await response.json()) as { environmentId: string; reason: string };
    expect(body).toMatchObject({ environmentId: ENV, reason: "exists" });
  });

  it("never reuses a deleted environment id (409 retired) and hard-deletes its data", async () => {
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

    const recreated = await createEnvironmentWith(fixture, ENV, "App3", []);
    expect(recreated.status).toBe(409);
    const body = (await recreated.json()) as { reason: string };
    expect(body.reason).toBe("retired");
  });

  it("rejects creating an environment whose id was burned by a chain rotate_epoch (§12-4)", async () => {
    // メタデータに対応しない rotate_epoch もチェーンとしては受理される(突合しない)
    await appendOperation(fixture, MEMBER, {
      op: "rotate_epoch",
      payload: { environmentId: "env-burned-0001", newEpoch: 2, reason: "burn" },
    });
    const response = await createEnvironmentWith(fixture, "env-burned-0001", "Burned", []);
    expect(response.status).toBe(409);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("retired");
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
    });
    const response = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token(READER)) },
      body: JSON.stringify({ environmentId: ENV, name: "App", deks }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
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

const wrapsFor = (environmentId: string, recipients: readonly string[], epoch = 1) =>
  wrapDekForAll({
    projectId,
    environmentId,
    epoch,
    dek: makeDek(),
    recipientUserIds: recipients,
  });

describe("環境作成の DEK ラップ検証(§12-6)", () => {
  it("rejects a wrap set missing a current member (422 recipient-missing)", async () => {
    const deks = await wrapsFor(ENV, [OWNER, MEMBER]);
    const response = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-missing");
  });

  it("rejects an empty wrap set (§12-4: エポック 1 の完全集合の同梱は必須)", async () => {
    // レビューループ 1 の指摘: 空集合はエポック単位の検査をすり抜けて
    // 「誰も DEK を持てない環境」を作れてしまう。個数 = 現メンバー数の明示検査で塞ぐ
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("recipient-missing");
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [] });
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

    // 新バージョンを push すると pull は最新のみ返す
    const v2 = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "postgres://beta",
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
        { value: fakePayload(aadFor(1, 2, override)) },
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
      { value: fakePayload(aadFor(1, 1)) },
    );
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ currentVersion: 1 });

    // 飛び番(3)も拒否
    const skipped = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: fakePayload(aadFor(1, 3)) },
    );
    expect(skipped.status).toBe(409);
    await expect(skipped.json()).resolves.toMatchObject({ currentVersion: 1 });
  });

  it("creation requires version 1 (409 currentVersion 0)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "DATABASE_URL",
      value: fakePayload(aadFor(1, 2)),
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({ currentVersion: 0 });
  });

  it("serializes concurrent pushes: exactly one winner, no lost or interleaved writes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const contenders = await Promise.all(
      Array.from({ length: 8 }, (_v, index) =>
        encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
          `postgres://contender-${index}`,
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
    for (const id of ids) {
      await createVariableOk(dek, id, `NAME_${id}`, `value-${id}`);
    }
    const values = await Promise.all(
      ids.map((id) =>
        encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: id, version: 2 },
          `next-${id}`,
        ),
      ),
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
      { value: fakePayload(aadFor(1, 2)) },
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
      { value: fakePayload(aadFor(1, 2)) },
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
      { value: fakePayload(aadFor(1, 2)) },
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
      value: fakePayload(aadFor(1, 1)),
    });
    expect(duplicate.status).toBe(409);
    expect(((await duplicate.json()) as { reason: string }).reason).toBe("exists");

    const sameName = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: "var-other",
      name: "DATABASE_URL",
      value: fakePayload({ ...aadFor(1, 1), variableId: "var-other" }),
    });
    expect(sameName.status).toBe(409);
    expect(((await sameName.json()) as { reason: string }).reason).toBe("duplicate-name");

    // 作成側の申告 AAD 不一致(§12-2): body の variableId と aad の不一致は 422
    const createMismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      { variableId: "var-other", name: "OTHER", value: fakePayload(aadFor(1, 1)) },
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
      value: fakePayload(aadFor(1, 1)),
    });
    expect(retired.status).toBe(409);
    expect(((await retired.json()) as { reason: string }).reason).toBe("retired");

    // 削除済み変数への push は 404
    const pushDeleted = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: fakePayload(aadFor(1, 2)) },
    );
    expect(pushDeleted.status).toBe(404);
  });

  it("rejects an oversized ciphertext with 413 (§12-8)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      variableId: VAR,
      name: "BIG",
      value: fakePayload(aadFor(1, 1), MAX_VALUE_CIPHERTEXT_BYTES + 1),
    });
    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      limitBytes: MAX_VALUE_CIPHERTEXT_BYTES,
    });
  });

  it("caps versions per variable (422 §12-8)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 1,000 回の実 push は非現実的なので latest_version を直接引き上げる
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: fakePayload(aadFor(1, MAX_VERSIONS_PER_VARIABLE + 1)) },
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
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
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
      { value: fakePayload(aadFor(1, 2)) },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "project-ciphertext-bytes",
      limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
    });
  });
});

describe("エポックとローテーション(§12-5 / §12-6 / CRYPTO_SPEC §7)", () => {
  it("accepts pushes only under the current chain epoch and completes the rotation flow", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek1, "var-static", "STATIC_KEY", "static-secret");

    // ローテーション前の未来エポック push も拒否
    const early = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: fakePayload(aadFor(2, 2)) },
    );
    expect(early.status).toBe(409);
    await expect(early.json()).resolves.toMatchObject({ currentEpoch: 1 });

    // rotate_epoch(チェーン追記)でエポック 2 へ
    await appendOperation(fixture, MEMBER, {
      op: "rotate_epoch",
      payload: { environmentId: ENV, newEpoch: 2, reason: "scheduled" },
    });

    // 旧エポックの push は 409(現エポックを返す — クライアントは再暗号化して再試行)
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: fakePayload(aadFor(1, 2)) },
    );
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ currentEpoch: 2 });

    // 新エポックの初回登録は完全集合を要求(部分は 422 recipient-missing)
    const dek2 = makeDek();
    const partial = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: [OWNER],
    });
    const rejected = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: partial,
    });
    expect(rejected.status).toBe(422);
    expect(((await rejected.json()) as { reason: string }).reason).toBe("recipient-missing");

    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: complete,
    });
    expect(registered.status).toBe(204);

    // 既存 (エポック, 受信者) の上書きは禁止(409 DekWrapExists)
    const overwrite = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: [READER],
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
      }),
    });
    expect(future.status).toBe(422);
    expect(((await future.json()) as { reason: string }).reason).toBe("epoch-out-of-range");

    // 新エポックで再暗号化した値を push(var-static は当時のエポックのまま保持 — §7)
    const v2 = await encryptValue(
      dek2,
      { projectId, environmentId: ENV, epoch: 2, variableId: VAR, version: 2 },
      "postgres://rotated",
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
    });
    // CSRF ヘッダーなしの書き込みは 403
    const headers = sessionHeaders(session);
    const withoutCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, cookie: headers["cookie"] ?? "" },
      body: JSON.stringify({ environmentId: ENV, name: "App", deks }),
    });
    expect(withoutCsrf.status).toBe(403);
    const accepted = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...headers },
      body: JSON.stringify({ environmentId: ENV, name: "App", deks }),
    });
    expect(accepted.status).toBe(200);
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
      value: fakePayload(aadFor(1, 1)),
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
      value: fakePayload(aadFor(1, 1)),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "variable-rows",
      limit: MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
    });
  });

  it("caps DEK wraps per request (422 dek-wraps-per-request)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 件数上限は受信者検証より先に判定されるため、構造だけ正しいフェイクで足りる
    const deks = Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
      epoch: 1,
      recipientUserId: `u${index}`,
      recipientEncPubHex: "ab".repeat(32),
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
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
});

describe("判定順と Schema 境界(§12-3 / §12-2)", () => {
  it("AAD 自己整合検査(422)は存在秘匿(404)に先行する(§12-3 の例外規定)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 非メンバーでも、AAD がリクエスト自身と食い違うなら 422(存在情報を運ばない)
    const mismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(STRANGER),
      { value: fakePayload(aadFor(1, 2, { variableId: "var-other" })) },
    );
    expect(mismatch.status).toBe(422);
    // AAD が自己整合していれば非メンバーには 404(§11-2)
    const consistent = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(STRANGER),
      { value: fakePayload(aadFor(1, 2)) },
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
    // 不正な EncryptedPayload: suite 不一致 / 大文字 hex nonce / タグ未満の暗号文
    const base = fakePayload(aadFor(1, 1));
    const badPayloads = [
      { ...base, suite: "maruhi/v2" },
      { ...base, nonceHex: "AB".repeat(12) },
      { ...base, ciphertextHex: "ab".repeat(15) },
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
