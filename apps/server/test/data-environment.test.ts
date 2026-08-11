// データプレーン API(AUTH_SPEC §12)の統合テスト — 環境管理・複合作成の DEK ラップ検証・エポックとローテーション(AUTH_SPEC §12-4 / §12-6)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  makeDek,
  signEntryAt,
  unwrapAndDecrypt,
  valueSignedBytesHashOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentComposite,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  dataUrl,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  renameEnvironmentRequest,
  requestJson,
  rotateEnvironmentComposite,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fakePayload,
  fixture,
  registerDataScenario,
  token,
  VAR,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

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

    // 環境一覧は裸 name でなく最新ステートメント + author 情報を返す(§12-2)
    const list = await requestJson("GET", "/environments", token(READER));
    expect(list.status).toBe(200);
    const listBody = (await list.json()) as {
      environments: {
        environmentId: string;
        currentEpoch: number;
        statement: {
          name: string;
          status: string;
          metaVersion: number;
          authorUserId: string;
          authorKeyFingerprintHex: string;
        };
      }[];
    };
    expect(listBody.environments.length).toBe(1);
    expect(listBody.environments[0]).toMatchObject({
      environmentId: ENV,
      currentEpoch: 1,
      statement: {
        name: "App",
        status: "active",
        metaVersion: 1,
        authorUserId: OWNER,
        authorKeyFingerprintHex: vectorKeyOf(OWNER).key_fingerprint_hex,
      },
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
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);

    // 変数・変数ステートメント・バージョン・ラップは即時削除、環境行は
    // tombstone(§12-4)。環境自身のステートメント連鎖(deleted 込み)は残る
    for (const table of [
      "variables",
      "variable_meta_statements",
      "variable_versions",
      "dek_wraps",
    ]) {
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
    const renamed = await renameEnvironmentRequest(fixture, "env-app-0002", "App", MEMBER);
    expect(renamed.status).toBe(409);
    const ok = await renameEnvironmentRequest(fixture, "env-app-0002", "Prod", MEMBER);
    expect(ok.status).toBe(204);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as {
      environments: { statement: { name: string } }[];
    };
    expect(listBody.environments.map((e) => e.statement.name).toSorted()).toEqual(["App", "Prod"]);
  });

  it("requires chain role admin for environment deletion (§12-3)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const asMember = await deleteEnvironmentRequest(fixture, ENV, MEMBER);
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
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
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
    ] as const) {
      const response = await requestJson(method, path, token(STRANGER));
      expect(response.status).toBe(404);
      const body = (await response.json()) as { projectId: string };
      expect(body.projectId).toBe(projectId);
    }
    // 削除(ステートメント必須)も非メンバーには 404。STRANGER はベクター鍵を
    // 持たないため未署名ダミーで送る(存在秘匿は署名検証より前 — §12-3)
    const removal = await requestJson("DELETE", `/environments/${ENV}`, token(STRANGER), {
      statement: {
        suite: "maruhi/v1",
        environmentId: ENV,
        name: "App",
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "cd".repeat(32),
        chainHeadHashHex: fixture.head.hashHex,
        chainHeadSeq: fixture.head.seq,
        signatureHex: "00".repeat(64),
      },
    });
    expect(removal.status).toBe(404);
    expect(((await removal.json()) as { projectId: string }).projectId).toBe(projectId);
  });

  it("rejects unauthenticated requests with 401", async () => {
    const response = await SELF.fetch(dataUrl("/environments"));
    expect(response.status).toBe(401);
  });
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
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
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
