// データプレーン API(AUTH_SPEC §12)の統合テスト — suite の永続化・数量ポリシー・判定順・エラー契約導出(AUTH_SPEC §12-2 / §12-3 / §12-8)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。

import {
  auditGroup,
  deksGroup,
  DekWrapExistsError,
  environmentsGroup,
  membershipGroup,
  rotationGroup,
  variablesGroup,
} from "@maruhi/api-schema";
import { Cause, Effect, Exit } from "effect";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";
import { describe, expect, it } from "vitest";

import { dataRejectionError, unwrapDataOutcome } from "../src/data-http.ts";
import type { DataRejection } from "../src/data-plane.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_DEK_WRAPS_PER_REQUEST,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
} from "../src/policy.ts";
import { wrapRowsExceeded } from "../src/quotas.ts";
import { makeDek, signEntryAt, wrapDekForAll } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  MEMBER,
  OWNER,
  projectId,
  READER,
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
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
  variableStatementFor,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

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
    const compositeBase = {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
    };
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
       INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at)
       SELECT 'env-seed-' || n, 'seed-' || n, 1, 0, NULL FROM seq`,
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
       INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at)
       SELECT 'env-seed-' || n, 'seed-' || n, 1, 0, 1 FROM seq`,
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
       INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       SELECT ?, 'var-seed-' || n, 'SEED_' || n, 1, 1, 0, NULL FROM seq`,
      MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
      ENV,
    );
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
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
       INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       SELECT ?, 'var-seed-' || n, 'SEED_' || n, 1, 1, 0, 1 FROM seq`,
      MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
      ENV,
    );
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
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

  it("rejects a malformed composite parentHeadHashHex with 400 (Schema)", async () => {
    // CAS の親ヘッド形式は Sha256Hex で固定(意図的な受理変更): 不正形式は
    // 409(ChainHeadConflict)へ到達せず schema 境界の 400 で落ちる
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: "env-head-form", dekCommitmentHex: "ab".repeat(32) },
      },
    });
    for (const bad of ["ab".repeat(31), "AB".repeat(32), "not-hex"]) {
      const response = await requestJson("POST", "/environments", token(OWNER), {
        parentHeadHashHex: bad,
        entry,
        statement: {
          suite: "maruhi/v1",
          environmentId: "env-head-form",
          name: "HeadForm",
          status: "active",
          metaVersion: 1,
          prevMetaSigHashHex: "",
          chainHeadHashHex: fixture.head.hashHex,
          chainHeadSeq: fixture.head.seq,
          signatureHex: "00".repeat(64),
        },
        deks: [],
      });
      expect(response.status).toBe(400);
    }
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
        // ステートメント側も同じ受理ポリシー形式(EnvironmentIdSchema)で 400 に
        // なる(entry と揃えて Schema 境界を固定)。署名検証には到達しない
        statement: {
          suite: "maruhi/v1",
          environmentId: badId,
          name: `Bad-${badId.length}`,
          status: "active",
          metaVersion: 1,
          prevMetaSigHashHex: "",
          chainHeadHashHex: fixture.head.hashHex,
          chainHeadSeq: fixture.head.seq,
          signatureHex: "00".repeat(64),
        },
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
        statement: unsignedVariableStatement(VAR, "DATABASE_URL"),
        value,
      });
      expect(response.status).toBe(400);
    }
  });
});

const rejectedOutcome = (rejection: DataRejection) => ({ kind: "rejected", rejection }) as const;

/**
 * エンドポイントの宣言エラーのタグ集合。実行時判定(Schema.is)から独立な
 * 経路として identifier 注釈(Schema.TaggedError がタグと同値で付与)から
 * 読む。effect 更新で注釈の形が変わったらここで明示的に落とし、契約導出の
 * 再検証(PR #49 で beta.107 に対して行った手動検証の再実行)を促す。
 */
const declaredTagsOf = (endpoint: HttpApiEndpoint.Top): ReadonlySet<string> =>
  new Set(
    Array.from(endpoint.error, (schema) => {
      const identifier = (schema.ast.annotations as Record<string, unknown> | undefined)?.[
        "identifier"
      ];
      if (typeof identifier !== "string") {
        throw new Error(
          "declared error schema without a string identifier annotation — " +
            "re-verify the error-contract derivation (Schema.is / endpoint.error) " +
            "against the new effect version",
        );
      }
      return identifier;
    }),
  );

describe("エラー契約の宣言からの導出(data-http.ts unwrapDataOutcome)", () => {
  // DO 拒否はエンドポイントの契約宣言(api-schema の error: [...])から導出した
  // 集合で選別される(手書きの allowed 列は存在しない)。ここでは宣言との
  // 対応関係そのものを写像単体で固定する。dek-wrap-exists は現行チェーン規則
  // (duplicate-environment / エポック単調性)の下では複合 create / rotate から
  // 実際には到達しないため、HTTP 統合ではなくこの単体で契約を検証する

  it("dek-wrap-exists は create / rotate の契約エラー(409 DekWrapExists)として返る", () => {
    // 契約ギャップ修正: 従来は create / rotate の宣言・allowed に無く、チェーン
    // 規則が緩んだ瞬間に defect(500)へ落ちる構造だった。宣言に加えたことで
    // 409 の型付きエラーとして返る
    for (const endpoint of [
      environmentsGroup.endpoints.create,
      environmentsGroup.endpoints.rotate,
    ] as const) {
      const error = Effect.runSync(
        Effect.flip(
          unwrapDataOutcome(
            rejectedOutcome({
              kind: "dek-wrap-exists",
              epoch: 2,
              recipientUserId: READER,
              storedRecipientEncPubHex: "ab".repeat(32),
            }),
            projectId,
            endpoint,
          ),
        ),
      );
      expect(error).toBeInstanceOf(DekWrapExistsError);
      // 409 は占有ラップの保存済み受信者 enc 公開鍵を運ぶ(AUTH_SPEC §12-6 —
      // 2026-08-15。再追加バックフィルの修復判定の材料)
      expect(error).toMatchObject({
        epoch: 2,
        recipientUserId: READER,
        storedRecipientEncPubHex: "ab".repeat(32),
      });
    }
  });

  it("契約外の拒否は defect(500)のまま(不変条件違反を型付きエラーに漏らさない)", () => {
    // variables.pull の宣言は ProjectNotFound / Forbidden / EnvironmentNotFound
    // のみ。version-conflict の拒否が漏れてきたら実装バグとして die する
    const exit = Effect.runSyncExit(
      unwrapDataOutcome(
        rejectedOutcome({ kind: "version-conflict", currentVersion: 3 }),
        projectId,
        variablesGroup.endpoints.pull,
      ),
    );
    expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true);
  });

  it("§11-2 の存在秘匿の畳み込み(not-member → 404 ProjectNotFound)も宣言内", () => {
    const error = Effect.runSync(
      Effect.flip(
        unwrapDataOutcome(
          rejectedOutcome({ kind: "not-member" }),
          projectId,
          variablesGroup.endpoints.pull,
        ),
      ),
    );
    expect(error).toMatchObject({ _tag: "ProjectNotFound", projectId });
  });

  // kind ごとの代表拒否(全フィールドが Schema の語彙内の有効値)。
  // satisfies で DataRejection の全 kind の網羅を型強制する — kind が増えたら
  // ここに足さない限りコンパイルが落ちる
  const representativeRejections = {
    "not-initialized": { kind: "not-initialized" },
    "not-member": { kind: "not-member" },
    "insufficient-role": { kind: "insufficient-role" },
    "environment-not-found": { kind: "environment-not-found", environmentId: "env-contract" },
    "environment-conflict": {
      kind: "environment-conflict",
      environmentId: "env-contract",
      reason: "duplicate-name",
    },
    "composite-required": { kind: "composite-required", op: "create_environment" },
    "chain-head-conflict": {
      kind: "chain-head-conflict",
      currentHeadSeq: 4,
      currentHeadHashHex: "ab".repeat(32),
    },
    "chain-entry-invalid": { kind: "chain-entry-invalid", seq: 2, reason: "bad-signature" },
    "chain-entry-too-large": { kind: "chain-entry-too-large", limitBytes: 1024 },
    "chain-capacity-exceeded": {
      kind: "chain-capacity-exceeded",
      maxEntries: 10,
      maxTotalBytes: 1024,
    },
    "payload-mismatch": { kind: "payload-mismatch", field: "environmentId" },
    "variable-not-found": { kind: "variable-not-found", variableId: "var-contract" },
    "variable-conflict": {
      kind: "variable-conflict",
      variableId: "var-contract",
      reason: "duplicate-name",
    },
    "version-conflict": { kind: "version-conflict", currentVersion: 3 },
    "epoch-conflict": { kind: "epoch-conflict", currentEpoch: 2 },
    "value-rejected": { kind: "value-rejected", reason: "signature-invalid" },
    "meta-rejected": { kind: "meta-rejected", reason: "signature-invalid" },
    "meta-version-conflict": { kind: "meta-version-conflict", currentMetaVersion: 2 },
    "name-not-nfc": { kind: "name-not-nfc" },
    "dek-wrap-rejected": { kind: "dek-wrap-rejected", reason: "duplicate-recipient" },
    "dek-wrap-exists": {
      kind: "dek-wrap-exists",
      epoch: 2,
      recipientUserId: READER,
      storedRecipientEncPubHex: "ab".repeat(32),
    },
    "dek-wrap-not-found": { kind: "dek-wrap-not-found", epoch: 2, recipientUserId: READER },
    "rotation-flag-not-found": {
      kind: "rotation-flag-not-found",
      environmentId: "env-contract",
      variableId: "var-contract",
    },
    "limit-exceeded": { kind: "limit-exceeded", resource: "variables", limit: 100 },
  } as const satisfies {
    readonly [K in DataRejection["kind"]]: Extract<DataRejection, { kind: K }>;
  };

  // kind → 期待エラータグのゴールデン表(data-http.ts rejectionErrors の写像の
  // 固定)。satisfies で全 kind の網羅を型強制する
  const expectedTagByKind = {
    "not-initialized": "ProjectNotFound",
    "not-member": "ProjectNotFound",
    "insufficient-role": "Forbidden",
    "environment-not-found": "EnvironmentNotFound",
    "environment-conflict": "EnvironmentConflict",
    "composite-required": "CompositeRequired",
    "chain-head-conflict": "ChainHeadConflict",
    "chain-entry-invalid": "ChainEntryInvalid",
    "chain-entry-too-large": "ChainEntryTooLarge",
    "chain-capacity-exceeded": "ChainCapacityExceeded",
    "payload-mismatch": "PayloadMismatch",
    "variable-not-found": "VariableNotFound",
    "variable-conflict": "VariableConflict",
    "version-conflict": "VersionConflict",
    "epoch-conflict": "EpochConflict",
    "value-rejected": "ValueSignatureRejected",
    "meta-rejected": "MetaStatementRejected",
    "meta-version-conflict": "MetaVersionConflict",
    "name-not-nfc": "NameNotNfc",
    "dek-wrap-rejected": "DekWrapRejected",
    "dek-wrap-exists": "DekWrapExists",
    "dek-wrap-not-found": "DekWrapNotFound",
    "rotation-flag-not-found": "RotationFlagNotFound",
    "limit-exceeded": "DataLimitExceeded",
  } as const satisfies Record<DataRejection["kind"], string>;

  // 全データプレーン + チェーンエンドポイント × 全拒否 kind の組み合わせ
  // (チェーン API — membership — の拒否も DataRejection で届き、同じ
  // unwrapDataOutcome を通る。worker ↔ DO の対応はこの表が固定する)
  const contractCases = Object.entries({
    membership: membershipGroup,
    environments: environmentsGroup,
    variables: variablesGroup,
    deks: deksGroup,
    rotation: rotationGroup,
    // audit.self は DO を経由しない(D1 のみ)が、写像と宣言の対応表としては
    // 同じ規律で固定する(宣言に無い拒否はすべて die 判定になる)
    audit: auditGroup,
  }).flatMap(([groupName, group]) =>
    Object.entries(group.endpoints).flatMap(([endpointName, endpoint]) =>
      Object.values(representativeRejections).map((rejection) => ({
        endpointLabel: `${groupName}.${endpointName}`,
        endpoint: endpoint as HttpApiEndpoint.Top,
        rejection: rejection as DataRejection,
      })),
    ),
  );

  /** 1 組み合わせの実測 / 期待判定("label: fail|die" の形。toEqual の diff 用)。 */
  const judgeContractCase = (contractCase: (typeof contractCases)[number]) => {
    const { endpoint, rejection, endpointLabel } = contractCase;
    const label = `${endpointLabel} ← ${rejection.kind}`;
    const exit = Effect.runSyncExit(
      unwrapDataOutcome(rejectedOutcome(rejection), projectId, endpoint),
    );
    const died = Exit.isFailure(exit) && Cause.hasDies(exit.cause);
    if (!died) {
      // 契約内なら返る失敗値そのものも写像どおりのタグであること
      const failed = Effect.runSync(
        Effect.flip(unwrapDataOutcome(rejectedOutcome(rejection), projectId, endpoint)),
      );
      expect(failed, label).toMatchObject({ _tag: expectedTagByKind[rejection.kind] });
    }
    return {
      observed: `${label}: ${died ? "die" : "fail"}`,
      expected: `${label}: ${declaredTagsOf(endpoint).has(expectedTagByKind[rejection.kind]) ? "fail" : "die"}`,
    };
  };

  it("DataRejection → エラークラスの写像(rejectionErrors)はゴールデン表どおり", () => {
    for (const rejection of Object.values(representativeRejections)) {
      expect(dataRejectionError(rejection, projectId), rejection.kind).toMatchObject({
        _tag: expectedTagByKind[rejection.kind],
      });
    }
  });

  it("全データプレーンエンドポイント × 全拒否 kind で fail / die 判定が宣言と厳密一致する", () => {
    // effect 更新(Schema.is / endpoint.error の意味変化)へのドリフト検出器。
    // beta.107 では全 14 エンドポイント × 全エラー種の厳密一致を手動検証済み
    // (PR #49)— このテストはその検証の自動再実行。ピン留め中の rc.109 への
    // 更新はこの検出器が green のまま通っている(手動検証の再実行は不要)
    const results = contractCases.map(judgeContractCase);
    // toEqual の diff で不一致の (endpoint, kind) がそのまま読めるようにする
    expect(results.map((result) => result.observed)).toEqual(
      results.map((result) => result.expected),
    );
    // 列挙が壊れて空回り(無条件パス)しないことの防衛線。エンドポイントを
    // 追加したらこの数を更新する(membership 3 / environments 5 / variables 6 /
    // deks 3 / rotation 2 / audit 3)
    expect(new Set(contractCases.map((contractCase) => contractCase.endpointLabel)).size).toBe(22);
  });
});
