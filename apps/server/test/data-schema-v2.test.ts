// レイアウト v2 — 値なしスキーマのサーバー受理面(S2)の統合テスト。
//
// 対象: AUTH_SPEC §12-5「レイアウト v2・declared・activation の受理」全項 +
// §12-8(description の受理検査)+ §12-11(schemaPolicy)+ §12-7(declared の
// 配布・advisory 同梱)。設計文書(docs/notes/value-free-schema-design.md §3)の
// 「停止しても安全」の実証 — 既定 disabled で v2 受理が眠ったまま・v1 不変 —
// と、§12-5 の 422 エラー名 4 種(schema-policy-disabled / activation-required /
// layout-regression / schema-required)の境界を固定する。
//
// スイートの分担(共有ヘルパは support/schema-v2-scenario.ts。分割の動機は
// support/membership-scenario.ts 冒頭を参照):
// - 本ファイル: schemaPolicy 設定・有効化ゲート・declared 作成と activation
// - data-schema-v2-transitions.test.ts: 遷移とレイアウト単調性・削除の直前一致・
//   スキーマ再発行と可逆性
// - data-schema-v2-locked.test.ts: schema-locked・description・未対応レイアウト

import { describe, expect, it } from "vitest";

import { encryptValue } from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  activateVariableRequest,
  createVariableOk,
  declareVariableOk,
  declareVariableRequest,
  ENV,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  setSchemaPolicyOk,
  token,
  unsignedManifest,
  v2Fields,
  VAR,
  varStatements,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";
import { createVariableV2Request } from "./support/schema-v2-scenario.ts";

registerDataScenario();

/** 監査行の件数(イベント名 × variable_id)。 */
async function auditCount(event: string, variableId?: string): Promise<number> {
  const rows =
    variableId === undefined
      ? await queryProjectDo(
          projectId,
          "SELECT COUNT(*) AS n FROM audit_events WHERE event = ?",
          event,
        )
      : await queryProjectDo(
          projectId,
          "SELECT COUNT(*) AS n FROM audit_events WHERE event = ? AND variable_id = ?",
          event,
          variableId,
        );
  return Number(rows[0]?.["n"]);
}

describe("schemaPolicy 設定(AUTH_SPEC §12-11)", () => {
  it("GET は既定 disabled を返す(read × reader 以上)。非メンバーは一律 404", async () => {
    const asReader = await requestJson("GET", "/schema-policy", token(READER));
    expect(asReader.status).toBe(200);
    await expect(asReader.json()).resolves.toEqual({ schemaPolicy: "disabled" });
    const asStranger = await requestJson("GET", "/schema-policy", token(STRANGER));
    expect(asStranger.status).toBe(404);
  });

  it("PUT は admin × admin(204)。変更は project.schema_policy_changed を旧値・新値つきで記録する", async () => {
    await setSchemaPolicyOk("enabled", OWNER);
    const read = await requestJson("GET", "/schema-policy", token(READER));
    await expect(read.json()).resolves.toEqual({ schemaPolicy: "enabled" });
    const rows = await queryProjectDo(
      projectId,
      "SELECT actor_type, actor_user_id, actor_key_fingerprint, payload FROM audit_events WHERE event = 'project.schema_policy_changed'",
    );
    expect(rows).toHaveLength(1);
    // actor = 変更した本人(type=user)。署名を伴わない設定操作のため FP なし
    // (AUDIT_SPEC §3.3)
    expect(rows[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: OWNER,
      actor_key_fingerprint: null,
    });
    expect(JSON.parse(String(rows[0]?.["payload"]))).toMatchObject({
      previous: "disabled",
      next: "enabled",
    });
  });

  it("同値の PUT は 204 のまま監査を追加しない(変わっていない遷移を「変更」として書かない)", async () => {
    await setSchemaPolicyOk("enabled", OWNER);
    await setSchemaPolicyOk("enabled", OWNER);
    expect(await auditCount("project.schema_policy_changed")).toBe(1);
  });

  it("PUT の認可: チェーン role member は 403、非メンバーは 404", async () => {
    const asMember = await requestJson("PUT", "/schema-policy", token(MEMBER), {
      schemaPolicy: "enabled",
    });
    expect(asMember.status).toBe(403);
    const asStranger = await requestJson("PUT", "/schema-policy", token(STRANGER), {
      schemaPolicy: "enabled",
    });
    expect(asStranger.status).toBe(404);
    // 拒否はポリシーを変えない
    const read = await requestJson("GET", "/schema-policy", token(OWNER));
    await expect(read.json()).resolves.toEqual({ schemaPolicy: "disabled" });
  });

  it("3 値以外の PUT は Schema 検証の 400", async () => {
    const response = await requestJson("PUT", "/schema-policy", token(OWNER), {
      schemaPolicy: "everything",
    });
    expect(response.status).toBe(400);
  });

  it("advisory 同梱(§12-7): 環境一覧・値付き pull・メタのみ pull に schemaPolicy が載る(検証材料ではない)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toMatchObject({ schemaPolicy: "locked" });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    await expect(pull.json()).resolves.toMatchObject({ schemaPolicy: "locked" });
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    await expect(metadata.json()).resolves.toMatchObject({ schemaPolicy: "locked" });
  });
});

describe("有効化ゲート — 既定 disabled は v2 の新規採用のみ拒否(§12-5 / §12-11)", () => {
  it("v2 の値同梱作成は 422 schema-policy-disabled(v1 経路は不変)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const rejected = await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    });
    expect(rejected.status).toBe(422);
    await expect(rejected.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-policy-disabled",
    });
    // v1 の作成は従来どおり受理される(既存 v1 プロジェクトへの影響ゼロの実証)
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  });

  it("declared 作成(値なし)は 422 schema-policy-disabled", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const rejected = await declareVariableRequest({
      variableId: VAR,
      name: "API_KEY",
      actorUserId: MEMBER,
    });
    expect(rejected.status).toBe(422);
    await expect(rejected.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-policy-disabled",
    });
    // 拒否は変数行・監査行を残さない
    expect(await auditCount("var.created", VAR)).toBe(0);
  });

  it("v1 変数への v2 再発行は 422 schema-policy-disabled", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url" }),
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-policy-disabled",
    });
  });
});

describe("declared 作成と activation(§12-5)", () => {
  it("enabled: declared 作成は値なしで受理され、保存バージョン 0・var.created(author FP)を記録する", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({
      variableId: VAR,
      name: "API_KEY",
      schema: { varType: "string", required: true, description: "third-party API key" },
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT latest_version, latest_meta_version, deleted_at FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    // 保存バージョン 0 のまま・アクティブ行(§12-5 — declared だけが正当な
    // version 0 状態。アクティブ変数枠にも数える)
    expect(rows).toEqual([{ latest_version: 0, latest_meta_version: 1, deleted_at: null }]);
    // 存在区間の開始 = metaVersion 1 の受理(AUDIT_SPEC §3.3 — declared 作成も
    // var.created。値署名がないため FP はステートメント署名の author 鍵 FP)
    const audits = await queryProjectDo(
      projectId,
      "SELECT actor_user_id, actor_key_fingerprint FROM audit_events WHERE event = 'var.created' AND variable_id = ?",
      VAR,
    );
    expect(audits).toHaveLength(1);
    expect(audits[0]?.["actor_user_id"]).toBe(MEMBER);
    expect(typeof audits[0]?.["actor_key_fingerprint"]).toBe("string");
    expect(await auditCount("var.version_pushed", VAR)).toBe(0);
  });

  it("配布(§12-7): declared は値付き pull の declaredVariables とメタのみ pull の variables に載り、値・DEK は運ばれない", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({
      variableId: VAR,
      name: "API_KEY",
      schema: { varType: "url", required: false, description: "endpoint" },
    });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const pulled = (await pull.json()) as {
      variables: readonly unknown[];
      declaredVariables?: readonly Record<string, unknown>[];
    };
    // 値配列には現れない(status active の値配布要求 — CRYPTO_SPEC §6.3 — の
    // 「declared だけが正当な値なし状態」の供給側)
    expect(pulled.variables).toEqual([]);
    expect(pulled.declaredVariables).toHaveLength(1);
    // v2 の運搬フィールド(§12-2)がステートメントに揃って載る
    expect(pulled.declaredVariables?.[0]).toMatchObject({
      variableId: VAR,
      status: "declared",
      layoutVersion: 2,
      varType: "url",
      required: false,
      description: "endpoint",
      authorUserId: MEMBER,
    });
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const metadataBody = (await metadata.json()) as {
      variables: readonly Record<string, unknown>[];
    };
    expect(metadataBody.variables).toHaveLength(1);
    expect(metadataBody.variables[0]).toMatchObject({ variableId: VAR, status: "declared" });
    // declared の配布は var.read を記録しない(値を配布していない — AUDIT_SPEC §3.3)
    expect(await auditCount("var.read", VAR)).toBe(0);
  });

  it("declared への通常 push は 422 activation-required", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "secret-value",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "ActivationRequired",
      variableId: VAR,
    });
  });

  it("activation 複合は 200 version 1 で受理され、var.version_pushed(version 1)を記録する", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ variableId: VAR, version: 1, epoch: 1 });
    expect(await auditCount("var.version_pushed", VAR)).toBe(1);
    expect(await auditCount("var.created", VAR)).toBe(1);
    // activation 後の pull は値を配布し、declaredVariables は空になる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const pulled = (await pull.json()) as {
      variables: readonly Record<string, unknown>[];
      declaredVariables?: readonly unknown[];
    };
    expect(pulled.variables).toHaveLength(1);
    expect(pulled.declaredVariables).toBeUndefined();
    // activation 後は通常 push が受理される(declared ゲートの解除)
    const next = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "rotated-value",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await storedValueSigHash(VAR, 1),
      },
    );
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: next },
    );
    expect(push.status).toBe(200);
  });

  it("activation は disabled 降格後もポリシーに依らず受理される(§12-11 の可逆性 — 継続ステートメント)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    await setSchemaPolicyOk("disabled", OWNER);
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(response.status).toBe(200);
  });

  it("active 変数への activation 複合は 422 payload-mismatch(status — 明示ガード。version の値に依らない)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    // version 1(CAS で落ちる形)と latest + 1(CAS を通過する形)の両方で
    // 同じ 422 になること — 対象判定を値 CAS に依存させない(pullfrog 指摘:
    // version 1 固定のヘルパでは「active 変数を狙えない」性質を検証できない)
    for (const version of [1, 2]) {
      const response = await activateVariableRequest({
        variableId: VAR,
        actorUserId: MEMBER,
        dek,
        plaintext: "postgres://beta",
        version,
        prevValueSigHashHex: version === 1 ? "" : await storedValueSigHash(VAR, 1),
      });
      expect(response.status, `version ${version}`).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        _tag: "PayloadMismatch",
        field: "status",
      });
    }
  });

  it("disabled 下の active v1 変数は activation 経路でも v2 へ昇格できない(§12-11 迂回の遮断)", async () => {
    // pullfrog 指摘の再現形: activation は schemaPolicy を検査しない(declared の
    // 直前は必ず v2 のため)が、その免除は対象の declared 限定が前提。ガードが
    // 無いと disabled のまま v1 active 変数 + version latest+1 で v2 再発行が通る
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "postgres://beta",
      version: 2,
      prevValueSigHashHex: await storedValueSigHash(VAR, 1),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "status",
    });
    // 拒否は何も書かない: 最新ステートメントはレイアウト 1 のまま・version も不変
    const rows = await queryProjectDo(
      projectId,
      `SELECT ms.layout_version, v.latest_version, v.latest_meta_version
       FROM variables v
       JOIN variable_meta_statements ms
         ON ms.environment_id = v.environment_id
        AND ms.variable_id = v.variable_id
        AND ms.meta_version = v.latest_meta_version
       WHERE v.environment_id = ? AND v.variable_id = ?`,
      ENV,
      VAR,
    );
    expect(rows).toEqual([{ layout_version: 1, latest_version: 1, latest_meta_version: 1 }]);
  });

  it("activation は改名を兼ねない(name は宣言時の名を保持 — 422 payload-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const renamed = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
      name: "API_TOKEN",
    });
    expect(renamed.status).toBe(422);
    await expect(renamed.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "name",
    });
    // 改名は rename 経路(declared → declared — var.renamed の監査つき)を挟めば
    // 同じ結果に到達できる(能力は失われない)
    const rename = await nextVariableStatement({
      variableId: VAR,
      name: "API_TOKEN",
      status: "declared",
      authorUserId: MEMBER,
      v2: v2Fields(),
    });
    const renameBundle = await manifestForStatement(rename, MEMBER);
    const renameResponse = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: rename, manifest: renameBundle.manifest },
    );
    expect(renameResponse.status).toBe(204);
    varStatements.set(VAR, { statement: rename, authorUserId: MEMBER });
    renameBundle.record();
    const activated = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(activated.status).toBe(200);
  });

  it("作成複合は deleted を創出できない(ワイヤ形の 400 — §12-5 の受理面が正)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    // 形式のみ有効なゼロ署名(Schema 400 は署名検証に到達しない)
    const statement = {
      suite: "maruhi/v1",
      environmentId: ENV,
      variableId: VAR,
      name: "API_KEY",
      status: "deleted",
      metaVersion: 1,
      prevMetaSigHashHex: "",
      ...v2Fields(),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: "00".repeat(64),
    };
    const withoutValue = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      {
        statement,
        manifest: unsignedManifest(),
      },
    );
    expect(withoutValue.status).toBe(400);
  });
});

/** 保存済み version の value signed-bytes ハッシュ(次 version の prev 材料)。 */
async function storedValueSigHash(variableId: string, version: number): Promise<string> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT signed_bytes_hash_hex FROM variable_versions WHERE environment_id = ? AND variable_id = ? AND version = ?",
    ENV,
    variableId,
    version,
  );
  return String(rows[0]?.["signed_bytes_hash_hex"]);
}
