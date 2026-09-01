// レイアウト v2 — 値なしスキーマのサーバー受理面(S2)の統合テスト —
// schema-locked(§12-11 作成時の一回検査)・description の受理検査(§12-8)・
// 未対応レイアウト(§12-2 裁定 CR)。スイート全体の分担は data-schema-v2.test.ts
// 冒頭、共有ヘルパは support/schema-v2-scenario.ts を参照。

import { describe, expect, it } from "vitest";

import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS } from "../src/policy.ts";
import { encryptValue } from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
} from "./support/data-fixture.ts";
import {
  aadFor,
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
  unsignedPayload,
  v2Fields,
  VAR,
  variableStatementFor,
  varStatements,
} from "./support/data-scenario.ts";
import { createVariableV2Request } from "./support/schema-v2-scenario.ts";

registerDataScenario();

describe("schema-locked(§12-11 — 作成時の一回検査)", () => {
  it("locked: v1 作成・varType なしの v2 作成は 422 schema-required、varType ありは受理", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    // v1 作成(layoutVersion 1)
    const v1Statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const v1Value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "postgres://alpha",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const v1Bundle = await manifestForStatement(v1Statement, MEMBER);
    const v1Response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: v1Statement,
      value: v1Value,
      manifest: v1Bundle.manifest,
    });
    expect(v1Response.status).toBe(422);
    await expect(v1Response.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-required",
    });
    // varType なしの v2 宣言
    const untyped = await declareVariableRequest({
      variableId: VAR,
      name: "API_KEY",
      actorUserId: MEMBER,
      schema: { varType: "" },
    });
    expect(untyped.status).toBe(422);
    await expect(untyped.json()).resolves.toMatchObject({
      _tag: "SchemaPolicyRejected",
      reason: "schema-required",
    });
    // varType ありは宣言・値同梱とも受理
    await declareVariableOk({ variableId: VAR, name: "API_KEY", schema: { varType: "string" } });
    const typedCreate = await createVariableV2Request({
      variableId: "var-typed",
      name: "TYPED_URL",
      plaintext: "https://example.invalid",
      dek,
      schema: { varType: "url" },
    });
    expect(typedCreate.status).toBe(200);
  });

  it("locked: スキーマ再発行で varType を空へ戻すことは妨げない(作成時の一回検査 — 継続不変条件ではない)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("locked", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "url" },
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "" }),
    });
    const { manifest, record } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(204);
    varStatements.set(VAR, { statement, authorUserId: MEMBER });
    record();
  });

  it("locked: enabled 期に varType なしで作られた declared の activation は遡及されず受理される", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY", schema: { varType: "" } });
    await setSchemaPolicyOk("locked", OWNER);
    const response = await activateVariableRequest({
      variableId: VAR,
      actorUserId: MEMBER,
      dek,
      plaintext: "secret-value",
    });
    expect(response.status).toBe(200);
  });
});

describe("description の受理検査(§12-8)", () => {
  it("1024 コードポイントは受理、超過は 422 too-long(サロゲートペアもコードポイントで数える)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    // アストラル面(UTF-16 で 2 単位)× 1024 = 1024 コードポイント → 受理
    await declareVariableOk({
      variableId: VAR,
      name: "API_KEY",
      schema: { description: "𠮷".repeat(MAX_SCHEMA_DESCRIPTION_CODEPOINTS) },
    });
    const rejected = await declareVariableRequest({
      variableId: "var-too-long",
      name: "OTHER_KEY",
      actorUserId: MEMBER,
      schema: { description: "a".repeat(MAX_SCHEMA_DESCRIPTION_CODEPOINTS + 1) },
    });
    expect(rejected.status).toBe(422);
    await expect(rejected.json()).resolves.toMatchObject({
      _tag: "SchemaDescriptionRejected",
      reason: "too-long",
    });
  });

  it("制御文字(改行・ANSI エスケープの ESC)は 422 control-characters(単一行に固定)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    for (const description of ["line one\nline two", "colored \u001b[31mred\u001b[0m"]) {
      const response = await declareVariableRequest({
        variableId: VAR,
        name: "API_KEY",
        actorUserId: MEMBER,
        schema: { description },
      });
      expect(response.status).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        _tag: "SchemaDescriptionRejected",
        reason: "control-characters",
      });
    }
  });
});

/** サポート外レイアウトの宣言作成(署名 API では作れないためゼロ署名)。 */
function unsupportedLayoutStatement(): Record<string, unknown> {
  return {
    suite: "maruhi/v1",
    environmentId: ENV,
    variableId: VAR,
    name: "API_KEY",
    status: "declared",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    ...v2Fields(),
    layoutVersion: 3,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

describe("未対応レイアウト(§12-2 — 裁定 CR)", () => {
  it("layoutVersion 3 は 422 unsupported-layout の型付き拒否(署名不正・500 に潰さない)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: unsupportedLayoutStatement(),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });

  it("サポート範囲検査は schemaPolicy より前(disabled / locked でも誤誘導エラーにしない)", async () => {
    // v3 クライアントへの正直な応答は常に「server update required」であり、
    // schema-policy-disabled(enabled 化しても直らない)や schema-required
    // (varType を足しても直らない)を先に返さない(裁定 CR の趣旨)
    await createEnvironmentOk(fixture, ENV, "App");
    for (const policy of ["disabled", "locked"] as const) {
      await setSchemaPolicyOk(policy, OWNER);
      const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
        statement: unsupportedLayoutStatement(),
        manifest: unsignedManifest(),
      });
      expect(response.status, policy).toBe(422);
      await expect(response.json()).resolves.toMatchObject({
        _tag: "MetaStatementRejected",
        reason: "unsupported-layout",
      });
    }
  });

  it("サポート範囲検査は作成の前段検査(重複名)より前(pullfrog 指摘 — 名前衝突の v3 に duplicate-name を返さない)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    // v3 宣言と同名の既存変数を先に作り、名前衝突の状況を用意する
    await createVariableOk(dek, "var-existing", "API_KEY", "occupied");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: unsupportedLayoutStatement(),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });

  it("サポート範囲検査は削除の直前一致・メタ CAS の判定より前(rename / 削除経路)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // v3 の後続ステートメント(rename 形・stale な metaVersion でも
    // unsupported-layout が CAS 409 より先に確定する)
    const successor = {
      suite: "maruhi/v1",
      environmentId: ENV,
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      metaVersion: 9,
      prevMetaSigHashHex: "ab".repeat(32),
      ...v2Fields(),
      layoutVersion: 3,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: "00".repeat(64),
    };
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: successor, manifest: unsignedManifest() },
    );
    expect(renamed.status).toBe(422);
    await expect(renamed.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
    // v3 の削除(直前一致 payload-mismatch でなく unsupported-layout)
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: { ...successor, status: "deleted", metaVersion: 2 },
        manifest: unsignedManifest(),
      },
    );
    expect(removed.status).toBe(422);
    await expect(removed.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
    // v3 の activation(status / name ガード・値 CAS でなく unsupported-layout —
    // PR #119 Bugbot 指摘: activate 経路も rename / 削除と同じ巻き上げ)
    const activated = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/activate`,
      token(MEMBER),
      {
        value: unsignedPayload(aadFor(1, 1, { variableId: VAR })),
        statement: successor,
        manifest: unsignedManifest(),
      },
    );
    expect(activated.status).toBe(422);
    await expect(activated.json()).resolves.toMatchObject({
      _tag: "MetaStatementRejected",
      reason: "unsupported-layout",
    });
  });
});
