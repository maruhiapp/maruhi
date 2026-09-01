// レイアウト v2 — 値なしスキーマのサーバー受理面(S2)の統合テスト —
// 遷移とレイアウト単調性・削除ステートメントの直前一致・スキーマ再発行と可逆性
// (AUTH_SPEC §12-5 / §12-11)。スイート全体の分担は data-schema-v2.test.ts 冒頭、
// 共有ヘルパは support/schema-v2-scenario.ts を参照。

import { describe, expect, it } from "vitest";

import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS } from "../src/policy.ts";
import { createEnvironmentOk, MEMBER, OWNER, READER, requestJson } from "./support/data-fixture.ts";
import {
  createVariableOk,
  declareVariableOk,
  declareVariableRequest,
  deleteVariableRequest,
  ENV,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  setSchemaPolicyOk,
  token,
  v2Fields,
  VAR,
  varStatements,
} from "./support/data-scenario.ts";
import { createVariableV2Request } from "./support/schema-v2-scenario.ts";

registerDataScenario();

describe("遷移とレイアウト単調性(§12-5)", () => {
  it("active → declared(rename 形)は 422 payload-mismatch(status 不変の受理検査)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "declared",
      authorUserId: MEMBER,
      v2: v2Fields(),
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
      _tag: "PayloadMismatch",
      field: "status",
    });
  });

  it("declared → declared のスキーマ再発行・rename は 204(宣言のまま更新できる)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await declareVariableOk({ variableId: VAR, name: "API_KEY" });
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "API_TOKEN",
      status: "declared",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "string", required: false, description: "renamed declaration" }),
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

  it("v2 変数への v1 後続(rename)は 422 layout-regression(レイアウト単調性)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    // v1 レイアウトの rename(スキーマ欄なし — 黙った消失の形)
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
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
      _tag: "MetaStatementRejected",
      reason: "layout-regression",
    });
  });

  it("削除済み ID での declared 再作成は 409 retired(ID 再利用禁止 — §12-1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await deleteVariableRequest(VAR, MEMBER)).status).toBe(204);
    const response = await declareVariableRequest({
      variableId: VAR,
      name: "API_KEY",
      actorUserId: MEMBER,
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "VariableConflict",
      reason: "retired",
    });
  });
});

/** v2 変数(スキーマ欄固定)を作成して記録する。 */
async function seedV2Variable(dek: Uint8Array): Promise<void> {
  await setSchemaPolicyOk("enabled", OWNER);
  const response = await createVariableV2Request({
    variableId: VAR,
    name: "DATABASE_URL",
    plaintext: "postgres://alpha",
    dek,
    schema: { varType: "url", required: true, description: "primary database" },
  });
  expect(response.status).toBe(200);
}

describe("削除ステートメントのスキーマ欄・レイアウトの直前一致(§12-5)", () => {
  it("スキーマ欄・レイアウトを保持した v2 削除は 204(declared の削除も同型)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url", required: true, description: "primary database" }),
    });
    const { manifest, record } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(204);
    record();
    // declared の削除(declared → deleted は可 — CRYPTO_SPEC §4.2)
    await declareVariableOk({ variableId: "var-declared-del", name: "PENDING_KEY" });
    const declared = varStatements.get("var-declared-del");
    expect(declared).toBeDefined();
    const declaredDelete = await nextVariableStatement({
      variableId: "var-declared-del",
      name: "PENDING_KEY",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields(),
    });
    const bundled = await manifestForStatement(declaredDelete, MEMBER);
    const declaredResponse = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/var-declared-del`,
      token(MEMBER),
      { statement: declaredDelete, manifest: bundled.manifest },
    );
    expect(declaredResponse.status).toBe(204);
  });

  it("スキーマ欄を改変した削除は 422 payload-mismatch(有効署名でも受理しない — 改変削除の遮断)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const cases: readonly (readonly [Partial<Parameters<typeof v2Fields>[0]>, string])[] = [
      [{ varType: "string", required: true, description: "primary database" }, "varType"],
      [{ varType: "url", required: false, description: "primary database" }, "required"],
      [{ varType: "url", required: true, description: "totally different" }, "description"],
    ];
    for (const [schema, field] of cases) {
      const statement = await nextVariableStatement({
        variableId: VAR,
        name: "DATABASE_URL",
        status: "deleted",
        authorUserId: MEMBER,
        v2: v2Fields(schema),
      });
      const { manifest } = await manifestForStatement(statement, MEMBER);
      const response = await requestJson(
        "DELETE",
        `/environments/${ENV}/variables/${VAR}`,
        token(MEMBER),
        { statement, manifest },
      );
      expect(response.status, field).toBe(422);
      await expect(response.json()).resolves.toMatchObject({ _tag: "PayloadMismatch", field });
    }
  });

  it("削除の description は受理ポリシーの対象外(改変は直前一致の 422 — 契約外の 500 に落ちない)", async () => {
    // 削除の規則は保存済み値の byte-exact 保持であり、description の受理
    // ポリシー(§12-8)は適用しない — 適用するとセルフホストの上限引き下げ後に
    // 既存 v2 変数が削除不能になる(「上限で削除を遮断しない」原則)。
    // 上限超過の description を持つ改変削除は preservation の payload-mismatch が
    // 捕捉する(PR #119 Bugbot 指摘: 以前は契約外 description-rejected → 500)
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields({
        varType: "url",
        required: true,
        description: "a".repeat(MAX_SCHEMA_DESCRIPTION_CODEPOINTS + 1),
      }),
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "description",
    });
  });

  it("v2 変数への v1 形の削除は 422 payload-mismatch(layoutVersion — レイアウトも直前一致)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await seedV2Variable(dek);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "deleted",
      authorUserId: MEMBER,
    });
    const { manifest } = await manifestForStatement(statement, MEMBER);
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "PayloadMismatch",
      field: "layoutVersion",
    });
  });
});

describe("スキーマ再発行と可逆性(§12-5 / §12-11)", () => {
  it("v2 変数のスキーマ欄のみの変更は改名と同一規則で受理され、配布に反映される", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
      schema: { varType: "string", required: true, description: "" },
    }).then((response) => expect(response.status).toBe(200));
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url", required: false, description: "connection string" }),
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
    const metadata = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    const body = (await metadata.json()) as { variables: readonly Record<string, unknown>[] };
    expect(body.variables[0]).toMatchObject({
      varType: "url",
      required: false,
      description: "connection string",
      metaVersion: 2,
    });
  });

  it("v1 変数への v2 再発行は enabled で受理される(自然な機会での移行)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await setSchemaPolicyOk("enabled", OWNER);
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields({ varType: "url" }),
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

  it("disabled への降格後も既に v2 の変数の継続(rename・削除)は受理され、新規採用だけが止まる(可逆性)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await setSchemaPolicyOk("enabled", OWNER);
    await createVariableV2Request({
      variableId: VAR,
      name: "DATABASE_URL",
      plaintext: "postgres://alpha",
      dek,
    }).then((response) => expect(response.status).toBe(200));
    await setSchemaPolicyOk("disabled", OWNER);
    // 継続 1: v2 rename は通る
    const rename = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
      v2: v2Fields(),
    });
    const renameBundle = await manifestForStatement(rename, MEMBER);
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: rename, manifest: renameBundle.manifest },
    );
    expect(renamed.status).toBe(204);
    varStatements.set(VAR, { statement: rename, authorUserId: MEMBER });
    renameBundle.record();
    // 継続 2: v2 削除も通る(降格が既存 v2 変数のライフサイクルを凍結しない)
    const remove = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "deleted",
      authorUserId: MEMBER,
      v2: v2Fields(),
    });
    const removeBundle = await manifestForStatement(remove, MEMBER);
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: remove, manifest: removeBundle.manifest },
    );
    expect(removed.status).toBe(204);
    removeBundle.record();
    // 新規採用は止まる
    const declared = await declareVariableRequest({
      variableId: "var-new-decl",
      name: "NEW_KEY",
      actorUserId: MEMBER,
    });
    expect(declared.status).toBe(422);
  });
});
