// strict 受理(AUTH_SPEC §12-10 (1))のユニットテスト。
//
// - 拒否の実効性は HttpApiBuilder と同一の組み立て(decodeUnknownEffect +
//   Schema.Union、options なし — docs/notes/session-32.md §2-2)で検証する
// - 負例: 注釈の後に .check(...) を合成すると SchemaParser の読む位置(最後の
//   check の annotations)から注釈が外れて strict が無警告で失効する
//   (session-32 §2-3)。assert 関数がこれを throw に格上げすることを固定する
// - 受理経路(workerd 実環境)での 400 拒否は apps/server/test/strict-payload.test.ts

import { Effect, Result, Schema } from "effect";
import { describe, expect, it } from "vitest";

import {
  assertSecurityCriticalPayloadsStrict,
  assertStrictPayloadRoot,
  maruhiApi,
  SECURITY_CRITICAL_PAYLOAD_ENDPOINTS,
  STRICT_EXEMPT_PAYLOAD_ENDPOINTS,
  strictPayload,
} from "../src/index.ts";

const anyValueFilter = Schema.makeFilter(() => true);

/** HttpApiBuilder が payload デコーダを組み立てる形(options なし)。 */
const decodeAsBuilder = (schema: Schema.Top) => {
  const decode = Schema.decodeUnknownEffect(Schema.Union([schema]));
  return (input: unknown) =>
    Effect.runSync(Effect.result(decode(input) as Effect.Effect<unknown, unknown, never>));
};

describe("strictPayload", () => {
  const schema = strictPayload(Schema.Struct({ nested: Schema.Struct({ a: Schema.String }) }));

  it("accepts a clean payload through the builder assembly", () => {
    const result = decodeAsBuilder(schema)({ nested: { a: "x" } });
    expect(Result.isSuccess(result)).toBe(true);
  });

  it("rejects a root-level unknown field", () => {
    const result = decodeAsBuilder(schema)({ nested: { a: "x" }, extra: 1 });
    expect(Result.isFailure(result)).toBe(true);
  });

  it("rejects a nested unknown field (annotation propagates)", () => {
    const result = decodeAsBuilder(schema)({ nested: { a: "x", extra: 1 } });
    expect(Result.isFailure(result)).toBe(true);
  });

  it("wins over a permissive caller-side ParseOptions", () => {
    const decode = Schema.decodeUnknownEffect(Schema.Union([schema]), {
      onExcessProperty: "ignore",
    });
    const result = Effect.runSync(
      Effect.result(
        decode({ nested: { a: "x" }, extra: 1 }) as Effect.Effect<unknown, unknown, never>,
      ),
    );
    expect(Result.isFailure(result)).toBe(true);
  });

  it("stays parser-effective when applied after .check(...)", () => {
    const checked = strictPayload(Schema.Struct({ a: Schema.String }).check(anyValueFilter));
    expect(() => assertStrictPayloadRoot(checked, "checked")).not.toThrow();
    expect(Result.isFailure(decodeAsBuilder(checked)({ a: "x", extra: 1 }))).toBe(true);
  });
});

describe("assertStrictPayloadRoot", () => {
  it("throws for a schema without the strict annotation", () => {
    expect(() => assertStrictPayloadRoot(Schema.Struct({ a: Schema.String }), "plain")).toThrow(
      /not parser-effective/,
    );
  });

  it("throws when .check(...) is composed after the annotation (silent-disable trap)", () => {
    // annotate → check の順: SchemaAST.annotate は checks があると最後の check へ
    // 注釈を付け、SchemaParser も最後の check から読む。よってこの順では注釈が
    // AST 本体に残り、parser の読む位置から外れる — strict は無警告で失効する
    const broken = Schema.Struct({ a: Schema.String })
      .annotate({ parseOptions: { onExcessProperty: "error" } })
      .check(anyValueFilter);
    expect(() => assertStrictPayloadRoot(broken, "broken")).toThrow(/not parser-effective/);
    // 前提の再確認: この壊れた形は builder 経路で実際に受理してしまう
    // (assert がなければ気づけない — session-32 §2-3 の実測の固定)
    expect(Result.isSuccess(decodeAsBuilder(broken)({ a: "x", extra: 1 }))).toBe(true);
  });

  it("throws when strictPayload(...) is recomposed with .check(...) afterwards", () => {
    const recomposed = strictPayload(Schema.Struct({ a: Schema.String })).check(anyValueFilter);
    expect(() => assertStrictPayloadRoot(recomposed, "recomposed")).toThrow(/not parser-effective/);
  });
});

describe("assertSecurityCriticalPayloadsStrict", () => {
  it("passes on the registered maruhi API (also runs at module load)", () => {
    expect(() => assertSecurityCriticalPayloadsStrict(maruhiApi)).not.toThrow();
  });

  it("covers every §12-10 (1) implemented surface", () => {
    // 列挙の退行防止(§16-1 ヘッド申告 = membership.attest を含む — PR-M4)
    expect(SECURITY_CRITICAL_PAYLOAD_ENDPOINTS).toEqual([
      ["membership", "init"],
      ["membership", "append"],
      ["membership", "attest"],
      ["environments", "create"],
      ["environments", "rotate"],
      ["environments", "rename"],
      ["environments", "remove"],
      ["variables", "create"],
      ["variables", "push"],
      // activation 複合(§12-5 — 2026-08-30 S2)
      ["variables", "activate"],
      ["variables", "rename"],
      ["variables", "remove"],
      ["deks", "register"],
      ["auth", "recoveryPut"],
      ["lease", "issue"],
      ["invites", "issue"],
      ["invites", "accept"],
    ]);
  });

  it("classifies every payload-bearing endpoint (strict と除外の重複なし)", () => {
    // 除外リストの退行防止: §12-10 (1) の対象外(署名済み構造・暗号文・鍵材料を
    // 運ばない mutation)のみが載ること
    expect(STRICT_EXEMPT_PAYLOAD_ENDPOINTS).toEqual([
      ["authCli", "cliStart"],
      ["authCli", "cliPoll"],
      ["authCli", "cliApprove"],
      ["deks", "remove"],
      ["rotation", "dismiss"],
      // schemaPolicy の PUT(§12-11 — 署名済み構造を運ばない 3 値の Literal)
      ["schemaPolicy", "set"],
    ]);
  });

  it("throws when a registered payload root lost its strict annotation", () => {
    const fakeApi = fakeApiFromRegistry(Schema.Struct({ a: Schema.String }));
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(/not parser-effective/);
  });

  it("throws for a payload-bearing endpoint in neither list (fail-closed)", () => {
    // 新設エンドポイントの分類漏れは黙って非 strict にならずロード時に落ちる
    const fakeApi = fakeApiFromRegistry(strictPayload(Schema.Struct({ a: Schema.String })));
    const membership = fakeApi.groups["membership"];
    if (membership === undefined) {
      throw new Error("fake api is missing the membership group");
    }
    membership.endpoints["newMutation"] = {
      payload: new Map([
        ["application/json", { schemas: [Schema.Struct({ a: Schema.String })] as [Schema.Top] }],
      ]),
    };
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(
      /membership\.newMutation.*not classified/,
    );
  });

  it("throws for a stale exempt entry (endpoint no longer exists)", () => {
    // 消えた・リネームされた面の除外指定が残ると、同名の security-critical 面の
    // 再利用時に「意識的除外」へ化けるため、除外側にも実在検査を課す
    const fakeApi = fakeApiFromRegistry(strictPayload(Schema.Struct({ a: Schema.String })));
    const rotation = fakeApi.groups["rotation"];
    if (rotation === undefined) {
      throw new Error("fake api is missing the rotation group");
    }
    delete rotation.endpoints["dismiss"];
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(
      /unknown endpoint "rotation\.dismiss"/,
    );
  });

  it("throws when a registered endpoint is missing", () => {
    expect(() => assertSecurityCriticalPayloadsStrict({ groups: {} })).toThrow(/unknown group/);
  });
});

type FakeApi = {
  groups: Record<
    string,
    {
      endpoints: Record<
        string,
        { payload: Map<string, { schemas: [Schema.Top, ...Array<Schema.Top>] }> }
      >;
    }
  >;
};

/**
 * 列挙面(strict)に指定スキーマ、除外面に素のスキーマを置いたフェイク API
 * (スイープの負例用 — 実在検査を通すため両リストの座標を揃える)。
 */
function fakeApiFromRegistry(schema: Schema.Top): FakeApi {
  const entries: readonly (readonly [string, string, Schema.Top])[] = [
    ...SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.map(([g, e]) => [g, e, schema] as const),
    ...STRICT_EXEMPT_PAYLOAD_ENDPOINTS.map(
      ([g, e]) => [g, e, Schema.Struct({ a: Schema.String })] as const,
    ),
  ];
  const groups: FakeApi["groups"] = {};
  for (const [group, endpoint, endpointSchema] of entries) {
    groups[group] ??= { endpoints: {} };
    groups[group].endpoints[endpoint] = {
      payload: new Map([["application/json", { schemas: [endpointSchema] as [Schema.Top] }]]),
    };
  }
  return { groups };
}
