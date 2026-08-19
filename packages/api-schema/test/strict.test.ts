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
    // 列挙の退行防止(§16-1 ヘッド申告は未実装のため対象外 — 実装時に追加する)
    expect(SECURITY_CRITICAL_PAYLOAD_ENDPOINTS).toEqual([
      ["membership", "init"],
      ["membership", "append"],
      ["environments", "create"],
      ["environments", "rotate"],
      ["environments", "rename"],
      ["environments", "remove"],
      ["variables", "create"],
      ["variables", "push"],
      ["variables", "rename"],
      ["variables", "remove"],
      ["deks", "register"],
      ["auth", "recoveryPut"],
      ["lease", "issue"],
      ["invites", "issue"],
      ["invites", "accept"],
    ]);
  });

  it("throws when a registered payload root lost its strict annotation", () => {
    const nonStrict = Schema.Struct({ a: Schema.String });
    const fakeApi = {
      groups: Object.fromEntries(
        SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.map(([group]) => [
          group,
          {
            endpoints: Object.fromEntries(
              SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.filter(([g]) => g === group).map(
                ([, endpoint]) => [
                  endpoint,
                  {
                    payload: new Map([
                      ["application/json", { schemas: [nonStrict] as [Schema.Top] }],
                    ]),
                  },
                ],
              ),
            ),
          },
        ]),
      ),
    };
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(/not parser-effective/);
  });

  it("throws when a registered endpoint is missing", () => {
    expect(() => assertSecurityCriticalPayloadsStrict({ groups: {} })).toThrow(/unknown group/);
  });
});
