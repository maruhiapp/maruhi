// strict 受理(AUTH_SPEC §12-10 (1))のユニットテスト。
//
// Effect rc.113 以降、スキーマ AST の parseOptions はパーサに読まれない。
// strict は payload スキーマのラッパーであり、HttpApiBuilder は options なしで
// Schema.Union([payload]) を decode する。エンドポイントの HttpApi.ParseOptions
// は使わない(エラー応答の strict encode が HTTP 500 になる)。
// 受理経路(workerd 実環境)での 400 拒否は apps/server/test/strict-payload.test.ts

import { Result, Schema } from "effect";
import { describe, expect, it } from "vitest";

import {
  assertSecurityCriticalPayloadsStrict,
  maruhiApi,
  SECURITY_CRITICAL_PAYLOAD_ENDPOINTS,
  STRICT_EXEMPT_PAYLOAD_ENDPOINTS,
  strictPayload,
} from "../src/index.ts";

const payload = Schema.Struct({ nested: Schema.Struct({ a: Schema.String }) });

/** HttpApiBuilder が payload デコーダを組み立てる形(options なしの Union)。 */
const decodeAsBuilder = (schema: Schema.Top, input: unknown) =>
  Schema.decodeUnknownResult(
    Schema.Union([schema]) as unknown as Schema.ConstraintDecoder<unknown>,
  )(input);

describe("strictPayload", () => {
  const strict = strictPayload(payload);

  it("accepts a clean payload through the builder assembly", () => {
    expect(Result.isSuccess(decodeAsBuilder(strict, { nested: { a: "x" } }))).toBe(true);
  });

  it("rejects a root-level unknown field", () => {
    expect(Result.isFailure(decodeAsBuilder(strict, { nested: { a: "x" }, extra: 1 }))).toBe(true);
  });

  it("rejects a nested unknown field", () => {
    expect(Result.isFailure(decodeAsBuilder(strict, { nested: { a: "x", extra: 1 } }))).toBe(true);
  });

  it("rejects an unknown field inside a union member", () => {
    const member = Schema.Struct({ a: Schema.String });
    const union = strictPayload(Schema.Union([member, Schema.Struct({ b: Schema.Number })]));
    expect(Result.isFailure(decodeAsBuilder(union, { a: "x", extra: 1 }))).toBe(true);
  });

  it("rejects an unknown field when encoding", () => {
    const encode = Schema.encodeUnknownResult(strict);
    const extra = encode({ nested: { a: "x" }, extra: 1 });
    const clean = encode({ nested: { a: "x" } });
    expect(Result.isFailure(extra)).toBe(true);
    expect(Result.isSuccess(clean)).toBe(true);
  });

  it("keeps rejecting unknown fields when a check is composed after the wrapper", () => {
    const checked = strictPayload(Schema.Struct({ a: Schema.String })).check(
      Schema.makeFilter(() => undefined),
    );
    expect(Result.isSuccess(decodeAsBuilder(checked, { a: "x" }))).toBe(true);
    expect(Result.isFailure(decodeAsBuilder(checked, { a: "x", extra: 1 }))).toBe(true);
  });

  it("ignores a schema AST parseOptions annotation (Effect rc.113+)", () => {
    const annotated = Schema.Struct({ a: Schema.String }).annotate({
      parseOptions: { onExcessProperty: "error" },
    });
    expect(Result.isSuccess(decodeAsBuilder(annotated, { a: "x", extra: 1 }))).toBe(true);
  });
});

describe("assertSecurityCriticalPayloadsStrict", () => {
  it("passes on the registered maruhi API (also runs at module load)", () => {
    expect(() => assertSecurityCriticalPayloadsStrict(maruhiApi)).not.toThrow();
  });

  it("covers every §12-10 (1) implemented surface", () => {
    // 列挙の退行防止(§16-1 ヘッド申告 = membership.attest を含む)
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
      // activation 複合(§12-5)
      ["variables", "activate"],
      ["variables", "rename"],
      ["variables", "remove"],
      ["deks", "register"],
      ["auth", "recoveryPut"],
      // master 鍵ラップ台帳(§13-7 — KL3): ラップ・分片・再封印値 = 鍵素材の暗号文
      ["keyWraps", "passkeyRegister"],
      ["keyWraps", "guardianCreate"],
      ["keyWraps", "handoffApprove"],
      // 端末登録簿(§13-11 — DK K3): 公開鍵の登録 = 鍵宣言クラス
      ["devices", "register"],
      ["devices", "requestCreate"],
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
      // ハンドオフ要求(§13-7 — KL3): request_id のみ
      ["keyWraps", "handoffCreate"],
    ]);
  });

  it("throws when a registered payload is not wrapped", () => {
    const fakeApi = fakeApiFromRegistry(false);
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApi)).toThrow(/not parser-effective/);
  });

  it("accepts a registry whose payloads are wrapped", () => {
    expect(() => assertSecurityCriticalPayloadsStrict(fakeApiFromRegistry(true))).not.toThrow();
  });

  it("throws for a payload-bearing endpoint in neither list (fail-closed)", () => {
    // 新設エンドポイントの分類漏れは黙って非 strict にならずロード時に落ちる
    const fakeApi = fakeApiFromRegistry(true);
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
    const fakeApi = fakeApiFromRegistry(true);
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

type FakeEndpoint = {
  payload: Map<string, { schemas: [Schema.Top, ...Array<Schema.Top>] }>;
};

type FakeApi = {
  groups: Record<string, { endpoints: Record<string, FakeEndpoint> }>;
};

/**
 * 列挙面を strictPayload(または素の Struct)、除外面を素の Struct にした
 * フェイク API(スイープの正例・負例 — 実在検査を通すため両リストの座標を揃える)。
 */
function fakeApiFromRegistry(strict: boolean): FakeApi {
  const schema = Schema.Struct({ a: Schema.String });
  const entries: readonly (readonly [string, string, boolean])[] = [
    ...SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.map(([g, e]) => [g, e, strict] as const),
    ...STRICT_EXEMPT_PAYLOAD_ENDPOINTS.map(([g, e]) => [g, e, false] as const),
  ];
  const groups: FakeApi["groups"] = {};
  for (const [group, endpoint, isStrict] of entries) {
    groups[group] ??= { endpoints: {} };
    groups[group].endpoints[endpoint] = {
      payload: new Map([
        [
          "application/json",
          { schemas: [isStrict ? strictPayload(schema) : schema] as [Schema.Top] },
        ],
      ]),
    };
  }
  return { groups };
}
