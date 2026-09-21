// security-critical 受理の strict 化(AUTH_SPEC §12-10 (1))。
//
// Effect v4 rc.113 以降、スキーマ AST 注釈 `parseOptions` はパーサに読まれない
// (SchemaAST.ParseOptions の説明: options はパース全体に適用され、スキーマ注釈は
// それを上書きしない)。rc.112 までの `strictPayload` = スキーマ注釈は、呼び出し側が
// options なしで decode すると未知フィールドを黙って落とす。
//
// 代わりに payload スキーマをラッパーで包む。decode と encode は内側スキーマへ
// `{ onExcessProperty: "error" }` を渡すので、ネストと Union を含めて未知フィールドを
// 拒否する。HttpApiBuilder は payload を `Schema.Union([schema])` で options なしに
// decode する。ラッパーはその組み立ての中でも拒否する。
//
// `HttpApi.ParseOptions` は使わない。同じ options が成功・エラーの符号化と
// path params・ヘッダにも渡る。`Schema.TaggedError` はスタック由来の非列挙
// フィールド(`originalLine` 等)を持つため、エラー応答の strict encode は
// HttpApiSchemaError になり HTTP 500 へ落ちる。ヘッダ codec は受信ヘッダ全体を
// 見るので、API 全体への `onExcessProperty: "error"` も使わない。
//
// 共有スキーマ自体は包まない。同じスキーマを返す他エンドポイントの応答へ
// strict を波及させない。このエンドポイントの成功・エラー符号化は従来どおり
// 未知フィールドを落とす。
//
// ロード時スイープは注釈を見ない。options なしの decode に未知フィールドを渡し、
// `UnexpectedKey` が出ることを要求する(`.check()` を後から足しても拒否は残る。
// AST の `parseOptions` 注釈だけは拒否しない)。実効性(実際に 400)は受理経路の
// 固定テスト(apps/server/test/strict-payload.test.ts)が保証する。

import { Effect, Result, Schema, SchemaIssue, SchemaTransformation } from "effect";

import { forEachEndpoint, requireRegisteredEndpoint } from "./sweep.ts";

/** 内側スキーマの decode / encode に渡す strict options。 */
const STRICT = { onExcessProperty: "error" } as const;

/**
 * スイープが「未知フィールド」と見なすプローブキー。
 * 受理経路の固定テスト(`__maruhiStrictProbe`)と同じ名前。
 */
const PROBE_KEY = "__maruhiStrictProbe";

/**
 * The structural slice of an `HttpApi` the sweep walks (the concrete
 * `HttpApi<...>` type is invariant in its group union, so the nominal
 * `HttpApi.Top` is not usable as a parameter type here).
 */
interface SweepableApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: {
          readonly payload: ReadonlyMap<
            string,
            { readonly schemas: readonly [Schema.Top, ...Array<Schema.Top>] }
          >;
        };
      };
    };
  };
}

/**
 * Wraps a security-critical payload schema so unknown fields are rejected
 * with a schema error (HTTP 400) instead of being silently dropped
 * (AUTH_SPEC §12-10 (1)).
 *
 * Decode and encode both pass `{ onExcessProperty: "error" }` to `schema`,
 * including nested structs and unions. The wrapper is what the server decodes
 * (no parse options) and what the client encodes. Do not put
 * `HttpApi.ParseOptions` on the endpoint: the same options apply to success
 * and error codecs, and encoding a `Schema.TaggedError` under strict excess
 * checking fails closed into HTTP 500.
 *
 * Shared component schemas stay unwrapped. Other endpoints that reuse the same
 * schema without this wrapper keep the default (strip unknown fields). Checks
 * composed after the wrapper do not turn the rejection off.
 */
export function strictPayload<S extends Schema.Top>(schema: S): S {
  // `to` を `Schema.toType(schema)` にすると encode の入力から未知キーが
  // 先に落ち、strict encode が成功してしまう。両側を Unknown にすると
  // encode が余分なキーを見る。型は内側スキーマのまま(ハンドラとクライアントの
  // payload 型は `Type` を使う)。
  return Schema.Unknown.pipe(
    Schema.decodeTo(
      Schema.Unknown,
      SchemaTransformation.transformEffect({
        decode: (input: unknown) =>
          Schema.decodeUnknownEffect(
            schema,
            STRICT,
          )(input).pipe(Effect.mapError((error) => error.issue)),
        encode: (value: unknown) =>
          Schema.encodeUnknownEffect(
            schema,
            STRICT,
          )(value).pipe(Effect.mapError((error) => error.issue)),
      }),
    ),
  ) as unknown as S;
}

/**
 * The security-critical mutation payload roots of the maruhi HTTP API — the
 * §12-10 (1) enumeration projected onto implemented endpoints, as
 * `[group, endpoint]` pairs:
 *
 * - chain appends incl. genesis (§11-4): membership init / append
 * - environment creation / rotation composites (§12-4)
 * - value pushes and meta operations (§12-5)
 * - DEK wrap registration (§12-6)
 * - recovery blob registration (§13-2)
 * - lease claims (§14)
 * - invitation issue / accept (§15-2)
 * - head-attestation submission (§16-1): membership attest
 */
export const SECURITY_CRITICAL_PAYLOAD_ENDPOINTS: ReadonlyArray<
  readonly [group: string, endpoint: string]
> = [
  ["membership", "init"],
  ["membership", "append"],
  ["membership", "attest"],
  ["environments", "create"],
  ["environments", "rotate"],
  ["environments", "rename"],
  ["environments", "remove"],
  ["variables", "create"],
  ["variables", "push"],
  // activation 複合(§12-5 — §12-10 (1) の「値 push・メタ操作」クラスに属する)
  ["variables", "activate"],
  ["variables", "rename"],
  ["variables", "remove"],
  ["deks", "register"],
  ["auth", "recoveryPut"],
  // master 鍵ラップ台帳(§13-7 — KL3): ラップ・分片・再封印値 = 鍵素材の暗号文
  ["keyWraps", "passkeyRegister"],
  ["keyWraps", "guardianCreate"],
  ["keyWraps", "handoffApprove"],
  // 端末登録簿(§13-11 — DK K3): 公開鍵の登録 = 鍵宣言クラス(未知フィールドを黙って落とさない)
  ["devices", "register"],
  ["devices", "requestCreate"],
  ["lease", "issue"],
  ["invites", "issue"],
  ["invites", "accept"],
];

/**
 * Payload-bearing endpoints that are deliberately **not** strict: mutations
 * that carry no signed structure, ciphertext or key material, so they fall
 * outside the §12-10 (1) enumeration. Every payload-bearing endpoint of the
 * API must appear in exactly one of the two lists — the sweep fails closed on
 * an endpoint that is in neither, so adding a payload endpoint forces a
 * conscious strict / non-strict decision instead of silently defaulting to
 * the permissive schema behavior.
 */
export const STRICT_EXEMPT_PAYLOAD_ENDPOINTS: ReadonlyArray<
  readonly [group: string, endpoint: string]
> = [
  // CLI ログイン(AUTH_SPEC §4 — 認証前のハンドオフ面。署名済み構造・暗号文・
  // 鍵材料を運ばない): start = 発行パラメータのみ、poll = フロー資格情報のみ、
  // approve = ブラウザの素のフォーム POST(欠落・不一致はハンドラが一様拒否)
  ["authCli", "cliStart"],
  ["authCli", "cliPoll"],
  ["authCli", "cliApprove"],
  // 削除対象ラップの座標参照のみ(§12-6 修復経路)
  ["deks", "remove"],
  // (environment, variable) 識別子の列挙のみ(AUDIT_SPEC §7)
  ["rotation", "dismiss"],
  // schemaPolicy の設定(AUTH_SPEC §12-11 — 署名済み構造を運ばない。3 値の
  // Literal で Schema 検証が閉じる)
  ["schemaPolicy", "set"],
  // ハンドオフ要求(§13-7 — KL3): request_id(一時公開鍵の SHA-256)のみ。
  // 署名済み構造・暗号文・鍵素材を運ばない
  ["keyWraps", "handoffCreate"],
];

/**
 * Asserts that decoding `schema` with no parse options rejects an unknown
 * field (AUTH_SPEC §12-10 (1)). Throws on failure.
 *
 * The assembly matches `HttpApiBuilder`: `Schema.Union([schema])` and no
 * options. An AST `parseOptions` annotation does not satisfy this check.
 */
function assertPayloadRejectsUnknownField(schema: Schema.Top, label: string): void {
  if (!payloadRejectsUnknownField(schema)) {
    throw new Error(
      `strict payload is not parser-effective for ${label}: ` +
        `wrap the payload with strictPayload (AUTH_SPEC §12-10 (1))`,
    );
  }
}

/** options なしの decode が未知フィールドを `UnexpectedKey` で拒否するか。 */
function payloadRejectsUnknownField(schema: Schema.Top): boolean {
  // Schema.Top の DecodingServices は unknown。security-critical payload は
  // サービスを要求しないので、builder と同じ Union を閉じたデコーダとして扱う。
  const decoded = Schema.decodeUnknownResult(
    Schema.Union([schema]) as unknown as Schema.ConstraintDecoder<unknown>,
  )({
    [PROBE_KEY]: true,
  });
  return Result.isFailure(decoded) && hasUnexpectedKey(decoded.failure.issue);
}

function hasUnexpectedKey(issue: SchemaIssue.Issue): boolean {
  // `_tag` 直読みは oxlint の no-underscore-dangle が禁止する。
  if (issue instanceof SchemaIssue.UnexpectedKey) {
    return true;
  }
  if ("issue" in issue && SchemaIssue.isIssue(issue.issue) && hasUnexpectedKey(issue.issue)) {
    return true;
  }
  if ("issues" in issue && Array.isArray(issue.issues)) {
    return issue.issues.some((child) => SchemaIssue.isIssue(child) && hasUnexpectedKey(child));
  }
  return false;
}

/**
 * Load-time sweep (AUTH_SPEC §12-10 (1)): asserts that every registered
 * security-critical payload rejects an unknown field when decoded with no
 * parse options, and that every payload-bearing endpoint of the API is
 * classified in exactly one of `SECURITY_CRITICAL_PAYLOAD_ENDPOINTS` /
 * `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`. An endpoint in neither list throws, so
 * for **body payloads** the §12-10 (1) rule "classify new and revised
 * endpoints against this standard" is machine-enforced instead of remaining a
 * process obligation. The sweep decodes the payload schema the way
 * `HttpApiBuilder` does (a union, no parse options). An unknown field arriving
 * via `query` or `headers` on an endpoint that does not declare those schemas
 * is outside its view (today that blind spot holds the `audit` reads and
 * `auth.githubCallback`, a state-changing GET). A future mutation modelling
 * request data as `query` or `headers` must be classified by review — and
 * must not receive `HttpApi.ParseOptions`, because header codecs see every
 * incoming header and the same options strict-encode error responses into
 * HTTP 500.
 */
export function assertSecurityCriticalPayloadsStrict(api: SweepableApi): void {
  const strict = new Set(SECURITY_CRITICAL_PAYLOAD_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
  const exempt = new Set(STRICT_EXEMPT_PAYLOAD_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
  for (const key of strict) {
    if (exempt.has(key)) {
      throw new Error(
        `security-critical payload sweep: "${key}" is listed as both strict and exempt`,
      );
    }
  }
  // 1. 列挙面の実在 + 未知フィールド拒否(リネーム・ラッパーの欠落を捕捉)
  for (const [groupName, endpointName] of SECURITY_CRITICAL_PAYLOAD_ENDPOINTS) {
    assertRegisteredPayloadStrict(api, groupName, endpointName);
  }
  // 2. 除外面の実在(stale エントリの排除 — 消えた・リネームされた面の除外指定が
  //    残ると、後で同名の security-critical 面が再利用されたとき「意識的除外」に
  //    化けるため、strict 側と同じ実在検査を課す)
  for (const [groupName, endpointName] of STRICT_EXEMPT_PAYLOAD_ENDPOINTS) {
    requirePayloadEndpoint(api, groupName, endpointName);
  }
  assertEveryPayloadClassified(api, strict, exempt);
}

/** 列挙面 1 件: 実在検査 + 未知フィールド拒否(スイープの 1.)。 */
function assertRegisteredPayloadStrict(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): void {
  const endpoint = requirePayloadEndpoint(api, groupName, endpointName);
  const label = `${groupName}.${endpointName}`;
  for (const content of endpoint.payload.values()) {
    for (const schema of content.schemas) {
      assertPayloadRejectsUnknownField(schema, label);
    }
  }
}

/**
 * 逆方向の fail-closed 検査(スイープの 3.): payload を持つ全エンドポイントが
 * どちらかのリストに分類されていること — 未分類の新設面は黙って非 strict に
 * ならずここで落ちる。
 */
function assertEveryPayloadClassified(
  api: SweepableApi,
  strict: ReadonlySet<string>,
  exempt: ReadonlySet<string>,
): void {
  forEachEndpoint(api, (key, endpoint) => {
    if (endpoint.payload.size > 0 && !strict.has(key) && !exempt.has(key)) {
      throw new Error(
        `security-critical payload sweep: "${key}" carries a payload but is not classified — ` +
          `add it to SECURITY_CRITICAL_PAYLOAD_ENDPOINTS (AUTH_SPEC §12-10 (1)) or, if it ` +
          `carries no signed structure, ciphertext or key material, to ` +
          `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`,
      );
    }
  });
}

/** リスト 1 件の実在検査: グループ・エンドポイント・payload の存在を要求する。 */
function requirePayloadEndpoint(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): SweepableApi["groups"][string]["endpoints"][string] {
  const endpoint = requireRegisteredEndpoint(
    api,
    "security-critical payload sweep",
    groupName,
    endpointName,
  );
  if (endpoint.payload.size === 0) {
    throw new Error(
      `security-critical payload sweep: "${groupName}.${endpointName}" has no payload schema`,
    );
  }
  return endpoint;
}
