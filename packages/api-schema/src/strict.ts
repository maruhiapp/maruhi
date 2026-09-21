// security-critical 受理の strict 化(AUTH_SPEC §12-10 (1))。
//
// Effect v4 rc.113 以降、スキーマ AST 注釈 `parseOptions` はパーサに読まれない
// (SchemaAST.ParseOptions の説明: options はパース全体に適用され、スキーマ注釈は
// それを上書きしない)。rc.112 までの `strictPayload` = スキーマ注釈は、呼び出し側が
// options なしで decode すると未知フィールドを黙って落とす。
//
// 代わりに security-critical エンドポイントへ `HttpApi.ParseOptions`
// (`onExcessProperty: "error"`)を付ける。HttpApiBuilder と HttpApiClient は
// エンドポイント > グループ > API の順で合成した注釈を読み、payload の復号・符号化、
// 成功・エラーの符号化、path params に同じ options を渡す。options はネストと
// Union を越えてパース全体に効く。
//
// API 全体には付けない。ヘッダ codec は受信ヘッダ全体を見るため、
// `onExcessProperty: "error"` は未宣言ヘッダ(`content-type` 等)を 400 にする。
// グループ単位も付けない。除外エンドポイント(署名済み構造・暗号文・鍵材料を
// 運ばない mutation)まで strict になる。
//
// 共有スキーマ自体には注釈しない。同じスキーマを返す他エンドポイントの応答へ
// strict を波及させない。このエンドポイントの成功・エラー符号化は同じ options に
// なる(余分なキーは黙って落とさず符号化に失敗する — fail-closed)。
//
// ロード時スイープはエンドポイント注釈を、HttpApiBuilder と同じ
// `Context.getOrUndefined(..., HttpApi.ParseOptions)` で読む。実効性(実際に 400)
// は受理経路の固定テスト(apps/server/test/strict-payload.test.ts)が保証する。

import { Context, type Schema, type SchemaAST } from "effect";
import { HttpApi } from "effect/unstable/httpapi";

import { forEachEndpoint, requireRegisteredEndpoint } from "./sweep.ts";

/** Builder とクライアントが payload に渡す strict options。 */
const STRICT_PARSE_OPTIONS = {
  onExcessProperty: "error",
} as const satisfies SchemaAST.ParseOptions;

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
          readonly annotations: Context.Context<never>;
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
 * Marks a security-critical endpoint as strict: unknown payload fields are
 * rejected with a schema error (HTTP 400) instead of being silently dropped
 * (AUTH_SPEC §12-10 (1)).
 *
 * The annotation is what `HttpApiBuilder` and `HttpApiClient` read. It applies
 * to the whole payload parse, including nested structs and unions, and also to
 * path params and to success / error codecs of this endpoint. Do not put it on
 * the API or on a group — header codecs see every incoming header, and exempt
 * sibling endpoints must stay permissive.
 *
 * Shared payload schemas stay unannotated. Other endpoints that reuse the same
 * schema without this annotation keep the default (strip unknown fields).
 */
export function strictEndpoint<
  E extends {
    annotate(key: typeof HttpApi.ParseOptions, value: SchemaAST.ParseOptions): E;
  },
>(endpoint: E): E {
  return endpoint.annotate(HttpApi.ParseOptions, STRICT_PARSE_OPTIONS);
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
 * Asserts that an endpoint carries `HttpApi.ParseOptions` with
 * `onExcessProperty: "error"` — the annotation `HttpApiBuilder` actually
 * reads (AUTH_SPEC §12-10 (1)). Throws on failure.
 */
function assertEndpointParseOptionsStrict(
  annotations: Context.Context<never>,
  label: string,
): void {
  const options = Context.getOrUndefined(annotations, HttpApi.ParseOptions);
  if (options?.onExcessProperty !== "error") {
    throw new Error(
      `strict payload annotation is not parser-effective for ${label}: ` +
        `annotate the endpoint with HttpApi.ParseOptions { onExcessProperty: "error" } ` +
        `(AUTH_SPEC §12-10 (1))`,
    );
  }
}

/**
 * Load-time sweep (AUTH_SPEC §12-10 (1)): asserts that every registered
 * security-critical endpoint carries `HttpApi.ParseOptions` with
 * `onExcessProperty: "error"`, and that every payload-bearing endpoint of the
 * API is classified in exactly one of `SECURITY_CRITICAL_PAYLOAD_ENDPOINTS` /
 * `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`. An endpoint in neither list throws, so
 * for **body payloads** the §12-10 (1) rule "classify new and revised
 * endpoints against this standard" is machine-enforced instead of remaining a
 * process obligation. The sweep inspects the endpoint annotation, which the
 * builder applies to the payload and, on the same endpoint, to path params and
 * success / error codecs. An unknown field arriving via `query` or `headers`
 * on an endpoint that does not declare those schemas is outside its view
 * (today that blind spot holds the `audit` reads and `auth.githubCallback`,
 * a state-changing GET). A future mutation modelling request data as `query`
 * or `headers` must be classified by review — and must not receive this
 * annotation if it declares headers, because header codecs see every incoming
 * header.
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
  // 1. 列挙面の実在 + エンドポイント注釈(リネーム・注釈の欠落を捕捉)
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

/** 列挙面 1 件: 実在検査 + ParseOptions 注釈検査(スイープの 1.)。 */
function assertRegisteredPayloadStrict(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): void {
  const endpoint = requirePayloadEndpoint(api, groupName, endpointName);
  assertEndpointParseOptionsStrict(endpoint.annotations, `${groupName}.${endpointName}`);
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
