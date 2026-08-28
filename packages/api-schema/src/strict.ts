// security-critical 受理スキーマの strict 化(AUTH_SPEC §12-10 (1))。
//
// Effect v4 の AST 注釈 `parseOptions` は parse 時に呼び出し側 ParseOptions と
// 合成され AST 側が勝つ(SchemaParser.makeParser — docs/notes/session-32.md §2 で
// 実証)。よって payload ルートへの 1 注釈で、HttpApiBuilder が options なしで
// decode する実経路でも strict(未知フィールド = 400)が効き、ネストと Union を
// 越えて伝播する。
//
// 既知の罠(session-32 §2-3): SchemaParser は AST に checks があると
// `parseOptions` を**最後の check の annotations** から読む。`SchemaAST.annotate`
// も checks があると最後の check へ注釈を付けるため、**注釈の後に `.check(...)` を
// 合成すると strict が無警告で失効する**。防衛は 2 層(session-32 §5-2):
//
// 1. `strictPayload(...)` は注釈直後に有効位置を assert する(ラップ時 fail-loud)
// 2. `assertSecurityCriticalPayloadsStrict(...)` が HttpApi 定義に登録された
//    payload ルートをロード時に走査する(ラップ後の再合成も捕捉する)
//
// 加えて実効性(実際に 400 で拒否される)は受理経路の固定テスト
// (apps/server/test/strict-payload.test.ts)が保証する — 注釈の存在でなく
// 拒否の挙動をテストする(適用順バグと upstream の読み取り位置変更の両方を検出)。

import type { Schema, SchemaAST } from "effect";

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
 * The parser-effective `parseOptions` of a schema AST, read through the same
 * path `SchemaParser.makeParser` uses: the last check's annotations when the
 * AST has checks, the AST's own annotations otherwise.
 */
function effectiveParseOptions(ast: SchemaAST.AST): SchemaAST.ParseOptions | undefined {
  const checks = ast.checks;
  const annotations =
    checks === undefined ? ast.annotations : checks[checks.length - 1]?.annotations;
  return annotations?.["parseOptions"] as SchemaAST.ParseOptions | undefined;
}

/**
 * Asserts that a payload root schema carries `onExcessProperty: "error"` in
 * the position the parser actually reads (AUTH_SPEC §12-10 (1)). Throws on
 * failure — composing `.check(...)` after the strict annotation silently
 * disables it, so this turns that silent failure into a load-time crash.
 */
export function assertStrictPayloadRoot(schema: Schema.Top, label: string): void {
  const options = effectiveParseOptions(schema.ast);
  if (options?.onExcessProperty !== "error") {
    throw new Error(
      `strict payload annotation is not parser-effective for ${label}: ` +
        `apply strictPayload(...) last, after every .check(...) composition ` +
        `(AUTH_SPEC §12-10 (1))`,
    );
  }
}

/**
 * Marks a security-critical mutation payload root as strict: unknown fields
 * are rejected with a schema error (HTTP 400) instead of being silently
 * dropped (AUTH_SPEC §12-10 (1)). The annotation propagates to every nested
 * field and across unions, so a single application at the payload root covers
 * the whole request body.
 *
 * The annotation is symmetric: the derived `HttpApiClient` encodes payloads
 * through this same schema, so excess properties fail at **client encode
 * time** too. TypeScript's excess-property check only fires on fresh object
 * literals, so build payloads as exact literals — spreading a wider object
 * into a payload fails at runtime without a compile-time warning.
 *
 * Apply this **last**, to a schema whose `.check(...)` compositions are all
 * done — a later `.check(...)` would silently disable the annotation
 * (the load-time asserts and the acceptance-path tests both guard this).
 */
export function strictPayload<S extends Schema.Top>(schema: S): S["Rebuild"] {
  const annotated = schema.annotate({ parseOptions: { onExcessProperty: "error" } });
  assertStrictPayloadRoot(annotated, "strictPayload(...)");
  return annotated;
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
  ["variables", "rename"],
  ["variables", "remove"],
  ["deks", "register"],
  ["auth", "recoveryPut"],
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
  // GitHub トークン + トークン名 + スコープのみ(AUTH_SPEC §4 — 認証前の交換面。
  // 署名済み構造・暗号文・鍵材料を運ばない)
  ["auth", "deviceExchange"],
  // 削除対象ラップの座標参照のみ(§12-6 修復経路)
  ["deks", "remove"],
  // (environment, variable) 識別子の列挙のみ(AUDIT_SPEC §7)
  ["rotation", "dismiss"],
];

/**
 * Load-time sweep (AUTH_SPEC §12-10 (1)): asserts that every registered
 * security-critical payload root carries the strict annotation in the
 * parser-effective position (catching recompositions that happened after
 * `strictPayload(...)` was applied — the wrapper's own assert runs only once,
 * at wrap time), and that every payload-bearing endpoint of the API is
 * classified in exactly one of `SECURITY_CRITICAL_PAYLOAD_ENDPOINTS` /
 * `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`. An endpoint in neither list throws, so
 * for **body payloads** the §12-10 (1) rule "classify new and revised
 * endpoints against this standard" is machine-enforced instead of remaining a
 * process obligation. The sweep inspects only `endpoint.payload` — an unknown
 * field arriving via `query` or `headers` is outside its view (path `params`
 * are template-extracted and structurally cannot carry an excess field).
 * Today that blind spot holds the `audit` reads and `auth.githubCallback`
 * (a state-changing GET — it exchanges the OAuth code and issues a session);
 * a future mutation modelling request data as `query` / `headers` must be
 * classified by review.
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
  // 1. 列挙面の実在 + strict 注釈の有効位置(リネーム・注釈の失効を捕捉)
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

/** 列挙面 1 件: 実在検査 + 全 payload スキーマの strict 注釈検査(スイープの 1.)。 */
function assertRegisteredPayloadStrict(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): void {
  const endpoint = requirePayloadEndpoint(api, groupName, endpointName);
  for (const [mediaType, { schemas }] of endpoint.payload) {
    for (const schema of schemas) {
      assertStrictPayloadRoot(schema, `${groupName}.${endpointName} (${mediaType})`);
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
  for (const [groupName, group] of Object.entries(api.groups)) {
    for (const [endpointName, endpoint] of Object.entries(group.endpoints)) {
      const key = `${groupName}.${endpointName}`;
      if (endpoint.payload.size > 0 && !strict.has(key) && !exempt.has(key)) {
        throw new Error(
          `security-critical payload sweep: "${key}" carries a payload but is not classified — ` +
            `add it to SECURITY_CRITICAL_PAYLOAD_ENDPOINTS (AUTH_SPEC §12-10 (1)) or, if it ` +
            `carries no signed structure, ciphertext or key material, to ` +
            `STRICT_EXEMPT_PAYLOAD_ENDPOINTS`,
        );
      }
    }
  }
}

/** リスト 1 件の実在検査: グループ・エンドポイント・payload の存在を要求する。 */
function requirePayloadEndpoint(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): SweepableApi["groups"][string]["endpoints"][string] {
  const group = api.groups[groupName];
  if (group === undefined) {
    throw new Error(`security-critical payload sweep: unknown group "${groupName}"`);
  }
  const endpoint = group.endpoints[endpointName];
  if (endpoint === undefined) {
    throw new Error(
      `security-critical payload sweep: unknown endpoint "${groupName}.${endpointName}"`,
    );
  }
  if (endpoint.payload.size === 0) {
    throw new Error(
      `security-critical payload sweep: "${groupName}.${endpointName}" has no payload schema`,
    );
  }
  return endpoint;
}
