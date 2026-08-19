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
 *
 * Head attestation (§16-1) is not implemented yet; add it here when it lands.
 */
export const SECURITY_CRITICAL_PAYLOAD_ENDPOINTS: ReadonlyArray<
  readonly [group: string, endpoint: string]
> = [
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
];

/**
 * Load-time sweep (AUTH_SPEC §12-10 (1)): walks every security-critical
 * payload root registered on the given HTTP API and asserts the strict
 * annotation sits in the parser-effective position. Catches recompositions
 * that happened after `strictPayload(...)` was applied — the wrapper's own
 * assert runs only once, at wrap time.
 */
export function assertSecurityCriticalPayloadsStrict(api: SweepableApi): void {
  for (const [groupName, endpointName] of SECURITY_CRITICAL_PAYLOAD_ENDPOINTS) {
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
    for (const [mediaType, { schemas }] of endpoint.payload) {
      for (const schema of schemas) {
        assertStrictPayloadRoot(schema, `${groupName}.${endpointName} (${mediaType})`);
      }
    }
  }
}
