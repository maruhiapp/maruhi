// ダッシュボード消費面のスイープ(裁定 BW — docs/notes/session-43.md §11)。
//
// 目録(src/dashboard/endpoints.ts)を登録済み HttpApi(api-schema — 値 import は
// テストプロセスのみ)と突合し、「パス整合」と「セッション許可」を fail-loud に
// する。serving-topology.test.ts(サーバー側の run_worker_first 被覆)の
// クライアント側対応物。
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { isSessionAllowedEndpoint, maruhiApi, UNAUTHENTICATED_ENDPOINTS } from "@maruhi/api-schema";
import { describe, expect, it } from "vitest";

import {
  apiPaths,
  DASHBOARD_ENDPOINTS,
  SAMPLE_ENVIRONMENT_ID,
  SAMPLE_INVITE_ID,
  SAMPLE_PROJECT_ID,
  SAMPLE_TOKEN_ID,
} from "../../src/dashboard/endpoints.ts";

/** 登録エンドポイント 1 面の構造スライス。 */
interface RegisteredEndpoint {
  readonly path: string;
  /** クエリ Schema(未宣言のエンドポイントでは undefined)。 */
  readonly query?: {
    readonly ast?: {
      readonly propertySignatures?: ReadonlyArray<{ readonly name: PropertyKey }>;
    };
  };
}

/** 検査対象の構造スライス(session-capability.ts の SweepableApi と同じ理由の構造型)。 */
interface PathedApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: RegisteredEndpoint;
      };
    };
  };
}

const api = maruhiApi as unknown as PathedApi;

/**
 * パステンプレートの `:param` を目録と同じサンプル値で具体化する。未知の
 * パラメータ名はそのまま残り、等値比較が落ちて目録の改訂を強制する(fail-loud)。
 */
function substituteTemplate(template: string): string {
  return template
    .replace(/:projectId/g, SAMPLE_PROJECT_ID)
    .replace(/:environmentId/g, SAMPLE_ENVIRONMENT_ID)
    .replace(/:tokenId/g, SAMPLE_TOKEN_ID)
    .replace(/:id/g, SAMPLE_INVITE_ID);
}

describe("dashboard endpoint sweep (裁定 BW)", () => {
  it("binds every consumed path builder to a real api-schema endpoint", () => {
    for (const { group, endpoint, sample } of DASHBOARD_ENDPOINTS) {
      const registered = api.groups[group]?.endpoints[endpoint];
      expect(registered, `${group}.${endpoint} is not a registered endpoint`).toBeDefined();
      expect(substituteTemplate(registered?.path ?? ""), `${group}.${endpoint}`).toBe(sample);
    }
  });

  it("classifies every consumed endpoint's auth surface correctly (AUTH_SPEC §5)", () => {
    // access: "session" はセッション許可列挙内(列挙外 API を呼ぶ画面は実行時
    // 403 でなくここで割れる)。access: "unauthenticated" は未認証面の列挙内
    // (認証必須の面をナビゲーション導線として消費する形もここで割れる)
    const unauthenticated = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
    for (const { group, endpoint, access } of DASHBOARD_ENDPOINTS) {
      if (access === "session") {
        expect(
          isSessionAllowedEndpoint(group, endpoint),
          `${group}.${endpoint} is not session-allowed — a browser session cannot call it`,
        ).toBe(true);
      } else {
        expect(
          unauthenticated.has(`${group}.${endpoint}`),
          `${group}.${endpoint} is marked unauthenticated in the manifest but not in AUTH_SPEC §5`,
        ).toBe(true);
      }
    }
  });

  it("has no duplicate entries (each consumed endpoint is listed once)", () => {
    const keys = DASHBOARD_ENDPOINTS.map(({ group, endpoint }) => `${group}.${endpoint}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("declares every consumed cursor query in the endpoint's query schema (裁定 CB)", () => {
    // withCursor が付けるカーソル名が api-schema のクエリ Schema に宣言されて
    // いること: パラメータ名のリネームは「ページングが黙って無反応になる」で
    // なくここで割れる(サーバーは未知クエリを無視するため実行時エラーが出ない)
    for (const { group, endpoint, cursor } of DASHBOARD_ENDPOINTS) {
      if (cursor === undefined) continue;
      expect(
        queryKeys(requireEndpoint(group, endpoint)),
        `${group}.${endpoint} does not declare a "${cursor}" query parameter in api-schema`,
      ).toContain(cursor);
    }
  });

  it("appends the declared cursor name from inside the paged builders (裁定 CB)", () => {
    // 呼び出し側は名前に触れない(取り違えは構文上あり得ない)。ビルダーが
    // 実際に付ける名前をここで固定する: 期待値のリテラルは意図的
    // (ビルダー同士の同語反復を避ける)
    expect(apiPaths.projects("x")).toBe("/projects?after=x");
    expect(apiPaths.auditEvents(SAMPLE_PROJECT_ID, "y")).toBe(
      `/projects/${SAMPLE_PROJECT_ID}/audit/events?before=y`,
    );
    expect(apiPaths.auditInvites(SAMPLE_PROJECT_ID, "y")).toBe(
      `/projects/${SAMPLE_PROJECT_ID}/audit/invites?before=y`,
    );
    expect(apiPaths.auditSelf("y")).toBe("/auth/audit/events?before=y");
  });

  it("keeps path literals out of screen code (builders are the only source)", () => {
    // ソーストリップワイヤ(裁定 BY / CA): 目録の網羅性は「画面が使うパスは
    // すべてビルダー経由」(API = endpoints.ts、SPA = routes.ts)という規律に
    // 依存する。ここでは src/ 配下(両ビルダー置き場を除く)に API 前置・
    // /dashboard 前置のパスリテラルが現れないことを機械検査し、ビルダーを
    // 迂回する消費面の混入をドリフトとして落とす
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(
        srcRoot,
        /["']\/(auth|projects|invites|dashboard)\b/,
        new Set([BUILDER_API_MODULE, BUILDER_SPA_MODULE].map((p) => join(srcRoot, p))),
      ),
      "path literal outside the builder modules — use apiPaths (endpoints.ts) or spaPaths (routes.ts)",
    ).toEqual([]);
  });

  it("keeps effect / api-schema imports type-only in bundle sources (裁定 BR/CD)", () => {
    // 裁定 BR「Effect / Schema の実行コードをバンドル(= TCB)へ持ち込まない」は
    // 規約でしかなかった: 値 import はビルドも実行も黙って通り、バンドルと
    // 供給網だけが静かに太る。verbatimModuleSyntax の下では type-only import が
    // `import type` 構文で明示されるため、値 import の混入を機械検査できる
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(
        srcRoot,
        // サブパス import(effect/schema 等 — 本リポジトリの主流形)も対象。
        // 行頭アンカー(m): import 文はトップレベル宣言で行頭に現れる —
        // アンカーなしだとコメント中の語「import」から実 import 文の from 句
        // までを 1 マッチに繋げて誤検知する(api.ts の裁定 CN 注記コメントが
        // 最初の踏み抜き)。再 export(`export { X } from …` /
        // `export * from …`)も同じ実行コードをバンドルへ引き込むため対象
        /^(?:import|export)\s+(?!type\b)[^;]*?from\s*["'](?:effect|@maruhi\/api-schema)(?:\/[^"']*)?["']/m,
        new Set(),
      ),
      "value import of effect / @maruhi/api-schema in bundle source — use `import type` (裁定 BR)",
    ).toEqual([]);
  });

  it("keeps route() declarations inside the SPA route catalog (裁定 BZ/CA)", () => {
    // SPA_ROUTES の権威性は「route() の宣言は routes.ts のみ」という規律に
    // 依存する(App.tsx へのインライン route() は非交差スイープを黙って
    // 狭める)。bindRoute( は別名なので誤検知しない
    const srcRoot = join(import.meta.dirname, "../../src");
    expect(
      findSourceOffenders(srcRoot, /\broute\(/, new Set([join(srcRoot, BUILDER_SPA_MODULE)])),
      "route() declared outside src/dashboard/routes.ts — add it to the SPA_ROUTES catalog instead",
    ).toEqual([]);
  });
});

/** ビルダー置き場(トリップワイヤの除外対象)— 解決済みパスで一意に指す。 */
const BUILDER_API_MODULE = "dashboard/endpoints.ts";
const BUILDER_SPA_MODULE = "dashboard/routes.ts";

/** 登録エンドポイントの取得(不在は fail-loud — パス整合テストと同じ前提)。 */
function requireEndpoint(group: string, endpoint: string): RegisteredEndpoint {
  const registered = api.groups[group]?.endpoints[endpoint];
  if (registered === undefined) throw new Error(`${group}.${endpoint} is not registered`);
  return registered;
}

/** クエリ Schema の宣言プロパティ名(未宣言は空)。 */
function queryKeys(registered: RegisteredEndpoint): PropertyKey[] {
  return (registered.query?.ast?.propertySignatures ?? []).map((p) => p.name);
}

/**
 * トリップワイヤの走査対象: TS/TSX ソース(除外は解決済みパスで比較 —
 * ファイル名比較だと別ディレクトリの同名ファイルが黙って免除される)。
 */
function isSweepTarget(
  entry: { isFile(): boolean; name: string },
  filePath: string,
  excluded: ReadonlySet<string>,
): boolean {
  return entry.isFile() && /\.(ts|tsx)$/.test(entry.name) && !excluded.has(filePath);
}

/**
 * src/ 配下で pattern にかかるファイルを列挙する共通走査(excluded は
 * 解決済みパスの集合)。パスリテラル検査はダブル/シングルクォートの文字列
 * のみ対象 — バッククォートはコメント内のパス例(`/auth/me` 等)と衝突する
 * ため対象外で、迂回可能性は許容する(word-hash トリップワイヤと同じ
 * 「善意のドリフト検出」の位置づけ — session-41 BG)。
 */
function findSourceOffenders(
  srcRoot: string,
  pattern: RegExp,
  excluded: ReadonlySet<string>,
): string[] {
  const offenders: string[] = [];
  for (const entry of readdirSync(srcRoot, { recursive: true, withFileTypes: true })) {
    const filePath = join(entry.parentPath, entry.name);
    if (!isSweepTarget(entry, filePath, excluded)) continue;
    if (pattern.test(readFileSync(filePath, "utf8"))) {
      offenders.push(filePath.slice(srcRoot.length + 1));
    }
  }
  return offenders;
}

// ---------------------------------------------------------------------------
// 消費面の envelope 型のスイープ(DK K8-2 / K8-7)。
//
// 裁定 BR は「ダッシュボードのワイヤ型は api-schema の Schema からの導出だけで持つ」
// (types.ts)。手書きの写しは api-schema の改訂で黙って古くなる(K7-8 の上位互換)。
// 主張は 2 つで、どちらも件数を件数と比べる(数え直し不要)。対象が消えれば
// readFileSync / 件数 0 で落ちる(空虚に通らない)。type-only import の規律は上の
// 「keeps effect / api-schema imports type-only」が src/ 全体で持つので、ここでは
// 繰り返さない(主張は 1 か所 — K6-R)。
// ---------------------------------------------------------------------------

const TYPES_MODULE = "dashboard/types.ts";

/** コメントを落とした本文(ブロック / JSDoc / 行コメント)。 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
}

/**
 * `<` の直後から対応する `>` までの型引数(ネストした `<…>` / `{…}` を跨ぐ —
 * 正規表現 `[^<>]+` はネストで当たらず、手書きの envelope を見逃す)。
 */
function typeArgumentAt(source: string, start: number): string {
  let depth = 1;
  for (const bracket of source.slice(start).matchAll(/[<>]/g)) {
    depth += bracket[0] === "<" ? 1 : -1;
    if (depth === 0) return source.slice(start, start + bracket.index).trim();
  }
  throw new Error("unterminated type argument list");
}

describe("dashboard envelope types are derived from api-schema (DK K8)", () => {
  const srcRoot = join(import.meta.dirname, "../../src");
  const typesSource = stripComments(readFileSync(join(srcRoot, TYPES_MODULE), "utf8"));
  const exportedNames = [...typesSource.matchAll(/^export type (\w+)\b/gm)].map((m) => m[1]);

  it("keeps types.ts to `typeof XxxSchema.Type` derivations only (no interface, no literal)", () => {
    expect(typesSource.match(/^(?:export )?interface\s/gm), "hand-written interface").toBeNull();
    // 折り返し(oxfmt が `=` の後で改行しうる)を跨いで数える
    const derived = typesSource.match(/^export type \w+\s*=\s*typeof \w+Schema\.Type;/gm) ?? [];
    expect(exportedNames.length, "types.ts must export at least one type").toBeGreaterThan(0);
    expect(derived.length, "every exported type must be `typeof XxxSchema.Type`").toBe(
      exportedNames.length,
    );
  });

  it("names a types.ts export at every consumption site (no inline envelope in screens)", () => {
    // 消費面の入口(apiGet / useApiResource / ApiResult / ResourceState)の型引数を
    // 全 src/ から集め、どれも types.ts の export 名であることを要求する —
    // 検査の射程を types.ts の 1 ファイルから消費面全体へ広げる(pullfrog の指摘)
    const known = new Set(exportedNames);
    // 入口を宣言する 2 モジュール(`<T>` / `<void>`)と types.ts 自身は対象外
    const entranceModules = new Set(
      [TYPES_MODULE, "dashboard/api.ts", "dashboard/use-api-resource.ts"].map((p) =>
        join(srcRoot, p),
      ),
    );
    const sites: Array<{ file: string; typeArg: string }> = [];
    for (const entry of readdirSync(srcRoot, { recursive: true, withFileTypes: true })) {
      const filePath = join(entry.parentPath, entry.name);
      if (!isSweepTarget(entry, filePath, entranceModules)) continue;
      const source = stripComments(readFileSync(filePath, "utf8"));
      for (const match of source.matchAll(
        /\b(?:apiGet|useApiResource|ApiResult|ResourceState)</g,
      )) {
        sites.push({
          file: filePath.slice(srcRoot.length + 1),
          typeArg: typeArgumentAt(source, match.index + match[0].length),
        });
      }
    }
    expect(sites.length, "no consumption site found — the sweep pattern is stale").toBeGreaterThan(
      0,
    );
    const offenders = sites.filter((site) => !known.has(site.typeArg));
    expect(
      offenders,
      "consumption site whose type argument is not a types.ts export — derive it there",
    ).toEqual([]);
  });
});
