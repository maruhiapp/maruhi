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
  DASHBOARD_ENDPOINTS,
  SAMPLE_ENVIRONMENT_ID,
  SAMPLE_PROJECT_ID,
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
    .replace(/:environmentId/g, SAMPLE_ENVIRONMENT_ID);
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

  it("keeps route() declarations inside the SPA route catalog (裁定 BZ/CA)", () => {
    // SPA_ROUTES の権威性は「route() の宣言は routes.ts のみ」という規律に
    // 依存する(App.tsx へのインライン route() は非交差スイープを黙って
    // 狭める — PR #107 pullfrog 指摘)。bindRoute( は別名なので誤検知しない
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
