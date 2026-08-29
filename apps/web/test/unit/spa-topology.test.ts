// SPA ルート空間と run_worker_first の非交差スイープ(裁定 BZ — session-43 §12)。
//
// 裁定 BO は「SPA は /dashboard 前置、API は /auth・/projects・/invites 前置」で
// 両空間を素に分離した。この分離の半分(API 側の被覆)はサーバー側の
// serving-topology.test.ts が検査するが、逆方向 —「SPA のルートが Worker に
// 飲まれない」— はこれまで手検証だった: run_worker_first に過剰な前置
// (例: `/*`)が入ると、SPA ルートへの navigation が Worker の 404 JSON に
// なって画面ごと消える。ここでは実ルート定義(SPA_ROUTES — App.tsx が
// bindRoute する唯一の目録)と実配信設定(apps/server/wrangler.jsonc)を
// そのまま突合し、非交差を fail-loud にする。
import { describe, expect, it } from "vitest";
import { unstable_readConfig } from "wrangler";

import { SAMPLE_PROJECT_ID } from "../../src/dashboard/endpoints.ts";
import { SPA_ROUTES, spaPaths } from "../../src/dashboard/routes.ts";

/** serving-topology.test.ts の ruleCovers と同じ意味論(完全一致 / 前置 + `*`)。 */
function ruleCovers(rule: string, path: string): boolean {
  if (rule.startsWith("!")) {
    throw new Error(
      `run_worker_first に負のルールがある: ${rule} — 非交差スイープの意味論を再裁定すること`,
    );
  }
  const starIndex = rule.indexOf("*");
  if (starIndex === -1) return rule === path;
  if (starIndex !== rule.length - 1) {
    throw new Error(
      `run_worker_first に中間ワイルドカードがある: ${rule} — 非交差スイープの意味論を再裁定すること`,
    );
  }
  return path.startsWith(rule.slice(0, -1));
}

/** ルートパスの `:param` をサンプル値で具体化する(navigation は常に具体パス)。 */
function samplePath(template: string): string {
  return template.replace(/:projectId/g, SAMPLE_PROJECT_ID);
}

describe("SPA route space vs run_worker_first (裁定 BZ)", () => {
  it("keeps every SPA route on the asset layer (never swallowed by the worker)", () => {
    const config = unstable_readConfig({
      config: new URL("../../../server/wrangler.jsonc", import.meta.url).pathname,
    });
    const rules = config.assets?.run_worker_first;
    expect(Array.isArray(rules), "assets.run_worker_first は文字列列挙でなければならない").toBe(
      true,
    );
    const ruleList = rules as string[];
    for (const spaRoute of SPA_ROUTES) {
      // 型上 path は省略可(pathless route)だが、SPA_ROUTES は全件パス付き
      expect(spaRoute.path, "every SPA route must declare a path").toBeDefined();
      const path = samplePath(spaRoute.path ?? "");
      expect(
        path.includes(":"),
        `route "${spaRoute.path}" has an unsubstituted param — extend samplePath`,
      ).toBe(false);
      const covering = ruleList.filter((rule) => ruleCovers(rule, path));
      expect(
        covering,
        `SPA route ${path} is covered by run_worker_first — navigation would hit the worker's 404`,
      ).toEqual([]);
    }
  });

  it("binds every spaPaths builder to a declared route (裁定 CA)", () => {
    // ビルダーとルート定義は routes.ts の同じ定数を読むが、ビルダーの追加が
    // SPA_ROUTES への登録(= 非交差スイープの対象化)を伴うことと、パラメータ
    // 置換が完全であること(:param の取りこぼしは実行時 404)をここで固定する
    const declaredPaths = new Set(SPA_ROUTES.map((r) => r.path));
    const built = [
      spaPaths.home(),
      spaPaths.about(),
      spaPaths.dashboard(),
      spaPaths.account(),
      spaPaths.project(SAMPLE_PROJECT_ID),
    ];
    for (const path of built) {
      expect(path.includes(":"), `builder output ${path} has an unsubstituted param`).toBe(false);
    }
    // project はサンプル置換後なのでテンプレート側を逆置換して突合する
    expect(declaredPaths.has(spaPaths.dashboard())).toBe(true);
    expect(declaredPaths.has(spaPaths.account())).toBe(true);
    expect(declaredPaths.has(spaPaths.home())).toBe(true);
    expect(declaredPaths.has(spaPaths.about())).toBe(true);
    expect(declaredPaths.has(spaPaths.project(":projectId"))).toBe(true);
  });
});
