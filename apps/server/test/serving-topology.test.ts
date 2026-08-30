// 配信トポロジ(W2 裁定 BM — docs/notes/session-43.md)の被覆スイープ。
//
// maruhi-server は web アセットを同一 Worker から配信し、API のパス空間を
// wrangler.jsonc の `assets.run_worker_first` で Worker 側へ固定する。この列挙は
// api-schema のパス空間の手書き複製であり、ドリフトは**無音で壊れる**:
// compatibility_date 2026-07-01 では navigation リクエストがアセット配信を優先
// (assets_navigation_prefers_asset_serving)するため、列挙漏れのエンドポイントは
// SPA シェルの 200 に飲まれてエラーにも記録にも現れない(本 PR 自身が
// /invites/accept でこのドリフトを 1 度踏んだ — session-43 §9 の欠陥修正。
// PR #107 pullfrog レビューの提案による検査化)。
//
// そこで session-capability.ts のスイープと同じ型で、登録済み HttpApi の全
// エンドポイントパスが run_worker_first のいずれかのルールに被覆されることを
// テスト時に検査する。新設エンドポイントが新しい前置を導入したら、この
// テストが落ちて wrangler.jsonc への追加を強制する(fail-loud)。
import { maruhiApi } from "@maruhi/api-schema";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

/** 検査対象の構造スライス(session-capability.ts の SweepableApi と同じ理由の構造型)。 */
interface PathedApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: { readonly path: string };
      };
    };
  };
}

/** 登録済み全エンドポイントの (識別子, パス) を列挙する。 */
function listEndpointPaths(api: PathedApi): Array<{ key: string; path: string }> {
  return Object.entries(api.groups).flatMap(([groupName, group]) =>
    Object.entries(group.endpoints).map(([endpointName, endpoint]) => ({
      key: `${groupName}.${endpointName}`,
      path: endpoint.path,
    })),
  );
}

/**
 * run_worker_first の 1 ルールがパスを被覆するか。Workers Static Assets の
 * ルールは glob(`*` = 任意の続き)で、本リポジトリでは「完全一致」と
 * 「前置 + `*`」だけを使う。それ以外の形(中間 `*`・負のルール)が現れたら
 * 検査を保守的に落とし、このテストの改訂を強制する。
 */
function ruleCovers(rule: string, path: string): boolean {
  if (rule.startsWith("!")) {
    throw new Error(
      `run_worker_first に負のルールがある: ${rule} — 被覆スイープの意味論を再裁定すること`,
    );
  }
  const starIndex = rule.indexOf("*");
  if (starIndex === -1) return rule === path;
  if (starIndex !== rule.length - 1) {
    throw new Error(
      `run_worker_first に中間ワイルドカードがある: ${rule} — 被覆スイープの意味論を再裁定すること`,
    );
  }
  return path.startsWith(rule.slice(0, -1));
}

describe("serving topology (W2 裁定 BM): run_worker_first covers the whole API path space", () => {
  it("routes every registered HttpApi endpoint to the worker, never the asset layer", () => {
    const rules = env.TEST_RUN_WORKER_FIRST;
    // 列挙形のみを正とする: true(全 Worker)は /invite ほか全アセットの配信を
    // 壊し、欠落は API 全面が SPA フォールバックへ落ちる — どちらも不成立
    expect(Array.isArray(rules), "assets.run_worker_first は文字列列挙でなければならない").toBe(
      true,
    );
    const ruleList = rules as string[];
    const uncovered = listEndpointPaths(maruhiApi as unknown as PathedApi).filter(
      ({ path }) => !ruleList.some((rule) => ruleCovers(rule, path)),
    );
    expect(
      uncovered,
      "api-schema のエンドポイントが run_worker_first に被覆されていない — " +
        "navigation リクエストが SPA シェルの 200 に無音で飲まれる(session-43 §9)。" +
        "apps/server/wrangler.jsonc の assets.run_worker_first へ前置を追加すること",
    ).toEqual([]);
  });

  it("keeps the static / SPA route space outside the worker-first rules (regression guard)", () => {
    // /invite(静的案内ページ — AUTH_SPEC §15-3)と SPA のルート空間(/dashboard
    // 前置 — 裁定 BO)がアセット層のまま配信されること: run_worker_first が
    // 過剰前置(例: /inv*・/*)でこれらを飲む形を将来の編集から守る
    const rules = env.TEST_RUN_WORKER_FIRST;
    expect(Array.isArray(rules)).toBe(true);
    const ruleList = rules as string[];
    for (const path of [
      "/invite",
      "/dashboard",
      `/dashboard/projects/${"ab".repeat(32)}`,
      "/dashboard/account",
    ]) {
      expect(
        ruleList.some((rule) => ruleCovers(rule, path)),
        `${path} must stay on the asset layer`,
      ).toBe(false);
    }
  });
});
