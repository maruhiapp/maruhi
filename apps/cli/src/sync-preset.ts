// `maruhi sync` のプリセット = 1 つの同期先に対する 2 種類のドライバの宣言
// (SY2 第 2 段 — integration-options.md §3 補足 13 W1「1 インターフェース × 2 種類」)。
//
// exec(sync-exec.ts — 導入済みのベンダー CLI)と http(sync-http.ts — ベンダー
// API)は同じプリセット id を共有し、設定の `driver` でどちらを使うかを選ぶ。
// レシートはプリセット id だけを持つので、ドライバを切り替えても前回の届き先の
// 記録はそのまま使える(同じ同期先に同じ名前・version を届けたという事実は
// ドライバに依らない)。

import { type ExecPreset, EXEC_PRESETS } from "./sync-exec.ts";
import { type HttpPreset, HTTP_PRESETS } from "./sync-http.ts";
import type { PresetId, ResolvedOptions } from "./sync-types.ts";

/** One deploy target kind: the same destination reachable through either driver. */
export interface SyncPreset {
  readonly id: PresetId;
  readonly exec: ExecPreset;
  readonly http: HttpPreset;
  /** 明示が無いときの production 判定(誤操作ガードの既定 — sync-config.ts)。 */
  readonly isProduction: (options: ResolvedOptions) => boolean;
}

/** Built-in presets (first-class targets — 2026-09-05 owner decision: Vercel / Cloudflare Workers). */
export const SYNC_PRESETS: Readonly<Record<PresetId, SyncPreset>> = {
  "cloudflare-workers": {
    id: "cloudflare-workers",
    exec: EXEC_PRESETS["cloudflare-workers"],
    http: HTTP_PRESETS["cloudflare-workers"],
    // wrangler の名前付き環境なし = トップレベルの Worker(本番)
    isProduction: (options) => options["environment"] === undefined,
  },
  vercel: {
    id: "vercel",
    exec: EXEC_PRESETS.vercel,
    http: HTTP_PRESETS.vercel,
    isProduction: (options) => options["environment"] === "production",
  },
};
