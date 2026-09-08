// `maruhi sync` のプリセット = 1 つの同期先に対する 2 種類のドライバの宣言
// (SY2 第 2 段 — integration-options.md §3 補足 13 W1「1 インターフェース × 2 種類」)。
//
// exec(sync-exec.ts — 導入済みのベンダー CLI)と http(sync-http.ts — ベンダー
// API)は同じプリセット id を共有し、設定の `driver` でどちらを使うかを選ぶ。
// レシートはプリセット id だけを持つので、ドライバを切り替えても前回の届き先の
// 記録はそのまま使える(同じ同期先に同じ名前・version を届けたという事実は
// ドライバに依らない)。
//
// 片方のドライバしか持てない同期先がある(SY4 の裁定 A): Netlify の CLI は値を
// 引数に取る(argv = `ps` で見える)ので exec の安全なレシピが書けず、http だけを
// 持つ。GitHub Actions secrets は逆に http を持てない(API はリポジトリ公開鍵への
// libsodium sealed box を要し、WebCrypto に無い — 補足 5。maruhi は封印を実装せず
// `gh` に任せる)。宣言の代わりに**理由**(`unavailable`)を置き、設定がその
// ドライバを選んだときの文面にする。`driver` を省いた設定は exec があれば exec、
// 無ければ http。

import { type ExecPreset, EXEC_PRESETS } from "./sync-exec.ts";
import { type HttpPreset, HTTP_PRESETS } from "./sync-http.ts";
import type { DriverKind, PresetId, ResolvedOptions } from "./sync-types.ts";

/** A driver the preset does not offer, with the reason shown to whoever configures it. */
export interface UnavailableDriver {
  readonly unavailable: string;
}

/** One deploy target kind: the same destination reachable through either driver. */
export interface SyncPreset {
  readonly id: PresetId;
  readonly exec: ExecPreset | UnavailableDriver;
  readonly http: HttpPreset | UnavailableDriver;
  /** 明示が無いときの production 判定(誤操作ガードの既定 — sync-config.ts)。 */
  readonly isProduction: (options: ResolvedOptions) => boolean;
}

/** 宣言が無い(理由だけの)ドライバか。 */
export function isUnavailable(
  declaration: ExecPreset | HttpPreset | UnavailableDriver,
): declaration is UnavailableDriver {
  return "unavailable" in declaration;
}

/** `driver` を省いた設定の既定: exec があれば exec、無ければ http。 */
export function defaultDriverOf(preset: SyncPreset): DriverKind {
  return isUnavailable(preset.exec) ? "http" : "exec";
}

// Netlify の deploy context のうち production 扱い(`all` は production を含む)
const NETLIFY_PRODUCTION_CONTEXTS = new Set(["production", "all"]);

/** Built-in presets (first-class targets — 2026-09-05 owner decision: Vercel / Cloudflare Workers; Netlify = SY4, http only; GitHub Actions secrets = SY5, exec only). */
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
  netlify: {
    id: "netlify",
    exec: {
      unavailable:
        "the netlify preset has no exec driver: the Netlify CLI takes the value as a command-line argument (visible in ps), so maruhi only talks to the Netlify API",
    },
    http: HTTP_PRESETS.netlify,
    isProduction: (options) => NETLIFY_PRODUCTION_CONTEXTS.has(String(options["context"])),
  },
  "github-actions": {
    id: "github-actions",
    exec: EXEC_PRESETS["github-actions"],
    http: {
      unavailable:
        "the github-actions preset has no http driver: the GitHub API takes the value sealed to the repository's public key with libsodium, which maruhi does not implement, so maruhi only drives the gh CLI",
    },
    // リポジトリ secrets(Environment なし)は全 workflow に効く = production 扱い。
    // Environment secrets はその名前が production のときだけ
    isProduction: (options) =>
      options["environment"] === undefined || options["environment"] === "production",
  },
};
