// `maruhi sync` のドライバ 2 種(exec = sync-exec.ts / http = sync-http.ts)が
// 共有する宣言の型。プリセットの合成は sync-preset.ts。

/** Preset identifiers accepted by the sync config (`targets.<name>.preset`), in display order. */
export const PRESET_IDS = ["cloudflare-workers", "vercel", "netlify", "github-actions"] as const;

/** One of {@link PRESET_IDS}. */
export type PresetId = (typeof PRESET_IDS)[number];

/** Driver identifiers accepted by the sync config (`targets.<name>.driver`). */
export type DriverKind = "exec" | "http";

/** Declaration of one preset option (validated by sync-config.ts). */
export interface OptionSpec {
  readonly type: "string" | "boolean";
  readonly required: boolean;
  /** 閉集合(Vercel の環境名など)。 */
  readonly values?: readonly string[];
  /**
   * 文字列オプションの形(閉集合でないが argv や URL に載る値 — GitHub の
   * `OWNER/REPO` など)。`values` と併用しない。`hint` は拒否文面の「期待する形」。
   */
  readonly pattern?: { readonly regex: RegExp; readonly hint: string };
}

/** 設定で与えられたオプション(プリセットの宣言で検証済み)。 */
export type ResolvedOptions = Readonly<Record<string, string | boolean>>;

/**
 * What the target's stdin reader does with trailing newlines — the driver refuses the
 * values whose bytes it could not deliver unchanged:
 * - `kept`: nothing is stripped (wrangler's JSON, the http APIs)
 * - `strippedFromSingleLine`: one trailing newline goes from a single-line value only
 *   (Vercel CLI) → a single-line value ending in one newline is refused
 * - `stripped`: every trailing CR / LF goes, from any value (gh) → a value ending in
 *   a newline is refused
 */
export type TrailingNewlineHandling = "kept" | "strippedFromSingleLine" | "stripped";

/**
 * What the target accepts as a name. The maruhi name is sent unchanged, so a name the
 * target would rename or refuse is refused here first (before anything is sent).
 */
export interface NameConstraint {
  readonly regex: RegExp;
  /** 拒否文面に添える規則の説明(名前だけを運ぶ文の一部)。 */
  readonly rule: string;
}

/** Value constraints the driver imposes on what it can carry. */
export interface ValueConstraints {
  /** 1 値の上限(バイト)。超えると拒否(切り詰めを黙って起こさない)。 */
  readonly maxBytes: number | null;
  /** 空の値を拒否する(空 stdin を「値なし」と読む CLI)。 */
  readonly nonEmpty: boolean;
  /** 末尾改行の扱い(落とされる形の値を拒否する)。 */
  readonly trailingNewline: TrailingNewlineHandling;
  /** 名前の規則(無ければ `null` = maruhi の名前がそのまま通る)。 */
  readonly name: NameConstraint | null;
}
