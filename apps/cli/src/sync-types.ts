// `maruhi sync` のドライバ 2 種(exec = sync-exec.ts / http = sync-http.ts)が
// 共有する宣言の型。プリセットの合成は sync-preset.ts。

/** Preset identifiers accepted by the sync config (`targets.<name>.preset`), in display order. */
export const PRESET_IDS = ["cloudflare-workers", "vercel", "netlify"] as const;

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
}

/** 設定で与えられたオプション(プリセットの宣言で検証済み)。 */
export type ResolvedOptions = Readonly<Record<string, string | boolean>>;

/** Value constraints the driver imposes on what it can carry. */
export interface ValueConstraints {
  /** 1 値の上限(バイト)。超えると拒否(切り詰めを黙って起こさない)。 */
  readonly maxBytes: number | null;
  /** 空の値を拒否する(空 stdin を「値なし」と読む CLI)。 */
  readonly nonEmpty: boolean;
  /** 末尾改行 1 つで終わる 1 行の値を拒否する(CLI が落としてしまう)。 */
  readonly refuseSingleLineTrailingNewline: boolean;
}
