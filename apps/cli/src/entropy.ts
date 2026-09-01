// スキーマ欄への実値混入(発見 D)の書き込み時クライアント検査(裁定 CW —
// fail-closed)。`maruhi schema set`(将来は schema import — S4)の name /
// description 入力に「秘密らしき高エントロピー部分文字列」を検出したら、
// 対話環境では警告 + 明示確認、非対話環境では明示フラグなしに型付きエラーで
// 拒否する。メタは平文でサーバー可視であり、実値の混入はゼロ知識の約束に
// ユーザー形の穴を開ける。
//
// 検出器・閾値は実装詳細(仕様が固定するのは要件と失敗方向のみ — 設計文書
// §1-2)。ここでは detect-secrets 系の定番ヒューリスティクスを採る:
//   - hex トークン(32 文字以上)の Shannon エントロピー ≥ 3.0
//   - 混在文字クラス(数字 + 大小文字、または数字 + base64 記号)の長い
//     トークン(20 文字以上)の Shannon エントロピー ≥ 3.5
// 誤検出は「確認 1 回 / 明示フラグ 1 個」のコスト、見逃しは平文メタへの実値
// 混入なので、閾値は検出側に倒す(fail-closed の失敗方向)。
//
// 検出結果に**入力そのものを含めない**: 呼び出し側のメッセージが端末・ログへ
// 流れるため、疑わしい値(= 秘密でありうる)を運ばない。位置と長さのみ返す。

/** 1 件の検出(値そのものは運ばない — 長さと種別のみ)。 */
export interface EntropyFinding {
  /** 検出した部分文字列の長さ(文字数)。 */
  readonly length: number;
  /** 検出根拠(hex = 長い hex 列、mixed = 混在文字クラスの高エントロピー列)。 */
  readonly kind: "hex" | "mixed";
}

/** トークン分割: 秘密値に現れる文字クラスの連(base64 / hex / URL-safe)。 */
const TOKEN_PATTERN = /[A-Za-z0-9+/=_-]+/g;

const HEX_TOKEN = /^[0-9a-fA-F]+$/;
const MIN_HEX_LENGTH = 32;
const MIN_MIXED_LENGTH = 20;
const HEX_ENTROPY_THRESHOLD = 3.0;
const MIXED_ENTROPY_THRESHOLD = 3.5;

/** 文字単位の Shannon エントロピー(bits/char)。 */
function shannonEntropyPerChar(token: string): number {
  const counts = new Map<string, number>();
  for (const char of token) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  const length = [...token].length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// 混在文字クラスの判定: 乱数トークン(API キー・base64 秘密)は「数字 +
// 大小文字の混在」か「数字 + base64 記号(+ / =)」をほぼ必ず含む。逆に
// 識別子的な正当入力(DATABASE_URL・camelCase 名・英文)はどちらも満たし
// にくい(大文字のみ + 数字、記号なし等)
function isMixedCharsetToken(token: string): boolean {
  const hasDigit = /\d/.test(token);
  if (!hasDigit) {
    return false;
  }
  const hasLower = /[a-z]/.test(token);
  const hasUpper = /[A-Z]/.test(token);
  const hasBase64Symbol = /[+/=]/.test(token);
  return (hasLower && hasUpper) || hasBase64Symbol;
}

function tokenFinding(token: string): EntropyFinding | null {
  // base64 パディングはエントロピーを下げるだけなので判定前に落とす
  const trimmed = token.replace(/=+$/, "");
  if (HEX_TOKEN.test(trimmed) && trimmed.length >= MIN_HEX_LENGTH) {
    if (shannonEntropyPerChar(trimmed.toLowerCase()) >= HEX_ENTROPY_THRESHOLD) {
      return { length: trimmed.length, kind: "hex" };
    }
    return null;
  }
  if (trimmed.length >= MIN_MIXED_LENGTH && isMixedCharsetToken(trimmed)) {
    if (shannonEntropyPerChar(trimmed) >= MIXED_ENTROPY_THRESHOLD) {
      return { length: trimmed.length, kind: "mixed" };
    }
  }
  return null;
}

/**
 * Scans free-form input (a schema-set name or description) for secret-like
 * high-entropy substrings (裁定 CW). Returns the first finding, or null.
 * The finding never carries the matched text — only its length and kind —
 * so callers can build messages without echoing a possible secret.
 */
export function findHighEntropySubstring(text: string): EntropyFinding | null {
  for (const match of text.matchAll(TOKEN_PATTERN)) {
    const finding = tokenFinding(match[0]);
    if (finding !== null) {
      return finding;
    }
  }
  return null;
}
