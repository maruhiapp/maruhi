// 非機密の JSON 文書(リポジトリアンカー・sync 設定・同期レシート)の共通の
// 入口: JSON として読めるか・最上位がオブジェクトか。理由は英語の短い文字列で
// 返し、呼び出し側が「どのファイルが・なぜ」を添える(内容そのものは文面に
// 出さない)。

/** Parses `content` as a JSON object; returns the reason when it is not one. */
export function parseJsonRecord(content: string): Record<string, unknown> | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return "not valid JSON";
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return "the top level must be an object";
  }
  return parsed as Record<string, unknown>;
}
