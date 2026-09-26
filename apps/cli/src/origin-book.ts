// origin → user_id で鍵を切るローカルの帳ファイル(known-fingerprints.json・own-devices.json)の
// 共通の外枠のデコード。1 件でも不正なら全体を破損扱いにする(部分読みしない — pins と同じ)。

// レコードキー(origin / user_id)の規律: 先頭は英数字(pins.ts の招待 id と
// 同じく `__proto__` を構造的に排除)、空白を含まない。origin は正規化済みの
// URL(http(s)://…)、user_id はサーバー採番 — どちらも形式へは依存しない
export const BOOK_KEY = /^[A-Za-z0-9]\S{0,1023}$/;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * `{ v: version, known: { origin: users } }` をデコードする。`decodeUsers` は 1 origin 分
 * (user_id → 中身)を読み、不正なら null を返す。
 */
export function decodeOriginBook<Users>(
  json: string,
  version: number,
  decodeUsers: (value: unknown) => Users | null,
): Record<string, Users> | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== version || !isRecord(value["known"])) {
    return null;
  }
  const known: Record<string, Users> = {};
  for (const [origin, rawUsers] of Object.entries(value["known"])) {
    const users = BOOK_KEY.test(origin) ? decodeUsers(rawUsers) : null;
    if (users === null) {
      return null;
    }
    known[origin] = users;
  }
  return known;
}
