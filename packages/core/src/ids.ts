// 識別子の生成(Web 標準 crypto のみ — Bun 固有 API 不使用。ブラウザ / Bun /
// workerd で動く)。暗号プロトコルではなく ID のエンコーディングだけを置く。

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * ULID(48-bit 時刻 + 80-bit 乱数、Crockford Base32、26 文字)。
 *
 * サーバーは主体識別子(AUTH_SPEC §2 の内部 user_id 等)に、クライアントは
 * master 鍵ラップ台帳の wrap_id / group_id(AUTH_SPEC §13-9 — AAD が id を
 * 束縛するため暗号化の前にクライアントが採番する)に使う。
 */
export function ulid(nowMs: number = Date.now()): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let time = "";
  let t = nowMs;
  for (let i = 0; i < 10; i += 1) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  let rand = "";
  for (let i = 0; i < 16; i += 1) {
    // 256 は 32 で割り切れるため mod にバイアスはない
    rand += CROCKFORD[(bytes[i] ?? 0) % 32];
  }
  return time + rand;
}
