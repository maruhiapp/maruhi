// 識別子・資格情報乱数の生成と照合(Web 標準 crypto のみ。Bun 固有 API 不使用)。
//
// ここにあるのは暗号プロトコルではなく ID / 乱数のエンコーディングのみ。
// 暗号操作(ハッシュ)は WebCrypto に委譲する(CLAUDE.md: 独自プリミティブ禁止)。

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * ULID(48-bit 時刻 + 80-bit 乱数、Crockford Base32、26 文字)。
 * AUTH_SPEC §2: 内部 user_id 等の主体識別子に使う。
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

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * 256-bit 乱数の Base62 表現(43 文字固定、AUTH_SPEC §6 のトークン本体)。
 */
export function randomBase62(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  let out = "";
  while (value > 0n) {
    out = BASE62[Number(value % 62n)] + out;
    value /= 62n;
  }
  return out.padStart(43, "0");
}

/** ランダム hex 文字列(`byteLength` バイト分)。セッション生値・OAuth state に使う。 */
export function randomHex(byteLength: number): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** SHA-256 の hex(小文字)。セッション / トークンの保存用ハッシュ(AUTH_SPEC §5 / §6)。 */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * タイミング安全な文字列比較(AUTH_SPEC §6)。長さが違っても全長を走査してから
 * 返す(比較対象はいずれも固定長ハッシュ hex)。
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < length; i += 1) {
    diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  }
  return diff === 0;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}
