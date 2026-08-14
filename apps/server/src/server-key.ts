// デプロイメント keypair(CRYPTO_SPEC §9)の導出と公開情報の提供。
//
// Workers Secret `SERVER_ENC_KEY_IKM`(32 バイト hex)から RFC 9180
// DeriveKeyPair で X25519 keypair を導出し、公開面(enc 公開鍵 + サーバー鍵 FP =
// SHA-256(enc_pub)[:16])を `/auth/config` に載せる(AUTH_SPEC §4)。
//
// A1 の線引き: サーバーはリース経路でも値を復号しない(CRYPTO_SPEC §9.1)。
// A1 では復号経路自体を作らない — 秘密鍵はこのモジュールの導出クロージャ外へ
// 出さず、公開情報のみを保持する(A2 のリース実装が自分宛ラップの開封を足す
// ときに、ここへ Open 経路を拡張する)。
//
// secret 未設定は「選択的開示なしの純粋 E2EE デプロイメント」(正常な既定)。
// 形式不正(hex でない・長さ不正)も未設定として扱う — /auth/config から
// serverKeyFingerprintHex が消えるため、grant CLI 側が「サーバー鍵未設定」を
// 明示エラーにする(トラブルシュートは docs/SELF_HOSTING.md)。GitHub OAuth の
// 未設定(503 SetupIncomplete)と違い fail-closed にしないのは、サーバー鍵が
// 任意機能でありログイン経路を塞ぐ理由がないため。

import {
  computeServerKeyFingerprint,
  decodeHex,
  deriveEncryptionKeyPair,
  encodeHex,
  exportEncryptionPublicKey,
} from "@maruhi/crypto";
import { Context, Effect } from "effect";

const IKM_BYTES = 32;

/** デプロイメント keypair の公開面(/auth/config が配布する — AUTH_SPEC §4)。 */
export interface ServerKeyInfo {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
}

export interface ServerKeyShape {
  /** 設定済みなら公開面、未設定(または形式不正)なら null。 */
  readonly info: Effect.Effect<ServerKeyInfo | null>;
}

export class ServerKey extends Context.Service<ServerKey, ServerKeyShape>()("ServerKey") {}

async function deriveInfo(ikmHex: string | undefined): Promise<ServerKeyInfo | null> {
  if (ikmHex === undefined || ikmHex === "") {
    return null;
  }
  const ikm = decodeHex(ikmHex);
  if (ikm === null || ikm.length !== IKM_BYTES) {
    return null;
  }
  const pair = await deriveEncryptionKeyPair({ ikm });
  if (!pair.ok) {
    return null;
  }
  const publicKey = await exportEncryptionPublicKey(pair.value.publicKey);
  const fingerprint = await computeServerKeyFingerprint(publicKey);
  if (!fingerprint.ok) {
    return null;
  }
  return {
    serverEncPubHex: encodeHex(publicKey),
    serverKeyFingerprintHex: encodeHex(fingerprint.value),
  };
}

/**
 * worker 起動時に一度だけ構築するサービス(buildServices — index.ts)。導出は
 * 初回参照時に 1 回だけ行い、以後は isolate 内でキャッシュする(ikm は
 * クロージャに閉じ、導出結果の公開面だけを保持する)。
 */
export function makeServerKey(ikmHex: string | undefined): ServerKeyShape {
  let cached: Promise<ServerKeyInfo | null> | undefined;
  return {
    info: Effect.promise(() => {
      cached ??= deriveInfo(ikmHex);
      return cached;
    }),
  };
}
