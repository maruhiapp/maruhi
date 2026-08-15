// ワークロードリース(AUTH_SPEC §14)のテストヘルパ。
//
// - OIDC トークンの組み立てと ES256 署名(鍵は support/oidc-issuer.ts の
//   ダミー。outboundService が同じ鍵の JWKS を配信する)
// - デプロイメント keypair(vitest.config.ts の SERVER_ENC_KEY_IKM から
//   実際に導出する)。テストは「サーバーが自分宛ラップを本当に開封できる」
//   ところまで検査するため、ダミー公開鍵ではなく実導出鍵を使う
//
// 鍵素材はすべてテスト専用の使い捨てダミーであり、実環境では使われない。

import {
  computeServerKeyFingerprint,
  deriveEncryptionKeyPair,
  encodeHex,
  exportEncryptionPublicKey,
} from "@maruhi/crypto";

import { OIDC_ISSUER, OIDC_KID, OIDC_PRIVATE_JWK } from "./oidc-issuer.ts";

/** リースのテストで使う既定の audience(デプロイメントの origin を模す)。 */
export const LEASE_AUDIENCE = "https://maruhi.test";

/** 既定の subject(GitHub Actions の `sub` claim 形式)。 */
export const LEASE_SUBJECT = "repo:maruhi-test/demo:ref:refs/heads/main";

export interface DeploymentKey {
  readonly encPubHex: string;
  readonly fingerprintHex: string;
}

let cachedKey: DeploymentKey | undefined;

/**
 * SERVER_ENC_KEY_IKM から実際に導出したデプロイメント鍵の公開面。サーバーが
 * `server-key.ts` で導出するものと同一(RFC 9180 DeriveKeyPair は決定論的)。
 */
export async function deploymentKey(): Promise<DeploymentKey> {
  if (cachedKey !== undefined) {
    return cachedKey;
  }
  // vitest.config.ts の miniflare bindings の SERVER_ENC_KEY_IKM("b0" × 32)と同値
  const ikm = Uint8Array.from({ length: 32 }, () => 0xb0);
  const pair = await deriveEncryptionKeyPair({ ikm });
  if (!pair.ok) {
    throw new Error("deployment key derivation failed");
  }
  const publicKey = await exportEncryptionPublicKey(pair.value.publicKey);
  const fingerprint = await computeServerKeyFingerprint(publicKey);
  if (!fingerprint.ok) {
    throw new Error("deployment key fingerprint failed");
  }
  cachedKey = {
    encPubHex: encodeHex(publicKey),
    fingerprintHex: encodeHex(fingerprint.value),
  };
  return cachedKey;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

const encodeSegment = (value: unknown): string =>
  base64Url(new TextEncoder().encode(JSON.stringify(value)));

export interface TokenOptions {
  readonly issuer?: string;
  readonly subject?: string;
  readonly audience?: string | readonly string[];
  /** 追加 claim(claim 制約の一致・不一致を作るため)。 */
  readonly claims?: Readonly<Record<string, unknown>>;
  readonly expSeconds?: number;
  readonly iatSeconds?: number;
  readonly alg?: string;
  readonly kid?: string | null;
  /** true なら署名を 1 バイト改竄する(signature-invalid の検査用)。 */
  readonly tamperSignature?: boolean;
  /** exp / iat を省く(missing-claim の検査用)。 */
  readonly omit?: readonly string[];
}

/**
 * ES256 の OIDC トークンを組み立てて署名する。`alg` / `kid` を差し替えられる
 * のは、許可リスト外 alg・未知 kid の拒否を実経路で検査するため(ヘッダーだけ
 * 差し替えても署名鍵は同じ = 「ヘッダーの alg を信じる実装」なら通ってしまう
 * 形を作れる)。
 */
export async function makeOidcToken(options: TokenOptions = {}): Promise<string> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const header = {
    alg: options.alg ?? "ES256",
    typ: "JWT",
    ...(options.kid === null ? {} : { kid: options.kid ?? OIDC_KID }),
  };
  const omit = new Set(options.omit ?? []);
  const claims: Record<string, unknown> = {
    iss: options.issuer ?? OIDC_ISSUER,
    sub: options.subject ?? LEASE_SUBJECT,
    aud: options.audience ?? LEASE_AUDIENCE,
    ...(omit.has("exp") ? {} : { exp: options.expSeconds ?? nowSeconds + 300 }),
    ...(omit.has("iat") ? {} : { iat: options.iatSeconds ?? nowSeconds - 5 }),
    ...options.claims,
  };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    OIDC_PRIVATE_JWK as unknown as JsonWebKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      new TextEncoder().encode(signingInput),
    ),
  );
  if (options.tamperSignature === true) {
    signature[0] = (signature[0] ?? 0) ^ 0x01;
  }
  return `${signingInput}.${base64Url(signature)}`;
}
