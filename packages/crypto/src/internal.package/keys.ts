// CRYPTO_SPEC §3: 鍵階層 — user master keypair(enc: X25519 / sig: Ed25519)、
// 鍵フィンガープリント、Environment Epoch DEK(256-bit 乱数)。
//
// enc 鍵は panva hpke の API で生成・変換する(HPKE Open の KeyPair 渡し経路と
// 確実に整合させるため)。sig 鍵は WebCrypto Ed25519。
// 秘密鍵は既定で非抽出(extractable=false)。エクスポートが必要な生成時のみ
// 呼び出し側が明示的に extractable=true を指定する。

import type { Key, KeyPair } from "hpke";

import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { hpkeSuite } from "./hpke.ts";

/** An X25519 key usable with the HPKE suite (CryptoKey-compatible, opaque). */
export type EncryptionKey = Key;

/** An X25519 key pair. HPKE Open requires the full pair (CRYPTO_SPEC §2). */
export type EncryptionKeyPair = KeyPair;

/** An Ed25519 WebCrypto key pair used for membership log signatures. */
export type SigningKeyPair = CryptoKeyPair;

const X25519_KEY_BYTES = 32;
const ED25519_KEY_BYTES = 32;
const DEK_BYTES = 32;
const FINGERPRINT_BYTES = 16;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/**
 * Generates a user encryption key pair (X25519, for receiving HPKE-wrapped
 * DEKs). The private key is non-extractable unless `extractable` is set —
 * pass true only when the key must be serialized (e.g. into the recovery
 * blob at signup).
 */
export async function generateEncryptionKeyPair(options?: {
  readonly extractable?: boolean;
}): Promise<EncryptionKeyPair> {
  return hpkeSuite().GenerateKeyPair(options?.extractable ?? false);
}

/**
 * Derives an encryption key pair deterministically from 32 bytes of input
 * keying material (RFC 9180 `DeriveKeyPair` — a standard HPKE API, verified
 * against the RFC 9180 official vectors in this package's tests). Used for
 * the deployment server key (CRYPTO_SPEC §9): the Workers Secret stores the
 * ikm and the keypair is re-derived at startup, so a single 32-byte secret
 * yields both keys. The private key stays non-extractable unless requested.
 */
export async function deriveEncryptionKeyPair(input: {
  readonly ikm: Uint8Array;
  readonly extractable?: boolean;
}): Promise<CryptoResult<EncryptionKeyPair>> {
  if (input.ikm.length !== X25519_KEY_BYTES) {
    return invalidInput("encryption key ikm length");
  }
  try {
    const pair = await hpkeSuite().DeriveKeyPair(input.ikm, input.extractable ?? false);
    return { ok: true, value: pair };
  } catch {
    return { ok: false, error: { kind: "KeyImportFailed", key: "encryption-private" } };
  }
}

/** Generates a user signing key pair (Ed25519, for membership log entries). */
export async function generateSigningKeyPair(options?: {
  readonly extractable?: boolean;
}): Promise<SigningKeyPair> {
  const pair = await crypto.subtle.generateKey("Ed25519", options?.extractable ?? false, [
    "sign",
    "verify",
  ]);
  // Ed25519 の generateKey は CryptoKeyPair を返す(型定義上の union を絞る)
  return pair as CryptoKeyPair;
}

/** Serializes an encryption public key to its 32-byte raw form. */
export async function exportEncryptionPublicKey(key: EncryptionKey): Promise<Uint8Array> {
  return hpkeSuite().SerializePublicKey(key);
}

/** Deserializes a 32-byte raw X25519 public key. */
export async function importEncryptionPublicKey(
  publicKey: Uint8Array,
): Promise<CryptoResult<EncryptionKey>> {
  if (publicKey.length !== X25519_KEY_BYTES) {
    return invalidInput("encryption public key length");
  }
  try {
    return { ok: true, value: await hpkeSuite().DeserializePublicKey(publicKey) };
  } catch {
    return { ok: false, error: { kind: "KeyImportFailed", key: "encryption-public" } };
  }
}

/**
 * Imports an encryption key pair from raw 32-byte keys. The private key is
 * imported non-extractable unless `extractable` is set. HPKE Open takes the
 * full pair, so the non-extractable path stays usable (CRYPTO_SPEC §2).
 */
export async function importEncryptionKeyPair(input: {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly extractable?: boolean;
}): Promise<CryptoResult<EncryptionKeyPair>> {
  if (input.publicKey.length !== X25519_KEY_BYTES) {
    return invalidInput("encryption public key length");
  }
  if (input.privateKey.length !== X25519_KEY_BYTES) {
    return invalidInput("encryption private key length");
  }
  try {
    const suite = hpkeSuite();
    const privateKey = await suite.DeserializePrivateKey(
      input.privateKey,
      input.extractable ?? false,
    );
    const publicKey = await suite.DeserializePublicKey(input.publicKey);
    return { ok: true, value: { publicKey, privateKey } };
  } catch {
    return { ok: false, error: { kind: "KeyImportFailed", key: "encryption-private" } };
  }
}

/**
 * Serializes an extractable X25519 private key to its 32-byte raw form
 * (the inverse of `importEncryptionKeyPair`). Only for persisting a freshly
 * generated master key into the OS keychain (CRYPTO_SPEC §3) — keys imported
 * for use stay non-extractable and fail here with `KeyExportFailed`.
 */
export async function exportEncryptionPrivateKey(
  key: EncryptionKey,
): Promise<CryptoResult<Uint8Array>> {
  try {
    const raw = await hpkeSuite().SerializePrivateKey(key);
    if (raw.length !== X25519_KEY_BYTES) {
      return { ok: false, error: { kind: "KeyExportFailed", key: "encryption-private" } };
    }
    return { ok: true, value: raw };
  } catch {
    return { ok: false, error: { kind: "KeyExportFailed", key: "encryption-private" } };
  }
}

/** Serializes a signing public key to its 32-byte raw form. */
export async function exportSigningPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

/** Imports a 32-byte raw Ed25519 public key (verify-only). */
export async function importSigningPublicKey(
  publicKey: Uint8Array,
): Promise<CryptoResult<CryptoKey>> {
  if (publicKey.length !== ED25519_KEY_BYTES) {
    return invalidInput("signing public key length");
  }
  try {
    const key = await crypto.subtle.importKey("raw", publicKey as BufferSource, "Ed25519", true, [
      "verify",
    ]);
    return { ok: true, value: key };
  } catch {
    return { ok: false, error: { kind: "KeyImportFailed", key: "signing-public" } };
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array | null {
  try {
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Serializes an extractable Ed25519 private key to its 32-byte RFC 8032 seed
 * (the inverse of `importSigningKeyPair`). WebCrypto has no raw export for
 * Ed25519 private keys, so the seed is read from the standard JWK (OKP) `d`
 * field. Only for persisting a freshly generated master key into the OS
 * keychain (CRYPTO_SPEC §3) — non-extractable keys fail with `KeyExportFailed`.
 */
export async function exportSigningPrivateSeed(key: CryptoKey): Promise<CryptoResult<Uint8Array>> {
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const seed = typeof jwk.d === "string" ? base64UrlDecode(jwk.d) : null;
    if (seed === null || seed.length !== ED25519_KEY_BYTES) {
      return { ok: false, error: { kind: "KeyExportFailed", key: "signing-private" } };
    }
    return { ok: true, value: seed };
  } catch {
    return { ok: false, error: { kind: "KeyExportFailed", key: "signing-private" } };
  }
}

/**
 * Imports a signing key pair from the raw 32-byte public key and the 32-byte
 * private seed (RFC 8032 form). WebCrypto has no raw import for Ed25519
 * private keys, so the seed goes through the standard JWK (OKP) form.
 */
export async function importSigningKeyPair(input: {
  readonly publicKey: Uint8Array;
  readonly privateSeed: Uint8Array;
  readonly extractable?: boolean;
}): Promise<CryptoResult<SigningKeyPair>> {
  if (input.publicKey.length !== ED25519_KEY_BYTES) {
    return invalidInput("signing public key length");
  }
  if (input.privateSeed.length !== ED25519_KEY_BYTES) {
    return invalidInput("signing private seed length");
  }
  const publicKey = await importSigningPublicKey(input.publicKey);
  if (!publicKey.ok) {
    return publicKey;
  }
  try {
    const jwk: JsonWebKey = {
      kty: "OKP",
      crv: "Ed25519",
      x: base64UrlEncode(input.publicKey),
      d: base64UrlEncode(input.privateSeed),
    };
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      "Ed25519",
      input.extractable ?? false,
      ["sign"],
    );
    return { ok: true, value: { publicKey: publicKey.value, privateKey } };
  } catch {
    return { ok: false, error: { kind: "KeyImportFailed", key: "signing-private" } };
  }
}

/**
 * Computes a user key fingerprint: first 16 bytes of
 * `SHA-256(enc_pub(32B) || sig_pub(32B))` (CRYPTO_SPEC §3). Both keys are
 * fixed-length, so this is plain concatenation (the §2.1 length-prefixed
 * encoding applies to AADs / info strings / canonical byte strings).
 */
export async function computeUserKeyFingerprint(
  encPublicKey: Uint8Array,
  sigPublicKey: Uint8Array,
): Promise<CryptoResult<Uint8Array>> {
  if (encPublicKey.length !== X25519_KEY_BYTES) {
    return invalidInput("encryption public key length");
  }
  if (sigPublicKey.length !== ED25519_KEY_BYTES) {
    return invalidInput("signing public key length");
  }
  const concatenated = new Uint8Array(encPublicKey.length + sigPublicKey.length);
  concatenated.set(encPublicKey, 0);
  concatenated.set(sigPublicKey, encPublicKey.length);
  const digest = await sha256(concatenated);
  return { ok: true, value: digest.slice(0, FINGERPRINT_BYTES) };
}

/**
 * Computes a server (deployment) key fingerprint: first 16 bytes of
 * `SHA-256(server_enc_pub(32B))`. The server holds only an X25519 encryption
 * key (CRYPTO_SPEC §9), so the user fingerprint definition (enc || sig) does
 * not apply. Fixed by test-vectors/chain-entries.json.
 */
export async function computeServerKeyFingerprint(
  serverEncPublicKey: Uint8Array,
): Promise<CryptoResult<Uint8Array>> {
  if (serverEncPublicKey.length !== X25519_KEY_BYTES) {
    return invalidInput("server encryption public key length");
  }
  const digest = await sha256(serverEncPublicKey);
  return { ok: true, value: digest.slice(0, FINGERPRINT_BYTES) };
}

/** Generates a fresh 256-bit Environment Epoch DEK (CRYPTO_SPEC §3). */
export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(DEK_BYTES));
}
