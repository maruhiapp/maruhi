import type { Key, KeyPair } from "hpke";

import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { hpkeSuite } from "./hpke.ts";

export type EncryptionKey = Key;

export type EncryptionKeyPair = KeyPair;

export type SigningKeyPair = CryptoKeyPair;

const X25519_KEY_BYTES = 32;
const ED25519_KEY_BYTES = 32;
const DEK_BYTES = 32;
const FINGERPRINT_BYTES = 16;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

export async function generateEncryptionKeyPair(options?: {
  readonly extractable?: boolean;
}): Promise<EncryptionKeyPair> {
  return hpkeSuite().GenerateKeyPair(options?.extractable ?? false);
}

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

export async function generateSigningKeyPair(options?: {
  readonly extractable?: boolean;
}): Promise<SigningKeyPair> {
  const pair = await crypto.subtle.generateKey("Ed25519", options?.extractable ?? false, [
    "sign",
    "verify",
  ]);
  return pair as CryptoKeyPair;
}

export async function exportEncryptionPublicKey(key: EncryptionKey): Promise<Uint8Array> {
  return hpkeSuite().SerializePublicKey(key);
}

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

export async function exportSigningPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

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

export async function computeServerKeyFingerprint(
  serverEncPublicKey: Uint8Array,
): Promise<CryptoResult<Uint8Array>> {
  if (serverEncPublicKey.length !== X25519_KEY_BYTES) {
    return invalidInput("server encryption public key length");
  }
  const digest = await sha256(serverEncPublicKey);
  return { ok: true, value: digest.slice(0, FINGERPRINT_BYTES) };
}

export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(DEK_BYTES));
}
