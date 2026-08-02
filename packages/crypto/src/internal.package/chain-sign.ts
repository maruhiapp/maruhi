// CRYPTO_SPEC §6.1: チェーンエントリの Ed25519 署名。
// WebCrypto の Ed25519 は RFC 8032 の決定論的署名(テストベクターと一致する)。

import { encodeHex } from "./bytes.ts";
import { canonicalChainSignedBytes } from "./chain-canonical.ts";
import type { ChainEntry, UnsignedChainEntry } from "./chain-types.ts";
import type { CryptoResult } from "./errors.ts";

/**
 * Signs an unsigned chain entry with the actor's Ed25519 private key and
 * returns the complete entry. The signature covers the canonical signed
 * bytes (CRYPTO_SPEC §6.1).
 */
export async function signChainEntry(input: {
  readonly entry: UnsignedChainEntry;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<ChainEntry>> {
  if (!Number.isSafeInteger(input.entry.seq) || input.entry.seq < 1) {
    return { ok: false, error: { kind: "InvalidInput", field: "seq" } };
  }
  if (!Number.isSafeInteger(input.entry.timestampMs) || input.entry.timestampMs < 0) {
    return { ok: false, error: { kind: "InvalidInput", field: "timestampMs" } };
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        canonicalChainSignedBytes(input.entry) as BufferSource,
      ),
    );
    return { ok: true, value: { ...input.entry, signatureHex: encodeHex(signature) } };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}
