import { encodeHex } from "./bytes.ts";
import { canonicalChainSignedBytes } from "./chain-canonical.ts";
import type { ChainEntry, UnsignedChainEntry } from "./chain-types.ts";
import type { CryptoResult } from "./errors.ts";

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
