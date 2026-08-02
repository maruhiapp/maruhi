import type { CryptoError, CryptoResult } from "@maruhi/crypto";
import { verifyChain } from "@maruhi/crypto";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import {
  ChainInvalidError,
  CryptoDecryptError,
  CryptoDekUnwrapError,
  CryptoDekWrapError,
  cryptoEffect,
  CryptoEncryptError,
  CryptoInvalidInputError,
  CryptoKeyImportError,
  CryptoSignError,
  fromCryptoResult,
  isProjectId,
  toWrappedCryptoError,
  type WrappedCryptoError,
} from "../src/index.ts";

// CryptoError の全 kind とマッピング先クラスの対応(判別子は crypto 側 kind →
// Effect 側タグ付きエラー。セッション 04 裁定 (b) の帰結)
const KIND_TO_CLASS: readonly [
  CryptoError,
  abstract new (...args: never[]) => WrappedCryptoError,
][] = [
  [{ kind: "InvalidInput", field: "nonce" }, CryptoInvalidInputError],
  [{ kind: "KeyImportFailed", key: "signing-public" }, CryptoKeyImportError],
  [{ kind: "EncryptFailed", operation: "variable" }, CryptoEncryptError],
  [{ kind: "DecryptFailed", operation: "recovery" }, CryptoDecryptError],
  [{ kind: "DekWrapFailed" }, CryptoDekWrapError],
  [{ kind: "DekUnwrapFailed" }, CryptoDekUnwrapError],
  [{ kind: "SignFailed" }, CryptoSignError],
  [{ kind: "ChainInvalid", seq: 3, reason: "bad-signature" }, ChainInvalidError],
];

describe("toWrappedCryptoError", () => {
  it("maps every CryptoError kind onto its tagged counterpart", () => {
    for (const [error, expectedClass] of KIND_TO_CLASS) {
      expect(toWrappedCryptoError(error)).toBeInstanceOf(expectedClass);
    }
  });

  it("preserves the identifying context of a chain failure", () => {
    const wrapped = toWrappedCryptoError({
      kind: "ChainInvalid",
      seq: 7,
      reason: "epoch-out-of-sequence",
    });
    expect(wrapped).toBeInstanceOf(ChainInvalidError);
    if (wrapped instanceof ChainInvalidError) {
      expect(wrapped.seq).toBe(7);
      expect(wrapped.reason).toBe("epoch-out-of-sequence");
    }
  });
});

describe("fromCryptoResult", () => {
  it("succeeds with the value of an ok result", async () => {
    const result: CryptoResult<number> = { ok: true, value: 42 };
    await expect(Effect.runPromise(fromCryptoResult(result))).resolves.toBe(42);
  });

  it("fails with the mapped tagged error of an error result", async () => {
    const result: CryptoResult<number> = {
      ok: false,
      error: { kind: "ChainInvalid", seq: 1, reason: "empty-chain" },
    };
    const error = await Effect.runPromise(Effect.flip(fromCryptoResult(result)));
    expect(error).toBeInstanceOf(ChainInvalidError);
  });
});

describe("cryptoEffect", () => {
  it("lifts a real @maruhi/crypto operation into Effect", async () => {
    // verifyChain([]) は empty-chain を値で返す — ラッパー経由で型付きエラーになる
    const error = await Effect.runPromise(Effect.flip(cryptoEffect(() => verifyChain([]))));
    expect(error).toBeInstanceOf(ChainInvalidError);
    if (error instanceof ChainInvalidError) {
      expect(error.reason).toBe("empty-chain");
      expect(error.seq).toBe(0);
    }
  });
});

describe("isProjectId", () => {
  it("accepts a lowercase 64-char hex string", () => {
    expect(isProjectId("ab".repeat(32))).toBe(true);
  });

  it("rejects uppercase, short, and non-hex strings", () => {
    expect(isProjectId("AB".repeat(32))).toBe(false);
    expect(isProjectId("ab".repeat(31))).toBe(false);
    expect(isProjectId("zz".repeat(32))).toBe(false);
  });
});
