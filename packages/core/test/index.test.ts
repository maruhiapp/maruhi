import type { CryptoError, CryptoResult } from "@maruhi/crypto";
import {
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  verifyChain,
} from "@maruhi/crypto";
import { Cause, Effect, Exit } from "effect";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ChainInvalidError,
  CryptoDecryptError,
  CryptoDekCommitmentError,
  CryptoDekUnwrapError,
  CryptoDekWrapError,
  CryptoDekWrapSignatureError,
  cryptoEffect,
  CryptoEncryptError,
  CryptoInvalidInputError,
  CryptoInviteAcceptSignatureError,
  CryptoInviteIssueSignatureError,
  CryptoInviteLinkSignatureError,
  CryptoKeyExportError,
  CryptoKeyImportError,
  cryptoPromise,
  type CryptoPromiseOperation,
  CryptoRejectedError,
  CryptoSignError,
  CryptoValueInvalidError,
  fromCryptoResult,
  isEnvironmentId,
  isProjectId,
  isVariableId,
  toWrappedCryptoError,
  type WrappedCryptoError,
} from "../src/index.ts";

// Correspondence between every CryptoError kind and its mapped class
// (the discriminator is the crypto-side kind → the Effect-side tagged
// error)
const KIND_TO_CLASS: readonly [
  CryptoError,
  abstract new (...args: never[]) => WrappedCryptoError,
][] = [
  [{ kind: "InvalidInput", field: "nonce" }, CryptoInvalidInputError],
  [{ kind: "KeyImportFailed", key: "signing-public" }, CryptoKeyImportError],
  [{ kind: "KeyExportFailed", key: "signing-private" }, CryptoKeyExportError],
  [{ kind: "EncryptFailed", operation: "variable" }, CryptoEncryptError],
  [{ kind: "DecryptFailed", operation: "recovery" }, CryptoDecryptError],
  [{ kind: "DekWrapFailed" }, CryptoDekWrapError],
  [{ kind: "DekUnwrapFailed" }, CryptoDekUnwrapError],
  [{ kind: "SignFailed" }, CryptoSignError],
  [{ kind: "DekWrapSignatureInvalid" }, CryptoDekWrapSignatureError],
  [{ kind: "InviteAcceptSignatureInvalid" }, CryptoInviteAcceptSignatureError],
  [{ kind: "InviteLinkSignatureInvalid" }, CryptoInviteLinkSignatureError],
  [{ kind: "InviteIssueSignatureInvalid" }, CryptoInviteIssueSignatureError],
  [{ kind: "DekCommitmentMismatch" }, CryptoDekCommitmentError],
  [{ kind: "ValueInvalid", reason: "signature-invalid" }, CryptoValueInvalidError],
  [{ kind: "ChainInvalid", seq: 3, reason: "bad-signature" }, ChainInvalidError],
];

// Static check of exhaustiveness: if a kind is added on the crypto side, this fails to compile
type CoveredKind = (typeof KIND_TO_CLASS)[number][0]["kind"];
type AllKindsCovered = CryptoError["kind"] extends CoveredKind ? true : never;
const allKindsCovered: AllKindsCovered = true;
void allKindsCovered;

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

  it("preserves the reason of a value verification failure", () => {
    const wrapped = toWrappedCryptoError({
      kind: "ValueInvalid",
      reason: "writer-key-mismatch-at-head",
    });
    expect(wrapped).toBeInstanceOf(CryptoValueInvalidError);
    if (wrapped instanceof CryptoValueInvalidError) {
      expect(wrapped.reason).toBe("writer-key-mismatch-at-head");
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
    // verifyChain([]) returns empty-chain as a value — it becomes a typed error through the wrapper
    const error = await Effect.runPromise(Effect.flip(cryptoEffect(() => verifyChain([]))));
    expect(error).toBeInstanceOf(ChainInvalidError);
    if (error instanceof ChainInvalidError) {
      expect(error.reason).toBe("empty-chain");
      expect(error.seq).toBe(0);
    }
  });
});

// Every @maruhi/crypto export that returns a bare Promise (no
// CryptoResult) — CryptoPromiseOperation is derived from the package's
// public surface, and this list is pinned to it both ways: `satisfies`
// keeps the list inside the union, `AllOperationsCovered` fails to
// compile if the union grows a member the list lacks
type CryptoExports = typeof import("@maruhi/crypto");
const BARE_PROMISE_OPERATIONS = [
  "computeChainEntryHash",
  "exportEncryptionPublicKey",
  "exportSigningPublicKey",
  "generateEncryptionKeyPair",
  "generateSigningKeyPair",
] as const satisfies readonly CryptoPromiseOperation[];
type AllOperationsCovered = CryptoPromiseOperation extends (typeof BARE_PROMISE_OPERATIONS)[number]
  ? true
  : never;
const allOperationsCovered: AllOperationsCovered = true;
void allOperationsCovered;

describe("cryptoPromise", () => {
  // Correctly-typed success values per operation — real key material
  // shapes without any cast (the two generators actually run)
  let thunks: { [K in CryptoPromiseOperation]: () => ReturnType<CryptoExports[K]> };
  beforeAll(async () => {
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const encPub = await exportEncryptionPublicKey(encPair.publicKey);
    const sigPub = await exportSigningPublicKey(sigPair.publicKey);
    thunks = {
      computeChainEntryHash: () => Promise.resolve("deadbeef"),
      exportEncryptionPublicKey: () => Promise.resolve(encPub),
      exportSigningPublicKey: () => Promise.resolve(sigPub),
      generateEncryptionKeyPair: () => Promise.resolve(encPair),
      generateSigningKeyPair: () => Promise.resolve(sigPair),
    };
  });

  for (const operation of BARE_PROMISE_OPERATIONS) {
    it(`passes the resolved value through (${operation})`, async () => {
      const expected = await thunks[operation]();
      await expect(Effect.runPromise(cryptoPromise(operation, thunks[operation]))).resolves.toBe(
        expected,
      );
    });

    it(`turns a rejection into CryptoRejected and leaks nothing (${operation})`, async () => {
      const effect = cryptoPromise(operation, () => Promise.reject(new Error("SENTINEL")));
      const error = await Effect.runPromise(Effect.flip(effect));
      expect(error).toBeInstanceOf(CryptoRejectedError);
      if (error instanceof CryptoRejectedError) {
        expect(error.operation).toBe(operation);
      }
      // The rejection cause is dropped on purpose: the sentinel must
      // surface through no serialization of the error or the exit
      expect(JSON.stringify(error)).not.toContain("SENTINEL");
      expect(String(error)).not.toContain("SENTINEL");
      expect(error.stack ?? "").not.toContain("SENTINEL");
      const exit = await Effect.runPromiseExit(effect);
      if (Exit.isFailure(exit)) {
        expect(Cause.pretty(exit.cause)).not.toContain("SENTINEL");
      } else {
        expect.unreachable("the effect must fail");
      }
    });
  }

  it("maps a synchronous throw from the thunk to CryptoRejected too", async () => {
    const effect = cryptoPromise("generateSigningKeyPair", () => {
      throw new Error("SENTINEL");
    });
    const error = await Effect.runPromise(Effect.flip(effect));
    expect(error).toBeInstanceOf(CryptoRejectedError);
    if (error instanceof CryptoRejectedError) {
      expect(error.operation).toBe("generateSigningKeyPair");
    }
    expect(JSON.stringify(error)).not.toContain("SENTINEL");
    expect(String(error)).not.toContain("SENTINEL");
    expect(error.stack ?? "").not.toContain("SENTINEL");
    const exit = await Effect.runPromiseExit(effect);
    if (Exit.isFailure(exit)) {
      expect(Cause.pretty(exit.cause)).not.toContain("SENTINEL");
    } else {
      expect.unreachable("the effect must fail");
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

// isEnvironmentId / isVariableId share the same §12-1 acceptance form
// (AUTH_SPEC). Because they also validate storage record keys, the
// boundary — rejecting `__proto__` (out of form via the leading `_`)
// and accepting `constructor` / `prototype` (legitimate IDs) — is
// pinned directly
for (const [name, guard] of [
  ["isEnvironmentId", isEnvironmentId],
  ["isVariableId", isVariableId],
] as const) {
  describe(name, () => {
    it("accepts §12-1 resource ids (1-64 chars, alphanumeric start)", () => {
      expect(guard("dev")).toBe(true);
      expect(guard("a")).toBe(true);
      expect(guard(`a${"b".repeat(63)}`)).toBe(true);
      expect(guard("A1_-x")).toBe(true);
      // An inherited-property name is a legitimate ID if it fits the form (the reading side defends via own-property)
      expect(guard("constructor")).toBe(true);
      expect(guard("prototype")).toBe(true);
    });

    it("rejects empty, leading-symbol, over-length, and out-of-alphabet ids", () => {
      expect(guard("")).toBe(false);
      expect(guard("__proto__")).toBe(false);
      expect(guard("-dev")).toBe(false);
      expect(guard("_dev")).toBe(false);
      expect(guard(`a${"b".repeat(64)}`)).toBe(false);
      expect(guard("dev/prod")).toBe(false);
      expect(guard("日本語")).toBe(false); // english-exempt: non-ASCII input test datum verifying rejection
    });
  });
}
