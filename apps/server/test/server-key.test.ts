// server-key.ts's Effect-cached derivation (W2-S2): one derivation
// per isolate however many calls race, a null "unconfigured" result
// cached like a success, and `zeroize` on every unsealed DEK on every
// exit path.

import {
  decodeHex,
  encodeHex,
  generateDek,
  importEncryptionPublicKey,
  wrapDek,
} from "@maruhi/crypto";
import { Effect, Fiber } from "effect";
import { describe, expect, it, vi } from "vitest";

import { makeServerKey, type ServerKeyInfo, type StoredServerWrap } from "../src/server-key.ts";

const IKM_HEX = "b0".repeat(32);
const PROJECT_ID = "0".repeat(64);
const CLAIMS_DIGEST_HEX = "1".repeat(64);
const WORKLOAD_PUB_HEX = "aa".repeat(32);

// A stored server-addressed wrap (the fixture dek_wraps rows carry) of
// a fresh DEK to this deployment's keypair
async function storedServerWrap(info: ServerKeyInfo) {
  const pub = decodeHex(info.serverEncPubHex);
  if (pub === null) throw new Error("serverEncPubHex is not hex");
  const pubKey = await importEncryptionPublicKey(pub);
  if (!pubKey.ok) throw new Error("server enc pub failed to import");
  const wrapped = await wrapDek({
    recipientPublicKey: pubKey.value,
    dek: generateDek(),
    context: {
      projectId: PROJECT_ID,
      environmentId: "prod",
      epoch: 1,
      recipientUserId: info.serverKeyFingerprintHex,
    },
  });
  if (!wrapped.ok) throw new Error("wrapDek failed");
  return {
    suite: "maruhi/v1" as const,
    epoch: 1,
    encHex: encodeHex(wrapped.value.enc),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

const resealInput = (wraps: readonly StoredServerWrap[]) => ({
  projectId: PROJECT_ID,
  environmentId: "prod",
  claimsDigestHex: CLAIMS_DIGEST_HEX,
  workloadPubHex: WORKLOAD_PUB_HEX,
  wraps,
});

describe("makeServerKey's derivation cache", () => {
  it("derives once however many info / reseal calls race", async () => {
    const key = makeServerKey(IKM_HEX);
    // The pinned suite's derivation signs exactly twice (HKDF extract
    // + expand — CRYPTO_SPEC §2, §9). An empty-wraps reseal adds no
    // sign (its only crypto call is importEncryptionPublicKey), so the
    // sign count directly counts derivations
    const signSpy = vi.spyOn(crypto.subtle, "sign");
    const [a, b, resealed, d] = await Effect.runPromise(
      Effect.all([key.info, key.info, key.reseal(resealInput([])), key.info], {
        concurrency: "unbounded",
      }),
    );
    const [c] = await Effect.runPromise(
      Effect.all([key.info, key.info], { concurrency: "unbounded" }),
    );
    const signs = signSpy.mock.calls.length;
    signSpy.mockRestore();
    if (a === null) throw new Error("a configured ikm yielded null");
    // Every racing call shares the first run's memoized
    // DerivedServerKey — the same object comes back each time
    expect(b).toBe(a);
    expect(d).toBe(a);
    expect(c).toBe(a);
    expect(resealed).toEqual([]);
    expect(signs).toBe(2);
  });

  it("an interrupted first caller cannot poison the cache", async () => {
    const key = makeServerKey(IKM_HEX);
    await Effect.runPromise(
      Effect.gen(function* () {
        const fiber = yield* Effect.forkChild(key.info);
        yield* Fiber.interrupt(fiber);
      }),
    );
    // Effect.cached replays the first run's Exit: if the evaluation
    // were interruptible, a cancelled request would leave an
    // interrupted Exit in the cell forever. The uninterruptible mask
    // around derive makes that Exit impossible — whether or not the
    // interrupt landed mid-derivation, a later call still resolves
    const info = await Effect.runPromise(key.info);
    expect(info).not.toBeNull();
  });

  it("caches a null (unset or malformed ikm) result like a success", async () => {
    const signSpy = vi.spyOn(crypto.subtle, "sign");
    for (const bad of [undefined, "", "not-hex", "ab".repeat(31)]) {
      const key = makeServerKey(bad);
      const [a, b] = await Effect.runPromise(
        Effect.all([key.info, key.info], { concurrency: "unbounded" }),
      );
      expect(a).toBeNull();
      expect(b).toBe(a);
      const resealed = await Effect.runPromise(
        key.reseal(resealInput([])).pipe(
          Effect.match({
            onSuccess: () => "succeeded" as const,
            onFailure: (failure) => failure,
          }),
        ),
      );
      expect(resealed).toBe("not-configured");
    }
    const signs = signSpy.mock.calls.length;
    signSpy.mockRestore();
    // No crypto was ever attempted for the unusable ikms
    expect(signs).toBe(0);
  });
});

describe("reseal's DEK hygiene", () => {
  it("re-wraps the stored wrap and zeroizes the unsealed DEK on success", async () => {
    const key = makeServerKey(IKM_HEX);
    const info = await Effect.runPromise(key.info);
    if (info === null) throw new Error("a configured ikm yielded null");
    const wrap = await storedServerWrap(info);
    // zeroize is bytes.fill(0) — the only .fill a reseal runs on the
    // 32-byte unsealed DEK
    const fillSpy = vi.spyOn(Uint8Array.prototype, "fill");
    const leased = await Effect.runPromise(key.reseal(resealInput([wrap])));
    const zeroizes = fillSpy.mock.calls.length;
    fillSpy.mockRestore();
    expect(leased).toHaveLength(1);
    expect(leased[0]?.suite).toBe("maruhi/v1");
    expect(leased[0]?.epoch).toBe(1);
    expect(leased[0]?.encHex).toMatch(/^[0-9a-f]{64}$/);
    expect(leased[0]?.ciphertextHex).toMatch(/^[0-9a-f]+$/);
    expect(zeroizes).toBe(1);
  });

  it("zeroizes the unsealed DEK even when the re-wrap itself fails", async () => {
    const key = makeServerKey(IKM_HEX);
    const info = await Effect.runPromise(key.info);
    if (info === null) throw new Error("a configured ikm yielded null");
    const wrap = await storedServerWrap(info);
    const fillSpy = vi.spyOn(Uint8Array.prototype, "fill");
    const outcome = await Effect.runPromise(
      key
        // A malformed claims digest makes wrapLeaseDek refuse the
        // context (InvalidInput) after the unwrap already succeeded
        .reseal({ ...resealInput([wrap]), claimsDigestHex: "not-hex" })
        .pipe(
          Effect.match({
            onSuccess: () => "succeeded" as const,
            onFailure: (failure) => failure,
          }),
        ),
    );
    const zeroizes = fillSpy.mock.calls.length;
    fillSpy.mockRestore();
    expect(outcome).toBe("wrap-failed");
    expect(zeroizes).toBe(1);
  });

  it("never reaches zeroize when the unwrap fails", async () => {
    const key = makeServerKey(IKM_HEX);
    const info = await Effect.runPromise(key.info);
    if (info === null) throw new Error("a configured ikm yielded null");
    const fillSpy = vi.spyOn(Uint8Array.prototype, "fill");
    const outcome = await Effect.runPromise(
      key
        .reseal(
          resealInput([
            {
              suite: "maruhi/v1",
              epoch: 1,
              encHex: "aa".repeat(32),
              ciphertextHex: "bb".repeat(48),
            },
          ]),
        )
        .pipe(
          Effect.match({
            onSuccess: () => "succeeded" as const,
            onFailure: (failure) => failure,
          }),
        ),
    );
    const zeroizes = fillSpy.mock.calls.length;
    fillSpy.mockRestore();
    expect(outcome).toBe("unwrap-failed");
    // The poisoned wrap produced no DEK, so there was nothing to erase
    expect(zeroizes).toBe(0);
  });

  it("answers not-configured without touching the wraps on an unset ikm", async () => {
    const key = makeServerKey(undefined);
    const fillSpy = vi.spyOn(Uint8Array.prototype, "fill");
    const outcome = await Effect.runPromise(
      key.reseal(resealInput([])).pipe(
        Effect.match({
          onSuccess: () => "succeeded" as const,
          onFailure: (failure) => failure,
        }),
      ),
    );
    const zeroizes = fillSpy.mock.calls.length;
    fillSpy.mockRestore();
    expect(outcome).toBe("not-configured");
    expect(zeroizes).toBe(0);
  });
});
