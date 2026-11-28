import {
  decodeHex,
  encodeHex,
  generateDek,
  importEncryptionPublicKey,
  wrapDek,
} from "@maruhi/crypto";
import { testEnvironmentId, testProjectId, testUserId } from "@maruhi/test-kit";
import { Effect, Exit, Fiber, Redacted } from "effect";
import { describe, expect, it, vi } from "vite-plus/test";

import {
  makeServerKey,
  makeServerKeyFromEnv,
  type ServerKeyInfo,
  type StoredServerWrap,
} from "../src/server-key.ts";

const IKM = Redacted.make("b0".repeat(32), { label: "SERVER_ENC_KEY_IKM" });
const PROJECT_ID = "0".repeat(64);
const CLAIMS_DIGEST_HEX = "1".repeat(64);
const WORKLOAD_PUB_HEX = "aa".repeat(32);

async function storedServerWrap(info: ServerKeyInfo) {
  const pub = decodeHex(info.serverEncPubHex);
  if (pub === null) throw new Error("serverEncPubHex is not hex");
  const pubKey = await importEncryptionPublicKey(pub);
  if (!pubKey.ok) throw new Error("server enc pub failed to import");
  const wrapped = await wrapDek({
    recipientPublicKey: pubKey.value,
    dek: generateDek(),
    context: {
      projectId: testProjectId(PROJECT_ID),
      environmentId: testEnvironmentId("prod"),
      epoch: 1,
      recipientUserId: testUserId(info.serverKeyFingerprintHex),
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
  projectId: testProjectId(PROJECT_ID),
  environmentId: testEnvironmentId("prod"),
  claimsDigestHex: CLAIMS_DIGEST_HEX,
  workloadPubHex: WORKLOAD_PUB_HEX,
  wraps,
});

describe("makeServerKey's derivation cache", () => {
  it("derives once however many info / reseal calls race", async () => {
    const key = makeServerKey(IKM);
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
    expect(b).toBe(a);
    expect(d).toBe(a);
    expect(c).toBe(a);
    expect(resealed).toEqual([]);
    expect(signs).toBe(2);
  });

  it("an interrupted first caller cannot poison the cache", async () => {
    const realSign = crypto.subtle.sign.bind(crypto.subtle);
    let releaseSign!: () => void;
    const signGate = new Promise<void>((resolve) => {
      releaseSign = resolve;
    });
    const signSpy = vi
      .spyOn(crypto.subtle, "sign")
      .mockImplementationOnce((algorithm, key, data) =>
        signGate.then(() => realSign(algorithm, key, data)),
      );
    const key = makeServerKey(IKM);
    const fiber = Effect.runFork(key.info);
    await vi.waitFor(() => expect(signSpy).toHaveBeenCalled());
    Effect.runFork(Fiber.interrupt(fiber));
    releaseSign();
    const exit = await Effect.runPromise(Fiber.await(fiber));
    const info = await Effect.runPromise(key.info);
    signSpy.mockRestore();
    expect(Exit.hasInterrupts(exit)).toBe(true);
    expect(info).not.toBeNull();
  });

  it("caches a null (unset or malformed ikm) result like a success", async () => {
    const signSpy = vi.spyOn(crypto.subtle, "sign");
    for (const bad of [undefined, "", "not-hex", "ab".repeat(31)]) {
      const key = makeServerKey(bad === undefined ? undefined : Redacted.make(bad));
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
    expect(signs).toBe(0);
  });
});

describe("reseal's DEK hygiene", () => {
  it("re-wraps the stored wrap and zeroizes the unsealed DEK on success", async () => {
    const key = makeServerKey(IKM);
    const info = await Effect.runPromise(key.info);
    if (info === null) throw new Error("a configured ikm yielded null");
    const wrap = await storedServerWrap(info);
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
    const key = makeServerKey(IKM);
    const info = await Effect.runPromise(key.info);
    if (info === null) throw new Error("a configured ikm yielded null");
    const wrap = await storedServerWrap(info);
    const fillSpy = vi.spyOn(Uint8Array.prototype, "fill");
    const outcome = await Effect.runPromise(
      key.reseal({ ...resealInput([wrap]), claimsDigestHex: "not-hex" }).pipe(
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

  it("zeroizes the unsealed DEK when an interrupt lands while the unwrap is in flight", async () => {
    const key = makeServerKey(IKM);
    const info = await Effect.runPromise(key.info);
    if (info === null) throw new Error("a configured ikm yielded null");
    const wrap = await storedServerWrap(info);
    const realDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    let releaseDecrypt!: () => void;
    const decryptGate = new Promise<void>((resolve) => {
      releaseDecrypt = resolve;
    });
    const decryptSpy = vi
      .spyOn(crypto.subtle, "decrypt")
      .mockImplementationOnce((algorithm, cryptoKey, data) =>
        decryptGate.then(() => realDecrypt(algorithm, cryptoKey, data)),
      );
    const fillSpy = vi.spyOn(Uint8Array.prototype, "fill");
    const fiber = Effect.runFork(key.reseal(resealInput([wrap])));
    await vi.waitFor(() => expect(decryptSpy).toHaveBeenCalled());
    Effect.runFork(Fiber.interrupt(fiber));
    releaseDecrypt();
    const exit = await Effect.runPromise(Fiber.await(fiber));
    const fills = [...fillSpy.mock.calls];
    fillSpy.mockRestore();
    decryptSpy.mockRestore();
    expect(Exit.hasInterrupts(exit)).toBe(true);
    expect(fills).toHaveLength(1);
    expect(fills[0]?.[0]).toBe(0);
  });

  it("never reaches zeroize when the unwrap fails", async () => {
    const key = makeServerKey(IKM);
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

describe("makeServerKeyFromEnv (the DO's env-facing construction)", () => {
  const RAW_IKM_HEX = "b0".repeat(32);

  it("derives the same keypair from the string shape as makeServerKey does", async () => {
    const fromEnv = await Effect.runPromise(makeServerKeyFromEnv(RAW_IKM_HEX));
    const direct = await Effect.runPromise(makeServerKey(IKM).info);
    expect(await Effect.runPromise(fromEnv.info)).toEqual(direct);
  });

  it("derives the same keypair from a Secrets Store binding", async () => {
    const store: SecretsStoreSecret = { get: () => Promise.resolve(RAW_IKM_HEX) };
    const fromStore = await Effect.runPromise(makeServerKeyFromEnv(store));
    const direct = await Effect.runPromise(makeServerKey(IKM).info);
    expect(await Effect.runPromise(fromStore.info)).toEqual(direct);
  });

  it("treats a failed store read as unconfigured, like an unset ikm", async () => {
    const failingStore: SecretsStoreSecret = {
      get: () => Promise.reject(new Error("store read failed")),
    };
    const fromStore = await Effect.runPromise(makeServerKeyFromEnv(failingStore));
    expect(await Effect.runPromise(fromStore.info)).toBeNull();
    const unset = await Effect.runPromise(makeServerKeyFromEnv(undefined));
    expect(await Effect.runPromise(unset.info)).toBeNull();
  });
});
