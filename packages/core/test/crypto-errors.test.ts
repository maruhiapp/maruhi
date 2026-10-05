import { Cause, Effect, Exit, Result } from "effect";
import { describe, expect, it } from "vitest";

import { ChainInvalidError, CryptoContractViolationError, cryptoEffect } from "../src/index.ts";

// A marker standing in for key material / a plaintext value riding in a
// rejection. It must appear in no serialization of the exit or the defect.
const SECRET_SENTINEL = "S3CR3T-KEY-MATERIAL-4d2f9a1b";

const defectOf = async (
  effect: Effect.Effect<unknown, unknown>,
): Promise<{ defect: unknown; pretty: string }> => {
  const exit = await Effect.runPromiseExit(effect);
  if (!Exit.isFailure(exit)) {
    expect.unreachable("the effect must fail");
  }
  const found = Cause.findDefect(exit.cause);
  if (!Result.isSuccess(found)) {
    expect.unreachable("the failure must be a defect");
  }
  return { defect: found.success, pretty: Cause.pretty(exit.cause) };
};

describe("cryptoEffect", () => {
  it("passes an ok CryptoResult through", async () => {
    await expect(
      Effect.runPromise(cryptoEffect(() => Promise.resolve({ ok: true, value: 42 }))),
    ).resolves.toBe(42);
  });

  it("maps an error CryptoResult onto the tagged error channel", async () => {
    const error = await Effect.runPromise(
      Effect.flip(
        cryptoEffect(() =>
          Promise.resolve({
            ok: false,
            error: { kind: "ChainInvalid", seq: 1, reason: "empty-chain" },
          }),
        ),
      ),
    );
    expect(error).toBeInstanceOf(ChainInvalidError);
  });

  it("dies with CryptoContractViolation on a rejection and leaks none of the rejection value", async () => {
    const rejection = new Error(SECRET_SENTINEL, { cause: new Error(`inner-${SECRET_SENTINEL}`) });
    const { defect, pretty } = await defectOf(cryptoEffect(() => Promise.reject(rejection)));

    // The defect keeps no part of the rejection: not the object itself,
    // not its message, not its cause chain
    expect(defect).toBeInstanceOf(CryptoContractViolationError);
    expect(defect).not.toBe(rejection);
    expect(JSON.stringify(defect)).not.toContain(SECRET_SENTINEL);
    expect(String(defect)).not.toContain(SECRET_SENTINEL);
    expect((defect as Error).stack ?? "").not.toContain(SECRET_SENTINEL);
    expect(pretty).not.toContain(SECRET_SENTINEL);
    // …but the crash is still diagnosable as the crypto contract breaking
    expect(pretty).toContain("CryptoContractViolation");
  });

  it("scrubs a non-Error rejection value the same way", async () => {
    const rejection = { leaked: SECRET_SENTINEL };
    const { defect, pretty } = await defectOf(cryptoEffect(() => Promise.reject(rejection)));
    expect(defect).toBeInstanceOf(CryptoContractViolationError);
    expect(defect).not.toBe(rejection);
    expect(pretty).not.toContain(SECRET_SENTINEL);
  });

  it("scrubs a synchronous throw by the thunk the same way", async () => {
    const thrown = new Error(SECRET_SENTINEL);
    const { defect, pretty } = await defectOf(
      cryptoEffect(() => {
        throw thrown;
      }),
    );
    expect(defect).toBeInstanceOf(CryptoContractViolationError);
    expect(defect).not.toBe(thrown);
    expect(pretty).not.toContain(SECRET_SENTINEL);
  });
});
