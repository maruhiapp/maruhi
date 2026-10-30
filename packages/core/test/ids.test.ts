import { Effect, Layer } from "effect";
import { SecureRandom } from "effect/crypto";
import { describe, expect, it } from "vitest";

import { ulid } from "../src/ids.ts";

// Format-invariance tests for the SecureRandom migration (Effect 4.1):
// the expected strings below were produced by the pre-migration
// implementation (ambient `crypto.getRandomValues` + the same encoding
// code) fed with the same byte streams, so equality here proves the
// service-based draw changed neither the algorithm nor the encoding.

/** A SecureRandom whose draws are a fixed byte pattern. */
const fixedRandom = (byteAt: (index: number) => number) =>
  Layer.mock(SecureRandom.SecureRandom, {
    randomBytes: (size: number) =>
      Effect.succeed(Uint8Array.from({ length: size }, (_, index) => byteAt(index))),
  });

const runUlid = (nowMs: number, byteAt: (index: number) => number): Promise<string> =>
  Effect.runPromise(ulid(nowMs).pipe(Effect.provide(fixedRandom(byteAt))));

describe("ulid (ids.ts)", () => {
  it("keeps the pre-migration output for a zero draw", async () => {
    expect(await runUlid(1_700_000_000_000, () => 0)).toBe("01HF7YAT000000000000000000");
  });

  it("keeps the pre-migration output for a patterned draw", async () => {
    expect(await runUlid(1_700_000_000_000, (index) => index * 17)).toBe(
      "01HF7YAT000H2K4N6Q8SAVCXEZ",
    );
  });

  it("keeps the pre-migration output at the byte ceiling", async () => {
    expect(await runUlid(1, () => 255)).toBe("0000000001ZZZZZZZZZZZZZZZZ");
  });

  it("is 26 Crockford Base32 chars with the time in the first 10", async () => {
    const id = await runUlid(1_700_000_000_000, (index) => index * 17);
    expect(id).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$/);
    expect(id.slice(0, 10)).toBe("01HF7YAT00");
  });
});
