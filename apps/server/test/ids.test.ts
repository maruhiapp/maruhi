import { Effect, Layer } from "effect";
import { Digest, SecureRandom } from "effect/crypto";
import { describe, expect, it } from "vitest";

import {
  createFlowToken,
  generateUserCode,
  importFlowSigningKey,
  verifyFlowToken,
} from "../src/auth.package/index.ts";
import {
  newOrgId,
  newUserId,
  randomBase62,
  randomHex,
  randomHexSync,
  sha256Hex,
} from "../src/ids.ts";

// Format-invariance tests for the SecureRandom / Digest migration
// (Effect 4.1): the expected strings below were produced by the
// pre-migration implementations (ambient WebCrypto draws + the same
// encoding code) fed with the same byte streams, so equality here
// proves the service-based versions changed neither byte lengths nor
// encodings (AUTH_SPEC §5 / §6).

/** A SecureRandom whose draws are a fixed byte pattern. */
const fixedRandom = (byteAt: (index: number) => number) =>
  Layer.mock(SecureRandom.SecureRandom, {
    randomBytes: (size: number) =>
      Effect.succeed(Uint8Array.from({ length: size }, (_, index) => byteAt(index))),
  });

const runWith = <A, E>(
  effect: Effect.Effect<A, E, SecureRandom.SecureRandom>,
  byteAt: (index: number) => number,
): Promise<A> => Effect.runPromise(effect.pipe(Effect.provide(fixedRandom(byteAt))));

describe("randomBase62 (AUTH_SPEC §6 token body)", () => {
  it("is 43 chars of zeroes for a zero draw (256-bit value, left-padded)", async () => {
    expect(await runWith(randomBase62(), () => 0)).toBe("0".repeat(43));
  });

  it("keeps the pre-migration encoding for a patterned draw", async () => {
    expect(await runWith(randomBase62(), (index) => index * 8 + 3)).toBe(
      "0ik1ZsQKCTvXUWwDdGunhsQOKAIgMWJjuSUUlmoBfFj",
    );
  });

  it("keeps the pre-migration encoding at the byte ceiling", async () => {
    const value = await runWith(randomBase62(), () => 255);
    expect(value).toBe("yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1");
    expect(value).toHaveLength(43);
  });
});

describe("randomHex", () => {
  it("is lowercase hex of exactly 2 * byteLength chars", async () => {
    const value = await runWith(randomHex(32), (index) => index * 8 + 3);
    expect(value).toMatch(/^[0-9a-f]{64}$/);
    expect(value.startsWith("030b13")).toBe(true);
  });

  it("randomHexSync produces the same encoding for the synchronous call sites", () => {
    expect(randomHexSync(16)).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("sha256Hex (AUTH_SPEC §5 / §6 storage hash)", () => {
  const runReal = (value: string): Promise<string> =>
    Effect.runPromise(sha256Hex(value).pipe(Effect.provide(Digest.layerWebCrypto)));

  it("matches the SHA-256 known-answer vectors", async () => {
    expect(await runReal("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(await runReal("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(await runReal("maruhi_pat_example")).toBe(
      "6b2809e992c889712e2297edd44794280a53a12538cdf63f2a42c09f8ba2c1ff",
    );
  });

  it("routes through the Digest service with the SHA-256 algorithm", async () => {
    let seenAlgorithm: string | undefined;
    let seenData: Uint8Array | undefined;
    const spy = Layer.mock(Digest.Digest, {
      digestHex: (algorithm, data) => {
        seenAlgorithm = algorithm.name;
        seenData = data;
        return Effect.succeed("ab".repeat(32));
      },
    });
    const value = await Effect.runPromise(sha256Hex("abc").pipe(Effect.provide(spy)));
    expect(value).toBe("ab".repeat(32));
    expect(seenAlgorithm).toBe("SHA-256");
    expect(seenData && new TextDecoder().decode(seenData)).toBe("abc");
  });
});

describe("newUserId / newOrgId", () => {
  it("mint ULIDs (26 Crockford chars) through the service draw", async () => {
    const userId = await runWith(newUserId(1_700_000_000_000), (index) => index * 17);
    const orgId = await runWith(newOrgId(1_700_000_000_000), (index) => index * 17);
    expect(userId).toBe("01HF7YAT000H2K4N6Q8SAVCXEZ");
    expect(orgId).toBe("01HF7YAT000H2K4N6Q8SAVCXEZ");
  });
});

describe("cli-flow draws", () => {
  it("generateUserCode keeps the XXXX-XXXX Crockford format and encoding", async () => {
    expect(await runWith(generateUserCode(), (index) => index * 37 + 5)).toBe("5AFM-SY38");
  });

  it("createFlowToken keeps the v1.<exp>.<randHex>.<macHex> shape and verifies", async () => {
    const key = await importFlowSigningKey("11".repeat(32));
    const token = await runWith(
      createFlowToken(key, "flow-1", 1_700_000_000_000),
      (index) => index * 8 + 3,
    );
    const segments = token.split(".");
    expect(segments).toHaveLength(4);
    expect(segments[0]).toBe("v1");
    expect(segments[1]).toBe("1700000000000");
    expect(segments[2]).toMatch(/^[0-9a-f]{64}$/);
    expect(segments[2]?.startsWith("030b13")).toBe(true);
    expect(segments[3]).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifyFlowToken(key, "flow-1", token, 1_700_000_000_000 - 1)).toBe("valid");
  });
});
