// The KeyFingerprintHex brand (crypto chain-types.ts; mints in core
// identity.ts). The type-level half is enforced by `tsc --noEmit` (the
// typecheck step of the quality gate): each `@ts-expect-error` line below
// must stay a compile error, so a change that lets a plain string — a
// provider identity, a user id, a row id — into a fingerprint position of a
// chain entry or an audit row fails the gate (an unused `@ts-expect-error` is
// itself an error). The runtime half pins the mints: the format check at the
// string mints, and agreement with crypto's computation at the computed ones.

import type {
  approvalSignersOf,
  ApprovalVote,
  ChainActor,
  ChainDevice,
  GrantServerPayload,
  ownerVotersOf,
  PendingProposal,
  RevokeDevicePayload,
  RevokeServerPayload,
  ServerGrant,
} from "@maruhi/crypto";
import { computeServerKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { vectorKeys } from "@maruhi/crypto/test-support";
import { Effect, Exit, Schema } from "effect";
import { describe, expect, expectTypeOf, it } from "vitest";

import type { AuditEventRecord, ChainMirrorSubject } from "../src/audit.ts";
import {
  decodeKeyFingerprintHex,
  decodeProviderUserId,
  decodeUserId,
  type KeyFingerprintHex,
  KeyFingerprintHexSchema,
  serverKeyFingerprintHex,
  type UserId,
  userKeyFingerprintHex,
} from "../src/identity.ts";

const fp: KeyFingerprintHex = decodeKeyFingerprintHex("ab".repeat(16));
const userId: UserId = decodeUserId("01J9Z3K4M5N6P7Q8R9S0T1V2W3");
/** A plain string of the right format: the brand still refuses it (provenance, not only format). */
const unminted = "cd".repeat(16);
/** GitHub's numeric id (AUTH_SPEC §3-2) and the display login. */
const providerSubject = decodeProviderUserId("583231");
const providerLogin = "octocat";

describe("KeyFingerprintHex brand — chain positions (CRYPTO_SPEC §6.1 / §6.2)", () => {
  it("refuses anything but a minted fingerprint as the entry actor's key", () => {
    const actors: readonly ChainActor[] = [
      { userId, keyFingerprintHex: fp },
      // @ts-expect-error a plain string is not a fingerprint
      { userId, keyFingerprintHex: unminted },
      // @ts-expect-error a provider subject is not a fingerprint
      { userId, keyFingerprintHex: providerSubject },
      // @ts-expect-error a provider login is not a fingerprint
      { userId, keyFingerprintHex: providerLogin },
      // @ts-expect-error a user id is not a fingerprint
      { userId, keyFingerprintHex: userId },
    ];
    expect(actors).toHaveLength(5);
  });

  it("refuses a plain string in the key positions of the payloads", () => {
    const grant: Pick<GrantServerPayload, "serverKeyFingerprintHex">[] = [
      { serverKeyFingerprintHex: fp },
      // @ts-expect-error grant_server names a server key by its fingerprint
      { serverKeyFingerprintHex: unminted },
    ];
    // @ts-expect-error revoke_server names a server key by its fingerprint
    const revoke: RevokeServerPayload = { serverKeyFingerprintHex: unminted };
    const revokeDevice: Pick<RevokeDevicePayload, "deviceFingerprintsHex">[] = [
      { deviceFingerprintsHex: [fp] },
      // @ts-expect-error revoke_device names devices by their fingerprints
      { deviceFingerprintsHex: [unminted] },
    ];
    expect([grant, revoke, revokeDevice]).toHaveLength(3);
  });

  it("types the verified chain's derived state with the brand (so it flows into entries and rows unchanged)", () => {
    expectTypeOf<ChainDevice["keyFingerprintHex"]>().toEqualTypeOf<KeyFingerprintHex>();
    expectTypeOf<ApprovalVote["keyFingerprintHex"]>().toEqualTypeOf<KeyFingerprintHex>();
    expectTypeOf<PendingProposal["proposerKeyFingerprintHex"]>().toEqualTypeOf<KeyFingerprintHex>();
    expectTypeOf<ServerGrant["serverKeyFingerprintHex"]>().toEqualTypeOf<KeyFingerprintHex>();
    // The four-eyes recount a client reuses (#337) carries both identity brands
    expectTypeOf<
      ReturnType<typeof approvalSignersOf>[number]["keyFingerprintHex"]
    >().toEqualTypeOf<KeyFingerprintHex>();
    expectTypeOf<ReturnType<typeof ownerVotersOf>>().toEqualTypeOf<ReadonlySet<UserId>>();
    // A minted fingerprint reads as a string everywhere a string is enough
    expectTypeOf<KeyFingerprintHex>().toExtend<string>();
    expectTypeOf<string>().not.toExtend<KeyFingerprintHex>();
    expectTypeOf<KeyFingerprintHex>().not.toExtend<UserId>();
    expectTypeOf<UserId>().not.toExtend<KeyFingerprintHex>();
  });
});

describe("KeyFingerprintHex brand — audit positions (AUDIT_SPEC §2 / §5.1)", () => {
  it("refuses anything but a minted fingerprint in the actor and target key columns", () => {
    const rows: Pick<AuditEventRecord, "actorKeyFingerprintHex" | "targetKeyFingerprintHex">[] = [
      { actorKeyFingerprintHex: fp, targetKeyFingerprintHex: fp },
      // @ts-expect-error a plain string is not an actor key fingerprint
      { actorKeyFingerprintHex: unminted },
      // @ts-expect-error a provider login is not a target key fingerprint
      { targetKeyFingerprintHex: providerLogin },
      // @ts-expect-error a provider subject is not an actor key fingerprint
      { actorKeyFingerprintHex: providerSubject },
    ];
    const subjects: ChainMirrorSubject[] = [
      { addedDeviceKeyFingerprintHex: fp },
      // @ts-expect-error the added device's fingerprint is computed from its keys
      { addedDeviceKeyFingerprintHex: unminted },
    ];
    expect([rows, subjects]).toHaveLength(2);
  });
});

describe("minting a KeyFingerprintHex", () => {
  it("decodes a fingerprint field into the brand without changing the value", () => {
    const decoded = Schema.decodeUnknownSync(KeyFingerprintHexSchema)("0123456789abcdef".repeat(2));
    expectTypeOf(decoded).toEqualTypeOf<KeyFingerprintHex>();
    expect(decoded).toBe("0123456789abcdef0123456789abcdef");
    expect(Schema.encodeSync(KeyFingerprintHexSchema)(decoded)).toBe(decoded);
  });

  it("refuses anything that is not 16 bytes of lowercase hex", () => {
    const decode = Schema.decodeUnknownSync(KeyFingerprintHexSchema);
    for (const bad of [
      "AB".repeat(16), // uppercase: string equality would no longer be fingerprint equality
      "ab".repeat(15),
      "ab".repeat(17),
      "ab".repeat(32), // a public key / hash width
      "zz".repeat(16),
      "583231",
      "",
    ]) {
      expect(() => decode(bad), bad).toThrow();
    }
    expect(() => decode(0xab)).toThrow();
    expect(() => decodeKeyFingerprintHex("octocat")).toThrow();
  });

  it("computes a device key's fingerprint from its public keys (CRYPTO_SPEC §3 — the vectors)", async () => {
    const keys = Object.values(vectorKeys);
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      const computed = await Effect.runPromise(
        userKeyFingerprintHex(hex(key.enc_pub_hex), hex(key.sig_pub_hex)),
      );
      expectTypeOf(computed).toEqualTypeOf<KeyFingerprintHex>();
      expect(computed).toBe(key.key_fingerprint_hex);
    }
  });

  it("computes a server key's fingerprint from its public key (CRYPTO_SPEC §9)", async () => {
    const serverEncPub = hex("5a".repeat(32));
    const expected = await computeServerKeyFingerprint(serverEncPub);
    if (!expected.ok) {
      throw new Error("server fingerprint failed");
    }
    const computed = await Effect.runPromise(serverKeyFingerprintHex(serverEncPub));
    expect(computed).toBe(encodeHex(expected.value));
  });

  it("fails on a key of the wrong length (a typed crypto error, not a malformed brand)", async () => {
    const exit = await Effect.runPromiseExit(userKeyFingerprintHex(new Uint8Array(31), hex("00")));
    expect(Exit.isFailure(exit)).toBe(true);
  });
});

function hex(value: string): Uint8Array {
  const bytes = decodeHex(value);
  if (bytes === null) {
    throw new Error(`bad hex in test data: ${value}`);
  }
  return bytes;
}
