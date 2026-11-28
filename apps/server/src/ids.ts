import {
  decodeOrgId,
  decodeProjectId,
  decodeUserId,
  ulid,
  type OrgId,
  type ProjectId,
  type UserId,
} from "@maruhi/core";
import { decodeHex, encodeHex } from "@maruhi/crypto";
import { Effect } from "effect";
import type { CryptoError } from "effect/crypto";
import { Digest, Mac, SecureRandom } from "effect/crypto";

export { ulid } from "@maruhi/core";

export const newUserId = (nowMs: number): Effect.Effect<UserId, never, SecureRandom.SecureRandom> =>
  Effect.map(ulid(nowMs), (id) => decodeUserId(id));

export const newOrgId = (nowMs: number): Effect.Effect<OrgId, never, SecureRandom.SecureRandom> =>
  Effect.map(ulid(nowMs), (id) => decodeOrgId(id));

export function projectIdOfGenesisHash(genesisHashHex: string): ProjectId {
  return decodeProjectId(genesisHashHex);
}

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export const randomBase62 = (): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(SecureRandom.SecureRandom, (random) =>
    Effect.map(random.randomBytes(32), (bytes) => {
      let value = 0n;
      for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
      }
      let out = "";
      while (value > 0n) {
        out = BASE62[Number(value % 62n)] + out;
        value /= 62n;
      }
      return out.padStart(43, "0");
    }),
  );

export const randomHex = (
  byteLength: number,
): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.flatMap(SecureRandom.SecureRandom, (random) =>
    Effect.map(random.randomBytes(byteLength), (bytes) => encodeHex(bytes)),
  );

export function randomHexSync(byteLength: number): string {
  return encodeHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export const sha256Hex = (
  value: string,
): Effect.Effect<string, CryptoError.CryptoError, Digest.Digest> =>
  Effect.flatMap(Digest.Digest, (digest) =>
    digest.digestHex(Digest.sha256, new TextEncoder().encode(value)),
  );

export function constantTimeEqual(a: string, b: string): boolean {
  const aBytes = decodeHex(a);
  const bBytes = decodeHex(b);
  if (aBytes === null || bBytes === null) {
    return false;
  }
  return Mac.timingSafeEqual(aBytes, bBytes);
}
