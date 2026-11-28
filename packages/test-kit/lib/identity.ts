import type { EncryptionKeyPair, KeyFingerprintHex, SigningKeyPair, UserId } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  encodeHex,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionKeyPair,
  importSigningKeyPair,
} from "@maruhi/crypto";
import {
  hexBytes,
  testKeyFingerprintHex,
  testUserId,
  unwrapResult,
  vectorKeys,
} from "@maruhi/crypto/test-support";

export interface TestIdentity {
  readonly userId: UserId;
  readonly encPubHex: string;
  readonly encSkHex: string;
  readonly sigPubHex: string;
  readonly sigSkSeedHex: string;
  readonly fingerprintHex: KeyFingerprintHex;
}

export interface GeneratedIdentity extends TestIdentity {
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
}

export async function generateIdentity(userId: string): Promise<GeneratedIdentity> {
  const encKeyPair = await generateEncryptionKeyPair({ extractable: true });
  const sigKeyPair = await generateSigningKeyPair({ extractable: true });
  const encPub = await exportEncryptionPublicKey(encKeyPair.publicKey);
  const sigPub = await exportSigningPublicKey(sigKeyPair.publicKey);
  const encSk = unwrapResult(await exportEncryptionPrivateKey(encKeyPair.privateKey), "exportEnc");
  const sigSeed = unwrapResult(await exportSigningPrivateSeed(sigKeyPair.privateKey), "exportSig");
  const fingerprint = unwrapResult(await computeUserKeyFingerprint(encPub, sigPub), "fingerprint");
  return {
    userId: testUserId(userId),
    encPubHex: encodeHex(encPub),
    encSkHex: encodeHex(encSk),
    sigPubHex: encodeHex(sigPub),
    sigSkSeedHex: encodeHex(sigSeed),
    fingerprintHex: testKeyFingerprintHex(encodeHex(fingerprint)),
    encKeyPair,
    sigKeyPair,
  };
}

export function vectorIdentity(vectorKeyName: string, userId = vectorKeyName): TestIdentity {
  const keys = vectorKeys[vectorKeyName];
  if (keys === undefined) {
    throw new Error(`no vector keys named ${vectorKeyName}`);
  }
  return {
    userId: testUserId(userId),
    encPubHex: keys.enc_pub_hex,
    encSkHex: keys.enc_sk_seed_hex,
    sigPubHex: keys.sig_pub_hex,
    sigSkSeedHex: keys.sig_sk_seed_hex,
    fingerprintHex: testKeyFingerprintHex(keys.key_fingerprint_hex),
  };
}

export function vectorIdentityByFingerprint(
  fingerprintHex: string,
  userId: string,
): TestIdentity | undefined {
  const name = Object.keys(vectorKeys).find(
    (candidate) => vectorKeys[candidate]?.key_fingerprint_hex === fingerprintHex,
  );
  return name === undefined ? undefined : vectorIdentity(name, userId);
}

export type SigningIdentity = Pick<TestIdentity, "sigPubHex" | "sigSkSeedHex">;

export async function signingKeyOf(identity: SigningIdentity): Promise<CryptoKey> {
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(identity.sigPubHex),
      privateSeed: hexBytes(identity.sigSkSeedHex),
    }),
    "importSigningKeyPair",
  );
  return pair.privateKey;
}

export async function encryptionKeyPairOf(
  identity: Pick<TestIdentity, "encPubHex" | "encSkHex">,
): Promise<EncryptionKeyPair> {
  return unwrapResult(
    await importEncryptionKeyPair({
      publicKey: hexBytes(identity.encPubHex),
      privateKey: hexBytes(identity.encSkHex),
    }),
    "importEncryptionKeyPair",
  );
}
