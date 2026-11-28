import {
  encodeHex,
  importEncryptionPublicKey,
  importSigningPublicKey,
  signDekWrap,
  SUITE_ID,
  unwrapDek,
  verifyDekWrapSignature,
  wrapDek,
} from "@maruhi/crypto";
import {
  hexBytes,
  testEnvironmentId,
  testProjectId,
  testUserId,
  unwrapResult,
} from "@maruhi/crypto/test-support";

import type { SigningIdentity, TestIdentity } from "./identity.ts";
import { encryptionKeyPairOf, signingKeyOf } from "./identity.ts";
import type { WireRecipientDek, WireWrappedDek } from "./wire.ts";

export interface WrapRecipient {
  readonly userId: string;
  readonly encPubHex: string;
}

export interface UnsignedWrap {
  readonly suite: string;
  readonly epoch: number;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

type WrapSigner = SigningIdentity & Pick<TestIdentity, "userId">;

export async function signWrap<const T extends UnsignedWrap>(
  signer: WrapSigner,
  projectId: string,
  environmentId: string,
  unsigned: T,
): Promise<T & { readonly signatureHex: string }> {
  const signatureHex = unwrapResult(
    await signDekWrap({
      context: {
        suite: unsigned.suite,
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(environmentId),
        epoch: unsigned.epoch,
        recipientUserId: testUserId(unsigned.recipientUserId),
        recipientEncPubHex: unsigned.recipientEncPubHex,
        encHex: unsigned.encHex,
        ciphertextHex: unsigned.ciphertextHex,
        signerUserId: signer.userId,
      },
      signingKey: await signingKeyOf(signer),
    }),
    "signDekWrap",
  );
  return { ...unsigned, signatureHex };
}

export async function wrapDekTo(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipient: WrapRecipient;
  readonly recipientClass?: WireWrappedDek["recipientClass"];
  readonly signer: WrapSigner;
}): Promise<WireWrappedDek> {
  const publicKey = unwrapResult(
    await importEncryptionPublicKey(hexBytes(input.recipient.encPubHex)),
    "importEncryptionPublicKey",
  );
  const wrapped = unwrapResult(
    await wrapDek({
      recipientPublicKey: publicKey,
      dek: input.dek,
      context: {
        projectId: testProjectId(input.projectId),
        environmentId: testEnvironmentId(input.environmentId),
        epoch: input.epoch,
        recipientUserId: testUserId(input.recipient.userId),
      },
    }),
    "wrapDek",
  );
  return signWrap(input.signer, input.projectId, input.environmentId, {
    suite: SUITE_ID,
    epoch: input.epoch,
    recipientClass: input.recipientClass ?? "member",
    recipientUserId: input.recipient.userId,
    recipientEncPubHex: input.recipient.encPubHex,
    encHex: encodeHex(wrapped.enc),
    ciphertextHex: encodeHex(wrapped.ciphertext),
  });
}

export function distributedWrapOf(
  wrap: WireWrappedDek,
  signer: Pick<TestIdentity, "userId" | "fingerprintHex">,
): WireRecipientDek {
  return {
    suite: wrap.suite,
    epoch: wrap.epoch,
    recipientEncPubHex: wrap.recipientEncPubHex,
    encHex: wrap.encHex,
    ciphertextHex: wrap.ciphertextHex,
    signatureHex: wrap.signatureHex,
    signerUserId: signer.userId,
    signerKeyFingerprintHex: signer.fingerprintHex,
  };
}

export async function verifyWrapSignature(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly recipient: WrapRecipient;
  readonly wrap: Pick<UnsignedWrap, "suite" | "epoch" | "encHex" | "ciphertextHex"> & {
    readonly signatureHex: string;
  };
  readonly signer: Pick<TestIdentity, "userId" | "sigPubHex">;
}): Promise<boolean> {
  const publicKey = unwrapResult(
    await importSigningPublicKey(hexBytes(input.signer.sigPubHex)),
    "importSigningPublicKey",
  );
  const result = await verifyDekWrapSignature({
    context: {
      suite: input.wrap.suite,
      projectId: testProjectId(input.projectId),
      environmentId: testEnvironmentId(input.environmentId),
      epoch: input.wrap.epoch,
      recipientUserId: testUserId(input.recipient.userId),
      recipientEncPubHex: input.recipient.encPubHex,
      encHex: input.wrap.encHex,
      ciphertextHex: input.wrap.ciphertextHex,
      signerUserId: input.signer.userId,
    },
    signatureHex: input.wrap.signatureHex,
    signerPublicKey: publicKey,
  });
  return result.ok;
}

export async function unwrapDekAs(
  recipient: Pick<TestIdentity, "userId" | "encPubHex" | "encSkHex">,
  input: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly wrapped: Pick<UnsignedWrap, "epoch" | "encHex" | "ciphertextHex">;
  },
): Promise<Uint8Array> {
  return unwrapResult(
    await unwrapDek({
      recipientKeyPair: await encryptionKeyPairOf(recipient),
      wrapped: {
        enc: hexBytes(input.wrapped.encHex),
        ciphertext: hexBytes(input.wrapped.ciphertextHex),
      },
      context: {
        projectId: testProjectId(input.projectId),
        environmentId: testEnvironmentId(input.environmentId),
        epoch: input.wrapped.epoch,
        recipientUserId: recipient.userId,
      },
    }),
    "unwrapDek",
  );
}
