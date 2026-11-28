import type { EnvValuesDigestEntry } from "@maruhi/crypto";
import {
  computeEnvValuesDigest,
  decryptVariable,
  encodeHex,
  encryptVariable,
  signValue,
  SUITE_ID,
} from "@maruhi/crypto";
import type { WireEncryptedPayload as LooseEncryptedPayload } from "@maruhi/crypto/test-support";
import {
  hexBytes,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  unwrapResult,
  valueContextOf,
  valueSignedBytesHashOf,
} from "@maruhi/crypto/test-support";

import type { ChainHead } from "./chain.ts";
import type { SigningIdentity, TestIdentity } from "./identity.ts";
import { signingKeyOf } from "./identity.ts";
import type { WireCheckpointSnapshot, WireDistributedValue, WireEncryptedPayload } from "./wire.ts";
import { unwrapDekAs } from "./wraps.ts";

type ValueWriter = SigningIdentity & Pick<TestIdentity, "userId">;

export async function signValueAt<const T extends Omit<LooseEncryptedPayload, "signatureHex">>(
  writer: ValueWriter,
  unsigned: T,
  head: ChainHead,
): Promise<
  Omit<T, "chainHeadHashHex" | "chainHeadSeq"> & {
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  }
> {
  const withHead = {
    ...unsigned,
    chainHeadHashHex: head.hashHex,
    chainHeadSeq: head.seq,
    signatureHex: "",
  };
  const signatureHex = unwrapResult(
    await signValue({
      context: valueContextOf(withHead, writer.userId),
      signingKey: await signingKeyOf(writer),
    }),
    "signValue",
  );
  return { ...withHead, signatureHex };
}

export async function encryptValue(input: {
  readonly dek: Uint8Array;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
  readonly writer: ValueWriter;
  readonly head: ChainHead;
  readonly prevValueSigHashHex?: string;
}): Promise<WireEncryptedPayload> {
  const context = {
    projectId: testProjectId(input.projectId),
    environmentId: testEnvironmentId(input.environmentId),
    epoch: input.epoch,
    variableId: testVariableId(input.variableId),
    version: input.version,
  };
  const encrypted = unwrapResult(
    await encryptVariable({
      dek: input.dek,
      context,
      plaintext:
        typeof input.plaintext === "string"
          ? new TextEncoder().encode(input.plaintext)
          : input.plaintext,
    }),
    "encryptVariable",
  );
  return signValueAt(
    input.writer,
    {
      suite: SUITE_ID,
      aad: context,
      nonceHex: encodeHex(encrypted.nonce),
      ciphertextHex: encodeHex(encrypted.ciphertext),
      prevValueSigHashHex: input.prevValueSigHashHex ?? "",
      chainHeadHashHex: input.head.hashHex,
      chainHeadSeq: input.head.seq,
    },
    input.head,
  );
}

function distributedValueOf(
  payload: WireEncryptedPayload,
  writer: Pick<TestIdentity, "userId" | "fingerprintHex">,
): WireDistributedValue {
  return {
    ...payload,
    writerUserId: writer.userId,
    writerKeyFingerprintHex: writer.fingerprintHex,
  };
}

export async function distributedValue(input: {
  readonly dek: Uint8Array;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
  readonly writer: ValueWriter & Pick<TestIdentity, "fingerprintHex">;
  readonly head: ChainHead;
  readonly prevValueSigHashHex?: string;
}): Promise<WireDistributedValue> {
  const payload = await encryptValue({
    ...input,
    prevValueSigHashHex: input.prevValueSigHashHex ?? (input.version === 1 ? "" : "cd".repeat(32)),
  });
  return distributedValueOf(payload, input.writer);
}

export async function decryptValue(
  dek: Uint8Array,
  payload: Pick<LooseEncryptedPayload, "aad" | "nonceHex" | "ciphertextHex">,
): Promise<string> {
  const plaintext = unwrapResult(
    await decryptVariable({
      dek,
      context: {
        projectId: testProjectId(payload.aad.projectId),
        environmentId: testEnvironmentId(payload.aad.environmentId),
        epoch: payload.aad.epoch,
        variableId: testVariableId(payload.aad.variableId),
        version: payload.aad.version,
      },
      nonce: hexBytes(payload.nonceHex),
      ciphertext: hexBytes(payload.ciphertextHex),
    }),
    "decryptVariable",
  );
  return new TextDecoder().decode(plaintext);
}

export async function unwrapAndDecrypt(input: {
  readonly recipient: Pick<TestIdentity, "userId" | "encPubHex" | "encSkHex">;
  readonly wrapped: {
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
  };
  readonly projectId: string;
  readonly environmentId: string;
  readonly payload: Pick<LooseEncryptedPayload, "aad" | "nonceHex" | "ciphertextHex">;
}): Promise<string> {
  const dek = await unwrapDekAs(input.recipient, input);
  return decryptValue(dek, input.payload);
}

export async function valuesDigestOf(entries: readonly EnvValuesDigestEntry[]): Promise<string> {
  return unwrapResult(await computeEnvValuesDigest(SUITE_ID, entries), "computeEnvValuesDigest");
}

export async function checkpointSnapshotValuesOf(
  values: readonly WireDistributedValue[],
): Promise<WireCheckpointSnapshot["values"]> {
  return Promise.all(
    values.map(async (value) => ({
      variableId: value.aad.variableId,
      version: value.aad.version,
      valueSigHashHex: await valueSignedBytesHashOf(value, value.writerUserId),
    })),
  );
}
