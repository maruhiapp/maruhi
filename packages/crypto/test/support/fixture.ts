import type {
  ChainActor,
  ChainEntry,
  ChainOperation,
  CryptoResult,
  EnvironmentId,
  KeyFingerprintHex,
  ProjectId,
  UnsignedChainEntry,
  UserId,
  VariableId,
  ValueSignatureContext,
} from "../../src/index.ts";
import {
  computeChainEntryHash,
  computeDekCommitment,
  computeValueSignedBytesHash,
  decodeHex,
  SUITE_ID,
} from "../../src/index.ts";

export const BASE_TIME_MS = 1754006400000;

export function unwrapResult<T>(result: CryptoResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${JSON.stringify(result.error)}`);
  }
  return result.value;
}

export function testUserId(value: string): UserId {
  return value as UserId;
}

export function testKeyFingerprintHex(value: string): KeyFingerprintHex {
  return value as KeyFingerprintHex;
}

export function testProjectId(value: string): ProjectId {
  return value as ProjectId;
}

export function testEnvironmentId(value: string): EnvironmentId {
  return value as EnvironmentId;
}

export function testVariableId(value: string): VariableId {
  return value as VariableId;
}

export function hexBytes(hex: string): Uint8Array {
  const bytes = decodeHex(hex);
  if (bytes === null) {
    throw new Error(`invalid hex in test data: ${hex.slice(0, 16)}…`);
  }
  return bytes;
}

export type LazyChainOperation = (projectId: string) => ChainOperation | Promise<ChainOperation>;

export interface ChainBuildStep {
  readonly actor: ChainActor;
  readonly operation: ChainOperation | LazyChainOperation;
  readonly signEntry: (unsigned: UnsignedChainEntry) => Promise<ChainEntry>;
}

export interface BuiltChain {
  readonly entries: readonly ChainEntry[];
  readonly hashes: readonly string[];
  readonly projectId: string;
}

export async function buildChainWith(steps: readonly ChainBuildStep[]): Promise<BuiltChain> {
  const entries: ChainEntry[] = [];
  const hashes: string[] = [];
  let prevHashHex = "0".repeat(64);
  for (const [index, step] of steps.entries()) {
    const projectId = hashes[0];
    if (typeof step.operation === "function" && projectId === undefined) {
      throw new Error("buildChain: genesis step cannot depend on the project id");
    }
    const operation =
      typeof step.operation === "function" ? await step.operation(projectId ?? "") : step.operation;
    const unsigned: UnsignedChainEntry = {
      ...operation,
      suite: SUITE_ID,
      seq: index + 1,
      prevHashHex,
      actor: step.actor,
      timestampMs: BASE_TIME_MS + index * 1000,
    };
    const entry = await step.signEntry(unsigned);
    const hash = await computeChainEntryHash(entry);
    entries.push(entry);
    hashes.push(hash);
    prevHashHex = hash;
  }
  const projectId = hashes[0];
  if (projectId === undefined) {
    throw new Error("buildChain: empty chain");
  }
  return { entries, hashes, projectId };
}

export interface WireEncryptedPayload {
  readonly suite: string;
  readonly aad: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly epoch: number;
    readonly variableId: string;
    readonly version: number;
  };
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export function valueContextOf(
  payload: WireEncryptedPayload,
  writerUserId: string,
): ValueSignatureContext {
  return {
    suite: payload.suite,
    projectId: testProjectId(payload.aad.projectId),
    environmentId: testEnvironmentId(payload.aad.environmentId),
    epoch: payload.aad.epoch,
    variableId: testVariableId(payload.aad.variableId),
    version: payload.aad.version,
    nonceHex: payload.nonceHex,
    ciphertextHex: payload.ciphertextHex,
    prevValueSigHashHex: payload.prevValueSigHashHex,
    writerUserId: testUserId(writerUserId),
    chainHeadHashHex: payload.chainHeadHashHex,
    chainHeadSeq: payload.chainHeadSeq,
  };
}

export async function valueSignedBytesHashOf(
  payload: WireEncryptedPayload,
  writerUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeValueSignedBytesHash(valueContextOf(payload, writerUserId)),
    "computeValueSignedBytesHash",
  );
}

export async function testDekCommitmentHex(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<string> {
  return unwrapResult(
    await computeDekCommitment({
      context: {
        suite: SUITE_ID,
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(environmentId),
        epoch,
      },
      dek,
    }),
    "computeDekCommitment",
  );
}
