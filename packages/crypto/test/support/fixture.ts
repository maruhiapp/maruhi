// Common core of the real crypto fixtures shared by the cli / server test
// support (apps/cli/test/support/crypto.ts /
// apps/server/test/support/data-crypto.ts). Uses only the public API of
// @maruhi/crypto. The two sides source keys differently (cli = generated each
// time / server = vector-pinned keys), so the caller injects the chain-signing
// means as the signEntry function.

import type {
  ChainEntry,
  ChainOperation,
  CryptoResult,
  UnsignedChainEntry,
  ValueSignatureContext,
} from "../../src/index.ts";
import {
  computeChainEntryHash,
  computeValueSignedBytesHash,
  decodeHex,
  SUITE_ID,
} from "../../src/index.ts";

/** Deterministic timestamp base for fixtures (2026-08-01T00:00:00Z). */
export const BASE_TIME_MS = 1754006400000;

/** Unwraps a CryptoResult to its plain value (failure = a test-data assembly bug = throw). */
export function unwrapResult<T>(result: CryptoResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${JSON.stringify(result.error)}`);
  }
  return result.value;
}

/** Hex inside tests is always well-formed (a null from decodeHex = an assembly bug = throw). */
export function hexBytes(hex: string): Uint8Array {
  const bytes = decodeHex(hex);
  if (bytes === null) {
    throw new Error(`invalid hex in test data: ${hex.slice(0, 16)}…`);
  }
  return bytes;
}

/**
 * Lazy construction of an op that depends on the project ID (= genesis hash).
 * Because the §5.2 commitment preimage contains project_id, the payloads of
 * create_environment / rotate_epoch cannot be finalized until the genesis is
 * assembled.
 */
export type LazyChainOperation = (projectId: string) => ChainOperation | Promise<ChainOperation>;

/** One step of buildChainWith (the caller supplies the actor identity and signing means). */
export interface ChainBuildStep {
  readonly actor: { readonly userId: string; readonly keyFingerprintHex: string };
  readonly operation: ChainOperation | LazyChainOperation;
  readonly signEntry: (unsigned: UnsignedChainEntry) => Promise<ChainEntry>;
}

export interface BuiltChain {
  readonly entries: readonly ChainEntry[];
  /** Entry hash of entries[i] (used as the CAS parent head). */
  readonly hashes: readonly string[];
  /** Project ID = genesis entry hash (CRYPTO_SPEC §6.4). */
  readonly projectId: string;
}

/** Assembles a valid signed chain (seq / prev_hash / timestamp are automatic). */
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

/** Wire representation of the EncryptedPayload shape (including the §4.1 signature block — AUTH_SPEC §12-2). */
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
  // Value write-signature block (CRYPTO_SPEC §4.1 / AUTH_SPEC §12-2)
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/** Reconstructs the §4.1 signature context from a WireEncryptedPayload. */
export function valueContextOf(
  payload: WireEncryptedPayload,
  writerUserId: string,
): ValueSignatureContext {
  return {
    suite: payload.suite,
    projectId: payload.aad.projectId,
    environmentId: payload.aad.environmentId,
    epoch: payload.aad.epoch,
    variableId: payload.aad.variableId,
    version: payload.aad.version,
    nonceHex: payload.nonceHex,
    ciphertextHex: payload.ciphertextHex,
    prevValueSigHashHex: payload.prevValueSigHashHex,
    writerUserId,
    chainHeadHashHex: payload.chainHeadHashHex,
    chainHeadSeq: payload.chainHeadSeq,
  };
}

/**
 * SHA-256 of value_signed_bytes (used as the next version's
 * prev_value_sig_hash_hex — the §4.1 chain). writer does not ride on the wire,
 * so it is specified explicitly.
 */
export async function valueSignedBytesHashOf(
  payload: WireEncryptedPayload,
  writerUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeValueSignedBytesHash(valueContextOf(payload, writerUserId)),
    "computeValueSignedBytesHash",
  );
}
