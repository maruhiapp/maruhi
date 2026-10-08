// Common core of the real crypto fixtures shared by the cli / server test
// support (apps/cli/test/support/crypto.ts /
// apps/server/test/support/data-crypto.ts). Uses only the public API of
// @maruhi/crypto. The two sides source keys differently (cli = generated each
// time / server = vector-pinned keys), so the caller injects the chain-signing
// means as the signEntry function.

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

/** Deterministic timestamp base for fixtures (2026-08-01T00:00:00Z). */
export const BASE_TIME_MS = 1754006400000;

/** Unwraps a CryptoResult to its plain value (failure = a test-data assembly bug = throw). */
export function unwrapResult<T>(result: CryptoResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${JSON.stringify(result.error)}`);
  }
  return result.value;
}

/**
 * Test-only mint of a {@link UserId} from a fixture literal or a test-vector
 * `user_id` (the vectors' free-format ids — AUTH_SPEC §11-1). The package
 * itself never mints one; production code mints only through
 * `UserIdSchema` in `@maruhi/core`. Test data is the test suites' trust
 * boundary, and this is the one cast that serves it.
 */
export function testUserId(value: string): UserId {
  return value as UserId;
}

/**
 * Test-only mint of a {@link KeyFingerprintHex} from a fixture literal or a
 * test-vector fingerprint. Production code mints only through the package's
 * own fingerprint computation and `@maruhi/core`'s format-checked mints. Like
 * {@link testUserId}, it is a plain cast with no format check: test data is
 * the test suites' trust boundary, and negative vectors carry malformed
 * fingerprints on purpose.
 */
export function testKeyFingerprintHex(value: string): KeyFingerprintHex {
  return value as KeyFingerprintHex;
}

/**
 * Test-only mints of {@link ProjectId}, {@link EnvironmentId} and
 * {@link VariableId} from fixture literals and test-vector ids. The package
 * itself never mints them; production code mints only through the
 * format-checked schemas in `@maruhi/core`. Like {@link testUserId}, they are
 * plain casts with no format check: test data is the test suites' trust
 * boundary, and negative vectors carry malformed ids on purpose.
 */
export function testProjectId(value: string): ProjectId {
  return value as ProjectId;
}

export function testEnvironmentId(value: string): EnvironmentId {
  return value as EnvironmentId;
}

export function testVariableId(value: string): VariableId {
  return value as VariableId;
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
  readonly actor: ChainActor;
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

/**
 * The §5.2 commitment of an environment's DEK (64 lowercase hex chars),
 * minting the ids at the test boundary. Shared by the app test-supports.
 */
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
