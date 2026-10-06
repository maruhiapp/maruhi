// CRYPTO_SPEC §4.3: the environment manifest (Ed25519).
// env_manifest_signed_bytes = LP("<suite>/env-manifest-sig", project_id,
//                                environment_id, epoch, manifest_version,
//                                variables_digest_hex,
//                                env_meta_version, env_meta_sig_hash_hex,
//                                prev_manifest_sig_hash_hex,
//                                issuer_user_id, chain_head_hash_hex, chain_head_seq)
// variables_digest_hex = lower_hex(SHA-256(LP("<suite>/env-manifest-vars",
//                                             entry_1, …, entry_n)))
// entry_i = LP(variable_id, status, meta_version, meta_sig_hash_hex)
//   — **byte-ascending** order of variable_id (UTF-8). The latest form of all
//   statements including tombstones. The empty set is also valid (an
//   environment with zero variables = an LP with zero elements). Each entry
//   embeds the byte string of a nested LP as one field (same convention as
//   scope_environments).
// The suite binding is carried by the domain string (same shape as §4.1 /
// §4.2); numbers (epoch / manifest_version / env_meta_version / meta_version /
// chain_head_seq) are base-10 stringified per §2.1, and binaries (hashes) go
// onto the LP as lowercase hex strings.
// Test vectors: test-vectors/env-manifest.json
//
// The signature's semantics: "issuer_user_id declared, at chain position
// (chain_head_hash, chain_head_seq) under current epoch epoch, that the
// complete picture of this environment's meta state is this" — attribution,
// content authenticity, and authorization-time binding + **epoch baking**
// (§4.3 — the manifest layer supplies the freshness anchor that meta
// statements lack).
// Verification of the declared head, authorization time, epoch integrity,
// digest recomputation, and prev chaining is carried by manifest-verify.ts
// (history queries by chain-history.ts); this module holds only the
// low-level normalization, signing, digest, and hashing.

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import type { MetaStatementStatus } from "./meta-sign.ts";
import { computeVariableKeyedDigest } from "./sorted-digest.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * One entry of the variables digest (CRYPTO_SPEC §4.3): the latest form of
 * one variable's metadata statement — tombstones (`deleted`) and layout v3
 * `declared` statements (§4.2 — a declaration with no value set) included. The digest encoder
 * is unchanged by layout v3: `declared` only appears as a new string value of
 * the `status` field (§4.3's coverage of the schema columns — the manifest
 * layer is unchanged).
 */
export interface VariablesDigestEntry {
  readonly variableId: string;
  readonly status: MetaStatementStatus;
  readonly metaVersion: number;
  /** SHA-256 (lowercase hex) of that statement's signed bytes (§4.2). */
  readonly metaSigHashHex: string;
}

function digestEntryInvalidField(entry: VariablesDigestEntry): string | null {
  if (entry.variableId.length === 0) {
    return "entry variableId";
  }
  if (entry.status !== "active" && entry.status !== "deleted" && entry.status !== "declared") {
    return "entry status";
  }
  if (!Number.isSafeInteger(entry.metaVersion) || entry.metaVersion < 1) {
    return "entry metaVersion";
  }
  if (!isLowercaseHexOfLength(entry.metaSigHashHex, SHA256_HEX_LENGTH)) {
    return "entry metaSigHashHex";
  }
  return null;
}

/**
 * Computes the canonical variables digest (CRYPTO_SPEC §4.3). The canonical
 * variable_id byte-ascending order is applied internally, duplicate variable
 * ids are rejected, and the empty set is valid (an environment with no
 * variables yet). The skeleton (validate → reject duplicates → internal sort
 * → nested LP) is the shared implementation in sorted-digest.ts (isomorphic
 * to §6.2's values_digest).
 */
export async function computeVariablesDigest(
  suite: string,
  entries: readonly VariablesDigestEntry[],
): Promise<CryptoResult<string>> {
  return computeVariableKeyedDigest({
    suite,
    domain: "env-manifest-vars",
    entries,
    variableIdOf: (entry) => entry.variableId,
    entryInvalidField: digestEntryInvalidField,
    entryFields: (entry) => [
      entry.variableId,
      entry.status,
      entry.metaVersion,
      entry.metaSigHashHex,
    ],
  });
}

/**
 * Fields bound by an environment-manifest signature (CRYPTO_SPEC §4.3): the
 * full wire form of one manifest version plus its authorization anchor and
 * the epoch burned in at issuance time (the freshness anchor of the metadata
 * layer). Hashes are lowercase hex strings.
 */
export interface EnvManifestContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  /** The environment's current epoch at issuance (§4.3 — the core anchor). */
  readonly epoch: number;
  /** 1-based counter (environment creation = 1; each meta op / rotate increments). */
  readonly manifestVersion: number;
  /** Canonical digest of all variable statements incl. tombstones (§4.3). */
  readonly variablesDigestHex: string;
  /** Latest environment meta statement bound by this manifest (§4.3). */
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  /**
   * SHA-256 (lowercase hex) of the previous manifest's signed bytes; the
   * empty string for manifestVersion 1 (the §4.3 chaining convention — same as §4.1 / §4.2).
   */
  readonly prevManifestSigHashHex: string;
  /** The issuer's own internal user id (binds attribution to the identity). */
  readonly issuerUserId: string;
  /** Entry hash of the chain head the issuer last verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head (both hash and seq are signed; mismatch fails). */
  readonly chainHeadSeq: number;
}

function numericFieldInvalid(context: EnvManifestContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  if (!Number.isSafeInteger(context.manifestVersion) || context.manifestVersion < 1) {
    return "context manifestVersion";
  }
  if (!Number.isSafeInteger(context.envMetaVersion) || context.envMetaVersion < 1) {
    return "context envMetaVersion";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

// Binary values are lowercase hex only (the same discipline as the §4.1 /
// §4.2 implementations — allowing uppercase hex would give one value multiple
// normalized forms and break signature uniqueness)
function hexFieldInvalid(context: EnvManifestContext): string | null {
  if (!isLowercaseHexOfLength(context.variablesDigestHex, SHA256_HEX_LENGTH)) {
    return "context variablesDigestHex";
  }
  if (!isLowercaseHexOfLength(context.envMetaSigHashHex, SHA256_HEX_LENGTH)) {
    return "context envMetaSigHashHex";
  }
  if (
    context.prevManifestSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevManifestSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevManifestSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

// suite, the coordinates (projectId / environmentId), and issuer must be
// non-empty (the same check level as meta-sign.ts — no legitimate call signs
// empty coordinates)
function contextInvalidField(context: EnvManifestContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  if (context.issuerUserId.length === 0) {
    return "context issuerUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/** Validates a manifest context (shared by sign / verify / hash). */
export function manifestContextInvalidField(context: EnvManifestContext): string | null {
  return contextInvalidField(context);
}

/**
 * Builds the canonical byte string signed for one environment manifest
 * (CRYPTO_SPEC §4.3). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify / hash below do); this builder assumes valid
 * input.
 */
export function buildEnvManifestSignedBytes(context: EnvManifestContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/env-manifest-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.manifestVersion,
    context.variablesDigestHex,
    context.envMetaVersion,
    context.envMetaSigHashHex,
    context.prevManifestSigHashHex,
    context.issuerUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the value carried
 * as the next manifest's `prev_manifest_sig_hash_hex` (the §4.3 chaining) and
 * compared for fork evidence (two valid signatures over distinct signed
 * bytes at the same manifestVersion — §14.2-5).
 */
export async function computeEnvManifestSignedBytesHash(
  context: EnvManifestContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildEnvManifestSignedBytes(context))) };
}

/**
 * Signs one environment manifest with the issuer's chain signing key
 * (Ed25519, CRYPTO_SPEC §4.3). Returns the signature as lowercase hex — the
 * wire form of `EnvironmentManifest.signatureHex` (AUTH_SPEC §12-2).
 *
 * Signing enforces the manifestVersion ↔ prev coupling (manifestVersion 1
 * signs an empty prev, later versions sign a 64-hex prev): producing a
 * rule-violating manifest is always a caller bug, unlike verification where
 * such wire data must be rejected with a typed reason instead (the same
 * asymmetry as meta-sign.ts).
 */
export async function signEnvManifest(input: {
  readonly context: EnvManifestContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if ((input.context.manifestVersion === 1) !== (input.context.prevManifestSigHashHex === "")) {
    return invalidInput("context prevManifestSigHashHex");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildEnvManifestSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

/**
 * Verifies one environment-manifest signature against an issuer's Ed25519
 * public key (CRYPTO_SPEC §4.3). This is the raw signature check only — head
 * existence, head-time authorization / epoch integrity, digest and env-meta
 * recomputation and prev chaining are the history-based checks in
 * `verifyDistributedEnvManifest` (manifest-verify.ts).
 */
export async function verifyEnvManifestSignature(input: {
  readonly context: EnvManifestContext;
  readonly signatureHex: string;
  readonly issuerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildEnvManifestSignedBytes(input.context),
    input.signatureHex,
    input.issuerPublicKey,
    {
      kind: "EnvManifestInvalid",
      reason: "signature-invalid",
    },
  );
}
