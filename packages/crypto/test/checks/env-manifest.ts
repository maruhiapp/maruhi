// Checks for CRYPTO_SPEC §4.3 (the environment manifest).
// Ed25519 is an RFC 8032 deterministic signature, so the signing direction is
// verified byte-for-byte against the vectors too.
// For the verification-rule kind (kind = "authorization"), pin that "the
// signature is valid but is rejected by the §4.3 / §6.3 history verification
// with expected_reason" via verifyDistributedEnvManifest against the history
// index built by verifyChainWithHistory.
//
// Manifest-specific pinning points (differences from metadata-signature):
// - computeVariablesDigest reproduces the variables_digest LP canonical form
//   (empty set, single, tombstone, byte ascending) (the digests section)
// - Epoch consistency of the checkpoint binding (§4.3 (2)): the two
//   composite-issuance positives (manifest-v1-create / manifest-rotate) pass
//   against the derived chains that carry the boundary checkpoint tuples
//   (checkpoint-boundary-* in chain-entries.json), while the same data
//   against the canonical chain lacking a checkpoint is rejected by the
//   composite-head-without-checkpoint-* negatives. Also negatives: failing
//   the exact-match binding (checkpoint-binding-mismatch), equivocation by
//   differing tuples on the same coordinate, and consistency rule 1
//   (checkpoint-regressed)
// - epoch-regression (an advanced manifestVersion stamped with the old
//   epoch after a rotate) is rejected under predecessor-included
//   verification — the core negative of this mechanism
// - digest-* (missing, tombstone hidden, order violation) is rejected by
//   recomputation over the verify-side set
// - Rejection of a false attestation whose tuple epoch field contradicts
//   the manifest content (hash does match) is pinned with a runtime-signed
//   chain (bindingEpochChecks — an implementation that only compares hashes
//   fails here)

import type {
  ChainEntry,
  ChainHistoryIndex,
  EnvManifestContext,
  ManifestInvalidReason,
  UnsignedChainEntry,
  VariablesDigestEntry,
} from "../../src/index.ts";
import {
  buildEnvManifestSignedBytes,
  computeChainEntryHash,
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signChainEntry,
  signEnvManifest,
  verifyChainWithHistory,
  verifyDistributedEnvManifest,
  verifyEnvManifestSignature,
} from "../../src/index.ts";
import manifestVectors from "../../test-vectors/env-manifest.json" with { type: "json" };
import { testEnvironmentId, testProjectId, testUserId, testVariableId } from "../support/fixture.ts";;
import { canonicalHistory, extendedVectorChainHistory } from "./chain-history.ts";
import {
  importVectorSigner,
  typedEntries,
  vectorEnvironmentDeks,
  vectorKeys,
} from "./chain-vector.ts";
import { manifestExtendedHistory } from "./manifest-history.ts";
import {
  type CheckResult,
  Checks,
  expectRejectedReason,
  fromHex,
  reasonCoverageChecks,
  toHex,
} from "./support.ts";

interface VectorContext {
  readonly suite: string;
  readonly project_id: string;
  readonly environment_id: string;
  readonly epoch: number;
  readonly manifest_version: number;
  readonly variables_digest_hex: string;
  readonly env_meta_version: number;
  readonly env_meta_sig_hash_hex: string;
  readonly prev_manifest_sig_hash_hex: string;
  readonly issuer_user_id: string;
  readonly chain_head_hash_hex: string;
  readonly chain_head_seq: number;
}

interface VectorEntry {
  readonly variable_id: string;
  readonly status: string;
  readonly meta_version: number;
  readonly meta_sig_hash_hex: string;
}

interface ManifestVector {
  readonly name: string;
  readonly context: VectorContext;
  readonly issuer_key_fingerprint_hex: string;
  readonly entries: readonly VectorEntry[];
  readonly signed_bytes_hex: string;
  readonly signed_bytes_sha256_hex: string;
  readonly signature_hex: string;
  readonly prev_base?: string;
}

interface ManifestNegative {
  readonly name: string;
  readonly kind?: string;
  readonly chain?: string;
  readonly context: VectorContext;
  readonly issuer_key_fingerprint_hex?: string;
  readonly entries?: readonly VectorEntry[];
  readonly verify_signed_bytes_hex?: string;
  readonly signed_bytes_hex?: string;
  readonly signature_hex: string;
  readonly verify_key_hex: string;
  readonly expected_reason?: string;
  readonly predecessor?: {
    readonly base: string;
    readonly signed_bytes_sha256_hex: string;
    readonly epoch: number;
  };
  readonly verify_entries?: readonly VectorEntry[];
  readonly verify_env_meta?: {
    readonly meta_version: number;
    readonly meta_sig_hash_hex: string;
  };
  readonly must_fail: boolean;
}

function contextOf(v: VectorContext): EnvManifestContext {
  return {
    suite: v.suite,
    projectId: testProjectId(v.project_id),
    environmentId: testEnvironmentId(v.environment_id),
    epoch: v.epoch,
    manifestVersion: v.manifest_version,
    variablesDigestHex: v.variables_digest_hex,
    envMetaVersion: v.env_meta_version,
    envMetaSigHashHex: v.env_meta_sig_hash_hex,
    prevManifestSigHashHex: v.prev_manifest_sig_hash_hex,
    issuerUserId: testUserId(v.issuer_user_id),
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

function entriesOf(entries: readonly VectorEntry[]): VariablesDigestEntry[] {
  return entries.map((entry) => ({
    variableId: testVariableId(entry.variable_id),
    status: entry.status as VariablesDigestEntry["status"],
    metaVersion: entry.meta_version,
    metaSigHashHex: entry.meta_sig_hash_hex,
  }));
}

const positives: readonly ManifestVector[] = manifestVectors.vectors;
const byName = new Map(positives.map((v) => [v.name, v]));

function predecessorOf(vector: ManifestVector) {
  if (vector.prev_base === undefined) {
    return undefined;
  }
  const base = byName.get(vector.prev_base);
  return base === undefined
    ? undefined
    : { signedBytesHashHex: base.signed_bytes_sha256_hex, epoch: base.context.epoch };
}

/** The envMeta expectation self-matches the context (the fixture env meta is correct — negatives overwrite it via verify_env_meta). */
function envMetaOf(context: EnvManifestContext) {
  return { metaVersion: context.envMetaVersion, sigHashHex: context.envMetaSigHashHex };
}

/** The digests section: pins the variables_digest LP canonical form (§4.3). */
async function digestChecks(c: Checks): Promise<void> {
  for (const digestCase of manifestVectors.digests) {
    const computed = await computeVariablesDigest("maruhi/v1", entriesOf(digestCase.entries));
    c.push(
      `env-manifest digest ${digestCase.name}`,
      computed.ok && computed.value === digestCase.variables_digest_hex,
      computed.ok ? undefined : JSON.stringify(computed.error),
    );
    // Normalized to canonical form regardless of input order (byte
    // ascending is the function's internal convention)
    const reversed = await computeVariablesDigest(
      "maruhi/v1",
      entriesOf(digestCase.entries.toReversed()),
    );
    c.push(
      `env-manifest digest ${digestCase.name}: order-independent input`,
      reversed.ok && reversed.value === digestCase.variables_digest_hex,
    );
  }
  // A duplicate variable_id violates the "one latest form per variable"
  // invariant = InvalidInput
  const single = manifestVectors.digests.find((d) => d.name === "single-entry");
  if (single !== undefined && single.entries.length === 1) {
    const duplicated = await computeVariablesDigest(
      "maruhi/v1",
      entriesOf([...single.entries, ...single.entries]),
    );
    c.push(
      "env-manifest digest: duplicate variable id rejected",
      !duplicated.ok && duplicated.error.kind === "InvalidInput",
    );
  }
}

/** Discriminativeness of the surrogate boundary and rejection of the numeric/hex boundaries (the split of duties is ruling G of session-34.md). */
async function digestBoundaryChecks(c: Checks): Promise<void> {
  // The surrogate-pair-boundary vector is actually a discriminating pair
  // (UTF-16 code-unit order = JS plain string comparison orders differently
  // from byte ascending). This is the only meta-check of ruling G
  // (session-34.md), so a missing vector is a failure, not a skip (do not
  // leave a shape where a rename or deletion stays green with only fewer
  // PASSes)
  const surrogate = manifestVectors.digests.find((d) => d.name === "surrogate-boundary-order");
  if (surrogate === undefined) {
    c.push(
      "env-manifest digest surrogate-boundary-order: discriminates UTF-16 ordering",
      false,
      "surrogate-boundary-order vector missing",
    );
  } else {
    const canonicalIds = surrogate.entries.map((entry) => entry.variable_id);
    const utf16Sorted = canonicalIds.toSorted();
    c.push(
      "env-manifest digest surrogate-boundary-order: discriminates UTF-16 ordering",
      utf16Sorted.join(" ") !== canonicalIds.join(" "),
    );
  }
  // Rejection of numeric/hex boundaries (the split of duties that JSON
  // vectors do not express is a session-34.md ruling): a non-integer /
  // MAX_SAFE_INTEGER + 1 metaVersion, and same-length uppercase hex (the
  // canonical form is lowercase hex — an implementation that accepts and
  // lowercases would create multiple canonical forms for one value, so
  // rejection is the spec's expected behavior)
  const validEntry: VariablesDigestEntry = {
    variableId: testVariableId("var-bounds-0001"),
    status: "active",
    metaVersion: 1,
    metaSigHashHex: "ab".repeat(32),
  };
  const badEntries: readonly { readonly name: string; readonly entry: VariablesDigestEntry }[] = [
    { name: "fractional meta version", entry: { ...validEntry, metaVersion: 1.5 } },
    {
      name: "unsafe integer meta version",
      entry: { ...validEntry, metaVersion: Number.MAX_SAFE_INTEGER + 1 },
    },
    {
      name: "uppercase meta sig hash",
      entry: { ...validEntry, metaSigHashHex: "AB".repeat(32) },
    },
  ];
  for (const bad of badEntries) {
    const result = await computeVariablesDigest("maruhi/v1", [bad.entry]);
    c.push(
      `env-manifest digest invalid input: ${bad.name}`,
      !result.ok && result.error.kind === "InvalidInput",
    );
  }
}

/** Two checks: the signing direction (deterministic re-signing) and the low-level verification direction. */
async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: EnvManifestContext,
  signatureHex: string,
  issuerKeyFingerprintHex: string,
): Promise<void> {
  // Sign with the issuer's device (user_id, FP) seed (2026-09-19 DK —
  // signers are per-device)
  const signer = await importVectorSigner(context.issuerUserId, issuerKeyFingerprintHex);
  if (signer === null) {
    c.push(`env-manifest ${name}: issuer keys`, false, "signer keys missing or failed to import");
    return;
  }
  const signed = await signEnvManifest({ context, signingKey: signer.privateKey });
  c.push(
    `env-manifest ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyEnvManifestSignature({
    context,
    signatureHex,
    issuerPublicKey: signer.publicKey,
  });
  c.push(`env-manifest ${name}: raw signature verify`, verified.ok);
}

/** Prerequisite chains for verification (name → verified history index). */
type Histories = Readonly<Record<string, ChainHistoryIndex>>;

/**
 * The two composite-issuance positives are verified under checkpoint
 * binding (§4.3 (2)), so the comparison targets are the derived chains that
 * carry the boundary checkpoint tuples. Everything else uses the canonical
 * chain (strict — no tuples).
 */
const POSITIVE_CHAIN: Readonly<Record<string, string>> = {
  "manifest-v1-create": "checkpoint-boundary-create",
  "manifest-rotate": "checkpoint-boundary-rotate",
  // Second-device issuance (2026-09-19 DK): the comparison target is the
  // device-key derived chain (strict path)
  "manifest-second-device-issuer-in-scope": "device-ops",
};

async function vectorChecks(c: Checks, histories: Histories): Promise<void> {
  for (const vector of positives) {
    const history = histories[POSITIVE_CHAIN[vector.name] ?? "canonical"];
    if (history === undefined) {
      c.push(`env-manifest ${vector.name}: history`, false, "history missing");
      continue;
    }
    const context = contextOf(vector.context);
    c.push(
      `env-manifest ${vector.name}: signed bytes construction`,
      toHex(buildEnvManifestSignedBytes(context)) === vector.signed_bytes_hex,
    );
    const hash = await computeEnvManifestSignedBytesHash(context);
    c.push(
      `env-manifest ${vector.name}: signed bytes hash`,
      hash.ok && hash.value === vector.signed_bytes_sha256_hex,
    );
    // Recomputation from the vector's entries (canonical form) matches the
    // signed digest
    const digest = await computeVariablesDigest(context.suite, entriesOf(vector.entries));
    c.push(
      `env-manifest ${vector.name}: digest recomputation`,
      digest.ok && digest.value === context.variablesDigestHex,
    );
    await signAndVerifyChecks(
      c,
      vector.name,
      context,
      vector.signature_hex,
      vector.issuer_key_fingerprint_hex,
    );

    // History-based composite verification (§4.3 / §6.3): predecessor
    // included when prev_base exists. manifest-v1-create / manifest-rotate
    // (the epoch consistency of composite issuance) also pass through here
    const distributed = await verifyDistributedEnvManifest({
      history,
      context,
      issuerKeyFingerprintHex: vector.issuer_key_fingerprint_hex,
      signatureHex: vector.signature_hex,
      entries: entriesOf(vector.entries),
      envMeta: envMetaOf(context),
      predecessor: predecessorOf(vector),
    });
    c.push(
      `env-manifest ${vector.name}: distributed verify`,
      distributed.ok && distributed.value.signedBytesHashHex === vector.signed_bytes_sha256_hex,
      distributed.ok ? undefined : JSON.stringify(distributed.error),
    );
  }
  // Re-confirm the data of the tombstone-including digest (§4.3)
  const del = byName.get("manifest-var-delete");
  c.push(
    "env-manifest manifest-var-delete: digest includes the tombstone",
    del !== undefined && del.entries.some((entry) => entry.status === "deleted"),
  );
}

async function forkChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const branches: readonly ManifestVector[] = manifestVectors.manifest_fork.branches;
  const hashes: string[] = [];
  for (const branch of branches) {
    const context = contextOf(branch.context);
    const result = await verifyDistributedEnvManifest({
      history,
      context,
      issuerKeyFingerprintHex: branch.issuer_key_fingerprint_hex,
      signatureHex: branch.signature_hex,
      entries: entriesOf(branch.entries),
      envMeta: envMetaOf(context),
      predecessor: predecessorOf(branch),
    });
    // Each branch passes all checks on its own (prevention is impossible —
    // the evidence-recording of §14.2-5)
    c.push(`env-manifest fork ${branch.name}: verifies individually`, result.ok);
    if (result.ok) {
      hashes.push(result.value.signedBytesHashHex);
    }
  }
  c.push(
    "env-manifest fork: same coordinate yields distinct hashes",
    hashes.length === 2 && hashes[0] !== hashes[1],
  );
}

/** Verify-side envMeta (unset = the vector context's own env_meta field). */
function verifyEnvMetaOf(negative: ManifestNegative, context: EnvManifestContext) {
  if (negative.verify_env_meta === undefined) {
    return envMetaOf(context);
  }
  return {
    metaVersion: negative.verify_env_meta.meta_version,
    sigHashHex: negative.verify_env_meta.meta_sig_hash_hex,
  };
}

/** Verify-side predecessor (the floor / anchor of the stored previous manifest — unset means no check). */
function predecessorAnchorOf(negative: ManifestNegative) {
  if (negative.predecessor === undefined) {
    return undefined;
  }
  return {
    signedBytesHashHex: negative.predecessor.signed_bytes_sha256_hex,
    epoch: negative.predecessor.epoch,
  };
}

// Exhaustiveness pinning of the reason space (consideration 7 — checked by
// support.ts's reasonCoverageChecks): the Record type enforces sync with the
// union at compile time (same shape as META_REASON_COVERAGE in
// metadata-signature.ts).
const MANIFEST_REASON_COVERAGE: Record<ManifestInvalidReason, true> = {
  "signature-invalid": true,
  "issuer-unknown": true,
  "chain-head-mismatch": true,
  "chain-head-future": true,
  "issuer-not-member-at-head": true,
  "issuer-key-mismatch-at-head": true,
  "issuer-role-insufficient-at-head": true,
  "issuer-environment-out-of-scope-at-head": true,
  "environment-not-created-at-head": true,
  "epoch-not-current-at-head": true,
  "checkpoint-binding-mismatch": true,
  "checkpoint-equivocation": true,
  "checkpoint-regressed": true,
  "env-meta-mismatch": true,
  "variables-digest-mismatch": true,
  "prev-shape-mismatch": true,
  "prev-hash-mismatch": true,
  "epoch-regressed": true,
};

/** Verification-rule negative: the signature is valid but history verification rejects it with expected_reason. */
async function ruleNegativeCheck(
  c: Checks,
  negative: ManifestNegative,
  histories: Histories,
  exercised: Set<ManifestInvalidReason>,
): Promise<void> {
  const chainHistory = histories[negative.chain ?? "canonical"];
  if (chainHistory === undefined) {
    c.push(
      `env-manifest rule negative: ${negative.name}`,
      false,
      `unknown chain ${negative.chain}`,
    );
    return;
  }
  const context = contextOf(negative.context);
  const result = await verifyDistributedEnvManifest({
    history: chainHistory,
    context,
    issuerKeyFingerprintHex: negative.issuer_key_fingerprint_hex ?? "",
    signatureHex: negative.signature_hex,
    // verify_entries = the set the verify side recomputes with (expresses
    // missing / tombstone-hidden / order-violating forms). Unset = the
    // vector's canonical set
    entries: entriesOf(negative.verify_entries ?? negative.entries ?? []),
    envMeta: verifyEnvMetaOf(negative, context),
    predecessor: predecessorAnchorOf(negative),
  });
  expectRejectedReason(
    c,
    `env-manifest rule negative: ${negative.name}`,
    !result.ok && result.error.kind === "EnvManifestInvalid" ? result.error.reason : undefined,
    negative.expected_reason,
    exercised,
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

/** Tamper/transplant negative: canonicalization reproduces the vector's verify-side byte string, and the original signature fails. */
async function tamperNegativeCheck(
  c: Checks,
  negative: ManifestNegative,
  exercised: Set<ManifestInvalidReason>,
): Promise<void> {
  const context = contextOf(negative.context);
  const bytesMatch =
    toHex(buildEnvManifestSignedBytes(context)) === negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`env-manifest negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const result = await verifyEnvManifestSignature({
    context,
    signatureHex: negative.signature_hex,
    issuerPublicKey: key.value,
  });
  expectRejectedReason(
    c,
    `env-manifest negative: ${negative.name}`,
    bytesMatch && !result.ok && result.error.kind === "EnvManifestInvalid"
      ? result.error.reason
      : undefined,
    "signature-invalid",
    exercised,
  );
}

async function negativeChecks(
  c: Checks,
  histories: Histories,
  exercised: Set<ManifestInvalidReason>,
): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of manifestVectors.negative as readonly ManifestNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, histories, exercised);
    } else {
      await tamperNegativeCheck(c, negative, exercised);
    }
  }
  // Pin the kind vocabulary (a third value would escape both sieves)
  c.push(
    "env-manifest negative: kind vocabulary is exhaustive",
    [...seenKinds].every((kind) => kind === "signature" || kind === "authorization"),
  );
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    c.push("env-manifest invalid input: base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const badContexts: readonly { name: string; context: EnvManifestContext }[] = [
    { name: "bad epoch", context: { ...baseContext, epoch: 0 } },
    { name: "bad manifest version", context: { ...baseContext, manifestVersion: 0 } },
    { name: "bad env meta version", context: { ...baseContext, envMetaVersion: 0 } },
    { name: "bad head seq", context: { ...baseContext, chainHeadSeq: 0 } },
    // Numeric boundary: §2.1 decimal-stringification is non-negative safe
    // integers only
    { name: "fractional epoch", context: { ...baseContext, epoch: 1.5 } },
    {
      name: "unsafe integer manifest version",
      context: { ...baseContext, manifestVersion: Number.MAX_SAFE_INTEGER + 1 },
    },
    // Same-length uppercase hex (the canonical form is lowercase hex)
    {
      name: "uppercase digest",
      context: { ...baseContext, variablesDigestHex: "AB".repeat(32) },
    },
    {
      name: "uppercase head hash",
      context: { ...baseContext, chainHeadHashHex: "AB".repeat(32) },
    },
    { name: "short digest", context: { ...baseContext, variablesDigestHex: "abcd" } },
    { name: "short env meta hash", context: { ...baseContext, envMetaSigHashHex: "abcd" } },
    { name: "short prev hash", context: { ...baseContext, prevManifestSigHashHex: "abcd" } },
    { name: "short head hash", context: { ...baseContext, chainHeadHashHex: "abcd" } },
    { name: "empty suite", context: { ...baseContext, suite: "" } },
    { name: "empty project id", context: { ...baseContext, projectId: testProjectId("")} },
    { name: "empty environment id", context: { ...baseContext, environmentId: testEnvironmentId("")} },
    { name: "empty issuer", context: { ...baseContext, issuerUserId: testUserId("")} },
  ];
  for (const bad of badContexts) {
    const signed = await signEnvManifest({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyEnvManifestSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
      issuerPublicKey: pair.publicKey,
    });
    c.push(
      `env-manifest invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  // A check only on the signing side (the verify side instead rejects
  // asymmetrically with a reason code — same shape as meta-sign)
  const coupledPrev = await signEnvManifest({
    context: { ...baseContext, manifestVersion: 1, prevManifestSigHashHex: "ab".repeat(32) },
    signingKey: pair.privateKey,
  });
  c.push(
    "env-manifest invalid input: sign rejects v1 with non-empty prev",
    !coupledPrev.ok && coupledPrev.error.kind === "InvalidInput",
  );
  const shortSignature = await verifyEnvManifestSignature({
    context: baseContext,
    signatureHex: "ab".repeat(63),
    issuerPublicKey: pair.publicKey,
  });
  c.push(
    "env-manifest invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    return;
  }
  const context = contextOf(base.context);
  const signer = await generateSigningKeyPair();
  const signed = await signEnvManifest({ context, signingKey: signer.privateKey });
  if (!signed.ok) {
    c.push("env-manifest: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyEnvManifestSignature({
    context,
    signatureHex: signed.value,
    issuerPublicKey: signer.publicKey,
  });
  c.push("env-manifest: roundtrip", verified.ok);

  const other = await generateSigningKeyPair();
  const wrongKey = await verifyEnvManifestSignature({
    context,
    signatureHex: signed.value,
    issuerPublicKey: other.publicKey,
  });
  c.push("env-manifest: roundtrip wrong key rejected", !wrongKey.ok);

  const wrongContext = await verifyEnvManifestSignature({
    context: { ...context, epoch: context.epoch + 1 },
    signatureHex: signed.value,
    issuerPublicKey: signer.publicKey,
  });
  c.push("env-manifest: roundtrip wrong context rejected", !wrongContext.ok);
}

/**
 * Rejection of a false attestation whose tuple epoch field contradicts the
 * manifest content (the hash does match). A shape vectors cannot express
 * (the tuple epoch is fixed by the chain consensus rules to the epoch
 * current at entry time, so producing a contradiction requires building a
 * chain that "re-attests the old manifest's hash under the new epoch after
 * a rotate") is pinned with a runtime-signed chain of vector keys: an
 * implementation that does not compare **both** (epoch, hash) — one that
 * only compares hashes — fails here.
 */
/**
 * Material for bindingEpochChecks: canonical chain seq 1-3 (through
 * create_environment) + rotate (epoch 2) + a false-attestation checkpoint
 * of "epoch 2, manifestVersion 1, hash(manifest-v1-create)", assembled and
 * verified with runtime signing of vector keys. Under the chain consensus
 * rules the tuple epoch matches the epoch current at entry time (2), so it
 * is valid.
 */
async function falseAttestationHistory(
  manifestSigHashHex: string,
): Promise<{ ok: true; history: ChainHistoryIndex } | { ok: false; detail: string }> {
  const member = vectorKeys["user-member-0002"];
  const rotateCommitment = vectorEnvironmentDeks["env-prod-0001"]?.["2"]?.dek_commitment_hex;
  const prefix = typedEntries.slice(0, 3);
  const head3 = prefix[prefix.length - 1];
  if (member === undefined || rotateCommitment === undefined || head3 === undefined) {
    return { ok: false, detail: "fixture missing" };
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(member.sig_pub_hex),
    privateSeed: fromHex(member.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    return { ok: false, detail: "key import failed" };
  }
  const actor = {
    userId: testUserId("user-member-0002"),
    keyFingerprintHex: member.key_fingerprint_hex,
  };
  const signEntry = async (entry: UnsignedChainEntry): Promise<ChainEntry> => {
    const signed = await signChainEntry({ entry, signingKey: pair.value.privateKey });
    if (!signed.ok) {
      throw new Error("chain entry signing failed");
    }
    return signed.value;
  };
  const rotate = await signEntry({
    suite: "maruhi/v1",
    seq: 4,
    prevHashHex: await computeChainEntryHash(head3),
    actor,
    timestampMs: head3.timestampMs + 1000,
    op: "rotate_epoch",
    payload: {
      environmentId: testEnvironmentId("env-prod-0001"),
      newEpoch: 2,
      reason: "scheduled",
      dekCommitmentHex: rotateCommitment,
    },
  });
  const falseAttestation = await signEntry({
    suite: "maruhi/v1",
    seq: 5,
    prevHashHex: await computeChainEntryHash(rotate),
    actor,
    timestampMs: head3.timestampMs + 2000,
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: testEnvironmentId("env-prod-0001"),
          epoch: 2,
          manifestVersion: 1,
          manifestSigHashHex,
          // The tuple content is unverifiable by chain verification (§6.2)
          // — a formally valid 64 hex
          valuesDigestHex: "ab".repeat(32),
        },
      ],
      auditHeadHashHex: "",
    },
  });
  const verified = await verifyChainWithHistory([...prefix, rotate, falseAttestation]);
  if (!verified.ok) {
    return { ok: false, detail: JSON.stringify(verified.error) };
  }
  return { ok: true, history: verified.value.history };
}

async function bindingEpochChecks(c: Checks): Promise<void> {
  const mv1 = byName.get("manifest-v1-create");
  if (mv1 === undefined) {
    c.push("env-manifest binding-epoch: chain verifies", false, "fixture missing");
    return;
  }
  const built = await falseAttestationHistory(mv1.signed_bytes_sha256_hex);
  c.push(
    "env-manifest binding-epoch: chain verifies",
    built.ok,
    built.ok ? undefined : built.detail,
  );
  if (!built.ok) {
    return;
  }
  const context = contextOf(mv1.context);
  const result = await verifyDistributedEnvManifest({
    history: built.history,
    context,
    issuerKeyFingerprintHex: mv1.issuer_key_fingerprint_hex,
    signatureHex: mv1.signature_hex,
    entries: entriesOf(mv1.entries),
    envMeta: envMetaOf(context),
  });
  c.push(
    "env-manifest binding-epoch: hash match with epoch mismatch is rejected",
    !result.ok &&
      result.error.kind === "EnvManifestInvalid" &&
      result.error.reason === "checkpoint-binding-mismatch",
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

export async function envManifestChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const histories: Histories = {
    canonical: await canonicalHistory(),
    "tenure-extension": await manifestExtendedHistory(),
    "checkpoint-boundary-create": await extendedVectorChainHistory("checkpoint-boundary-create"),
    "checkpoint-boundary-rotate": await extendedVectorChainHistory("checkpoint-boundary-rotate"),
    "checkpoint-boundary-equivocation": await extendedVectorChainHistory(
      "checkpoint-boundary-equivocation",
    ),
    "device-ops": await extendedVectorChainHistory("device-ops"),
  };
  const canonical = histories["canonical"];
  if (canonical === undefined) {
    throw new Error("canonical history missing");
  }
  const exercised = new Set<ManifestInvalidReason>();
  await digestChecks(c);
  await digestBoundaryChecks(c);
  await vectorChecks(c, histories);
  await forkChecks(c, canonical);
  await negativeChecks(c, histories, exercised);
  await bindingEpochChecks(c);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  reasonCoverageChecks(c, "env-manifest", MANIFEST_REASON_COVERAGE, exercised);
  return c.results;
}
