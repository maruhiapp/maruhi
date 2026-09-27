// Checks for CRYPTO_SPEC §4.1 (the value write signature).
// Ed25519 is an RFC 8032 deterministic signature, so the signing direction is
// verified byte-for-byte against the vectors too.
// For the verification-rule kind (kind = "authorization"), pin that "the
// signature is valid but is rejected by the §6.3 history verification with
// expected_reason" via verifyDistributedValue against the history index built
// by verifyChainWithHistory.

import type {
  ChainHistoryIndex,
  ValueInvalidReason,
  ValueSignatureContext,
} from "../../src/index.ts";
import {
  buildValueSignedBytes,
  computeValueSignedBytesHash,
  generateSigningKeyPair,
  importSigningPublicKey,
  signValue,
  verifyDistributedValue,
  verifyValueSignature,
} from "../../src/index.ts";
import valueVectors from "../../test-vectors/value-signature.json" with { type: "json" };
import { canonicalHistory, extendedHistory, extendedVectorChainHistory } from "./chain-history.ts";
import { importVectorSigner } from "./chain-vector.ts";
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
  readonly variable_id: string;
  readonly version: number;
  readonly nonce_hex: string;
  readonly ciphertext_hex: string;
  readonly prev_value_sig_hash_hex: string;
  readonly writer_user_id: string;
  readonly chain_head_hash_hex: string;
  readonly chain_head_seq: number;
}

interface RuleNegative {
  readonly name: string;
  readonly kind?: string;
  readonly chain?: string;
  readonly context: VectorContext;
  readonly writer_key_fingerprint_hex?: string;
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
  readonly must_fail: boolean;
}

function contextOf(v: VectorContext): ValueSignatureContext {
  return {
    suite: v.suite,
    projectId: v.project_id,
    environmentId: v.environment_id,
    epoch: v.epoch,
    variableId: v.variable_id,
    version: v.version,
    nonceHex: v.nonce_hex,
    ciphertextHex: v.ciphertext_hex,
    prevValueSigHashHex: v.prev_value_sig_hash_hex,
    writerUserId: v.writer_user_id,
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

const positives = valueVectors.vectors;
const byName = new Map(positives.map((v) => [v.name, v]));

/**
 * Comparison chains (name → verified history index): canonical (canonical
 * 24), tenure-extension (the re-add derived chain in value-signature.json),
 * device-ops (the device-key derived chain in chain-entries.json —
 * 2026-09-19 DK). A vector with `chain` unset means canonical
 */
type Histories = Readonly<Record<string, ChainHistoryIndex>>;

function historyFor(
  histories: Histories,
  chain: string | undefined,
): ChainHistoryIndex | undefined {
  return histories[chain ?? "canonical"];
}

/** Two checks: the signing direction (deterministic re-signing) and the low-level verification direction. */
async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: ValueSignatureContext,
  signatureHex: string,
  writerKeyFingerprintHex: string,
): Promise<void> {
  // Signing direction: sign with the writer's device (user_id, FP) seed and
  // match the expected signature (Ed25519 is deterministic)
  const signer = await importVectorSigner(context.writerUserId, writerKeyFingerprintHex);
  if (signer === null) {
    c.push(`value-sig ${name}: writer keys`, false, "signer keys missing or failed to import");
    return;
  }
  const signed = await signValue({ context, signingKey: signer.privateKey });
  c.push(
    `value-sig ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyValueSignature({
    context,
    signatureHex,
    writerPublicKey: signer.publicKey,
  });
  c.push(`value-sig ${name}: raw signature verify`, verified.ok);
}

async function vectorChecks(c: Checks, histories: Histories): Promise<void> {
  for (const vector of positives) {
    const history = historyFor(histories, "chain" in vector ? vector.chain : undefined);
    if (history === undefined) {
      c.push(`value-sig ${vector.name}: history`, false, "history missing");
      continue;
    }
    const context = contextOf(vector.context);
    c.push(
      `value-sig ${vector.name}: signed bytes construction`,
      toHex(buildValueSignedBytes(context)) === vector.signed_bytes_hex,
    );
    const hash = await computeValueSignedBytesHash(context);
    c.push(
      `value-sig ${vector.name}: signed bytes hash`,
      hash.ok && hash.value === vector.signed_bytes_sha256_hex,
    );
    await signAndVerifyChecks(
      c,
      vector.name,
      context,
      vector.signature_hex,
      vector.writer_key_fingerprint_hex,
    );

    // History-based composite verification (§6.3): when prev_base exists,
    // check with the predecessor included
    const base = "prev_base" in vector ? byName.get(vector.prev_base as string) : undefined;
    const distributed = await verifyDistributedValue({
      history,
      context,
      writerKeyFingerprintHex: vector.writer_key_fingerprint_hex,
      signatureHex: vector.signature_hex,
      predecessor:
        base === undefined
          ? undefined
          : { signedBytesHashHex: base.signed_bytes_sha256_hex, epoch: base.context.epoch },
    });
    c.push(
      `value-sig ${vector.name}: distributed verify`,
      distributed.ok && distributed.value.signedBytesHashHex === vector.signed_bytes_sha256_hex,
    );
  }
}

async function forkChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const branches = valueVectors.fork_same_version.branches;
  const predecessorName = branches[0]?.prev_base;
  const predecessor = predecessorName === undefined ? undefined : byName.get(predecessorName);
  const hashes: string[] = [];
  for (const branch of branches) {
    const result = await verifyDistributedValue({
      history,
      context: contextOf(branch.context),
      writerKeyFingerprintHex: branch.writer_key_fingerprint_hex,
      signatureHex: branch.signature_hex,
      predecessor:
        predecessor === undefined
          ? undefined
          : {
              signedBytesHashHex: predecessor.signed_bytes_sha256_hex,
              epoch: predecessor.context.epoch,
            },
    });
    // Each branch passes all checks on its own (prevention is impossible —
    // the evidence-recording of §14.2-5)
    c.push(`value-sig fork ${branch.name}: verifies individually`, result.ok);
    if (result.ok) {
      hashes.push(result.value.signedBytesHashHex);
    }
  }
  // Distinct signed_bytes hashes on the same coordinate = mechanically
  // decidable evidence of equivocation
  c.push(
    "value-sig fork: same coordinate yields distinct hashes",
    hashes.length === 2 && hashes[0] !== hashes[1],
  );
}

// Exhaustiveness pinning of the reason space (consideration 7 — checked by
// support.ts's reasonCoverageChecks): the Record type enforces sync with the
// union at compile time (same shape as META_REASON_COVERAGE in
// metadata-signature.ts).
const VALUE_REASON_COVERAGE: Record<ValueInvalidReason, true> = {
  "signature-invalid": true,
  "writer-unknown": true,
  "chain-head-mismatch": true,
  "chain-head-future": true,
  "writer-not-member-at-head": true,
  "writer-key-mismatch-at-head": true,
  "writer-role-insufficient-at-head": true,
  "writer-environment-out-of-scope-at-head": true,
  "environment-not-created-at-head": true,
  "epoch-not-current-at-head": true,
  "prev-shape-mismatch": true,
  "prev-hash-mismatch": true,
  "epoch-regressed": true,
};

/** Verification-rule negative: the signature is valid but history verification rejects it with expected_reason. */
async function ruleNegativeCheck(
  c: Checks,
  negative: RuleNegative,
  histories: Histories,
  exercised: Set<ValueInvalidReason>,
): Promise<void> {
  const chainHistory = historyFor(histories, negative.chain);
  if (chainHistory === undefined) {
    c.push(`value-sig rule negative: ${negative.name}`, false, `unknown chain ${negative.chain}`);
    return;
  }
  const result = await verifyDistributedValue({
    history: chainHistory,
    context: contextOf(negative.context),
    writerKeyFingerprintHex: negative.writer_key_fingerprint_hex ?? "",
    signatureHex: negative.signature_hex,
    predecessor:
      negative.predecessor === undefined
        ? undefined
        : {
            signedBytesHashHex: negative.predecessor.signed_bytes_sha256_hex,
            epoch: negative.predecessor.epoch,
          },
  });
  expectRejectedReason(
    c,
    `value-sig rule negative: ${negative.name}`,
    !result.ok && result.error.kind === "ValueInvalid" ? result.error.reason : undefined,
    negative.expected_reason,
    exercised,
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

/** Tamper/transplant negative: canonicalization reproduces the vector's verify-side byte string, and the original signature fails. */
async function tamperNegativeCheck(
  c: Checks,
  negative: RuleNegative,
  exercised: Set<ValueInvalidReason>,
): Promise<void> {
  const context = contextOf(negative.context);
  const bytesMatch = toHex(buildValueSignedBytes(context)) === negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`value-sig negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const result = await verifyValueSignature({
    context,
    signatureHex: negative.signature_hex,
    writerPublicKey: key.value,
  });
  expectRejectedReason(
    c,
    `value-sig negative: ${negative.name}`,
    bytesMatch && !result.ok && result.error.kind === "ValueInvalid"
      ? result.error.reason
      : undefined,
    "signature-invalid",
    exercised,
  );
}

async function negativeChecks(
  c: Checks,
  histories: Histories,
  exercised: Set<ValueInvalidReason>,
): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of valueVectors.negative as readonly RuleNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, histories, exercised);
    } else {
      await tamperNegativeCheck(c, negative, exercised);
    }
  }
  // Pin the kind vocabulary (a third value would escape both sieves)
  c.push(
    "value-sig negative: kind vocabulary is exhaustive",
    [...seenKinds].every((kind) => kind === "signature" || kind === "authorization"),
  );
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    c.push("value-sig invalid input: base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const badContexts: readonly { name: string; context: ValueSignatureContext }[] = [
    { name: "bad epoch", context: { ...baseContext, epoch: 0 } },
    { name: "bad version", context: { ...baseContext, version: 0 } },
    { name: "bad head seq", context: { ...baseContext, chainHeadSeq: 0 } },
    { name: "short nonce hex", context: { ...baseContext, nonceHex: "ab" } },
    {
      name: "uppercase ciphertext hex",
      context: { ...baseContext, ciphertextHex: baseContext.ciphertextHex.toUpperCase() },
    },
    { name: "short ciphertext", context: { ...baseContext, ciphertextHex: "ab".repeat(15) } },
    { name: "short prev hash", context: { ...baseContext, prevValueSigHashHex: "abcd" } },
    { name: "short head hash", context: { ...baseContext, chainHeadHashHex: "abcd" } },
    { name: "empty suite", context: { ...baseContext, suite: "" } },
    { name: "empty project id", context: { ...baseContext, projectId: "" } },
    { name: "empty environment id", context: { ...baseContext, environmentId: "" } },
    // An empty variable id is rejected on par with the other coordinates
    // (same expectation as meta-sig's "empty variable id")
    { name: "empty variable id", context: { ...baseContext, variableId: "" } },
    { name: "empty writer", context: { ...baseContext, writerUserId: "" } },
  ];
  for (const bad of badContexts) {
    const signed = await signValue({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyValueSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
      writerPublicKey: pair.publicKey,
    });
    c.push(
      `value-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  // A check only on the signing side: never sign a version 1 with a non-
  // empty prev (the verify side instead rejects asymmetrically with a reason
  // code, "valid signature + prev-shape-mismatch")
  const coupled = await signValue({
    context: { ...baseContext, version: 1, prevValueSigHashHex: "ab".repeat(32) },
    signingKey: pair.privateKey,
  });
  c.push(
    "value-sig invalid input: sign rejects v1 with non-empty prev",
    !coupled.ok && coupled.error.kind === "InvalidInput",
  );
  const shortSignature = await verifyValueSignature({
    context: baseContext,
    signatureHex: "ab".repeat(63),
    writerPublicKey: pair.publicKey,
  });
  c.push(
    "value-sig invalid input: short signature",
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
  const signed = await signValue({ context, signingKey: signer.privateKey });
  if (!signed.ok) {
    c.push("value-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyValueSignature({
    context,
    signatureHex: signed.value,
    writerPublicKey: signer.publicKey,
  });
  c.push("value-sig: roundtrip", verified.ok);

  const other = await generateSigningKeyPair();
  const wrongKey = await verifyValueSignature({
    context,
    signatureHex: signed.value,
    writerPublicKey: other.publicKey,
  });
  c.push("value-sig: roundtrip wrong key rejected", !wrongKey.ok);

  const wrongContext = await verifyValueSignature({
    context: { ...context, variableId: "var-transplanted-9999" },
    signatureHex: signed.value,
    writerPublicKey: signer.publicKey,
  });
  c.push("value-sig: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function valueSignatureChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  const histories: Histories = {
    canonical: history,
    "tenure-extension": await extendedHistory(),
    "device-ops": await extendedVectorChainHistory("device-ops"),
  };
  const exercised = new Set<ValueInvalidReason>();
  await vectorChecks(c, histories);
  await forkChecks(c, history);
  await negativeChecks(c, histories, exercised);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  reasonCoverageChecks(c, "value-sig", VALUE_REASON_COVERAGE, exercised);
  return c.results;
}
