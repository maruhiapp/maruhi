import type { ChainHistoryIndex, HeadAttestationContext } from "../../src/index.ts";
import {
  buildHeadAttestationSignedBytes,
  computeHeadAttestationSignedBytesHash,
  generateSigningKeyPair,
  importSigningPublicKey,
  signHeadAttestation,
  verifyDistributedHeadAttestation,
  verifyHeadAttestationSignature,
} from "../../src/index.ts";
import vectors from "../../test-vectors/head-attestation.json" with { type: "json" };
import { testProjectId, testUserId } from "../support/fixture.ts";
import { canonicalHistory, extendedVectorChainHistory } from "./chain-history.ts";
import { importVectorSigner } from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

interface VectorContext {
  readonly suite: string;
  readonly project_id: string;
  readonly attester_user_id: string;
  readonly chain_head_hash_hex: string;
  readonly chain_head_seq: number;
}

interface AttestationVector {
  readonly name: string;
  readonly chain?: string;
  readonly context: VectorContext;
  readonly attester_key_fingerprint_hex: string;
  readonly signed_bytes_hex: string;
  readonly signed_bytes_sha256_hex: string;
  readonly signature_hex: string;
}

interface AttestationNegative {
  readonly name: string;
  readonly kind?: string;
  readonly chain?: string;
  readonly context: VectorContext;
  readonly attester_key_fingerprint_hex?: string;
  readonly verify_signed_bytes_hex?: string;
  readonly signature_hex: string;
  readonly verify_key_hex?: string;
  readonly expected_reason?: string;
  readonly must_fail: boolean;
}

function contextOf(v: VectorContext): HeadAttestationContext {
  return {
    suite: v.suite,
    projectId: testProjectId(v.project_id),
    attesterUserId: testUserId(v.attester_user_id),
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

const positives: readonly AttestationVector[] = vectors.vectors;

type Histories = Readonly<Record<string, ChainHistoryIndex>>;

function historyFor(
  histories: Histories,
  chain: string | undefined,
): ChainHistoryIndex | undefined {
  return histories[chain ?? "canonical"];
}

async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: HeadAttestationContext,
  signatureHex: string,
  attesterKeyFingerprintHex: string,
): Promise<void> {
  const signer = await importVectorSigner(context.attesterUserId, attesterKeyFingerprintHex);
  if (signer === null) {
    c.push(
      `head-attestation ${name}: attester keys`,
      false,
      "signer keys missing or failed to import",
    );
    return;
  }
  const signed = await signHeadAttestation({ context, signingKey: signer.privateKey });
  c.push(
    `head-attestation ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyHeadAttestationSignature({
    context,
    signatureHex,
    attesterPublicKey: signer.publicKey,
  });
  c.push(`head-attestation ${name}: raw signature verify`, verified.ok);
}

async function vectorChecks(c: Checks, histories: Histories): Promise<void> {
  for (const vector of positives) {
    const history = historyFor(histories, vector.chain);
    if (history === undefined) {
      c.push(`head-attestation ${vector.name}: history`, false, "history missing");
      continue;
    }
    const context = contextOf(vector.context);
    c.push(
      `head-attestation ${vector.name}: signed bytes construction`,
      toHex(buildHeadAttestationSignedBytes(context)) === vector.signed_bytes_hex,
    );
    const hash = await computeHeadAttestationSignedBytesHash(context);
    c.push(
      `head-attestation ${vector.name}: signed bytes hash`,
      hash.ok && hash.value === vector.signed_bytes_sha256_hex,
    );
    await signAndVerifyChecks(
      c,
      vector.name,
      context,
      vector.signature_hex,
      vector.attester_key_fingerprint_hex,
    );

    const distributed = await verifyDistributedHeadAttestation({
      history,
      context,
      attesterKeyFingerprintHex: vector.attester_key_fingerprint_hex,
      signatureHex: vector.signature_hex,
    });
    c.push(
      `head-attestation ${vector.name}: distributed verify`,
      distributed.ok && distributed.value.signedBytesHashHex === vector.signed_bytes_sha256_hex,
      distributed.ok ? undefined : JSON.stringify(distributed.error),
    );
  }
}

function distributionGateChecks(c: Checks, canonical: ChainHistoryIndex): void {
  const removed = positives.find((vector) => vector.name === "removed-attester-in-tenure");
  const basic = positives.find((vector) => vector.name === "basic");
  c.push(
    "head-attestation: removed attester is not a current member (distribution gate)",
    removed !== undefined &&
      canonical.memberStateAt(removed.context.attester_user_id, canonical.headSeq) === undefined &&
      basic !== undefined &&
      canonical.memberStateAt(basic.context.attester_user_id, canonical.headSeq) !== undefined,
  );
}

async function ruleNegativeCheck(
  c: Checks,
  negative: AttestationNegative,
  histories: Histories,
): Promise<void> {
  const history = historyFor(histories, negative.chain);
  if (history === undefined) {
    c.push(
      `head-attestation rule negative: ${negative.name}`,
      false,
      `unknown chain ${negative.chain}`,
    );
    return;
  }
  const result = await verifyDistributedHeadAttestation({
    history,
    context: contextOf(negative.context),
    attesterKeyFingerprintHex: negative.attester_key_fingerprint_hex ?? "",
    signatureHex: negative.signature_hex,
  });
  c.push(
    `head-attestation rule negative: ${negative.name}`,
    !result.ok &&
      result.error.kind === "HeadAttestationInvalid" &&
      result.error.reason === negative.expected_reason,
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

async function tamperNegativeCheck(c: Checks, negative: AttestationNegative): Promise<void> {
  const context = contextOf(negative.context);
  const bytesMatch =
    toHex(buildHeadAttestationSignedBytes(context)) === negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex ?? ""));
  if (!key.ok) {
    c.push(`head-attestation negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const result = await verifyHeadAttestationSignature({
    context,
    signatureHex: negative.signature_hex,
    attesterPublicKey: key.value,
  });
  c.push(
    `head-attestation negative: ${negative.name}`,
    bytesMatch &&
      !result.ok &&
      result.error.kind === "HeadAttestationInvalid" &&
      result.error.reason === "signature-invalid",
  );
}

async function negativeChecks(c: Checks, histories: Histories): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of vectors.negative as readonly AttestationNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, histories);
    } else {
      await tamperNegativeCheck(c, negative);
    }
  }
  c.push(
    "head-attestation negative: kind vocabulary is exhaustive",
    [...seenKinds].every((kind) => kind === "signature" || kind === "authorization"),
  );
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    c.push("head-attestation invalid input: base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const badContexts: readonly { name: string; context: HeadAttestationContext }[] = [
    {
      name: "uppercase head hash",
      context: { ...baseContext, chainHeadHashHex: baseContext.chainHeadHashHex.toUpperCase() },
    },
    { name: "short head hash", context: { ...baseContext, chainHeadHashHex: "abcd" } },
    { name: "zero head seq", context: { ...baseContext, chainHeadSeq: 0 } },
    { name: "non-integer head seq", context: { ...baseContext, chainHeadSeq: 1.5 } },
    {
      name: "unsafe head seq",
      context: { ...baseContext, chainHeadSeq: Number.MAX_SAFE_INTEGER + 2 },
    },
    { name: "empty suite", context: { ...baseContext, suite: "" } },
    { name: "empty project id", context: { ...baseContext, projectId: testProjectId("") } },
    { name: "empty attester", context: { ...baseContext, attesterUserId: testUserId("") } },
  ];
  for (const bad of badContexts) {
    const signed = await signHeadAttestation({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyHeadAttestationSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
      attesterPublicKey: pair.publicKey,
    });
    c.push(
      `head-attestation invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  const shortSignature = await verifyHeadAttestationSignature({
    context: baseContext,
    signatureHex: "ab".repeat(63),
    attesterPublicKey: pair.publicKey,
  });
  c.push(
    "head-attestation invalid input: short signature",
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
  const signed = await signHeadAttestation({ context, signingKey: signer.privateKey });
  if (!signed.ok) {
    c.push("head-attestation: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyHeadAttestationSignature({
    context,
    signatureHex: signed.value,
    attesterPublicKey: signer.publicKey,
  });
  c.push("head-attestation: roundtrip", verified.ok);

  const other = await generateSigningKeyPair();
  const wrongKey = await verifyHeadAttestationSignature({
    context,
    signatureHex: signed.value,
    attesterPublicKey: other.publicKey,
  });
  c.push("head-attestation: roundtrip wrong key rejected", !wrongKey.ok);

  const wrongContext = await verifyHeadAttestationSignature({
    context: { ...context, projectId: testProjectId(`${context.projectId.slice(0, -1)}0`) },
    signatureHex: signed.value,
    attesterPublicKey: signer.publicKey,
  });
  c.push("head-attestation: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function headAttestationChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const canonical = await canonicalHistory();
  const histories: Histories = {
    canonical,
    "device-ops": await extendedVectorChainHistory("device-ops"),
  };
  await vectorChecks(c, histories);
  distributionGateChecks(c, canonical);
  await negativeChecks(c, histories);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
