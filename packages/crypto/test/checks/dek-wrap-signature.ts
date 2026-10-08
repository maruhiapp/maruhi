// Checks for CRYPTO_SPEC §5.1 (the DEK wrap registration signature).
// Ed25519 is the RFC 8032 deterministic signature, so the sign direction is
// also verified to match the vector exactly.
// The negatives pin that "the implementation's canonicalization reproduces the
// vector's verify_signed_bytes_hex, and on top of that the original signature
// fails verification" (tampering, coordinate transplants, key mismatch, suite
// mismatch).

import {
  buildDekWrapSignatureBytes,
  type DekWrapSignatureContext,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signDekWrap,
  verifyDekWrapSignature,
} from "../../src/index.ts";
import vectors from "../../test-vectors/dek-wrap-signature.json" with { type: "json" };
import { testEnvironmentId, testProjectId, testUserId } from "../support/fixture.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = vectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("dek-wrap-signature.json: basic vector missing");
}
const base = baseVector;

interface VectorContext {
  readonly suite: string;
  readonly project_id: string;
  readonly environment_id: string;
  readonly epoch: number;
  readonly recipient_user_id: string;
  readonly recipient_enc_pub_hex: string;
  readonly enc_hex: string;
  readonly ciphertext_hex: string;
  readonly signer_user_id: string;
}

function contextOf(v: VectorContext): DekWrapSignatureContext {
  return {
    suite: v.suite,
    projectId: testProjectId(v.project_id),
    environmentId: testEnvironmentId(v.environment_id),
    epoch: v.epoch,
    recipientUserId: testUserId(v.recipient_user_id),
    recipientEncPubHex: v.recipient_enc_pub_hex,
    encHex: v.enc_hex,
    ciphertextHex: v.ciphertext_hex,
    signerUserId: testUserId(v.signer_user_id),
  };
}

async function vectorChecks(c: Checks): Promise<void> {
  const signer = await importSigningKeyPair({
    publicKey: fromHex(vectors.signer.sig_pub_hex),
    privateSeed: fromHex(vectors.signer.sig_sk_seed_hex),
  });
  const verifyKey = await importSigningPublicKey(fromHex(vectors.signer.sig_pub_hex));
  if (!signer.ok || !verifyKey.ok) {
    c.push("dek-wrap-sig: vector keys", false, "signer key import failed");
    return;
  }
  // The positive cases cover both the member class (basic) and the server
  // class (server-basic — the server key FP in the recipient position) (§5.1 /
  // §9). Ed25519 is deterministic, so the sign direction also matches exactly
  for (const vector of vectors.vectors) {
    // The canonical byte string matches the vector (including the domain string = suite binding)
    c.push(
      `dek-wrap-sig: ${vector.name} signed bytes construction`,
      toHex(buildDekWrapSignatureBytes(contextOf(vector))) === vector.signed_bytes_hex,
    );
    const signed = await signDekWrap({
      context: contextOf(vector),
      signingKey: signer.value.privateKey,
    });
    c.push(
      `dek-wrap-sig: ${vector.name} sign == signature`,
      signed.ok && signed.value === vector.signature_hex,
    );
    const verified = await verifyDekWrapSignature({
      context: contextOf(vector),
      signatureHex: vector.signature_hex,
      signerPublicKey: verifyKey.value,
    });
    c.push(`dek-wrap-sig: ${vector.name} verify`, verified.ok);
  }
}

async function negativeChecks(c: Checks): Promise<void> {
  for (const negative of vectors.negative) {
    const context = contextOf(negative.context);
    // The implementation's canonicalization reproduces the vector's verify-side byte string
    const bytesMatch =
      toHex(buildDekWrapSignatureBytes(context)) === negative.verify_signed_bytes_hex;
    const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
    if (!key.ok) {
      c.push(`dek-wrap-sig negative: ${negative.name}`, false, "verify key import failed");
      continue;
    }
    const result = await verifyDekWrapSignature({
      context,
      signatureHex: negative.signature_hex,
      signerPublicKey: key.value,
    });
    c.push(
      `dek-wrap-sig negative: ${negative.name}`,
      bytesMatch && !result.ok && result.error.kind === "DekWrapSignatureInvalid",
    );
  }
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const pair = await generateSigningKeyPair();
  // A non-(non-negative safe integer) epoch / uppercase or wrong-length hex is InvalidInput
  const badContexts: readonly { name: string; context: DekWrapSignatureContext }[] = [
    { name: "bad epoch", context: { ...contextOf(base), epoch: Number.NaN } },
    {
      name: "uppercase ciphertext hex",
      context: { ...contextOf(base), ciphertextHex: base.ciphertext_hex.toUpperCase() },
    },
    { name: "short enc hex", context: { ...contextOf(base), encHex: "ab" } },
    { name: "empty suite", context: { ...contextOf(base), suite: "" } },
    { name: "empty signer", context: { ...contextOf(base), signerUserId: testUserId("") } },
  ];
  for (const bad of badContexts) {
    const signed = await signDekWrap({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyDekWrapSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
      signerPublicKey: pair.publicKey,
    });
    c.push(
      `dek-wrap-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  // A wrong-length signature hex is also InvalidInput (fixed at 64 bytes)
  const shortSignature = await verifyDekWrapSignature({
    context: contextOf(base),
    signatureHex: "ab".repeat(63),
    signerPublicKey: pair.publicKey,
  });
  c.push(
    "dek-wrap-sig invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  const signer = await generateSigningKeyPair();
  const signed = await signDekWrap({ context: contextOf(base), signingKey: signer.privateKey });
  if (!signed.ok) {
    c.push("dek-wrap-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyDekWrapSignature({
    context: contextOf(base),
    signatureHex: signed.value,
    signerPublicKey: signer.publicKey,
  });
  c.push("dek-wrap-sig: roundtrip", verified.ok);

  // Verification fails under a different key
  const other = await generateSigningKeyPair();
  const wrongKey = await verifyDekWrapSignature({
    context: contextOf(base),
    signatureHex: signed.value,
    signerPublicKey: other.publicKey,
  });
  c.push("dek-wrap-sig: roundtrip wrong key rejected", !wrongKey.ok);

  // Swapping the context fails verification (implementation-side re-confirmation of coordinate transplants)
  const wrongContext = await verifyDekWrapSignature({
    context: { ...contextOf(base), projectId: testProjectId("proj-other") },
    signatureHex: signed.value,
    signerPublicKey: signer.publicKey,
  });
  c.push("dek-wrap-sig: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function dekWrapSignatureChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorChecks(c);
  await negativeChecks(c);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
