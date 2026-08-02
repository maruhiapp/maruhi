// CRYPTO_SPEC §5.1(DEK ラップの登録署名)のチェック。
// Ed25519 は RFC 8032 の決定論的署名なので、署名方向もベクターと完全一致で検証する。
// negative は「ベクターの verify_signed_bytes_hex を実装の正規化が再現し、
// その上で元の署名が検証に失敗する」ことを固定する(改竄・座標移植・鍵不一致・
// suite 不一致)。

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
}

function contextOf(v: VectorContext): DekWrapSignatureContext {
  return {
    suite: v.suite,
    projectId: v.project_id,
    environmentId: v.environment_id,
    epoch: v.epoch,
    recipientUserId: v.recipient_user_id,
    recipientEncPubHex: v.recipient_enc_pub_hex,
    encHex: v.enc_hex,
    ciphertextHex: v.ciphertext_hex,
  };
}

async function vectorChecks(c: Checks): Promise<void> {
  // 正規化バイト列がベクターと一致(ドメイン文字列 = suite の束縛を含む)
  c.push(
    "dek-wrap-sig: signed bytes construction",
    toHex(buildDekWrapSignatureBytes(contextOf(base))) === base.signed_bytes_hex,
  );

  // 署名方向: ベクターの署名者 seed で署名し、期待署名と一致(Ed25519 は決定論的)
  const signer = await importSigningKeyPair({
    publicKey: fromHex(vectors.signer.sig_pub_hex),
    privateSeed: fromHex(vectors.signer.sig_sk_seed_hex),
  });
  if (!signer.ok) {
    c.push("dek-wrap-sig: vector sign", false, "signer key import failed");
    return;
  }
  const signed = await signDekWrap({
    context: contextOf(base),
    signingKey: signer.value.privateKey,
  });
  c.push(
    "dek-wrap-sig: vector sign == signature",
    signed.ok && signed.value === base.signature_hex,
  );

  // 検証方向: 正例が通る
  const verifyKey = await importSigningPublicKey(fromHex(vectors.signer.sig_pub_hex));
  if (!verifyKey.ok) {
    c.push("dek-wrap-sig: vector verify", false, "verify key import failed");
    return;
  }
  const verified = await verifyDekWrapSignature({
    context: contextOf(base),
    signatureHex: base.signature_hex,
    signerPublicKey: verifyKey.value,
  });
  c.push("dek-wrap-sig: vector verify", verified.ok);
}

async function negativeChecks(c: Checks): Promise<void> {
  for (const negative of vectors.negative) {
    const context = contextOf(negative.context);
    // 実装の正規化がベクターの検証側バイト列を再現すること
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
  // epoch が非負の安全な整数でない / hex が大文字・長さ不正なら InvalidInput
  const badContexts: readonly { name: string; context: DekWrapSignatureContext }[] = [
    { name: "bad epoch", context: { ...contextOf(base), epoch: Number.NaN } },
    {
      name: "uppercase ciphertext hex",
      context: { ...contextOf(base), ciphertextHex: base.ciphertext_hex.toUpperCase() },
    },
    { name: "short enc hex", context: { ...contextOf(base), encHex: "ab" } },
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
  // 署名 hex の長さ不正も InvalidInput(64 バイト固定)
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

  // 別の鍵では検証失敗
  const other = await generateSigningKeyPair();
  const wrongKey = await verifyDekWrapSignature({
    context: contextOf(base),
    signatureHex: signed.value,
    signerPublicKey: other.publicKey,
  });
  c.push("dek-wrap-sig: roundtrip wrong key rejected", !wrongKey.ok);

  // 文脈差し替えは検証失敗(座標移植の実装側再確認)
  const wrongContext = await verifyDekWrapSignature({
    context: { ...contextOf(base), projectId: "proj-other" },
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
