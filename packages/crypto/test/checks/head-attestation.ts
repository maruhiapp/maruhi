// CRYPTO_SPEC §6.6(ヘッド申告)のチェック。
// Ed25519 は RFC 8032 の決定論的署名なので、署名方向もベクターと完全一致で検証する。
// 検証規則系(kind = "authorization")は「署名は有効だが §6.6 / §6.3-2 の履歴検証で
// expected_reason により拒否される」ことを、verifyChainWithHistory で構築した
// 履歴索引に対する verifyDistributedHeadAttestation で固定する。
//
// 申告固有の固定点(value / meta との差):
// - removed-attester-in-tenure は **positive**(削除済み attester の在籍区間内
//   過去申告は検証を通る)だが、attester は現メンバーでない — 配布・照合の
//   選別ゲート(§6.6 (1) 前半)が実装テスト側の責務であることをここで固定する
// - 必要 role の下限は reader(reader-attestation が positive)
// - chain-head-mismatch は「拒否して捨てる」ではなく照合 (a) の硬い証拠の入口
//   (扱いは CLI 実装テストの領分 — ここでは理由コードの固定まで)

import type { ChainHistoryIndex, HeadAttestationContext } from "../../src/index.ts";
import {
  buildHeadAttestationSignedBytes,
  computeHeadAttestationSignedBytesHash,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signHeadAttestation,
  verifyDistributedHeadAttestation,
  verifyHeadAttestationSignature,
} from "../../src/index.ts";
import vectors from "../../test-vectors/head-attestation.json" with { type: "json" };
import { canonicalHistory } from "./chain-history.ts";
import { vectorKeys } from "./chain-vector.ts";
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
  readonly context: VectorContext;
  readonly attester_key_fingerprint_hex: string;
  readonly signed_bytes_hex: string;
  readonly signed_bytes_sha256_hex: string;
  readonly signature_hex: string;
}

interface AttestationNegative {
  readonly name: string;
  readonly kind?: string;
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
    projectId: v.project_id,
    attesterUserId: v.attester_user_id,
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

const positives: readonly AttestationVector[] = vectors.vectors;

/** 署名方向(決定論的再署名)と低水準の検証方向の 2 チェック。 */
async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: HeadAttestationContext,
  signatureHex: string,
): Promise<void> {
  const keys = vectorKeys[context.attesterUserId];
  if (keys === undefined) {
    c.push(`head-attestation ${name}: attester keys`, false, "attester keys missing");
    return;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  const publicKey = await importSigningPublicKey(fromHex(keys.sig_pub_hex));
  if (!pair.ok || !publicKey.ok) {
    c.push(`head-attestation ${name}: attester keys`, false, "key import failed");
    return;
  }
  const signed = await signHeadAttestation({ context, signingKey: pair.value.privateKey });
  c.push(
    `head-attestation ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyHeadAttestationSignature({
    context,
    signatureHex,
    attesterPublicKey: publicKey.value,
  });
  c.push(`head-attestation ${name}: raw signature verify`, verified.ok);
}

async function vectorChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  for (const vector of positives) {
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
    await signAndVerifyChecks(c, vector.name, context, vector.signature_hex);

    // 履歴ベースの複合検証(§6.6): removed-attester-in-tenure も positive
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
  // 配布対象の選別ゲート(§6.6 (1) 前半 = 現メンバー検査)の材料の固定:
  // removed-attester-in-tenure の attester は検証は通るが現メンバーではない
  const removed = positives.find((vector) => vector.name === "removed-attester-in-tenure");
  const basic = positives.find((vector) => vector.name === "basic");
  c.push(
    "head-attestation: removed attester is not a current member (distribution gate)",
    removed !== undefined &&
      history.memberStateAt(removed.context.attester_user_id, history.headSeq) === undefined &&
      basic !== undefined &&
      history.memberStateAt(basic.context.attester_user_id, history.headSeq) !== undefined,
  );
}

/** 検証規則系 negative: 署名は有効だが履歴検証が expected_reason で拒否する。 */
async function ruleNegativeCheck(
  c: Checks,
  negative: AttestationNegative,
  history: ChainHistoryIndex,
): Promise<void> {
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

/** 改竄・移植系 negative: 正規化がベクターの検証側バイト列を再現し、元署名が失敗する。 */
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

async function negativeChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of vectors.negative as readonly AttestationNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, history);
    } else {
      await tamperNegativeCheck(c, negative);
    }
  }
  // kind 語彙の固定(第三の値が導入されると両ふるいから漏れる — session-13 の教訓)
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
    { name: "empty project id", context: { ...baseContext, projectId: "" } },
    { name: "empty attester", context: { ...baseContext, attesterUserId: "" } },
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
    context: { ...context, projectId: `${context.projectId.slice(0, -1)}0` },
    signatureHex: signed.value,
    attesterPublicKey: signer.publicKey,
  });
  c.push("head-attestation: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function headAttestationChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  await vectorChecks(c, history);
  await negativeChecks(c, history);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
