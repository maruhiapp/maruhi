// CRYPTO_SPEC §4.1(値の書き込み署名)のチェック。
// Ed25519 は RFC 8032 の決定論的署名なので、署名方向もベクターと完全一致で検証する。
// 検証規則系(kind = "authorization")は「署名は有効だが §6.3 の履歴検証で
// expected_reason により拒否される」ことを、verifyChainWithHistory で構築した
// 履歴索引に対する verifyDistributedValue で固定する。

import type { ChainHistoryIndex, ValueSignatureContext } from "../../src/index.ts";
import {
  buildValueSignedBytes,
  computeValueSignedBytesHash,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signValue,
  verifyDistributedValue,
  verifyValueSignature,
} from "../../src/index.ts";
import valueVectors from "../../test-vectors/value-signature.json" with { type: "json" };
import { canonicalHistory, extendedHistory } from "./chain-history.ts";
import { vectorKeys } from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

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

async function vectorChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  for (const vector of positives) {
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

    // 署名方向: writer の seed で署名し期待署名と一致(Ed25519 は決定論的)
    const keys = vectorKeys[vector.context.writer_user_id];
    if (keys === undefined) {
      c.push(`value-sig ${vector.name}: writer keys`, false, "writer keys missing");
      continue;
    }
    const pair = await importSigningKeyPair({
      publicKey: fromHex(keys.sig_pub_hex),
      privateSeed: fromHex(keys.sig_sk_seed_hex),
    });
    if (!pair.ok) {
      c.push(`value-sig ${vector.name}: writer keys`, false, "key import failed");
      continue;
    }
    const signed = await signValue({ context, signingKey: pair.value.privateKey });
    c.push(
      `value-sig ${vector.name}: deterministic re-sign matches vector`,
      signed.ok && signed.value === vector.signature_hex,
    );

    // 低水準の検証方向
    const publicKey = await importSigningPublicKey(fromHex(keys.sig_pub_hex));
    if (!publicKey.ok) {
      c.push(`value-sig ${vector.name}: verify key import`, false);
      continue;
    }
    const verified = await verifyValueSignature({
      context,
      signatureHex: vector.signature_hex,
      writerPublicKey: publicKey.value,
    });
    c.push(`value-sig ${vector.name}: raw signature verify`, verified.ok);

    // 履歴ベースの複合検証(§6.3): prev_base があれば predecessor 込みで検査
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
    // 分岐は単体では全検証を通る(防止は不能 — §14.2-5 の証拠化)
    c.push(`value-sig fork ${branch.name}: verifies individually`, result.ok);
    if (result.ok) {
      hashes.push(result.value.signedBytesHashHex);
    }
  }
  // 同一座標に異なる signed_bytes ハッシュ = equivocation の機械判定可能な証拠
  c.push(
    "value-sig fork: same coordinate yields distinct hashes",
    hashes.length === 2 && hashes[0] !== hashes[1],
  );
}

async function negativeChecks(
  c: Checks,
  history: ChainHistoryIndex,
  extended: ChainHistoryIndex,
): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of valueVectors.negative as readonly RuleNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      // 署名は有効(verify_reference.mjs が確認)だが、履歴検証が
      // expected_reason で拒否する
      const chainHistory = negative.chain === "tenure-extension" ? extended : history;
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
      c.push(
        `value-sig rule negative: ${negative.name}`,
        !result.ok &&
          result.error.kind === "ValueInvalid" &&
          result.error.reason === negative.expected_reason,
        result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
      );
      continue;
    }
    // 改竄・移植系: 実装の正規化がベクターの検証側バイト列を再現し、元署名が失敗する
    const context = contextOf(negative.context);
    const bytesMatch = toHex(buildValueSignedBytes(context)) === negative.verify_signed_bytes_hex;
    const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
    if (!key.ok) {
      c.push(`value-sig negative: ${negative.name}`, false, "verify key import failed");
      continue;
    }
    const result = await verifyValueSignature({
      context,
      signatureHex: negative.signature_hex,
      writerPublicKey: key.value,
    });
    c.push(
      `value-sig negative: ${negative.name}`,
      bytesMatch &&
        !result.ok &&
        result.error.kind === "ValueInvalid" &&
        result.error.reason === "signature-invalid",
    );
  }
  // kind 語彙の固定(第三の値が導入されると両ふるいから漏れる — session-13 の教訓)
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
  // 署名側だけの結合検査: version 1 に非空 prev を署名させない(検証側は
  // 「有効署名 + prev-shape-mismatch」として理由コードで拒否する非対称)
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
  const extended = await extendedHistory();
  await vectorChecks(c, history);
  await forkChecks(c, history);
  await negativeChecks(c, history, extended);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
