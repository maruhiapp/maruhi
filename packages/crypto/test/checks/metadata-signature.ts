// CRYPTO_SPEC §4.2(変数・環境メタデータの署名付きステートメント)のチェック。
// Ed25519 は RFC 8032 の決定論的署名なので、署名方向もベクターと完全一致で検証する。
// 検証規則系(kind = "authorization")は「署名は有効だが §6.3 の履歴検証で
// expected_reason により拒否される」ことを、verifyChainWithHistory で構築した
// 履歴索引に対する verifyDistributedMetaStatement で固定する。
//
// メタ固有の固定点(value-signature との差):
// - var-meta-head-before-env-create は **positive**(エポックアンカー不在 —
//   環境の存在を検査しない意図された非対称。§14.3-5 / AUTH_SPEC §12-4)
// - rename_fork(同一 metaVersion の分岐)と name_swap(名前入替は署名失敗)
// - revive-after-delete(deleted な predecessor の後続は全拒否)

import type { ChainHistoryIndex, MetaStatementContext } from "../../src/index.ts";
import {
  buildMetaSignedBytes,
  computeMetaSignedBytesHash,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signMetaStatement,
  verifyDistributedMetaStatement,
  verifyMetaStatementSignature,
} from "../../src/index.ts";
import metaVectors from "../../test-vectors/metadata-signature.json" with { type: "json" };
import { canonicalHistory } from "./chain-history.ts";
import { vectorKeys } from "./chain-vector.ts";
import { metaExtendedHistory } from "./meta-history.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

interface VectorContext {
  readonly kind: string;
  readonly suite: string;
  readonly project_id: string;
  readonly environment_id: string;
  readonly variable_id?: string;
  readonly name: string;
  readonly status: string;
  readonly meta_version: number;
  readonly prev_meta_sig_hash_hex: string;
  readonly author_user_id: string;
  readonly chain_head_hash_hex: string;
  readonly chain_head_seq: number;
}

interface MetaVector {
  readonly name: string;
  readonly context: VectorContext;
  readonly author_key_fingerprint_hex: string;
  readonly signed_bytes_hex: string;
  readonly signed_bytes_sha256_hex: string;
  readonly signature_hex: string;
  readonly prev_base?: string;
}

interface MetaNegative {
  readonly name: string;
  readonly kind?: string;
  readonly chain?: string;
  readonly context: VectorContext;
  readonly author_key_fingerprint_hex?: string;
  readonly verify_signed_bytes_hex?: string;
  readonly signed_bytes_hex?: string;
  readonly signature_hex: string;
  readonly verify_key_hex: string;
  readonly expected_reason?: string;
  readonly predecessor?: {
    readonly base: string;
    readonly signed_bytes_sha256_hex: string;
    readonly status: string;
  };
  readonly must_fail: boolean;
}

function contextOf(v: VectorContext): MetaStatementContext {
  return {
    suite: v.suite,
    projectId: v.project_id,
    environmentId: v.environment_id,
    target:
      v.kind === "variable"
        ? { kind: "variable", variableId: v.variable_id ?? "" }
        : { kind: "environment" },
    name: v.name,
    status: v.status as MetaStatementContext["status"],
    metaVersion: v.meta_version,
    prevMetaSigHashHex: v.prev_meta_sig_hash_hex,
    authorUserId: v.author_user_id,
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

const positives: readonly MetaVector[] = metaVectors.vectors;
const byName = new Map(positives.map((v) => [v.name, v]));

function predecessorOf(vector: MetaVector) {
  if (vector.prev_base === undefined) {
    return undefined;
  }
  const base = byName.get(vector.prev_base);
  return base === undefined
    ? undefined
    : {
        signedBytesHashHex: base.signed_bytes_sha256_hex,
        status: base.context.status as MetaStatementContext["status"],
      };
}

/** 署名方向(決定論的再署名)と低水準の検証方向の 2 チェック。 */
async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: MetaStatementContext,
  signatureHex: string,
): Promise<void> {
  const keys = vectorKeys[context.authorUserId];
  if (keys === undefined) {
    c.push(`meta-sig ${name}: author keys`, false, "author keys missing");
    return;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  const publicKey = await importSigningPublicKey(fromHex(keys.sig_pub_hex));
  if (!pair.ok || !publicKey.ok) {
    c.push(`meta-sig ${name}: author keys`, false, "key import failed");
    return;
  }
  const signed = await signMetaStatement({ context, signingKey: pair.value.privateKey });
  c.push(
    `meta-sig ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyMetaStatementSignature({
    context,
    signatureHex,
    authorPublicKey: publicKey.value,
  });
  c.push(`meta-sig ${name}: raw signature verify`, verified.ok);
}

async function vectorChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  for (const vector of positives) {
    const context = contextOf(vector.context);
    c.push(
      `meta-sig ${vector.name}: signed bytes construction`,
      toHex(buildMetaSignedBytes(context)) === vector.signed_bytes_hex,
    );
    const hash = await computeMetaSignedBytesHash(context);
    c.push(
      `meta-sig ${vector.name}: signed bytes hash`,
      hash.ok && hash.value === vector.signed_bytes_sha256_hex,
    );
    // 削除ステートメント(status deleted、metaVersion > 1)は正当に署名できる
    // 必要があるため、削除ベクターも決定論的再署名まで検査する
    await signAndVerifyChecks(c, vector.name, context, vector.signature_hex);

    // 履歴ベースの複合検証(§6.3): prev_base があれば predecessor 込みで検査。
    // var-meta-head-before-env-create(環境作成前ヘッド)もここを通る = positive
    const distributed = await verifyDistributedMetaStatement({
      history,
      context,
      authorKeyFingerprintHex: vector.author_key_fingerprint_hex,
      signatureHex: vector.signature_hex,
      predecessor: predecessorOf(vector),
    });
    c.push(
      `meta-sig ${vector.name}: distributed verify`,
      distributed.ok && distributed.value.signedBytesHashHex === vector.signed_bytes_sha256_hex,
      distributed.ok ? undefined : JSON.stringify(distributed.error),
    );
  }
  // 削除は直前 active 名を保持する(§4.2)ことのデータ再確認
  const del = byName.get("var-delete");
  const rename = byName.get("var-rename");
  c.push(
    "meta-sig var-delete: keeps last active name",
    del?.context.status === "deleted" && del.context.name === rename?.context.name,
  );
}

async function forkChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const branches: readonly MetaVector[] = metaVectors.rename_fork.branches;
  const hashes: string[] = [];
  for (const branch of branches) {
    const result = await verifyDistributedMetaStatement({
      history,
      context: contextOf(branch.context),
      authorKeyFingerprintHex: branch.author_key_fingerprint_hex,
      signatureHex: branch.signature_hex,
      predecessor: predecessorOf(branch),
    });
    // 分岐は単体では全検証を通る(防止は不能 — §14.2-5 の証拠化)
    c.push(`meta-sig fork ${branch.name}: verifies individually`, result.ok);
    if (result.ok) {
      hashes.push(result.value.signedBytesHashHex);
    }
  }
  c.push(
    "meta-sig fork: same coordinate yields distinct hashes",
    hashes.length === 2 && hashes[0] !== hashes[1],
  );
}

async function nameSwapChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  // 正規 2 本は各々検証を通る(名前 ↔ ID の束縛は署名が担う)
  for (const statement of metaVectors.name_swap.statements as readonly MetaVector[]) {
    const result = await verifyDistributedMetaStatement({
      history,
      context: contextOf(statement.context),
      authorKeyFingerprintHex: statement.author_key_fingerprint_hex,
      signatureHex: statement.signature_hex,
    });
    c.push(`meta-sig name-swap ${statement.name}: verifies individually`, result.ok);
  }
  // name フィールドだけを入れ替えたバイト列では元署名の検証に失敗する
  for (const swapped of metaVectors.name_swap.swapped as readonly MetaNegative[]) {
    const context = contextOf(swapped.context);
    const bytesMatch = toHex(buildMetaSignedBytes(context)) === swapped.verify_signed_bytes_hex;
    const key = await importSigningPublicKey(fromHex(swapped.verify_key_hex));
    if (!key.ok) {
      c.push(`meta-sig name-swap: ${swapped.name}`, false, "verify key import failed");
      continue;
    }
    const result = await verifyMetaStatementSignature({
      context,
      signatureHex: swapped.signature_hex,
      authorPublicKey: key.value,
    });
    c.push(`meta-sig name-swap: ${swapped.name}`, bytesMatch && !result.ok);
  }
}

/** 検証規則系 negative: 署名は有効だが履歴検証が expected_reason で拒否する。 */
async function ruleNegativeCheck(
  c: Checks,
  negative: MetaNegative,
  history: ChainHistoryIndex,
  extended: ChainHistoryIndex,
): Promise<void> {
  const chainHistory = negative.chain === "tenure-extension" ? extended : history;
  const result = await verifyDistributedMetaStatement({
    history: chainHistory,
    context: contextOf(negative.context),
    authorKeyFingerprintHex: negative.author_key_fingerprint_hex ?? "",
    signatureHex: negative.signature_hex,
    predecessor:
      negative.predecessor === undefined
        ? undefined
        : {
            signedBytesHashHex: negative.predecessor.signed_bytes_sha256_hex,
            status: negative.predecessor.status as MetaStatementContext["status"],
          },
  });
  c.push(
    `meta-sig rule negative: ${negative.name}`,
    !result.ok &&
      result.error.kind === "MetaStatementInvalid" &&
      result.error.reason === negative.expected_reason,
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

/** 改竄・移植系 negative: 正規化がベクターの検証側バイト列を再現し、元署名が失敗する。 */
async function tamperNegativeCheck(c: Checks, negative: MetaNegative): Promise<void> {
  const context = contextOf(negative.context);
  const bytesMatch = toHex(buildMetaSignedBytes(context)) === negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`meta-sig negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const result = await verifyMetaStatementSignature({
    context,
    signatureHex: negative.signature_hex,
    authorPublicKey: key.value,
  });
  c.push(
    `meta-sig negative: ${negative.name}`,
    bytesMatch &&
      !result.ok &&
      result.error.kind === "MetaStatementInvalid" &&
      result.error.reason === "signature-invalid",
  );
}

async function negativeChecks(
  c: Checks,
  history: ChainHistoryIndex,
  extended: ChainHistoryIndex,
): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of metaVectors.negative as readonly MetaNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, history, extended);
    } else {
      await tamperNegativeCheck(c, negative);
    }
  }
  // kind 語彙の固定(第三の値が導入されると両ふるいから漏れる — session-13 の教訓)
  c.push(
    "meta-sig negative: kind vocabulary is exhaustive",
    [...seenKinds].every((kind) => kind === "signature" || kind === "authorization"),
  );
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    c.push("meta-sig invalid input: base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const badContexts: readonly { name: string; context: MetaStatementContext }[] = [
    { name: "bad meta version", context: { ...baseContext, metaVersion: 0 } },
    { name: "bad head seq", context: { ...baseContext, chainHeadSeq: 0 } },
    { name: "empty name", context: { ...baseContext, name: "" } },
    {
      name: "bad status",
      context: { ...baseContext, status: "archived" as MetaStatementContext["status"] },
    },
    { name: "short prev hash", context: { ...baseContext, prevMetaSigHashHex: "abcd" } },
    { name: "short head hash", context: { ...baseContext, chainHeadHashHex: "abcd" } },
    { name: "empty suite", context: { ...baseContext, suite: "" } },
    { name: "empty author", context: { ...baseContext, authorUserId: "" } },
    {
      name: "empty variable id",
      context: { ...baseContext, target: { kind: "variable", variableId: "" } },
    },
  ];
  for (const bad of badContexts) {
    const signed = await signMetaStatement({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyMetaStatementSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
      authorPublicKey: pair.publicKey,
    });
    c.push(
      `meta-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  // 署名側だけの結合検査(検証側は理由コードで拒否する非対称 — value-sign と同型):
  // metaVersion 1 に非空 prev、metaVersion 1 の status deleted(作成は active — §4.2)
  const coupledPrev = await signMetaStatement({
    context: { ...baseContext, metaVersion: 1, prevMetaSigHashHex: "ab".repeat(32) },
    signingKey: pair.privateKey,
  });
  c.push(
    "meta-sig invalid input: sign rejects v1 with non-empty prev",
    !coupledPrev.ok && coupledPrev.error.kind === "InvalidInput",
  );
  const coupledStatus = await signMetaStatement({
    context: { ...baseContext, metaVersion: 1, prevMetaSigHashHex: "", status: "deleted" },
    signingKey: pair.privateKey,
  });
  c.push(
    "meta-sig invalid input: sign rejects deleted at metaVersion 1",
    !coupledStatus.ok && coupledStatus.error.kind === "InvalidInput",
  );
  const shortSignature = await verifyMetaStatementSignature({
    context: baseContext,
    signatureHex: "ab".repeat(63),
    authorPublicKey: pair.publicKey,
  });
  c.push(
    "meta-sig invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

/** deleted な predecessor の後続は status を問わず拒否する(§4.2 — tombstone は終端)。 */
async function deletedPredecessorChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const deleted = byName.get("var-delete");
  const keys = vectorKeys["user-admin-0003"];
  if (deleted === undefined || keys === undefined) {
    c.push("meta-sig deleted predecessor: fixtures", false);
    return;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    c.push("meta-sig deleted predecessor: key import", false);
    return;
  }
  // deleted → deleted(削除の重ね書き)も revived-after-delete で拒否される
  const successor: MetaStatementContext = {
    ...contextOf(deleted.context),
    metaVersion: deleted.context.meta_version + 1,
    prevMetaSigHashHex: deleted.signed_bytes_sha256_hex,
  };
  const signature = await signMetaStatement({
    context: successor,
    signingKey: pair.value.privateKey,
  });
  if (!signature.ok) {
    c.push("meta-sig deleted predecessor: sign", false);
    return;
  }
  const result = await verifyDistributedMetaStatement({
    history,
    context: successor,
    authorKeyFingerprintHex: keys.key_fingerprint_hex,
    signatureHex: signature.value,
    predecessor: {
      signedBytesHashHex: deleted.signed_bytes_sha256_hex,
      status: "deleted",
    },
  });
  c.push(
    "meta-sig: any successor of a deleted predecessor is rejected",
    !result.ok &&
      result.error.kind === "MetaStatementInvalid" &&
      result.error.reason === "revived-after-delete",
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  const base = positives[0];
  if (base === undefined) {
    return;
  }
  const context = contextOf(base.context);
  const signer = await generateSigningKeyPair();
  const signed = await signMetaStatement({ context, signingKey: signer.privateKey });
  if (!signed.ok) {
    c.push("meta-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyMetaStatementSignature({
    context,
    signatureHex: signed.value,
    authorPublicKey: signer.publicKey,
  });
  c.push("meta-sig: roundtrip", verified.ok);

  const other = await generateSigningKeyPair();
  const wrongKey = await verifyMetaStatementSignature({
    context,
    signatureHex: signed.value,
    authorPublicKey: other.publicKey,
  });
  c.push("meta-sig: roundtrip wrong key rejected", !wrongKey.ok);

  const wrongContext = await verifyMetaStatementSignature({
    context: { ...context, name: `${context.name}-transplanted` },
    signatureHex: signed.value,
    authorPublicKey: signer.publicKey,
  });
  c.push("meta-sig: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function metadataSignatureChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  const extended = await metaExtendedHistory();
  await vectorChecks(c, history);
  await forkChecks(c, history);
  await nameSwapChecks(c, history);
  await negativeChecks(c, history, extended);
  await invalidInputChecks(c);
  await deletedPredecessorChecks(c, history);
  await roundtripChecks(c);
  return c.results;
}
