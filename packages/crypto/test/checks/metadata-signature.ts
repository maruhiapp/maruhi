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

import type {
  ChainHistoryIndex,
  CryptoResult,
  MetaStatementContext,
  MetaVariableSchema,
} from "../../src/index.ts";
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
  readonly layout_version?: number;
  readonly var_type?: string;
  readonly required?: string;
  readonly description?: string;
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
  readonly expected_error?: string;
  readonly predecessor?: {
    readonly base: string;
    readonly signed_bytes_sha256_hex: string;
    readonly status: string;
    readonly layout_version?: number;
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
    layoutVersion: v.layout_version,
    // レイアウト v2 のスキーマ欄(var_type / required / description)は 3 欄
    // 同時に存在する(§4.2 — required がベクター側の存在判定の代表)
    schema:
      v.required === undefined
        ? undefined
        : {
            varType: (v.var_type ?? "") as MetaVariableSchema["varType"],
            required: v.required as MetaVariableSchema["required"],
            description: v.description ?? "",
          },
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
        // MetaPredecessor 側は必須(fail-closed)。ベクターの省略 = v1
        layoutVersion: base.context.layout_version ?? 1,
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
  deleteRetentionChecks(c);
}

/** 削除ステートメントの保持規約(§4.2)のデータ再確認。 */
function deleteRetentionChecks(c: Checks): void {
  // 削除は直前 active 名を保持する
  const del = byName.get("var-delete");
  const rename = byName.get("var-rename");
  c.push(
    "meta-sig var-delete: keeps last active name",
    del?.context.status === "deleted" && del.context.name === rename?.context.name,
  );
  // v2 の削除は name と同じ規約でスキーマ欄とレイアウトを直前ステートメントから
  // 完全保持する(§4.2 レイアウト v2)
  const v2Delete = byName.get("var-v2-delete-keeps-schema");
  const v2Create = byName.get("var-v2-create-typed");
  c.push(
    "meta-sig var-v2-delete-keeps-schema: keeps schema and layout from predecessor",
    v2Delete?.context.status === "deleted" &&
      v2Delete.context.layout_version === 2 &&
      v2Delete.context.name === v2Create?.context.name &&
      v2Delete.context.var_type === v2Create.context.var_type &&
      v2Delete.context.required === v2Create.context.required &&
      v2Delete.context.description === v2Create.context.description,
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
            layoutVersion: negative.predecessor.layout_version ?? 1,
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

/**
 * 構造違反系 negative(kind = invalid-input): 署名は当該バイト列に対して有効
 * (参照実装が確認済み)だが、ワイヤ形の構造違反(v1 の declared・v2 の空
 * required)として署名検証に到達する前に InvalidInput で拒否する(§4.2 /
 * 裁定 CS — 拒否は暗号検証によるものではない)。
 */
async function invalidInputNegativeCheck(c: Checks, negative: MetaNegative): Promise<void> {
  const context = contextOf(negative.context);
  // エンコーダ自体は全域関数なのでベクターの signed_bytes を再現できることも固定
  const bytesMatch = toHex(buildMetaSignedBytes(context)) === negative.signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`meta-sig invalid-input negative: ${negative.name}`, false, "key import failed");
    return;
  }
  const verified = await verifyMetaStatementSignature({
    context,
    signatureHex: negative.signature_hex,
    authorPublicKey: key.value,
  });
  const hash = await computeMetaSignedBytesHash(context);
  c.push(
    `meta-sig invalid-input negative: ${negative.name}`,
    bytesMatch &&
      !verified.ok &&
      verified.error.kind === negative.expected_error &&
      !hash.ok &&
      hash.error.kind === negative.expected_error,
    verified.ok ? "verified unexpectedly" : JSON.stringify(verified.error),
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
    } else if (negative.kind === "invalid-input") {
      await invalidInputNegativeCheck(c, negative);
    } else {
      await tamperNegativeCheck(c, negative);
    }
  }
  // kind 語彙の固定(第三の値が導入されると各ふるいから漏れる — session-13 の教訓)
  c.push(
    "meta-sig negative: kind vocabulary is exhaustive",
    [...seenKinds].every(
      (kind) => kind === "signature" || kind === "authorization" || kind === "invalid-input",
    ),
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
    { name: "empty project id", context: { ...baseContext, projectId: "" } },
    { name: "empty environment id", context: { ...baseContext, environmentId: "" } },
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

/**
 * レイアウト依存の構造違反(§4.2 — JSON ベクターで表現しない分担): v1 に
 * スキーマ欄、v2 のスキーマ欄欠落、var_type の閉集合違反、環境メタへの v2。
 */
async function layoutInvalidInputChecks(c: Checks): Promise<void> {
  const base = positives[0];
  const v2Base = byName.get("var-v2-create-typed");
  if (base === undefined || v2Base === undefined) {
    c.push("meta-sig invalid input: v2 base vector", false);
    return;
  }
  const pair = await generateSigningKeyPair();
  const baseContext = contextOf(base.context);
  const v2Context = contextOf(v2Base.context);
  const layoutBadContexts: readonly { name: string; context: MetaStatementContext }[] = [
    { name: "schema on layout 1", context: { ...baseContext, schema: v2Context.schema } },
    { name: "missing schema on layout 2", context: { ...v2Context, schema: undefined } },
    {
      name: "unknown var type",
      context: {
        ...v2Context,
        schema: {
          varType: "secret" as MetaVariableSchema["varType"],
          required: "true",
          description: "Rule fixture",
        },
      },
    },
    {
      name: "environment target on layout 2",
      context: { ...v2Context, target: { kind: "environment" } },
    },
  ];
  for (const bad of layoutBadContexts) {
    const signed = await signMetaStatement({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyMetaStatementSignature({
      context: bad.context,
      signatureHex: v2Base.signature_hex,
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
}

function isUnsupportedLayout(result: CryptoResult<unknown>, layoutVersion: number): boolean {
  return (
    !result.ok &&
    result.error.kind === "UnsupportedMetaLayout" &&
    result.error.layoutVersion === layoutVersion
  );
}

/**
 * レイアウト選択(§4.2 / 裁定 CR — 拒否ケースに参照期待値が存在しないため
 * 規約 21 の分担どおりハーネス側で固定): サポート外の layoutVersion は
 * **署名検証より前に** UnsupportedMetaLayout で拒否する(署名不正・
 * InvalidInput に潰さない誠実な破壊様式)。明示 layoutVersion 1 は省略と同値。
 */
async function layoutSelectionChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  const base = byName.get("var-v2-create-typed");
  if (base === undefined) {
    c.push("meta-sig layout selection: base vector", false);
    return;
  }
  const future: MetaStatementContext = { ...contextOf(base.context), layoutVersion: 3 };
  const pair = await generateSigningKeyPair();
  const signed = await signMetaStatement({ context: future, signingKey: pair.privateKey });
  const verified = await verifyMetaStatementSignature({
    context: future,
    signatureHex: base.signature_hex,
    authorPublicKey: pair.publicKey,
  });
  const hash = await computeMetaSignedBytesHash(future);
  // 署名鍵の解決(author-unknown)にすら到達しない = 署名検証より前の拒否を、
  // 履歴に存在しない FP を渡して固定する
  const distributed = await verifyDistributedMetaStatement({
    history,
    context: future,
    authorKeyFingerprintHex: "00".repeat(16),
    signatureHex: base.signature_hex,
  });
  c.push(
    "meta-sig layout selection: sign rejects unsupported layout",
    isUnsupportedLayout(signed, 3),
  );
  c.push(
    "meta-sig layout selection: verify rejects unsupported layout",
    isUnsupportedLayout(verified, 3),
  );
  c.push(
    "meta-sig layout selection: hash rejects unsupported layout",
    isUnsupportedLayout(hash, 3),
  );
  c.push(
    "meta-sig layout selection: distributed verify rejects before key resolution",
    isUnsupportedLayout(distributed, 3),
  );
  // layoutVersion の構造違反(0 / 非整数)は InvalidInput(バージョン交渉でなく
  // ワイヤ形の壊れ)
  for (const bad of [0, 1.5]) {
    const result = await computeMetaSignedBytesHash({
      ...contextOf(base.context),
      layoutVersion: bad,
    });
    c.push(
      `meta-sig layout selection: layoutVersion ${bad} is invalid input`,
      !result.ok && result.error.kind === "InvalidInput",
    );
  }
  // 明示 layoutVersion 1 は省略と同値(§4.2 — 省略 = 1)
  const v1 = byName.get("var-create");
  if (v1 === undefined) {
    c.push("meta-sig layout selection: v1 base vector", false);
    return;
  }
  const explicit = buildMetaSignedBytes({ ...contextOf(v1.context), layoutVersion: 1 });
  c.push(
    "meta-sig layout selection: explicit layoutVersion 1 equals omitted",
    toHex(explicit) === v1.signed_bytes_hex,
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
      layoutVersion: 1,
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
  await layoutInvalidInputChecks(c);
  await layoutSelectionChecks(c, history);
  await deletedPredecessorChecks(c, history);
  await roundtripChecks(c);
  return c.results;
}
