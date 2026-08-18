// CRYPTO_SPEC §4.3(環境マニフェスト)のチェック。
// Ed25519 は RFC 8032 の決定論的署名なので、署名方向もベクターと完全一致で検証する。
// 検証規則系(kind = "authorization")は「署名は有効だが §4.3 / §6.3 の履歴検証で
// expected_reason により拒否される」ことを、verifyChainWithHistory で構築した
// 履歴索引に対する verifyDistributedEnvManifest で固定する。
//
// マニフェスト固有の固定点(metadata-signature との差):
// - variables_digest の LP 正規形(空集合・単一・tombstone・バイト昇順)を
//   computeVariablesDigest が再現する(digests セクション)
// - 複合発行のエポック整合(manifest-v1-create / manifest-rotate = 宣言ヘッドの
//   次エントリがエポックを確立する形)が positive で通る
// - epoch-regression(rotate 後に旧エポックを焼き込んだ前進 manifestVersion)が
//   predecessor 込み検証で落ちる — 本機構の核となる negative
// - digest-*(欠落・tombstone 隠し・順序違反)が verify 側集合での再計算で落ちる

import type {
  ChainHistoryIndex,
  EnvManifestContext,
  VariablesDigestEntry,
} from "../../src/index.ts";
import {
  buildEnvManifestSignedBytes,
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  signEnvManifest,
  verifyDistributedEnvManifest,
  verifyEnvManifestSignature,
} from "../../src/index.ts";
import manifestVectors from "../../test-vectors/env-manifest.json" with { type: "json" };
import { canonicalHistory } from "./chain-history.ts";
import { vectorKeys } from "./chain-vector.ts";
import { manifestExtendedHistory } from "./manifest-history.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

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
    projectId: v.project_id,
    environmentId: v.environment_id,
    epoch: v.epoch,
    manifestVersion: v.manifest_version,
    variablesDigestHex: v.variables_digest_hex,
    envMetaVersion: v.env_meta_version,
    envMetaSigHashHex: v.env_meta_sig_hash_hex,
    prevManifestSigHashHex: v.prev_manifest_sig_hash_hex,
    issuerUserId: v.issuer_user_id,
    chainHeadHashHex: v.chain_head_hash_hex,
    chainHeadSeq: v.chain_head_seq,
  };
}

function entriesOf(entries: readonly VectorEntry[]): VariablesDigestEntry[] {
  return entries.map((entry) => ({
    variableId: entry.variable_id,
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

/** envMeta の期待値は context の自己一致(フィクスチャの環境メタは正 — negative は verify_env_meta で上書き)。 */
function envMetaOf(context: EnvManifestContext) {
  return { metaVersion: context.envMetaVersion, sigHashHex: context.envMetaSigHashHex };
}

/** digests セクション: variables_digest の LP 正規形の固定(§4.3)。 */
async function digestChecks(c: Checks): Promise<void> {
  for (const digestCase of manifestVectors.digests) {
    const computed = await computeVariablesDigest("maruhi/v1", entriesOf(digestCase.entries));
    c.push(
      `env-manifest digest ${digestCase.name}`,
      computed.ok && computed.value === digestCase.variables_digest_hex,
      computed.ok ? undefined : JSON.stringify(computed.error),
    );
    // 入力順に依らず正規形へ正規化される(バイト昇順は関数の内部規約)
    const reversed = await computeVariablesDigest(
      "maruhi/v1",
      entriesOf(digestCase.entries.toReversed()),
    );
    c.push(
      `env-manifest digest ${digestCase.name}: order-independent input`,
      reversed.ok && reversed.value === digestCase.variables_digest_hex,
    );
  }
  // 重複 variable_id は「変数ごとに最新形 1 本」の不変条件違反 = InvalidInput
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

/** 署名方向(決定論的再署名)と低水準の検証方向の 2 チェック。 */
async function signAndVerifyChecks(
  c: Checks,
  name: string,
  context: EnvManifestContext,
  signatureHex: string,
): Promise<void> {
  const keys = vectorKeys[context.issuerUserId];
  if (keys === undefined) {
    c.push(`env-manifest ${name}: issuer keys`, false, "issuer keys missing");
    return;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  const publicKey = await importSigningPublicKey(fromHex(keys.sig_pub_hex));
  if (!pair.ok || !publicKey.ok) {
    c.push(`env-manifest ${name}: issuer keys`, false, "key import failed");
    return;
  }
  const signed = await signEnvManifest({ context, signingKey: pair.value.privateKey });
  c.push(
    `env-manifest ${name}: deterministic re-sign matches vector`,
    signed.ok && signed.value === signatureHex,
  );
  const verified = await verifyEnvManifestSignature({
    context,
    signatureHex,
    issuerPublicKey: publicKey.value,
  });
  c.push(`env-manifest ${name}: raw signature verify`, verified.ok);
}

async function vectorChecks(c: Checks, history: ChainHistoryIndex): Promise<void> {
  for (const vector of positives) {
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
    // ベクターの entries(正規形)からの再計算が署名済みダイジェストと一致する
    const digest = await computeVariablesDigest(context.suite, entriesOf(vector.entries));
    c.push(
      `env-manifest ${vector.name}: digest recomputation`,
      digest.ok && digest.value === context.variablesDigestHex,
    );
    await signAndVerifyChecks(c, vector.name, context, vector.signature_hex);

    // 履歴ベースの複合検証(§4.3 / §6.3): prev_base があれば predecessor 込み。
    // manifest-v1-create / manifest-rotate(複合発行のエポック整合)もここを通る
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
  // tombstone 込みダイジェスト(§4.3)のデータ再確認
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
    // 分岐は単体では全検証を通る(防止は不能 — §14.2-5 の証拠化)
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

/** 検証規則系 negative: 署名は有効だが履歴検証が expected_reason で拒否する。 */
async function ruleNegativeCheck(
  c: Checks,
  negative: ManifestNegative,
  history: ChainHistoryIndex,
  extended: ChainHistoryIndex,
): Promise<void> {
  const chainHistory = negative.chain === "tenure-extension" ? extended : history;
  const context = contextOf(negative.context);
  const result = await verifyDistributedEnvManifest({
    history: chainHistory,
    context,
    issuerKeyFingerprintHex: negative.issuer_key_fingerprint_hex ?? "",
    signatureHex: negative.signature_hex,
    // verify_entries = 検証側が再計算に使う集合(欠落・tombstone 隠し・順序違反の
    // 表現)。無指定はベクターの正規形集合
    entries: entriesOf(negative.verify_entries ?? negative.entries ?? []),
    envMeta:
      negative.verify_env_meta === undefined
        ? envMetaOf(context)
        : {
            metaVersion: negative.verify_env_meta.meta_version,
            sigHashHex: negative.verify_env_meta.meta_sig_hash_hex,
          },
    predecessor:
      negative.predecessor === undefined
        ? undefined
        : {
            signedBytesHashHex: negative.predecessor.signed_bytes_sha256_hex,
            epoch: negative.predecessor.epoch,
          },
  });
  c.push(
    `env-manifest rule negative: ${negative.name}`,
    !result.ok &&
      result.error.kind === "EnvManifestInvalid" &&
      result.error.reason === negative.expected_reason,
    result.ok ? "verified unexpectedly" : JSON.stringify(result.error),
  );
}

/** 改竄・移植系 negative: 正規化がベクターの検証側バイト列を再現し、元署名が失敗する。 */
async function tamperNegativeCheck(c: Checks, negative: ManifestNegative): Promise<void> {
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
  c.push(
    `env-manifest negative: ${negative.name}`,
    bytesMatch &&
      !result.ok &&
      result.error.kind === "EnvManifestInvalid" &&
      result.error.reason === "signature-invalid",
  );
}

async function negativeChecks(
  c: Checks,
  history: ChainHistoryIndex,
  extended: ChainHistoryIndex,
): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of manifestVectors.negative as readonly ManifestNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "authorization") {
      await ruleNegativeCheck(c, negative, history, extended);
    } else {
      await tamperNegativeCheck(c, negative);
    }
  }
  // kind 語彙の固定(第三の値が導入されると両ふるいから漏れる — session-13 の教訓)
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
    { name: "short digest", context: { ...baseContext, variablesDigestHex: "abcd" } },
    { name: "short env meta hash", context: { ...baseContext, envMetaSigHashHex: "abcd" } },
    { name: "short prev hash", context: { ...baseContext, prevManifestSigHashHex: "abcd" } },
    { name: "short head hash", context: { ...baseContext, chainHeadHashHex: "abcd" } },
    { name: "empty suite", context: { ...baseContext, suite: "" } },
    { name: "empty project id", context: { ...baseContext, projectId: "" } },
    { name: "empty environment id", context: { ...baseContext, environmentId: "" } },
    { name: "empty issuer", context: { ...baseContext, issuerUserId: "" } },
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
  // 署名側だけの結合検査(検証側は理由コードで拒否する非対称 — meta-sign と同型)
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

export async function envManifestChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  const history = await canonicalHistory();
  const extended = await manifestExtendedHistory();
  await digestChecks(c);
  await vectorChecks(c, history);
  await forkChecks(c, history);
  await negativeChecks(c, history, extended);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
