// CRYPTO_SPEC §4.3: 環境マニフェスト(Ed25519)。
// env_manifest_signed_bytes = LP("<suite>/env-manifest-sig", project_id,
//                                environment_id, epoch, manifest_version,
//                                variables_digest_hex,
//                                env_meta_version, env_meta_sig_hash_hex,
//                                prev_manifest_sig_hash_hex,
//                                issuer_user_id, chain_head_hash_hex, chain_head_seq)
// variables_digest_hex = lower_hex(SHA-256(LP("<suite>/env-manifest-vars",
//                                             entry_1, …, entry_n)))
// entry_i = LP(variable_id, status, meta_version, meta_sig_hash_hex)
//   — variable_id の**バイト昇順**(UTF-8)。tombstone を含む全ステートメントの
//   最新形。空集合も有効(変数ゼロの環境 = 要素 0 の LP)。各 entry は入れ子 LP の
//   バイト列を 1 フィールドとして埋め込む(scope_environments と同じ規約)。
// suite の束縛はドメイン文字列が担い(§4.1 / §4.2 と同型)、数値(epoch /
// manifest_version / env_meta_version / meta_version / chain_head_seq)は §2.1 の
// とおり 10 進文字列化、バイナリ(ハッシュ)は hex 小文字文字列として LP に載せる。
// テストベクター: test-vectors/env-manifest.json
//
// 署名の意味論は「issuer_user_id が、チェーン位置 (chain_head_hash,
// chain_head_seq)・現エポック epoch の下で、この環境のメタ状態の全体像はこれだと
// 宣言した」の帰属・内容真正性・認可時点束縛 + **エポック焼き込み**(§4.3 —
// メタステートメントに欠けていた鮮度アンカーをマニフェスト層が供給する)。
// 宣言ヘッド・認可時点・エポック整合・ダイジェスト再計算・prev 連鎖の検証は
// manifest-verify.ts(履歴照会は chain-history.ts)が担い、本モジュールは
// 正規化・署名・ダイジェスト・ハッシュの低水準のみ。

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import type { MetaStatementStatus } from "./meta-sign.ts";
import { computeVariableKeyedDigest } from "./sorted-digest.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * One entry of the variables digest (CRYPTO_SPEC §4.3): the latest form of
 * one variable's metadata statement — tombstones (`deleted`) included.
 */
export interface VariablesDigestEntry {
  readonly variableId: string;
  readonly status: MetaStatementStatus;
  readonly metaVersion: number;
  /** SHA-256 (lowercase hex) of that statement's signed bytes (§4.2). */
  readonly metaSigHashHex: string;
}

function digestEntryInvalidField(entry: VariablesDigestEntry): string | null {
  if (entry.variableId.length === 0) {
    return "entry variableId";
  }
  if (entry.status !== "active" && entry.status !== "deleted") {
    return "entry status";
  }
  if (!Number.isSafeInteger(entry.metaVersion) || entry.metaVersion < 1) {
    return "entry metaVersion";
  }
  if (!isLowercaseHexOfLength(entry.metaSigHashHex, SHA256_HEX_LENGTH)) {
    return "entry metaSigHashHex";
  }
  return null;
}

/**
 * Computes the canonical variables digest (CRYPTO_SPEC §4.3). The canonical
 * variable_id byte-ascending order is applied internally, duplicate variable
 * ids are rejected, and the empty set is valid (an environment with no
 * variables yet). 骨格(検証 → 重複拒否 → 内部ソート → 入れ子 LP)は
 * sorted-digest.ts の共有実装(§6.2 values_digest と同型)。
 */
export async function computeVariablesDigest(
  suite: string,
  entries: readonly VariablesDigestEntry[],
): Promise<CryptoResult<string>> {
  return computeVariableKeyedDigest({
    suite,
    domain: "env-manifest-vars",
    entries,
    variableIdOf: (entry) => entry.variableId,
    entryInvalidField: digestEntryInvalidField,
    entryFields: (entry) => [
      entry.variableId,
      entry.status,
      entry.metaVersion,
      entry.metaSigHashHex,
    ],
  });
}

/**
 * Fields bound by an environment-manifest signature (CRYPTO_SPEC §4.3): the
 * full wire form of one manifest version plus its authorization anchor and
 * the epoch burned in at issuance time (the freshness anchor of the metadata
 * layer). Hashes are lowercase hex strings.
 */
export interface EnvManifestContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  /** The environment's current epoch at issuance (§4.3 — the core anchor). */
  readonly epoch: number;
  /** 1-based counter (environment creation = 1; each meta op / rotate increments). */
  readonly manifestVersion: number;
  /** Canonical digest of all variable statements incl. tombstones (§4.3). */
  readonly variablesDigestHex: string;
  /** Latest environment meta statement bound by this manifest (§4.3). */
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  /**
   * SHA-256 (lowercase hex) of the previous manifest's signed bytes; the
   * empty string for manifestVersion 1 (§4.3 の連鎖規約 — §4.1 / §4.2 と同一).
   */
  readonly prevManifestSigHashHex: string;
  /** The issuer's own internal user id (binds attribution to the identity). */
  readonly issuerUserId: string;
  /** Entry hash of the chain head the issuer last verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head (both hash and seq are signed; mismatch fails). */
  readonly chainHeadSeq: number;
}

function numericFieldInvalid(context: EnvManifestContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  if (!Number.isSafeInteger(context.manifestVersion) || context.manifestVersion < 1) {
    return "context manifestVersion";
  }
  if (!Number.isSafeInteger(context.envMetaVersion) || context.envMetaVersion < 1) {
    return "context envMetaVersion";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

// バイナリ列は hex 小文字のみ(§4.1 / §4.2 実装と同じ規律 — 大文字 hex を許すと
// 同一値に複数の正規形が生まれ、署名の一意性が壊れる)
function hexFieldInvalid(context: EnvManifestContext): string | null {
  if (!isLowercaseHexOfLength(context.variablesDigestHex, SHA256_HEX_LENGTH)) {
    return "context variablesDigestHex";
  }
  if (!isLowercaseHexOfLength(context.envMetaSigHashHex, SHA256_HEX_LENGTH)) {
    return "context envMetaSigHashHex";
  }
  if (
    context.prevManifestSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevManifestSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevManifestSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

// suite と座標(projectId / environmentId)・issuer は非空(meta-sign.ts と同じ
// 検査水準 — 空の座標を署名する正当な呼び出しは存在しない)
function contextInvalidField(context: EnvManifestContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  if (context.issuerUserId.length === 0) {
    return "context issuerUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/** Validates a manifest context (shared by sign / verify / hash). */
export function manifestContextInvalidField(context: EnvManifestContext): string | null {
  return contextInvalidField(context);
}

/**
 * Builds the canonical byte string signed for one environment manifest
 * (CRYPTO_SPEC §4.3). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify / hash below do); this builder assumes valid
 * input.
 */
export function buildEnvManifestSignedBytes(context: EnvManifestContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/env-manifest-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.manifestVersion,
    context.variablesDigestHex,
    context.envMetaVersion,
    context.envMetaSigHashHex,
    context.prevManifestSigHashHex,
    context.issuerUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the value carried
 * as the next manifest's `prev_manifest_sig_hash_hex` (§4.3 の連鎖) and
 * compared for fork evidence (two valid signatures over distinct signed
 * bytes at the same manifestVersion — §14.2-5).
 */
export async function computeEnvManifestSignedBytesHash(
  context: EnvManifestContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildEnvManifestSignedBytes(context))) };
}

/**
 * Signs one environment manifest with the issuer's chain signing key
 * (Ed25519, CRYPTO_SPEC §4.3). Returns the signature as lowercase hex — the
 * wire form of `EnvironmentManifest.signatureHex` (AUTH_SPEC §12-2).
 *
 * Signing enforces the manifestVersion ↔ prev coupling (manifestVersion 1
 * signs an empty prev, later versions sign a 64-hex prev): producing a
 * rule-violating manifest is always a caller bug, unlike verification where
 * such wire data must be rejected with a typed reason instead (meta-sign.ts
 * と同じ非対称).
 */
export async function signEnvManifest(input: {
  readonly context: EnvManifestContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if ((input.context.manifestVersion === 1) !== (input.context.prevManifestSigHashHex === "")) {
    return invalidInput("context prevManifestSigHashHex");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildEnvManifestSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

/**
 * Verifies one environment-manifest signature against an issuer's Ed25519
 * public key (CRYPTO_SPEC §4.3). This is the raw signature check only — head
 * existence, head-time authorization / epoch integrity, digest and env-meta
 * recomputation and prev chaining are the history-based checks in
 * `verifyDistributedEnvManifest` (manifest-verify.ts).
 */
export async function verifyEnvManifestSignature(input: {
  readonly context: EnvManifestContext;
  readonly signatureHex: string;
  readonly issuerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildEnvManifestSignedBytes(input.context),
    input.signatureHex,
    input.issuerPublicKey,
    {
      kind: "EnvManifestInvalid",
      reason: "signature-invalid",
    },
  );
}
