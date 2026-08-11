// CRYPTO_SPEC §4.2: 変数・環境メタデータの署名付きステートメント(Ed25519)。
// var_meta_signed_bytes = LP("<suite>/var-meta-sig", project_id, environment_id,
//                            variable_id, name, status, meta_version,
//                            prev_meta_sig_hash_hex, author_user_id,
//                            chain_head_hash_hex, chain_head_seq)
// env_meta_signed_bytes = LP("<suite>/env-meta-sig", project_id, environment_id,
//                            name, status, meta_version, prev_meta_sig_hash_hex,
//                            author_user_id, chain_head_hash_hex, chain_head_seq)
// suite と var / env の別はドメイン文字列が束縛する(§4.1 / §5.1 と同型)。
// 数値(meta_version / chain_head_seq)は §2.1 のとおり 10 進文字列化し、
// バイナリ列(ハッシュ)は hex 小文字文字列として LP に載せる。
// name は UTF-8 バイト列としてそのまま束縛する(byte-exact — NFC 正規化は
// 署名前のクライアントの責務で、検証者は正規化しない。§4.2)。
// テストベクター: test-vectors/metadata-signature.json
//
// 署名の意味論は「author_user_id が、チェーン位置 (chain_head_hash,
// chain_head_seq) の状態を知った上で、この安定識別子にこの名前・状態を束縛した」
// の帰属・内容真正性・認可時点束縛である(§4.2)。メタステートメントはエポックに
// 相当する鮮度アンカーを持たない(前進 meta_version への注入は v1 未検出の既知
// 残余 — §14.3-5)。宣言ヘッド・認可時点・prev 連鎖の検証は meta-verify.ts
// (履歴照会は chain-history.ts)が担い、本モジュールは正規化・署名・ハッシュの
// 低水準のみ。

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed, type LengthPrefixedField } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/** Lifecycle status a metadata statement binds (CRYPTO_SPEC §4.2). */
export type MetaStatementStatus = "active" | "deleted";

/**
 * The stable identifier a statement binds the name/status to: a variable
 * (var-meta-sig) or the environment itself (env-meta-sig). The two kinds use
 * distinct domain strings, so signatures never transplant across kinds.
 */
export type MetaStatementTarget =
  | { readonly kind: "variable"; readonly variableId: string }
  | { readonly kind: "environment" };

/**
 * Fields bound by a metadata-statement signature (CRYPTO_SPEC §4.2): the full
 * wire form of one statement version plus its authorization anchor. The name
 * is bound byte-exactly as UTF-8; hashes are lowercase hex strings.
 */
export interface MetaStatementContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly name: string;
  readonly status: MetaStatementStatus;
  /** 1-based counter (creation = 1; each rename / delete increments). */
  readonly metaVersion: number;
  /**
   * SHA-256 (lowercase hex) of the previous statement's signed bytes; the
   * empty string for metaVersion 1 (§4.2 の連鎖規約 — §4.1 と同一).
   */
  readonly prevMetaSigHashHex: string;
  /** The author's own internal user id (binds attribution to the identity). */
  readonly authorUserId: string;
  /** Entry hash of the chain head the author last verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head (both hash and seq are signed; mismatch fails). */
  readonly chainHeadSeq: number;
}

function numericFieldInvalid(context: MetaStatementContext): string | null {
  if (!Number.isSafeInteger(context.metaVersion) || context.metaVersion < 1) {
    return "context metaVersion";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

// バイナリ列は hex 小文字のみ(§4.1 実装と同じ規律 — 大文字 hex を許すと
// 同一値に複数の正規形が生まれ、署名の一意性が壊れる)
function hexFieldInvalid(context: MetaStatementContext): string | null {
  if (
    context.prevMetaSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevMetaSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevMetaSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

// suite と署名対象の座標(projectId / environmentId)は非空。座標の非空検査は
// 防御的一貫性のため(LP により空でも符号化は無曖昧 = 脆弱性ではないが、
// 他フィールドと検査水準を揃える — session-15 レビュー①)。空の座標を署名する
// 正当な呼び出しは存在しない
function coordinateFieldInvalid(context: MetaStatementContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  return null;
}

// 署名対象の構造検証。metaVersion ↔ prev の結合(1 = 空 / > 1 = 64 hex)は
// ここでは検査しない: 検証側は「署名は有効だが規則違反」のステートメント
// (ベクターの rule negative v1-nonempty-prev 等)の署名をまず検証できる必要が
// あり、結合は検証規則(meta-verify.ts の prev-shape-mismatch)として理由
// コード付きで拒否する(value-sign.ts と同じ非対称)。
function contextInvalidField(context: MetaStatementContext): string | null {
  const coordinate = coordinateFieldInvalid(context);
  if (coordinate !== null) {
    return coordinate;
  }
  if (context.target.kind === "variable" && context.target.variableId.length === 0) {
    return "context variableId";
  }
  if (context.name.length === 0) {
    return "context name";
  }
  if (context.status !== "active" && context.status !== "deleted") {
    return "context status";
  }
  if (context.authorUserId.length === 0) {
    return "context authorUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/** Validates a metadata-statement context (shared by sign / verify / hash). */
export function metaContextInvalidField(context: MetaStatementContext): string | null {
  return contextInvalidField(context);
}

/**
 * Builds the canonical byte string signed for one metadata statement
 * (CRYPTO_SPEC §4.2). The domain string embeds the suite identifier and the
 * statement kind (var / env), so a signature never transplants across suites
 * or kinds. Callers must validate the context first (sign / verify / hash
 * below do); this builder assumes valid input.
 */
export function buildMetaSignedBytes(context: MetaStatementContext): Uint8Array {
  const fields: LengthPrefixedField[] = [
    context.target.kind === "variable"
      ? `${context.suite}/var-meta-sig`
      : `${context.suite}/env-meta-sig`,
    context.projectId,
    context.environmentId,
  ];
  if (context.target.kind === "variable") {
    fields.push(context.target.variableId);
  }
  fields.push(
    context.name,
    context.status,
    context.metaVersion,
    context.prevMetaSigHashHex,
    context.authorUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  );
  return encodeLengthPrefixed(fields);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the value carried
 * as the next statement's `prev_meta_sig_hash_hex` (§4.2 の連鎖) and compared
 * for fork evidence (two valid signatures over distinct signed bytes at the
 * same metaVersion — §14.2-5).
 */
export async function computeMetaSignedBytesHash(
  context: MetaStatementContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildMetaSignedBytes(context))) };
}

/**
 * Signs one metadata statement with the author's chain signing key (Ed25519,
 * CRYPTO_SPEC §4.2). Returns the signature as lowercase hex — the wire form
 * of `VariableMetaStatement.signatureHex` (AUTH_SPEC §12-2).
 *
 * Signing enforces the metaVersion ↔ prev coupling (metaVersion 1 signs an
 * empty prev, later versions sign a 64-hex prev) and that a creation
 * (metaVersion 1) is `active` (削除はインクリメント — §4.2): producing a
 * rule-violating statement is always a caller bug, unlike verification where
 * such wire data must be rejected with a typed reason instead.
 */
export async function signMetaStatement(input: {
  readonly context: MetaStatementContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if ((input.context.metaVersion === 1) !== (input.context.prevMetaSigHashHex === "")) {
    return invalidInput("context prevMetaSigHashHex");
  }
  if (input.context.metaVersion === 1 && input.context.status !== "active") {
    return invalidInput("context status");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildMetaSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

/**
 * Verifies one metadata-statement signature against an author's Ed25519
 * public key (CRYPTO_SPEC §4.2). This is the raw signature check only — head
 * existence, head-time authorization / role level and prev chaining are the
 * history-based checks in `verifyDistributedMetaStatement` (meta-verify.ts).
 */
export async function verifyMetaStatementSignature(input: {
  readonly context: MetaStatementContext;
  readonly signatureHex: string;
  readonly authorPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildMetaSignedBytes(input.context),
    input.signatureHex,
    input.authorPublicKey,
    {
      kind: "MetaStatementInvalid",
      reason: "signature-invalid",
    },
  );
}
