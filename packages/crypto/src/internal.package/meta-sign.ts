// CRYPTO_SPEC §4.2: 変数・環境メタデータの署名付きステートメント(Ed25519)。
// var_meta_signed_bytes = LP("<suite>/var-meta-sig", project_id, environment_id,
//                            variable_id, name, status, meta_version,
//                            prev_meta_sig_hash_hex, author_user_id,
//                            chain_head_hash_hex, chain_head_seq)
// env_meta_signed_bytes = LP("<suite>/env-meta-sig", project_id, environment_id,
//                            name, status, meta_version, prev_meta_sig_hash_hex,
//                            author_user_id, chain_head_hash_hex, chain_head_seq)
// レイアウト v2(0.8-draft — セッション 46 裁定 CR / CS。変数のみ — 環境メタは
// v1 のまま):
// var_meta_signed_bytes_v2 = LP("<suite>/var-meta-sig-v2", project_id,
//                               environment_id, variable_id, name, status,
//                               var_type, required, description, meta_version,
//                               prev_meta_sig_hash_hex, author_user_id,
//                               chain_head_hash_hex, chain_head_seq)
// suite と var / env の別・レイアウト版はドメイン文字列が束縛する(§4.1 / §5.1 と
// 同型。レイアウト版はステートメント種ローカルで suite は据え置き — maruhi/v2 は
// PQ ハイブリッドに予約)。どのレイアウトで signed_bytes を計算するかはワイヤの
// layoutVersion(省略 = 1)が選択し、サポート範囲の検査は**署名検証より前**に
// 行って超過を型付きエラー UnsupportedMetaLayout で拒否する(署名不正に潰さない
// 誠実な破壊様式 — 裁定 CR)。
// 数値(meta_version / chain_head_seq)は §2.1 のとおり 10 進文字列化し、
// バイナリ列(ハッシュ)は hex 小文字文字列として LP に載せる。
// name / description は UTF-8 バイト列としてそのまま束縛する(byte-exact — NFC
// 正規化は署名前のクライアントの責務で、検証者は正規化しない。§4.2)。
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
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * Lifecycle status a metadata statement binds (CRYPTO_SPEC §4.2).
 * `declared` — declared but no value set — exists only in variable layout v2
 * (裁定 CS: v1 は不変); layout 1 statements are limited to the first two.
 */
export type MetaStatementStatus = "active" | "deleted" | "declared";

/**
 * Declared type of a variable's value (CRYPTO_SPEC §4.2 layout v2). A closed
 * set — `""` means unspecified; no validation DSL / enum / defaults (裁定 CT).
 * The declaration is advisory (§14.3-7): the signature proves the author
 * declared this type, never that values conform to it.
 */
export type MetaVarType = "" | "string" | "number" | "boolean" | "url";

const META_VAR_TYPES: readonly string[] = ["", "string", "number", "boolean", "url"];

/**
 * Schema fields of a variable meta statement in layout v2 (CRYPTO_SPEC §4.2):
 * bound byte-exactly into the signed bytes between `status` and
 * `meta_version`. `required` is mandatory-explicit (`"true" | "false"` — the
 * empty string is rejected so no client-side default interpretation can
 * diverge); `description` is free UTF-8 (byte-exact, verifiers never
 * normalize — display-side neutralization is AUTH_SPEC §12-8's duty).
 */
export interface MetaVariableSchema {
  readonly varType: MetaVarType;
  readonly required: "true" | "false";
  readonly description: string;
}

/** Supported wire layout versions of variable meta statements (§4.2). */
export const SUPPORTED_META_LAYOUT_VERSIONS: readonly number[] = [1, 2];

/**
 * Resolves the effective layout version of a statement or predecessor
 * (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2): the wire `layoutVersion` field is a
 * carrier field outside the signed bytes, and omission means layout 1.
 */
export function metaLayoutVersionOf(carrier: {
  readonly layoutVersion?: number | undefined;
}): number {
  return carrier.layoutVersion ?? 1;
}

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
  /**
   * Wire layout version (§4.2 — omitted = 1). Selects which layout's signed
   * bytes are computed. Layout 2 is variable statements only and requires
   * `schema`; environment statements stay layout 1 (本改訂の対象外).
   */
  readonly layoutVersion?: number | undefined;
  /** Layout v2 schema fields — present iff the layout version is 2. */
  readonly schema?: MetaVariableSchema | undefined;
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

// レイアウト 1 の構造検証: スキーマ欄は存在せず、status は 2 値(declared は
// v2 限定 — 裁定 CS: v1 declared はワイヤ形の構造違反として InvalidInput。
// ベクター v1-declared-status)
function layoutV1FieldInvalid(context: MetaStatementContext): string | null {
  if (context.schema !== undefined) {
    return "context schema";
  }
  if (context.status !== "active" && context.status !== "deleted") {
    return "context status";
  }
  return null;
}

// レイアウト 2 の構造検証: 変数ステートメント限定(環境メタは v1 のまま —
// §4.2)、スキーマ欄必須、var_type は閉集合、required は明示必須で空文字列を
// 許さない(fail-closed — ベクター v2-empty-required)、status は 3 値
function layoutV2FieldInvalid(context: MetaStatementContext): string | null {
  if (context.target.kind !== "variable") {
    return "context layoutVersion";
  }
  if (context.schema === undefined) {
    return "context schema";
  }
  if (!META_VAR_TYPES.includes(context.schema.varType)) {
    return "context varType";
  }
  if (context.schema.required !== "true" && context.schema.required !== "false") {
    return "context required";
  }
  const statuses: readonly string[] = ["active", "deleted", "declared"];
  return statuses.includes(context.status) ? null : "context status";
}

// レイアウト依存の構造検証(前提: レイアウト版はサポート範囲内)。status の
// 語彙・スキーマ欄の有無はレイアウトが決める
function layoutFieldInvalid(context: MetaStatementContext): string | null {
  return metaLayoutVersionOf(context) === 1
    ? layoutV1FieldInvalid(context)
    : layoutV2FieldInvalid(context);
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
  const layout = layoutFieldInvalid(context);
  if (layout !== null) {
    return layout;
  }
  if (context.authorUserId.length === 0) {
    return "context authorUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/**
 * Validates a metadata-statement context (shared by sign / verify / hash).
 * The check order is fixed by CRYPTO_SPEC §4.2 (裁定 CR): the layoutVersion
 * support range is inspected **before** any layout-dependent field validation
 * and before signature verification, so an unsupported layout surfaces as the
 * typed `UnsupportedMetaLayout` ("client update required") — never as an
 * `InvalidInput` about fields the verifier cannot understand, and never as a
 * signature failure indistinguishable from tampering.
 */
export function metaContextRejection(context: MetaStatementContext): CryptoError | null {
  if (
    context.layoutVersion !== undefined &&
    (!Number.isSafeInteger(context.layoutVersion) || context.layoutVersion < 1)
  ) {
    return { kind: "InvalidInput", field: "context layoutVersion" };
  }
  const layout = metaLayoutVersionOf(context);
  if (!SUPPORTED_META_LAYOUT_VERSIONS.includes(layout)) {
    return { kind: "UnsupportedMetaLayout", layoutVersion: layout };
  }
  const field = contextInvalidField(context);
  return field === null ? null : { kind: "InvalidInput", field };
}

/**
 * Builds the canonical byte string signed for one metadata statement
 * (CRYPTO_SPEC §4.2). The domain string embeds the suite identifier, the
 * statement kind (var / env) and — for variable layout v2 — the layout
 * version, so a signature never transplants across suites, kinds or layouts
 * (レイアウト混同は署名不一致で構造的に失敗する — §1 原則 6). Callers must
 * validate the context first (sign / verify / hash below do); this builder
 * assumes valid input.
 */
export function buildMetaSignedBytes(context: MetaStatementContext): Uint8Array {
  if (
    metaLayoutVersionOf(context) === 2 &&
    context.target.kind === "variable" &&
    context.schema !== undefined
  ) {
    return encodeLengthPrefixed([
      `${context.suite}/var-meta-sig-v2`,
      context.projectId,
      context.environmentId,
      context.target.variableId,
      context.name,
      context.status,
      context.schema.varType,
      context.schema.required,
      context.schema.description,
      context.metaVersion,
      context.prevMetaSigHashHex,
      context.authorUserId,
      context.chainHeadHashHex,
      context.chainHeadSeq,
    ]);
  }
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
  const rejection = metaContextRejection(context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
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
 * (metaVersion 1) is never `deleted` (削除はインクリメント — §4.2。作成は
 * active、または v2 変数では declared — 値なしの宣言作成): producing a
 * rule-violating statement is always a caller bug, unlike verification where
 * such wire data must be rejected with a typed reason instead.
 */
export async function signMetaStatement(input: {
  readonly context: MetaStatementContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const rejection = metaContextRejection(input.context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
  }
  if ((input.context.metaVersion === 1) !== (input.context.prevMetaSigHashHex === "")) {
    return invalidInput("context prevMetaSigHashHex");
  }
  if (input.context.metaVersion === 1 && input.context.status === "deleted") {
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
  const rejection = metaContextRejection(input.context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
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
