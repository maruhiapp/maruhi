// メタステートメントのサーバー検証(AUTH_SPEC §12-5 のメタ規則 = CRYPTO_SPEC §4.2 / §6.4)。

import type {
  ChainHistoryIndex,
  ChainMember,
  MetaInvalidReason,
  MetaPredecessor,
  MetaStatementTarget,
  MetaVariableSchema,
} from "@maruhi/crypto";
import { SUPPORTED_META_LAYOUT_VERSIONS, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { Effect } from "effect";

import type {
  DataRejectedError,
  MetaStatementInput,
  MetaStatementRejectReason,
  SchemaPolicy,
} from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import type { MetaAnchor } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS, MAX_VERSIONS_PER_VARIABLE } from "./policy.ts";
import { metaVersionsExceeded } from "./quotas.ts";

/**
 * crypto の詳細理由 → ワイヤ理由への写像(値署名の VALUE_REJECT_REASONS と同じ
 * 仮裁定 C の規約 — 3 語彙を共有し、仕様がエラー名を明示する layout-regression
 * のみ独立の理由コードで返す。§12-5)。網羅は Record 型が静的に強制する。
 */
const META_REJECT_REASONS: Readonly<Record<MetaInvalidReason, MetaStatementRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "author-unknown": "chain-head-state-mismatch",
  "author-not-member-at-head": "chain-head-state-mismatch",
  "author-key-mismatch-at-head": "chain-head-state-mismatch",
  "author-role-insufficient-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "revived-after-delete": "chain-head-state-mismatch",
  // §4.2 レイアウト v2 の遷移(active → declared)は state-mismatch へ畳む
  // (revived-after-delete と同じ遷移クラス — 仕様は個別のエラー名を与えない)
  "declared-after-active": "chain-head-state-mismatch",
  // レイアウト単調性(v2 変数への v1 後続)は仕様がエラー名を明示する(§12-5)
  "layout-regression": "layout-regression",
};

/**
 * ワイヤの MetaStatementInput → crypto の署名対象スキーマ欄(required の
 * boolean ↔ "true"/"false" の写像はこの 1 箇所)。
 */
function cryptoSchemaOf(statement: MetaStatementInput): MetaVariableSchema | undefined {
  if (statement.schema === undefined) {
    return undefined;
  }
  return {
    varType: statement.schema.varType,
    required: statement.schema.required ? "true" : "false",
    description: statement.schema.description,
  };
}

/**
 * メタステートメントの受理検証(§12-5 の 1〜3 + prev 連鎖)。検査内容:
 *
 * 1. 署名は呼び出し主体の受理時点チェーン導出 sig 鍵で検証し、author_user_id にも
 *    呼び出し主体を用いる(他人が署名したステートメントの持ち込み拒否)
 * 2. 宣言ヘッド(hash + seq)の exact pair が検証対象チェーン上に存在する
 * 3. 宣言ヘッド時点でも必要 role(環境の削除のみ admin、それ以外は member —
 *    §12-3 の二重判定)で、当時の束縛鍵 = 受理時点の鍵
 * 4. metaVersion 1 は prev 空、> 1 は保存済み直前ステートメントの signed-bytes
 *    hash と一致し、直前が deleted なら拒否(§4.2 — 再 active 化の禁止)
 *
 * エポック整合(値の §12-5 の 4)はメタに存在しない(エポックアンカーなし —
 * §4.2。環境の存在も検査しない — §12-4 の複合同梱形との両立)。
 * 座標(project / environment / variable)はサーバー側の値(genesis ハッシュ・
 * URL / 保存先)から再構成する — ワイヤの申告値から組まない(§12-5)。
 *
 * 成功時はサーバー再計算の signed_bytes ハッシュを返す(保存行に書く)。
 */
export const ensureMetaStatementSignature = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly statement: MetaStatementInput;
  /** metaVersion > 1 のとき保存済み直前ステートメントのアンカー(呼び出し側が引く)。 */
  readonly predecessor?: MetaPredecessor | undefined;
}) =>
  Effect.gen(function* () {
    const verified = yield* Effect.promise(() =>
      verifyDistributedMetaStatement({
        history: input.history,
        context: {
          suite: input.statement.suite,
          projectId: input.projectId,
          environmentId: input.environmentId,
          target: input.target,
          name: input.statement.name,
          status: input.statement.status,
          // レイアウト v2 の運搬フィールド(§12-2 — 省略 = 1)。どのレイアウトの
          // signed_bytes を再計算するかを選択する(裁定 CR)
          layoutVersion: input.statement.layoutVersion,
          schema: cryptoSchemaOf(input.statement),
          metaVersion: input.statement.metaVersion,
          prevMetaSigHashHex: input.statement.prevMetaSigHashHex,
          // author = 呼び出し主体(§12-5 の 1)。検証鍵と head 時点の束縛一致は
          // FP(受理時点のチェーン導出メンバー)で verifyDistributedMetaStatement が検査
          authorUserId: input.member.userId,
          chainHeadHashHex: input.statement.chainHeadHashHex,
          chainHeadSeq: input.statement.chainHeadSeq,
        },
        authorKeyFingerprintHex: input.member.keyFingerprintHex,
        signatureHex: input.statement.signatureHex,
        predecessor: input.predecessor,
      }),
    );
    if (verified.ok) {
      return verified.value.signedBytesHashHex;
    }
    if (verified.error.kind === "MetaStatementInvalid") {
      return yield* rejectData({
        kind: "meta-rejected",
        reason: META_REJECT_REASONS[verified.error.reason],
      });
    }
    // 申告 layoutVersion がこのサーバーのサポート範囲({1, 2})を超える形は、
    // ワイヤに layoutVersion が乗った本改訂以降「古いサーバー × 新しい
    // クライアント」の**正常系**として発生する(裁定 CR — PR #116 レビュー
    // 対応)。一次判定は各受理列の最前段の ensureSupportedLayout が担い、
    // ここは fail-closed の二重防衛(新しい受理経路が最前段の検査を落としても
    // defect = 改ざん警告と区別のつかない 500 にはならない)
    if (verified.error.kind === "UnsupportedMetaLayout") {
      return yield* rejectData({ kind: "meta-rejected", reason: "unsupported-layout" });
    }
    // InvalidInput / KeyImportFailed は Schema 検証済みワイヤ + 検証済み
    // チェーン由来の鍵では到達しない(実装バグ = defect。エラー値に秘密は
    // 含まれない)
    return yield* Effect.die(
      new Error(`meta statement verification failed: ${verified.error.kind}`),
    );
  });

/**
 * §12-1: name は NFC 正規形でなければ 422。サーバーは検査のみで正規化しない
 * (byte-exact 署名との両立 — 正規化の実施主体は署名前のクライアント)。
 */
export const ensureNfcName = (name: string): Effect.Effect<void, DataRejectedError> =>
  name.normalize("NFC") === name ? Effect.void : Effect.fail(rejectData({ kind: "name-not-nfc" }));

/**
 * ステートメントの実効レイアウト(ワイヤ規約: 省略 = 1 — §12-2)。
 */
export const statementLayoutVersion = (statement: MetaStatementInput): number =>
  statement.layoutVersion ?? 1;

/**
 * 申告 layoutVersion のサポート範囲検査(裁定 CR — §12-2 / CRYPTO_SPEC §4.2)。
 * **v2 系の他のどの受理検査よりも前**に呼ぶ: サポート外レイアウト(v3〜 —
 * 「古いサーバー × 新しいクライアント」の正常系)には schemaPolicy ゲート・
 * schema-locked・削除の直前一致などの判定が原理的に定義できず、それらの
 * エラーを先に返すと「ポリシーを直せば通る」という誤誘導になる。正直な
 * update-required = `unsupported-layout` を常に最初に返す。
 * (署名検証内の同判定 — crypto の UnsupportedMetaLayout — は fail-closed の
 * 二重防衛として残る)。
 */
export const ensureSupportedLayout = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  SUPPORTED_META_LAYOUT_VERSIONS.includes(statementLayoutVersion(statement))
    ? Effect.void
    : Effect.fail(rejectData({ kind: "meta-rejected", reason: "unsupported-layout" }));

/**
 * §12-8: スキーマ description の受理検査 — 1024 コードポイント以下・制御文字
 * (Unicode カテゴリ Cc — 改行・タブ・ANSI エスケープの ESC を含む)なし。
 * NFC 正規化は要求しない(識別子でなく照合に使わない — name との意図的な差)。
 * v1 ステートメント(スキーマ欄なし)は対象外。本検査は受理ポリシーであり
 * 悪意サーバーの配布を拘束しない(クライアントの表示は独立に必ず中和する)。
 */
export const ensureDescriptionPolicy = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> => {
  if (statement.schema === undefined) {
    return Effect.void;
  }
  const description = statement.schema.description;
  if (/\p{Cc}/u.test(description)) {
    return Effect.fail(rejectData({ kind: "description-rejected", reason: "control-characters" }));
  }
  // 上限は Unicode コードポイント数(UTF-16 コード単位ではない — §12-8)
  if ([...description].length > MAX_SCHEMA_DESCRIPTION_CODEPOINTS) {
    return Effect.fail(rejectData({ kind: "description-rejected", reason: "too-long" }));
  }
  return Effect.void;
};

/**
 * §12-11 / §12-5 の有効化ゲート: disabled のプロジェクトはレイアウト v2 の
 * **新規採用**(metaVersion 1 の v2 作成と、直前ステートメントが v1 の変数への
 * v2 再発行)を 422 で拒否する。直前が既に v2 の変数の継続ステートメント
 * (削除・activation・rename・スキーマ再発行)はポリシーに依らず受理する
 * (可逆性 — 降格が既存 v2 変数のライフサイクルを凍結しない)。v1 ステート
 * メントはポリシーに依らず従来どおり受理する。判定は受理時点のポリシー
 * (project DO の直列化の中で呼び出し側が読む)。
 */
export const ensureSchemaPolicyAllowsLayout = (input: {
  readonly schemaPolicy: SchemaPolicy;
  readonly statement: MetaStatementInput;
  /** 直前ステートメントの実効レイアウト(作成 = 直前なしは 1 を渡す)。 */
  readonly predecessorLayoutVersion: number;
}): Effect.Effect<void, DataRejectedError> =>
  input.schemaPolicy === "disabled" &&
  statementLayoutVersion(input.statement) >= 2 &&
  input.predecessorLayoutVersion === 1
    ? Effect.fail(rejectData({ kind: "schema-policy-rejected", reason: "schema-policy-disabled" }))
    : Effect.void;

/**
 * §12-5: 削除ステートメントのスキーマ欄・レイアウトは直前ステートメントと
 * byte-exact に一致すること(name の「直前の active 名を保持」と同じ規約の
 * 受理検査 — crypto 層は意図的に検査しない。実装しないと有効署名を持つ改変
 * 削除〔スキーマ欄を書き換えた status = deleted〕が受理される)。不一致は
 * name と同じ payload-mismatch(不一致フィールド名付き)で拒否する。
 */
function deletePreservationMismatch(
  anchor: MetaAnchor,
  statement: MetaStatementInput,
): string | null {
  if (statementLayoutVersion(statement) !== anchor.layoutVersion) {
    return "layoutVersion";
  }
  if (anchor.schema === null || statement.schema === undefined) {
    // レイアウト一致済み: 両方 v1(スキーマ欄なし)のみここへ来る
    return null;
  }
  if (statement.schema.varType !== anchor.schema.varType) {
    return "varType";
  }
  if (statement.schema.required !== anchor.schema.required) {
    return "required";
  }
  if (statement.schema.description !== anchor.schema.description) {
    return "description";
  }
  return null;
}

/** metaVersion の CAS(§12-5): 申告 == 最新 + 1 のみ。409 は最新番号のみを返す。 */
export const ensureMetaCas = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  statement.metaVersion === latestMetaVersion + 1
    ? Effect.void
    : Effect.fail(
        rejectData({ kind: "meta-version-conflict", currentMetaVersion: latestMetaVersion }),
      );

const ensureMetaQuota = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  metaVersionsExceeded(latestMetaVersion, statement.status)
    ? Effect.fail(
        rejectData({
          kind: "limit-exceeded",
          resource: "meta-versions",
          limit: MAX_VERSIONS_PER_VARIABLE,
        }),
      )
    : Effect.void;

/**
 * rename / スキーマ再発行 / 削除 / activation に共通するメタ受理列(§12-5):
 * metaVersion 上限 → CAS(409 は最新番号のみ)→ 保存済み直前ステートメントの
 * アンカー取得(CAS 通過後は必ず存在 — 欠落は defect)→ 受理面の v2 検査
 * (schemaPolicy の有効化ゲート・description の受理ポリシー・削除ステートメントの
 * スキーマ欄/レイアウト直前一致)→ 署名検証(predecessor 込み — prev 連鎖・
 * 削除後の再ステートメント拒否・遷移規則・レイアウト単調性)。
 * 成功時はサーバー再計算の signed_bytes ハッシュを返す。
 */
export const acceptMetaStatement = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly statement: MetaStatementInput;
  /**
   * 受理時点の schemaPolicy(変数ステートメントのみ — 呼び出し側が DO permit
   * 下で読む。環境ステートメントは v2 の対象外なので渡さない)。
   */
  readonly schemaPolicy?: SchemaPolicy;
}) =>
  Effect.gen(function* () {
    // サポート範囲検査は最前段(ensureSupportedLayout の doc — 裁定 CR)
    yield* ensureSupportedLayout(input.statement);
    yield* ensureMetaQuota(input.latestMetaVersion, input.statement);
    yield* ensureMetaCas(input.latestMetaVersion, input.statement);
    const store = yield* DataStore;
    const anchor =
      input.target.kind === "variable"
        ? yield* store.variableMetaAnchor(
            input.environmentId,
            input.target.variableId,
            input.latestMetaVersion,
          )
        : yield* store.environmentMetaAnchor(input.environmentId, input.latestMetaVersion);
    if (anchor === null) {
      return yield* Effect.die(new Error("meta predecessor row missing after CAS acceptance"));
    }
    // 有効化ゲート(§12-11): disabled 下の v1 変数への v2 再発行を拒否する
    // (直前が v2 の継続ステートメントはポリシーに依らず通る)
    if (input.schemaPolicy !== undefined) {
      yield* ensureSchemaPolicyAllowsLayout({
        schemaPolicy: input.schemaPolicy,
        statement: input.statement,
        predecessorLayoutVersion: anchor.layoutVersion,
      });
    }
    // description の受理ポリシー(§12-8 — v1 ステートメントは対象外)
    yield* ensureDescriptionPolicy(input.statement);
    // 削除ステートメントのスキーマ欄・レイアウトの直前一致(§12-5 — S2 義務)
    if (input.target.kind === "variable" && input.statement.status === "deleted") {
      const field = deletePreservationMismatch(anchor, input.statement);
      if (field !== null) {
        return yield* rejectData({ kind: "payload-mismatch", field });
      }
    }
    return yield* ensureMetaStatementSignature({
      projectId: input.projectId,
      environmentId: input.environmentId,
      target: input.target,
      history: input.history,
      member: input.member,
      statement: input.statement,
      // アンカーの保存実値(layout_version 列 — レイアウト単調性検査の入力。
      // MetaPredecessor.layoutVersion は fail-closed の必須フィールド)
      predecessor: {
        signedBytesHashHex: anchor.signedBytesHashHex,
        status: anchor.status,
        layoutVersion: anchor.layoutVersion,
      },
    });
  });
