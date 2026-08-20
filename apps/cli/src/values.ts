// 配布された値・メタデータステートメントの検証(CRYPTO_SPEC §6.3)。
//
// 復号・名前解決より前に、すべての値の §4.1 値署名と、環境・全変数(削除済み
// 含む)の §4.2 メタステートメントを検証済みチェーン履歴に対して検証する。
// 期待座標は申告値を信用せず自前で組み立てる: projectId = 検証済み genesis
// ハッシュ、environmentId = リクエストに使った ID、variableId = pull 応答の
// 外側メタデータ。writer / author は配布された user_id + 鍵 FP(チェーン履歴と
// 照合)。名前はステートメント検証を経たものだけを信用する(§12-2 — 裸の
// name スナップショットは wire から消えた)。
//
// future head(宣言 seq > 自ビューのヘッド)は値・ステートメントとも即時拒否
// せず、**1 回だけ**再同期して延長検査(sync.ts の ensureExtensionOf)を通し、
// 新ビューで全体を再検証する(有界 — §6.3-2b。PR-2 の機構の流用)。
//
// 同一環境内で同名の active ステートメントが複数検証に通る場合(サーバーの
// equivocation)は解決を拒否する(§4.2)。非 NFC 名の配布は警告(SHOULD —
// §12-1。byte-exact 照合は誤解決を生まないが、視覚的同名の並存を不可視に
// しない)。deleted 済み variableId の active 併置(無断復活の運搬形)は拒否。
//
// latest-only の限界(裁定 B): pull は最新版のみ運ぶため predecessor を持たず、
// 値の prev 実在一致・エポック非減少、メタの prev 実在一致・削除後の再 active 化
// はここでは検査できない(形の検査のみ)。検査済みと偽らない — 永続床による
// 検出は PR-4 の領分。**メタはエポックアンカーを持たないため、前進 meta_version
// への注入は床を持っても検出されない**(§14.3-5 の既知残余)。

import type {
  DistributedEncryptedPayload,
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  RecipientDek,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { MetaStatementContext } from "@maruhi/crypto";
import { verifyDistributedMetaStatement, verifyDistributedValue } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { requireChainEnvironment } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import {
  buildEnvironmentFloor,
  checkEnvironmentMetadataPull,
  checkEnvironmentPull,
  type FloorHandle,
  type VerifiedActiveStatement,
  type VerifiedMetaEvidence,
  type VerifiedPullSnapshot,
  type VerifiedTombstone,
} from "./floor-check.ts";
import { formatFloorViolation } from "./floor-evidence.ts";
import type { ManifestFloor } from "./floor.ts";
import {
  type ManifestDigestEntry,
  missingManifestMessage,
  type VerifiedManifest,
  verifyDistributedManifest,
} from "./manifest.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

/** One pulled variable whose write signature and statement passed §6.3. */
export interface VerifiedPulledValue {
  readonly variableId: string;
  /** 検証済みステートメントの name(これ以外の名前を信用しない — §12-2)。 */
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** 署名済みの prev(直前 version の signed bytes ハッシュ。version 1 は空)。 */
  readonly prevValueSigHashHex: string;
  /**
   * Locally recomputed hash of the value's signed bytes — the prev anchor
   * for pushing the next version (§4.1 の連鎖) and the comparator for
   * same-coordinate equivocation evidence (§14.2-5).
   */
  readonly signedBytesHashHex: string;
  /** 検証済みステートメントの metaVersion(巻き戻し・fork 検査の基準)。 */
  readonly metaVersion: number;
  /** ステートメントの signed bytes ハッシュ(自計算 — 同一 metaVersion の相違検査)。 */
  readonly metaSignedBytesHashHex: string;
  /** 署名済みの prev(直前 metaVersion の signed bytes ハッシュ。metaVersion 1 は空)。 */
  readonly prevMetaSigHashHex: string;
  /** 値署名の宣言ヘッド(床検査の fork 証拠に含める — §6.3 / §14.2-5)。 */
  readonly valueChainHeadSeq: number;
  readonly valueChainHeadHashHex: string;
  /** メタステートメントの宣言ヘッド(同上)。 */
  readonly metaChainHeadSeq: number;
  readonly metaChainHeadHashHex: string;
  /** 検証済みの値署名と帰属(fork 証拠の自己完結性 — §14.2-5)。 */
  readonly valueSignatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
  /** 検証済みのステートメント署名と帰属(同上)。 */
  readonly metaSignatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/** A bulk pull whose values and statements all passed verification (§12-7 / §6.3). */
export interface VerifiedEnvironmentPull {
  /** 検証に使ったビュー(future head の有界再同期で前進していることがある)。 */
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedPulledValue[];
  /** 検証済み tombstone(マニフェスト発行のダイジェスト材料 — §4.3)。 */
  readonly tombstones: readonly VerifiedTombstone[];
  /** 検証済みの環境メタステートメント(マニフェスト発行の envMeta 材料)。 */
  readonly environment: VerifiedMetaEvidence;
  /**
   * 検証済みマニフェスト(§4.3)。null は移行経路(allowMissingManifest)が
   * 欠落を許容した場合のみ — 通常経路の欠落は拒否済み(§6.3)。
   */
  readonly manifest: VerifiedManifest | null;
  /** 自分宛ラップ(検証は deks.ts の §5.1 / §5.2 経路が担う)。 */
  readonly deks: readonly RecipientDek[];
  /** 非 NFC 名の配布などの SHOULD 警告(呼び出し側が表示する)。 */
  readonly warnings: readonly string[];
}

/** One pulled variable on the wire (statement + value — AUTH_SPEC §12-7 / §14-2). */
export interface PulledWire {
  readonly variableId: string;
  readonly statement: DistributedVariableMetaStatement;
  readonly value: DistributedEncryptedPayload;
}

type VerifyOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "future" }
  | { readonly kind: "rejected"; readonly message: string };

/** 申告 AAD の座標成分が期待座標(検証済み genesis / 要求 env / 応答外側 id)と一致するか(§6.3-5)。 */
function coordinatesMatch(
  verified: VerifiedProject,
  environmentId: string,
  variable: PulledWire,
): boolean {
  const aad = variable.value.aad;
  return (
    aad.projectId === verified.projectId &&
    aad.environmentId === environmentId &&
    aad.variableId === variable.variableId
  );
}

/**
 * 検証失敗理由 → future / rejected。chain-head-future と「未同期区間の新規
 * メンバーが宣言する自ビューより先のヘッド(writer / author が未知 かつ 宣言
 * seq > 自ヘッド)」は有界再同期の入口(future)へ。それ以外は拒否
 * (PR-2 レビューループ 1 [低] の分類を値・メタで共有する)。
 */
function failureOutcome<T>(
  verified: VerifiedProject,
  label: string,
  chainHeadSeq: number,
  error: { readonly kind: string; readonly reason?: string },
): VerifyOutcome<T> {
  if (error.kind === "ValueInvalid" || error.kind === "MetaStatementInvalid") {
    const unknownSigner = error.reason === "writer-unknown" || error.reason === "author-unknown";
    if (
      error.reason === "chain-head-future" ||
      (unknownSigner && chainHeadSeq > verified.history.headSeq)
    ) {
      return { kind: "future" };
    }
  }
  const reason = error.reason ?? error.kind;
  return {
    kind: "rejected",
    message: `Verification of ${label} failed (reason=${reason}). It may have been replaced or forged by the server`,
  };
}

/**
 * 検証済みステートメント → 証拠材料の共通フィールド(§14.2-5 の自己完結性)。
 * 床検査と証拠表示が使う 7 フィールドの写像をここに一本化する(手書きの
 * 再列挙で 1 フィールド落とすと、テストに落ちずに equivocation 証拠が黙って
 * 弱くなるため)。
 */
function metaEvidenceFields(
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  metaSigHashHex: string,
): Omit<VerifiedMetaEvidence, "status"> {
  return {
    metaVersion: statement.metaVersion,
    metaSigHashHex,
    chainHeadSeq: statement.chainHeadSeq,
    chainHeadHashHex: statement.chainHeadHashHex,
    signatureHex: statement.signatureHex,
    authorUserId: statement.authorUserId,
    authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
  };
}

/** ステートメントの複合検証(§6.3)。期待座標から context を自前で組む。 */
async function verifyStatement(
  verified: VerifiedProject,
  environmentId: string,
  target: MetaStatementContext["target"],
  statement: DistributedVariableMetaStatement | DistributedEnvironmentMetaStatement,
  label: string,
): Promise<VerifyOutcome<{ readonly signedBytesHashHex: string }>> {
  const result = await verifyDistributedMetaStatement({
    history: verified.history,
    context: {
      suite: statement.suite,
      projectId: verified.projectId,
      environmentId,
      target,
      name: statement.name,
      status: statement.status,
      metaVersion: statement.metaVersion,
      prevMetaSigHashHex: statement.prevMetaSigHashHex,
      authorUserId: statement.authorUserId,
      chainHeadHashHex: statement.chainHeadHashHex,
      chainHeadSeq: statement.chainHeadSeq,
    },
    authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
    signatureHex: statement.signatureHex,
  });
  if (!result.ok) {
    return failureOutcome(verified, label, statement.chainHeadSeq, result.error);
  }
  return { kind: "ok", value: result.value };
}

async function verifyOne(
  verified: VerifiedProject,
  environmentId: string,
  variable: PulledWire,
): Promise<VerifyOutcome<VerifiedPulledValue>> {
  const payload = variable.value;
  const statement = variable.statement;
  // 座標整合(§6.3-5): 検証・復号は期待座標で行うため不一致はどのみち失敗するが、
  // 明示検査で「どの座標が食い違ったか」を可視化する。名前はステートメント検証を
  // 通るまで信用できないため、メッセージは variableId で識別する
  if (!coordinatesMatch(verified, environmentId, variable)) {
    return {
      kind: "rejected",
      message: `Variable ${displayText(variable.variableId)} declares AAD coordinates that do not match the requested context (an inconsistent server response)`,
    };
  }
  if (statement.environmentId !== environmentId || statement.variableId !== variable.variableId) {
    return {
      kind: "rejected",
      message: `Variable ${displayText(variable.variableId)} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
    };
  }
  // 名前 → variableId の対応は検証済みステートメント経由が必須(§4.2 / §12-7)
  const verifiedStatement = await verifyStatement(
    verified,
    environmentId,
    { kind: "variable", variableId: variable.variableId },
    statement,
    `variable ${displayText(variable.variableId)}'s meta statement`,
  );
  if (verifiedStatement.kind !== "ok") {
    return verifiedStatement;
  }
  if (statement.status !== "active") {
    return {
      kind: "rejected",
      message: `Variable ${displayText(variable.variableId)} was served a deleted statement together with a value (a possible unauthorized undeletion)`,
    };
  }
  const result = await verifyDistributedValue({
    history: verified.history,
    context: {
      suite: payload.suite,
      projectId: verified.projectId,
      environmentId,
      epoch: payload.aad.epoch,
      variableId: variable.variableId,
      version: payload.aad.version,
      nonceHex: payload.nonceHex,
      ciphertextHex: payload.ciphertextHex,
      prevValueSigHashHex: payload.prevValueSigHashHex,
      writerUserId: payload.writerUserId,
      chainHeadHashHex: payload.chainHeadHashHex,
      chainHeadSeq: payload.chainHeadSeq,
    },
    writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
    signatureHex: payload.signatureHex,
  });
  if (!result.ok) {
    return failureOutcome(
      verified,
      `variable ${displayText(statement.name)}'s value signature`,
      payload.chainHeadSeq,
      result.error,
    );
  }
  return {
    kind: "ok",
    value: {
      variableId: variable.variableId,
      name: statement.name,
      version: payload.aad.version,
      epoch: payload.aad.epoch,
      nonceHex: payload.nonceHex,
      ciphertextHex: payload.ciphertextHex,
      prevValueSigHashHex: payload.prevValueSigHashHex,
      signedBytesHashHex: result.value.signedBytesHashHex,
      metaVersion: statement.metaVersion,
      metaSignedBytesHashHex: verifiedStatement.value.signedBytesHashHex,
      prevMetaSigHashHex: statement.prevMetaSigHashHex,
      valueChainHeadSeq: payload.chainHeadSeq,
      valueChainHeadHashHex: payload.chainHeadHashHex,
      metaChainHeadSeq: statement.chainHeadSeq,
      metaChainHeadHashHex: statement.chainHeadHashHex,
      valueSignatureHex: payload.signatureHex,
      writerUserId: payload.writerUserId,
      writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
      metaSignatureHex: statement.signatureHex,
      authorUserId: statement.authorUserId,
      authorKeyFingerprintHex: statement.authorKeyFingerprintHex,
    },
  };
}

interface PullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  /** 最新マニフェスト(§12-7 — 欠落は一律拒否 §6.3。optional は移行の過渡状態のみ)。 */
  readonly manifest?: DistributedEnvironmentManifest;
}

/** 環境自身のステートメント検証(active であること込み)。証拠材料を返す。 */
async function verifyEnvironmentStatement(
  verified: VerifiedProject,
  environmentId: string,
  statement: DistributedEnvironmentMetaStatement,
): Promise<VerifyOutcome<VerifiedMetaEvidence>> {
  if (statement.environmentId !== environmentId) {
    return {
      kind: "rejected",
      message: `The environment statement's coordinates do not match the requested environment ${environmentId} (possible transplantation)`,
    };
  }
  const result = await verifyStatement(
    verified,
    environmentId,
    { kind: "environment" },
    statement,
    `environment ${environmentId}'s meta statement`,
  );
  if (result.kind !== "ok") {
    return result;
  }
  if (statement.status !== "active") {
    return {
      kind: "rejected",
      message: `Environment ${environmentId} was served a deleted statement (distribution of a deleted environment — an inconsistent server response)`,
    };
  }
  return {
    kind: "ok",
    value: {
      status: "active",
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    },
  };
}

/** 削除済み変数の tombstone ステートメント検証(active 側との併置 = 無断復活の運搬形も拒否)。 */
async function verifyDeletedStatements(
  verified: VerifiedProject,
  environmentId: string,
  deleted: readonly DistributedVariableMetaStatement[],
  activeIds: ReadonlySet<string>,
): Promise<VerifyOutcome<readonly VerifiedTombstone[]>> {
  const seen = new Set<string>();
  const tombstones: VerifiedTombstone[] = [];
  for (const statement of deleted) {
    if (statement.environmentId !== environmentId) {
      return {
        kind: "rejected",
        message: `Deleted variable ${displayText(statement.variableId)} has statement coordinates that do not match the requested environment`,
      };
    }
    if (seen.has(statement.variableId) || activeIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        message: `Variable ${displayText(statement.variableId)} was served as both active and deleted (an unauthorized undeletion = equivocation in transit)`,
      };
    }
    seen.add(statement.variableId);
    if (statement.status !== "deleted") {
      return {
        kind: "rejected",
        message: `An active statement was served in the deleted list: ${displayText(statement.variableId)}`,
      };
    }
    const result = await verifyStatement(
      verified,
      environmentId,
      { kind: "variable", variableId: statement.variableId },
      statement,
      `deleted variable ${displayText(statement.variableId)}'s meta statement`,
    );
    if (result.kind !== "ok") {
      return result;
    }
    tombstones.push({
      variableId: statement.variableId,
      // deleted は直前 active 名を保持する(§4.2)— 削除済み変数の表示名の
      // 検証済みの唯一の源(要ローテーションフラグの名前解決 — AUDIT_SPEC §7)
      name: statement.name,
      status: "deleted",
      ...metaEvidenceFields(statement, result.value.signedBytesHashHex),
    });
  }
  return { kind: "ok", value: tombstones };
}

/** 検証済み active 集合の名前検査: 同名 active の重複 = 解決拒否(§4.2)、非 NFC = 警告(SHOULD)。 */
function checkVerifiedNames(
  values: readonly { readonly variableId: string; readonly name: string }[],
  warnings: string[],
): string | null {
  const seenNames = new Set<string>();
  for (const value of values) {
    // 一意性は byte-exact 比較(§12-1。全受理名が NFC ならば NFC 一致と同値)
    if (seenNames.has(value.name)) {
      return `Multiple active statements with the same name passed verification (server equivocation): ${displayText(value.name)}. Refusing name resolution`;
    }
    seenNames.add(value.name);
    if (value.name.normalize("NFC") !== value.name) {
      warnings.push(
        `Variable ${displayText(value.variableId)} has a name that is not NFC-normalized (an honest server would not accept it — beware that visually identical names may coexist)`,
      );
    }
  }
  return null;
}

/**
 * メタデータのみ pull のアクティブ変数ステートメント群の検証(§12-7 の
 * メタデータのみモード)。座標整合・variableId 重複拒否・active であることの
 * 検査は値付き pull の verifyOne と同一の規律で、値署名の検証だけがない。
 */
async function verifyActiveStatements(
  verified: VerifiedProject,
  environmentId: string,
  statements: readonly DistributedVariableMetaStatement[],
): Promise<
  VerifyOutcome<{ readonly values: readonly VerifiedActiveStatement[]; readonly ids: Set<string> }>
> {
  const seenIds = new Set<string>();
  const values: VerifiedActiveStatement[] = [];
  for (const statement of statements) {
    if (statement.environmentId !== environmentId) {
      return {
        kind: "rejected",
        message: `Variable ${displayText(statement.variableId)} has statement coordinates that do not match the requested context (possible renaming or transplantation)`,
      };
    }
    if (seenIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        message: `Duplicate variable IDs within one response (an inconsistent server response): ${statement.variableId}`,
      };
    }
    seenIds.add(statement.variableId);
    const outcome = await verifyStatement(
      verified,
      environmentId,
      { kind: "variable", variableId: statement.variableId },
      statement,
      `variable ${displayText(statement.variableId)}'s meta statement`,
    );
    if (outcome.kind !== "ok") {
      return outcome;
    }
    if (statement.status !== "active") {
      return {
        kind: "rejected",
        message: `Variable ${displayText(statement.variableId)} was served a deleted statement in the active list (a possible unauthorized undeletion)`,
      };
    }
    values.push({
      variableId: statement.variableId,
      name: statement.name,
      status: "active",
      ...metaEvidenceFields(statement, outcome.value.signedBytesHashHex),
    });
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

/** アクティブ変数群の検証(variableId 重複の拒否込み)。 */
async function verifyActiveVariables(
  verified: VerifiedProject,
  environmentId: string,
  variables: readonly PulledWire[],
): Promise<
  VerifyOutcome<{ readonly values: readonly VerifiedPulledValue[]; readonly ids: Set<string> }>
> {
  const seenIds = new Set<string>();
  const values: VerifiedPulledValue[] = [];
  for (const variable of variables) {
    // 同一応答内の variableId 重複は無条件拒否(同一座標に異なる signed bytes を
    // 併置する equivocation の運搬形を含む — 裁定 G)
    if (seenIds.has(variable.variableId)) {
      return {
        kind: "rejected",
        message: `Duplicate variable IDs within one response (an inconsistent server response): ${variable.variableId}`,
      };
    }
    seenIds.add(variable.variableId);
    const outcome = await verifyOne(verified, environmentId, variable);
    if (outcome.kind !== "ok") {
      return outcome;
    }
    values.push(outcome.value);
  }
  return { kind: "ok", value: { values, ids: seenIds } };
}

/** 検証段の実行結果(rejected は失敗チャネルへ潰し済み — future | ok の 2 値)。 */
type StageResult<T> = { readonly kind: "ok"; readonly value: T } | { readonly kind: "future" };

/**
 * 検証段の共通ラッパ: crypto 実行自体の失敗を CliError へ、rejected を失敗
 * チャネルへ潰す(各段の残余は future | ok の 2 値になる)。
 */
function verifyStage<T>(
  run: () => Promise<VerifyOutcome<T>>,
  description: string,
): Effect.Effect<StageResult<T>, CliError> {
  return Effect.gen(function* () {
    const outcome = yield* Effect.tryPromise({
      try: run,
      catch: () => cliError(`${description} failed to run (crypto error)`),
    });
    if (outcome.kind === "rejected") {
      return yield* Effect.fail(cliError(outcome.message));
    }
    return outcome.kind === "future"
      ? ({ kind: "future" } as const)
      : ({ kind: "ok", value: outcome.value } as const);
  });
}

/**
 * マニフェスト段(§4.3 / §6.3): 欠落 = 一律拒否(唯一の例外は移行経路の
 * allowMissingManifest — manifest.ts のモジュールコメント)。配布された場合は
 * 検証済み全ステートメント(tombstone 込み)からダイジェストを再計算して照合する。
 */
function verifyManifestStage(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly manifest: DistributedEnvironmentManifest | undefined;
  readonly allowMissingManifest: boolean;
  readonly entries: readonly ManifestDigestEntry[];
  readonly environment: VerifiedMetaEvidence;
  /** 床のマニフェスト記録(隣接 prev 検証の predecessor — M1-A1。床なし = null)。 */
  readonly floorManifest: ManifestFloor | null;
}): Effect.Effect<StageResult<VerifiedManifest | null>, CliError> {
  const wireManifest = input.manifest;
  if (wireManifest === undefined) {
    return input.allowMissingManifest
      ? Effect.succeed({ kind: "ok", value: null } as const)
      : Effect.fail(cliError(missingManifestMessage(input.environmentId)));
  }
  return verifyStage(
    () =>
      verifyDistributedManifest({
        verified: input.verified,
        environmentId: input.environmentId,
        manifest: wireManifest,
        entries: input.entries,
        envMeta: {
          metaVersion: input.environment.metaVersion,
          sigHashHex: input.environment.metaSigHashHex,
        },
        floorManifest: input.floorManifest,
      }),
    "Environment-manifest verification",
  );
}

/**
 * pull 応答の共通検証骨格(§6.3): 環境ステートメント → アクティブ集合(値付き /
 * メタのみで差し替わる)→ tombstone → 名前検査 → **マニフェスト**(ダイジェスト
 * 再計算・エポック整合 — §4.3。欠落 = 一律拒否。唯一の例外は移行経路の
 * allowMissingManifest — manifest.ts のモジュールコメント)。future はどの段でも
 * 全体を future にする(有界再同期の入口)。
 */
function verifyAllCommon<T extends { readonly variableId: string; readonly name: string }>(
  verified: VerifiedProject,
  environmentId: string,
  pull: {
    readonly statement: DistributedEnvironmentMetaStatement;
    readonly deletedVariables: readonly DistributedVariableMetaStatement[];
    readonly manifest?: DistributedEnvironmentManifest | undefined;
  },
  verifyActives: () => Promise<
    VerifyOutcome<{ readonly values: readonly T[]; readonly ids: Set<string> }>
  >,
  /** 検証済みアクティブ 1 件 → variables_digest のエントリ(§4.3 (3) の再計算材料)。 */
  digestEntryOf: (value: T) => ManifestDigestEntry,
  /** 移行経路(--init-manifest)のみ true — 欠落の許容であって検証の緩和ではない。 */
  allowMissingManifest: boolean,
  /** 床のマニフェスト記録(隣接 prev 検証 — M1-A1。床を持たない経路は null)。 */
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedMetaEvidence;
      readonly variables: readonly T[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest | null;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return Effect.gen(function* () {
    const environment = yield* verifyStage(
      () => verifyEnvironmentStatement(verified, environmentId, pull.statement),
      "Environment-statement verification",
    );
    if (environment.kind === "future") {
      return { kind: "future" } as const;
    }
    const actives = yield* verifyStage(
      verifyActives,
      "Variable-statement / value-signature verification",
    );
    if (actives.kind === "future") {
      return { kind: "future" } as const;
    }
    const deleted = yield* verifyStage(
      () =>
        verifyDeletedStatements(verified, environmentId, pull.deletedVariables, actives.value.ids),
      "Deleted-variable-statement verification",
    );
    if (deleted.kind === "future") {
      return { kind: "future" } as const;
    }
    const warnings: string[] = [];
    const nameFailure = checkVerifiedNames(actives.value.values, warnings);
    if (nameFailure !== null) {
      return yield* Effect.fail(cliError(nameFailure));
    }
    const manifest = yield* verifyManifestStage({
      verified,
      environmentId,
      manifest: pull.manifest,
      allowMissingManifest,
      entries: [
        ...actives.value.values.map(digestEntryOf),
        ...deleted.value.map((tombstone) => ({
          variableId: tombstone.variableId,
          status: "deleted" as const,
          metaVersion: tombstone.metaVersion,
          metaSigHashHex: tombstone.metaSigHashHex,
        })),
      ],
      environment: environment.value,
      floorManifest,
    });
    if (manifest.kind === "future") {
      return { kind: "future" } as const;
    }
    return {
      kind: "ok",
      environment: environment.value,
      variables: actives.value.values,
      tombstones: deleted.value,
      manifest: manifest.value,
      warnings,
    } as const;
  });
}

function verifyAll(
  verified: VerifiedProject,
  environmentId: string,
  pull: PullWire,
  allowMissingManifest: boolean,
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly snapshot: VerifiedPullSnapshot;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(
    verified,
    environmentId,
    pull,
    () => verifyActiveVariables(verified, environmentId, pull.variables),
    (value) => ({
      variableId: value.variableId,
      status: "active" as const,
      metaVersion: value.metaVersion,
      metaSigHashHex: value.metaSignedBytesHashHex,
    }),
    allowMissingManifest,
    floorManifest,
  ).pipe(
    Effect.map((result) =>
      result.kind === "future"
        ? result
        : ({
            kind: "ok",
            snapshot: {
              environment: result.environment,
              variables: result.variables,
              tombstones: result.tombstones,
              manifest: result.manifest,
            },
            warnings: result.warnings,
          } as const),
    ),
  );
}

/**
 * 検証済み配布物に対する meta-op intent の照合(§6.3 記録規律 (ii) — 3-F)。
 * 検証済みマニフェストが intent の版へ到達・追い越していれば、確認義務は
 * 解決できる:
 * - 同版・同ハッシュ = 自分の発行が配布されている(accepted)
 * - 同版・異ハッシュ = 自分の発行は保存されていない(not-accepted — 配布側の
 *   検証済みマニフェストは観測として床へ join 済みで、証拠は失われない)
 * - 前進 = 検証済み後続状態の観測により義務を果たした(superseded)
 * - 配布版が intent より古い = 未解決のまま(次の照合機会に持ち越す)
 */
function resolveMetaIntents(
  floor: FloorHandle,
  manifest: VerifiedManifest | null,
): Effect.Effect<void, CliError> {
  if (manifest === null) {
    return Effect.void;
  }
  return Effect.forEach(
    floor.unresolvedIntents().filter((intent) => intent.op === "meta-op"),
    (intent) => {
      if (manifest.manifestVersion > intent.manifestVersion) {
        return floor.resolveIntent(intent.id, "superseded");
      }
      if (manifest.manifestVersion === intent.manifestVersion) {
        return floor.resolveIntent(
          intent.id,
          manifest.signedBytesHashHex === intent.manifestSigHashHex ? "accepted" : "not-accepted",
        );
      }
      return Effect.void;
    },
    { discard: true },
  );
}

/**
 * 床検査(§6.3 の (a)(b)(c))と床コミット(更新順序の規範: 検査は前回成功
 * pull の基準、基準の前進は検証成功後に変数床と原子的に)。検査はすべて
 * 署名検証を通過したデータ同士の比較なので、不一致は否認不能な証拠であり
 * 全件拒否する(§6.3 の「拒否・警告」の強い側)。
 *
 * コミット点は §6.3 検証成功(以後のラップ検証・復号の失敗で床は巻き戻さない
 * — 記録されるのは署名検証済みダイジェストのみで、基準の単調性論証は復号の
 * 成否と独立。「成功した pull(検証込み)」の「検証」は §6.3 を指す解釈)。
 */
function enforceFloor(input: {
  readonly floor: FloorHandle;
  /**
   * 規則 (c) 基準の導出に使うビュー。**pull 応答の取得より前に検証したビュー**
   * でなければならない: 応答より新しいビュー(future head の有界再同期後)から
   * 基準を導出すると、応答生成と再同期の間の rotate で基準が過前進し、
   * 「ローテーション後・再暗号化完了前の正当な旧エポック最新値」(§12-7)を
   * 次回 pull で誤拒否する(§6.3 の「チェーン同期単独で基準を前進させない」
   * 規範の再同期経路への適用 — レビュー②)。基準 ≤ 応答生成時点のエポックなら、
   * 以後に受理される正規 push のエポックは常に基準以上で誤拒否がない。
   */
  readonly baselineView: VerifiedProject;
  /** 検証に使ったビュー(床のチェーンヘッドのコミット値)。 */
  readonly commitView: VerifiedProject;
  readonly environmentId: string;
  readonly snapshot: VerifiedPullSnapshot;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const violation = checkEnvironmentPull(input.floor.current(), input.snapshot);
    if (violation !== null) {
      // 拒否 + 提示可能な証拠(座標・両 signed bytes ハッシュ・宣言ヘッド)
      return yield* Effect.fail(
        cliError(
          formatFloorViolation(
            { projectId: input.commitView.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    // 環境がチェーンに存在しないのに検証を通る配布はここで止まる(メタは
    // エポックアンカーを持たないため、変数ゼロの環境ではステートメント検証
    // だけでは検出できない)
    yield* requireChainEnvironment(input.commitView, input.environmentId);
    // 規則 (c) 基準の前進値 = 応答取得前ビューのチェーン導出現エポック(§6.2 —
    // サーバー申告の currentEpoch は使わない)
    const baselineEnvironment = input.baselineView.state.environments.get(input.environmentId);
    if (baselineEnvironment === undefined) {
      // 応答取得と再同期の間に環境が作られた稀なレース: 基準を過前進させずに
      // 導出できるビューがないため、このコミットは見送る(次回 pull で確立。
      // 床は SHOULD — 検出材料の確立が一周遅れるだけで誤検出はない)
      return;
    }
    yield* input.floor.commitPull(
      buildEnvironmentFloor(baselineEnvironment.currentEpoch, input.snapshot),
      { seq: input.commitView.state.headSeq, hashHex: input.commitView.state.headHashHex },
    );
    // 検証済み配布物が到達したので、この環境の未解決 meta intent(3-F)を照合する
    yield* resolveMetaIntents(input.floor, input.snapshot.manifest);
  });
}

/**
 * pull 系の共通骨格(§6.3-2b): 取得 → 検証 → 床検査(accept)。future
 * (宣言ヘッドが自ビューより先 = 自チェーンが古いだけの可能性)はどの段でも
 * **1 回だけ**再同期し、旧ビューの延長であることを検査してから全体を再検証
 * する(有界。延長検査 + prev_hash 連鎖により、前進ビューは openProject 時の
 * 床検査と整合したまま — 床 seq 以下の全エントリが一致する)。再検証も future
 * なら divergedMessage で拒否する。
 */
function pullWithBoundedResync<TWire, TVerified>(input: {
  readonly verified: VerifiedProject;
  /** future head 時の有界再同期(1 回)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly fetch: Effect.Effect<TWire, CliError>;
  readonly verify: (
    view: VerifiedProject,
    wire: TWire,
  ) => Effect.Effect<
    { readonly kind: "ok"; readonly value: TVerified } | { readonly kind: "future" },
    CliError
  >;
  /** 床検査・コミット。view = 検証に使ったビュー(再同期で前進していることがある)。 */
  readonly accept: (view: VerifiedProject, value: TVerified) => Effect.Effect<void, CliError>;
  readonly divergedMessage: string;
}): Effect.Effect<
  { readonly view: VerifiedProject; readonly wire: TWire; readonly value: TVerified },
  CliError
> {
  return Effect.gen(function* () {
    const wire = yield* input.fetch;
    const first = yield* input.verify(input.verified, wire);
    if (first.kind === "ok") {
      yield* input.accept(input.verified, first.value);
      return { view: input.verified, wire, value: first.value };
    }
    const advanced = yield* resyncExtended(input.resync, input.verified);
    const second = yield* input.verify(advanced, wire);
    if (second.kind === "ok") {
      yield* input.accept(advanced, second.value);
      return { view: advanced, wire, value: second.value };
    }
    return yield* Effect.fail(cliError(input.divergedMessage));
  });
}

/**
 * Pulls one environment and verifies every value's write signature and every
 * metadata statement (environment, active variables, tombstones) before
 * anything is decrypted or resolved by name (§6.3 / §12-7). A declared head
 * beyond the local view triggers one bounded re-sync with the extension
 * check; everything is then re-verified against the advanced view.
 */
export function pullVerifiedEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** future head 時の有界再同期(1 回)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** ローカル床(§6.3)。検査(規則 (a)(b)(c))と検証成功後の原子コミットを担う。 */
  readonly floor: FloorHandle;
  /**
   * マニフェスト**欠落**の許容(移行経路 `maruhi env rotate --init-manifest` のみ
   * — session-27 §14 PR-M1)。配布された場合の検証は緩和しない。既定 false =
   * 欠落は一律拒否(§6.3)。
   */
  readonly allowMissingManifest?: boolean;
}): Effect.Effect<VerifiedEnvironmentPull, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pull({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAll(
          view,
          input.environmentId,
          wire,
          input.allowMissingManifest === true,
          // 隣接版の prev 検証(M1-A1): 床のマニフェスト記録を predecessor として渡す
          input.floor.current()?.manifest ?? null,
        ).pipe(
          Effect.map((result) =>
            result.kind === "future"
              ? result
              : ({
                  kind: "ok",
                  value: { snapshot: result.snapshot, warnings: result.warnings },
                } as const),
          ),
        ),
      accept: (view, value) =>
        enforceFloor({
          floor: input.floor,
          // 検証は(前進していることのある)view、規則 (c) 基準は応答取得前の
          // ビューから導出する(enforceFloor の baselineView 契約 — 再同期での
          // 基準過前進を防ぐ)
          baselineView: input.verified,
          commitView: view,
          environmentId: input.environmentId,
          snapshot: value.snapshot,
        }),
      divergedMessage:
        "A value or statement bound to a head that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.snapshot.variables,
      tombstones: value.snapshot.tombstones,
      environment: value.snapshot.environment,
      manifest: value.snapshot.manifest,
      deks: wire.deks,
      warnings: value.warnings,
    }),
  );
}

/**
 * Verifies the distribution material of a workload-lease response
 * (CRYPTO_SPEC §9.1 duty (4): environment statement, every active variable's
 * statement + write signature, every tombstone). Same discipline as the bulk
 * pull with exactly one difference: **a declared head beyond the chain is an
 * immediate rejection**, never a bounded re-sync — the chain travels in the
 * same response (AUTH_SPEC §14-2), so "our chain is merely stale" is not an
 * honest explanation; the response contradicts itself.
 *
 * 床は使わない: ワークロードは床を持たない初回同期クラス(§14.3-3)で、
 * その主要な緩和はリポジトリアンカー(anchor.ts — §6.3 帯域外アンカー (b))。
 */
export function verifyLeaseDistribution(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly wire: PullWire;
}): Effect.Effect<
  { readonly variables: readonly VerifiedPulledValue[]; readonly warnings: readonly string[] },
  CliError
> {
  return Effect.gen(function* () {
    // マニフェスト検証は義務(CRYPTO_SPEC §9.1 (5) — 2026-08-18)で、欠落 =
    // 一律拒否(移行許容はない: ワークロードは初期化を行えない — 初期化は
    // メンバーの明示操作 §14 PR-M1)。床由来の prev 検査は適用しない —
    // ワークロードは床を持たない初回同期クラス(§14.3-3。session-31 §3 M1-A1
    // の lease 適用外の注記): 署名・digest・エポック整合・欠落拒否は pull と
    // 同水準のまま、predecessor は null(共有検証器の同一性)
    const result = yield* verifyAll(input.verified, input.environmentId, input.wire, false, null);
    if (result.kind === "future") {
      return yield* Effect.fail(
        cliError(
          "A value or statement in the lease response declares a chain head beyond the chain included in the same response (the response contradicts itself)",
        ),
      );
    }
    return { variables: result.snapshot.variables, warnings: result.warnings };
  });
}

/** メタデータのみ pull の検証済み応答(§12-7 のメタデータのみモード)。 */
export interface VerifiedEnvironmentMetadata {
  /** 検証に使ったビュー(future head の有界再同期で前進していることがある)。 */
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedActiveStatement[];
  /** 検証済み tombstone(削除済み変数の名前解決の唯一の源 — AUDIT_SPEC §7)。 */
  readonly tombstones: readonly VerifiedTombstone[];
  /** 検証済みの環境メタステートメント(マニフェスト発行の envMeta 材料)。 */
  readonly environment: VerifiedMetaEvidence;
  /** 検証済みマニフェスト(欠落は拒否済み — メタのみ pull に移行許容はない)。 */
  readonly manifest: VerifiedManifest;
  readonly warnings: readonly string[];
}

interface MetadataPullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly DistributedVariableMetaStatement[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly manifest?: DistributedEnvironmentManifest;
}

/** メタデータのみ pull の検証済み中間値(pullWithBoundedResync の TVerified)。 */
interface VerifiedMetadataValue {
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedActiveStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
  readonly warnings: readonly string[];
}

function verifyAllMetadata(
  verified: VerifiedProject,
  environmentId: string,
  pull: MetadataPullWire,
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedMetaEvidence;
      readonly variables: readonly VerifiedActiveStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest | null;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(
    verified,
    environmentId,
    pull,
    () => verifyActiveStatements(verified, environmentId, pull.variables),
    (statement) => ({
      variableId: statement.variableId,
      status: "active" as const,
      metaVersion: statement.metaVersion,
      metaSigHashHex: statement.metaSigHashHex,
    }),
    false,
    floorManifest,
  );
}

/**
 * メタデータのみ pull の床検査(値を運ばない形 — メタ水準の規則 (a)(b) と
 * 欠落・削除取り消しのみ。checkEnvironmentMetadataPull 参照)と**環境水準の
 * 床コミット**(session-31 §3 M1-A3): チェーンヘッド・環境メタ床・マニフェスト
 * 床・環境水準エポック観測(§6.3 座標 (ii))を join する。**値床は捏造しない・
 * pull 基準(規則 (c))は前進させない** — 値を読んでいない観測から値水準の
 * 基準を作ると、ローテーション後・再暗号化完了前の正当な旧エポック値を
 * 誤拒否する(§6.3 の規範)。
 */
function enforceMetadataFloor(input: {
  readonly floor: FloorHandle;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedActiveStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const violation = checkEnvironmentMetadataPull(input.floor.current(), {
      environment: input.environment,
      variables: input.variables,
      tombstones: input.tombstones,
      manifest: input.manifest,
    });
    if (violation !== null) {
      return yield* Effect.fail(
        cliError(
          formatFloorViolation(
            { projectId: input.verified.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    // 環境がチェーンに存在しないのに検証を通る配布はここで止まる(enforceFloor
    // と同じファントム環境検査 — メタはエポックアンカーを持たない)
    const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
    // 検証済み事実の join(§6.3 — 記録契機の列挙ではなく単一の記録規則)。
    // journal-before-release: 追記の永続化が検査合格の使用・成功報告に先行する
    yield* input.floor.commitMetadata(
      {
        observedEpoch: environment.currentEpoch,
        metaVersion: input.environment.metaVersion,
        metaSigHashHex: input.environment.metaSigHashHex,
        manifest: {
          manifestVersion: input.manifest.manifestVersion,
          epoch: input.manifest.epoch,
          manifestSigHashHex: input.manifest.signedBytesHashHex,
        },
      },
      { seq: input.verified.state.headSeq, hashHex: input.verified.state.headHashHex },
    );
    // 検証済み配布物が到達したので、この環境の未解決 meta intent(3-F)を照合する
    yield* resolveMetaIntents(input.floor, input.manifest);
  });
}

/**
 * Pulls only the metadata of one environment (§12-7 metadata-only mode: no
 * values, no DEKs — the server records no `var.read`) and verifies the
 * environment statement, every active variable statement and every tombstone
 * against the verified chain history before any name is trusted (§6.3).
 * Future heads get the same single bounded re-sync as the full pull. Used
 * for name → variableId resolution (push) — a write-path read that must not
 * be recorded as having read values it never received.
 */
export function pullVerifiedEnvironmentMetadata(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** future head 時の有界再同期(1 回)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** ローカル床(§6.3)。メタ水準の検査 + 環境水準コミット(enforceMetadataFloor — M1-A3)。 */
  readonly floor: FloorHandle;
}): Effect.Effect<VerifiedEnvironmentMetadata, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pullMetadata({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAllMetadata(
          view,
          input.environmentId,
          wire,
          // 隣接版の prev 検証(M1-A1): metadata-only / value pull の両経路で同一
          input.floor.current()?.manifest ?? null,
        ).pipe(
          Effect.flatMap(
            (
              result,
            ): Effect.Effect<
              | { readonly kind: "ok"; readonly value: VerifiedMetadataValue }
              | { readonly kind: "future" },
              CliError
            > => {
              if (result.kind === "future") {
                return Effect.succeed({ kind: "future" as const });
              }
              // allowMissing なしの verifyAllCommon は欠落を拒否済み — null は
              // 型面の残余(構造的に到達しない)なので明示的に落とす
              if (result.manifest === null) {
                return Effect.fail(cliError(missingManifestMessage(input.environmentId)));
              }
              return Effect.succeed({
                kind: "ok" as const,
                value: {
                  environment: result.environment,
                  variables: result.variables,
                  tombstones: result.tombstones,
                  manifest: result.manifest,
                  warnings: result.warnings,
                },
              });
            },
          ),
        ),
      accept: (view, value) =>
        enforceMetadataFloor({
          floor: input.floor,
          verified: view,
          environmentId: input.environmentId,
          environment: value.environment,
          variables: value.variables,
          tombstones: value.tombstones,
          manifest: value.manifest,
        }),
      divergedMessage:
        "A statement bound to a head that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, value }) => ({
      verified: view,
      variables: value.variables,
      tombstones: value.tombstones,
      environment: value.environment,
      manifest: value.manifest,
      warnings: value.warnings,
    }),
  );
}

/**
 * 環境一覧の署名済みステートメントから「検証済みの削除済み環境」の集合を返す
 * (§12-4 — 削除も署名付きステートメント)。検証に失敗した・座標が合わない・
 * status が deleted でないステートメントは含めない(fail-closed — 呼び出し側は
 * 削除を信用せず対象に残す。サーバーの申告だけで黙ってスキップしない §7)。
 */
export function verifiedDeletedEnvironments(
  verified: VerifiedProject,
  environments: readonly {
    readonly environmentId: string;
    readonly statement: DistributedEnvironmentMetaStatement;
  }[],
): Effect.Effect<ReadonlySet<string>, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const deleted = new Set<string>();
      for (const environment of environments) {
        const statement = environment.statement;
        if (
          statement.environmentId !== environment.environmentId ||
          statement.status !== "deleted"
        ) {
          continue;
        }
        const outcome = await verifyStatement(
          verified,
          environment.environmentId,
          { kind: "environment" },
          statement,
          `environment ${displayText(environment.environmentId)}'s deletion statement`,
        );
        if (outcome.kind === "ok") {
          deleted.add(environment.environmentId);
        }
      }
      return deleted;
    },
    catch: () => cliError("Environment-statement verification failed"),
  });
}
