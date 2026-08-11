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
  /** 自分宛ラップ(検証は deks.ts の §5.1 / §5.2 経路が担う)。 */
  readonly deks: readonly RecipientDek[];
  /** 非 NFC 名の配布などの SHOULD 警告(呼び出し側が表示する)。 */
  readonly warnings: readonly string[];
}

interface PulledWire {
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
    message: `${label} の検証に失敗しました(reason=${reason})。サーバーによる差し替え・偽造の可能性があります`,
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
      message: `変数 ${displayText(variable.variableId)} の申告 AAD 座標が要求文脈と一致しません(サーバー応答の不整合)`,
    };
  }
  if (statement.environmentId !== environmentId || statement.variableId !== variable.variableId) {
    return {
      kind: "rejected",
      message: `変数 ${displayText(variable.variableId)} のステートメント座標が要求文脈と一致しません(名前の付け替え・移植の可能性)`,
    };
  }
  // 名前 → variableId の対応は検証済みステートメント経由が必須(§4.2 / §12-7)
  const verifiedStatement = await verifyStatement(
    verified,
    environmentId,
    { kind: "variable", variableId: variable.variableId },
    statement,
    `変数 ${displayText(variable.variableId)} のメタステートメント`,
  );
  if (verifiedStatement.kind !== "ok") {
    return verifiedStatement;
  }
  if (statement.status !== "active") {
    return {
      kind: "rejected",
      message: `変数 ${displayText(variable.variableId)} に deleted ステートメントが値付きで配布されました(削除の無断取り消しの可能性)`,
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
      `変数 ${displayText(statement.name)} の値署名`,
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
      message: `環境ステートメントの座標が要求環境 ${environmentId} と一致しません(移植の可能性)`,
    };
  }
  const result = await verifyStatement(
    verified,
    environmentId,
    { kind: "environment" },
    statement,
    `環境 ${environmentId} のメタステートメント`,
  );
  if (result.kind !== "ok") {
    return result;
  }
  if (statement.status !== "active") {
    return {
      kind: "rejected",
      message: `環境 ${environmentId} に deleted ステートメントが配布されました(削除済み環境の配布 — サーバー応答の不整合)`,
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
        message: `削除済み変数 ${displayText(statement.variableId)} のステートメント座標が要求環境と一致しません`,
      };
    }
    if (seen.has(statement.variableId) || activeIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        message: `変数 ${displayText(statement.variableId)} が active と deleted の両方で配布されました(削除の無断取り消し = equivocation の運搬形)`,
      };
    }
    seen.add(statement.variableId);
    if (statement.status !== "deleted") {
      return {
        kind: "rejected",
        message: `削除済み一覧に active ステートメントが配布されました: ${displayText(statement.variableId)}`,
      };
    }
    const result = await verifyStatement(
      verified,
      environmentId,
      { kind: "variable", variableId: statement.variableId },
      statement,
      `削除済み変数 ${displayText(statement.variableId)} のメタステートメント`,
    );
    if (result.kind !== "ok") {
      return result;
    }
    tombstones.push({
      variableId: statement.variableId,
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
      return `同名の active ステートメントが複数検証に通りました(サーバー equivocation): ${displayText(value.name)}。名前解決を拒否します`;
    }
    seenNames.add(value.name);
    if (value.name.normalize("NFC") !== value.name) {
      warnings.push(
        `変数 ${displayText(value.variableId)} の名前が NFC 正規形ではありません(正規サーバーは受理しない形 — 視覚的に同名の変数が並存しうるため注意してください)`,
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
        message: `変数 ${displayText(statement.variableId)} のステートメント座標が要求文脈と一致しません(名前の付け替え・移植の可能性)`,
      };
    }
    if (seenIds.has(statement.variableId)) {
      return {
        kind: "rejected",
        message: `変数 ID が同一応答内で重複しています(サーバー応答の不整合): ${statement.variableId}`,
      };
    }
    seenIds.add(statement.variableId);
    const outcome = await verifyStatement(
      verified,
      environmentId,
      { kind: "variable", variableId: statement.variableId },
      statement,
      `変数 ${displayText(statement.variableId)} のメタステートメント`,
    );
    if (outcome.kind !== "ok") {
      return outcome;
    }
    if (statement.status !== "active") {
      return {
        kind: "rejected",
        message: `変数 ${displayText(statement.variableId)} に deleted ステートメントがアクティブ一覧で配布されました(削除の無断取り消しの可能性)`,
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
        message: `変数 ID が同一応答内で重複しています(サーバー応答の不整合): ${variable.variableId}`,
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

/**
 * pull 応答の共通検証骨格(§6.3): 環境ステートメント → アクティブ集合(値付き /
 * メタのみで差し替わる)→ tombstone → 名前検査。future はどの段でも全体を
 * future にする(有界再同期の入口)。
 */
function verifyAllCommon<T extends { readonly variableId: string; readonly name: string }>(
  verified: VerifiedProject,
  environmentId: string,
  pull: {
    readonly statement: DistributedEnvironmentMetaStatement;
    readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  },
  verifyActives: () => Promise<
    VerifyOutcome<{ readonly values: readonly T[]; readonly ids: Set<string> }>
  >,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedMetaEvidence;
      readonly variables: readonly T[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return Effect.gen(function* () {
    const environment = yield* Effect.tryPromise({
      try: () => verifyEnvironmentStatement(verified, environmentId, pull.statement),
      catch: () => cliError("環境ステートメントの検証が失敗しました(暗号処理エラー)"),
    });
    if (environment.kind === "future") {
      return { kind: "future" } as const;
    }
    if (environment.kind === "rejected") {
      return yield* Effect.fail(cliError(environment.message));
    }
    const actives = yield* Effect.tryPromise({
      try: verifyActives,
      catch: () => cliError("変数ステートメント・値署名の検証が失敗しました(暗号処理エラー)"),
    });
    if (actives.kind === "future") {
      return { kind: "future" } as const;
    }
    if (actives.kind === "rejected") {
      return yield* Effect.fail(cliError(actives.message));
    }
    const deleted = yield* Effect.tryPromise({
      try: () =>
        verifyDeletedStatements(verified, environmentId, pull.deletedVariables, actives.value.ids),
      catch: () => cliError("削除済み変数ステートメントの検証が失敗しました(暗号処理エラー)"),
    });
    if (deleted.kind === "future") {
      return { kind: "future" } as const;
    }
    if (deleted.kind === "rejected") {
      return yield* Effect.fail(cliError(deleted.message));
    }
    const warnings: string[] = [];
    const nameFailure = checkVerifiedNames(actives.value.values, warnings);
    if (nameFailure !== null) {
      return yield* Effect.fail(cliError(nameFailure));
    }
    return {
      kind: "ok",
      environment: environment.value,
      variables: actives.value.values,
      tombstones: deleted.value,
      warnings,
    } as const;
  });
}

function verifyAll(
  verified: VerifiedProject,
  environmentId: string,
  pull: PullWire,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly snapshot: VerifiedPullSnapshot;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(verified, environmentId, pull, () =>
    verifyActiveVariables(verified, environmentId, pull.variables),
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
            },
            warnings: result.warnings,
          } as const),
    ),
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
        verifyAll(view, input.environmentId, wire).pipe(
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
        "再同期後もチェーンに存在しないヘッドへ束縛された値またはステートメントが配布されています(チェーン分岐または偽造の証拠)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.snapshot.variables,
      deks: wire.deks,
      warnings: value.warnings,
    }),
  );
}

/** メタデータのみ pull の検証済み応答(§12-7 のメタデータのみモード)。 */
export interface VerifiedEnvironmentMetadata {
  /** 検証に使ったビュー(future head の有界再同期で前進していることがある)。 */
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedActiveStatement[];
  readonly warnings: readonly string[];
}

interface MetadataPullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly DistributedVariableMetaStatement[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
}

function verifyAllMetadata(
  verified: VerifiedProject,
  environmentId: string,
  pull: MetadataPullWire,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedMetaEvidence;
      readonly variables: readonly VerifiedActiveStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(verified, environmentId, pull, () =>
    verifyActiveStatements(verified, environmentId, pull.variables),
  );
}

/**
 * メタデータのみ pull の床検査(値を運ばない形 — メタ水準の規則 (a)(b) と
 * 欠落・削除取り消しのみ。checkEnvironmentMetadataPull 参照)。床のコミットは
 * 行わない: 変数床のレコードは値のダイジェストを要し、メタだけから作らない
 * (基準の確立が値を運ぶ pull まで一周遅れるだけで誤検出はない — 床は SHOULD)。
 */
function enforceMetadataFloor(input: {
  readonly floor: FloorHandle;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly environment: VerifiedMetaEvidence;
  readonly variables: readonly VerifiedActiveStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const violation = checkEnvironmentMetadataPull(input.floor.current(), {
      environment: input.environment,
      variables: input.variables,
      tombstones: input.tombstones,
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
    yield* requireChainEnvironment(input.verified, input.environmentId);
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
  /** ローカル床(§6.3)。メタ水準の検査のみ — コミットしない(enforceMetadataFloor)。 */
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
        verifyAllMetadata(view, input.environmentId, wire).pipe(
          Effect.map((result) =>
            result.kind === "future" ? result : ({ kind: "ok", value: result } as const),
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
        }),
      divergedMessage:
        "再同期後もチェーンに存在しないヘッドへ束縛されたステートメントが配布されています(チェーン分岐または偽造の証拠)",
    }),
    ({ view, value }) => ({
      verified: view,
      variables: value.variables,
      warnings: value.warnings,
    }),
  );
}
