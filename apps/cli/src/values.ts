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
  checkEnvironmentPull,
  type FloorHandle,
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
      metaVersion: statement.metaVersion,
      metaSigHashHex: result.value.signedBytesHashHex,
      chainHeadSeq: statement.chainHeadSeq,
      chainHeadHashHex: statement.chainHeadHashHex,
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
      metaVersion: statement.metaVersion,
      metaSigHashHex: result.value.signedBytesHashHex,
      chainHeadSeq: statement.chainHeadSeq,
      chainHeadHashHex: statement.chainHeadHashHex,
    });
  }
  return { kind: "ok", value: tombstones };
}

/** 検証済み active 集合の名前検査: 同名 active の重複 = 解決拒否(§4.2)、非 NFC = 警告(SHOULD)。 */
function checkVerifiedNames(
  values: readonly VerifiedPulledValue[],
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
  return Effect.gen(function* () {
    const environment = yield* Effect.promise(() =>
      verifyEnvironmentStatement(verified, environmentId, pull.statement),
    );
    if (environment.kind === "future") {
      return { kind: "future" } as const;
    }
    if (environment.kind === "rejected") {
      return yield* Effect.fail(cliError(environment.message));
    }
    const actives = yield* Effect.promise(() =>
      verifyActiveVariables(verified, environmentId, pull.variables),
    );
    if (actives.kind === "future") {
      return { kind: "future" } as const;
    }
    if (actives.kind === "rejected") {
      return yield* Effect.fail(cliError(actives.message));
    }
    const deleted = yield* Effect.promise(() =>
      verifyDeletedStatements(verified, environmentId, pull.deletedVariables, actives.value.ids),
    );
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
      snapshot: {
        environment: environment.value,
        variables: actives.value.values,
        tombstones: deleted.value,
      },
      warnings,
    } as const;
  });
}

/**
 * 床検査(§6.3 の (a)(b)(c))と床コミット(更新順序の規範: 検査は前回成功
 * pull の基準、基準の前進は検証成功後に変数床と原子的に)。検査はすべて
 * 署名検証を通過したデータ同士の比較なので、不一致は否認不能な証拠であり
 * 全件拒否する(§6.3 の「拒否・警告」の強い側)。
 */
function enforceFloor(input: {
  readonly floor: FloorHandle;
  readonly verified: VerifiedProject;
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
            { projectId: input.verified.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    // 規則 (c) 基準の前進値 = 今回のチェーン導出現エポック(§6.2 — サーバー
    // 申告の currentEpoch は使わない)。環境がチェーンに存在しないのに検証を
    // 通る配布はここで止まる(メタはエポックアンカーを持たないため、変数ゼロの
    // 環境ではステートメント検証だけでは検出できない)
    const chainEpoch = (yield* requireChainEnvironment(input.verified, input.environmentId))
      .currentEpoch;
    yield* input.floor.commitPull(buildEnvironmentFloor(chainEpoch, input.snapshot), {
      seq: input.verified.state.headSeq,
      hashHex: input.verified.state.headHashHex,
    });
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
  return Effect.gen(function* () {
    const response = yield* input.client.variables
      .pull({ params: { projectId: input.verified.projectId, environmentId: input.environmentId } })
      .pipe(Effect.mapError(toCliError));
    const first = yield* verifyAll(input.verified, input.environmentId, response);
    if (first.kind === "ok") {
      yield* enforceFloor({
        floor: input.floor,
        verified: input.verified,
        environmentId: input.environmentId,
        snapshot: first.snapshot,
      });
      return {
        verified: input.verified,
        variables: first.snapshot.variables,
        deks: response.deks,
        warnings: first.warnings,
      };
    }
    // 宣言ヘッドが自ビューより先 = 自チェーンが古いだけの可能性(§6.3-2b)。
    // 1 回だけ再同期し、旧ビューの延長であることを検査してから全体を再検証する
    // (延長検査 + prev_hash 連鎖により、前進ビューは openProject 時の床検査と
    // 整合したまま — 床 seq 以下の全エントリが一致する)
    const advanced = yield* resyncExtended(input.resync, input.verified);
    const second = yield* verifyAll(advanced, input.environmentId, response);
    if (second.kind === "ok") {
      yield* enforceFloor({
        floor: input.floor,
        verified: advanced,
        environmentId: input.environmentId,
        snapshot: second.snapshot,
      });
      return {
        verified: advanced,
        variables: second.snapshot.variables,
        deks: response.deks,
        warnings: second.warnings,
      };
    }
    return yield* Effect.fail(
      cliError(
        "再同期後もチェーンに存在しないヘッドへ束縛された値またはステートメントが配布されています(チェーン分岐または偽造の証拠)",
      ),
    );
  });
}
