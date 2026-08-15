// 全環境ローテーション義務(CRYPTO_SPEC §7)の走査の共有実装。
//
// revoke_server(server-revoke)と remove_member / member 未満への降格
// (member remove / change-role)は、いずれも「チェーン上の基準 seq より後に
// 現エポックが始まっていない環境は強制ローテーション、それ以外は検証パス
// (未完了の再暗号化の再開 or 完了確認)」という同じ中断復旧構造を持つ。
// 進捗ファイルは持たず、チェーン導出状態だけから対象を決める(別デバイス・
// 別メンバーからの再開もそのまま成立する — server-revoke の規律の共有化)。
//
// 削除済み環境の除外は**検証済みの削除ステートメント**のみを根拠とする
// (サーバーの 404 申告だけで黙ってスキップしない — §7)。

import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { displayText } from "./display.ts";
import type { RotationSummary } from "./env-rotate.ts";
import type { CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { VerifiedProject } from "./sync.ts";
import { verifiedDeletedEnvironments } from "./values.ts";

/** ローテーション注入のモード: force = 新エポック必須 / verify = 再開・確認のみ。 */
export type SweepRotateMode = "force" | "verify";

/** 1 環境のローテーションの注入(cli.ts が envRotateOp を床付きで包んで渡す)。 */
export type SweepRotate<R> = (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, R>;

/** 全環境走査の結果(revoke / remove / 降格で共通の報告材料)。 */
export interface SweepOutcome {
  /** ローテーション(強制 or 再開)を実行した環境(環境 ID → 結果)。 */
  readonly rotated: readonly {
    readonly environmentId: string;
    readonly summary: RotationSummary;
    /** 新エポックを要求した実行か(true = 強制 / false = 検証パスの再開)。 */
    readonly forcedNewEpoch: boolean;
  }[];
  /** ローテーションに失敗した環境(§7 — 黙ってスキップしない)。 */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
  /** 基準より後のエポックで、未完了の再暗号化がないことを**確認済み**の環境。 */
  readonly alreadyRotated: readonly string[];
}

/**
 * 「基準 seq の後にまだローテーションされていない環境」の導出(中断復旧の基準)。
 * 基準 seq より現エポックの開始 seq が前 = その環境の現 DEK は基準イベント
 * (失効・削除・降格)の前に配られたまま。チェーンだけから決まるので進捗
 * ファイルは不要。開始 seq が導出できない環境は fail-closed で対象に含める
 * (環境が黙って対象から外れる形にしない)。
 */
function pendingEnvironmentsAfter(
  verified: VerifiedProject,
  baselineSeq: number,
): readonly string[] {
  const pending: string[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
    if (startSeq === undefined || startSeq < baselineSeq) {
      pending.push(environmentId);
    }
  }
  return pending.toSorted();
}

// ---------------------------------------------------------------------------
// ローテーション義務の一般化導出(§7 の 3 種)と未収束の常時警告(B2 裁定 —
// 「誰も見ない verify 限定の警告は検出にならない」。§9 の開示常時明示と同じ規律)
// ---------------------------------------------------------------------------

/** §7 のローテーション義務エントリ(全 3 種)。 */
export interface RotationMandate {
  readonly kind: "member-removed" | "role-demoted" | "server-revoked";
  /** member 系 = 対象 user_id / server-revoked = サーバー鍵 FP。 */
  readonly target: string;
  readonly seq: number;
}

/**
 * チェーン上の全ローテーション義務エントリ(§7): `remove_member`(常に)、
 * member 未満への降格 `change_role`(直前 role が member 以上 — 検証済み履歴の
 * memberStateAt で判定)、`revoke_server`(常に)。member.ts の対象スコープ判定と
 * 未収束警告(下記)が同じ 1 導出を共有する(判定のズレを構造的に防ぐ)。
 */
export function rotationMandates(verified: VerifiedProject): readonly RotationMandate[] {
  const mandates: RotationMandate[] = [];
  for (const entry of verified.entries) {
    if (entry.op === "remove_member") {
      mandates.push({ kind: "member-removed", target: entry.payload.targetUserId, seq: entry.seq });
      continue;
    }
    if (entry.op === "revoke_server") {
      mandates.push({
        kind: "server-revoked",
        target: entry.payload.serverKeyFingerprintHex,
        seq: entry.seq,
      });
      continue;
    }
    if (entry.op === "change_role" && ROLE_RANK[entry.payload.newRole] < ROLE_RANK.member) {
      const before = verified.history.memberStateAt(entry.payload.targetUserId, entry.seq - 1);
      if (before !== undefined && ROLE_RANK[before.role] >= ROLE_RANK.member) {
        mandates.push({
          kind: "role-demoted",
          target: entry.payload.targetUserId,
          seq: entry.seq,
        });
      }
    }
  }
  return mandates;
}

/** 未収束の義務(義務エントリより後に現エポックが始まっていない環境が残る)。 */
export interface UnconvergedMandate extends RotationMandate {
  readonly pendingEnvironmentIds: readonly string[];
}

/**
 * 未収束のローテーション義務の導出(チェーン導出のみ)。環境 E が義務 M に
 * ついて未収束 = E は M より前に作成され(後に作成された環境の DEK を対象は
 * 知り得ない)、E の現エポックの開始 seq が M より前(= M 後のローテーションが
 * まだ)。開始 seq が導出できない環境は fail-closed で未収束に含める
 * (pendingEnvironmentsAfter と同じ規律)。削除済み(検証済み)環境は除外。
 * なお「エポックは進んだが再暗号化が未完」はチェーンから見えない残余で、
 * その検出は各義務コマンドの再実行(sweep の検証パス)が担う。
 */
export function unconvergedMandates(
  verified: VerifiedProject,
  deletedVerified: ReadonlySet<string>,
): readonly UnconvergedMandate[] {
  const mandates = rotationMandates(verified);
  if (mandates.length === 0) {
    return [];
  }
  const results: UnconvergedMandate[] = [];
  for (const mandate of mandates) {
    const pending: string[] = [];
    for (const [environmentId, environment] of verified.state.environments) {
      if (deletedVerified.has(environmentId) || environment.createdAtSeq > mandate.seq) {
        continue;
      }
      const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
      if (startSeq === undefined || startSeq < mandate.seq) {
        pending.push(environmentId);
      }
    }
    if (pending.length > 0) {
      results.push({ ...mandate, pendingEnvironmentIds: pending.toSorted() });
    }
  }
  return results;
}

/**
 * 義務種別ごとの収束コマンドの案内(行動可能な警告 — B2 裁定)。義務の契機が
 * 現チェーン状態で取り消されている(対象の再追加・再昇格、有効な grant の存在)
 * 場合は元コマンドを名指ししない — 再実行は残りのローテーションの完了ではなく
 * チェーン状態の再変更(再削除・再降格・有効 grant の失効)を引き起こす。
 * その場合は環境ごとの強制ローテーション(reason は義務種別と同じ固定文字列)
 * だけを案内する。
 */
function mandateAdvice(verified: VerifiedProject, mandate: UnconvergedMandate): string {
  if (mandate.kind === "member-removed") {
    if (!verified.state.members.has(mandate.target)) {
      return `maruhi member remove ${displayText(mandate.target)} の再実行`;
    }
  } else if (mandate.kind === "role-demoted") {
    const member = verified.state.members.get(mandate.target);
    if (member !== undefined && ROLE_RANK[member.role] < ROLE_RANK.member) {
      return `maruhi member change-role ${displayText(mandate.target)} の再実行(降格時の role を指定)`;
    }
  } else if (verified.state.serverGrants.size === 0) {
    return "maruhi server revoke の再実行";
  }
  return `未収束の各環境での maruhi env rotate <環境 ID> --reason ${mandate.kind} の実行`;
}

/**
 * 未収束のローテーション義務の常時警告(B2 裁定)。全コマンドのチェーン同期後に
 * 呼ぶ(収束系コマンド — member remove / change-role / server revoke / env
 * rotate — は自分の sweep 報告が担うため呼ばない)。チェーン導出のみの前段
 * 判定が空なら通信ゼロで終わり、候補があるときだけ削除済み環境の検証済み
 * フィルタ(環境一覧の GET 1 回)を行う。警告は SHOULD — 取得・検証の失敗で
 * コマンド自体を止めない(その旨だけ告げて続行する)。
 */
export function warnUnconvergedMandates(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const candidates = unconvergedMandates(input.verified, new Set());
    if (candidates.length === 0) {
      return;
    }
    const io = yield* CliIo;
    const filtered = yield* verifiedDeletedEnvironmentSet(input.client, input.verified).pipe(
      Effect.map((deletedVerified) => unconvergedMandates(input.verified, deletedVerified)),
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* io.logError(
            `注意: 未収束のローテーション義務の候補がありますが、削除済み環境の検証に失敗したため確定できません(${error.message})`,
          );
          return [] as readonly UnconvergedMandate[];
        }),
      ),
    );
    if (filtered.length === 0) {
      return;
    }
    yield* io.logError(
      "警告: 未収束のローテーション義務があります(CRYPTO_SPEC §7)— 旧 DEK の保持者が現在値を読める可能性が残っています:",
    );
    for (const mandate of filtered) {
      yield* io.logError(
        `  ${mandate.kind}(target=${displayText(mandate.target)}, seq=${mandate.seq}): 環境 ${mandate.pendingEnvironmentIds.map(displayText).join(", ")} — ${mandateAdvice(input.verified, mandate)}で収束します`,
      );
    }
  });
}
export function verifiedDeletedEnvironmentSet(
  client: MaruhiClient,
  verified: VerifiedProject,
): Effect.Effect<ReadonlySet<string>, CliError> {
  return Effect.gen(function* () {
    const listed = yield* client.environments
      .list({ params: { projectId: verified.projectId } })
      .pipe(Effect.mapError(toCliError));
    return yield* verifiedDeletedEnvironments(verified, listed.environments);
  });
}

/** 1 環境のローテーションの結果化(失敗は投げずに集める — §7 の全環境走査用)。 */
function rotateOutcome<R>(
  rotate: SweepRotate<R>,
  environmentId: string,
  mode: SweepRotateMode,
): Effect.Effect<
  | { readonly kind: "ok"; readonly summary: RotationSummary }
  | { readonly kind: "failed"; readonly message: string },
  never,
  R
> {
  return rotate(environmentId, mode).pipe(
    Effect.map((summary) => ({ kind: "ok", summary }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", message: error.message } as const)),
  );
}

/**
 * §7 の全環境走査: pending は強制ローテーション、それ以外は検証パス
 * (未完了の再暗号化の再開 or 完了確認)。1 環境の失敗で残りを止めない
 * (失敗は集めて報告し、再実行で続きから再開する)。
 */
export function sweepRotations<R>(input: {
  readonly rotate: SweepRotate<R>;
  readonly verified: VerifiedProject;
  /** ローテーション義務を発生させたチェーンイベントの seq(revoke / remove / 降格)。 */
  readonly baselineSeq: number;
  readonly deletedVerified: ReadonlySet<string>;
}): Effect.Effect<SweepOutcome, never, R> {
  return Effect.gen(function* () {
    const pendingSet = new Set(pendingEnvironmentsAfter(input.verified, input.baselineSeq));
    const candidates = [...input.verified.state.environments.keys()]
      .filter((environmentId) => !input.deletedVerified.has(environmentId))
      .toSorted();
    const rotated: {
      readonly environmentId: string;
      readonly summary: RotationSummary;
      readonly forcedNewEpoch: boolean;
    }[] = [];
    const failed: { readonly environmentId: string; readonly message: string }[] = [];
    const alreadyRotated: string[] = [];
    for (const environmentId of candidates.filter((id) => pendingSet.has(id))) {
      const result = yield* rotateOutcome(input.rotate, environmentId, "force");
      if (result.kind === "ok") {
        rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: true });
      } else {
        failed.push({ environmentId, message: result.message });
      }
    }
    // エポックは基準より後に始まっているが、その回の**再暗号化が完了したか**は
    // チェーンからは分からない(§12-7 の過渡状態)。検証パスで確かめる
    for (const environmentId of candidates.filter((id) => !pendingSet.has(id))) {
      const result = yield* rotateOutcome(input.rotate, environmentId, "verify");
      if (result.kind !== "ok") {
        failed.push({ environmentId, message: result.message });
      } else if (
        result.summary.mode === "up-to-date" &&
        result.summary.remaining === 0 &&
        result.summary.failure === null
      ) {
        alreadyRotated.push(environmentId);
      } else {
        // 再開した(または部分完了が残った)— 表示・終了コードは呼び出し側の
        // reportRotation が RotationSummary から導く
        rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: false });
      }
    }
    return { rotated, failed, alreadyRotated: alreadyRotated.toSorted() };
  });
}
