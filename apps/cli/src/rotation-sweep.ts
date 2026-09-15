// ローテーション義務(CRYPTO_SPEC §7)の走査の共有実装。
//
// revoke_server(server-revoke)と remove_member / member 未満への降格 / scope の
// 縮小(member remove / change-role)は、いずれも「義務の環境集合のうち、チェーン上の
// 基準 seq より後に現エポックが始まっていない環境は強制ローテーション、それ以外は
// 検証パス(未完了の再暗号化の再開 or 完了確認)」という同じ中断復旧構造を持つ。
// 進捗ファイルは持たず、チェーン導出状態だけから対象を決める(別デバイス・
// 別メンバーからの再開もそのまま成立する — server-revoke の規律の共有化)。
//
// **義務の環境集合(2026-09-15 ES K4 — 設計録 K4-J)**: remove = 対象の現 scope(削除
// 直前)、降格 = 対象の新 scope、縮小 = 旧 scope \ 新 scope、revoke_server = 全環境
// (不変 — 設計録 §6)。`all` は義務 seq 時点で存在した環境集合に具体化する(後に
// 作成された環境の DEK を対象は持ちえない)。1 対象に複数の義務(縮小の後の remove)が
// あれば、環境ごとに最大の基準 seq を採る。
//
// 削除済み環境の除外は**検証済みの削除ステートメント**のみを根拠とする
// (サーバーの 404 申告だけで黙ってスキップしない — §7)。

import {
  ALL_SCOPE,
  type ChainEntry,
  type ChainMember,
  type MemberScope,
  memberScopeOf,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { displayText } from "./display.ts";
import type { RotationSummary } from "./env-rotate.ts";
import type { CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { compareCodePoints, environmentsOfScopeAt, scopeChangeAt } from "./scope.ts";
import type { VerifiedProject } from "./sync.ts";
import { verifiedDeletedEnvironments } from "./values.ts";

/** ローテーション注入のモード: force = 新エポック必須 / verify = 再開・確認のみ。 */
export type SweepRotateMode = "force" | "verify";

/** 1 環境のローテーションの注入(cli.ts が envRotateOp を床付きで包んで渡す)。 */
export type SweepRotate<R> = (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, R>;

/** 全環境走査の結果(revoke / remove / 降格 / 縮小で共通の報告材料)。 */
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

/** 環境 → 義務の基準 seq(複数の義務があれば最大)。 */
export type EnvironmentBaselines = ReadonlyMap<string, number>;

/**
 * 義務エントリ列から「環境 → 基準 seq」を畳む(sweep と未収束判定の共通入力)。
 * 同じ環境に複数の義務があれば最大の seq(最後の義務の後にローテーションされて
 * いれば、それ以前の義務も同時に閉じる — エポックは環境単位)。
 */
export function baselinesOf(mandates: readonly RotationMandate[]): EnvironmentBaselines {
  const baselines = new Map<string, number>();
  for (const mandate of mandates) {
    for (const environmentId of mandate.environmentIds) {
      const current = baselines.get(environmentId);
      if (current === undefined || current < mandate.seq) {
        baselines.set(environmentId, mandate.seq);
      }
    }
  }
  return baselines;
}

/**
 * 環境 E が基準 seq について未収束か: E の現エポックの開始 seq が基準より前 = E の
 * 現 DEK は基準イベント(失効・削除・降格・縮小)の前に配られたまま。開始 seq が
 * 導出できない環境は fail-closed で未収束に含める(環境が黙って対象から外れる形に
 * しない)。
 */
function isPendingAt(
  verified: VerifiedProject,
  environmentId: string,
  baselineSeq: number,
): boolean {
  const environment = verified.state.environments.get(environmentId);
  if (environment === undefined) {
    return true;
  }
  const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
  return startSeq === undefined || startSeq < baselineSeq;
}

// ---------------------------------------------------------------------------
// ローテーション義務の一般化導出(§7 の 4 種)と未収束の常時警告(B2 裁定 —
// 「誰も見ない verify 限定の警告は検出にならない」。§9 の開示常時明示と同じ規律)
// ---------------------------------------------------------------------------

/** §7 のローテーション義務エントリ(全 4 種 — 2026-09-15 ES K4 で `scope-narrowed` を追加)。 */
export interface RotationMandate {
  readonly kind: "member-removed" | "role-demoted" | "scope-narrowed" | "server-revoked";
  /** member 系 = 対象 user_id / server-revoked = サーバー鍵 FP。 */
  readonly target: string;
  readonly seq: number;
  /**
   * 義務の環境集合(CRYPTO_SPEC §7 — seq 時点のチェーン導出環境集合に具体化。昇順)。
   * remove = 対象の現 scope、降格 = 対象の新 scope、縮小 = 旧 \ 新、revoke = 全環境。
   */
  readonly environmentIds: readonly string[];
}

/**
 * チェーン上の全ローテーション義務エントリ(§7): `remove_member`(常に)、
 * member 未満への降格 `change_role`(直前 role が member 以上 — 検証済み履歴の
 * memberStateAt で判定)、scope の縮小 `change_role`(旧 \ 新 ≠ ∅)、`revoke_server`
 * (常に)。member.ts の対象スコープ判定と未収束警告(下記)が同じ 1 導出を共有する
 * (判定のズレを構造的に防ぐ)。降格と縮小が同時なら 2 つの義務(同 seq)になる。
 */
export function rotationMandates(verified: VerifiedProject): readonly RotationMandate[] {
  return verified.entries.flatMap((entry) => mandatesOfEntry(verified, entry));
}

/** 1 エントリが生む義務(0〜2 個 — 降格と縮小が同時なら 2 個)。 */
function mandatesOfEntry(verified: VerifiedProject, entry: ChainEntry): readonly RotationMandate[] {
  if (entry.op === "remove_member") {
    const before = verified.history.memberStateAt(entry.payload.targetUserId, entry.seq - 1);
    // 直前の状態が導出できなければ fail-closed で全環境(黙って縮めない)
    const scope: MemberScope = before?.scope ?? ALL_SCOPE;
    return [
      {
        kind: "member-removed",
        target: entry.payload.targetUserId,
        seq: entry.seq,
        environmentIds: environmentsOfScopeAt(verified, scope, entry.seq),
      },
    ];
  }
  if (entry.op === "revoke_server") {
    return [
      {
        kind: "server-revoked",
        target: entry.payload.serverKeyFingerprintHex,
        seq: entry.seq,
        environmentIds: environmentsOfScopeAt(verified, ALL_SCOPE, entry.seq),
      },
    ];
  }
  return entry.op === "change_role" ? changeRoleMandates(verified, entry) : [];
}

/** change_role の義務: 降格(新 scope の全環境)と縮小(旧 \ 新)— 同時なら 2 個。 */
function changeRoleMandates(
  verified: VerifiedProject,
  entry: ChainEntry & { readonly op: "change_role" },
): readonly RotationMandate[] {
  const before = verified.history.memberStateAt(entry.payload.targetUserId, entry.seq - 1);
  if (before === undefined) {
    return [];
  }
  const after = memberScopeOf(entry.payload);
  const mandates: RotationMandate[] = [];
  if (
    ROLE_RANK[entry.payload.newRole] < ROLE_RANK.member &&
    ROLE_RANK[before.role] >= ROLE_RANK.member
  ) {
    mandates.push({
      kind: "role-demoted",
      target: entry.payload.targetUserId,
      seq: entry.seq,
      environmentIds: environmentsOfScopeAt(verified, after, entry.seq),
    });
  }
  const { narrowed } = scopeChangeAt(verified, before.scope, after, entry.seq);
  if (narrowed.length > 0) {
    mandates.push({
      kind: "scope-narrowed",
      target: entry.payload.targetUserId,
      seq: entry.seq,
      environmentIds: narrowed,
    });
  }
  return mandates;
}

/** 未収束の義務(義務エントリより後に現エポックが始まっていない環境が残る)。 */
export interface UnconvergedMandate extends RotationMandate {
  readonly pendingEnvironmentIds: readonly string[];
}

/**
 * 未収束のローテーション義務の導出(チェーン導出のみ)。環境 E が義務 M に
 * ついて未収束 = E ∈ M の環境集合(M 時点で存在した scope 内の環境)で、E の現
 * エポックの開始 seq が M より前(= M 後のローテーションがまだ)。開始 seq が
 * 導出できない環境は fail-closed で未収束に含める。削除済み(検証済み)環境は除外。
 * なお「エポックは進んだが再暗号化が未完」はチェーンから見えない残余で、
 * その検出は各義務コマンドの再実行(sweep の検証パス)が担う。
 */
function unconvergedMandates(
  verified: VerifiedProject,
  deletedVerified: ReadonlySet<string>,
): readonly UnconvergedMandate[] {
  const results: UnconvergedMandate[] = [];
  for (const mandate of rotationMandates(verified)) {
    const pending = mandate.environmentIds.filter(
      (environmentId) =>
        !deletedVerified.has(environmentId) && isPendingAt(verified, environmentId, mandate.seq),
    );
    if (pending.length > 0) {
      results.push({ ...mandate, pendingEnvironmentIds: pending });
    }
  }
  return results;
}

/**
 * 巻き戻された義務(対象が再追加・再昇格・再拡大・再 grant 済み)の案内。義務
 * コマンドの再実行を案内すると**現役の対象へ元の破壊的操作を再適用させてしまう**
 * ため、負っているのはローテーションだけであることを明示し、
 * 非破壊の env rotate へ誘導する。義務自体は残る(remove/降格の残余は
 * エポックアンカーの健全性 — §7 — であり、対象の復帰では消えない)。
 */
function reversedAdvice(state: string): string {
  return `${state} — do not re-run the operation against the target; rotating the affected environment individually with \`maruhi env rotate <environment> --new-epoch --reason <text>\` converges the mandate`;
}

/**
 * 義務種別ごとの収束コマンドの案内(行動可能な警告 — B2 裁定)。対象の現在
 * 状態を見て、巻き戻し済み(再追加・再昇格・再拡大・再 grant)なら破壊的操作の
 * 再実行を案内しない。
 */
function mandateAdvice(verified: VerifiedProject, mandate: UnconvergedMandate): string {
  switch (mandate.kind) {
    case "member-removed":
      return verified.state.members.has(mandate.target)
        ? reversedAdvice("the target has been re-added")
        : `re-running \`maruhi member remove ${displayText(mandate.target)}\` converges the mandate`;
    case "role-demoted":
      return demotionAdvice(verified.state.members.get(mandate.target), mandate);
    case "scope-narrowed":
      return narrowingAdvice(verified, verified.state.members.get(mandate.target), mandate);
    case "server-revoked":
      return verified.state.serverGrants.has(mandate.target)
        ? reversedAdvice("the target server key has been re-granted")
        : "re-running `maruhi server revoke` converges the mandate";
  }
}

function demotionAdvice(member: ChainMember | undefined, mandate: UnconvergedMandate): string {
  if (member === undefined) {
    // 降格後に削除された対象へ change-role は再実行できない(現メンバー限定)
    return reversedAdvice("the target has been removed");
  }
  if (ROLE_RANK[member.role] >= ROLE_RANK.member) {
    return reversedAdvice("the target has been re-promoted to member or above");
  }
  return `re-running \`maruhi member change-role ${displayText(mandate.target)} --role ${member.role}\` converges the mandate`;
}

function narrowingAdvice(
  verified: VerifiedProject,
  member: ChainMember | undefined,
  mandate: UnconvergedMandate,
): string {
  if (member === undefined) {
    return reversedAdvice("the target has been removed");
  }
  const current = new Set(environmentsOfScopeAt(verified, member.scope, verified.state.headSeq));
  if (mandate.pendingEnvironmentIds.some((environmentId) => current.has(environmentId))) {
    return reversedAdvice("the target's scope has been widened again");
  }
  return `re-running \`maruhi member change-role ${displayText(mandate.target)}\` with the target's current scope (\`--env …\`) converges the mandate`;
}

/**
 * 未収束義務の解決: チェーン導出のみの前段判定が空なら通信ゼロで空を返し、
 * 候補があるときだけ削除済み環境の検証済みフィルタ(環境一覧の GET 1 回)を
 * 行う。取得・検証の失敗は null(= 判定不能。注意は出力済み)— 呼び出し側の
 * コマンドを失敗させない(チェーン検証自体は成功している)。
 * 常時警告(warnUnconvergedMandates)と project verify の詳細表示が共有する。
 */
export function resolveUnconvergedMandates(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
}): Effect.Effect<readonly UnconvergedMandate[] | null, never, CliIo> {
  return Effect.gen(function* () {
    const candidates = unconvergedMandates(input.verified, new Set());
    if (candidates.length === 0) {
      return candidates;
    }
    return yield* verifiedDeletedEnvironmentSet(input.client, input.verified).pipe(
      Effect.map((deletedVerified) => unconvergedMandates(input.verified, deletedVerified)),
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* logNote(
            `there are candidate unconverged rotation mandates, but they cannot be confirmed because verification of a deleted environment failed (${error.message})`,
          );
          return null;
        }),
      ),
    );
  });
}

/** 1 義務ぶんの警告行(常時警告と project verify の詳細表示で共通)。 */
export function describeUnconvergedMandate(
  verified: VerifiedProject,
  mandate: UnconvergedMandate,
): string {
  return `${mandate.kind} (target=${displayText(mandate.target)}, seq=${mandate.seq}): environments ${mandate.pendingEnvironmentIds.map(displayText).join(", ")} — ${mandateAdvice(verified, mandate)}`;
}

/**
 * 未収束のローテーション義務の常時警告(B2 裁定)。全コマンドのチェーン同期後に
 * 呼ぶ(収束系コマンド — member remove / change-role / server revoke / env
 * rotate — は自分の sweep 報告が担うため呼ばない)。警告は SHOULD — 取得・
 * 検証の失敗でコマンド自体を止めない(その旨だけ告げて続行する)。
 */
export function warnUnconvergedMandates(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const filtered = yield* resolveUnconvergedMandates(input);
    if (filtered === null || filtered.length === 0) {
      return;
    }
    const io = yield* CliIo;
    yield* logWarning(
      "there are unconverged rotation mandates (CRYPTO_SPEC §7) — holders of the old DEKs may still be able to read current values:",
    );
    for (const mandate of filtered) {
      yield* io.logError(`  ${describeUnconvergedMandate(input.verified, mandate)}`);
    }
  });
}

/** 削除済み環境の検証済み集合(環境一覧の GET 1 回 + 削除ステートメント検証 — §7)。 */
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
 * §7 の義務環境の走査: 基準より前に現エポックが始まった環境は強制ローテーション、
 * それ以外は検証パス(未完了の再暗号化の再開 or 完了確認)。1 環境の失敗で残りを
 * 止めない(失敗は集めて報告し、再実行で続きから再開する)。対象は `baselines`
 * (義務の環境集合 → 基準 seq。baselinesOf)に限る — scope 外の環境を rotate の
 * 対象に含めない(CRYPTO_SPEC §7)。
 */
export function sweepRotations<R>(input: {
  readonly rotate: SweepRotate<R>;
  readonly verified: VerifiedProject;
  /** 義務の環境集合 → 基準 seq(revoke / remove / 降格 / 縮小)。 */
  readonly baselines: EnvironmentBaselines;
  readonly deletedVerified: ReadonlySet<string>;
}): Effect.Effect<SweepOutcome, never, R> {
  return Effect.gen(function* () {
    const candidates = [...input.baselines.keys()]
      .filter((environmentId) => !input.deletedVerified.has(environmentId))
      .toSorted(compareCodePoints);
    const isPending = (environmentId: string) =>
      isPendingAt(input.verified, environmentId, input.baselines.get(environmentId) ?? 0);
    const rotated: {
      readonly environmentId: string;
      readonly summary: RotationSummary;
      readonly forcedNewEpoch: boolean;
    }[] = [];
    const failed: { readonly environmentId: string; readonly message: string }[] = [];
    const alreadyRotated: string[] = [];
    for (const environmentId of candidates.filter(isPending)) {
      const result = yield* rotateOutcome(input.rotate, environmentId, "force");
      if (result.kind === "ok") {
        rotated.push({ environmentId, summary: result.summary, forcedNewEpoch: true });
      } else {
        failed.push({ environmentId, message: result.message });
      }
    }
    // エポックは基準より後に始まっているが、その回の**再暗号化が完了したか**は
    // チェーンからは分からない(§12-7 の過渡状態)。検証パスで確かめる
    for (const environmentId of candidates.filter((id) => !isPending(id))) {
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
    return { rotated, failed, alreadyRotated: alreadyRotated.toSorted(compareCodePoints) };
  });
}
