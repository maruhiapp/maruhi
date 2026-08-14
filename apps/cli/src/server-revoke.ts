// `maruhi server revoke`(CRYPTO_SPEC §7 / §9 — Wave 2 A1)。
//
// revoke_server をチェーンへ追記し、**プロジェクトの全環境**を強制ローテーション
// する(§7 — 失効の実効性はローテーションが担う。ローテーションなしの revoke は
// 「開示を止めたつもり」の見せかけになる)。ローテーションは PR-1 の
// envRotateOp を環境ごとに再利用する(reason は固定文字列)。
//
// 中断復旧(進捗ファイルなし — 分散状態から導出): revoke がチェーンに載った後で
// 落ちても、再実行が「最後の revoke_server の seq」を基準に収束する:
// - 現エポックの開始 seq が revoke より前の環境 = まだ回っていない →
//   強制ローテーション(forceNewEpoch)
// - 開始 seq が revoke より後の環境 = エポックは進んだが、**再暗号化が途中で
//   落ちた可能性が残る**(§12-7 の過渡状態)→ 検証パス(envRotateOp の
//   forceNewEpoch なし実行 = 未完了があれば再開・なければ確認のみ)で
//   「エポックが進んだだけの見せかけの完了」を塞ぐ
// 削除済み環境は、**検証済みの削除ステートメント**がある場合のみスキップする
// (サーバーの 404 申告だけで黙ってスキップしない — §7。検証できなければ
// 対象に残り、rotate の失敗として表面化する)。

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { ChainEntry, SigningKeyPair } from "@maruhi/crypto";
import { signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { RotationSummary } from "./env-rotate.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import { verifiedDeletedEnvironments } from "./values.ts";

const MAX_ATTEMPTS = 5;

/** revoke 後の全環境ローテーションでチェーンに記録される理由(§6.2 payload)。 */
export const REVOKE_ROTATION_REASON = "server-revoked";

/** ローテーション注入のモード: force = 新エポック必須 / verify = 再開・確認のみ。 */
export type RevokeRotateMode = "force" | "verify";

export interface RevokeSummary {
  /** チェーンへ追記したか(false = 有効 grant がない・並行 revoke 済みで、失効後の続きから再開)。 */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string | null;
  /** ローテーション(強制 or 再開)を実行した環境(環境 ID → 結果)。 */
  readonly rotated: readonly {
    readonly environmentId: string;
    readonly summary: RotationSummary;
    /** 新エポックを要求した実行か(true = 強制 / false = 検証パスの再開)。 */
    readonly forcedNewEpoch: boolean;
  }[];
  /** ローテーションに失敗した環境(§7 — 黙ってスキップしない)。 */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
  /** 失効より後のエポックで、未完了の再暗号化がないことを**確認済み**の環境。 */
  readonly alreadyRotated: readonly string[];
  /** 検証済みの削除ステートメントによりスキップした環境。 */
  readonly skippedDeleted: readonly string[];
}

function requireOwner(
  verified: VerifiedProject,
  signerUserId: string,
): Effect.Effect<{ readonly userId: string; readonly keyFingerprintHex: string }, CliError> {
  const member = verified.state.members.get(signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("revoke_server は owner のみが実行できます(CRYPTO_SPEC §6.2)"));
  }
  return Effect.succeed({ userId: member.userId, keyFingerprintHex: member.keyFingerprintHex });
}

/** 失効対象の grant を選ぶ(複数あるときは --fingerprint で明示)。 */
function selectGrant(
  verified: VerifiedProject,
  fingerprintHex: string | null,
): Effect.Effect<{ readonly serverKeyFingerprintHex: string } | null, CliError> {
  const grants = [...verified.state.serverGrants.values()];
  if (grants.length === 0) {
    return Effect.succeed(null);
  }
  if (fingerprintHex !== null) {
    const found = grants.find((grant) => grant.serverKeyFingerprintHex === fingerprintHex);
    if (found === undefined) {
      return Effect.fail(
        cliError(
          "--fingerprint に一致する有効な grant がありません(maruhi project verify で有効な grant の FP を確認してください)",
        ),
      );
    }
    return Effect.succeed({ serverKeyFingerprintHex: found.serverKeyFingerprintHex });
  }
  if (grants.length > 1) {
    return Effect.fail(
      cliError(
        `有効な grant が複数あります(${grants.map((grant) => grant.serverKeyFingerprintHex).join(", ")})。--fingerprint で失効対象を指定してください`,
      ),
    );
  }
  const only = grants[0];
  return only === undefined
    ? Effect.succeed(null)
    : Effect.succeed({ serverKeyFingerprintHex: only.serverKeyFingerprintHex });
}

/** revoke_server エントリを現ヘッドの直後に署名する。 */
function signRevokeEntry(input: {
  readonly verified: VerifiedProject;
  readonly actor: { readonly userId: string; readonly keyFingerprintHex: string };
  readonly serverKeyFingerprintHex: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            op: "revoke_server",
            actor: input.actor,
            payload: { serverKeyFingerprintHex: input.serverKeyFingerprintHex },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKeyPair.privateKey,
        }),
      catch: () => cliError("revoke_server エントリの署名に失敗しました"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("revoke_server エントリの署名に失敗しました"));
    }
    return signed.value;
  });
}

/**
 * 「失効後にまだローテーションされていない環境」の導出(中断復旧の基準)。
 * revoke の seq より現エポックの開始 seq が前 = その環境の現 DEK は失効した
 * サーバー鍵に開示されたまま。チェーンだけから決まるので進捗ファイルは不要。
 * 開始 seq が導出できない環境は fail-closed で対象に含める(applyCreateEnvironment
 * の不変条件が崩れたとき、環境が黙って失効対象から外れる形にしない)。
 */
function pendingEnvironmentsAfter(verified: VerifiedProject, revokeSeq: number): readonly string[] {
  const pending: string[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
    if (startSeq === undefined || startSeq < revokeSeq) {
      pending.push(environmentId);
    }
  }
  return pending.toSorted();
}

/** チェーン上の最後の revoke_server の seq(存在しなければ null)。 */
function lastRevokeSeq(verified: VerifiedProject): number | null {
  for (let index = verified.entries.length - 1; index >= 0; index -= 1) {
    const entry = verified.entries[index];
    if (entry !== undefined && entry.op === "revoke_server") {
      return entry.seq;
    }
  }
  return null;
}

interface RevokeState {
  readonly verified: VerifiedProject;
  readonly target: string;
  /** 並行 revoke で既に失効済み — 追記せずローテーションへ進む。 */
  readonly alreadyRevoked: boolean;
}

export function serverRevokeOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly fingerprintHex: string | null;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /**
   * 1 環境のローテーション(PR-1 の envRotateOp を環境ごとの床付きで包んだもの —
   * cli.ts が注入する)。force = reason 固定 + forceNewEpoch(§7 の強制)、
   * verify = reason なし + forceNewEpoch なし(未完了の再暗号化があれば再開、
   * なければ確認のみ — 新エポックは作らない)。
   */
  readonly rotate: (
    environmentId: string,
    mode: RevokeRotateMode,
  ) => Effect.Effect<RotationSummary, CliError, R>;
}): Effect.Effect<RevokeSummary, CliError, R> {
  return Effect.gen(function* () {
    const actor = yield* requireOwner(input.verified, input.signerUserId);
    const target = yield* selectGrant(input.verified, input.fingerprintHex);

    let verified = input.verified;
    let appended = false;
    let revokedFingerprint: string | null = null;

    if (target !== null) {
      revokedFingerprint = target.serverKeyFingerprintHex;
      const outcome = yield* retryOnConflict<
        RevokeState,
        { readonly verified: VerifiedProject; readonly appended: boolean },
        "head-conflict"
      >(
        { verified, target: target.serverKeyFingerprintHex, alreadyRevoked: false },
        {
          maxAttempts: MAX_ATTEMPTS,
          attempt: (state) =>
            state.alreadyRevoked
              ? Effect.succeed({ verified: state.verified, appended: false })
              : Effect.gen(function* () {
                  const entry = yield* signRevokeEntry({
                    verified: state.verified,
                    actor,
                    serverKeyFingerprintHex: state.target,
                    signingKeyPair: input.signingKeyPair,
                  });
                  yield* input.client.membership
                    .append({
                      params: { projectId: state.verified.projectId },
                      payload: { parentHeadHashHex: state.verified.state.headHashHex, entry },
                    })
                    .pipe(
                      Effect.mapError((error) =>
                        error instanceof ChainHeadConflictError ? error : toCliError(error),
                      ),
                    );
                  return { verified: state.verified, appended: true };
                }),
          classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
          recover: (state) =>
            Effect.gen(function* () {
              const resynced = yield* resyncExtended(input.resync, state.verified);
              yield* requireOwner(resynced, input.signerUserId);
              // 並行 revoke で既に失効していたら追記せず先へ(ローテーションは行う)
              return {
                verified: resynced,
                target: state.target,
                alreadyRevoked: !resynced.state.serverGrants.has(state.target),
              };
            }),
          exhaustedMessage: `revoke_server のチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
        },
      );
      verified = outcome.verified;
      appended = outcome.appended;
      // 受理後の再同期で失効の掲載を確認(サーバー申告を真実源にしない)
      verified = yield* resyncExtended(input.resync, verified);
      if (verified.state.serverGrants.has(target.serverKeyFingerprintHex)) {
        return yield* Effect.fail(
          cliError(
            "revoke_server の受理後の再同期で grant が失効していません(サーバー応答の矛盾)。配布されたチェーンを調査してください",
          ),
        );
      }
    }

    // ローテーション対象の導出: 追記した実行では「最後の revoke の seq」が今回の
    // 追記そのもの。追記しなかった実行(中断復旧)ではチェーン履歴から取る
    const revokeSeq = lastRevokeSeq(verified);
    if (revokeSeq === null) {
      return yield* Effect.fail(
        cliError(
          "有効な grant_server がなく、チェーン上に revoke_server もありません(失効するものがありません)",
        ),
      );
    }
    // 検証済みの削除環境をローテーション対象から除外する(削除済み環境は
    // rotate も pull も 404 で、回すべきラップも残っていない)。除外の根拠は
    // **署名済み削除ステートメントの検証**のみ — サーバーの 404 申告だけで
    // 黙ってスキップしない(§7)。検証できなければ対象に残り、失敗として
    // 表面化する
    const listed = yield* input.client.environments
      .list({ params: { projectId: verified.projectId } })
      .pipe(Effect.mapError(toCliError));
    const deletedVerified = yield* verifiedDeletedEnvironments(verified, listed.environments);
    const skippedDeleted = [...verified.state.environments.keys()]
      .filter((environmentId) => deletedVerified.has(environmentId))
      .toSorted();

    const sweep = yield* sweepRotations({
      rotate: input.rotate,
      verified,
      revokeSeq,
      deletedVerified,
    });

    return {
      appended,
      serverKeyFingerprintHex: revokedFingerprint,
      ...sweep,
      skippedDeleted,
    };
  });
}

/** 1 環境のローテーションの結果化(失敗は投げずに集める — §7 の全環境走査用)。 */
function rotateOutcome<R>(
  rotate: (
    environmentId: string,
    mode: RevokeRotateMode,
  ) => Effect.Effect<RotationSummary, CliError, R>,
  environmentId: string,
  mode: RevokeRotateMode,
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
function sweepRotations<R>(input: {
  readonly rotate: (
    environmentId: string,
    mode: RevokeRotateMode,
  ) => Effect.Effect<RotationSummary, CliError, R>;
  readonly verified: VerifiedProject;
  readonly revokeSeq: number;
  readonly deletedVerified: ReadonlySet<string>;
}): Effect.Effect<Pick<RevokeSummary, "rotated" | "failed" | "alreadyRotated">, never, R> {
  return Effect.gen(function* () {
    const pendingSet = new Set(pendingEnvironmentsAfter(input.verified, input.revokeSeq));
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
    // エポックは失効より後に始まっているが、その回の**再暗号化が完了したか**は
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
