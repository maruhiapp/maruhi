// `maruhi server revoke`(CRYPTO_SPEC §7 / §9 — Wave 2 A1)。
//
// revoke_server をチェーンへ追記し、**プロジェクトの全環境**を強制ローテーション
// する(§7 — 失効の実効性はローテーションが担う。ローテーションなしの revoke は
// 「開示を止めたつもり」の見せかけになる)。ローテーションは PR-1 の
// envRotateOp を環境ごとに再利用する(reason は固定文字列)。
//
// 中断復旧(進捗ファイルなし — 分散状態から導出): revoke がチェーンに載った後で
// 落ちても、再実行が「有効 grant なし → 最後の revoke_server の seq を取り、
// 現エポックの開始 seq がそれより前の環境だけを続きからローテーション」で収束
// する。rotate が 404(削除済み環境)の場合は §7 の規律どおり黙ってスキップ
// せず、検証済み削除ステートメントの確認を促して失敗として報告する。

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

const MAX_ATTEMPTS = 5;

/** revoke 後の全環境ローテーションでチェーンに記録される理由(§6.2 payload)。 */
export const REVOKE_ROTATION_REASON = "server-revoked";

export interface RevokeSummary {
  /** チェーンへ追記したか(false = 有効 grant がなく、失効後の続きから再開)。 */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string | null;
  /** ローテーションを実行した環境(環境 ID → 結果)。 */
  readonly rotated: readonly {
    readonly environmentId: string;
    readonly summary: RotationSummary;
  }[];
  /** ローテーションに失敗した環境(§7 — 黙ってスキップしない)。 */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
  /** 既にローテーション済みで何もしなかった環境。 */
  readonly alreadyRotated: readonly string[];
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
 */
function pendingEnvironmentsAfter(verified: VerifiedProject, revokeSeq: number): readonly string[] {
  const pending: string[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    const startSeq = environment.epochStartSeqs.get(environment.currentEpoch);
    if (startSeq !== undefined && startSeq < revokeSeq) {
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
   * cli.ts が注入する。reason = REVOKE_ROTATION_REASON / forceNewEpoch = true)。
   */
  readonly rotate: (environmentId: string) => Effect.Effect<RotationSummary, CliError, R>;
}): Effect.Effect<RevokeSummary, CliError, R> {
  return Effect.gen(function* () {
    const actor = yield* requireOwner(input.verified, input.signerUserId);
    const target = yield* selectGrant(input.verified, input.fingerprintHex);

    let verified = input.verified;
    let appended = false;
    let revokedFingerprint: string | null = null;

    if (target !== null) {
      revokedFingerprint = target.serverKeyFingerprintHex;
      verified = yield* retryOnConflict<RevokeState, VerifiedProject, "head-conflict">(
        { verified, target: target.serverKeyFingerprintHex },
        {
          maxAttempts: MAX_ATTEMPTS,
          attempt: (state) =>
            Effect.gen(function* () {
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
              return state.verified;
            }),
          classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
          recover: (state) =>
            Effect.gen(function* () {
              const resynced = yield* resyncExtended(input.resync, state.verified);
              yield* requireOwner(resynced, input.signerUserId);
              // 並行 revoke で既に失効していたら追記せず先へ(ローテーションは行う)
              if (!resynced.state.serverGrants.has(state.target)) {
                return yield* Effect.fail(
                  cliError(
                    "対象の grant は再同期後のチェーンに存在しません(並行 revoke の可能性)。再実行するとローテーションの続きから再開します",
                  ),
                );
              }
              return { verified: resynced, target: state.target };
            }),
          exhaustedMessage: `revoke_server のチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
        },
      );
      appended = true;
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
    const pending = pendingEnvironmentsAfter(verified, revokeSeq);
    const alreadyRotated = [...verified.state.environments.keys()]
      .filter((environmentId) => !pending.includes(environmentId))
      .toSorted();

    // §7: 全環境で rotate_epoch。1 環境の失敗で残りを止めない(失敗は集めて
    // 報告し、再実行で続きから再開する)
    const rotated: { readonly environmentId: string; readonly summary: RotationSummary }[] = [];
    const failed: { readonly environmentId: string; readonly message: string }[] = [];
    for (const environmentId of pending) {
      const result = yield* input.rotate(environmentId).pipe(
        Effect.map((summary) => ({ kind: "ok", summary }) as const),
        Effect.catch((error) =>
          Effect.succeed({ kind: "failed", message: error.message } as const),
        ),
      );
      if (result.kind === "ok") {
        rotated.push({ environmentId, summary: result.summary });
      } else {
        failed.push({ environmentId, message: result.message });
      }
    }

    return {
      appended,
      serverKeyFingerprintHex: revokedFingerprint,
      rotated,
      failed,
      alreadyRotated,
    };
  });
}
