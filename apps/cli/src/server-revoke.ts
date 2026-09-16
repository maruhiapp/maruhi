// `maruhi server revoke`(CRYPTO_SPEC §7 / §9)。
//
// revoke_server をチェーンへ追記し、**プロジェクトの全環境**を強制ローテーション
// する(§7 — 失効の実効性はローテーションが担う。ローテーションなしの revoke は
// 「開示を止めたつもり」の見せかけになる)。ローテーションは envRotateOp を
// 環境ごとに再利用する(reason は固定文字列)。
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
import type { ChainEntry, ProposableOperation, SigningKeyPair } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { isApprovalTarget } from "./approval-rules.ts";
import { ensureStillTarget, proposeOperation, type ProposedSummary } from "./approval.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import { cliError, type CliError } from "./errors.ts";
import { retryOnConflict } from "./retry.ts";
import {
  baselinesOf,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
  verifiedDeletedEnvironmentSet,
} from "./rotation-sweep.ts";
import { compareCodePoints } from "./scope.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/** revoke 後の全環境ローテーションでチェーンに記録される理由(§6.2 payload)。 */
export const REVOKE_ROTATION_REASON = "server-revoked";

/** revoke の結果: 提案(四眼 — K6)か適用。 */
export type ServerRevokeOutcome =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: RevokeSummary };

export interface RevokeSummary extends SweepOutcome {
  /** チェーンへ追記したか(false = 有効 grant がない・並行 revoke 済みで、失効後の続きから再開)。 */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string | null;
  /** 検証済みの削除ステートメントによりスキップした環境。 */
  readonly skippedDeleted: readonly string[];
}

function requireOwner(
  verified: VerifiedProject,
  signerUserId: string,
): Effect.Effect<void, CliError> {
  const member = verified.state.members.get(signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("Only an owner can run revoke_server (CRYPTO_SPEC §6.2)"));
  }
  return Effect.void;
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
          "No active grant matches --fingerprint (check the fingerprints of active grants with `maruhi project verify`)",
        ),
      );
    }
    return Effect.succeed({ serverKeyFingerprintHex: found.serverKeyFingerprintHex });
  }
  if (grants.length > 1) {
    return Effect.fail(
      cliError(
        `Multiple grants are active (${grants.map((grant) => grant.serverKeyFingerprintHex).join(", ")}). Specify which one to revoke with --fingerprint`,
      ),
    );
  }
  const only = grants[0];
  return only === undefined
    ? Effect.succeed(null)
    : Effect.succeed({ serverKeyFingerprintHex: only.serverKeyFingerprintHex });
}

/** revoke_server エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。 */
function signRevokeEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly serverKeyFingerprintHex: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: input.serverKeyFingerprintHex },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the revoke_server entry",
  });
}

/** チェーン上の最後の revoke_server の適用 seq(存在しなければ null。提案経由の適用も含む — K6-C)。 */
function lastRevokeSeq(verified: VerifiedProject): number | null {
  for (let index = verified.applied.length - 1; index >= 0; index -= 1) {
    const applied = verified.applied[index];
    if (applied !== undefined && applied.operation.op === "revoke_server") {
      return applied.seq;
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

/**
 * revoke 適用後の全環境走査(§7)。直接追記の revoke と、四眼で適用を完成させた承認者の
 * 履行(approval-approve.ts)が共有する。`revokeSeq` = 義務の基準(適用 seq)。
 */
export function sweepAfterRevoke<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly revokeSeq: number;
  readonly rotate: SweepRotate<R>;
}): Effect.Effect<SweepOutcome & { readonly skippedDeleted: readonly string[] }, CliError, R> {
  return Effect.gen(function* () {
    // 検証済みの削除環境をローテーション対象から除外する(削除済み環境は
    // rotate も pull も 404 で、回すべきラップも残っていない)。除外の根拠は
    // **署名済み削除ステートメントの検証**のみ — サーバーの 404 申告だけで
    // 黙ってスキップしない(§7)。検証できなければ対象に残り、失敗として
    // 表面化する
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const skippedDeleted = [...input.verified.state.environments.keys()]
      .filter((environmentId) => deletedVerified.has(environmentId))
      .toSorted(compareCodePoints);

    // 義務の環境集合 = revoke 時点の全環境(§7 — revoke_server は不変。後に作成された
    // 環境の DEK をサーバー鍵は持ちえない)。導出は rotationMandates と共有
    const sweep = yield* sweepRotations({
      rotate: input.rotate,
      verified: input.verified,
      baselines: baselinesOf(
        rotationMandates(input.verified).filter(
          (mandate) => mandate.kind === "server-revoked" && mandate.seq === input.revokeSeq,
        ),
      ),
      deletedVerified,
    });
    return { ...sweep, skippedDeleted };
  });
}

export function serverRevokeOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly fingerprintHex: string | null;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /**
   * 1 環境のローテーション(envRotateOp を環境ごとの床付きで包んだもの —
   * cli.ts が注入する)。force = reason 固定 + forceNewEpoch(§7 の強制)、
   * verify = reason なし + forceNewEpoch なし(未完了の再暗号化があれば再開、
   * なければ確認のみ — 新エポックは作らない)。
   */
  readonly rotate: SweepRotate<R>;
  readonly proposal: { readonly expiresAtMs: number; readonly nowMs: number };
}): Effect.Effect<ServerRevokeOutcome, CliError, R> {
  return Effect.gen(function* () {
    yield* requireOwner(input.verified, input.signerUserId);
    const target = yield* selectGrant(input.verified, input.fingerprintHex);

    // 四眼(K6-A): 方針が revoke_server を対象にしていれば提案して終わる(全環境の
    // rotate は適用を完成させた承認者が行う — 承認項目 22)。再開(有効 grant なし)は
    // 提案しない
    if (target !== null) {
      const inner: ProposableOperation = {
        op: "revoke_server",
        payload: { serverKeyFingerprintHex: target.serverKeyFingerprintHex },
      };
      if (isApprovalTarget(inner, input.verified.state.approvalPolicy)) {
        const proposal = yield* proposeOperation({
          client: input.client,
          verified: input.verified,
          signerUserId: input.signerUserId,
          signingKeyPair: input.signingKeyPair,
          inner,
          expiresAtMs: input.proposal.expiresAtMs,
          resync: input.resync,
          recheck: (view) =>
            Effect.gen(function* () {
              yield* requireOwner(view, input.signerUserId);
              if (!view.state.serverGrants.has(target.serverKeyFingerprintHex)) {
                return yield* Effect.fail(
                  cliError(
                    "The grant was revoked by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi server revoke` to resume the rotation",
                  ),
                );
              }
            }),
          nowMs: input.proposal.nowMs,
        });
        return { kind: "proposed", proposal };
      }
    }

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
                    signerUserId: input.signerUserId,
                    serverKeyFingerprintHex: state.target,
                    signingKeyPair: input.signingKeyPair,
                  });
                  yield* appendEntry(input.client, state.verified, entry);
                  return { verified: state.verified, appended: true };
                }),
          classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
          recover: (state) =>
            Effect.gen(function* () {
              const resynced = yield* resyncExtended(input.resync, state.verified);
              yield* requireOwner(resynced, input.signerUserId);
              yield* ensureStillTarget(
                resynced,
                { op: "revoke_server", payload: { serverKeyFingerprintHex: state.target } },
                false,
              );
              // 並行 revoke で既に失効していたら追記せず先へ(ローテーションは行う)
              return {
                verified: resynced,
                target: state.target,
                alreadyRevoked: !resynced.state.serverGrants.has(state.target),
              };
            }),
          exhaustedMessage: `revoke_server's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
        },
      );
      verified = outcome.verified;
      appended = outcome.appended;
      // 受理後の再同期で失効の掲載を確認(サーバー申告を真実源にしない)
      verified = yield* resyncExtended(input.resync, verified);
      if (verified.state.serverGrants.has(target.serverKeyFingerprintHex)) {
        return yield* Effect.fail(
          cliError(
            "The resync after revoke_server was accepted still shows the grant as active (the server's response contradicts the chain). Investigate the served chain",
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
          "There is no active grant_server and no revoke_server on the chain (nothing to revoke)",
        ),
      );
    }
    const sweep = yield* sweepAfterRevoke({
      client: input.client,
      verified,
      revokeSeq,
      rotate: input.rotate,
    });
    return {
      kind: "applied",
      summary: { appended, serverKeyFingerprintHex: revokedFingerprint, ...sweep },
    };
  });
}
