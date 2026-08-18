// §7 の全環境走査へ注入する 1 環境ローテーション(server revoke / member
// remove / change-role で共用)。
//
// ADR-0016 第 2 段階の移行で cli.ts(gunshi 側)から切り出した。第 2 段階の
// 完了により、利用者は全員 effect/unstable/cli 側(effect-cli.ts)になった。

import { isEnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { CliServices, ProjectContext } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import type { RotationSummary } from "./env-rotate.ts";
import { envRotateOp } from "./env-rotate.ts";
import { type CliError, usageError } from "./errors.ts";
import type { SweepRotateMode } from "./rotation-sweep.ts";

/** チェーン導出の環境 ID が CLI の形式検査に通らない場合の防衛(通常は到達しない)。 */
function cliErrorForInvalidChainEnvironmentId(): CliError {
  return usageError(
    "A chain-derived environment ID fails the CLI's format check (the chain contradicts the server's acceptance policy)",
  );
}

/**
 * §7 の全環境走査へ注入する 1 環境ローテーション。義務エントリの追記や先行の
 * rotate でチェーンは前進しているので、各環境は再同期済みビューで開始する。
 * force = §7 の強制(新エポック必須)/ verify = 検証パス(未完了の再暗号化が
 * あれば再開)。
 */
export function sweepRotateFor(
  context: ProjectContext,
  reason: string,
): (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, CliServices> {
  return (environmentId: string, mode: SweepRotateMode) =>
    Effect.gen(function* () {
      if (!isEnvironmentId(environmentId)) {
        return yield* Effect.fail(cliErrorForInvalidChainEnvironmentId());
      }
      const floorHandle = yield* floorHandleFor(context, environmentId);
      const verified = yield* context.resync;
      return yield* envRotateOp({
        client: context.client,
        verified,
        environmentId,
        recipient: context.recipient,
        reason: mode === "force" ? reason : undefined,
        forceNewEpoch: mode === "force",
        // 全環境走査は移行操作ではない — マニフェスト欠落の許容は明示の
        // `maruhi env rotate <env> --init-manifest` に限る(session-27 §14)
        initManifest: false,
        signerUserId: context.session.userId,
        signingKeyPair: context.masterKeys.sigKeyPair,
        resync: context.resync,
        floor: floorHandle,
      });
    });
}
