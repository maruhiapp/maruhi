// チェーンエントリの署名と追記の共有実装(CRYPTO_SPEC §6.1 / §6.4)。
//
// メンバーシップ操作(add_member / remove_member / change_role — member.ts)と
// サーバー開示操作(grant_server / revoke_server — server-grant / server-revoke)
// は、いずれも「現ヘッドの直後に署名 → 親ヘッド CAS で追記(409 は
// ChainHeadConflict として呼び出し側の retryOnConflict へ)」という同じ構造を
// 持つ。署名の組み立てと追記 POST をここに一本化する(op ごとの事前検査・
// CAS 競合からの回復はそれぞれの op が持つ)。

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { ChainEntry, ChainOperation, SigningKeyPair } from "@maruhi/crypto";
import { signChainEntry, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/**
 * 検証済みビューの現ヘッドの直後に、署名者の鍵で 1 エントリを署名する。
 * actor(user_id + 鍵 FP)は検証済みビューの現メンバー集合から解決する
 * (非メンバーは署名者になれない)。`failureText` は署名失敗時の文言
 * (op 名を含めて呼び出し側が与える)。
 */
export function signEntryAtHead(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly operation: ChainOperation;
  readonly signingKeyPair: SigningKeyPair;
  readonly failureText: string;
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    const actor = input.verified.state.members.get(input.signerUserId);
    if (actor === undefined) {
      return yield* Effect.fail(cliError("Not a chain-derived member"));
    }
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({
          entry: {
            suite: SUITE_ID,
            seq: input.verified.state.headSeq + 1,
            prevHashHex: input.verified.state.headHashHex,
            ...input.operation,
            actor: { userId: actor.userId, keyFingerprintHex: actor.keyFingerprintHex },
            timestampMs: Date.now(),
          },
          signingKey: input.signingKeyPair.privateKey,
        }),
      catch: () => cliError(input.failureText),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError(input.failureText));
    }
    return signed.value;
  });
}

/**
 * 親ヘッド CAS つきの追記。ヘッド競合は `ChainHeadConflictError` のまま返す
 * (呼び出し側の retryOnConflict が classify する)。それ以外は CliError へ写す。
 */
export function appendEntry(
  client: MaruhiClient,
  verified: VerifiedProject,
  entry: ChainEntry,
): Effect.Effect<void, ChainHeadConflictError | CliError> {
  return client.membership
    .append({
      params: { projectId: verified.projectId },
      payload: { parentHeadHashHex: verified.state.headHashHex, entry },
    })
    .pipe(
      Effect.asVoid,
      Effect.mapError((error) =>
        error instanceof ChainHeadConflictError ? error : toCliError(error),
      ),
    );
}
