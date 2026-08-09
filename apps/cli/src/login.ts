// maruhi login / logout(AUTH_SPEC §4 / §6)。
//
// - GitHub トークンはこのファイルのローカル変数にのみ存在し、/auth/device/exchange
//   へ渡した後は参照を残さない(両側で即時破棄 — §4-5)
// - 永続化するのは maruhi 発行トークンのみ、保存先は OS キーチェーンのみ
// - login の再実行は同名トークンのローテーション(§6): サーバー側で旧トークンが
//   自動失効する
// - logout は自トークンの失効(§6 v1 線引き)+ キーチェーンからの削除

import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient } from "./api.ts";
import { pollDeviceFlow, startDeviceFlow } from "./device-flow.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import {
  Keychain,
  masterKeyEntryName,
  parseStoredToken,
  type StoredToken,
  tokenEntryName,
} from "./keychain.ts";

/** `maruhi login`: device flow → token exchange → keychain. */
export function loginOp(input: {
  readonly origin: string;
  readonly clientId: string;
  readonly tokenName: string;
  readonly githubBaseUrl?: string;
  /** ポーリング間隔の下限(秒。テストのみ短縮)。 */
  readonly minIntervalSeconds?: number;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const flowOptions = {
      clientId: input.clientId,
      ...(input.githubBaseUrl === undefined ? {} : { githubBaseUrl: input.githubBaseUrl }),
      ...(input.minIntervalSeconds === undefined
        ? {}
        : { minIntervalSeconds: input.minIntervalSeconds }),
    };

    const authorization = yield* startDeviceFlow(flowOptions);
    // verificationUri / userCode は GitHub(または上書き先)由来の外部文字列。
    // 制御文字・ANSI を生で端末へ流さない
    yield* io.log(
      `ブラウザで ${displayText(authorization.verificationUri)} を開き、次のコードを入力してください:`,
    );
    yield* io.log("");
    yield* io.log(`    ${displayText(authorization.userCode)}`);
    yield* io.log("");
    yield* io.log("承認を待っています…");

    // GitHub トークンはこのスコープ限り。キーチェーン・設定・ログへは出さない
    const githubAccessToken = yield* pollDeviceFlow({ ...flowOptions, authorization });

    const client = yield* makeApiClient({ baseUrl: input.origin });
    const exchanged = yield* client.auth
      .deviceExchange({
        payload: { githubAccessToken, tokenName: input.tokenName },
      })
      .pipe(Effect.mapError(toCliError));

    const record: StoredToken = {
      token: exchanged.token,
      userId: exchanged.userId,
      tokenId: exchanged.tokenId,
    };
    yield* keychain.set(tokenEntryName(input.origin), JSON.stringify(record)).pipe(
      // 保存できないなら発行済みトークンを孤児化させない: サーバー側の失効を
      // 試みてから失敗させる(元エラー = キーチェーン不達を優先しつつ、失効の
      // 成否を正確に報告する — 失効成功を無条件に主張しない)
      Effect.catch((setError) =>
        Effect.gen(function* () {
          const authed = yield* makeApiClient({ baseUrl: input.origin, token: exchanged.token });
          const revoked = yield* authed.auth.revokeToken({}).pipe(
            Effect.map(() => true),
            Effect.catch(() => Effect.succeed(false)),
          );
          return yield* Effect.fail(
            cliError(
              revoked
                ? `${setError.message}(いま発行したトークンはサーバー側で失効させました)`
                : `${setError.message}(発行したトークンの失効にも失敗しました。同名トークン(${input.tokenName})での再ログインが成功すればローテーションにより自動失効します)`,
            ),
          );
        }),
      ),
    );
    yield* io.log(
      `ログインしました(user: ${displayText(exchanged.userId)})。トークンは OS キーチェーンに保存されました`,
    );
    yield* io.log(`同名トークン(${input.tokenName})の再ログインは旧トークンの失効を伴います`);
    yield* nextStepHint(input.origin, exchanged.userId, exchanged.token);
  });
}

/**
 * ログイン後の次の一歩の案内(デバイス追加・保管リマインダ — CRYPTO_SPEC §8 の
 * フローの入口)。補助線なので、状態確認の失敗でログイン成功を失敗に変えない
 * (握り潰しではなく明示の劣化: 案内をスキップするだけで他に副作用がない)。
 */
function nextStepHint(
  origin: string,
  userId: string,
  token: string,
): Effect.Effect<void, never, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const master = yield* keychain.get(masterKeyEntryName(origin, userId));
    const client = yield* makeApiClient({ baseUrl: origin, token });
    const status = yield* client.auth.recoveryStatus({});
    if (master === null) {
      yield* io.log(
        status.registered
          ? "このデバイスに master 鍵がありません。リカバリーコードで復元できます: `maruhi key recover`"
          : "master 鍵がありません。`maruhi key generate` で生成してください",
      );
    } else if (!status.registered) {
      yield* io.logError(
        "注意: リカバリーコードが未登録です。鍵を失うと復元できません — `maruhi key recovery` で発行してください",
      );
    }
  }).pipe(Effect.catch(() => Effect.void));
}

/** `maruhi logout`: revoke the presented token, then remove it from the keychain. */
export function logoutOp(input: {
  readonly origin: string;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const entryName = tokenEntryName(input.origin);
    const stored = yield* keychain.get(entryName);
    if (stored === null) {
      return yield* Effect.fail(
        cliError(
          "このサーバーのトークンはキーチェーンにありません(MARUHI_TOKEN は環境変数側で管理してください)",
        ),
      );
    }
    const record = parseStoredToken(stored);
    if (record === null) {
      // 壊れたレコードは失効を呼べないが、残しても使えないため削除する
      yield* keychain.remove(entryName);
      return yield* Effect.fail(
        cliError(
          "キーチェーンのトークンレコードが壊れていたため削除しました(サーバー側の失効は行えていません)",
        ),
      );
    }
    const client = yield* makeApiClient({ baseUrl: input.origin, token: record.token });
    // キーチェーン削除を失効「より先」に行う: 失効後に削除が失敗すると、
    // サーバーが無効化済みのトークンをキーチェーンに残し、以後の全コマンドが
    // その死んだトークンで 401 になる(手動でしか復旧できない)。削除が先なら
    // 最悪でもサーバー側に生きたトークンが残るだけで、再ログインで回収できる
    yield* keychain.remove(entryName);
    yield* client.auth.revokeToken({}).pipe(
      // 既に失効済み(401)は成功として扱う。それ以外(ネットワーク等)は
      // 失敗させ、サーバー側に生きたトークンが残りうることを利用者へ伝える
      Effect.catchTag("Unauthorized", () => Effect.void),
      Effect.mapError(toCliError),
    );
    yield* io.log("ログアウトしました(トークンを失効し、キーチェーンから削除しました)");
    // resolveSession は MARUHI_TOKEN をキーチェーンより優先する(session.ts)。
    // 環境変数が残っていると「ログアウトしたのに CLI が動き続ける」ため明示する
    if ((io.envVar("MARUHI_TOKEN") ?? "").length > 0) {
      yield* io.log(
        "注意: MARUHI_TOKEN が設定されているため、CLI は引き続きその トークンで認証されます(環境変数のトークンはここでは失効しません。管理は環境変数側で行ってください)",
      );
    }
  });
}
