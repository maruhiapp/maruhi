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
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { Keychain, parseStoredToken, type StoredToken, tokenEntryName } from "./keychain.ts";

/** `maruhi login`: device flow → token exchange → keychain. */
export function loginOp(input: {
  readonly origin: string;
  readonly clientId: string;
  readonly tokenName: string;
  readonly githubBaseUrl?: string;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const flowOptions =
      input.githubBaseUrl === undefined
        ? { clientId: input.clientId }
        : { clientId: input.clientId, githubBaseUrl: input.githubBaseUrl };

    const authorization = yield* startDeviceFlow(flowOptions);
    yield* io.log(
      `ブラウザで ${authorization.verificationUri} を開き、次のコードを入力してください:`,
    );
    yield* io.log("");
    yield* io.log(`    ${authorization.userCode}`);
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
      // 試みてから失敗させる(失効自体の失敗は握らず元エラーを優先)
      Effect.catch((setError) =>
        Effect.gen(function* () {
          const authed = yield* makeApiClient({ baseUrl: input.origin, token: exchanged.token });
          yield* authed.auth.revokeToken({}).pipe(Effect.catch(() => Effect.void));
          // 元エラー(キーチェーン不達)を優先しつつ、いま発行したトークンは
          // 失効済みであること(= MARUHI_TOKEN に流用できないこと)を明示する
          return yield* Effect.fail(
            cliError(`${setError.message}(いま発行したトークンはサーバー側で失効させました)`),
          );
        }),
      ),
    );
    yield* io.log(
      `ログインしました(user: ${exchanged.userId})。トークンは OS キーチェーンに保存されました`,
    );
    yield* io.log(`同名トークン(${input.tokenName})の再ログインは旧トークンの失効を伴います`);
  });
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
    yield* client.auth.revokeToken({}).pipe(
      // 既に失効済み(401)はローカル削除に進んでよい。それ以外(ネットワーク等)は
      // キーチェーンを残したまま失敗させ、サーバー側に生きたトークンを放置しない
      Effect.catchTag("Unauthorized", () => Effect.void),
      Effect.mapError(toCliError),
    );
    yield* keychain.remove(entryName);
    yield* io.log("ログアウトしました(トークンを失効し、キーチェーンから削除しました)");
  });
}
