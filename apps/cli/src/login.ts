// maruhi login / logout(AUTH_SPEC §4 / §6)。
//
// - GitHub トークンはこのファイルのローカル変数にのみ存在し、/auth/device/exchange
//   へ渡した後は参照を残さない(両側で即時破棄 — §4-5)
// - 永続化するのは maruhi 発行トークンのみ、保存先は OS キーチェーンのみ
// - login の再実行は同名トークンのローテーション(§6): サーバー側で旧トークンが
//   自動失効する
// - logout は自トークンの失効(§6 v1 線引き)+ キーチェーンからの削除

import { SetupIncompleteError } from "@maruhi/api-schema";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { makeApiClient } from "./api.ts";
import { pollDeviceFlow, startDeviceFlow } from "./device-flow.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import {
  hasRedactedPlaceholder,
  Keychain,
  masterKeyEntryName,
  parseStoredToken,
  redactedPlaceholderTokenMessage,
  serializeStoredToken,
  type StoredToken,
  tokenEntryName,
} from "./keychain.ts";
import { envTokenStatus } from "./session.ts";

/**
 * GitHub OAuth App client_id の解決(AUTH_SPEC §4): `--github-client-id`
 * フラグ → config の `githubClientId` → サーバーの公開設定エンドポイント
 * `GET /auth/config`。config は自動解決の導入後も上書き手段として残す
 * (GHES・テスト用 — セッション 11 裁定 (iii))。
 */
export function resolveClientId(input: {
  readonly origin: string;
  readonly explicit: string | undefined;
  readonly configured: string | undefined;
}): Effect.Effect<string, CliError, HttpClient.HttpClient> {
  if (input.explicit !== undefined) {
    return Effect.succeed(input.explicit);
  }
  if (input.configured !== undefined) {
    return Effect.succeed(input.configured);
  }
  return Effect.gen(function* () {
    const client = yield* makeApiClient({ baseUrl: input.origin });
    const config = yield* client.auth.authConfig({}).pipe(
      Effect.mapError((error) =>
        // 未設定サーバー(SetupIncomplete)は failure.ts の案内をそのまま使う。
        // それ以外(到達不能・旧サーバー等)は手動設定の逃げ道を添える
        error instanceof SetupIncompleteError
          ? toCliError(error)
          : cliError(
              `${toCliError(error).message}(client_id をサーバーから自動取得できませんでした。\`maruhi config set githubClientId <id>\` で手動設定できます)`,
            ),
      ),
    );
    return config.githubClientId;
  });
}

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
        // 剥がす理由: exchange のワイヤ境界。GitHub トークンの生値はここで
        // 一度だけ本文に載り、以後 CLI 側には残らない(AUTH_SPEC §4-5)
        payload: {
          githubAccessToken: Redacted.value(githubAccessToken),
          tokenName: input.tokenName,
        },
      })
      .pipe(Effect.mapError(toCliError));

    const issuedToken = Redacted.make(exchanged.token, { label: "maruhi-token" });
    const record: StoredToken = {
      token: issuedToken,
      userId: exchanged.userId,
      tokenId: exchanged.tokenId,
    };
    // JSON.stringify(record) は使わない — Redacted.toJSON() が伏字を返し、
    // "<redacted>" がキーチェーンへ書かれる(keychain.ts の注記)
    yield* keychain.set(tokenEntryName(input.origin), serializeStoredToken(record)).pipe(
      // 保存できないなら発行済みトークンを孤児化させない: サーバー側の失効を
      // 試みてから失敗させる(元エラー = キーチェーン不達を優先しつつ、失効の
      // 成否を正確に報告する — 失効成功を無条件に主張しない)
      Effect.catch((setError) =>
        Effect.gen(function* () {
          const authed = yield* makeApiClient({ baseUrl: input.origin, token: issuedToken });
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
    yield* nextStepHint(input.origin, exchanged.userId, issuedToken);
  });
}

/**
 * ログイン後の次の一歩の案内(デバイス追加・保管リマインダ — CRYPTO_SPEC §8 の
 * フローの入口)。補助線なので、状態確認の失敗でログイン成功を失敗に変えない。
 * ただし無言では飲まない(CLAUDE.md): 失敗時はスキップした旨を 1 行で明示する。
 */
function nextStepHint(
  origin: string,
  userId: string,
  token: Redacted.Redacted<string>,
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
  }).pipe(
    Effect.catch(() =>
      Effect.flatMap(CliIo, (io) =>
        io.logError(
          "注意: リカバリー登録状態を確認できなかったため、次の一歩の案内をスキップしました(ログインには影響しません。状態は `maruhi key show` で確認できます)",
        ),
      ),
    ),
  );
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
      const redacted = hasRedactedPlaceholder(stored);
      yield* keychain.remove(entryName);
      return yield* Effect.fail(
        cliError(
          redacted
            ? `${redactedPlaceholderTokenMessage}(使えないレコードなので削除しました。サーバー側の失効は行えていません)`
            : "キーチェーンのトークンレコードが壊れていたため削除しました(サーバー側の失効は行えていません)",
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
    // 環境変数が残っていると「ログアウトしたのに CLI が動き続ける」ため明示する。
    // 判定は envTokenStatus に委ねる: ここで独自に見ると、セッション解決とは
    // 違う結論(空白だけの値・origin 不一致でも「認証されます」)を出してしまう
    const envToken = yield* envTokenStatus(input.origin);
    if (envToken === "active") {
      yield* io.log(
        "注意: MARUHI_TOKEN が設定されているため、CLI は引き続きそのトークンで認証されます(環境変数のトークンはここでは失効しません。管理は環境変数側で行ってください)",
      );
    } else if (envToken === "inactive") {
      // 設定はされているがこの origin には効かない。この状態は**キーチェーンへ
      // 落ちずに失敗する**ので、消し忘れを「ログインしていません」以外の言葉で示す
      yield* io.log(
        "注意: MARUHI_TOKEN が設定されていますが、MARUHI_TOKEN_ORIGIN がこのサーバーと一致しないため認証には使われません(このままでは次のコマンドが失敗します。環境変数を解除するか、MARUHI_TOKEN_ORIGIN を対象サーバーに合わせてください)",
      );
    }
  });
}
