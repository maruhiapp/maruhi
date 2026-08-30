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
import { displayText, formatUtcDate } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import {
  hasRedactedPlaceholder,
  Keychain,
  masterKeyEntryName,
  parseStoredToken,
  redactedPlaceholderEnvTokenMessage,
  redactedPlaceholderTokenMessage,
  serializeStoredToken,
  type StoredToken,
  tokenEntryName,
} from "./keychain.ts";
import { type EnvTokenStatus, envTokenStatus } from "./session.ts";

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
              `${toCliError(error).message} (could not auto-resolve the client_id from the server; you can set it manually with \`maruhi config set githubClientId <id>\`)`,
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
  /** 明示 TTL(日。AUTH_SPEC §6 — W3a。省略時はサーバー既定の 90 日)。 */
  readonly expiresInDays?: number;
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
      `Open ${displayText(authorization.verificationUri)} in your browser and enter this code:`,
    );
    yield* io.log("");
    yield* io.log(`    ${displayText(authorization.userCode)}`);
    yield* io.log("");
    yield* io.log("Waiting for approval\u2026");

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
          ...(input.expiresInDays === undefined ? {} : { expiresInDays: input.expiresInDays }),
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
                ? `${setError.message} (the token just issued has been revoked on the server)`
                : `${setError.message} (revoking the issued token also failed; a successful re-login with the same token name (${input.tokenName}) will revoke it automatically by rotation)`,
            ),
          );
        }),
      ),
    );
    yield* io.log(
      `Logged in (user: ${displayText(exchanged.userId)}). The token is stored in the OS keychain`,
    );
    // 有効期限は発行時に固定される(AUTH_SPEC §6 の既定 TTL — W3a)。期限が
    // 来ると 401 になるため、いつ再ログインが要るかを発行時点で可視にする。
    // 表示は display.ts の total フォーマッタ経由(サーバー申告の無制限 number を
    // Date#toISOString へ直接渡さない — deepsec B1/B4/B5 と同じ規律。PR #108
    // pullfrog 指摘)。フィールド欠落 = W3a より古いサーバー(TTL 未実装)
    if (exchanged.expiresAtMs !== undefined) {
      yield* io.log(
        `The token expires on ${formatUtcDate(exchanged.expiresAtMs)} (UTC). Re-login (\`maruhi login\`) rotates it`,
      );
    } else {
      yield* io.log(
        "Note: this server did not report a token expiry (it predates token TTLs; --token-ttl-days has no effect). Update the server to enforce token lifetimes",
      );
    }
    yield* io.log(
      `Re-logging in with the same token name (${input.tokenName}) revokes the old token`,
    );
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
          ? "No master key on this device. You can restore it with your recovery code: `maruhi key recover`"
          : "No master key yet. Generate one with `maruhi key generate`",
      );
    } else if (!status.registered) {
      yield* io.logError(
        "Note: no recovery code is registered. If you lose the key it cannot be restored — issue one with `maruhi key recovery`",
      );
    }
  }).pipe(
    Effect.catch(() =>
      Effect.flatMap(CliIo, (io) =>
        io.logError(
          "Note: skipped the next-step hint because the recovery registration status could not be checked (login itself is unaffected; check the status with `maruhi key show`)",
        ),
      ),
    ),
  );
}

/**
 * ログアウト後に MARUHI_TOKEN が残っていることの案内(残らないなら null)。
 *
 * `active` 以外はどれも**キーチェーンへ落ちずに失敗する**状態だが、直し方は
 * 別々(貼り直す・足す・合わせる)なので、原因ごとに言い分ける。
 */
function envTokenNotice(status: EnvTokenStatus): string | null {
  switch (status.kind) {
    case "unset":
      return null;
    case "active":
      return "Note: MARUHI_TOKEN is set, so the CLI stays authenticated with that token (the env-var token is not revoked here; manage it on the environment side)";
    case "placeholder":
      return `Note: ${redactedPlaceholderEnvTokenMessage} (the next command will fail as-is)`;
    case "originInvalid":
      // 理由は解決側の文言をそのまま使う(言い換えると次の失敗と食い違う)
      return `Note: MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN cannot be used, so the token is not used for authentication (${status.reason}). The next command will fail as-is — unset the env vars or fix the reported problem`;
    case "originMissing":
      return "Note: MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN is not set, so the token is not used for authentication (the next command will fail as-is — unset MARUHI_TOKEN or set MARUHI_TOKEN_ORIGIN to the target server's origin)";
    case "originMismatch":
      return "Note: MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN does not match this server, so the token is not used for authentication (the next command will fail as-is — unset the env vars or point MARUHI_TOKEN_ORIGIN at the target server)";
  }
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
          "No token for this server in the keychain (MARUHI_TOKEN is managed on the environment side)",
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
            ? `${redactedPlaceholderTokenMessage} (the unusable record has been deleted; the server-side revocation could not be performed)`
            : "The keychain token record was corrupt, so it has been deleted (the server-side revocation could not be performed)",
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
    yield* io.log("Logged out (the token was revoked and removed from the keychain)");
    // resolveSession は MARUHI_TOKEN をキーチェーンより優先する(session.ts)。
    // 環境変数が残っていると「ログアウトしたのに CLI が動き続ける」ため明示する。
    // 判定は envTokenStatus に委ねる: ここで独自に見ると、セッション解決とは
    // 違う結論(空白だけの値・origin 不一致でも「認証されます」)を出してしまう
    const notice = envTokenNotice(yield* envTokenStatus(input.origin));
    if (notice !== null) {
      yield* io.log(notice);
    }
  });
}
