// GitHub device flow(RFC 8628。AUTH_SPEC §4)。
//
// ここで得る GitHub アクセストークンは呼び出し元のローカル変数にのみ存在し、
// /auth/device/exchange へ渡した後は破棄される(保存・ログ出力禁止 —
// AUTH_SPEC §10)。エラーメッセージにもトークン値を含めない。第三者(GitHub)の
// 資格情報なので maruhi トークンと同様に `Redacted` で包み、剥がすのは
// exchange のワイヤ境界だけにする(login.ts)。
//
// githubBaseUrl はテスト(ローカル HTTP モック)用の注入点。本番は既定値。

import { Duration, Effect, Redacted } from "effect";

import { cliError, type CliError } from "./errors.ts";

const GITHUB_BASE_URL = "https://github.com";
const DEVICE_FLOW_SCOPE = "read:user user:email";
const SLOW_DOWN_EXTRA_SECONDS = 5;
// RFC 8628 §3.5: interval 省略時の既定は 5 秒。サーバーが 0 や負値を返しても
// ビジースピン(CPU・レート制限)にならないよう、この値を下限に固定する
const DEFAULT_POLL_INTERVAL_SECONDS = 5;

/** RFC 8628 §3.2 device authorization response (the fields the CLI uses). */
export interface DeviceAuthorization {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly intervalSeconds: number;
  readonly expiresInSeconds: number;
}

interface DeviceFlowOptions {
  readonly clientId: string;
  readonly githubBaseUrl?: string;
  /** ポーリング間隔の下限(秒)。既定 5(RFC 8628)。テストのみ短縮する。 */
  readonly minIntervalSeconds?: number;
}

function postForm(
  url: string,
  form: Record<string, string>,
): Effect.Effect<Record<string, unknown>, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
          "user-agent": "maruhi-cli",
        },
        body: new URLSearchParams(form),
      });
      // RFC 8628 / RFC 6749 準拠実装は error 応答を HTTP 400 + JSON ボディで
      // 返しうる(github.com は 200 + error だが、準拠実装も受ける)。
      // JSON オブジェクトが取れる限りステータスに関わらず呼び出し元の
      // error フィールド分類に委ねる
      const text = await response.text();
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
      if (typeof parsed === "object" && parsed !== null) {
        return parsed as Record<string, unknown>;
      }
      throw new Error(`HTTP ${response.status}`);
    },
    catch: (error) =>
      cliError(
        `GitHub への接続に失敗しました(ネットワーク・URL を確認してください): ${
          error instanceof Error ? error.message : String(error)
        }`,
      ),
  });
}

/** Starts the device flow: returns the user code and verification URI to show. */
export function startDeviceFlow(
  options: DeviceFlowOptions,
): Effect.Effect<DeviceAuthorization, CliError> {
  const base = options.githubBaseUrl ?? GITHUB_BASE_URL;
  const minInterval = options.minIntervalSeconds ?? DEFAULT_POLL_INTERVAL_SECONDS;
  return Effect.gen(function* () {
    const body = yield* postForm(`${base}/login/device/code`, {
      client_id: options.clientId,
      scope: DEVICE_FLOW_SCOPE,
    });
    const deviceCode = body["device_code"];
    const userCode = body["user_code"];
    const verificationUri = body["verification_uri"];
    const interval = body["interval"];
    const expiresIn = body["expires_in"];
    if (
      typeof deviceCode !== "string" ||
      typeof userCode !== "string" ||
      typeof verificationUri !== "string"
    ) {
      return yield* Effect.fail(
        cliError(
          "GitHub の device flow 開始応答を解釈できません(client_id が device flow 有効な OAuth App か確認してください)",
        ),
      );
    }
    return {
      deviceCode,
      userCode,
      verificationUri,
      // 省略・0・負値・非数・下限未満はすべて下限(既定 5 秒)に丸める
      intervalSeconds:
        typeof interval === "number" && interval >= minInterval ? interval : minInterval,
      expiresInSeconds: typeof expiresIn === "number" && expiresIn > 0 ? expiresIn : 900,
    } satisfies DeviceAuthorization;
  });
}

/**
 * Polls the token endpoint until the user approves (RFC 8628 §3.4 / §3.5):
 * `authorization_pending` keeps polling at the current interval, `slow_down`
 * adds 5 seconds, anything else fails. Gives up after `expiresInSeconds`.
 */
export function pollDeviceFlow(
  options: DeviceFlowOptions & {
    readonly authorization: DeviceAuthorization;
    /** RFC 8628 §3.5 の増分(既定 5 秒)。テストのみ短縮する。 */
    readonly slowDownExtraSeconds?: number;
  },
): Effect.Effect<Redacted.Redacted<string>, CliError> {
  const base = options.githubBaseUrl ?? GITHUB_BASE_URL;
  const slowDownExtra = options.slowDownExtraSeconds ?? SLOW_DOWN_EXTRA_SECONDS;
  const deadlineMs = Date.now() + options.authorization.expiresInSeconds * 1000;

  const poll = (intervalSeconds: number): Effect.Effect<Redacted.Redacted<string>, CliError> =>
    Effect.gen(function* () {
      yield* Effect.sleep(Duration.seconds(intervalSeconds));
      if (Date.now() > deadlineMs) {
        return yield* Effect.fail(
          cliError("認可コードの有効期限が切れました。`maruhi login` をやり直してください"),
        );
      }
      const body = yield* postForm(`${base}/login/oauth/access_token`, {
        client_id: options.clientId,
        device_code: options.authorization.deviceCode,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      });
      const accessToken = body["access_token"];
      if (typeof accessToken === "string" && accessToken.length > 0) {
        return Redacted.make(accessToken, { label: "github-token" });
      }
      const errorCode = body["error"];
      if (errorCode === "authorization_pending") {
        return yield* poll(intervalSeconds);
      }
      if (errorCode === "slow_down") {
        return yield* poll(intervalSeconds + slowDownExtra);
      }
      if (errorCode === "expired_token") {
        return yield* Effect.fail(
          cliError("認可コードの有効期限が切れました。`maruhi login` をやり直してください"),
        );
      }
      if (errorCode === "access_denied") {
        return yield* Effect.fail(cliError("ブラウザ側で認可が拒否されました"));
      }
      return yield* Effect.fail(cliError("GitHub の device flow 応答を解釈できません"));
    });

  return poll(options.authorization.intervalSeconds);
}
