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
// interval / expires_in の上限(deepsec M 残課題 B3): RFC 8628 は上限を定めず、
// 敵対的・誤設定のエンドポイントが巨大な値を返すと deadline 検査に到達しない
// まま長時間 sleep する。実値(github.com / GHES とも interval 5 秒・
// expires_in 900 秒)に余裕を持たせた運用上限へ丸める。
// interval の上限は意図的に緩い(レビューループ 9): 悪意ある巨大値は sleep 前の
// deadline 検査が既に無害化している(残り時間を越える sleep はしない)ため、
// この上限の役目は「deadline 検査の粒度を有界に保つ」だけ — きつくすると
// interval > 上限 を正当に要求する RFC 準拠エンドポイントで、slow_down との
// 追いかけ合いにより login が恒久に不能になる
const MAX_POLL_INTERVAL_SECONDS = 900;
const DEFAULT_EXPIRES_IN_SECONDS = 900;
const MAX_EXPIRES_IN_SECONDS = 1800;

/**
 * interval を [下限, 上限] に丸める(下限はテスト用 knob で変更可)。下限が
 * 上限を越える場合は下限が勝つ(不正入力と有効入力で結果が食い違わないよう、
 * 上限側も下限で底上げする)。
 */
function clampInterval(seconds: number, minSeconds: number): number {
  if (!Number.isFinite(seconds) || seconds < minSeconds) {
    return minSeconds;
  }
  return Math.min(seconds, Math.max(MAX_POLL_INTERVAL_SECONDS, minSeconds));
}

/** expires_in を (0, 上限] に丸める(非数・非有限・非正は既定値)。start / poll 共用。 */
function clampExpires(seconds: unknown): number {
  return typeof seconds === "number" && Number.isFinite(seconds) && seconds > 0
    ? Math.min(seconds, MAX_EXPIRES_IN_SECONDS)
    : DEFAULT_EXPIRES_IN_SECONDS;
}

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
        `Failed to connect to GitHub (check your network and the URL): ${
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
          "Cannot interpret GitHub's device-flow start response (check that the client_id belongs to an OAuth App with the device flow enabled)",
        ),
      );
    }
    return {
      deviceCode,
      userCode,
      verificationUri,
      // 省略・0・負値・非数・下限未満はすべて下限(既定 5 秒)に、上限超過は
      // 上限に丸める(B3: 巨大値による長時間 sleep / 実質無期限ポーリングを防ぐ)
      intervalSeconds: clampInterval(typeof interval === "number" ? interval : 0, minInterval),
      expiresInSeconds: clampExpires(expiresIn),
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
  // startDeviceFlow が丸めた値を信頼せず、こちらでも検証と上限を適用する
  // (呼び出し元が応答値を直接渡しても deadline が有界であることを保つ)。
  // 非有限・非正は既定値へ倒す — 素の Math.min だと NaN が deadline を無効化し、
  // B3 が塞いだ無期限ポーリングが復活する(レビューループ 1)
  const deadlineMs = Date.now() + clampExpires(options.authorization.expiresInSeconds) * 1000;
  // interval も同じ理由で再検証する(レビューループ 2): NaN は deadline 比較を
  // 常に偽にし sleep も即時解決になるため、authorization_pending のたびに
  // 無間隔で再 POST する(0・負値はビジースピン)。expires と対で clamp する
  const minInterval = options.minIntervalSeconds ?? DEFAULT_POLL_INTERVAL_SECONDS;

  const poll = (intervalSeconds: number): Effect.Effect<Redacted.Redacted<string>, CliError> =>
    Effect.gen(function* () {
      // deadline は sleep の**前**に検査する(B3): 次のポーリング時刻が deadline を
      // 越えるならコードは待っている間に失効する。敵対的・誤設定のエンドポイントが
      // 巨大 interval を返しても、deadline を越えて sleep し続けない
      if (Date.now() + intervalSeconds * 1000 > deadlineMs) {
        return yield* Effect.fail(
          cliError("The authorization code expired. Run `maruhi login` again"),
        );
      }
      yield* Effect.sleep(Duration.seconds(intervalSeconds));
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
        // slow_down の累積も clampInterval で丸める(B3: 際限ない後退で deadline
        // 検査の粒度が粗くなり続けるのを防ぐ。下限が勝つ規約も初期値と揃える —
        // レビューループ 7)
        return yield* poll(clampInterval(intervalSeconds + slowDownExtra, minInterval));
      }
      if (errorCode === "expired_token") {
        return yield* Effect.fail(
          cliError("The authorization code expired. Run `maruhi login` again"),
        );
      }
      if (errorCode === "access_denied") {
        return yield* Effect.fail(cliError("The authorization was denied in the browser"));
      }
      return yield* Effect.fail(cliError("Cannot interpret GitHub's device-flow response"));
    });

  return poll(clampInterval(options.authorization.intervalSeconds, minInterval));
}
