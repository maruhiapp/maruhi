// maruhi login / logout(AUTH_SPEC §4 / §6)。
//
// login はサーバー仲介の web-flow ハンドオフ(§4 — 2026-08-31 全面改訂):
// start → verificationUrl と userCode の表示(対話端末 × 非エージェントのみ
// ブラウザ自動起動を試みる)→ poll。CLI はアイデンティティプロバイダと直接
// 通信しない(client_id 解決は廃止)。
//
// - flowToken は CLI 専用の bearer 資格情報(§4-1 (1))。ローカル変数にのみ
//   存在し、表示・ログ・保存をしない(poll の payload にのみ載る)
// - 永続化するのは maruhi 発行トークンのみ、保存先は OS キーチェーンのみ
// - login の再実行は同名トークンのローテーション(§6): サーバー側で旧トークンが
//   自動失効する
// - logout は自トークンの失効(§6 v1 線引き)+ キーチェーンからの削除

import { MIN_CLI_POLL_INTERVAL_SECONDS } from "@maruhi/api-schema";
import { Duration, Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { AgentProfileRef } from "./agent-gate.ts";
import { makeApiClient, type MaruhiClient } from "./api.ts";
import { displayText, escapeText, formatUtcDate } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
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

// サーバー申告値の運用上限(device flow 時代の B3 と同じ論拠): 敵対的・誤設定
// サーバーの巨大値で deadline 検査に到達しないまま長時間 sleep しない。実値
// (サーバーの TTL 15 分・間隔 5 秒)に余裕を持たせた丸め
const MAX_POLL_INTERVAL_SECONDS = 900;
const DEFAULT_EXPIRES_IN_SECONDS = 900;
const MAX_EXPIRES_IN_SECONDS = 1800;

/**
 * ポーリング間隔を [下限, 上限] に丸める(下限はワイヤ共有の
 * MIN_CLI_POLL_INTERVAL_SECONDS — §4-1 (5)。テストのみ短縮可)。0・負値・非数は
 * 下限へ(ビジースピンしない)。下限が上限を越える場合は下限が勝つ。
 */
function clampInterval(seconds: number, minSeconds: number): number {
  if (!Number.isFinite(seconds) || seconds < minSeconds) {
    return minSeconds;
  }
  return Math.min(seconds, Math.max(MAX_POLL_INTERVAL_SECONDS, minSeconds));
}

/**
 * ブラウザ自動起動に渡してよい URL か(fail-closed)。verificationUrl は
 * サーバー応答由来の untrusted 入力で、表示側は displayText で中和している —
 * OS の opener に渡す側も同様に生値を信頼しない。OS の URL ハンドラは任意
 * スキームをディスパッチするため http(s) のみ許可し、パース不能値も拒否する。
 * 不合格は自動起動のスキップ = 手動オープン案内(表示済みの URL)への縮退。
 */
function isOpenableUrl(raw: string): boolean {
  if (!URL.canParse(raw)) {
    return false;
  }
  const { protocol } = new URL(raw);
  return protocol === "https:" || protocol === "http:";
}

/**
 * ブラウザ自動起動の UX 分岐(§4-1 (2) — ADR-0016 決定 7 の既存サービスを
 * 流用する分岐であって新しいセキュリティゲートではない)。「対話端末 ×
 * 非エージェント × URL 検証合格(isOpenableUrl)」のときのみ試みる。失敗・
 * 非対象・検証不合格のいずれも表示 + ポーリングで完走する — 縮退経路は
 * この 1 本で全環境を覆う。
 */
function maybeOpenBrowser(
  io: CliIoShape,
  verificationUrl: string,
): Effect.Effect<void, never, Stdio.Stdio> {
  return Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (agent.isAgent || !stdinIsTerminal || !stdoutIsTerminal || !isOpenableUrl(verificationUrl)) {
      return;
    }
    const opened = yield* io.openBrowser(verificationUrl);
    if (opened) {
      yield* io.log("Opened the browser (if nothing appeared, open the URL above manually)");
    }
  });
}

/** expiresInSeconds を (0, 上限] に丸める(非数・非有限・非正は既定値)。 */
function clampExpires(seconds: number): number {
  return Number.isFinite(seconds) && seconds > 0
    ? Math.min(seconds, MAX_EXPIRES_IN_SECONDS)
    : DEFAULT_EXPIRES_IN_SECONDS;
}

const FLOW_EXPIRED_MESSAGE = "The sign-in request expired. Run `maruhi login` again";

/** poll 1 回の帰結(レート制限は失敗ではなく次回間隔の調整として扱う)。 */
type PollOutcome =
  | { readonly kind: "pending" }
  | { readonly kind: "backoff"; readonly retryAfterSeconds: number }
  | {
      readonly kind: "approved";
      readonly token: string;
      readonly tokenId: string;
      readonly userId: string;
      readonly expiresAtMs: number;
    };

function pollOnce(
  client: MaruhiClient,
  flowId: string,
  flowToken: string,
): Effect.Effect<PollOutcome, CliError> {
  return client.authCli.cliPoll({ payload: { flowId, flowToken } }).pipe(
    Effect.flatMap((result): Effect.Effect<PollOutcome, CliError> => {
      if (result.status === "approved") {
        return Effect.succeed({ kind: "approved", ...result });
      }
      if (result.status === "denied") {
        return Effect.fail(cliError("The sign-in was denied in the browser. No token was issued"));
      }
      return Effect.succeed({ kind: "pending" });
    }),
    // 期限切れ(型付き — §4-2)はポーリングをやめて再ログインを案内する
    Effect.catchTag("CliFlowExpired", () => Effect.fail(cliError(FLOW_EXPIRED_MESSAGE))),
    // 一様拒否(§4-2): 資格不一致・消費済みフローの再 poll 等。理由は
    // 出し分けられない(サーバーがオラクルを作らない)ので再ログインを案内する
    Effect.catchTag("CliFlowRejected", () =>
      Effect.fail(
        cliError("The sign-in flow was rejected by the server. Run `maruhi login` again"),
      ),
    ),
    // 429 は失敗ではない(§4-1 (5) — サーバーは超過ポーリングを拒否してよい)。
    // 案内された待ち時間だけ下がって続ける
    Effect.catchTag("AuthRateLimited", (error) =>
      Effect.succeed<PollOutcome>({ kind: "backoff", retryAfterSeconds: error.retryAfterSeconds }),
    ),
    Effect.mapError(toCliError),
  );
}

/** `maruhi login`: start → browser approval → poll → keychain(AUTH_SPEC §4)。 */
export function loginOp(input: {
  readonly origin: string;
  readonly tokenName: string;
  /**
   * 発行した PAT の生値を端末へ 1 度だけ表示する(AUTH_SPEC §6 の「発行時の
   * 端末表示 1 箇所」— 裁定 CK。リース非対応環境の MARUHI_TOKEN 供給用)。
   * 表示可否のゲート(ADR-0016 決定 7 — fail-closed 2 層)は呼び出し側が
   * **通信より前**に通している前提。
   */
  readonly showToken: boolean;
  /**
   * tokenName がこの端末の既定名(`cli:<hostname>`)か(裁定 CM — 既定名の
   * 真実源は呼び出し側の引数層なのでここでは判定しない)。身元スワップ注記の
   * 分岐に使う: 既定名で供給した場合に「素の再ログイン」を勧めると、同名
   * ローテーションが**いま表示したトークン自体を失効させる**(PR #108
   * Bugbot 指摘)。
   */
  readonly tokenNameIsDefault: boolean;
  /** 明示 TTL(日。AUTH_SPEC §6 — W3a。省略時はサーバー既定の 90 日)。 */
  readonly expiresInDays?: number;
  /** ポーリング間隔の下限(秒。テストのみ短縮)。 */
  readonly minIntervalSeconds?: number;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const client = yield* makeApiClient({ baseUrl: input.origin });

    // 開始(§4-1 (1) — サーバーは無記録。フロー資格はここで得る 2 識別子のみ)
    const started = yield* client.authCli
      .cliStart({
        payload: {
          tokenName: input.tokenName,
          ...(input.expiresInDays === undefined ? {} : { expiresInDays: input.expiresInDays }),
        },
      })
      .pipe(Effect.mapError(toCliError));

    // verificationUrl / userCode はサーバー由来の外部文字列。制御文字・ANSI を
    // 生で端末へ流さない(displayText で中和)
    yield* io.log("Open this URL in your browser to approve the sign-in:");
    yield* io.log("");
    yield* io.log(`    ${displayText(started.verificationUrl)}`);
    yield* io.log("");
    yield* io.log(`Confirmation code: ${displayText(started.userCode)}`);
    yield* io.log(
      "Approve in the browser only if it shows this exact code (AUTH_SPEC's phishing guard)",
    );

    yield* maybeOpenBrowser(io, started.verificationUrl);
    yield* io.log("Waiting for approval\u2026");

    // 取得(§4-1 (5))。deadline は sleep の**前**に検査する(次のポーリング
    // 時刻が deadline を越えるならフローは待っている間に失効する)
    const minInterval = input.minIntervalSeconds ?? MIN_CLI_POLL_INTERVAL_SECONDS;
    const deadlineMs = Date.now() + clampExpires(started.expiresInSeconds) * 1000;
    const initialInterval = clampInterval(started.pollIntervalSeconds, minInterval);
    const poll = (
      intervalSeconds: number,
    ): Effect.Effect<Extract<PollOutcome, { readonly kind: "approved" }>, CliError> =>
      Effect.gen(function* () {
        if (Date.now() + intervalSeconds * 1000 > deadlineMs) {
          return yield* Effect.fail(cliError(FLOW_EXPIRED_MESSAGE));
        }
        yield* Effect.sleep(Duration.seconds(intervalSeconds));
        const outcome = yield* pollOnce(client, started.flowId, started.flowToken);
        if (outcome.kind === "approved") {
          return outcome;
        }
        if (outcome.kind === "backoff") {
          return yield* poll(clampInterval(outcome.retryAfterSeconds, intervalSeconds));
        }
        return yield* poll(intervalSeconds);
      });
    const approved = yield* poll(initialInterval);

    const issuedToken = Redacted.make(approved.token, { label: "maruhi-token" });
    const record: StoredToken = {
      token: issuedToken,
      userId: approved.userId,
      tokenId: approved.tokenId,
      // 期限接近の事前警告(裁定 CL)のローカル判定材料
      expiresAtMs: approved.expiresAtMs,
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
      `Logged in (user: ${displayText(approved.userId)}). The token is stored in the OS keychain`,
    );
    if (input.showToken) {
      // 生値の唯一の表示点(AUTH_SPEC §6「発行時の端末表示 1 箇所」— 裁定 CK)。
      // 剥がすのはこの表示のためだけで、値は保存済み(上のキーチェーン)以外へ
      // 流れない。呼び出し側の値表示ゲート(fail-closed 2 層)通過が前提で、
      // 対話端末以外(パイプ・CI・エージェント)ではここへ到達しない。
      // token はワイヤ上無制約の Schema.String(サーバーが全バイトを選べる)
      // なので中和して出す — ただしコピーする値なので displayText(U+FFFD への
      // 破壊的置換)でなく escapeText(allow-list — 正直な Base62 値は素通し、
      // 注入は可視のエスケープ列になる)を使う(PR #108 pullfrog 指摘)
      yield* io.log("");
      yield* io.log(`    ${escapeText(Redacted.value(issuedToken))}`);
      yield* io.log("");
      yield* io.log(
        "This value is not shown again (re-login rotates it). To use it on a runtime without lease support, set MARUHI_TOKEN to this value and MARUHI_TOKEN_ORIGIN to the server origin, and clear your terminal scrollback afterwards",
      );
      // 供給ログインの身元スワップの可視化(裁定 CM): キーチェーンのスロットは
      // origin 単位なので、この発行はこの端末のアクティブトークンも置き換えた。
      // 復し方は発行名で分岐する(PR #108 Bugbot 指摘): 既定名で発行した場合に
      // 「素の再ログイン」を勧めると、同名ローテーションが**いま表示した
      // トークン自体を失効させ**、貼り付け先の環境を切断する。既定名なら
      // 「別名で発行し直す」が正しい復し方
      yield* io.log(
        input.tokenNameIsDefault
          ? "Note: this token was issued under this machine's default token name and is now the active keychain token. If it is destined for another environment, issue it under a distinct name instead (`maruhi login --token-name <name> --show-token`) — a later plain `maruhi login` on this machine rotates the default-name token and would cut that environment off"
          : "Note: this token is now also this machine's active keychain token. If it is destined for another environment, run a plain `maruhi login` afterwards so this machine keeps a token of its own (the provisioned token is untouched — it has a different name) — sharing one token across environments muddles audit attribution, and revoking it cuts off both",
      );
    }
    // 有効期限は発行時に固定される(AUTH_SPEC §6 の既定 TTL — W3a)。期限が
    // 来ると 401 になるため、いつ再ログインが要るかを発行時点で可視にする。
    // 表示は display.ts の total フォーマッタ経由(サーバー申告の無制限 number を
    // Date#toISOString へ直接渡さない — deepsec B1/B4/B5 と同じ規律)
    yield* io.log(
      `The token expires on ${formatUtcDate(approved.expiresAtMs)} (UTC). Re-login (\`maruhi login\`) rotates it`,
    );
    yield* io.log(
      `Re-logging in with the same token name (${input.tokenName}) revokes the old token`,
    );
    yield* nextStepHint(input.origin, approved.userId, issuedToken);
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
