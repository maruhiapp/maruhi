// パスキー PRF 経路(CRYPTO_SPEC §8.2 / AUTH_SPEC §13-7 — KL3 K5)。
//
// 登録 `maruhi key seal passkey`: CLI が配る localhost ページ(passkey-page.ts /
// passkey-listener.ts)でパスキーを作り、その PRF 出力から KEK を導き、master 鍵ブロブ B
// をラップして台帳へ登録する。台帳への書き込みは全材料が揃った**最後の 1 回**だけ
// (途中失敗で半端な行を残さない — 補足 20 裁定 I)。
//
// 復元 `maruhi key recover --passkey`: 台帳のラップを取り、同じパスキーの PRF で KEK を
// 再導出して B を復号し、自己検証を通してキーチェーン(`maruhi agent` の中なら agent の
// メモリ)へ保存する。
//
// 儀式(登録・復元・削除)は人間の対話端末でのみ行い、AI エージェント環境では拒否する
// (ADR-0016 決定 7 の既存ゲート)。リスナーはゲートの後でしか立たない。PRF 出力・KEK・B の
// 平文は関数ローカルにのみ存在し、ログ・エラー・DOM に出ない。
//
// 台帳の状態(`GET /auth/key-wraps`)は passkey 行の prf_salt を運ばないため、復元では
// 儀式の前に当該行のラップ(`GET /auth/key-wraps/passkey/:wrapId` — 合算窓 5 回 / 時)を
// 1 件だけ取る。複数登録があるときは利用者に番号で選ばせる(全件を取ると窓と要監視の
// 監査事件を無駄に消費する — 補足 20 実装録)。

import { MAX_PASSKEY_WRAPS_PER_USER } from "@maruhi/api-schema";
import { decodeHex, derivePasskeyKek, encodeHex, unwrapMasterBlob } from "@maruhi/crypto";
import { Duration, Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { Keychain, parseStoredMasterKey, serializeStoredMasterKey } from "./keychain.ts";
import { newLedgerId, wrapOwnBlob } from "./master-ops.ts";
import { logNote } from "./notice.ts";
import { type PrfListener, startPrfListener } from "./passkey-listener.ts";
import type { PrfPageConfig, PrfPageErrorCode } from "./passkey-page.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  importMasterKeys,
  loadMasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";

/** 儀式の待ち時間の上限(ブラウザ起動 + 生体認証に十分。放置端末で聞き続けない)。 */
const CEREMONY_TIMEOUT = Duration.minutes(5);
const PRF_SALT_BYTES = 32;
const USER_HANDLE_BYTES = 16;

type CeremonyAction = "register" | "recover" | "remove";

function ensurePasskeyCeremonyAllowed(
  io: CliIoShape,
  action: CeremonyAction,
): Effect.Effect<void, CliError, Stdio.Stdio> {
  const agentError =
    action === "recover"
      ? "Refused to restore the master key with a passkey because an AI agent environment was detected (the restored key would land in the agent's session; run this yourself on a human interactive terminal)"
      : action === "register"
        ? "Refused to seal the master key to a passkey because an AI agent environment was detected (sealing is a key ceremony; run this yourself on a human interactive terminal)"
        : "Refused to remove a passkey wrap because an AI agent environment was detected (this changes how your key can be recovered; run this yourself on a human interactive terminal)";
  const noun =
    action === "recover"
      ? "Passkey recovery"
      : action === "register"
        ? "Passkey sealing"
        : "Passkey wrap removal";
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError,
    terminalError: `${noun} is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
  });
}

/** ページの理由コード → 利用者への案内(自由文はページから受け取らない)。 */
function ceremonyFailure(code: PrfPageErrorCode, action: "register" | "recover"): CliError {
  switch (code) {
    case "not-allowed":
      return cliError(
        action === "register"
          ? "The passkey was not created (the browser prompt was cancelled, timed out, or the authenticator refused). Nothing was registered — re-run to try again"
          : "The passkey was not used (the browser prompt was cancelled, timed out, or no registered passkey is available on this device). Nothing was changed — re-run to try again",
      );
    case "already-registered":
      return cliError(
        "This authenticator already holds a passkey that is registered for your account. Remove that wrap first with `maruhi key seal remove <wrap-id>` (see `maruhi key seal list`), or use another authenticator",
      );
    case "prf-unsupported":
      return cliError(
        "This browser or authenticator does not support the WebAuthn PRF extension with user verification, so it cannot seal or restore the key. Try another browser or authenticator",
      );
    case "unexpected":
      return cliError(
        "The passkey step failed in the browser (unexpected error). Nothing was changed — re-run, or try another browser",
      );
  }
}

/** URL の表示とブラウザの自動起動(login と同じ 1 本の縮退経路)。 */
function announceListener(io: CliIoShape, listener: PrfListener): Effect.Effect<void> {
  return Effect.gen(function* () {
    yield* io.logError("");
    yield* io.logError("Open this page in your browser to continue with your passkey:");
    yield* io.logError("");
    yield* io.logError(`    ${listener.url}`);
    yield* io.logError("");
    yield* io.logError(
      `If this terminal runs on a remote machine (SSH, a dev container, Codespaces), forward port ${listener.port} to your local machine first and open the URL there`,
    );
    const opened = yield* io.openBrowser(listener.url);
    yield* io.logError(
      opened
        ? "Opened your browser. If nothing appeared, open the URL above manually (waiting up to 5 minutes; press Ctrl+C to cancel)"
        : "Could not open a browser automatically. Open the URL above manually (waiting up to 5 minutes; press Ctrl+C to cancel)",
    );
  });
}

/** 儀式の結果(ページの 1 POST)。 */
interface PrfOutcome {
  readonly credentialIdHex: string;
  readonly prf: Uint8Array;
}

/**
 * リスナーを立て、ページの 1 POST を待ち、必ず閉じる。トークンはリスナーと同寿命。
 * PRF 出力はここから返る値としてだけ存在する。
 */
function runPrfCeremony(
  config: PrfPageConfig,
  action: "register" | "recover",
): Effect.Effect<PrfOutcome, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    return yield* Effect.acquireUseRelease(
      Effect.tryPromise({
        try: () => startPrfListener(config),
        catch: () =>
          cliError(
            "Cannot listen on 127.0.0.1 for the passkey page (no free local port, or loopback networking is unavailable)",
          ),
      }),
      (listener) =>
        Effect.gen(function* () {
          yield* announceListener(io, listener);
          const post = yield* Effect.promise(() => listener.outcome).pipe(
            Effect.timeout(CEREMONY_TIMEOUT),
            Effect.catchTag("TimeoutError", () =>
              Effect.fail(
                cliError(
                  "Timed out waiting for the passkey page (5 minutes). Nothing was changed — re-run to try again",
                ),
              ),
            ),
          );
          if ("error" in post) {
            return yield* Effect.fail(ceremonyFailure(post.error, action));
          }
          const prf = decodeHex(post.prfHex);
          if (prf === null) {
            return yield* Effect.fail(cliError("The passkey page sent a malformed PRF value"));
          }
          return { credentialIdHex: post.credentialIdHex, prf };
        }),
      (listener) => Effect.promise(() => listener.close()),
    );
  });
}

function deriveKek(prf: Uint8Array): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
    const kek = yield* Effect.tryPromise({
      try: () => derivePasskeyKek(prf),
      catch: () => cliError("Failed to derive the wrapping key from the passkey (crypto error)"),
    });
    if (!kek.ok) {
      return yield* Effect.fail(
        cliError(
          "The passkey returned a PRF value of the wrong size, so no wrapping key can be derived",
        ),
      );
    }
    return kek.value;
  });
}

/** 台帳の passkey 行(status の写し)。 */
interface PasskeyRow {
  readonly wrapId: string;
  readonly label: string | null;
  readonly credentialIdHex: string;
  readonly updatedAtMs: number;
}

function fetchPasskeyRows(
  client: MaruhiClient,
): Effect.Effect<readonly PasskeyRow[], CliError, HttpClient.HttpClient> {
  return client.keyWraps.status({}).pipe(
    Effect.map((status) => status.passkeys),
    Effect.mapError(toCliError),
  );
}

function describeRow(row: PasskeyRow): string {
  const label = row.label === null ? "(no label)" : displayText(row.label);
  return `${row.wrapId}  ${label}  credential ${row.credentialIdHex.slice(0, 16)}…  ${formatUtcMinutes(row.updatedAtMs)}`;
}

/** `maruhi key seal passkey [--label]`: seal the master key to a new passkey. */
export function sealPasskeyOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly label?: string | undefined;
}): Effect.Effect<void, CliError, Keychain | CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensurePasskeyCeremonyAllowed(io, "register");
    const masterKeys = yield* loadMasterKeys(input.session);
    const rows = yield* fetchPasskeyRows(input.client);
    if (rows.length >= MAX_PASSKEY_WRAPS_PER_USER) {
      return yield* Effect.fail(
        cliError(
          `You already have ${MAX_PASSKEY_WRAPS_PER_USER} passkeys registered (the limit). Remove one with \`maruhi key seal remove <wrap-id>\` first (see \`maruhi key seal list\`)`,
        ),
      );
    }
    // wrap_id は AAD が束縛するので暗号化の前に採番する。prf_salt は登録ごとの乱数
    // (公開パラメータ)。user handle も登録ごとの乱数(裁定 G)
    const wrapId = newLedgerId();
    const prfSaltHex = encodeHex(crypto.getRandomValues(new Uint8Array(PRF_SALT_BYTES)));
    const outcome = yield* runPrfCeremony(
      {
        mode: "register",
        rpId: "localhost",
        userName: `maruhi · ${new URL(input.session.origin).host}`,
        userIdHex: encodeHex(crypto.getRandomValues(new Uint8Array(USER_HANDLE_BYTES))),
        prfSaltHex,
        excludeCredentialIdsHex: rows.map((row) => row.credentialIdHex),
      },
      "register",
    );
    const kek = yield* deriveKek(outcome.prf);
    const wrapped = yield* wrapOwnBlob({
      masterKeys,
      kek,
      context: { userId: input.session.userId, kind: "passkey-prf", wrapRef: wrapId },
    });
    yield* input.client.keyWraps
      .passkeyRegister({
        payload: {
          wrapId,
          wrap: {
            suite: "maruhi/v1",
            nonceHex: encodeHex(wrapped.nonce),
            ciphertextHex: encodeHex(wrapped.ciphertext),
          },
          credentialIdHex: outcome.credentialIdHex,
          prfSaltHex,
          rpId: "localhost",
          ...(input.label === undefined ? {} : { label: input.label }),
        },
      })
      .pipe(
        Effect.catchTag("KeyWrapPolicy", (error) =>
          Effect.fail(
            error.reason === "too-many-passkeys"
              ? cliError(
                  `The server refused the registration: the passkey limit (${MAX_PASSKEY_WRAPS_PER_USER}) is reached. Remove one with \`maruhi key seal remove <wrap-id>\` first`,
                )
              : cliError(
                  `The server refused the registration (${error.reason}). Re-run to try again`,
                ),
          ),
        ),
        Effect.mapError(toCliError),
      );
    yield* io.log(`Sealed the master key to a passkey (wrap ${wrapId})`);
    yield* io.log(`key fingerprint: ${masterKeys.fingerprintHex}`);
    yield* logNote(
      "restore it on another device with `maruhi key recover --passkey`. If you delete the passkey from your authenticator, remove this wrap with `maruhi key seal remove` too",
    );
  });
}

/** 復元に使う passkey 行を選ぶ(1 件なら自動、複数なら番号で選ばせる)。 */
function choosePasskeyRow(
  io: CliIoShape,
  rows: readonly PasskeyRow[],
): Effect.Effect<PasskeyRow, CliError> {
  return Effect.gen(function* () {
    const first = rows[0];
    if (first === undefined) {
      return yield* Effect.fail(
        cliError(
          "No passkey is registered for your account. Run `maruhi key seal passkey` on a device that still has the master key, or restore with `maruhi key recover` (recovery code) or `maruhi key recover --handoff`",
        ),
      );
    }
    if (rows.length === 1) {
      return first;
    }
    yield* io.logError("Registered passkeys:");
    for (const [index, row] of rows.entries()) {
      yield* io.logError(`  ${index + 1}. ${describeRow(row)}`);
    }
    const answer = yield* io.promptLine({
      prompt: `Which passkey will you use? [1-${rows.length}]: `,
    });
    const chosen = /^\d+$/.test(answer.trim()) ? rows[Number(answer.trim()) - 1] : undefined;
    if (chosen === undefined) {
      return yield* Effect.fail(
        cliError("The passkey recovery was cancelled (nothing was changed)"),
      );
    }
    return chosen;
  });
}

/** 選んだ行のラップを取る(合算窓を 1 回消費する — 要監視の監査事件)。 */
function fetchWrap(
  client: MaruhiClient,
  wrapId: string,
): Effect.Effect<
  {
    readonly prfSaltHex: string;
    readonly credentialIdHex: string;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
  },
  CliError,
  HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const wrap = yield* client.keyWraps.passkeyGet({ params: { wrapId } }).pipe(
      Effect.catchTag("KeyWrapNotFound", () =>
        Effect.fail(
          cliError(
            "That passkey wrap no longer exists on the server (it was removed meanwhile). Run `maruhi key seal list` to see what is registered",
          ),
        ),
      ),
      Effect.catchTag("KeyWrapRateLimited", (error) =>
        Effect.fail(
          cliError(
            `The key-wrap fetch limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
    const nonce = decodeHex(wrap.wrap.nonceHex);
    const ciphertext = decodeHex(wrap.wrap.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(cliError("The server response is malformed (cannot decode hex)"));
    }
    return {
      prfSaltHex: wrap.prfSaltHex,
      credentialIdHex: wrap.credentialIdHex,
      nonce,
      ciphertext,
    };
  });
}

/** `maruhi key recover --passkey`: restore the master key with a registered passkey. */
export function recoverWithPasskeyOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensurePasskeyCeremonyAllowed(io, "recover");
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "A master key already exists on this device. Overwriting it would lose the existing key, so this is refused (check it with `maruhi key show`)",
    );
    const row = yield* choosePasskeyRow(io, yield* fetchPasskeyRows(input.client));
    const wrap = yield* fetchWrap(input.client, row.wrapId);
    const outcome = yield* runPrfCeremony(
      {
        mode: "recover",
        rpId: "localhost",
        credentials: [{ credentialIdHex: wrap.credentialIdHex, prfSaltHex: wrap.prfSaltHex }],
      },
      "recover",
    );
    if (outcome.credentialIdHex !== wrap.credentialIdHex) {
      return yield* Effect.fail(
        cliError(
          "The browser used a different passkey than the one whose wrap was fetched, so the key cannot be restored. Re-run and choose the matching passkey",
        ),
      );
    }
    const kek = yield* deriveKek(outcome.prf);
    const unwrapped = yield* Effect.tryPromise({
      try: () =>
        unwrapMasterBlob({
          kek,
          wrapped: { nonce: wrap.nonce, ciphertext: wrap.ciphertext },
          context: { userId: input.session.userId, kind: "passkey-prf", wrapRef: row.wrapId },
        }),
      catch: () => cliError("Failed to decrypt the wrapped master key (crypto error)"),
    });
    if (!unwrapped.ok) {
      return yield* Effect.fail(
        cliError(
          "Cannot decrypt the wrapped master key with this passkey. The passkey's PRF output does not match the registration (the wrap or its parameters were altered, or the passkey was re-created) — nothing was changed",
        ),
      );
    }
    const record = parseStoredMasterKey(new TextDecoder().decode(unwrapped.value));
    if (record === null) {
      return yield* Effect.fail(
        cliError(
          "The decrypted blob is not a master-key record. The device that registered this passkey holds a broken key record, or a newer maruhi wrote it — update maruhi, or restore another way",
        ),
      );
    }
    const validated = yield* importMasterKeys(record).pipe(
      Effect.mapError(() =>
        cliError(
          "The decrypted master-key record cannot be loaded (unknown suite or corrupt). Update maruhi, or restore another way",
        ),
      ),
    );
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Restored the master key via passkey",
      fingerprintHex: validated.fingerprintHex,
    });
  });
}

/** `maruhi key seal list`: list the passkey wraps in the ledger (public parameters only). */
export function listPasskeysOp(input: {
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rows = yield* fetchPasskeyRows(input.client);
    if (rows.length === 0) {
      yield* io.log("No passkeys are registered (seal your key with `maruhi key seal passkey`)");
      return;
    }
    for (const row of rows) {
      yield* io.log(describeRow(row));
    }
  });
}

/** `maruhi key seal remove <wrap-id>`: delete one passkey wrap from the ledger. */
export function removePasskeyOp(input: {
  readonly client: MaruhiClient;
  readonly wrapId: string;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensurePasskeyCeremonyAllowed(io, "remove");
    yield* input.client.keyWraps.passkeyDelete({ params: { wrapId: input.wrapId } }).pipe(
      Effect.catchTag("KeyWrapNotFound", () =>
        Effect.fail(
          cliError("No passkey wrap with that ID (list them with `maruhi key seal list`)"),
        ),
      ),
      Effect.mapError(toCliError),
    );
    yield* io.log(`Removed passkey wrap ${displayText(input.wrapId)}`);
    yield* logNote(
      "the passkey itself stays in your authenticator; delete it there if you no longer want it",
    );
  });
}
