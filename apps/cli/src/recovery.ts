// リカバリーコードの発行・再発行・開封(CRYPTO_SPEC §8 / AUTH_SPEC §13)。
//
// - リカバリーコード(256-bit)はプロセスメモリと表示にのみ存在し、ディスク・
//   キーチェーン・ログへ書かない(コードの保管はユーザーの責務)
// - ラップ対象 B = **予備鍵**のレコード(2026-09-19 DK — 旧: master 鍵)の JSON 直列化
//   (CRYPTO_SPEC §8 の「直列化形式は CLI 実装時に確定」の確定点。端末鍵と同じ形)。
//   開封側は importMasterKeys の自己検証を通してから、**端末鍵の発行にだけ用いる**
//   (§8.1 — 保存はしない。復元の後段は key-recover.ts)
// - コードの表示・入力は鍵素材を端末へ通すため、stdin / stdout / stderr の
//   全てが TTY の人間環境だけ許可する(既知 AI agent は二次層でも拒否)
// - 保存確認(ROADMAP の紛失対策 UX): 表示したコードの最終グループを再入力
//   させてから完了とする。確認前にサーバー登録を済ませる — 確認に失敗しても
//   再発行(`maruhi key recovery`)でやり直せる状態を先に作る

import {
  decodeHex,
  encodeHex,
  generateRecoverySecret,
  SUITE_ID,
  unwrapMasterSecret,
  wrapMasterSecret,
} from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { escapeText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import {
  classifyUnreadableMasterKey,
  declaredSuiteOf,
  hasRedactedPlaceholder,
  parseStoredMasterKey,
  placeholderCause,
  serializeStoredMasterKey,
  type StoredMasterKey,
} from "./keychain.ts";
import { logNote } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { formatRecoveryCode, parseRecoveryCode } from "./recovery-code.ts";
import { generateReserveKeys, recordReserveLocally } from "./reserve.ts";
import {
  type CliSession,
  cryptoBackendUsable,
  type MasterKeyImportError,
  retryOnSupportedRuntime,
  unsupportedCryptoCause,
} from "./session.ts";

/** 保存確認・コード入力の再試行回数(タイプミスの救済。超過は明示エラー)。 */
const PROMPT_ATTEMPTS = 3;

const agentRefusalMessage =
  "Refused to issue a recovery code because an AI agent environment was detected (the code is key material; it may only be shown on a human interactive terminal)";

function ensureRecoveryCodeInteractionAllowed(
  io: CliIoShape,
  action: "issue" | "read",
): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      action === "issue"
        ? agentRefusalMessage
        : "Refused to read a recovery code because an AI agent environment was detected (the code is key material; run the recovery on a human interactive terminal)",
    terminalError: `Recovery-code ${action === "issue" ? "display" : "entry"} is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
  });
}

/**
 * Issues (or reissues) the recovery code for the reserve key `record`:
 * generate → wrap → register → display → save confirmation. `maruhi key
 * generate`(初回封印)/ `maruhi key recovery`(再発行・分離)/ `maruhi key reserve
 * rotate` の共通本体。`record` は予備鍵のレコード(reserve.ts)— 端末鍵を渡す経路は無い。
 */
export function issueRecoveryCodeOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly record: StoredMasterKey;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureRecoveryCodeInteractionAllowed(io, "issue");

    // 既登録の置換(再発行)は事前に明示する(旧コードはこの操作で無効になる)
    const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
    if (status.registered) {
      yield* io.logError(
        "Replacing the existing recovery registration (previous recovery codes become invalid)",
      );
    }

    const secret = Redacted.make(generateRecoverySecret(), { label: "recovery-secret" });
    // JSON.stringify(record) は使わない — 秘密側が伏字のままラップされ、
    // 「復元できたのに鍵が使えない」リカバリーブロブを登録してしまう
    // (キーチェーン保存と同じ罠。keychain.ts の注記)
    const blob = new TextEncoder().encode(serializeStoredMasterKey(input.record));
    const wrapped = yield* Effect.tryPromise({
      try: () =>
        wrapMasterSecret({
          // 剥がす理由: リカバリーラップの鍵導出入力(暗号境界)
          recoverySecret: Redacted.value(secret),
          userId: input.session.userId,
          masterSecretBlob: blob,
        }),
      catch: () => cliError("Failed to encrypt the recovery blob (crypto error)"),
    });
    if (!wrapped.ok) {
      return yield* Effect.fail(cliError("Failed to create the recovery wrap"));
    }
    yield* input.client.auth
      .recoveryPut({
        payload: {
          suite: SUITE_ID,
          nonceHex: encodeHex(wrapped.value.nonce),
          ciphertextHex: encodeHex(wrapped.value.ciphertext),
        },
      })
      .pipe(Effect.mapError(toCliError));

    // コードの表示ブロックは丸ごと stderr へ(プロンプトと同じチャネル)。
    // stdout はリダイレクト・パイプされうる: コードは鍵素材であり、
    // `maruhi key generate > log` で平文ファイルに残る経路を作らない。
    // stderr なら確認プロンプトと同じ画面に出て、確認の儀式も成立する
    const code = formatRecoveryCode(secret);
    yield* io.logError("");
    yield* io.logError("Issued your recovery code. Store it somewhere safe now:");
    yield* io.logError("");
    // 剥がす理由: コードの表示が発行の機能そのもの(二度と表示されない)。
    // 表示可否はこの関数の冒頭の TTY + agent ゲートで判定済みで、剥がすのは
    // その後ろ。stderr 自体も TTY であることを確認済み
    yield* io.logError(`    ${Redacted.value(code)}`);
    yield* io.logError("");
    yield* io.logError(
      "Recommended: print it or save it in a password manager. This code will never be shown again",
    );
    yield* io.logError(
      "With this code plus your account sign-in, you can restore your reserve key on a machine that has no device key and register that machine as a new device (`maruhi key recover`)",
    );
    yield* confirmCodeSaved(code);
    yield* io.logError("Save confirmation complete");
  });
}

/** 表示したコードの最終グループの再入力で保存を確認する(紛失対策 UX)。 */
function confirmCodeSaved(code: Redacted.Redacted<string>): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 剥がす理由: 最終グループの照合材料。既に表示済みのコードであり、
    // ここで取り出す部分文字列は出力せず比較にしか使わない
    const groups = Redacted.value(code).split("-");
    const last = groups[groups.length - 1] ?? "";
    for (let attempt = 1; attempt <= PROMPT_ATTEMPTS; attempt += 1) {
      const answer = yield* io.promptLine({
        prompt: `To confirm you saved the code, enter its last group (group ${groups.length}, 4 characters): `,
      });
      if (answer.trim().toUpperCase() === last) {
        return;
      }
      yield* io.logError("It does not match. Check the code shown above");
    }
    return yield* Effect.fail(
      cliError(
        "Save confirmation failed. The recovery registration itself is complete — store the code shown above, or reissue it with `maruhi key recovery`",
      ),
    );
  });
}

/**
 * Opens the recovery blob with a prompted recovery code and returns the reserve
 * key record (memory only — nothing is stored). `maruhi key recover`(復元の
 * 前段)と台帳変更の開封(ledger-open.ts — `key recovery` / `key seal passkey` /
 * `guardian add` / `key reserve rotate`)が共有する。復元の後段(新端末鍵の発行 →
 * `add_device` → 予備鍵の破棄)は key-recover.ts。
 */
export function unwrapRecoveryBlobWithCode(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<StoredMasterKey, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 発行側と対称の線引き: コードは鍵素材であり、エージェント越しの stdin に
    // 打ち込ませる経路も作らない(入力はエージェントのセッション層から読める)。
    // 開封は人間の対話端末で行う
    yield* ensureRecoveryCodeInteractionAllowed(io, "read");

    const wrap = yield* input.client.auth.recoveryGet({}).pipe(
      Effect.catchTag("RecoveryWrapNotFound", () =>
        Effect.fail(
          cliError(
            "No recovery code is registered for your account. Run `maruhi key recovery` on a device that is registered, or restore with `maruhi key recover --passkey` / `--handoff`",
          ),
        ),
      ),
      Effect.catchTag("RecoveryRateLimited", (error) =>
        Effect.fail(
          cliError(
            `The recovery-blob fetch limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
    const nonce = decodeHex(wrap.nonceHex);
    const ciphertext = decodeHex(wrap.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(cliError("The server response is malformed (cannot decode hex)"));
    }

    // コード入力 → 復号はローカル再試行(取得レート制限の窓を消費しない)
    return yield* unwrapWithPromptedCode({
      nonce,
      ciphertext,
      userId: input.session.userId,
    });
  });
}

/** 再登録の手順そのもの(どの原因でも同じ)。 */
const reRegisterAction =
  "seal a new reserve key by running `maruhi key recovery --replace` on a device of yours that is registered (it does not open the ledger; the reserve keys recorded on that machine are revoked).";

/**
 * ブロブが使えないときの共通の出口(このデバイスでは直せない)。
 *
 * 「このコードでは復元できません」は**破損・伏字の場合にだけ真**。未知スイートの
 * ブロブは更新すれば同じコードで復元できるので、この文言を付けてはいけない
 * (付けると、使えるコードを捨てさせる)。
 */
const reRegisterGuidance = `This code cannot restore the key — ${reRegisterAction}`;

/**
 * 開封したブロブが鍵素材として読み込めない({@link importMasterKeys} の失敗)ときの
 * 写し(key-recover.ts / ledger-open.ts が使う)。未知スイート(より新しい maruhi が
 * 別デバイスで登録した)は破損ではない。残る 2 つを区別する: 環境が非対応なら
 * ブロブもコードも無事(**捨てさせない**)、そうでなければ本当に壊れている(再登録が要る)。
 */
export function mapUnloadableRecoveryBlob<A, R>(
  effect: Effect.Effect<A, MasterKeyImportError, R>,
): Effect.Effect<A, CliError, R> {
  return effect.pipe(
    Effect.catchTag("MasterKeyUnknownSuite", (error) =>
      Effect.fail(cliError(foreignRecoveryBlobMessage(error.suite))),
    ),
    Effect.catchTag("MasterKeyCorrupt", () =>
      Effect.flatMap(cryptoBackendUsable(), (usable) =>
        Effect.fail(cliError(usable ? brokenRecoveryBlobMessage : unsupportedCryptoOnRecover)),
      ),
    ),
  );
}

/**
 * 環境が非対応のときの文言(この経路版)。
 *
 * この経路は ensureNoStoredMasterKey を通っており、このデバイスに鍵は無い —
 * 「保存されている鍵を消さないでください」は指す物が無い。代わりに**無事な物**
 * (コードとブロブ)を名指しする: 書かないと、失敗をコードのせいだと思って
 * 唯一の復元手段を捨てられる。
 */
const unsupportedCryptoOnRecover =
  `${unsupportedCryptoCause}. The recovery code you entered and the registered blob are intact — do not discard them. ${retryOnSupportedRuntime}` as const;

/**
 * ブロブは解釈できたが鍵素材が読み込めないときの文言。
 *
 * **原因を「壊れている」と断定しない**: このフォークは形が現行と同じブロブ
 * (= parse を通ったもの)しか来ないため、「本当に壊れている」のと「スイートを
 * 変えずに符号化だけ変えた将来版が書いた」のを**観測では区別できない**
 * (suite は暗号スイートの識別子であって保存形式の版ではない — keychain.ts の
 * 注記と同じ理由)。断定して `reRegisterGuidance`(「このコードでは復元できません」)を
 * 付けると、別デバイスでの再登録で**使えるコードを失効させてしまう**。
 * 先に更新を促し、再登録はその後の手段として置く。
 */
const brokenRecoveryBlobMessage =
  `Cannot load the key material in the registered recovery blob (the record is corrupt, or in a format this version does not know). First update maruhi to the latest version and re-run (the recovery code you just entered may still work — do not discard it). If updating does not fix it, ${reRegisterAction}` as const;

/**
 * ブロブが現行版の知らないスイートで書かれていたときの文言。
 *
 * キーチェーンのレコードと違い**消すものは無い**(ブロブはサーバー側にあり、
 * このデバイスに鍵は保存されていない)ので、削除の警告は要らない。スイート名は
 * ブロブ由来の自由文字列なので、端末へ出す前にエスケープする。
 */
function foreignRecoveryBlobMessage(suite: string | null): string {
  const named = suite === null ? "" : ` (${escapeText(suite)})`;
  return `The registered recovery blob cannot be read by this version${named}. It may have been written by a newer maruhi — update maruhi to the latest version and re-run (the recovery code you just entered still works — do not discard it). If you cannot update, ${reRegisterAction}`;
}

/**
 * 復号済みブロブの解釈。**平文の鍵素材(hex)を持つ文字列をこの関数の外へ
 * 出さない**ために切り出してある: 呼び出し側にはレコードと真偽値しか渡らず、
 * エラーメッセージの組み立てから物理的に届かない(この経路は master 秘密鍵が
 * 素の文字列として現れる唯一の場所)。
 */
function readRecoveryBlob(bytes: Uint8Array): {
  readonly record: StoredMasterKey | null;
  readonly placeholder: boolean;
  /** 解釈できなかったときの分類(キーチェーン側と同じ規準)。 */
  readonly classification: "corrupt" | "foreign";
  /** 解釈できなかったブロブが名乗るスイート(名乗らなければ null)。 */
  readonly declaredSuite: string | null;
} {
  const blob = new TextDecoder().decode(bytes);
  // 分類とスイートの取り出しも**この関数の中で**行う: どちらもブロブの生文字列を
  // 要るため、外へ出すと平文の鍵素材を持つ文字列が呼び出し側へ漏れる
  return {
    record: parseStoredMasterKey(blob),
    placeholder: hasRedactedPlaceholder(blob),
    classification: classifyUnreadableMasterKey(blob),
    declaredSuite: declaredSuiteOf(blob),
  };
}

function unwrapWithPromptedCode(input: {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly userId: string;
}): Effect.Effect<StoredMasterKey, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (let attempt = 1; attempt <= PROMPT_ATTEMPTS; attempt += 1) {
      // 入力されたコードは鍵素材そのもの。**入口で包む**(素の string のまま
      // 置くと、同じブロックにある logError へ 1 行で載せられてしまい、
      // 剥がす箇所の棚卸しにも現れない)。剥がすのは解釈の直前だけ
      const answer = Redacted.make(
        yield* io.promptLine({
          prompt: "Enter your recovery code: ",
          secret: true,
        }),
        { label: "recovery-code" },
      );
      const secret = parseRecoveryCode(Redacted.value(answer));
      if (secret === null) {
        yield* io.logError(
          "The code is malformed (13 groups of 4 characters; hyphens, spaces, and letter case are ignored)",
        );
        continue;
      }
      const unwrapped = yield* Effect.tryPromise({
        try: () =>
          unwrapMasterSecret({
            // 剥がす理由: リカバリーブロブ復号の鍵導出入力(暗号境界)
            recoverySecret: Redacted.value(secret),
            userId: input.userId,
            wrapped: { nonce: input.nonce, ciphertext: input.ciphertext },
          }),
        catch: () => cliError("Failed to decrypt the recovery blob (crypto error)"),
      });
      if (!unwrapped.ok) {
        yield* io.logError("Cannot decrypt. Check that the code is correct");
        continue;
      }
      const parsed = readRecoveryBlob(unwrapped.value);
      const record = parsed.record;
      if (record === null) {
        // 復号は成功したのに中身が壊れている = 登録時のブロブが不正(コードの
        // 誤りではないので再入力させない)。伏字保存はここでも区別する:
        // ブロブは serializeStoredMasterKey の 3 つ目のシンクであり、同じ
        // 剥がし忘れが届きうる。しかも `maruhi key recovery` での再登録は
        // master 鍵の読み込み(= 復元済みであること)を要するため、鍵を失った
        // デバイスでは実行できない — 案内としても成立しない
        return yield* Effect.fail(
          cliError(
            parsed.placeholder
              ? // 壊れているのは**サーバー登録済みのブロブ**であってキーチェーンの
                // レコードではない(この経路は ensureNoStoredMasterKey を通って
                // いるので、キーチェーンに master 鍵は存在しない)
                `${placeholderCause("The registered recovery blob")}. ${reRegisterGuidance} Also report this as a maruhi bug`
              : // 形が違うだけかもしれない(将来版が書いたブロブ)。キーチェーン側と
                // 同じ分類を使い、破損と言い切れないものには更新を先に案内する。
                // 破損側でも再登録は**鍵が残っている別のデバイス**でしか実行
                // できない(このデバイスには鍵が無い)ので、その断りを落とさない
                parsed.classification === "foreign"
                ? foreignRecoveryBlobMessage(parsed.declaredSuite)
                : `Cannot interpret the decrypted blob as a key record. ${reRegisterGuidance}`,
          ),
        );
      }
      return record;
    }
    return yield* Effect.fail(
      cliError("Recovery-code entry failed repeatedly. Check the code and re-run"),
    );
  });
}

/**
 * `maruhi key generate` の後段: 予備鍵の生成と初回封印(K4-2 — 予備鍵は最初の台帳封印で
 * 生まれる)。順序は封印 → ローカル記録(→ チェーン登録は次の同期 — K4-1 の反例 1)。
 * エージェント環境では封印(儀式)そのものをスキップし(拒否ではなく案内)、端末鍵の
 * 生成は成立させる。予備鍵は後日の `maruhi key recovery` が作る。
 */
export function issueRecoveryAfterKeygen(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      yield* io.log(
        "Skipped creating the reserve key and its recovery code because this is an AI agent environment. Run `maruhi key recovery` on a human interactive terminal (until then you have no reserve key: losing this device means losing access)",
      );
      return;
    }
    yield* sealNewReserve(input).pipe(
      Effect.mapError((error) =>
        cliError(
          `${error.message} (the device key generation itself is complete; create the reserve key later with \`maruhi key recovery\`)`,
        ),
      ),
    );
  });
}

/**
 * Generates a reserve key, seals it with a fresh recovery code and records its
 * public side locally (K4-1 の順序: 封印 → 記録。チェーン登録は次の同期)。
 */
export function sealNewReserve(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore> {
  return Effect.gen(function* () {
    const reserve = yield* generateReserveKeys();
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: reserve.record,
    });
    yield* recordReserveLocally(input.session, reserve);
    yield* logNote(
      `created your reserve key (fingerprint ${reserve.fingerprintHex}). It lives only in the recovery ledger; it is registered on each project the next time this device syncs it`,
    );
  });
}
