// リカバリーコードの発行・再発行・復元(CRYPTO_SPEC §8 / AUTH_SPEC §13)。
//
// - リカバリーコード(256-bit)はプロセスメモリと表示にのみ存在し、ディスク・
//   キーチェーン・ログへ書かない(コードの保管はユーザーの責務)
// - ラップ対象の master 鍵ブロブ = キーチェーンの StoredMasterKey レコードの
//   JSON 直列化(CRYPTO_SPEC §8 の「直列化形式は CLI 実装時に確定」の確定点。
//   復元側は importMasterKeys の自己検証を通してから保存する)
// - コードの表示は鍵素材の表示なので、AI エージェント環境では拒否する
//   (agent.ts と同じ線引き)
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
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import {
  hasRedactedPlaceholder,
  Keychain,
  parseStoredMasterKey,
  placeholderCause,
  serializeStoredMasterKey,
  type StoredMasterKey,
} from "./keychain.ts";
import { formatRecoveryCode, parseRecoveryCode } from "./recovery-code.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
} from "./session.ts";

/** 保存確認・コード入力の再試行回数(タイプミスの救済。超過は明示エラー)。 */
const PROMPT_ATTEMPTS = 3;

const agentRefusalMessage =
  "AI エージェント環境を検出したため、リカバリーコードの発行を拒否しました(コードは鍵素材であり、表示は人間の対話端末に限ります)";

/**
 * Issues (or reissues) the recovery code: generate → wrap → register →
 * display → save confirmation. `maruhi key generate` と `maruhi key recovery`
 * の共通本体。
 */
export function issueRecoveryCodeOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(cliError(agentRefusalMessage));
    }

    // 既登録の置換(再発行)は事前に明示する(旧コードはこの操作で無効になる)
    const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
    if (status.registered) {
      yield* io.logError(
        "既存のリカバリー登録を置き換えます(これまでのリカバリーコードは無効になります)",
      );
    }

    const secret = Redacted.make(generateRecoverySecret(), { label: "recovery-secret" });
    // JSON.stringify(record) は使わない — 秘密側が伏字のままラップされ、
    // 「復元できたのに鍵が使えない」リカバリーブロブを登録してしまう
    // (キーチェーン保存と同じ罠。keychain.ts の注記)
    const blob = new TextEncoder().encode(serializeStoredMasterKey(input.masterKeys.record));
    const wrapped = yield* Effect.tryPromise({
      try: () =>
        wrapMasterSecret({
          // 剥がす理由: リカバリーラップの鍵導出入力(暗号境界)
          recoverySecret: Redacted.value(secret),
          userId: input.session.userId,
          masterSecretBlob: blob,
        }),
      catch: () => cliError("リカバリーブロブの暗号化に失敗しました(暗号処理エラー)"),
    });
    if (!wrapped.ok) {
      return yield* Effect.fail(cliError("リカバリーラップの作成に失敗しました"));
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
    yield* io.logError("リカバリーコードを発行しました。今すぐ安全な場所に保管してください:");
    yield* io.logError("");
    // 剥がす理由: コードの表示が発行の機能そのもの(二度と表示されない)。
    // 表示可否はこの関数の冒頭のエージェントゲートで判定済みで、剥がすのは
    // その後ろ。出力先が stderr であることも意図的に維持する(上の注記)
    yield* io.logError(`    ${Redacted.value(code)}`);
    yield* io.logError("");
    yield* io.logError(
      "推奨: 印刷またはパスワードマネージャへの保存。このコードは二度と表示されません",
    );
    yield* io.logError(
      "このコードと GitHub 認証で、鍵を失ったデバイスから master 鍵を復元できます(`maruhi key recover`)",
    );
    yield* confirmCodeSaved(code);
    yield* io.logError("保存確認が完了しました");
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
        prompt: `保存の確認のため、コードの最後のグループ(${groups.length} 番目の 4 文字)を入力してください: `,
      });
      if (answer.trim().toUpperCase() === last) {
        return;
      }
      yield* io.logError("一致しません。表示されたコードを確認してください");
    }
    return yield* Effect.fail(
      cliError(
        "保存確認に失敗しました。リカバリー登録自体は完了しています — 上に表示されたコードを保管し直すか、`maruhi key recovery` で再発行してください",
      ),
    );
  });
}

/**
 * `maruhi key recover`: 認証済みセッションでラップ済みブロブを取得し、
 * リカバリーコードの入力で復号して master 鍵をキーチェーンへ復元する
 * (CRYPTO_SPEC §8 のデバイス追加・鍵喪失フロー)。
 */
export function recoverMasterKeyOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    // 発行側と対称の線引き: コードは鍵素材であり、エージェント越しの stdin に
    // 打ち込ませる経路も作らない(入力はエージェントのセッション層から読める)。
    // 復元は人間の対話端末で行う
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "AI エージェント環境を検出したため、リカバリーコードの入力を拒否しました(コードは鍵素材です。復元は人間の対話端末で実行してください)",
        ),
      );
    }
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "master 鍵は既にこのデバイスにあります。上書きすると既存の鍵を失うため拒否します(`maruhi key show` で確認できます)",
    );

    const wrap = yield* input.client.auth.recoveryGet({}).pipe(
      Effect.catchTag("RecoveryWrapNotFound", () =>
        Effect.fail(
          cliError(
            "リカバリーが未登録です。鍵が残っているデバイスで `maruhi key recovery` を実行して登録してください",
          ),
        ),
      ),
      Effect.catchTag("RecoveryRateLimited", (error) =>
        Effect.fail(
          cliError(
            `リカバリーブロブの取得回数が上限に達しました。${error.retryAfterSeconds} 秒後に再試行してください`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
    const nonce = decodeHex(wrap.nonceHex);
    const ciphertext = decodeHex(wrap.ciphertextHex);
    if (nonce === null || ciphertext === null) {
      return yield* Effect.fail(cliError("サーバーの応答が不正です(hex を解釈できません)"));
    }

    // コード入力 → 復号はローカル再試行(取得レート制限の窓を消費しない)
    const record = yield* unwrapWithPromptedCode({
      nonce,
      ciphertext,
      userId: input.session.userId,
    });
    const validated = yield* importMasterKeys(record);
    yield* keychain.set(entryName, serializeStoredMasterKey(record));
    yield* io.log("master 鍵を復元し、OS キーチェーンに保存しました");
    yield* io.log(`key fingerprint: ${validated.fingerprintHex}`);
  });
}

function unwrapWithPromptedCode(input: {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly userId: string;
}): Effect.Effect<StoredMasterKey, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (let attempt = 1; attempt <= PROMPT_ATTEMPTS; attempt += 1) {
      const answer = yield* io.promptLine({
        prompt: "リカバリーコードを入力してください: ",
        secret: true,
      });
      const secret = parseRecoveryCode(answer);
      if (secret === null) {
        yield* io.logError(
          "コードの形式が不正です(4 文字 × 13 グループ。ハイフン・空白・大文字小文字は無視されます)",
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
        catch: () => cliError("リカバリーブロブの復号に失敗しました(暗号処理エラー)"),
      });
      if (!unwrapped.ok) {
        yield* io.logError("復号できません。コードが正しいか確認してください");
        continue;
      }
      const blob = new TextDecoder().decode(unwrapped.value);
      const record = parseStoredMasterKey(blob);
      if (record === null) {
        // 復号は成功したのに中身が壊れている = 登録時のブロブが不正(コードの
        // 誤りではないので再入力させない)。伏字保存はここでも区別する:
        // ブロブは serializeStoredMasterKey の 3 つ目のシンクであり、同じ
        // 剥がし忘れが届きうる。しかも `maruhi key recovery` での再登録は
        // master 鍵の読み込み(= 復元済みであること)を要するため、鍵を失った
        // デバイスでは実行できない — 案内としても成立しない
        return yield* Effect.fail(
          cliError(
            hasRedactedPlaceholder(blob)
              ? // 壊れているのは**サーバー登録済みのブロブ**であってキーチェーンの
                // レコードではない(この経路は ensureNoStoredMasterKey を通って
                // いるので、キーチェーンに master 鍵は存在しない)
                `${placeholderCause("登録済みのリカバリーブロブ")}。このコードでは復元できません。master 鍵が残っている別のデバイスで \`maruhi key recovery\` を実行して再登録してください。併せて不具合として報告してください`
              : "復号したブロブを master 鍵レコードとして解釈できません。`maruhi key recovery` で再登録してください",
          ),
        );
      }
      return record;
    }
    return yield* Effect.fail(
      cliError("リカバリーコードの入力に連続で失敗しました。コードを確認して再実行してください"),
    );
  });
}

/**
 * `maruhi key generate` の後段: リカバリーコードの初回発行。エージェント環境
 * では発行そのものをスキップし(拒否ではなく案内)、鍵生成は成立させる。
 */
export function issueRecoveryAfterKeygen(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      yield* io.log(
        "AI エージェント環境のため、リカバリーコードの発行をスキップしました。人間の対話端末で `maruhi key recovery` を実行してください(発行するまで鍵の紛失に備えられません)",
      );
      return;
    }
    const masterKeys = yield* loadMasterKeys(input.session);
    yield* issueRecoveryCodeOp({ session: input.session, client: input.client, masterKeys }).pipe(
      Effect.mapError((error) =>
        cliError(
          `${error.message}(master 鍵の生成は完了しています。リカバリーコードは \`maruhi key recovery\` で改めて発行できます)`,
        ),
      ),
    );
  });
}
