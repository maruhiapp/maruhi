// `maruhi key publish [--gh]` と鍵登録の導線(CRYPTO_SPEC §6.5 裏付け元 — IV2、
// 補足 21 裁定 G ④ / G ⑥)。
//
// 自分の maruhi sig 公開鍵(Ed25519)を GitHub の **SSH 署名鍵** として登録する
// ための表示・補助。鍵素材は公開鍵だけなので儀式ではなく、表示ゲートも不要。
//
// - 既定: OpenSSH 公開鍵行(`ssh-ed25519 …`)を stdout に 1 行だけ出し、登録手順
//   (https://github.com/settings/ssh/new — Key type = Signing Key)を stderr に出す
// - `--gh`: 導入済みの gh CLI(`gh ssh-key add - --type signing`)を ProcessRunner
//   経由で呼ぶ(取りに行かない — 補足 16 と同じ)。API 直は不可(maruhi は GitHub の
//   トークンを持たない — AUTH_SPEC §4)。鍵行は stdin で渡す
// - 登録の導線(G ⑥): 鍵生成の直後(`key generate` / `invite accept` 内の生成)に、
//   対話端末 + 非エージェントなら「今すぐ登録しますか」と聞き、yes のときだけ gh を
//   呼ぶ(黙って登録はしない — 利用者の GitHub アカウントを無断で変えない)。
//   非対話・EOF は「登録しない」として案内だけ出す(鍵生成そのものは完了済み)

import { decodeHex, encodeOpenSshEd25519PublicKey } from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import { logNote } from "./notice.ts";
import { ProcessRunner } from "./run.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";
import { GH_ENV } from "./sync-exec.ts";

/** 手動登録先(GitHub の設定ページ)。 */
const GITHUB_SSH_SETTINGS_URL = "https://github.com/settings/ssh/new";

/** 自分の sig 公開鍵の OpenSSH 行(コメント無し — 相互運用の符号化、新プリミティブではない)。 */
function openSshSigningKeyLine(keys: MasterKeys): Effect.Effect<string, CliError> {
  const raw = decodeHex(keys.record.sigPubHex);
  if (raw === null) {
    return Effect.fail(cliError("The stored signing public key is malformed"));
  }
  const encoded = encodeOpenSshEd25519PublicKey(raw);
  return encoded.ok
    ? Effect.succeed(encoded.value)
    : Effect.fail(cliError("The stored signing public key cannot be encoded as an OpenSSH key"));
}

/** gh 側のタイトル(一覧で maruhi の鍵と分かるように FP を添える)。 */
function keyTitleOf(keys: MasterKeys): string {
  return `maruhi ${keys.fingerprintHex}`;
}

/**
 * `gh ssh-key add - --type signing` を呼ぶ(stdin = 鍵行)。gh の未導入・未ログイン・
 * 拒否は CliError(出力は公開鍵しか含まないので、整形して添える)。
 */
function registerViaGh(input: {
  readonly line: string;
  readonly keys: MasterKeys;
}): Effect.Effect<void, CliError, ProcessRunner> {
  return Effect.gen(function* () {
    const runner = yield* ProcessRunner;
    const outcome = yield* runner.exec({
      command: [
        "gh",
        "ssh-key",
        "add",
        "-",
        "--type",
        "signing",
        "--title",
        keyTitleOf(input.keys),
      ],
      cwd: ".",
      extraEnv: GH_ENV,
      // 公開鍵なので秘密ではないが、exec の stdin は Redacted で受ける契約(run.ts)
      stdin: Redacted.make(new TextEncoder().encode(`${input.line}\n`), {
        label: "openssh-public-key",
      }),
    });
    if (outcome.exitCode !== 0) {
      const detail = outcome.output.trim().split("\n").slice(-3).join(" ").trim();
      return yield* Effect.fail(
        cliError(
          `gh could not add the signing key (exit ${outcome.exitCode}${detail.length > 0 ? `: ${detail}` : ""}). Sign in with \`gh auth login\` (the token needs the admin:ssh_signing_key scope — run \`gh auth refresh -s admin:ssh_signing_key\`), or add the key by hand at ${GITHUB_SSH_SETTINGS_URL}`,
        ),
      );
    }
  });
}

/** 手動登録の手順(stderr)。 */
function manualInstructions(keys: MasterKeys): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.logError(
      `Add the line above at ${GITHUB_SSH_SETTINGS_URL} with Key type = Signing Key (title e.g. "${keyTitleOf(keys)}"), or run \`maruhi key publish --gh\` to add it through the gh CLI`,
    );
    yield* io.logError(
      "Once registered, inviters who named your GitHub login can add you without the 12-word call (CRYPTO_SPEC §6.5). If an older key of yours from maruhi is registered there, remove it",
    );
  });
}

/** `maruhi key publish [--gh]`。 */
export function keyPublishOp(input: {
  readonly session: CliSession;
  readonly viaGh: boolean;
}): Effect.Effect<void, CliError, Keychain | CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keys = yield* loadMasterKeys(input.session);
    const line = yield* openSshSigningKeyLine(keys);
    if (!input.viaGh) {
      // stdout は鍵行だけ(`maruhi key publish > key.pub` / `| pbcopy` で使える)
      yield* io.log(line);
      yield* manualInstructions(keys);
      return;
    }
    yield* registerViaGh({ line, keys });
    yield* io.log(
      `Registered your signing key on GitHub as "${keyTitleOf(keys)}" (fingerprint ${keys.fingerprintHex})`,
    );
    yield* io.log(
      "Inviters who name your GitHub login can now add you without the 12-word call (CRYPTO_SPEC §6.5)",
    );
  });
}

/**
 * 鍵生成直後の登録の導線(裁定 G ⑥ (b)): 対話端末 + 非エージェントなら yes で
 * `gh` 経由の登録まで済ませる。それ以外(非対話・エージェント・EOF・no)は案内
 * だけ出す。ここでの失敗は鍵生成の成否に影響させない(登録は後からできる)。
 */
export function offerGithubRegistration(input: {
  readonly session: CliSession;
}): Effect.Effect<
  void,
  never,
  Keychain | CliIo | ProcessRunner | Stdio.Stdio | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const interactive =
      !io.agentProfile().isAgent &&
      (yield* stdio.stdinIsTerminal) &&
      (yield* stdio.stdoutIsTerminal);
    const keys = yield* loadMasterKeys(input.session).pipe(
      Effect.catch(() => Effect.succeed(null)),
    );
    if (keys === null) {
      return;
    }
    const line = yield* openSshSigningKeyLine(keys).pipe(Effect.catch(() => Effect.succeed(null)));
    if (line === null) {
      return;
    }
    if (!interactive) {
      yield* logNote(
        "register this key on GitHub as a signing key with `maruhi key publish` so inviters can add you without the 12-word call",
      );
      return;
    }
    yield* io.log(
      "Registering this key on GitHub as a signing key lets inviters who name your GitHub login add you without the 12-word call (CRYPTO_SPEC §6.5)",
    );
    const answer = yield* io
      .promptLine({
        prompt:
          "Type yes to register it now through the gh CLI (requires `gh auth login`); anything else to skip: ",
      })
      .pipe(Effect.catch(() => Effect.succeed("")));
    if (answer.trim().toLowerCase() !== "yes") {
      yield* logNote("skipped. You can register it later with `maruhi key publish`");
      return;
    }
    yield* registerViaGh({ line, keys }).pipe(
      Effect.flatMap(() =>
        io.log(`Registered your signing key on GitHub as "${keyTitleOf(keys)}"`),
      ),
      Effect.catch((error) =>
        logNote(`${error.message} (you can register it later with \`maruhi key publish\`)`),
      ),
    );
  });
}
