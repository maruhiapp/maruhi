// `maruhi run -- <cmd>`: 子プロセス環境変数へのメモリ注入のみで値を渡す
// (CLAUDE.md ディスクレス不変条件)。ファイル・一時ファイル・ソケット等の
// 中間経路を作らない。エージェント検出時も run は許可される(値の表示では
// なく、サンクションされた消費経路であるため — タスク裁定)。

import { Context, Effect, Redacted } from "effect";

import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import type { DecryptedVariable } from "./pull.ts";

/** Child-process boundary: spawn with injected env vars, inherit stdio. */
export interface ProcessRunnerShape {
  /** Runs `command`, merging `extraEnv` into the inherited environment. Returns the exit code. */
  readonly run: (input: {
    readonly command: readonly string[];
    readonly extraEnv: Readonly<Record<string, string>>;
  }) => Effect.Effect<number, CliError>;
}

export class ProcessRunner extends Context.Service<ProcessRunner, ProcessRunnerShape>()(
  "cli/ProcessRunner",
) {}

// 実行制御系の環境変数名は注入を拒否する(レビューループ 1 [低]): 変数名は
// 平文メタデータで AAD に束縛されないため、悪意あるサーバーが名前と暗号文の
// 対応を付け替えても復号は成功する。正当な秘密値がこれらの名前で注入されると
// 子プロセスのコード実行制御になるため、名前空間ごと塞ぐ。
// このリストは best-effort の緩和策であり網羅ではない — 根本策は名前の
// 暗号学的束縛(仕様側の検討事項 — session-11.md 申し送り)。
// 比較は大文字化して行う(Windows の環境変数名は大文字小文字を区別しない —
// レビューループ 2 [低])
const DENIED_ENV_NAMES = new Set([
  "PATH",
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "SSLKEYLOGFILE",
  "BUN_OPTIONS",
  "BASH_ENV",
  "ENV",
  "IFS",
  "SHELL",
  "ZDOTDIR",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
  "PERL5OPT",
  "PERL5LIB",
  "PERLLIB",
  "RUBYOPT",
  "RUBYLIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "CLASSPATH",
  "GCONV_PATH",
]);
const DENIED_ENV_PREFIXES = ["LD_", "DYLD_", "GIT_"];

function isDeniedEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  return DENIED_ENV_NAMES.has(upper) || DENIED_ENV_PREFIXES.some((p) => upper.startsWith(p));
}

// 注入する環境変数名は POSIX 識別子に限定する(bash 関数インポート名など
// 特殊文字を含む注入経路を構造的に塞ぐ。denylist は識別子内の実行制御名を覆う)
const SAFE_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Builds the env-var map to inject: variable display names become env names.
 * Names and values are validated for env-var safety (no `=`, no NUL, UTF-8,
 * no execution-control names); the error mentions only the variable name,
 * never the value.
 */
export function buildInjectionEnv(
  variables: readonly DecryptedVariable[],
): Effect.Effect<Readonly<Record<string, string>>, CliError> {
  return Effect.gen(function* () {
    const env: Record<string, string> = {};
    // Windows の環境変数名は大文字小文字を区別しないため、大小違いだけの
    // 名前の共存を許すと片方が黙って潰れる。衝突として拒否する
    const seenUpper = new Set<string>();
    for (const variable of variables) {
      const upper = variable.name.toUpperCase();
      if (seenUpper.has(upper)) {
        return yield* Effect.fail(
          cliError(
            `Variable names collide differing only by letter case (they become the same env var on Windows): ${displayText(variable.name)}`,
          ),
        );
      }
      seenUpper.add(upper);
      // 環境変数名は POSIX 識別子([A-Za-z_][A-Za-z0-9_]*)に限定する。
      // これは `=` / NUL / 制御文字だけでなく、bash 関数インポートの
      // エンコード名(BASH_FUNC_x%% や x() 形式 — shellshock 系の関数注入)も
      // 弾く: 悪意あるメンバーがそうした名前の変数を作り、被害者が
      // `maruhi run -- bash ...` を実行するとシェルが攻撃者定義関数を読み込む
      if (!SAFE_ENV_NAME.test(variable.name)) {
        return yield* Effect.fail(
          cliError(
            `The variable name cannot be injected as an env var (names may use only alphanumerics and _, starting with a letter or _): ${displayText(variable.name)}`,
          ),
        );
      }
      if (isDeniedEnvName(variable.name)) {
        return yield* Effect.fail(
          cliError(
            `Refusing to inject variable name ${displayText(variable.name)}: it is an execution-control env var (rename the variable)`,
          ),
        );
      }
      // 剥がす理由: 子プロセス env への注入(この関数の産物)。注入の直前だけで
      // 剥がし、平文は返り値の env map にのみ現れる。エラーメッセージは
      // 変数名しか運ばない(下の 3 分岐とも値を含めない)
      // デコード方針は display.ts に一本化(fatal — pull --show と共通)
      const value = decodeValueText(Redacted.value(variable.value));
      if (value === null) {
        return yield* Effect.fail(
          cliError(
            `The value of variable ${displayText(variable.name)} is not valid UTF-8 (it cannot be injected as an env var)`,
          ),
        );
      }
      if (value.includes("\0")) {
        return yield* Effect.fail(
          cliError(
            `The value of variable ${displayText(variable.name)} contains NUL (it cannot be injected as an env var)`,
          ),
        );
      }
      env[variable.name] = value;
    }
    return env;
  });
}

/**
 * Message shown when `maruhi run` has no command after `--`. Shared by the
 * argument check at the CLI entry point and the guard in {@link runOp}.
 *
 * 文面を 1 か所に置く(2 実装が食い違わないように)。
 */
export const RUN_COMMAND_REQUIRED =
  "Specify the command to run after `--` (example: maruhi run -- printenv MY_VAR)";

/** `maruhi run`: inject decrypted variables into the child env and run the command. */
export function runOp(input: {
  readonly command: readonly string[];
  readonly variables: readonly DecryptedVariable[];
}): Effect.Effect<number, CliError, ProcessRunner> {
  return Effect.gen(function* () {
    // 空文字列は実行できない(`maruhi run -- "$CMD"` の CMD 未設定がこの形)。
    // 「引数が 1 つある」ことと「実行対象がある」ことは別
    if (input.command.length === 0 || (input.command[0] ?? "").trim() === "") {
      // 書き方の誤り = usage エラー(2)。入口の検査と同じ扱いにする
      return yield* Effect.fail(usageError(RUN_COMMAND_REQUIRED));
    }
    const runner = yield* ProcessRunner;
    const extraEnv = yield* buildInjectionEnv(input.variables);
    return yield* runner.run({ command: input.command, extraEnv });
  });
}
