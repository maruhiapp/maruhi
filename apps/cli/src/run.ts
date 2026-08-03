// `maruhi run -- <cmd>`: 子プロセス環境変数へのメモリ注入のみで値を渡す
// (CLAUDE.md ディスクレス不変条件)。ファイル・一時ファイル・ソケット等の
// 中間経路を作らない。エージェント検出時も run は許可される(値の表示では
// なく、サンクションされた消費経路であるため — タスク裁定)。

import { Context, Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
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

const decoder = new TextDecoder("utf-8", { fatal: true });

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
    for (const variable of variables) {
      if (variable.name.includes("=") || variable.name.includes("\0")) {
        return yield* Effect.fail(
          cliError(`変数名を環境変数として注入できません(不正な文字を含みます): ${variable.name}`),
        );
      }
      if (isDeniedEnvName(variable.name)) {
        return yield* Effect.fail(
          cliError(
            `変数名 ${variable.name} は実行制御系の環境変数のため注入を拒否します(変数を改名してください)`,
          ),
        );
      }
      let value: string;
      try {
        value = decoder.decode(variable.value);
      } catch {
        return yield* Effect.fail(
          cliError(
            `変数 ${variable.name} の値が UTF-8 として不正です(環境変数として注入できません)`,
          ),
        );
      }
      if (value.includes("\0")) {
        return yield* Effect.fail(
          cliError(`変数 ${variable.name} の値に NUL が含まれます(環境変数として注入できません)`),
        );
      }
      env[variable.name] = value;
    }
    return env;
  });
}

/** `maruhi run`: inject decrypted variables into the child env and run the command. */
export function runOp(input: {
  readonly command: readonly string[];
  readonly variables: readonly DecryptedVariable[];
}): Effect.Effect<number, CliError, ProcessRunner> {
  return Effect.gen(function* () {
    if (input.command.length === 0) {
      return yield* Effect.fail(
        cliError(
          "実行するコマンドを `--` の後に指定してください(例: maruhi run -- printenv MY_VAR)",
        ),
      );
    }
    const runner = yield* ProcessRunner;
    const extraEnv = yield* buildInjectionEnv(input.variables);
    return yield* runner.run({ command: input.command, extraEnv });
  });
}
