// `maruhi run -- <cmd>`: 子プロセス環境変数へのメモリ注入のみで値を渡す
// (CLAUDE.md ディスクレス不変条件)。ファイル・一時ファイル・ソケット等の
// 中間経路を作らない。エージェント検出時も run は許可される(値の表示では
// なく、サンクションされた消費経路であるため — タスク裁定)。
//
// 値なしスキーマ(§4.2 レイアウト v2)の fail-fast(設計文書 §1-4 — 裁定
// CT / CU): presence は硬く(required = true の declared → 子プロセスを
// **起動せず**型付きエラー)、型は柔らかく(注入直前の平文への advisory 検証 —
// 不一致は警告のみで実行続行 §14.3-7)。**エラー・警告文面に description を
// 含めない**(ログ経由の注入面を作らない — session-46 §8 第 3 周)。

import { Context, Effect, Redacted } from "effect";

import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import type { DeclaredVariable, DecryptedVariable } from "./pull.ts";

/** Child-process boundary: inject values, inherit non-maruhi env + stdio. */
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

const MARUHI_ENV_PREFIX = "MARUHI_";

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
  "NODE_REPL_EXTERNAL_MODULE",
  "SSLKEYLOGFILE",
  "BUN_OPTIONS",
  "BASH_ENV",
  "ENV",
  "IFS",
  "SHELL",
  "ZDOTDIR",
  // rc ファイル・設定ディレクトリの参照先を差し替えられる名前(deepsec M2):
  // HOME を差し替えると bash / zsh / 各種ツールが攻撃者パスの rc・設定を読む
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  // プロンプト評価でコマンド実行になる bash/zsh の変数(M2)。PS1 / PS4 も
  // コマンド置換・xtrace(SHELLOPTS=xtrace + PS4)経由で実行制御になる
  "PROMPT_COMMAND",
  "PS0",
  "PS1",
  "PS4",
  "SHELLOPTS",
  "BASHOPTS",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
  "PYTHONUSERBASE",
  "PYTHONWARNINGS",
  "PYTHONBREAKPOINT",
  "PYTHONEXECUTABLE",
  "PYTHON",
  "NODE_GYP_FORCE_PYTHON",
  // 対話モード強制(M2): 子プロセス終了後に REPL が開き、後続入力を実行する
  "PYTHONINSPECT",
  "PERL5OPT",
  "PERL5LIB",
  "PERLLIB",
  "RUBYOPT",
  "RUBYLIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS",
  "CLASSPATH",
  "GCONV_PATH",
  // Windows の実行解決(M2): PATHEXT は拡張子探索、COMSPEC はシェル本体、
  // SYSTEMROOT / WINDIR はシステム DLL・実行体の解決基準を差し替えられる
  "PATHEXT",
  "COMSPEC",
  "SYSTEMROOT",
  "WINDIR",
  // 子プロセスが**別のプログラムを起動する**ときの起動先(deepsec R3):
  // LESSOPEN / LESSCLOSE は `|cmd %s` 形式でそのままコマンド実行、PAGER 系と
  // EDITOR / VISUAL / BROWSER は git・systemctl・各種 CLI が直接 spawn する
  "LESSOPEN",
  "LESSCLOSE",
  "PAGER",
  "MANPAGER",
  "EDITOR",
  "VISUAL",
  "BROWSER",
  // パスフレーズ入力の代行プログラム(R3): ssh / sudo が指定先を実行する
  "SSH_ASKPASS",
  "SUDO_ASKPASS",
  // インタプリタの初期化フック・モジュール探索(R3)。LUA_INIT は任意の Lua を
  // 実行し、LUA_PATH / LUA_CPATH は require の探索先を差し替える
  "LUA_INIT",
  "LUA_PATH",
  "LUA_CPATH",
  "PSMODULEPATH",
  // glibc / ローダの挙動と補助データの探索先(R3)。GLIBC_TUNABLES は
  // チューナブル経由で挙動を変え、LOCPATH / NLSPATH / TERMINFO / TERMCAP は
  // プロセスが読み込むバイナリ記述子(ロケール・端末定義)の出所を差し替える
  "GLIBC_TUNABLES",
  "MALLOC_CONF",
  "LOCPATH",
  "NLSPATH",
  "TERMINFO",
  "TERMINFO_DIRS",
  "TERMCAP",
  "CDPATH",
  // shell function autoload と TLS trust root。既存の BASH_ENV / ZDOTDIR /
  // NODE_EXTRA_CA_CERTS と同じ実行・信頼境界(deepsec 08-27 follow-up)
  "FPATH",
  "KSH_ENV",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "CURL_CA_BUNDLE",
  "REQUESTS_CA_BUNDLE",
  "AWS_CA_BUNDLE",
  "NPM_CONFIG_USERCONFIG",
  "NPM_CONFIG_GLOBALCONFIG",
  "NPM_CONFIG_SCRIPT_SHELL",
  "NPM_CONFIG_SHELL",
  "NPM_CONFIG_NODE_OPTIONS",
  "NPM_CONFIG_PREFIX",
  "NPM_CONFIG_CAFILE",
  "NPM_CONFIG_IGNORE_SCRIPTS",
  "NPM_CONFIG_NODE_GYP",
  "NPM_CONFIG_PYTHON",
  "NPM_CONFIG_INIT_MODULE",
  "NPM_CONFIG_EDITOR",
  "NPM_CONFIG_VIEWER",
  "NPM_CONFIG_STRICT_SSL",
  "NPM_CONFIG_CA",
  "NPM_CONFIG_GIT",
  "DOTNET_STARTUP_HOOKS",
  "GEM_HOME",
  "GEM_PATH",
  "HOSTALIASES",
]);
// NODE_ / PYTHON_ / BUN_ の包括 prefix 拒否は採らない(M2 の要検討事項の裁定):
// NODE_ENV / PYTHONDONTWRITEBYTECODE 等、実行制御でない正当な変数を大量に
// 巻き込み、rename の強制が互換性を壊す。実行制御になる既知の名前を個別に足す。
//
// `MARUHI_` だけは包括 prefix で塞ぐ(deepsec S3)。上の裁定と矛盾しない理由は
// **maruhi 自身が予約する名前空間**だから: 巻き込む「正当な変数」が原理的に
// 存在せず(この名前空間の意味は maruhi が決める)、逆にここへ 1 つでも通すと
// 入れ子の `maruhi` の挙動を注入側が決められる。実際 `MARUHI_TOKEN` /
// `MARUHI_TOKEN_ORIGIN` は resolveSession がキーチェーンより**先に**見るため、
// 悪意あるメンバーがその名前の変数に自分の PAT を入れておくと、被害者の
// `maruhi run -- make deploy` の中の `maruhi pull` が攻撃者として認証される
// (変数名は AAD に束縛されない平文メタデータ = 共同メンバーが決められる)。
// 個別名の列挙にすると将来 MARUHI_* を増やしたときに同じ穴が再発する
//
// NPM_CONFIG_ は registry credential / private registry URL という正当なsecret・
// 設定注入用途があるため包括拒否しない。実行・require・spawn・TLS trustを直接
// 変える上記キーだけを個別拒否する。NPM_CONFIG_REGISTRY はinstall先を変えるが
// private registryの基本設定でもあるため許可し、install scriptの実行可否は
// 呼び出すnpmコマンド側の責務とする
const DENIED_ENV_PREFIXES = ["LD_", "DYLD_", "GIT_", "CORECLR_", "COR_", MARUHI_ENV_PREFIX];

function isDeniedEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  return DENIED_ENV_NAMES.has(upper) || DENIED_ENV_PREFIXES.some((p) => upper.startsWith(p));
}

/**
 * 子プロセスへ渡す環境。親の一般環境は継承するが、maruhi 自身の制御・資格情報
 * 名前空間は除く(deepsec S6)。
 *
 * keychain-less / CI の MARUHI_TOKEN は run のセッション解決には必要だが、
 * 子へ渡すと注入値より長寿命・広スコープな PAT まで依存コードが読める。
 * 大文字化比較は Windows の環境変数名が case-insensitive なため。
 */
export function buildChildEnvironment(
  inherited: Readonly<Record<string, string | undefined>>,
  extraEnv: Readonly<Record<string, string>>,
): Readonly<Record<string, string>> {
  const child: Record<string, string> = {};
  const copyAllowed = (name: string, value: string | undefined): void => {
    if (value !== undefined && !name.toUpperCase().startsWith(MARUHI_ENV_PREFIX)) {
      child[name] = value;
    }
  };
  for (const [name, value] of Object.entries(inherited)) {
    copyAllowed(name, value);
  }
  // extraEnv は buildInjectionEnv で既に MARUHI_* を拒否するが、ProcessRunner
  // 境界を直接使う将来 caller に対しても資格情報名前空間を通さない
  for (const [name, value] of Object.entries(extraEnv)) {
    copyAllowed(name, value);
  }
  return child;
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
            `Variable names collide differing only by letter case (they become the same environment variable on Windows): ${displayText(variable.name)}`,
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
            `The variable name cannot be injected as an environment variable (names may use only alphanumerics and _, starting with a letter or _): ${displayText(variable.name)}`,
          ),
        );
      }
      if (isDeniedEnvName(variable.name)) {
        return yield* Effect.fail(
          cliError(
            `Refusing to inject variable name ${displayText(variable.name)}: it is an execution-control environment variable (rename the variable)`,
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
            `The value of variable ${displayText(variable.name)} is not valid UTF-8 (it cannot be injected as an environment variable)`,
          ),
        );
      }
      if (value.includes("\0")) {
        return yield* Effect.fail(
          cliError(
            `The value of variable ${displayText(variable.name)} contains NUL (it cannot be injected as an environment variable)`,
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

/**
 * Presence fail-fast (設計文書 §1-4 — 裁定 CT / CU): required = true の
 * declared 変数が検証済み集合に存在する場合、**子プロセスを起動する前**に
 * 型付きエラーで終了する(変数名を列挙。判定材料は署名済みステートメント +
 * マニフェスト被覆のみ — §14.2-8: サーバー申告に依存しない)。required =
 * false の declared は注入せず情報表示のみ(stderr)。文面はどちらも
 * description を含めない。
 */
export function enforceDeclaredPresence(
  declared: readonly DeclaredVariable[],
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const missing = declared
      .filter((variable) => variable.required)
      .map((variable) => displayText(variable.name))
      .toSorted();
    if (missing.length > 0) {
      // 子プロセス未起動の硬いエラー(presence — verified statements only)。
      // 復旧導線は 2 つ明示する: 値を設定する(activation)か、宣言が誤りなら
      // --optional で required を下げる(宣言の削除コマンドは未提供 — PR #121)
      return yield* Effect.fail(
        cliError(
          `Required variables are declared but have no value yet (verified from signed statements — CRYPTO_SPEC §14.2): ${missing.join(", ")}. Set each value with \`maruhi push <NAME>\` (the first push of a declared variable activates it), or downgrade a mistaken declaration with \`maruhi schema set <NAME> --optional\`. The command was not started`,
        ),
      );
    }
    const optional = declared
      .filter((variable) => !variable.required)
      .map((variable) => displayText(variable.name))
      .toSorted();
    if (optional.length > 0) {
      yield* logNote(
        `declared variables without values were not injected (declared as not required): ${optional.join(", ")}`,
      );
    }
  });
}

// advisory 型検証(§14.3-7)の判定。宣言型は閉集合(§4.2 — "" = 未指定は
// 検査対象外)。判定は注入直前のメモリ内の平文にのみ触れ、結果(真偽)以外を
// 外へ出さない。number は 10 進表記(整数・小数・指数)のみ受ける(Number()
// の "0x1f" / "Infinity" 受理を型一致に数えない)
const NUMBER_TEXT = /^-?(?:\d+)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

function matchesDeclaredType(varType: "string" | "number" | "boolean" | "url", text: string) {
  switch (varType) {
    case "string":
      return true;
    case "number":
      return NUMBER_TEXT.test(text);
    case "boolean":
      return text === "true" || text === "false";
    case "url":
      return URL.canParse(text);
  }
}

/**
 * Advisory declared-type check at injection time (§14.3-7): mismatches are
 * warnings only and execution continues (type conformance is never verified —
 * the declaration is advisory). 文面は変数名・宣言型名のみ(値も description も
 * 含めない)。不正 UTF-8 はここでは黙って素通しする(buildInjectionEnv が
 * 変数名付きの硬いエラーにする — 二重報告しない)。
 */
export function typeAdvisoryWarnings(variables: readonly DecryptedVariable[]): readonly string[] {
  const warnings: string[] = [];
  for (const variable of variables) {
    if (variable.varType === "") {
      continue;
    }
    // 剥がす理由: 注入直前の advisory 型検証(メモリ内のみ)。判定結果(真偽)
    // 以外は外へ出ない — 警告文面は変数名と宣言型名だけを運ぶ
    const text = decodeValueText(Redacted.value(variable.value));
    if (text !== null && !matchesDeclaredType(variable.varType, text)) {
      warnings.push(
        `The value of variable ${displayText(variable.name)} does not match its declared type "${variable.varType}" (the declaration is advisory — CRYPTO_SPEC §14.3; continuing)`,
      );
    }
  }
  return warnings;
}

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
