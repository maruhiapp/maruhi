// `maruhi sync` の exec ドライバ(SY2 第 1 段 — integration-options.md §3
// 補足 10 V1 / 補足 13 W1 / 補足 14 M2 / 補足 16)。
//
// 導入済み・ログイン済みのベンダー CLI(`wrangler` / `vercel`)を子プロセスと
// して起動し、値を **stdin だけ**で渡す。argv には名前とオプションしか載らない:
// 引数テンプレート({@link ArgTemplate})に値のトークンは存在しない(型で禁止 —
// SY1 申し送りの含意 (d))。プリセットは宣言的なデータ(コマンド・引数
// テンプレート・stdin の形式・1 プロセスあたりの件数・テレメトリ off の環境
// 変数・値の制約・オプションの宣言)で、追加はデータ + 偽 CLI の検査で済む
// (`gh secret set NAME` は raw-value / 1 件ずつ / `GH_TELEMETRY=false` の
// 宣言で載った — SY5)。
//
// ベンダー CLI の実測は SY1 の申し送り表(2026-09-05。Vercel CLI 59.11.7 は
// 2026-09-06 に再確認 — 版・`readStandardInput` / `normalizeStdinEnvValue` とも
// 不変。gh は 2026-09-08 に v2.100.0 の `pkg/cmd/secret/set/set.go` で再確認):
//   - wrangler 4.128.0 `secret bulk`: stdin の JSON `{"k":"v"}` を 1 リクエスト、
//     `null` = 削除、1 回 100 件、空 stdin は「No content found」で exit 0
//     (→ 空の入力では呼ばない)、`--name` / `--env`、`WRANGLER_SEND_METRICS=false`
//     (`true` / `false` 厳密)
//   - Vercel CLI 59.11.7 `env add NAME [env]`: stdin の**最初の data チャンク
//     1 回分**だけを 500 ms 待って読む(→ 一度に書いて閉じる。Linux の実測は
//     65,536 バイトまで完全、macOS のパイプは初期 16 KiB → 上限 16 KiB)、
//     1 行の値からだけ末尾改行 1 つを落とす(→ 末尾改行 1 つで終わる 1 行の値は
//     表現できないので拒否)、空 stdin は「値なし」= 対話(→ 空値は拒否)、
//     `--force` = API の upsert(rm → add の窓は無い)、`--non-interactive` で
//     全プロンプトが失敗に倒れる、`VERCEL_TELEMETRY_DISABLED=1`
//   - gh 2.100.0 `secret set NAME`: `--body` 省略 + 非対話で stdin を **すべて**読み
//     `bytes.TrimRight(body, "\r\n")`(→ 末尾の CR / LF を全部落とすので、改行で
//     終わる値は単行・複数行とも表現できない = 拒否)、空 stdin は空の本文として
//     封印して送る(API の受理は未確認 — 拒否は gh の文面で見える)、封印
//     (libsodium sealed box)はクライアント側、上書き、`gh secret delete NAME`
//     (不在名は API の 404 = 非 0)、`-R OWNER/REPO` / `--env <Environment>` /
//     `--app {actions|agents|codespaces|dependabot}`(Environment secrets は
//     actions のみ)、認証は `GH_TOKEN`(次いで `GITHUB_TOKEN`)か `gh auth login`、
//     未ログインは終了コード 4、`GH_TELEMETRY=false` / `DO_NOT_TRACK=1`。名前は
//     GitHub 側で英数字と `_`・数字始まり不可・`GITHUB_` 接頭辞不可・**大文字で
//     保存**(大文字小文字を同一視)— 大小違いの 2 名が 1 つの secret に畳まれる
//     形を作らないよう、大文字の名前だけを通す(docs.github.com「Secrets
//     reference」2026-09-08)
//
// ベンダー CLI の stdout / stderr は値を含みうる前提で扱う: 成功時は捨て、失敗時も
// 値を伏せた末尾だけを出す({@link scrubVendorOutput})。

import { Redacted } from "effect";

import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { ExecInput } from "./run.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";

/**
 * One argv token of a preset. A literal, the variable name, or a value taken
 * from the target's options. There is deliberately no token for the value.
 */
export type ArgTemplate =
  | string
  | { readonly kind: "name" }
  /** 必須オプションの値をそのまま(位置引数)。 */
  | { readonly kind: "option"; readonly option: string }
  /** 任意オプション: 設定されていれば `flag value` の 2 トークン。 */
  | { readonly kind: "option"; readonly option: string; readonly flag: string }
  /** boolean オプションが `equals` のときだけ `flag` を 1 トークン足す。 */
  | {
      readonly kind: "switch";
      readonly option: string;
      readonly equals: boolean;
      readonly flag: string;
    };

/** A declarative exec preset (data only — no code per vendor). */
export interface ExecPreset {
  /** 既定の実行体(PATH 上の導入済み CLI)。 */
  readonly command: string;
  /** 子へ足す非機密の環境変数(テレメトリ off)。 */
  readonly env: Readonly<Record<string, string>>;
  /** stdin の形式: 名前 → 値の JSON オブジェクト 1 つ、または値そのもの。 */
  readonly transport: "json-object" | "raw-value";
  /** 1 プロセスに載せる最大件数(raw-value は常に 1)。 */
  readonly batch: number;
  /** 書き込みの argv(コマンド名を除く)。 */
  readonly writeArgs: readonly ArgTemplate[];
  /** 削除: JSON の `null`(同じ書き込みプロセスに同居)か、別コマンドの argv。 */
  readonly delete: "json-null" | { readonly args: readonly ArgTemplate[] };
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  /**
   * オプション同士の整合(1 つの `OptionSpec` では表せない — GitHub の Environment
   * secrets は actions アプリだけ、など)。設定時に呼ばれ、不整合なら
   * `<option>: <理由>` の形の文字列を返す(http プリセットの `check` と同じ契約)。
   */
  readonly check?: (options: ResolvedOptions) => string | null;
  /** `sync init` が添えるサインインの案内(ベンダー CLI の資格の置き場と最小権限)。 */
  readonly signInHint?: string;
}

// macOS のパイプは初期容量 16 KiB(それ以上は書き手がブロックし、Vercel CLI の
// 「最初のチャンクだけ」読みが切れる)。Linux の実測上限 64 KiB ではなく、
// 環境差を跨いで安全な側に置く
const VERCEL_MAX_VALUE_BYTES = 16 * 1024;

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

/**
 * Non-secret environment for every `gh` maruhi starts (`gh secret set` here, `gh
 * workflow run` in sync-push.ts): telemetry off (SY1 の実測表の gh 行), no update
 * check, and no interactive prompt (gh is already non-interactive when its stdio is
 * not a terminal; this cuts the prompt structurally).
 */
export const GH_ENV: Readonly<Record<string, string>> = {
  GH_TELEMETRY: "false",
  DO_NOT_TRACK: "1",
  GH_NO_UPDATE_NOTIFIER: "1",
  GH_PROMPT_DISABLED: "1",
};

// gh 2.100.0 の `--app` の閉集合(shared.GetSecretApp)。省略 = actions
const GITHUB_SECRET_APPS = ["actions", "agents", "codespaces", "dependabot"] as const;

/**
 * GitHub secret names (docs.github.com「Secrets reference」): alphanumerics and `_`,
 * not starting with a digit, not starting with `GITHUB_`, stored in uppercase. Only
 * uppercase names are accepted so that no two maruhi names fold into one secret.
 */
const GITHUB_SECRET_NAME = /^(?!GITHUB_)[A-Z_][A-Z0-9_]*$/;

// gh の `-R [HOST/]OWNER/REPO`(先頭 `-` = フラグと読まれる形は構造で除く)
const GITHUB_REPO = /^(?:[A-Za-z0-9.-]+\/)?[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

// GitHub Environment 名(gh の argv に載る。フラグと読まれる先頭 `-` だけを除く)
const GITHUB_ENVIRONMENT_NAME = /^[^-\s][^\n\r]*$/;

/**
 * Built-in exec presets (first-class targets — 2026-09-05 owner decision: Vercel /
 * Cloudflare Workers; GitHub Actions secrets through `gh` — SY5). Netlify has none:
 * `netlify env:set KEY value` takes the value as an argument (SY1 の実測表), so the
 * only safe recipe is the http driver (sync-preset.ts declares why).
 */
export const EXEC_PRESETS = {
  "cloudflare-workers": {
    command: "wrangler",
    env: { WRANGLER_SEND_METRICS: "false", DO_NOT_TRACK: "1" },
    transport: "json-object",
    batch: 100,
    writeArgs: [
      "secret",
      "bulk",
      { kind: "option", option: "name", flag: "--name" },
      { kind: "option", option: "environment", flag: "--env" },
      { kind: "option", option: "config", flag: "--config" },
    ],
    delete: "json-null",
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      name: { type: "string", required: false },
      environment: { type: "string", required: false },
      config: { type: "string", required: false },
    },
  },
  vercel: {
    command: "vercel",
    env: { VERCEL_TELEMETRY_DISABLED: "1" },
    transport: "raw-value",
    batch: 1,
    writeArgs: [
      "env",
      "add",
      { kind: "name" },
      { kind: "option", option: "environment" },
      { kind: "option", option: "gitBranch", flag: "--git-branch" },
      { kind: "option", option: "project", flag: "--project" },
      { kind: "option", option: "scope", flag: "--scope" },
      { kind: "switch", option: "sensitive", equals: false, flag: "--no-sensitive" },
      "--force",
      "--non-interactive",
    ],
    delete: {
      args: [
        "env",
        "rm",
        { kind: "name" },
        { kind: "option", option: "environment" },
        { kind: "option", option: "gitBranch", flag: "--git-branch" },
        { kind: "option", option: "project", flag: "--project" },
        { kind: "option", option: "scope", flag: "--scope" },
        "--yes",
        "--non-interactive",
      ],
    },
    constraints: {
      maxBytes: VERCEL_MAX_VALUE_BYTES,
      nonEmpty: true,
      trailingNewline: "strippedFromSingleLine",
      name: null,
    },
    options: {
      environment: { type: "string", required: true, values: VERCEL_ENVIRONMENTS },
      gitBranch: { type: "string", required: false },
      project: { type: "string", required: false },
      scope: { type: "string", required: false },
      sensitive: { type: "boolean", required: false },
    },
  },
  "github-actions": {
    command: "gh",
    env: GH_ENV,
    transport: "raw-value",
    batch: 1,
    writeArgs: [
      "secret",
      "set",
      { kind: "name" },
      { kind: "option", option: "repo", flag: "--repo" },
      { kind: "option", option: "environment", flag: "--env" },
      { kind: "option", option: "app", flag: "--app" },
    ],
    delete: {
      args: [
        "secret",
        "delete",
        { kind: "name" },
        { kind: "option", option: "repo", flag: "--repo" },
        { kind: "option", option: "environment", flag: "--env" },
        { kind: "option", option: "app", flag: "--app" },
      ],
    },
    constraints: {
      // GitHub の上限は 48 KB(docs)だが単位と測り方が未確認で、gh は stdin を全部
      // 読んで API に渡す(切り詰めの経路が無い)= 超過は API の拒否が gh の文面で
      // 見える。未確認の数に依存させない
      maxBytes: null,
      // gh は空 stdin を空の本文として封印して送る(値なしとは読まない)。
      // 改行だけの値は trailingNewline が先に拒む
      nonEmpty: false,
      trailingNewline: "stripped",
      name: {
        regex: GITHUB_SECRET_NAME,
        rule: "GitHub stores secret names in uppercase and accepts only uppercase letters, digits, and _, not starting with a digit or with GITHUB_",
      },
    },
    options: {
      repo: {
        type: "string",
        required: false,
        pattern: { regex: GITHUB_REPO, hint: "OWNER/REPO (or HOST/OWNER/REPO)" },
      },
      environment: {
        type: "string",
        required: false,
        pattern: {
          regex: GITHUB_ENVIRONMENT_NAME,
          hint: "a GitHub Environment name (not starting with -)",
        },
      },
      app: { type: "string", required: false, values: GITHUB_SECRET_APPS },
    },
    // Environment secrets は actions アプリだけ(gh shared.IsSupportedSecretEntity)。
    // gh は値を stdin から読んだ**後**にこれを拒むので、設定の段階で止める
    check: (options) =>
      options["environment"] !== undefined &&
      options["app"] !== undefined &&
      options["app"] !== "actions"
        ? `app: environment secrets exist for GitHub Actions only, so app must be "actions" (or left out) when environment is set`
        : null,
    signInHint:
      "the github-actions preset runs the gh CLI, which must be installed and signed in (`gh auth login`, or GH_TOKEN in the environment) with write access to the repository's secrets: in a fine-grained token, Secrets for repository secrets, Environments for Environment secrets, Dependabot secrets for app dependabot (see the Deploy targets page in the docs)",
  },
} as const satisfies Readonly<Record<string, ExecPreset>>;

/** One variable to write at the target (the value stays wrapped until spawn). */
export interface SyncWrite {
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
}

/** One vendor-CLI process to run, with the names it carries (for reporting). */
export interface ExecInvocation extends ExecInput {
  readonly kind: "write" | "delete";
  readonly names: readonly string[];
}

/** 1 トークンの展開(値は決して載らない — テンプレートに値のトークンが無い)。 */
function renderToken(
  template: ArgTemplate,
  options: Readonly<Record<string, string | boolean>>,
  name: string | null,
): readonly string[] {
  if (typeof template === "string") {
    return [template];
  }
  if (template.kind === "name") {
    // json-object の書き込みでは名前は stdin の JSON 側にあり、テンプレートに
    // name トークンは現れない(現れたら宣言の誤り = 内部エラー)
    if (name === null) {
      throw new Error("preset declares a name token for a batched command");
    }
    return [name];
  }
  if (template.kind === "switch") {
    return options[template.option] === template.equals ? [template.flag] : [];
  }
  const value = options[template.option];
  if (typeof value !== "string") {
    return [];
  }
  return "flag" in template ? [template.flag, value] : [value];
}

/** 引数テンプレートを、名前とオプションから argv に展開する。 */
function renderArgs(
  templates: readonly ArgTemplate[],
  options: Readonly<Record<string, string | boolean>>,
  name: string | null,
): string[] {
  return templates.flatMap((template) => renderToken(template, options, name));
}

/** 1 値の制約検査(文面は変数名だけを運ぶ)。 */
export function checkValueConstraints(
  driver: { readonly constraints: ValueConstraints; readonly label: string },
  name: string,
  plaintext: Uint8Array,
): CliError | null {
  const shown = displayText(name);
  const { constraints, label } = driver;
  if (constraints.nonEmpty && plaintext.byteLength === 0) {
    return cliError(
      `Variable ${shown} is empty, and ${label} treats an empty value on stdin as no value. Set a non-empty value with \`maruhi push ${shown}\` or leave this variable out of the target`,
    );
  }
  if (constraints.maxBytes !== null && plaintext.byteLength > constraints.maxBytes) {
    return cliError(
      `Variable ${shown} is ${plaintext.byteLength} bytes, above the ${constraints.maxBytes}-byte limit maruhi applies for ${label} (it reads only the first chunk of stdin, so a larger value could be cut off silently). Leave this variable out of the target, or set it through the platform's dashboard`,
    );
  }
  if (
    constraints.trailingNewline === "strippedFromSingleLine" &&
    endsWithSingleLineNewline(plaintext)
  ) {
    return cliError(
      `Variable ${shown} is a single line ending with a newline, which ${label} strips from stdin. Push the value without the trailing newline (\`printf %s\` instead of \`echo\`), or leave this variable out of the target`,
    );
  }
  if (constraints.trailingNewline === "stripped" && endsWithNewline(plaintext)) {
    return cliError(
      `Variable ${shown} ends with a newline, which ${label} strips from stdin (every trailing CR or LF, from a single-line and a multi-line value alike). Push the value without the trailing newline (\`printf %s\` instead of \`echo\`), or leave this variable out of the target`,
    );
  }
  if (constraints.name !== null && !constraints.name.regex.test(name)) {
    return cliError(
      `Variable ${shown} has a name ${label} cannot store as is: ${constraints.name.rule}. Rename the variable in maruhi, or leave it out of the target`,
    );
  }
  return null;
}

/** 末尾が LF か CR か(gh の `TrimRight("\r\n")` が何かを落とす形)。 */
function endsWithNewline(bytes: Uint8Array): boolean {
  const last = bytes[bytes.length - 1];
  return last === 0x0a || last === 0x0d;
}

/** 「末尾が改行 1 つ(LF / CRLF)で、それ以外に改行を含まない」か。 */
function endsWithSingleLineNewline(bytes: Uint8Array): boolean {
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) {
    return false;
  }
  const end =
    bytes.length > 1 && bytes[bytes.length - 2] === 0x0d ? bytes.length - 2 : bytes.length - 1;
  for (let index = 0; index < end; index += 1) {
    if (bytes[index] === 0x0a || bytes[index] === 0x0d) {
      return false;
    }
  }
  return true;
}

const encoder = new TextEncoder();

/**
 * Builds the processes to run for one target: writes (and deletes) in the
 * preset's transport, values only on stdin. Pure — nothing is spawned here.
 *
 * 値の UTF-8 検査は呼び出し側(sync-plan.ts)が `checkValueConstraints` と
 * 並べて済ませている前提(JSON 文字列・stdin の raw の両方でテキストである
 * ことが要る)。ここでは Redacted を剥がして stdin のバイト列に**再び包む**。
 */
export function buildInvocations(input: {
  readonly preset: ExecPreset;
  readonly command: string;
  readonly cwd: string;
  readonly options: Readonly<Record<string, string | boolean>>;
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}): readonly ExecInvocation[] {
  const { preset } = input;
  const invocations: ExecInvocation[] = [];
  const base = (args: readonly string[]) => ({
    command: [input.command, ...args],
    cwd: input.cwd,
    extraEnv: preset.env,
  });
  if (preset.transport === "json-object") {
    // 名前 → 値(削除は null)の JSON を 1 プロセスに `batch` 件ずつ
    const entries: (readonly [string, string | null])[] = [
      ...input.writes.map((write) => {
        // 剥がす理由: stdin の JSON 本文の組み立て(産物は再び Redacted に包む)
        const text = decodeValueText(Redacted.value(write.value));
        if (text === null) {
          // prepareWork(sync-plan.ts)が送る前に弾いている前提。到達 = 実装の
          // 不整合なので、空文字列を黙って書く(最悪の形)のでなく落とす。
          // 文面は値も変数名も運ばない
          throw new Error("a value that is not valid UTF-8 reached buildInvocations");
        }
        return [write.name, text] as const;
      }),
      ...(preset.delete === "json-null" ? input.deletes.map((name) => [name, null] as const) : []),
    ];
    for (let start = 0; start < entries.length; start += preset.batch) {
      const chunk = entries.slice(start, start + preset.batch);
      invocations.push({
        ...base(renderArgs(preset.writeArgs, input.options, null)),
        kind: "write",
        names: chunk.map(([name]) => name),
        stdin: Redacted.make(encoder.encode(JSON.stringify(Object.fromEntries(chunk))), {
          label: "sync-stdin",
        }),
      });
    }
  } else {
    for (const write of input.writes) {
      invocations.push({
        ...base(renderArgs(preset.writeArgs, input.options, write.name)),
        kind: "write",
        names: [write.name],
        // 値をそのまま(改行を足さない — 末尾改行の扱いは checkValueConstraints)
        stdin: write.value,
      });
    }
  }
  if (preset.delete !== "json-null") {
    for (const name of input.deletes) {
      invocations.push({
        ...base(renderArgs(preset.delete.args, input.options, name)),
        kind: "delete",
        names: [name],
        stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
      });
    }
  }
  return invocations;
}

/** 失敗時に見せるベンダー出力の行数(末尾)。 */
const SHOWN_TAIL_LINES = 20;

/**
 * 失敗時に見せるベンダー出力の文字数の上限(UTF-16 の文字数。表示の上限であって
 * 記憶量の上限ではない)。**伏せた後に**掛ける — 伏せる前に切ると、切れ目に
 * かかった値の後半が断片に一致しなくなって漏れる(Security Agent 指摘)。
 */
const SHOWN_TAIL_CHARS = 64 * 1024;

/** 末尾 `cap` 文字ぶんだけを保つ(先頭から捨てる)。伏せた文字列にだけ使う。 */
function keepTail(text: string, cap: number): string {
  return text.length <= cap ? text : text.slice(text.length - cap);
}

/**
 * Scrubs a vendor CLI's captured output for display: every synced value (and
 * every line of a multi-line one) is replaced over the whole output, control
 * characters are neutralized, and only then are the last lines kept. Best
 * effort — the output is shown only on failure, prefixed as filtered.
 */
export function scrubVendorOutput(
  output: string,
  values: readonly SyncWrite[],
  /** 値のほかに伏せる秘密(http ドライバの統合トークン — 応答に echo されうる)。 */
  tokens: readonly Redacted.Redacted<string>[] = [],
): string[] {
  let text = output;
  const fragments = new Set<string>();
  for (const token of tokens) {
    // 剥がす理由: 出力からの伏せ字化(トークンの断片を探して置き換える。産物には残らない)
    const secret = Redacted.value(token);
    if (secret.length > 0) {
      fragments.add(secret);
      fragments.add(JSON.stringify(secret).slice(1, -1));
    }
  }
  for (const write of values) {
    // 剥がす理由: 出力からの伏せ字化(値の断片を探して置き換える。産物には残らない)
    const plaintext = decodeValueText(Redacted.value(write.value));
    if (plaintext === null) {
      continue;
    }
    for (const fragment of [plaintext, ...plaintext.split(/\r?\n/)]) {
      if (fragment.length === 0) {
        continue;
      }
      fragments.add(fragment);
      // wrangler は JSON を受け取るので、失敗時に本文を echo すると値は JSON
      // 文字列として(`\"` / `\\` / `\n` に逃がされて)現れる(Bugbot 指摘)。
      // 逃がした形も断片に加える(素の形と同じなら集合が吸収する)
      fragments.add(JSON.stringify(fragment).slice(1, -1));
    }
  }
  // 長い断片から置換する(短い断片が長い断片の一部を先に潰して取りこぼさない)
  for (const fragment of [...fragments].toSorted((a, b) => b.length - a.length)) {
    text = text.split(fragment).join("[redacted]");
  }
  const lines = keepTail(text, SHOWN_TAIL_CHARS)
    .split(/\r?\n/)
    .filter((line) => line.length > 0);
  return lines.slice(-SHOWN_TAIL_LINES).map((line) => displayText(line));
}
