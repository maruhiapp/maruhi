// docs が名乗る CLI の語彙(コマンド名・フラグ)が、CLI の help golden
// (`apps/cli/test/golden/help.txt` — 出荷されている字面の正)と一致することを固定する。
// ES K7-A / DK K6-O の原則「docs の語彙は CLI の help から写し、docs が名前を発明しない」を、
// 目視でなく構造で守る(DK K6-T: 真偽が機械で判定できる裁定は検査に落とす)。
//
// 検査するのは docs の ```sh ブロックとインラインコードに現れる `maruhi …` の呼び出しだけ:
//   1. コマンド経路(`maruhi device approve` 等)が help に存在すること
//   2. グループ(子コマンドを持つ経路)の後ろに来るのが子コマンドであること
//   3. 添えられた `--flag` が、その経路の FLAGS か GLOBAL FLAGS にあること
// 散文の主張(「コードかパスキーで開く」)は機械では捉えられないので、この検査の外
// (そこは K6-R の「規範の主張は 1 ページが持つ」で守る)。
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const siteRoot = join(import.meta.dirname, "..", "..");
const repoRoot = join(siteRoot, "..", "..");
const help = readFileSync(join(repoRoot, "apps", "cli", "test", "golden", "help.txt"), "utf8");

/** help の 1 節(`$ maruhi <path> --help` の中身)が宣言するフラグと、グループか否か。 */
interface CommandSpec {
  readonly flags: ReadonlySet<string>;
  /** 子コマンドを持ち、引数を取らない経路(`maruhi device` 等)。 */
  readonly isGroup: boolean;
}

const defined = (value: string | undefined): value is string => value !== undefined;

/** 節の中で `--flag` で始まる行は FLAGS / GLOBAL FLAGS のものだけ(他の節は語で始まる)。 */
function parseSection(lines: readonly string[]): CommandSpec {
  const flags = lines.map((line) => /^\s+(--[a-z][a-z-]*)/.exec(line)?.[1]).filter(defined);
  const isGroup = lines.includes("SUBCOMMANDS") && !lines.includes("ARGUMENTS");
  return { flags: new Set(flags), isGroup };
}

/** help golden の各節から、コマンド経路 → その宣言。 */
function helpIndex(text: string): ReadonlyMap<string, CommandSpec> {
  const index = new Map<string, CommandSpec>();
  for (const section of text.split(/^\$ maruhi ?/m).slice(1)) {
    const [header, ...rest] = section.split("\n");
    index.set((header ?? "").replace(/--help\s*$/, "").trim(), parseSection(rest));
  }
  return index;
}

const commands = helpIndex(help);
const globalFlags = new Set(["--help", "--version"]);
const pages = readdirSync(join(siteRoot, "docs")).filter((name) => name.endsWith(".mdx"));

const pageText = (page: string): string => readFileSync(join(siteRoot, "docs", page), "utf8");

/** ページの ```sh ブロック(中身)。 */
function shellBlocks(markdown: string): string[] {
  return [...markdown.matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");
}

/** ドキュメントのコード(```sh ブロックとインラインコード)を 1 行ずつ。 */
function codeLines(markdown: string): string[] {
  const spans = [...markdown.matchAll(/`([^`\n]+)`/g)].map((m) => m[1] ?? "");
  return [...shellBlocks(markdown).flatMap((block) => block.split("\n")), ...spans];
}

interface Invocation {
  readonly path: string;
  /** 経路の後ろに残った語(引数、またはグループの子コマンド)。 */
  readonly rest: readonly string[];
  readonly flags: readonly string[];
}

/** 経路 = help に存在する最長の前置(残りは引数: `config set server <url>` の `server` 等)。 */
function resolvePath(words: readonly string[]): { path: string; rest: string[] } {
  for (let n = words.length; n > 0; n--) {
    const candidate = words.slice(0, n).join(" ");
    if (commands.has(candidate)) return { path: candidate, rest: words.slice(n) };
  }
  return { path: words[0] ?? "", rest: [] };
}

/** `--`(run / agent の子コマンド区切り)までを見る。 */
function until(tokens: readonly string[], stop: number): readonly string[] {
  return stop === -1 ? tokens : tokens.slice(0, stop);
}

/** `--`(子コマンド区切り)より前のフラグ。 */
function flagsBeforeSeparator(tokens: readonly string[]): string[] {
  return until(tokens, tokens.indexOf("--"))
    .map((token) => /^(--[a-z][a-z-]*)/.exec(token)?.[1])
    .filter(defined);
}

/** 先頭から続く小文字の語(コマンド経路の候補。`<fp>` や `"MacBook"` で止まる)。 */
function leadingWords(tokens: readonly string[]): readonly string[] {
  return until(
    tokens,
    tokens.findIndex((token) => !/^[a-z][a-z-]*$/.test(token)),
  );
}

/**
 * 1 行に現れる `maruhi …` の呼び出し。呼び出しと見なすのは、行またはシェルの連結の
 * **先頭**にある `maruhi`(`$ ` の後も可)だけ: 散文の中の語("runs maruhi at an
 * interactive terminal" — CLI の文言の引用)は対象にしない。
 */
function parseSegment(segment: string): Invocation | null {
  const call = /^\s*(?:\$ ?)?maruhi\b(.*)$/.exec(segment);
  if (call === null) return null;
  const tokens = (call[1] ?? "").trim().split(/\s+/).filter(Boolean);
  const words = leadingWords(tokens);
  if (words.length === 0) return null;
  return { ...resolvePath(words), flags: flagsBeforeSeparator(tokens) };
}

function invocations(line: string): Invocation[] {
  return line
    .split(/&&|\|\||[|;]/)
    .map(parseSegment)
    .filter((call): call is Invocation => call !== null);
}

function unknownFlags(call: Invocation, spec: CommandSpec): string[] {
  const unknown = call.flags.filter((flag) => !spec.flags.has(flag) && !globalFlags.has(flag));
  return unknown.map((flag) => `maruhi ${call.path} ${flag} (no such flag)`);
}

/** 1 つの呼び出しが help と食い違う点(無ければ空)。 */
function problemsOf(call: Invocation): string[] {
  const spec = commands.get(call.path);
  if (spec === undefined) return [`maruhi ${call.path} (no such command)`];
  // グループの後ろに来られるのは子コマンドだけ(`maruhi device frobnicate` を捕らえる)
  const strayWord = spec.isGroup ? call.rest[0] : undefined;
  if (strayWord !== undefined) return [`maruhi ${call.path} ${strayWord} (no such subcommand)`];
  return unknownFlags(call, spec);
}

function vocabularyProblems(markdown: string): string[] {
  const problems = codeLines(markdown).flatMap((line) => invocations(line).flatMap(problemsOf));
  return [...new Set(problems)];
}

describe("docs quote the CLI vocabulary of apps/cli/test/golden/help.txt", () => {
  it("indexes the help golden", () => {
    expect(commands.size).toBeGreaterThan(40);
    expect(commands.get("device approve")?.flags).toContain("--cap");
    expect(commands.get("guardian add")?.flags.has("--passkey")).toBe(false);
    expect(commands.get("device")?.isGroup).toBe(true);
    expect(commands.get("device revoke")?.isGroup).toBe(false);
  });

  it.each(pages)("%s names only commands and flags the CLI has", (page) => {
    expect(vocabularyProblems(pageText(page))).toEqual([]);
  });

  it("catches an invented command, subcommand or flag", () => {
    expect(vocabularyProblems("```sh\nmaruhi device frobnicate\n```")).toEqual([
      "maruhi device frobnicate (no such subcommand)",
    ]);
    expect(vocabularyProblems("`maruhi guardian add --passkey`")).toEqual([
      "maruhi guardian add --passkey (no such flag)",
    ]);
    // 散文の中の `maruhi` は呼び出しではない(CLI の文言の引用)
    expect(vocabularyProblems("`a person runs maruhi at an interactive terminal`")).toEqual([]);
  });
});

// 以下は K6-T(裁定の構造への回し直し)で足した固定。いずれも「文言の点検」を検査に
// 置き換えるもので、対象は本 PR が主張していることだけ。
describe("the docs keep the device-key vocabulary and coverage", () => {
  const devices = pageText("devices.mdx");

  // K6-A: Devices のページは `device` / `token` グループと `key reserve` を網羅する
  // (グループの子コマンドが増えたら、このページに書くか裁定し直すこと)
  it.each(["device", "token", "key reserve"])(
    "devices.mdx covers every `%s` subcommand",
    (group) => {
      const depth = group.split(" ").length + 1;
      const subcommands = [...commands.keys()].filter(
        (path) => path.startsWith(`${group} `) && path.split(" ").length === depth,
      );
      expect(subcommands.length).toBeGreaterThan(0);
      expect(subcommands.filter((path) => !devices.includes(`maruhi ${path}`))).toEqual([]);
    },
  );

  // K6-D: ダッシュボードの文言は Web の実装から写す(言い換えない)
  it.each([
    ["fingerprint not reported", "ProjectScreen.tsx"],
    ["as reported by the server", "DevicesScreen.tsx"],
    ["Lost a device?", "DevicesScreen.tsx"],
  ])("quotes %s as the dashboard has it", (phrase, file) => {
    const source = readFileSync(join(repoRoot, "apps", "web", "src", "dashboard", file), "utf8");
    expect(source).toContain(phrase);
    expect(devices).toContain(phrase);
  });

  // K6-H: 端末鍵以後の語彙。`master key` が残ってよいのは、CLI の `maruhi agent` の
  // help がまだその語を使っていることを断る 1 か所だけ(help が改まったらここも直す)
  it.each(pages)("%s does not fall back to the pre-device-key vocabulary", (page) => {
    const hits = [...pageText(page).matchAll(/master key/gi)].length;
    expect(hits).toBe(page === "linux-keychain.mdx" ? 1 : 0);
  });

  // K6-U: 台帳を変えるコマンドの列挙(`designating guardians` を含む文)は、開封の材料を
  // 名乗らない。`maruhi guardian add` は `--passkey` を受けないので、この列挙に材料を足すと
  // 必ず嘘になる(同じ誤りが devices / recover の両ページで出た — K6-R の原則の機械化)。
  // 列挙の文が 1 つも無ければ検査は空虚になるので、存在も固定する(言い回しを変えるなら
  // この pin も一緒に直す — 無関係な編集で静かに失われないように)
  it("keeps the ledger-changing enumeration free of an opening material", () => {
    const listings = pages.flatMap((page) =>
      pageText(page)
        .split(/(?<=[.:])\s+/)
        .filter((sentence) => sentence.includes("designating guardians")),
    );
    expect(listings.length).toBeGreaterThan(0);
    expect(listings.filter((sentence) => /with the code|or a passkey/.test(sentence))).toEqual([]);
  });

  // K6-L: `recipes.test.ts` が実行するのは deploy-targets.mdx のブロックだけ。
  // 他のページの ```sh がその形に偶然一致しないこと(一致させるなら検査対象に加える)
  it.each(pages.filter((page) => page !== "deploy-targets.mdx"))(
    "%s has no block that recipes.test.ts would execute",
    (page) => {
      const recipes = shellBlocks(pageText(page)).filter((block) =>
        block.startsWith("maruhi run --env production -- "),
      );
      expect(recipes).toEqual([]);
    },
  );
});

// K6-Y: docs が書く上限・レート制限・TTL を、定義側の定数に釘で留める。値が変われば
// この検査が落ち、docs と一緒に直すことになる(数値は語彙と同じく「写す」もの —
// K7-A。ES K7 では目視で写していた)。同じ数値を複数ページが写すので、釘は
// (定数, ページ × 語句) の対で持つ(1 ページだけ留めると他ページの写しが野放しになる)。
interface Limit {
  readonly file: string;
  readonly name: string;
  /** `export const <name> = <rhs>;` の右辺の字面(`15 * 60 * 1000` を「15 分」と読めるまま留める)。 */
  readonly value: string;
  readonly mentions: ReadonlyArray<readonly [page: string, phrase: string]>;
}

const DEVICES_API = "packages/api-schema/src/devices-api.ts";
const KEY_WRAPS = "apps/server/src/db.package/key-wraps.ts";
const FIFTEEN_MINUTES = "15 * 60 * 1000";

const LIMITS: readonly Limit[] = [
  {
    file: "apps/server/src/policy.ts",
    name: "MAX_DEVICES_PER_MEMBER",
    value: "16",
    mentions: [["devices.mdx", "16 active devices"]],
  },
  {
    file: DEVICES_API,
    name: "MAX_DEVICE_ADD_REQUESTS_PER_HOUR",
    value: "5",
    mentions: [
      ["devices.mdx", "five device-add requests per hour"],
      ["linux-keychain.mdx", "five device-add requests per user per hour"],
    ],
  },
  {
    file: DEVICES_API,
    name: "MAX_DEVICE_REGISTRY_ROWS_PER_USER",
    value: "32",
    mentions: [["devices.mdx", "32 rows"]],
  },
  {
    file: DEVICES_API,
    name: "DEVICE_ADD_REQUEST_TTL_MS",
    value: FIFTEEN_MINUTES,
    mentions: [
      ["devices.mdx", "The request lives 15 minutes"],
      ["devices.mdx", "Requests expire 15 minutes after"],
    ],
  },
  {
    file: "packages/api-schema/src/key-wraps-api.ts",
    name: "HANDOFF_REQUEST_TTL_MS",
    value: FIFTEEN_MINUTES,
    mentions: [["recover-your-key.mdx", "Requests expire after 15 minutes"]],
  },
  {
    file: KEY_WRAPS,
    name: "HANDOFF_REQUEST_LIMIT",
    value: "5",
    mentions: [["recover-your-key.mdx", "five per user per hour"]],
  },
  {
    file: KEY_WRAPS,
    name: "APPROVAL_LIMIT",
    value: "20",
    mentions: [["recover-your-key.mdx", "20 per user per hour"]],
  },
  {
    file: KEY_WRAPS,
    name: "KEY_BLOB_FETCH_LIMIT",
    value: "5",
    mentions: [
      ["recover-your-key.mdx", "five fetches of the sealed reserve key per user per hour"],
      ["linux-keychain.mdx", "five fetches per hour"],
    ],
  },
];

/** `export const NAME = <rhs>;` の右辺(そのままの字面)。 */
function constantOf(source: string, name: string): string | undefined {
  const match = new RegExp(`export const ${name}\\s*=\\s*([^;]+);`).exec(source);
  return match?.[1]?.trim();
}

describe("the documented limits match the constants that enforce them", () => {
  it.each(LIMITS.map((limit) => [limit.name, limit] as const))("%s", (_name, limit) => {
    const source = readFileSync(join(repoRoot, ...limit.file.split("/")), "utf8");
    expect(constantOf(source, limit.name)).toBe(limit.value);
    const missing = limit.mentions.filter(([page, phrase]) => !pageText(page).includes(phrase));
    expect(missing).toEqual([]);
  });
});
