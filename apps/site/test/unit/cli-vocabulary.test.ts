import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const siteRoot = join(import.meta.dirname, "..", "..");
const repoRoot = join(siteRoot, "..", "..");
const help = readFileSync(join(repoRoot, "apps", "cli", "test", "golden", "help.txt"), "utf8");

interface CommandSpec {
  readonly flags: ReadonlySet<string>;
  readonly valuedFlags: ReadonlySet<string>;
  readonly isGroup: boolean;
  readonly requiredArgs: number;
}

const defined = (value: string | undefined): value is string => value !== undefined;

function parseSection(lines: readonly string[]): CommandSpec {
  const flags = lines.map((line) => /^\s+(--[a-z][a-z-]*)/.exec(line)?.[1]).filter(defined);
  const isGroup = lines.includes("SUBCOMMANDS") && !lines.includes("ARGUMENTS");
  return {
    flags: new Set(flags),
    valuedFlags: new Set(lines.map(valuedFlagOf).filter(defined)),
    isGroup,
    requiredArgs: requiredArgsOf(lines),
  };
}

function valuedFlagOf(line: string): string | undefined {
  return /^\s+(--[a-z][a-z-]*)(?:, -[a-z])?\s+[a-z]+\s{2,}/.exec(line)?.[1];
}

function requiredArgsOf(lines: readonly string[]): number {
  const usage = lines[lines.indexOf("USAGE") + 1] ?? "";
  const [beforeSeparator = ""] = usage.split(" -- ");
  return [...beforeSeparator.replace(/\[[^\]]*\]/g, "").matchAll(/<[^>]+>/g)].length;
}

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
const pages = readdirSync(join(siteRoot, "src", "content", "docs")).filter((name) =>
  name.endsWith(".mdx"),
);

const pageText = (page: string): string =>
  readFileSync(join(siteRoot, "src", "content", "docs", page), "utf8");

function shellBlocks(markdown: string): string[] {
  return [...markdown.matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");
}

function codeLines(markdown: string): string[] {
  const spans = [...markdown.matchAll(/`([^`\n]+)`/g)].map((m) => m[1] ?? "");
  return [...shellBlocks(markdown).flatMap((block) => block.split("\n")), ...spans];
}

interface Invocation {
  readonly path: string;
  readonly rest: readonly string[];
  readonly flags: readonly string[];
  readonly tokens: readonly string[];
}

function resolvePath(words: readonly string[]): { path: string; rest: string[] } {
  for (let n = words.length; n > 0; n--) {
    const candidate = words.slice(0, n).join(" ");
    if (commands.has(candidate)) return { path: candidate, rest: words.slice(n) };
  }
  return { path: words[0] ?? "", rest: [] };
}

function until(tokens: readonly string[], stop: number): readonly string[] {
  return stop === -1 ? tokens : tokens.slice(0, stop);
}

function flagsBeforeSeparator(tokens: readonly string[]): string[] {
  return until(tokens, tokens.indexOf("--"))
    .map((token) => /^(--[a-z][a-z-]*)/.exec(token)?.[1])
    .filter(defined);
}

function leadingWords(tokens: readonly string[]): readonly string[] {
  return until(
    tokens,
    tokens.findIndex((token) => !/^[a-z][a-z-]*$/.test(token)),
  );
}

function parseSegment(segment: string): Invocation | null {
  const call = /^\s*(?:\$ ?)?maruhi\b(.*)$/.exec(segment);
  if (call === null) return null;
  const tokens = (call[1] ?? "").trim().split(/\s+/).filter(Boolean);
  const words = leadingWords(tokens);
  if (words.length === 0) return null;
  const resolved = resolvePath(words);
  const pathLength = resolved.path.split(" ").length;
  return { ...resolved, flags: flagsBeforeSeparator(tokens), tokens: tokens.slice(pathLength) };
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

function problemsOf(call: Invocation): string[] {
  const spec = commands.get(call.path);
  if (spec === undefined) return [`maruhi ${call.path} (no such command)`];
  const strayWord = spec.isGroup ? call.rest[0] : undefined;
  if (strayWord !== undefined) return [`maruhi ${call.path} ${strayWord} (no such subcommand)`];
  return unknownFlags(call, spec);
}

function positionalCount(call: Invocation, spec: CommandSpec): number {
  const words = until(call.tokens, call.tokens.findIndex(endsArguments));
  const flagValues = new Set(
    words.flatMap((word, i) => (spec.valuedFlags.has(word) ? [i + 1] : [])),
  );
  return words.filter((word, i) => !word.startsWith("--") && !flagValues.has(i)).length;
}

function endsArguments(token: string): boolean {
  return token === "--" || token === "\\" || token.startsWith("#");
}

function missingArguments(markdown: string): string[] {
  const calls = shellBlocks(markdown)
    .flatMap((block) => block.split("\n"))
    .flatMap(invocations);
  const problems = calls.flatMap((call) => {
    const spec = commands.get(call.path);
    if (spec === undefined || spec.isGroup) return [];
    return positionalCount(call, spec) < spec.requiredArgs
      ? [`maruhi ${call.path} (missing a required argument)`]
      : [];
  });
  return [...new Set(problems)];
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

  it("indexes required arguments and flags that take a value", () => {
    const required = ["env create", "env diff", "member add", "run"].map(
      (path) => commands.get(path)?.requiredArgs,
    );
    expect(required).toEqual([1, 2, 0, 0]);
    const push = commands.get("push")?.valuedFlags ?? new Set<string>();
    expect([push.has("--env"), push.has("--no-sync")]).toEqual([true, false]);
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
    expect(vocabularyProblems("`a person runs maruhi at an interactive terminal`")).toEqual([]);
  });

  it.each(pages)("%s gives every shell example its required arguments", (page) => {
    expect(missingArguments(pageText(page))).toEqual([]);
  });

  it("catches a shell example without its required argument", () => {
    expect(missingArguments("```sh\nmaruhi env create\n```")).toEqual([
      "maruhi env create (missing a required argument)",
    ]);
    expect(missingArguments("```sh\nmaruhi env create --project abc\n```")).toEqual([
      "maruhi env create (missing a required argument)",
    ]);
    expect(missingArguments("```sh\nmaruhi env create dev # comment\n```")).toEqual([]);
    expect(missingArguments("run `maruhi env create` first")).toEqual([]);
  });
});

describe("the docs keep the device-key vocabulary and coverage", () => {
  const devices = pageText("devices.mdx");

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

  it.each([
    ["fingerprint not reported", "OverviewMembers.tsx"],
    ["as reported by the server", "DevicesScreen.tsx"],
    ["Lost a device?", "DevicesScreen.tsx"],
  ])("quotes %s as the dashboard has it", (phrase, file) => {
    const source = readFileSync(join(repoRoot, "apps", "web", "src", "dashboard", file), "utf8");
    expect(source).toContain(phrase);
    expect(devices).toContain(phrase);
  });

  it.each([...pages, "apps/cli/test/golden/help.txt"])(
    "%s does not fall back to the pre-device-key vocabulary",
    (page) => {
      const text = page.endsWith(".mdx") ? pageText(page) : help;
      expect([...text.matchAll(/master key/gi)].length).toBe(0);
    },
  );

  it("states who can place a device-add request with the same words as `device approve`", () => {
    const source = readFileSync(
      join(repoRoot, "apps", "cli", "src", "device.package", "device-approve.ts"),
      "utf8",
    );
    expect(source).toContain("account-wide admin API token");
    expect(devices).toContain("account-wide admin API token");
  });

  it("quotes the note that a failed registry write leaves the request in place", () => {
    const source = readFileSync(
      join(repoRoot, "apps", "cli", "src", "device.package", "device-approve.ts"),
      "utf8",
    );
    expect(source).toContain("The request is left in place until");
    expect(source).toContain("will not see the completion signal");
    expect(devices).toContain(
      "… will not see the completion signal. The request is left in place until …",
    );
  });

  it("keeps the ledger-changing enumeration free of an opening material", () => {
    const listings = pages.flatMap((page) =>
      pageText(page)
        .split(/(?<=[.:])\s+/)
        .filter((sentence) => sentence.includes("designating guardians")),
    );
    expect(listings.length).toBeGreaterThan(0);
    expect(listings.filter((sentence) => /with the code|or a passkey/.test(sentence))).toEqual([]);
  });

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

describe("devices.mdx quotes CLI messages as the CLI prints them", () => {
  const cliDir = join(repoRoot, "apps", "cli", "src");
  const cliSource = readdirSync(cliDir, { recursive: true, encoding: "utf8" })
    .filter((name) => name.endsWith(".ts"))
    .map((name) => readFileSync(join(cliDir, name), "utf8"))
    .join("\n")
    .replaceAll("\\`", "")
    .replaceAll("`", "");
  const MIN_FRAGMENT = 12;

  interface Quote {
    readonly quote: string;
    readonly fragments: readonly string[];
  }

  function quotesOf(markdown: string): Quote[] {
    return [...markdown.matchAll(/^- \*\*`([^`]+)`\*\*/gm)].map((match) => {
      const quote = match[1] ?? "";
      const fragments = quote
        .split("…")
        .map((fragment) => fragment.trim())
        .filter((fragment) => fragment.length >= MIN_FRAGMENT);
      return { quote, fragments };
    });
  }

  function unquotable(quotes: readonly Quote[]): string[] {
    return quotes.flatMap(({ quote, fragments }) =>
      fragments.length === 0
        ? [`${quote} (no fragment of ${MIN_FRAGMENT}+ characters)`]
        : fragments
            .filter((fragment) => !cliSource.includes(fragment))
            .map((f) => `${quote}: ${f}`),
    );
  }

  const quotes = quotesOf(pageText("devices.mdx"));

  it("collects the quoted messages", () => {
    expect(quotes.length).toBeGreaterThanOrEqual(10);
  });

  it("finds every quoted fragment in the CLI source", () => {
    expect(unquotable(quotes)).toEqual([]);
  });

  it("catches a paraphrased quote and a quote too short to check", () => {
    expect(unquotable(quotesOf("- **`No pending request matches that fingerprint …`**."))).toEqual([
      "No pending request matches that fingerprint …: No pending request matches that fingerprint",
    ]);
    expect(unquotable(quotesOf("- **`… on …`**."))).toEqual([
      "… on … (no fragment of 12+ characters)",
    ]);
  });
});

interface Mention {
  readonly page: string;
  readonly phrase: string;
  readonly times?: number;
}

interface Limit {
  readonly file: string;
  readonly name: string;
  readonly value: string;
  readonly mentions: readonly Mention[];
}

const DEVICES_API = "packages/api-schema/src/devices-api.ts";
const DEVICE_CLI = "apps/cli/src/device.package/device-add.ts";
const KEY_WRAPS = "apps/server/src/db.package/key-wraps.ts";
const FIFTEEN_MINUTES = "15 * 60 * 1000";

const LIMITS: readonly Limit[] = [
  {
    file: "apps/server/src/policy.ts",
    name: "MAX_DEVICES_PER_MEMBER",
    value: "16",
    mentions: [
      { page: "devices.mdx", phrase: "16 active devices" },
      { page: "devices.mdx", phrase: "for that member (16)" },
    ],
  },
  {
    file: DEVICES_API,
    name: "MAX_DEVICE_ADD_REQUESTS_PER_HOUR",
    value: "5",
    mentions: [
      { page: "devices.mdx", phrase: "five device-add requests per hour" },
      {
        page: "linux-keychain.mdx",
        phrase: "five device-add requests per user per hour",
        times: 2,
      },
    ],
  },
  {
    file: DEVICES_API,
    name: "MAX_DEVICE_REGISTRY_ROWS_PER_USER",
    value: "32",
    mentions: [{ page: "devices.mdx", phrase: "32 rows" }],
  },
  {
    file: DEVICES_API,
    name: "DEVICE_ADD_REQUEST_TTL_MS",
    value: FIFTEEN_MINUTES,
    mentions: [
      { page: "devices.mdx", phrase: "The request lives 15 minutes" },
      { page: "devices.mdx", phrase: "Requests expire 15 minutes after" },
      { page: "devices.mdx", phrase: "five minutes after the request" },
    ],
  },
  {
    file: DEVICE_CLI,
    name: "DEVICE_ADD_WAIT_HINT_AFTER_MS",
    value: "DEVICE_ADD_REQUEST_TTL_MS / 3",
    mentions: [{ page: "devices.mdx", phrase: "five minutes after the request" }],
  },
  {
    file: "packages/api-schema/src/key-wraps-api.ts",
    name: "HANDOFF_REQUEST_TTL_MS",
    value: FIFTEEN_MINUTES,
    mentions: [{ page: "recover-your-key.mdx", phrase: "Requests expire after 15 minutes" }],
  },
  {
    file: KEY_WRAPS,
    name: "HANDOFF_REQUEST_LIMIT",
    value: "5",
    mentions: [
      { page: "recover-your-key.mdx", phrase: "Guardian handoff requests: five per user per hour" },
    ],
  },
  {
    file: KEY_WRAPS,
    name: "APPROVAL_LIMIT",
    value: "20",
    mentions: [{ page: "recover-your-key.mdx", phrase: "20 per user per hour" }],
  },
  {
    file: KEY_WRAPS,
    name: "KEY_BLOB_FETCH_LIMIT",
    value: "5",
    mentions: [
      {
        page: "recover-your-key.mdx",
        phrase: "five fetches of the sealed reserve key per user per hour",
      },
      { page: "recover-your-key.mdx", phrase: "guardian groups together): five per user per hour" },
      { page: "linux-keychain.mdx", phrase: "five fetches per hour", times: 2 },
    ],
  },
];

function constantOf(source: string, name: string): string | undefined {
  const match = new RegExp(`export const ${name}\\s*=\\s*([^;]+);`).exec(source);
  return match?.[1]?.trim();
}

function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

function countedMention(mention: Mention): { where: string; times: number } {
  return {
    where: `${mention.page}: ${mention.phrase}`,
    times: occurrences(pageText(mention.page), mention.phrase),
  };
}

describe("the documented limits match the constants that enforce them", () => {
  it.each(LIMITS.map((limit) => [limit.name, limit] as const))("%s", (_name, limit) => {
    const source = readFileSync(join(repoRoot, ...limit.file.split("/")), "utf8");
    expect(constantOf(source, limit.name)).toBe(limit.value);
    expect(limit.mentions.map(countedMention)).toEqual(
      limit.mentions.map((mention) => ({
        where: `${mention.page}: ${mention.phrase}`,
        times: mention.times ?? 1,
      })),
    );
  });
});
