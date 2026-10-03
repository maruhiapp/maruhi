// Pins that the CLI vocabulary (command names, flags) the docs cite matches
// the CLI's help golden (`apps/cli/test/golden/help.txt` — the canonical
// shipped text). The ES K7-A / DK K6-O principle "docs copy their vocabulary
// from the CLI help; docs invent no names" is enforced structurally rather
// than by eye (DK K6-T: a ruling whose truth a machine can decide becomes a
// check).
//
// Only `maruhi …` invocations appearing in docs' ```sh blocks and inline
// code are checked:
//   1. the command path (`maruhi device approve` etc.) exists in help
//   2. what follows a group (a path that has subcommands) is a subcommand
//   3. each attached `--flag` is in that path's FLAGS or GLOBAL FLAGS
//   4. each ```sh block invocation carries as many required positional
//      arguments as USAGE declares (`<environment-id>` etc.) (inline code is
//      out of scope — it may name only the command inside prose. Pins the
//      regression where getting-started shipped `maruhi env create` with no
//      argument)
// Claims in prose ("opens with a code or a passkey") cannot be captured
// mechanically, so they are outside this check (that is covered by K6-R's
// "one page owns each normative claim").
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const siteRoot = join(import.meta.dirname, "..", "..");
const repoRoot = join(siteRoot, "..", "..");
const help = readFileSync(join(repoRoot, "apps", "cli", "test", "golden", "help.txt"), "utf8");

/** The flags one help section (the body of `$ maruhi <path> --help`) declares, and whether it is a group. */
interface CommandSpec {
  readonly flags: ReadonlySet<string>;
  /** Flags that take a value (`--project string` etc. — the next word is the flag's value, not a positional argument). */
  readonly valuedFlags: ReadonlySet<string>;
  /** A path that has subcommands and takes no arguments (`maruhi device` etc.). */
  readonly isGroup: boolean;
  /** The number of required positional arguments on the USAGE line (inside `[...]` and after `--` do not count). */
  readonly requiredArgs: number;
}

const defined = (value: string | undefined): value is string => value !== undefined;

/** Within a section, lines starting with `--flag` belong only to FLAGS / GLOBAL FLAGS (other sections start with a word). */
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

/** Among FLAGS lines, the flags that take a value, marked by a type name (`string` etc.). */
function valuedFlagOf(line: string): string | undefined {
  return /^\s+(--[a-z][a-z-]*)(?:, -[a-z])?\s+[a-z]+\s{2,}/.exec(line)?.[1];
}

/** The `<…>` on the USAGE line that sit outside `[...]` and before `--`. */
function requiredArgsOf(lines: readonly string[]): number {
  const usage = lines[lines.indexOf("USAGE") + 1] ?? "";
  const [beforeSeparator = ""] = usage.split(" -- ");
  return [...beforeSeparator.replace(/\[[^\]]*\]/g, "").matchAll(/<[^>]+>/g)].length;
}

/** From each help-golden section, command path → its declaration. */
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

/** A page's ```sh blocks (contents). */
function shellBlocks(markdown: string): string[] {
  return [...markdown.matchAll(/```[a-z]*\n([\s\S]*?)```/g)].map((m) => m[1] ?? "");
}

/** The document's code (```sh blocks and inline code), one line at a time. */
function codeLines(markdown: string): string[] {
  const spans = [...markdown.matchAll(/`([^`\n]+)`/g)].map((m) => m[1] ?? "");
  return [...shellBlocks(markdown).flatMap((block) => block.split("\n")), ...spans];
}

interface Invocation {
  readonly path: string;
  /** Words left after the path (arguments, or a group's subcommand). */
  readonly rest: readonly string[];
  readonly flags: readonly string[];
  /** Words after the path and before `--` that are neither a flag nor a flag's value (positional-argument candidates). */
  readonly tokens: readonly string[];
}

/** The path is the longest leading prefix that exists in help (the rest are arguments: `server` in `config set server <url>` etc.). */
function resolvePath(words: readonly string[]): { path: string; rest: string[] } {
  for (let n = words.length; n > 0; n--) {
    const candidate = words.slice(0, n).join(" ");
    if (commands.has(candidate)) return { path: candidate, rest: words.slice(n) };
  }
  return { path: words[0] ?? "", rest: [] };
}

/** Look only up to `--` (the subcommand separator of run / agent). */
function until(tokens: readonly string[], stop: number): readonly string[] {
  return stop === -1 ? tokens : tokens.slice(0, stop);
}

/** Flags before `--` (the subcommand separator). */
function flagsBeforeSeparator(tokens: readonly string[]): string[] {
  return until(tokens, tokens.indexOf("--"))
    .map((token) => /^(--[a-z][a-z-]*)/.exec(token)?.[1])
    .filter(defined);
}

/** The leading run of lowercase words (command-path candidates; stops at `<fp>` or `"MacBook"`). */
function leadingWords(tokens: readonly string[]): readonly string[] {
  return until(
    tokens,
    tokens.findIndex((token) => !/^[a-z][a-z-]*$/.test(token)),
  );
}

/**
 * The `maruhi …` invocations appearing on one line. Only a `maruhi` at the
 * **start** of a line or a shell conjunction (after `$ ` is fine) counts as
 * an invocation: the word inside prose ("runs maruhi at an interactive
 * terminal" — quoting the CLI's wording) is not a target.
 */
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

/** The points where one invocation disagrees with help (empty if none). */
function problemsOf(call: Invocation): string[] {
  const spec = commands.get(call.path);
  if (spec === undefined) return [`maruhi ${call.path} (no such command)`];
  // Only a subcommand may follow a group (catches `maruhi device frobnicate`)
  const strayWord = spec.isGroup ? call.rest[0] : undefined;
  if (strayWord !== undefined) return [`maruhi ${call.path} ${strayWord} (no such subcommand)`];
  return unknownFlags(call, spec);
}

/** The number of positional arguments (stops at a `#` comment, a line-continuation `\`, or `--`; flags and their values do not count). */
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

/** The points where ```sh block invocations miss USAGE's required positional arguments (empty if none). */
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
    // `maruhi` inside prose is not an invocation (quoting the CLI's wording)
    expect(vocabularyProblems("`a person runs maruhi at an interactive terminal`")).toEqual([]);
  });

  it.each(pages)("%s gives every shell example its required arguments", (page) => {
    expect(missingArguments(pageText(page))).toEqual([]);
  });

  it("catches a shell example without its required argument", () => {
    expect(missingArguments("```sh\nmaruhi env create\n```")).toEqual([
      "maruhi env create (missing a required argument)",
    ]);
    // A flag's value does not count as a positional argument
    expect(missingArguments("```sh\nmaruhi env create --project abc\n```")).toEqual([
      "maruhi env create (missing a required argument)",
    ]);
    expect(missingArguments("```sh\nmaruhi env create dev # comment\n```")).toEqual([]);
    // Inline code is out of scope (prose naming only the command)
    expect(missingArguments("run `maruhi env create` first")).toEqual([]);
  });
});

// The following pins were added in K6-T (converting rulings into
// structure). Each replaces "checking the wording" with a check, and the
// target is only what this PR asserts.
describe("the docs keep the device-key vocabulary and coverage", () => {
  const devices = pageText("devices.mdx");

  // K6-A: the Devices page covers the `device` / `token` groups and
  // `key reserve` (if a group gains subcommands, either write them on this
  // page or re-rule)
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

  // K6-D: dashboard wording is copied from the web implementation (no
  // paraphrasing)
  it.each([
    ["fingerprint not reported", "ProjectScreen.tsx"],
    ["as reported by the server", "DevicesScreen.tsx"],
    ["Lost a device?", "DevicesScreen.tsx"],
  ])("quotes %s as the dashboard has it", (phrase, file) => {
    const source = readFileSync(join(repoRoot, "apps", "web", "src", "dashboard", file), "utf8");
    expect(source).toContain(phrase);
    expect(devices).toContain(phrase);
  });

  // K6-H / K7-5: the post-device-key vocabulary. No `master key` remains in
  // docs or in the CLI help (K7 rewrote the help of `maruhi agent` /
  // `--key-ttl`, so even K6's "one remaining note" is gone)
  it.each([...pages, "apps/cli/test/golden/help.txt"])(
    "%s does not fall back to the pre-device-key vocabulary",
    (page) => {
      const text = page.endsWith(".mdx") ? pageText(page) : help;
      expect([...text.matchAll(/master key/gi)].length).toBe(0);
    },
  );

  // K7-7: the discipline of a FP's provenance (only an account-wide admin
  // token can place a request — `ensureKeyMaterialAccess`) is an
  // unremovable duplication stated in its own words by both the docs and
  // `device approve`'s output, so the copied phrase is pinned on both
  it("states who can place a device-add request with the same words as `device approve`", () => {
    const source = readFileSync(join(repoRoot, "apps", "cli", "src", "device.ts"), "utf8");
    expect(source).toContain("account-wide admin API token");
    expect(devices).toContain("account-wide admin API token");
  });

  // DK K9-3: that a failed registry write leaves the request in place
  // (K9-1) is an unremovable duplication stated by both `device approve`'s
  // Note and the docs, so the Note phrase the docs quote is pinned on both
  // (rewording the Note would falsify the docs' quote)
  it("quotes the note that a failed registry write leaves the request in place", () => {
    const source = readFileSync(join(repoRoot, "apps", "cli", "src", "device.ts"), "utf8");
    expect(source).toContain("The request is left in place until");
    expect(source).toContain("will not see the completion signal");
    expect(devices).toContain(
      "… will not see the completion signal. The request is left in place until …",
    );
  });

  // K6-U: the enumeration of ledger-changing commands (sentences
  // containing `designating guardians`) names no opening material.
  // `maruhi guardian add` does not accept `--passkey`, so adding a material
  // to this enumeration is always a lie (the same mistake appeared on both
  // the devices and recover pages — mechanizing the K6-R principle).
  // With zero enumeration sentences the check is vacuous, so existence is
  // pinned too (if the phrasing changes, fix this pin with it — so an
  // unrelated edit cannot silently lose it)
  it("keeps the ledger-changing enumeration free of an opening material", () => {
    const listings = pages.flatMap((page) =>
      pageText(page)
        .split(/(?<=[.:])\s+/)
        .filter((sentence) => sentence.includes("designating guardians")),
    );
    expect(listings.length).toBeGreaterThan(0);
    expect(listings.filter((sentence) => /with the code|or a passkey/.test(sentence))).toEqual([]);
  });

  // K6-L: `recipes.test.ts` executes only deploy-targets.mdx's blocks.
  // No other page's ```sh may accidentally match that shape (if you make
  // one match, add it to the checked set)
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

// DK K10-6: devices.mdx's "What can go wrong" quotes the CLI's wording in
// the form `- \`…\`**. That each fragment of a quote split on `…` (12+
// characters) really exists in the CLI's wording (`apps/cli/src/*.ts` —
// the literal text minus backquotes) is pinned by netting the quote's
// shape itself rather than nailing each copy (a PR that changes the
// wording cannot leave the quote behind — the K9-9 shape). Vacuity (no
// quotes collected) and accidental matches (short fragments) are both
// denied inside the same check (K8-2). Other pages that quote examples
// with values filled in (environment-scopes / four-eyes) are out of scope.
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

  /** The `- \`…\`**` quotes and their `…`-split fragments (short fragments match by chance, so they do not count). */
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

// K6-Y: pins the limits, rate limits, and TTLs the docs write to the
// defining constants. If a value changes this check fails and the docs are
// fixed with it (numbers are copied just like vocabulary — K7-A).
// The pin is by **occurrence count** of the phrase (an existence check is
// satisfied by the first of duplicated sentences, and editing the second
// onward still passes green — K6-Y supplement 3). If the count changes,
// both the side that added a copy and the side that removed one fail, so
// future duplication cannot be born silently.
interface Mention {
  readonly page: string;
  readonly phrase: string;
  /** The number of times this phrase appears on the page (default 1). */
  readonly times?: number;
}

interface Limit {
  readonly file: string;
  readonly name: string;
  /** The literal right-hand side of `export const <name> = <rhs>;` (kept so `15 * 60 * 1000` still reads as "15 minutes"). */
  readonly value: string;
  readonly mentions: readonly Mention[];
}

const DEVICES_API = "packages/api-schema/src/devices-api.ts";
const DEVICE_CLI = "apps/cli/src/device.ts";
const KEY_WRAPS = "apps/server/src/db.package/key-wraps.ts";
const FIFTEEN_MINUTES = "15 * 60 * 1000";

const LIMITS: readonly Limit[] = [
  {
    file: "apps/server/src/policy.ts",
    name: "MAX_DEVICES_PER_MEMBER",
    value: "16",
    mentions: [
      { page: "devices.mdx", phrase: "16 active devices" },
      // A quote of the CLI wording that `failure.ts` fills with `${e.limit}` (a second copy of the same constant)
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
      // K7-15: the mid-wait guidance (TTL / 3) is also a copy of the TTL.
      // If the TTL changes, "five minutes" moves too (while the constant's
      // right-hand side stays symbolic, this pin alone holds it)
      { page: "devices.mdx", phrase: "five minutes after the request" },
    ],
  },
  {
    // K7-3: the mid-wait guidance (TTL / 3 = 5 minutes). The docs copy it
    // as "five minutes"
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
      // The summary section of the same page (the parentheses distinguish
      // it from the guardian-request section)
      { page: "recover-your-key.mdx", phrase: "guardian groups together): five per user per hour" },
      { page: "linux-keychain.mdx", phrase: "five fetches per hour", times: 2 },
    ],
  },
];

/** The right-hand side of `export const NAME = <rhs>;` (verbatim). */
function constantOf(source: string, name: string): string | undefined {
  const match = new RegExp(`export const ${name}\\s*=\\s*([^;]+);`).exec(source);
  return match?.[1]?.trim();
}

function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/** The phrase and its actual occurrence count (a mismatch with the expectation shows in the diff). */
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
