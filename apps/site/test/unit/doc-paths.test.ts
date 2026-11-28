import { execSync } from "node:child_process";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const siteRoot = join(import.meta.dirname, "..", "..");
const repoRoot = join(siteRoot, "..", "..");

const tracked = execSync("git ls-files", { cwd: repoRoot, encoding: "utf8" }).trim().split("\n");
const trackedSet = new Set(tracked);
const basenameIndex = new Set(tracked.map((path) => basename(path)));

const EXT =
  "(?:mdx|tsx|jsx|mts|cts|mjs|cjs|jsonc|json|toml|yaml|yml|html|sql|txt|pem|age|lock|css|sh|md|ts|js)";
const SEG = "[A-Za-z0-9_@+~-]+";
const TOKEN = new RegExp(
  `(?<![\\w.~/-])(?:\\.{1,2}/|\\.${SEG}/|${SEG}(?:\\.${SEG})*/)${SEG}(?:[./]${SEG})*\\.${EXT}\\b` +
    `|(?<![\\w./~@-])(?:\\.{1,2}/)?${SEG}(?:\\.${SEG})*\\.${EXT}\\b`,
  "g",
);

const PATH_RUN = "[A-Za-z0-9_@+~./-]*";
const BRACE_GROUP = `\\{(?=[^{}]*[A-Za-z])${PATH_RUN}(?:,${PATH_RUN})+\\}`;
const BRACE_WORD = new RegExp(
  `(?<![A-Za-z0-9_@+~./$\\\\-])(?:${PATH_RUN}${BRACE_GROUP})+${PATH_RUN}`,
  "g",
);

function expandWord(word: string): readonly string[] {
  const group = /^([^{]*)\{([^{}]*)\}(.*)$/.exec(word);
  if (group === null) {
    return [word];
  }
  const [, prefix = "", items = "", suffix = ""] = group;
  return items.split(",").flatMap((item) => expandWord(`${prefix}${item}${suffix}`));
}

function expandBraces(text: string): string {
  return text.replace(BRACE_WORD, (word) => expandWord(word).join(" "));
}

const ALLOWED: Readonly<Record<string, string>> = {
  "args.test.ts": "former test file name (its cases moved)",
  "data-programs.ts": "the former pre-split file, referenced as history",
  "worker-not-found-error.ts": "a source file inside wrangler, referenced by name",
  "english.txt": "the upstream BIP39 wordlist file name (embedded in bip39-english.ts)",
  "Node.js": "the product name, not a file",
  "./app.js": "a page asset the passkey listener serves at runtime",
  "./config.json": "a page asset the passkey listener serves at runtime",
  "config.json": "the on-disk config file name (a runtime artifact)",
  "known-fingerprints.json": "the on-disk ledger file name (a runtime artifact)",
  "own-devices.json": "the on-disk ledger file name (a runtime artifact)",
  "devcontainer.json": "a generated devcontainer config name",
  "job.json": "a scratch file in a documented operator procedure",
  "d1.sql": "the operator-side decrypted dump file in a documented procedure",
  "d1.ordered.sql": "the operator-side reordered dump file in a documented procedure",
  "maruhi.proxy.json": "the user-side proxy config file name",
  "maruhi.rotate.json": "the user-side rotation config file name",
  "maruhi.sync.json": "the user-side sync config file name",
  "maruhi-sync.yml": "a workflow filename for the user's repository",
  "lease-policy.json": "the lease policy file name in a documented example",
  "maruhi-install.sh": "the downloaded installer script name",
  "checksums.txt": "a build artifact of the release process",
  "apps/cli/dist/checksums.txt": "a build artifact of the release process",
  ".maruhi/anchor.json": "the on-disk anchor file name (a runtime artifact)",
  ".netlify/state.json": "the vendor CLI's state file name",
  ".cursor/mcp.json": "the MCP host's config file name",
  "project.json": "a deepsec working file name",
  ".github/workflows/deploy.yml": "a workflow example for the user's repository",
  ".github/workflows/maruhi-sync.yml": "a workflow example for the user's repository",
  ".github/workflows/rotate-stripe.yml": "a workflow example for the user's repository",
  ".github/workflows/rotate.yml": "a workflow example for the user's repository",
  ".github/workflows/rotation-check.yml": "a workflow example for the user's repository",
  ".github/workflows/test.yml": "a workflow example for the user's repository",
  "./scripts/finalize-stripe.sh": "a user-repository script in a documented example",
  "./scripts/rotate-stripe.sh": "a user-repository script in a documented example",
  "scripts/finalize-stripe.sh": "a user-repository script in a documented example",
  "scripts/rotate-stripe.sh": "a user-repository script in a documented example",
  "import/acme.identities.json": "an object key in the documented import procedure",
  "acme.ndjson.gz.identities.json": "an object key in the documented import procedure",
  "restore/jobs/import-acme.json": "an object key in the documented restore procedure",
  "restore/jobs/job-1.json": "an object key in the documented restore procedure",
  "restore/results/import-acme.json": "an object key in the documented restore procedure",
  "restore/results/job-1.json": "an object key in the documented restore procedure",
  ".package/command.ts": "a template path — `<domain>` stands for the package name",
  ".deepsec/node_modules/deepsec/SKILL.md": "a file inside the deepsec tool's own directory",
  ".deepsec/node_modules/deepsec/dist/docs/writing-matchers.md":
    "a file inside the deepsec tool's own directory",
};

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      walk(path, out);
    } else {
      out.push(path);
    }
  }
  return out;
}

function targetDocs(): readonly string[] {
  const rootDocs = readdirSync(join(repoRoot, "docs"))
    .filter(
      (name) =>
        name.endsWith(".md") && !name.startsWith("DEEPSEC_FINDINGS_") && !/_REVIEW_/.test(name),
    )
    .map((name) => join("docs", name));
  const siteDocs = walk(join(repoRoot, "apps", "site", "src", "content", "docs")).map((path) =>
    path.slice(repoRoot.length + 1),
  );
  return ["CLAUDE.md", "AGENTS.md", "README.md", "CONTRIBUTING.md", ...rootDocs, ...siteDocs];
}

function targetSources(): readonly string[] {
  return ["apps", "packages"].flatMap((root) =>
    readdirSync(join(repoRoot, root)).flatMap((project) => {
      const srcDir = join(repoRoot, root, project, "src");
      if (!existsSync(srcDir)) {
        return [];
      }
      return walk(srcDir)
        .filter((path) => path.endsWith(".ts") || path.endsWith(".tsx"))
        .map((path) => path.slice(repoRoot.length + 1));
    }),
  );
}

function commentsOf(source: string): string {
  const noUrls = source.replace(/https?:\/\/\S+/g, " ");
  return [
    ...[...noUrls.matchAll(/\/\/[^\n]*/g)].map((match) => match[0]),
    ...[...noUrls.matchAll(/\/\*[\s\S]*?\*\//g)].map((match) => match[0]),
  ].join("\n");
}

interface Miss {
  readonly file: string;
  readonly token: string;
}

let extracted = 0;
const misses = new Map<string, Miss>();

function relPathMiss(file: string, token: string): boolean {
  const resolved = resolve(dirname(join(repoRoot, file)), token).slice(repoRoot.length + 1);
  return !trackedSet.has(resolved);
}

function slashPathMiss(token: string): boolean {
  return !trackedSet.has(token) && !tracked.some((path) => path.endsWith(`/${token}`));
}

function isMiss(file: string, token: string): boolean {
  if (token.startsWith("./") || token.startsWith("../")) {
    return relPathMiss(file, token);
  }
  if (token.includes("/")) {
    return slashPathMiss(token);
  }
  return !basenameIndex.has(token);
}

function skippable(token: string): boolean {
  return token.includes("*") || ALLOWED[token] !== undefined;
}

function checkedTokens(text: string): readonly string[] {
  const noUrls = expandBraces(text.replace(/https?:\/\/\S+/g, " "));
  return [...noUrls.matchAll(TOKEN)].map((match) => match[0]).filter((token) => !skippable(token));
}

function missesIn(file: string, text: string): readonly string[] {
  return checkedTokens(text).filter((token) => isMiss(file, token));
}

function scanTokens(file: string, text: string): void {
  const tokens = checkedTokens(text);
  extracted += tokens.length;
  for (const token of tokens) {
    if (isMiss(file, token)) {
      misses.set(`${token} @ ${file}`, { file, token });
    }
  }
}

for (const file of targetDocs()) {
  scanTokens(file, readFileSync(join(repoRoot, file), "utf8"));
}
for (const file of targetSources()) {
  scanTokens(file, commentsOf(readFileSync(join(repoRoot, file), "utf8")));
}

describe("brace paths", () => {
  it("expands every alternative into its own path", () => {
    expect(expandBraces("apps/server/src/do/{chain-do,do-schema}.ts and src/{a,b}/{c,d}.ts")).toBe(
      "apps/server/src/do/chain-do.ts apps/server/src/do/do-schema.ts and src/a/c.ts src/a/d.ts src/b/c.ts src/b/d.ts",
    );
  });

  it("expands an empty alternative", () => {
    expect(expandBraces("src/foo{,.test}.ts")).toBe("src/foo.ts src/foo.test.ts");
  });

  it("leaves prose braces, quantifiers and template placeholders as they are", () => {
    const text =
      "{single}.ts {epoch, recipientUserId} [a-z]{0,63} x{1,3}.md \\w{2,4}.ts ${a,b}.ts {} {,}";
    expect(expandBraces(text)).toBe(text);
  });

  it("keeps a path that a quantifier follows", () => {
    expect(
      missesIn("CLAUDE.md", "apps/cli/src/bin.ts{1,2} apps/cli/src/no-such-file.ts{1,2}"),
    ).toEqual(["apps/cli/src/no-such-file.ts"]);
  });

  it("checks each expanded path against the tracked files", () => {
    expect(missesIn("CLAUDE.md", "apps/site/test/unit/{doc-paths,no-such-file}.test.ts")).toEqual([
      "apps/site/test/unit/no-such-file.test.ts",
    ]);
    expect(missesIn("CLAUDE.md", "apps/cli/src/{bin,cli}.ts")).toEqual([]);
    expect(missesIn("CLAUDE.md", "{bin,no-such-file}.ts")).toEqual(["no-such-file.ts"]);
  });
});

describe("file references in live docs and source comments", () => {
  it("extracts a real corpus (the check isn't idling — ≈500 tokens after the ADR-0020 comment removal)", () => {
    expect(extracted).toBeGreaterThan(400);
  });

  it("every file reference resolves to a tracked file", () => {
    const offenders = [...misses.values()].map((miss) => `${miss.file}: ${miss.token}`).toSorted();
    expect(offenders).toEqual([]);
  });
});
