// File references in live documentation and source comments must resolve —
// a comment that names a file which no longer exists is a stale pointer
// (the drift file moves create). Two target sets:
//
//   A. Live documents: CLAUDE.md, AGENTS.md, README.md, CONTRIBUTING.md,
//      docs/*.md (except dated records — DEEPSEC_FINDINGS_* and
//      *_REVIEW_*, and docs/adr/ + docs/notes/ are not scanned at all),
//      and apps/site/docs/.
//   B. Comments (// and block) inside apps/*/src and packages/*/src.
//
// Token classes: a token containing "/" resolves as a repo path — either
// verbatim from the root, or as the trailing segment-set of any tracked
// file (covers package-relative mentions like `test-vectors/x.json` or
// `db.package/audit.ts`). A leading `./` or `../` resolves against the
// referring file's own directory. A bare filename must exist somewhere in
// the tracked tree. Everything is checked against `git ls-files` (the
// tracked tree — what a reader would find).
//
// An extractor that stops matching would report zero offenders while
// collecting zero tokens, so an under-count on the extracted total fails
// the check first (≈1.5k tokens at main 94d3b72).
//
// Legitimate references that are not repository files — runtime artifacts
// the product writes (ledgers, configs), object keys in the backup bucket,
// user-repository examples in the docs recipes, names of former files
// (kept as history), files inside external packages, and product names
// that happen to carry a file-like suffix — live in ALLOWED with a reason
// each.

import { execSync } from "node:child_process";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

const siteRoot = join(import.meta.dirname, "..", "..");
const repoRoot = join(siteRoot, "..", "..");

const tracked = execSync("git ls-files", { cwd: repoRoot, encoding: "utf8" }).trim().split("\n");
const trackedSet = new Set(tracked);
const basenameIndex = new Set(tracked.map((path) => basename(path)));

// Longest-first alternation + a trailing word boundary (so `x.md` cannot
// match inside `x.mdx`, nor `x.js` inside `x.json`). `.env`-suffixed
// tokens are environment-variable namespaces in practice, so `env` is
// deliberately absent.
const EXT =
  "(?:mdx|tsx|jsx|mts|cts|mjs|cjs|jsonc|json|toml|yaml|yml|html|sql|txt|pem|age|lock|css|sh|md|ts|js)";
const SEG = "[A-Za-z0-9_@+~-]+";
const TOKEN = new RegExp(
  `(?<![\\w.~/-])(?:\\.{1,2}/|\\.${SEG}/|${SEG}(?:\\.${SEG})*/)${SEG}(?:[./]${SEG})*\\.${EXT}\\b` +
    `|(?<![\\w./~@-])(?:\\.{1,2}/)?${SEG}(?:\\.${SEG})*\\.${EXT}\\b`,
  "g",
);

/** References that legitimately are not repository files (token → reason). */
const ALLOWED: Readonly<Record<string, string>> = {
  // Former names kept as history (the file was renamed/split)
  "args.test.ts": "former test file name (its cases moved)",
  "data-programs.ts": "the former pre-split file, referenced as history",
  // External packages' own files and the product's own name
  "worker-not-found-error.ts": "a source file inside wrangler, referenced by name",
  "english.txt": "the upstream BIP39 wordlist file name (embedded in bip39-english.ts)",
  "Node.js": "the product name, not a file",
  // Runtime artifacts the product writes (ledgers / configs / assets the
  // user machine holds, never repo files)
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
  // Example paths inside a user's own repository (docs recipes)
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
  // Object keys in the backup bucket / operator-side paths
  "import/acme.identities.json": "an object key in the documented import procedure",
  "acme.ndjson.gz.identities.json": "an object key in the documented import procedure",
  "restore/jobs/import-acme.json": "an object key in the documented restore procedure",
  "restore/jobs/job-1.json": "an object key in the documented restore procedure",
  "restore/results/import-acme.json": "an object key in the documented restore procedure",
  "restore/results/job-1.json": "an object key in the documented restore procedure",
  // The deepsec tool's own checkout layout
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

/** Target A — live documents (dated records excluded). */
function targetDocs(): readonly string[] {
  const rootDocs = readdirSync(join(repoRoot, "docs"))
    .filter(
      (name) =>
        name.endsWith(".md") && !name.startsWith("DEEPSEC_FINDINGS_") && !/_REVIEW_/.test(name),
    )
    .map((name) => join("docs", name));
  const siteDocs = walk(join(repoRoot, "apps", "site", "docs")).map((path) =>
    path.slice(repoRoot.length + 1),
  );
  return ["CLAUDE.md", "AGENTS.md", "README.md", "CONTRIBUTING.md", ...rootDocs, ...siteDocs];
}

/** Target B — the comments of every .ts/.tsx under each app's or package's src/. */
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

/** Line + block comments of a source file (URLs removed first so a `//` inside a scheme is never a comment start). */
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

function record(file: string, token: string): void {
  misses.set(`${token} @ ${file}`, { file, token });
}

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

function scanTokens(file: string, text: string): void {
  const noUrls = text.replace(/https?:\/\/\S+/g, " ");
  for (const match of noUrls.matchAll(TOKEN)) {
    const token = match[0];
    if (!skippable(token)) {
      extracted += 1;
      if (isMiss(file, token)) {
        record(file, token);
      }
    }
  }
}

for (const file of targetDocs()) {
  scanTokens(file, readFileSync(join(repoRoot, file), "utf8"));
}
for (const file of targetSources()) {
  scanTokens(file, commentsOf(readFileSync(join(repoRoot, file), "utf8")));
}

describe("file references in live docs and source comments", () => {
  it("extracts a real corpus (the check isn't idling — ≈1.5k tokens at main 94d3b72)", () => {
    expect(extracted).toBeGreaterThan(1000);
  });

  it("every file reference resolves to a tracked file", () => {
    const offenders = [...misses.values()].map((miss) => `${miss.file}: ${miss.token}`).toSorted();
    expect(offenders).toEqual([]);
  });
});
