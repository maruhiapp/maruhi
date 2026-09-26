// English-only source check (ADR-0019). Scans text files for CJK characters
// and fails if any are found outside the exemptions.
//
//   bun scripts/check-english.mjs          files changed vs the PR base ref
//   bun scripts/check-english.mjs --all    every tracked file (post-migration)
//
// A line containing the word `english-exempt` is skipped (inline opt-out for
// intentional non-English data). Whole files are exempted by listing them in
// scripts/english-exemptions.txt (exact path, or a directory prefix ending
// in `/`).

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ALL = process.argv.includes("--all");

const TEXT_EXT =
  /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts|json|jsonc|md|mdx|yml|yaml|toml|sh|rb|py|css|html?|svg|txt|astro|cfg|ini|env|example)$/i;

// Hiragana, katakana, halfwidth katakana, CJK ext-A, unified + compat
// ideographs, and CJK punctuation. U+3299 (the maruhi mark glyph) is
// intentionally out of range.
const CJK = /[　-〿぀-ゟ゠-ヿㇰ-ㇿｦ-ﾟ㐀-䶿一-鿿豈-﫿]/;

function git(args) {
  return execSync(`git ${args}`, { cwd: ROOT, encoding: "utf8" }).trim();
}

function exemptPaths() {
  const file = join(ROOT, "scripts", "english-exemptions.txt");
  return readFileSync(file, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

function isExempt(path, exemptions) {
  return exemptions.some((e) => (e.endsWith("/") ? path.startsWith(e) : path === e));
}

function changedFiles() {
  const baseRef = process.env.GITHUB_BASE_REF || "main";
  let mergeBase;
  for (const candidate of [`origin/${baseRef}`, "origin/main", "main"]) {
    try {
      mergeBase = git(`merge-base ${candidate} HEAD`);
      break;
    } catch {
      continue;
    }
  }
  if (!mergeBase) {
    console.error(
      "check-english: could not find a merge base; pass --all or fetch the base branch",
    );
    process.exit(2);
  }
  // Working-tree diff against the merge base covers both committed branch
  // changes (CI) and not-yet-committed local edits (bun run check pre-commit)
  return git(`diff --name-only ${mergeBase}`).split("\n").filter(Boolean);
}

const files = (ALL ? git("ls-files").split("\n") : changedFiles()).filter((path) =>
  TEXT_EXT.test(path),
);
const exemptions = exemptPaths();

const offenders = [];
for (const path of files) {
  if (isExempt(path, exemptions)) continue;
  let text;
  try {
    text = readFileSync(join(ROOT, path), "utf8");
  } catch {
    continue;
  }
  text.split("\n").forEach((line, i) => {
    if (CJK.test(line) && !line.includes("english-exempt")) {
      offenders.push(`${path}:${i + 1}: ${line.trim().slice(0, 100)}`);
    }
  });
}

if (offenders.length > 0) {
  console.error(`check-english: ${offenders.length} line(s) contain CJK text (ADR-0019).`);
  console.error(
    "Translate them, or for intentional non-English data add an inline" +
      " `english-exempt` marker / a path entry in scripts/english-exemptions.txt:",
  );
  for (const line of offenders.slice(0, 50)) console.error(`  ${line}`);
  if (offenders.length > 50) console.error(`  ... and ${offenders.length - 50} more`);
  process.exit(1);
}
console.log(
  `check-english: clean (${files.length} file(s) scanned${ALL ? ", --all" : ", changed-only"})`,
);
