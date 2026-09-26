// English-only source check (ADR-0019). Scans text for CJK characters and
// fails if any are found outside the exemptions.
//
//   bun scripts/check-english.mjs          lines added vs the PR base ref
//   bun scripts/check-english.mjs --all    every tracked file (post-migration)
//
// Changed mode is a ratchet: only lines a diff *adds* are checked, so a PR
// that touches a file with pre-existing Japanese is not forced to translate
// it (ADR-0019 decision 4). --all checks whole files and is for the
// post-migration steady state.
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

// Hiragana, katakana, halfwidth katakana, CJK ext-A, unified + compat
// ideographs, and CJK punctuation. U+3299 (the maruhi mark glyph) is
// intentionally out of range.
const CJK = /[　-〿぀-ゟ゠-ヿㇰ-ㇿｦ-ﾟ㐀-䶿一-鿿豈-﫿]/;

function git(args) {
  return execSync(`git ${args}`, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 1 << 28,
  }).trim();
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

function mergeBaseWith(candidate) {
  try {
    return git(`merge-base ${candidate} HEAD`);
  } catch {
    return null;
  }
}

function mergeBase() {
  const baseRef = process.env.GITHUB_BASE_REF || "main";
  for (const candidate of [`origin/${baseRef}`, "origin/main", "main"]) {
    const mb = mergeBaseWith(candidate);
    if (mb) return mb;
  }
  console.error("check-english: could not find a merge base; pass --all or fetch the base branch");
  process.exit(2);
}

// Every line of a file as {path, line, text}; empty for unreadable/binary files.
function fileLines(path) {
  let text;
  try {
    text = readFileSync(join(ROOT, path), "utf8");
  } catch {
    return [];
  }
  if (text.includes("")) return [];
  return text.split("\n").map((line, i) => ({ path, line: i + 1, text: line }));
}

// Lines added by the working-tree diff vs the merge base (covers committed
// branch changes and not-yet-committed local edits), plus whole contents of
// untracked files, which the diff never mentions.
function addedLines() {
  const out = [];
  let path = null;
  let line = 0;
  for (const raw of git(`diff -U0 --no-color ${mergeBase()}`).split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) {
      line = Number(hunk[1]);
    } else if (raw.startsWith("+++ ")) {
      path = raw.startsWith("+++ b/") ? raw.slice(6) : null;
    } else if (path && raw.startsWith("+")) {
      out.push({ path, line, text: raw.slice(1) });
      line += 1;
    }
  }
  for (const untracked of git("ls-files --others --exclude-standard").split("\n")) {
    if (untracked) out.push(...fileLines(untracked));
  }
  return out;
}

function allLines() {
  return git("ls-files")
    .split("\n")
    .filter(Boolean)
    .flatMap((path) => fileLines(path));
}

const lines = ALL ? allLines() : addedLines();
const exemptions = exemptPaths();

const offenders = [];
for (const { path, line, text } of lines) {
  if (isExempt(path, exemptions)) continue;
  if (CJK.test(text) && !text.includes("english-exempt")) {
    offenders.push(`${path}:${line}: ${text.trim().slice(0, 100)}`);
  }
}

if (offenders.length > 0) {
  console.error(
    `check-english: ${offenders.length} ${ALL ? "line(s)" : "added line(s)"} contain CJK text (ADR-0019).`,
  );
  console.error(
    "Translate them, or for intentional non-English data add an inline" +
      " `english-exempt` marker / a path entry in scripts/english-exemptions.txt:",
  );
  for (const line of offenders.slice(0, 50)) console.error(`  ${line}`);
  if (offenders.length > 50) console.error(`  ... and ${offenders.length - 50} more`);
  process.exit(1);
}
console.log(
  `check-english: clean (${lines.length} ${ALL ? "file line(s), --all" : "added line(s), changed-only"})`,
);
