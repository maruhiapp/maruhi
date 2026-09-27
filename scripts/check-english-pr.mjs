// English-only PR text check (ADR-0019 decision 5). Fails when the PR title,
// the PR description, or any commit message in the PR contains CJK text.
//
//   PR_TITLE, PR_BODY, BASE_SHA, HEAD_SHA come from the pull_request event
//   (.github/workflows/english-pr.yml). Run locally with only BASE_SHA /
//   HEAD_SHA set to check the commit messages of a branch.
//
// A line containing `english-exempt` is skipped, as in check-english.mjs.

import { execFileSync } from "node:child_process";

// Same class as scripts/check-english.mjs, written with escapes so this file
// holds no CJK itself: CJK punctuation, hiragana, katakana, katakana phonetic
// extensions, halfwidth katakana, CJK ext-A, unified + compatibility
// ideographs, fullwidth forms. U+3299 (the maruhi mark) stays out of range.
const CJK = new RegExp(
  "[\\u3000-\\u303f\\u3040-\\u309f\\u30a0-\\u30ff\\u31f0-\\u31ff\\uff66-\\uff9f\\u3400-\\u4dbf\\u4e00-\\u9fff\\uf900-\\ufaff\\uff00-\\uff60]",
);

// Offending lines of one text, labelled with where the text came from.
function offendingLines(label, text) {
  return (text ?? "")
    .split("\n")
    .filter((line) => CJK.test(line) && !line.includes("english-exempt"))
    .map((line) => `${label}: ${line.trim().slice(0, 100)}`);
}

// Every commit message in BASE_SHA..HEAD_SHA (the PR's own commits).
function commitMessages() {
  const { BASE_SHA: base, HEAD_SHA: head } = process.env;
  if (!base || !head) return [];
  const log = execFileSync("git", ["log", "--format=%h%x00%B%x1e", `${base}..${head}`], {
    encoding: "utf8",
    maxBuffer: 1 << 26,
  });
  return log
    .split("\x1e")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [sha, message] = entry.split("\0");
      return { sha, message };
    });
}

const offenders = [
  ...offendingLines("PR title", process.env.PR_TITLE),
  ...offendingLines("PR description", process.env.PR_BODY),
  ...commitMessages().flatMap(({ sha, message }) => offendingLines(`commit ${sha}`, message)),
];

if (offenders.length > 0) {
  console.error(
    `check-english-pr: ${offenders.length} line(s) contain CJK text (ADR-0019 decision 5).`,
  );
  console.error("PR titles, PR descriptions and commit messages are English:");
  for (const line of offenders.slice(0, 50)) console.error(`  ${line}`);
  process.exit(1);
}
console.log("check-english-pr: clean (PR title, description and commit messages)");
