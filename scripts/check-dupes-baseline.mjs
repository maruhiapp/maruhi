import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const BASELINE = "fallow-baselines/dupes.json";

const args = process.argv.slice(2);
const restore = args.includes("--restore");
const baseRef = args.find((arg) => !arg.startsWith("--")) ?? "origin/main";

function git(...gitArgs) {
  return execFileSync("git", gitArgs, { encoding: "utf8", maxBuffer: 1 << 26 });
}

function baselineAt(rev) {
  if (git("ls-tree", "--name-only", rev, "--", BASELINE).trim() === "") return null;
  return git("show", `${rev}:${BASELINE}`);
}

function shapeOf(group) {
  const ranges = group.split("|").map((instance) => {
    const match = /^(.*):(\d+)-(\d+)$/.exec(instance);
    return match === null
      ? null
      : { file: match[1], lines: Number(match[3]) - Number(match[2]) + 1 };
  });
  if (ranges.some((range) => range === null)) return null;
  return {
    files: ranges.map((range) => range.file),
    lines: Math.max(...ranges.map((range) => range.lines)),
  };
}

function copiesPerFile(files) {
  const counts = new Map();
  for (const file of files) counts.set(file, (counts.get(file) ?? 0) + 1);
  return counts;
}

function shrinksInPlace(entry, base) {
  const next = shapeOf(entry.group);
  const previous = shapeOf(base.group);
  if (next === null || previous === null) return false;
  const before = copiesPerFile(previous.files);
  return (
    entry.count <= base.count &&
    next.lines <= previous.lines &&
    [...copiesPerFile(next.files)].every(([file, copies]) => copies <= (before.get(file) ?? 0))
  );
}

function entriesOf(text, label) {
  if (text === null) return [];
  const baseline = JSON.parse(text);
  const fingerprints = baseline.clone_fingerprints ?? [];
  const groups = baseline.clone_groups ?? [];
  return fingerprints.map((fingerprint, index) => {
    const match = /^dup:([0-9a-f]+):(\d+)$/.exec(fingerprint);
    if (match === null) {
      throw new Error(`${label}: unrecognized clone fingerprint ${JSON.stringify(fingerprint)}`);
    }
    return { hash: match[1], count: Number(match[2]), group: groups[index] ?? fingerprint };
  });
}

const mergeBase = git("merge-base", "HEAD", baseRef).trim();
const baseText = baselineAt(mergeBase);
const baseEntries = entriesOf(baseText, `${baseRef} (${mergeBase.slice(0, 12)})`);
const baseCounts = new Map(baseEntries.map((entry) => [entry.hash, entry.count]));
const currentEntries = entriesOf(readFileSync(BASELINE, "utf8"), BASELINE);
const currentHashes = new Set(currentEntries.map((entry) => entry.hash));
const departed = baseEntries.filter((entry) => !currentHashes.has(entry.hash));
const grown = currentEntries.filter((entry) => {
  if ((baseCounts.get(entry.hash) ?? 0) >= entry.count) return false;
  const index = departed.findIndex((base) => shrinksInPlace(entry, base));
  if (index === -1) return true;
  departed.splice(index, 1);
  return false;
});

if (grown.length === 0) {
  console.log(
    `${BASELINE}: shrink-only check passed against ${baseRef} (merge-base ${mergeBase.slice(0, 12)})`,
  );
} else {
  console.error(
    `${BASELINE} gained ${grown.length} clone group(s) relative to ${baseRef} (merge-base ${mergeBase.slice(0, 12)}).`,
  );
  for (const entry of grown) {
    console.error(`  new: ${entry.group}`);
  }
  console.error(
    "The duplication baseline is shrink-only: remove the new clones instead of baselining them.",
  );
  if (restore && baseText !== null) {
    writeFileSync(BASELINE, baseText);
    console.error(`Restored ${BASELINE} to its merge-base version.`);
  }
  process.exit(1);
}
