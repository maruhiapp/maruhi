// Shrink-only gate (CI 5b) for the fallow duplication baseline
// (fallow-baselines/dupes.json). The baseline lists accepted clone debt; it may
// lose entries but never gain them. Fails when the working-tree baseline holds
// a clone the baseline at the merge-base with <base-ref> did not.
//
//   bun scripts/check-dupes-baseline.mjs [--restore] [<base-ref>]
//
//   <base-ref>  defaults to origin/main (CI passes the PR's base branch)
//   --restore   on growth, write the merge-base version back before failing
//               (used by `bun run fallow:baseline`, so a re-save can only
//               shrink the file)
//
// Entries are compared by `clone_fingerprints` (`dup:<content hash>:<count>`),
// which survive line shifts; `clone_groups` carries line ranges and is only
// used to name an offending entry. A fingerprint passes when the base holds
// the same hash with at least as many occurrences (removing one copy of a
// baselined clone is shrinking, adding one is growth).
//
// A refactor that trims a baselined clone without removing it changes the
// clone's content hash. Such an in-place shrink also passes: a new entry is
// accepted when it replaces a base entry that left the baseline, spans the
// same files with no more copies, and is no longer per copy. Each base entry
// covers at most one replacement.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const BASELINE = "fallow-baselines/dupes.json";

const args = process.argv.slice(2);
const restore = args.includes("--restore");
const baseRef = args.find((arg) => !arg.startsWith("--")) ?? "origin/main";

function git(...gitArgs) {
  return execFileSync("git", gitArgs, { encoding: "utf8", maxBuffer: 1 << 26 });
}

/** The baseline text at `rev`, or null when the file does not exist there. */
function baselineAt(rev) {
  // Absent at that revision: every current entry is growth
  if (git("ls-tree", "--name-only", rev, "--", BASELINE).trim() === "") return null;
  return git("show", `${rev}:${BASELINE}`);
}

/** `a.ts:3-9|b.ts:4-10` → the file list and the longest copy's line count. */
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

/** Whether `entry` is `base` trimmed in place: same files, no more copies, no longer. */
function shrinksInPlace(entry, base) {
  const next = shapeOf(entry.group);
  const previous = shapeOf(base.group);
  if (next === null || previous === null) return false;
  return (
    entry.count <= base.count &&
    next.lines <= previous.lines &&
    next.files.every((file) => previous.files.includes(file))
  );
}

/** Fingerprint → { hash, count, group } for one baseline file's text. */
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
// Base entries that left the baseline; each may absorb one in-place shrink
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
