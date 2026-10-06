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
const baseCounts = new Map(
  entriesOf(baseText, `${baseRef} (${mergeBase.slice(0, 12)})`).map((entry) => [
    entry.hash,
    entry.count,
  ]),
);
const grown = entriesOf(readFileSync(BASELINE, "utf8"), BASELINE).filter(
  (entry) => (baseCounts.get(entry.hash) ?? 0) < entry.count,
);

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
