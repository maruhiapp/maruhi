// Regeneration check for the committed test vectors (CI step 7c).
//
// Runs the documented generator (`bun run generate`, see ../README.md) in a
// scratch copy of test-vectors/ and fails when any regenerated vector file
// differs from the committed one. Formatting is ignored (the committed files
// are oxfmt-formatted, the generators are not): both sides are parsed and
// compared as JSON, key order included. The committed checkout is never
// written to.
//
// The scratch copy starts without the generated *.json files, so a vector
// the generator no longer produces is reported as missing instead of being
// carried over from the copy. hpke/ (extracted RFC 9180 vectors, not
// generated) is copied as is and not compared.
//
// Needs: `bun install` in this directory, python3 with pyca/cryptography.
// Usage (in this directory): bun run regen-check
// Exit: 0 = byte-equivalent, 1 = differences, 2 = environment problem.

import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TOOLS_DIR = import.meta.dirname;
const VECTORS_DIR = join(TOOLS_DIR, "..");

/** The vector files the generator owns: every *.json directly in test-vectors/. */
function generatedFiles(dir) {
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .toSorted();
}

/** First JSON path at which two parsed values differ, or null when equal. */
export function firstDifference(a, b, path = "$") {
  if (Object.is(a, b)) return null;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) {
    return path;
  }
  if (Array.isArray(a) !== Array.isArray(b)) return path;
  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  // Key order counts: the generators emit a fixed order and oxfmt keeps it
  if (keysA.join("\u0000") !== keysB.join("\u0000")) return `${path} (keys)`;
  for (const key of keysA) {
    const found = firstDifference(a[key], b[key], `${path}.${key}`);
    if (found !== null) return found;
  }
  return null;
}

/** Runs the generator in `scratch` and compares; returns the problems found. */
function regenerateAndCompare(scratch) {
  // Copy the tools (minus node_modules, which is linked) and hpke/; leave
  // the generated files out so the generator has to produce every one
  cpSync(TOOLS_DIR, join(scratch, "tools"), {
    recursive: true,
    filter: (source) => !source.startsWith(join(TOOLS_DIR, "node_modules")),
  });
  symlinkSync(join(TOOLS_DIR, "node_modules"), join(scratch, "tools", "node_modules"), "dir");
  cpSync(join(VECTORS_DIR, "hpke"), join(scratch, "hpke"), { recursive: true });

  const run = spawnSync("bun", ["run", "generate"], {
    cwd: join(scratch, "tools"),
    encoding: "utf8",
  });
  if (run.status !== 0) {
    return [`the generator failed (exit ${run.status})\n${run.stdout}\n${run.stderr}`];
  }

  const committed = generatedFiles(VECTORS_DIR);
  const regenerated = generatedFiles(scratch);
  const problems = [];
  for (const name of committed) {
    if (!regenerated.includes(name)) {
      problems.push(`${name}: committed but not produced by the generator`);
      continue;
    }
    const want = JSON.parse(readFileSync(join(VECTORS_DIR, name), "utf8"));
    const got = JSON.parse(readFileSync(join(scratch, name), "utf8"));
    const where = firstDifference(want, got);
    if (where !== null) problems.push(`${name}: differs at ${where}`);
  }
  for (const name of regenerated) {
    if (!committed.includes(name)) problems.push(`${name}: produced but not committed`);
  }
  if (problems.length === 0) {
    console.log(`regen-check: ${committed.length} vector files match a fresh generator run`);
  }
  return problems;
}

function main() {
  // Fail early with a readable reason instead of a Python traceback halfway
  // through the generator chain
  const probe = spawnSync("python3", ["-c", "import cryptography"], { stdio: "ignore" });
  if (probe.status !== 0) {
    console.error("regen-check: python3 with pyca/cryptography is required (see ../README.md)");
    return 2;
  }
  if (!existsSync(join(TOOLS_DIR, "node_modules"))) {
    console.error("regen-check: run `bun install --frozen-lockfile` in this directory first");
    return 2;
  }
  const scratch = mkdtempSync(join(tmpdir(), "maruhi-vectors-"));
  let problems;
  try {
    problems = regenerateAndCompare(scratch);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  if (problems.length === 0) return 0;
  console.error(
    [
      "regen-check: the committed vectors do not match a fresh generator run:",
      ...problems.map((p) => `  - ${p}`),
      "Regenerate with `bun run generate` + `oxfmt ../*.json` and commit the result",
    ].join("\n"),
  );
  return 1;
}

if (import.meta.main) process.exitCode = main();
