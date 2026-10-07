// Reads `.dev.vars.example` (KEY=value lines) into the dummy bindings the
// server tests run with, so the example stays the single source of the
// dummy secret values (a stale or incomplete example fails the suite
// instead of drifting from it).
// The format is deliberately tiny: blank lines and `#` comment lines are
// skipped, every other line is `KEY=value` with an upper-case key and a
// non-empty value taken verbatim after the first `=` (no quoting, no
// interpolation). Anything else throws, so a malformed example cannot
// silently drop an entry.
// Node (vitest.config.ts) only — do not import from the test bodies
// (workerd).

import { readFileSync } from "node:fs";

const SKIPPED = /^(#.*)?$/;
const ENTRY = /^([A-Z][A-Z0-9_]*)=(.+)$/;

export function readDevVarsExample(path: string): Readonly<Record<string, string>> {
  const pairs = readFileSync(path, "utf8")
    .split("\n")
    .map((raw, index) => ({ line: raw.trim(), where: `${path}:${index + 1}` }))
    .filter(({ line }) => !SKIPPED.test(line))
    .map(({ line, where }) => {
      const match = ENTRY.exec(line);
      if (match === null) {
        throw new Error(`${where}: expected a non-empty KEY=value line`);
      }
      return [match[1], match[2]] as const;
    });
  const entries = Object.fromEntries(pairs);
  if (Object.keys(entries).length !== pairs.length) {
    throw new Error(`${path}: duplicate key`);
  }
  return entries;
}
