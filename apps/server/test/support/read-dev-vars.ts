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
