import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { renderAll } from "./theme.ts";

const repoRoot = join(import.meta.dirname, "..", "..", "..");

for (const [relative, content] of renderAll(repoRoot)) {
  const target = join(repoRoot, relative);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
  console.log(`wrote ${relative}`);
}
