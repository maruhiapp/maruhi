// `bun run --filter @maruhi/site theme:build` — writes the site's theme
// artifacts (theme.css / theme/tokens.ts / logo-dark.svg / copied assets)
// from apps/web/theme/maruhi.css. The artifacts are committed. Drift is
// detected by test/unit/theme.test.ts (regenerated = committed).
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
