// `bun run --filter @maruhi/site theme:build` — apps/web/theme/maruhi.css からサイトの
// テーマ生成物(theme.css / theme/tokens.ts / logo-dark.svg / 複製資産)を書き出す。
// 生成物はコミットする。差分の検知は test/unit/theme.test.ts(再生成 = コミット済み)。
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
