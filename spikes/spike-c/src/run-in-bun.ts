// Bun ランタイム実環境での検証(vitest は Node 上で走るため、Bun は直接実行で確認する)。
// 実行: bun run src/run-in-bun.ts
import { runChecks } from "./checks.ts";

declare const Bun: { readonly version: string } | undefined;

if (typeof Bun === "undefined") {
  throw new Error("このスクリプトは Bun で実行すること(bun run src/run-in-bun.ts)");
}

console.log(`runtime: Bun ${Bun.version}`);
const results = await runChecks();
for (const r of results) {
  console.log(
    `${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.detail !== undefined ? `  (${r.detail})` : ""}`,
  );
}
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
if (failed.length > 0) throw new Error(`${failed.length} checks failed`);
