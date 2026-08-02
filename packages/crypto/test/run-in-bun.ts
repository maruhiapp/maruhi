// Bun ランタイム実環境での全チェック実行(CRYPTO_SPEC §11)。
// vitest は Node 上で走るため、Bun(CLI の実行環境)は直接実行で検証する。
// 実行: bun run test/run-in-bun.ts(packages/crypto で)
import { runAllChecks } from "./all-checks.ts";

declare const Bun: { readonly version: string } | undefined;

if (typeof Bun === "undefined") {
  throw new Error("このスクリプトは Bun で実行すること(bun run test/run-in-bun.ts)");
}

console.log(`runtime: Bun ${Bun.version}`);
const results = await runAllChecks();
for (const r of results.filter((x) => !x.ok)) {
  console.error(`FAIL  ${r.name}${r.detail === undefined ? "" : `  (${r.detail})`}`);
}
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed}/${results.length} passed`);
if (failed > 0) {
  throw new Error(`${failed} checks failed`);
}
