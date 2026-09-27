// Runs all checks under the real Bun runtime (CRYPTO_SPEC §11).
// vitest runs on Node, so Bun (the CLI's runtime environment) is verified by direct execution.
// Usage: bun run test/run-in-bun.ts (inside packages/crypto)
import { runAllChecks } from "./all-checks.ts";

declare const Bun: { readonly version: string } | undefined;

if (typeof Bun === "undefined") {
  throw new Error("Run this script with Bun (bun run test/run-in-bun.ts)");
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
