// Shared body of the vendor CLI shims (`wrangler` / `vercel`): record argv and the whole of stdin
// into RECIPE_TEST_LOG so the test can assert where the plaintext went. Exit 0 like a successful
// vendor call.
import { appendFileSync, readFileSync } from "node:fs";

export function recordVendorCall(tool: string): void {
  const log = process.env["RECIPE_TEST_LOG"];
  if (log === undefined) {
    console.error(`${tool} shim: RECIPE_TEST_LOG is required`);
    process.exit(2);
  }
  // fd 0 を EOF まで読む(パイプ前提。端末なら読まない)
  const stdin = process.stdin.isTTY ? "" : readFileSync(0, "utf8");
  appendFileSync(log, JSON.stringify({ tool, argv: process.argv.slice(2), stdin }) + "\n");
}
