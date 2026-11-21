import { appendFileSync, readFileSync } from "node:fs";

export function recordVendorCall(tool: string): void {
  const log = process.env["RECIPE_TEST_LOG"];
  if (log === undefined) {
    console.error(`${tool} shim: RECIPE_TEST_LOG is required`);
    process.exit(2);
  }
  const stdin = process.stdin.isTTY ? "" : readFileSync(0, "utf8");
  appendFileSync(log, JSON.stringify({ tool, argv: process.argv.slice(2), stdin }) + "\n");
}
