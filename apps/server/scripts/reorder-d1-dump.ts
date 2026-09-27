// Reorders a `wrangler d1 export` dump into an importable order (operations
// runbook — docs/notes/hosted-ops.md §5-1 (3) / docs/SELF_HOSTING.md
// "Restoring a D1 export").
//
// Behavior on the real service found during a restore drill (hosted-ops.md
// §5-3):
// - export orders tables by creation as "CREATE TABLE -> that table's
//   INSERTs" blocks, so INSERTs of a child table (api_tokens etc.) appear
//   before the foreign-key parent table (users)
// - the leading `PRAGMA defer_foreign_keys=TRUE` does not take effect on the
//   `wrangler d1 execute --file` import path — it stops with
//   `no such table: main.users` / `FOREIGN KEY constraint failed`
// So reorder to (1) all CREATE TABLEs -> (2) INSERTs in foreign-key parent ->
// child order -> (3) CREATE INDEXes. BEGIN / COMMIT are dropped (D1 import
// executes per statement).
//
// Assumption: statement splitting relies on "a statement ends at a line whose
// end is `;`" (export INSERTs are one line; CREATE TABLE spans multiple lines
// ending with `);`). If a TEXT value contains a newline the split breaks, but
// current schema values are base64 / hashes / constrained identifiers with no
// newlines, and even when it breaks the leftover is rejected as an
// unclassified statement (fail-closed). Revisit this when adding a column
// that can contain newlines.
//
// Usage (from apps/server): bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>
// Handles no secrets (SQL text reordering only). Delete decrypted dumps after
// the work.

import { reorderD1Dump, UnclassifiedStatementsError } from "./reorder-d1-dump.lib.ts";

const [input, output] = process.argv.slice(2);
if (input === undefined || output === undefined) {
  console.error("usage: bun scripts/reorder-d1-dump.ts <in.sql> <out.sql>");
  process.exit(2);
}
try {
  const { sql, summary } = reorderD1Dump(await Bun.file(input).text());
  await Bun.write(output, sql);
  console.log(
    `reordered ${String(summary.statements)} statements: ${String(summary.tables)} tables, ${String(summary.inserts)} inserts, ${String(summary.indexes)} indexes (dropped ${String(summary.dropped)} BEGIN/COMMIT)`,
  );
  console.log(`insert order: ${summary.insertOrder.join(" > ")}`);
} catch (error) {
  if (error instanceof UnclassifiedStatementsError) {
    console.error(error.message);
    for (const statement of error.statements) {
      console.error(`  ${statement.slice(0, 80)}`);
    }
    process.exit(1);
  }
  throw error;
}
