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
