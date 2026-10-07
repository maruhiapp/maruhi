// schema.package's public surface: only the symbols other src files import.
// The `maruhi schema` command pieces live in command.ts, imported directly by
// commands/index.ts — re-exporting them here would close an import cycle
// (index → command → schema-import → push → index).
export {
  requireVerifiedEnvironment,
  resolveSchemaTarget,
  SCHEMA_UNTRUSTED_HEADER,
  schemaRows,
  type SchemaSetState,
  type SchemaTargetKey,
} from "./schema.ts";
export { signContinuationStatementV3, signDeleteStatementV3 } from "./schema-statement.ts";
