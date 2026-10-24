// env.package's public surface: only the symbols other src files import.
// The `maruhi env` command pieces live in command.ts, imported directly by
// commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). sweep-rotate.ts runs env rotate's op on each environment of a
// mandate's sweep, rotation-sweep.ts and rotation-report.ts take its
// summary, and sync.package's sync-rotate.ts advances a receipt to the
// variables it re-encrypted.
export { envRotateOp, type ReencryptedVariable, type RotationSummary } from "./env-rotate.ts";
