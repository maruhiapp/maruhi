// push.package's public surface: only the symbols other src files import.
// The `maruhi push` command pieces live in command.ts, imported directly
// by commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). var.package's rotate and rollback, rotation-proposals.ts,
// schema.package's import and sync.package's receipts write a value with
// pushVariable, and var rollback compares values with sameRedactedBytes.
// env.package's env-rotate-push.ts re-encrypts with encryptAndSignPayload
// and judges a conflict's winner with winnerInconsistency, as push does.
export {
  encryptAndSignPayload,
  type PushedVersion,
  pushVariable,
  sameRedactedBytes,
} from "./push.ts";
export { winnerInconsistency } from "./push-winner.ts";
