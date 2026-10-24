// server.package's public surface: only the symbols other src files import.
// The `maruhi server` command pieces live in command.ts, imported directly
// by commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). approval.package's approval-approve.ts completes an approved
// grant or revocation with these. server-disclosure.ts stays at the src
// root: project.package/command.ts imports it on the startup path, where
// this index would also load server-grant.ts and with it chain-sync.ts.
// context.ts and four other domain files import it too.
export { backfillServerGrant } from "./server-grant.ts";
export { sweepAfterRevoke } from "./server-revoke.ts";
