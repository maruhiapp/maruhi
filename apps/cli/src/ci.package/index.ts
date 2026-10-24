// ci.package's public surface: only the symbols other src files import.
// The `maruhi ci` command pieces live in command.ts, imported directly by
// commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). `maruhi ci sync`'s op lives in sync.package (sync-ci.ts) and
// leases through this index.
export { type CiLeaseInput, leaseEnvironments } from "./ci-lease.ts";
