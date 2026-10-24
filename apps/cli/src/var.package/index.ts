// var.package's public surface: only the symbols other src files import.
// The `maruhi var` command pieces live in command.ts, imported directly by
// commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). ci.package's ci-rotate.ts runs a rotation's connector with var
// rotate's error mapping, and rotation-proposals.ts confirms a proposal's
// acceptance with var rotate's confirmation step.
export { callConnector, connectorFailure, ensureConfirmed } from "./var-rotate.ts";
