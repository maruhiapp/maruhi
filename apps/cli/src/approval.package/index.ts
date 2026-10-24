// approval.package's public surface: only the symbols other src files import.
// The `maruhi approval` command pieces live in command.ts, imported directly
// by commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). member.package and server.package propose their operations
// through approval.ts, commands/shared.ts builds a proposal's input and
// reports the proposed operation with its types, and `maruhi project policy
// approvals` loads setApprovalPolicyOp lazily. approval-rules.ts stays at
// the src root: the command layer imports it on the startup path, where this
// index would also load approval.ts and with it chain-sync.ts.
export {
  ensureStillTarget,
  type PolicyRequest,
  type ProposalInput,
  type ProposeContext,
  type ProposedSummary,
  proposeOperation,
  proposeRecheck,
  setApprovalPolicyOp,
} from "./approval.ts";
