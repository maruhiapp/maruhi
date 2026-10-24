// member.package's public surface: only the symbols other src files import.
// The `maruhi member` command pieces live in command.ts, imported directly
// by commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). approval.package's approval-approve.ts completes an approved
// member operation with these, and commands/shared.ts reports a member add
// and a role change for both command groups. member-list.ts stays at the src
// root: `maruhi project` lists members too, on the startup path, where this
// index would also load member-add.ts and with it chain-sync.ts.
export { backfillNewMember, type MemberAddSummary } from "./member-add.ts";
export {
  fulfilRoleChange,
  type RoleChangeFulfilment,
  selfObligationReason,
} from "./member-change-role.ts";
export { type MemberSweepOutcome, sweepMemberMandates } from "./member.ts";
