// invite.package's public surface: only the symbols other src files import.
// The `maruhi invite` command pieces live in command.ts, imported directly
// by commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). member.package's add lists and verifies the invites a member
// accepted with these, as `maruhi invite list` does. invite-link.ts stays at
// the src root: pins.ts, github-signing-keys.ts and commands/shared.ts take
// GITHUB_LOGIN from it, and through this index pins.ts would load invite.ts,
// which imports pins.ts, closing a cycle.
export {
  acceptanceFailureText,
  type InvitationRow,
  type InviteAcceptance,
  issuanceFailureText,
  listInvitations,
  pinMismatchOf,
  verifyAcceptanceBlock,
  verifyIssuance,
} from "./invite.ts";
