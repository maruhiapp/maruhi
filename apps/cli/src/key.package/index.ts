// key.package's public surface: only the symbols other src files import.
// The `maruhi key` command pieces live in command.ts, imported directly by
// commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). invite.package's accept generates a key for a user who has none
// with keyGenerateOp and offers to register it on GitHub with
// offerGithubRegistration, as key generate does. key-record.ts, the record
// shape the device key shares with the reserve key, and the reserve key's
// ledger (reserve.ts, recovery.ts, recovery-code.ts and ledger-open.ts)
// stay at the src root: guardian.package's add opens the ledger and
// device-add.ts generates a key record, and through this index either
// would also load keygen.ts and key-publish.ts.
export { offerGithubRegistration } from "./key-publish.ts";
export { keyGenerateOp } from "./keygen.ts";
