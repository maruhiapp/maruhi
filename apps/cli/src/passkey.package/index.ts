// passkey.package's public surface: only the symbols other src files import.
// There is no command.ts here — the passkey subcommands live inside
// commands/key.ts, which imports this index like any other outside file.
export {
  listPasskeysOp,
  openReserveWithPasskey,
  removePasskeyOp,
  sealPasskeyOp,
} from "./passkey.ts";
