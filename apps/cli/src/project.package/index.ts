// project.package's public surface: only the symbols other src files import.
// The `maruhi project` command pieces live in command.ts, imported directly
// by commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). device.ts, device-standing.ts and key-recover.ts list the
// projects a user belongs to the way `maruhi project list` does.
export { fetchProjectMemberships } from "./project-list.ts";
