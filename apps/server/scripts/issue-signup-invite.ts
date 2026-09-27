// Issues a sign-up invite code (operations — AUTH_SPEC §3).
//
// The server has no issuance API or UI (hosted-design.md §2-2 — the wrangler /
// script path). This script only generates the code and computes its hash;
// the operator registers it in D1 by running the wrangler command it prints
// (this script does not ask for CF credentials).
//
// - The raw value (maruhi_sgn_…) is shown on this terminal exactly once. Only
//   the SHA-256 hash goes into the DB (same discipline as AUTH_SPEC §15
//   invite tokens)
// - The code is single-use and expires (default 7 days — adjust with --days);
//   it carries only permission to create an account (not tied to any project,
//   org, or role)
//
// Usage (from apps/server):
//   bun run scripts/issue-signup-invite.ts [--days 7] [--origin https://your.deployment]

import { randomBase62, sha256Hex, ulid } from "../src/ids.ts";

const SIGNUP_CODE_PREFIX = "maruhi_sgn_";
const DEFAULT_TTL_DAYS = 7;

function readFlag(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

const daysRaw = readFlag("days");
const days = daysRaw === undefined ? DEFAULT_TTL_DAYS : Number.parseInt(daysRaw, 10);
if (!Number.isInteger(days) || days < 1 || days > 365) {
  console.error("--days must be an integer between 1 and 365");
  process.exit(2);
}
const origin = readFlag("origin") ?? "<your-deployment-origin>";

const nowMs = Date.now();
const expiresAtMs = nowMs + days * 24 * 60 * 60 * 1000;
const id = ulid(nowMs);
const code = SIGNUP_CODE_PREFIX + randomBase62();
const tokenHash = await sha256Hex(code);

const insertSql = `INSERT INTO signup_invites (id, token_hash, status, expires_at, created_at) VALUES ('${id}', '${tokenHash}', 'pending', ${String(expiresAtMs)}, ${String(nowMs)});`;

console.log("Sign-up invite code (shown once — send it over a private channel):");
console.log("");
console.log(`    ${code}`);
console.log("");
console.log("Sign-up link for the invitee (the link carries the code):");
console.log("");
console.log(`    ${origin}/auth/github/start?signup_code=${code}`);
console.log("");
console.log(
  `Expires: ${new Date(expiresAtMs).toISOString()} (${String(days)} days). Invite id: ${id}`,
);
console.log("");
console.log("Register it (only the SHA-256 hash is stored — run from apps/server):");
console.log("");
console.log(`    bunx wrangler d1 execute maruhi --remote --command "${insertSql}"`);
console.log("");
console.log(
  "To revoke it before use: bunx wrangler d1 execute maruhi --remote --command \"DELETE FROM signup_invites WHERE id = '" +
    id +
    "' AND status = 'pending';\"",
);
