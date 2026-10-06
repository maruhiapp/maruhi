// `maruhi project list` (AUTH_SPEC §11-5): the list of projects
// where I am a chain-derived member. Verifies the server
// implementation as the API's first consumer.
//
// TCB discipline: the response (projectId / role) is a **server
// declaration** (§11-5 — role is the value DO's read-time check
// returns, but from the client's view it is a declaration that went
// through no verification). Where verified state is needed is
// `maruhi project verify`'s remit; this display is for discovery
// (which project IDs I hold). Projects outside the token's scope do
// not appear in the response (§11-5's scope intersection).

import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";

/**
 * Bounds the page chasing (server-fixed at 100 / page — §11-5). At
 * a volume an honest server never reaches (10,000 projects), it
 * bounds a runaway or malicious server's infinite nextAfter chain.
 */
const MAX_LIST_PAGES = 100;

/** One row of the list (the received shape of api-schema's ProjectMembershipSchema). */
interface MembershipRow {
  readonly projectId: string;
  readonly role: "owner" | "admin" | "member" | "reader";
}

/**
 * Fetches every page of the caller's project memberships (server-reported —
 * discovery only; verified state comes from syncing each chain). `maruhi
 * project list` and the device-side commands that scan every
 * project (device.ts / key-recover.ts) share this.
 */
export const fetchProjectMemberships = Effect.fn("project-list.fetchProjectMemberships")(function* (
  client: MaruhiClient,
): Effect.fn.Return<readonly MembershipRow[], CliError> {
  const rows: MembershipRow[] = [];
  let after: string | undefined;
  for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
    const response = yield* client.membership
      .list({ query: after === undefined ? {} : { after } })
      .pipe(Effect.mapError(toCliError));
    rows.push(...response.projects);
    after = response.nextAfter;
    if (after === undefined) {
      break;
    }
  }
  if (after !== undefined) {
    return yield* Effect.fail(
      cliError(
        `The server kept returning more pages past the ${MAX_LIST_PAGES}-page bound — stopping. This does not happen with an honest server; re-run and investigate the server if it persists`,
      ),
    );
  }
  return rows;
});

/** Fetches every page and displays one project per line (stdout carries data only). */
export const projectListOp = Effect.fn("project-list.projectListOp")(function* (input: {
  readonly client: MaruhiClient;
}): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const rows = yield* fetchProjectMemberships(input.client);
  if (rows.length === 0) {
    yield* io.log("No projects");
    yield* io.logError(
      "You are not a chain-derived member of any project visible to this credential (projects outside the token's scopes are not listed)",
    );
    return;
  }
  for (const row of rows) {
    yield* io.log(`${displayText(row.projectId)}\trole=${row.role}`);
  }
  yield* io.logError(
    `${countNoun(rows.length, "project")} as reported by the server — run \`maruhi project verify --project <id>\` for verified state`,
  );
});
