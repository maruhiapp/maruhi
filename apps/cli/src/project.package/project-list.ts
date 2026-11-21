import { type ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { countNoun, displayText } from "../display.ts";
import type { CliError } from "../errors.ts";
import { cliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";

const MAX_LIST_PAGES = 100;

interface MembershipRow {
  readonly projectId: ProjectId;
  readonly role: "owner" | "admin" | "member" | "reader";
}

export const fetchProjectMemberships = Effect.fn("project-list.fetchProjectMemberships")(function* (
  client: MaruhiClient,
): Effect.fn.Return<readonly MembershipRow[], CliError> {
  const rows: MembershipRow[] = [];
  let after: ProjectId | undefined;
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
