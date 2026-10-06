// The `maruhi token` group (AUTH_SPEC §6 — design record dk-design.md §9 K4-13).
//
// No values, no keys, no agent gate: a catalog of tokens (id, name, prefix,
// scopes, expiry — no hashes) and revocation by id. Authorization is
// server-side (`*` × admin token, or the session principal — §6 / §13-2).
// Device revocation (`device revoke`) leads here.

import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "./api.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";

/** `maruhi token list`. */
export const tokenListOp = Effect.fn("token.tokenListOp")(function* (input: {
  readonly client: MaruhiClient;
}): Effect.fn.Return<void, CliError, CliIo | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const { tokens } = yield* input.client.auth.listTokens({}).pipe(
    Effect.catchTag(
      "Forbidden",
      () =>
        Effect.fail(
          cliError(
            "Listing tokens needs an admin token (all projects × admin) or a browser session; this token cannot list them (AUTH_SPEC §6)",
          ),
        ),
      (error) => Effect.fail(toCliError(error)),
    ),
  );
  if (tokens.length === 0) {
    yield* io.log("No API tokens");
    return;
  }
  yield* io.log("id\tname\tprefix\tscopes\tcreated\tlast used\texpires");
  for (const token of [...tokens].toSorted((a, b) => a.createdAtMs - b.createdAtMs)) {
    yield* io.log(
      `${displayText(token.id)}\t${displayText(token.name)}\t${displayText(token.tokenPrefix)}\t${token.scopes.map((scope) => `${displayText(scope.project)}:${scope.permission}`).join(",")}\t${formatUtcMinutes(token.createdAtMs)}\t${token.lastUsedAtMs === null ? "never" : formatUtcMinutes(token.lastUsedAtMs)}\t${formatUtcMinutes(token.expiresAtMs)}`,
    );
  }
});

/** `maruhi token revoke <token-id>`. */
export const tokenRevokeOp = Effect.fn("token.tokenRevokeOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly tokenId: string;
}): Effect.fn.Return<void, CliError, CliIo | HttpClient.HttpClient> {
  const io = yield* CliIo;
  yield* input.client.auth.revokeTokenById({ params: { tokenId: input.tokenId } }).pipe(
    Effect.catchTags(
      {
        TokenNotFound: () =>
          Effect.fail(
            cliError(
              `No token with id ${displayText(input.tokenId)} belongs to you (already revoked, or another account's — see \`maruhi token list\`)`,
            ),
          ),
        Forbidden: () =>
          Effect.fail(
            cliError(
              "Revoking a token by id needs an admin token (all projects × admin) or a browser session (AUTH_SPEC §6)",
            ),
          ),
      },
      (error) => Effect.fail(toCliError(error)),
    ),
  );
  yield* io.log(`Revoked token ${displayText(input.tokenId)}`);
});
