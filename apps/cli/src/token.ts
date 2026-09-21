// `maruhi token` グループ(AUTH_SPEC §6 — 設計録 dk-design.md §9 K4-13)。
//
// 値ゼロ・鍵不要・エージェントゲート非適用: トークンの目録(id・名前・接頭辞・
// スコープ・期限 — ハッシュは無い)と指定失効。認可はサーバー(`*` × admin トークン、
// またはセッション主体 — §6 / §13-2)。端末の失効(`device revoke`)がここへ誘導する。

import { ForbiddenError, TokenNotFoundError } from "@maruhi/api-schema";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";

/** `maruhi token list`. */
export function tokenListOp(input: {
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { tokens } = yield* input.client.auth
      .listTokens({})
      .pipe(
        Effect.mapError((error) =>
          error instanceof ForbiddenError
            ? cliError(
                "Listing tokens needs an admin token (all projects × admin) or a browser session; this token cannot list them (AUTH_SPEC §6)",
              )
            : toCliError(error),
        ),
      );
    if (tokens.length === 0) {
      yield* io.log("No API tokens");
      return;
    }
    yield* io.log("id\tname\tprefix\tscopes\tcreated\tlast used\texpires");
    for (const token of [...tokens].toSorted((a, b) => a.createdAtMs - b.createdAtMs)) {
      yield* io.log(
        `${displayText(token.id)}\t${displayText(token.name)}\t${displayText(token.tokenPrefix)}\t${token.scopes.map((scope) => `${displayText(scope.project)}:${scope.permission}`).join(",")}\t${formatUtcMinutes(token.createdAtMs)}\t${token.lastUsedAtMs === null ? "never" : formatUtcMinutes(token.lastUsedAtMs)}\t${token.expiresAtMs === null ? "never" : formatUtcMinutes(token.expiresAtMs)}`,
      );
    }
  });
}

/** `maruhi token revoke <token-id>`. */
export function tokenRevokeOp(input: {
  readonly client: MaruhiClient;
  readonly tokenId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.auth
      .revokeTokenById({ params: { tokenId: input.tokenId } })
      .pipe(
        Effect.mapError((error) =>
          error instanceof TokenNotFoundError
            ? cliError(
                `No token with id ${displayText(input.tokenId)} belongs to you (already revoked, or another account's — see \`maruhi token list\`)`,
              )
            : error instanceof ForbiddenError
              ? cliError(
                  "Revoking a token by id needs an admin token (all projects × admin) or a browser session (AUTH_SPEC §6)",
                )
              : toCliError(error),
        ),
      );
    yield* io.log(`Revoked token ${displayText(input.tokenId)}`);
  });
}
