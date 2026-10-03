// `maruhi token` (discipline: see commands/index.ts).

import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import { openSession } from "../context.ts";
import { tokenListOp, tokenRevokeOp } from "../token.ts";
import { NonBlank, serverOnlyFlags } from "./flags.ts";

export const tokenListConfig = serverOnlyFlags();
export const tokenRevokeConfig = {
  ...serverOnlyFlags(),
  "token-id": Argument.String("token-id").pipe(
    Argument.withDescription("Token id as shown by `maruhi token list`"),
    Argument.withSchema(NonBlank),
  ),
};

export function makeTokenCommands() {
  const tokenList = Command.make("list", tokenListConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* tokenListOp({ client: context.client });
    }),
  ).pipe(Command.withDescription("List your API tokens (ids, names, scopes, expiry)"));

  const tokenRevoke = Command.make("revoke", tokenRevokeConfig, (values) =>
    Effect.gen(function* () {
      const context = yield* openSession(values.server);
      yield* tokenRevokeOp({ client: context.client, tokenId: values["token-id"] });
    }),
  ).pipe(Command.withDescription("Revoke one of your API tokens by id"));

  const token = Command.make("token").pipe(
    Command.withDescription("Manage your API tokens (list / revoke)"),
    Command.withSubcommands([tokenList, tokenRevoke]),
  );

  return token;
}
