import { hostname } from "node:os";

import {
  DEFAULT_TOKEN_TTL_DAYS,
  MAX_TOKEN_NAME_LENGTH,
  MAX_TOKEN_TTL_DAYS,
} from "@maruhi/api-schema";
import { Effect } from "effect";
import { Command, Flag } from "effect/cli";

import { ensureValueDisplayAllowed } from "../agent-gate.ts";
import { loadCliConfig } from "../config.ts";
import { CliError, usageError } from "../errors.ts";
import { serverOnlyFlags, singleFlag, singleValued } from "./flags.ts";
import { resolveServerOrigin } from "./lazy.ts";

export const loginConfig = {
  ...serverOnlyFlags(),
  "token-name": singleValued(
    "token-name",
    "Token name (signing in again with the same name rotates the token; default: cli:<hostname>)",
  ),
  "token-ttl-days": Flag.Int("token-ttl-days").pipe(
    Flag.withDescription(
      `Token lifetime in days (1-${MAX_TOKEN_TTL_DAYS}; default ${DEFAULT_TOKEN_TTL_DAYS}). For unattended use on runtimes without lease support`,
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  "show-token": singleFlag(
    "show-token",
    "Print the issued token once, to provision MARUHI_TOKEN on a runtime without lease support (interactive terminals only)",
  ),
};

export const logoutConfig = serverOnlyFlags();

function requireTokenName(value: string | undefined): Effect.Effect<string, CliError> {
  const name = value ?? `cli:${hostname()}`;
  return name.length > MAX_TOKEN_NAME_LENGTH
    ? Effect.fail(usageError(`--token-name must be at most ${MAX_TOKEN_NAME_LENGTH} characters`))
    : Effect.succeed(name);
}

function requireTokenTtlDays(
  value: number | undefined,
): Effect.Effect<number | undefined, CliError> {
  if (value === undefined) {
    return Effect.succeed(undefined);
  }
  return value < 1 || value > MAX_TOKEN_TTL_DAYS
    ? Effect.fail(usageError(`--token-ttl-days must be between 1 and ${MAX_TOKEN_TTL_DAYS}`))
    : Effect.succeed(value);
}

export function makeLoginLogoutCommands() {
  const login = Command.make(
    "login",
    loginConfig,
    Effect.fn("commands-login-logout.login")(function* (values) {
      const { loginOp } = yield* Effect.promise(() =>
        import("../login.ts").then((m) => ({ loginOp: m.loginOp })),
      );

      const tokenName = yield* requireTokenName(values["token-name"]);
      const expiresInDays = yield* requireTokenTtlDays(values["token-ttl-days"]);
      if (values["show-token"]) {
        yield* ensureValueDisplayAllowed;
      }
      const config = yield* loadCliConfig;
      const origin = yield* resolveServerOrigin(values.server, config);
      yield* loginOp({
        origin,
        tokenName,
        showToken: values["show-token"],
        tokenNameIsDefault: tokenName === `cli:${hostname()}`,
        ...(expiresInDays === undefined ? {} : { expiresInDays }),
      });
    }),
  ).pipe(
    Command.withDescription(
      "Sign in by approving a request in your browser, and store the token in the OS keychain (or in the current `maruhi agent` session)",
    ),
  );

  const logout = Command.make(
    "logout",
    logoutConfig,
    Effect.fn("commands-login-logout.logout")(function* (values) {
      const { logoutOp } = yield* Effect.promise(() =>
        import("../login.ts").then((m) => ({ logoutOp: m.logoutOp })),
      );

      const config = yield* loadCliConfig;
      const origin = yield* resolveServerOrigin(values.server, config);
      yield* logoutOp({ origin });
    }),
  ).pipe(
    Command.withDescription(
      "Revoke this machine's token and remove it from the OS keychain (or from the current `maruhi agent` session)",
    ),
  );

  return { login, logout };
}
