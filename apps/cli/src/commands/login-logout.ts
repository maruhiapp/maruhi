// `maruhi login` / `maruhi logout` (discipline: see commands/index.ts).

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

/**
 * The length check of `--token-name` (**the given value itself never
 * appears in the error**). The bound reads the same constant as
 * `@maruhi/api-schema`'s declaration (transcribing the number onto the
 * CLI side would keep refusing under a stale bound when the declaration
 * is relaxed).
 */
function requireTokenName(value: string | undefined): Effect.Effect<string, CliError> {
  const name = value ?? `cli:${hostname()}`;
  return name.length > MAX_TOKEN_NAME_LENGTH
    ? Effect.fail(usageError(`--token-name must be at most ${MAX_TOKEN_NAME_LENGTH} characters`))
    : Effect.succeed(name);
}

/**
 * The range check of `--token-ttl-days` (AUTH_SPEC §6). The bound and
 * default read the same constants as `@maruhi/api-schema`'s declaration
 * (same reason as requireTokenName: a misspelling drops before the
 * browser approval completes). An omitted one is returned as undefined,
 * left to the server-side default (90 days).
 */
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
        import("../login.ts").then(({ loginOp }) => ({ loginOp })),
      );
      const { resolveServerOrigin } = yield* Effect.promise(() =>
        import("../session.ts").then(({ resolveServerOrigin }) => ({ resolveServerOrigin })),
      );

      // Checked **before any communication**. The bound is shared with
      // api-schema (MAX_TOKEN_NAME_LENGTH). Without it, a too-long name
      // surfaces as start's encode failure (a diagnostic confusingly close
      // to a connection failure)
      const tokenName = yield* requireTokenName(values["token-name"]);
      const expiresInDays = yield* requireTokenTtlDays(values["token-ttl-days"]);
      // --show-token prints the issued PAT's raw value to the terminal
      // (AUTH_SPEC §6's "one place of terminal display at issuance" —
      // ruling CK). The displayability is judged by the same fail-closed
      // two-layer gate as value display (ADR-0016 decision 7), **before
      // any communication**: on an environment where it is refused, a
      // completed browser approval would revoke only the old token through
      // a same-name rotation and end with no new raw value obtained (the
      // worst failure shape — just breaking the CI token to be replaced)
      if (values["show-token"]) {
        yield* ensureValueDisplayAllowed;
      }
      const config = yield* loadCliConfig;
      const origin = yield* resolveServerOrigin(values.server, config);
      yield* loginOp({
        origin,
        tokenName,
        showToken: values["show-token"],
        // The default-name judgment uses the resolved actual name
        // (explicitly passing cli:<hostname> also counts as the default
        // name — the branch keys on the fact that a plain re-login becomes
        // a same-name rotation. Ruling CM)
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
        import("../login.ts").then(({ logoutOp }) => ({ logoutOp })),
      );
      const { resolveServerOrigin } = yield* Effect.promise(() =>
        import("../session.ts").then(({ resolveServerOrigin }) => ({ resolveServerOrigin })),
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
