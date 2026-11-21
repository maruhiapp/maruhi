import { MIN_CLI_POLL_INTERVAL_SECONDS } from "@maruhi/api-schema";
import type { UserId } from "@maruhi/core";
import { Cause, Clock, Duration, Effect, Option, Pull, Redacted, Schedule, Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { AgentProfileRef } from "./agent-gate.ts";
import { makeApiClient, type MaruhiClient } from "./api.ts";
import { countNoun, displayText, escapeText, formatUtcDate } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import {
  describeStore,
  hasRedactedPlaceholder,
  Keychain,
  masterKeyEntryName,
  parseStoredToken,
  redactedPlaceholderEnvTokenMessage,
  redactedPlaceholderTokenMessage,
  serializeStoredToken,
  type StoredToken,
  tokenEntryName,
  tokenRecordNoun,
} from "./keychain.ts";
import { logNote } from "./notice.ts";
import { type EnvTokenStatus, envTokenStatus } from "./session.ts";

const MAX_POLL_INTERVAL_SECONDS = 900;
const DEFAULT_EXPIRES_IN_SECONDS = 900;
const MAX_EXPIRES_IN_SECONDS = 1800;

function clampInterval(seconds: number, minSeconds: number): number {
  if (!Number.isFinite(seconds) || seconds < minSeconds) {
    return minSeconds;
  }
  return Math.min(seconds, Math.max(MAX_POLL_INTERVAL_SECONDS, minSeconds));
}

function isOpenableUrl(raw: string): boolean {
  if (!URL.canParse(raw)) {
    return false;
  }
  const { protocol } = new URL(raw);
  return protocol === "https:" || protocol === "http:";
}

const maybeOpenBrowser = Effect.fn("login.maybeOpenBrowser")(function* (
  io: CliIoShape,
  verificationUrl: string,
): Effect.fn.Return<void, never, Stdio.Stdio> {
  const agent = yield* AgentProfileRef;
  const stdio = yield* Stdio.Stdio;
  const stdinIsTerminal = yield* stdio.stdinIsTerminal;
  const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
  if (agent.isAgent || !stdinIsTerminal || !stdoutIsTerminal || !isOpenableUrl(verificationUrl)) {
    return;
  }
  const opened = yield* io.openBrowser(verificationUrl);
  yield* io.logError(
    opened
      ? "Opened your browser. If nothing appeared, open the URL above manually"
      : "Could not open a browser automatically. Open the URL above manually",
  );
});

function clampExpires(seconds: number): number {
  return Number.isFinite(seconds) && seconds > 0
    ? Math.min(seconds, MAX_EXPIRES_IN_SECONDS)
    : DEFAULT_EXPIRES_IN_SECONDS;
}

function describeWindow(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return minutes >= 1 ? countNoun(minutes, "minute") : countNoun(Math.floor(seconds), "second");
}

function flowExpiredMessage(window: string): string {
  return `The sign-in request expired (it was valid for ${window}). Run \`maruhi login\` again`;
}

const signupPolicyPreflight = Effect.fn("login.signupPolicyPreflight")(function* (
  client: MaruhiClient,
  io: CliIoShape,
): Effect.fn.Return<void, CliError, Stdio.Stdio> {
  const config = yield* client.auth.authConfig({}).pipe(Effect.option);
  const policy = Option.isNone(config) ? undefined : config.value.signupPolicy;
  if (policy !== "invite" && policy !== "closed") {
    return;
  }
  yield* io.logError(
    policy === "invite"
      ? "This server is invite-only: CLI sign-in works only for existing accounts. If you don't have a maruhi account yet, sign up in your browser first using your sign-up invite link, then run `maruhi login` again"
      : "This server is not accepting new sign-ups: CLI sign-in works only for existing accounts",
  );
  if (yield* interactiveHumanTerminal) {
    yield* confirmExistingAccount(io);
  }
});

const interactiveHumanTerminal: Effect.Effect<boolean, never, Stdio.Stdio> = Effect.gen(
  function* () {
    const agent = yield* AgentProfileRef;
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    return !agent.isAgent && stdinIsTerminal && stdoutIsTerminal;
  },
);

const confirmExistingAccount = Effect.fn("login.confirmExistingAccount")(function* (
  io: CliIoShape,
): Effect.fn.Return<void, CliError> {
  const answer = yield* io.promptLine({
    prompt: "Do you already have a maruhi account on this server? [y/N] ",
  });
  const normalized = answer.trim().toLowerCase();
  if (normalized !== "y" && normalized !== "yes") {
    return yield* Effect.fail(
      cliError(
        "Aborted before starting the sign-in. Sign up in the browser first, then run `maruhi login` again",
      ),
    );
  }
});

type PollOutcome =
  | { readonly kind: "pending" }
  | { readonly kind: "backoff"; readonly retryAfterSeconds: number }
  | {
      readonly kind: "approved";
      readonly token: string;
      readonly tokenId: string;
      readonly userId: UserId;
      readonly expiresAtMs: number;
    };

function pollOnce(
  client: MaruhiClient,
  flowId: string,
  flowToken: string,
  window: string,
): Effect.Effect<PollOutcome, CliError> {
  return client.authCli.cliPoll({ payload: { flowId, flowToken } }).pipe(
    Effect.flatMap((result): Effect.Effect<PollOutcome, CliError> => {
      if (result.status === "approved") {
        return Effect.succeed({ kind: "approved", ...result });
      }
      if (result.status === "denied") {
        return Effect.fail(cliError("The sign-in was denied in the browser. No token was issued"));
      }
      return Effect.succeed({ kind: "pending" });
    }),
    Effect.catchTag("CliFlowExpired", () => Effect.fail(cliError(flowExpiredMessage(window)))),
    Effect.catchTag("CliFlowRejected", () =>
      Effect.fail(
        cliError("The sign-in flow was rejected by the server. Run `maruhi login` again"),
      ),
    ),
    Effect.catchTag("AuthRateLimited", (error) =>
      Effect.succeed<PollOutcome>({ kind: "backoff", retryAfterSeconds: error.retryAfterSeconds }),
    ),
    Effect.mapError(toCliError),
  );
}

export const loginOp = Effect.fn("login.loginOp")(function* (input: {
  readonly origin: string;
  readonly tokenName: string;
  readonly showToken: boolean;
  readonly tokenNameIsDefault: boolean;
  readonly expiresInDays?: number;
}): Effect.fn.Return<void, CliError, Keychain | CliIo | HttpClient.HttpClient | Stdio.Stdio> {
  const io = yield* CliIo;
  const keychain = yield* Keychain;
  const client = yield* makeApiClient({ baseUrl: input.origin });

  yield* signupPolicyPreflight(client, io);

  const started = yield* client.authCli
    .cliStart({
      payload: {
        tokenName: input.tokenName,
        ...(input.expiresInDays === undefined ? {} : { expiresInDays: input.expiresInDays }),
      },
    })
    .pipe(Effect.mapError(toCliError));

  const expiresInSeconds = clampExpires(started.expiresInSeconds);
  const window = describeWindow(expiresInSeconds);
  yield* io.logError("Open this URL in your browser to approve the sign-in:");
  yield* io.logError("");
  yield* io.logError(`    ${displayText(started.verificationUrl)}`);
  yield* io.logError("");
  yield* io.logError(`Confirmation code: ${displayText(started.userCode)}`);
  yield* io.logError(
    "Approve only if the browser shows this exact code (it protects you against phishing)",
  );
  yield* io.logError(`This request expires in ${window}`);
  yield* io.logError("");

  yield* maybeOpenBrowser(io, started.verificationUrl);
  yield* io.logError("Waiting for approval\u2026");

  const deadlineMs = (yield* Clock.currentTimeMillis) + expiresInSeconds * 1000;
  const initialInterval = clampInterval(started.pollIntervalSeconds, MIN_CLI_POLL_INTERVAL_SECONDS);
  const pendingOutcome: PollOutcome = { kind: "pending" };
  const awaitingApproval: Schedule.Schedule<PollOutcome, PollOutcome> = Schedule.while(
    Schedule.fromStepWithMetadata(
      Effect.sync(() => {
        let intervalSeconds = initialInterval;
        return ({
          input: lastOutcome,
          now,
        }: Schedule.InputMetadata<PollOutcome>): Pull.Pull<
          [PollOutcome, Duration.Duration],
          Cause.Done<PollOutcome>,
          PollOutcome
        > => {
          if (lastOutcome.kind === "backoff") {
            intervalSeconds = clampInterval(lastOutcome.retryAfterSeconds, intervalSeconds);
          }
          return now + intervalSeconds * 1000 > deadlineMs
            ? Cause.done(lastOutcome)
            : Effect.succeed<[PollOutcome, Duration.Duration]>([
                lastOutcome,
                Duration.seconds(intervalSeconds),
              ]);
        };
      }),
    ),
    ({ input: polled }) => polled.kind !== "approved",
  );
  const outcome = yield* pollOnce(client, started.flowId, started.flowToken, window).pipe(
    Effect.scheduleFrom<PollOutcome, PollOutcome, never, never>(pendingOutcome, awaitingApproval),
  );
  if (outcome.kind !== "approved") {
    return yield* Effect.fail(cliError(flowExpiredMessage(window)));
  }
  const approved = outcome;

  const issuedToken = Redacted.make(approved.token, { label: "maruhi-token" });
  const record: StoredToken = {
    token: issuedToken,
    userId: approved.userId,
    tokenId: approved.tokenId,
    expiresAtMs: approved.expiresAtMs,
  };
  yield* keychain.set(tokenEntryName(input.origin), serializeStoredToken(record)).pipe(
    Effect.catch((setError) =>
      Effect.gen(function* () {
        const authed = yield* makeApiClient({ baseUrl: input.origin, token: issuedToken });
        const revoked = yield* authed.auth.revokeToken({}).pipe(
          Effect.map(() => true),
          Effect.orElseSucceed(() => false),
        );
        return yield* Effect.fail(
          cliError(
            revoked
              ? `${setError.message} (the token just issued has been revoked on the server)`
              : `${setError.message} (revoking the issued token also failed; a successful re-login with the same token name (${input.tokenName}) will revoke it automatically by rotation)`,
          ),
        );
      }),
    ),
  );
  yield* io.log(
    `Signed in as ${displayText(approved.userId)}. The token is stored in ${describeStore(keychain.kind)}`,
  );
  if (input.showToken) {
    yield* io.log("");
    yield* io.log(`    ${escapeText(Redacted.value(issuedToken))}`);
    yield* io.log("");
    yield* io.log(
      "This value is not shown again (signing in again rotates it). To use it on a runtime without lease support, set MARUHI_TOKEN to this value and MARUHI_TOKEN_ORIGIN to the server origin, and clear your terminal scrollback afterwards",
    );
    yield* logNote(
      input.tokenNameIsDefault
        ? "this token was issued under this machine's default token name and is now the active keychain token. If it is destined for another environment, issue it under a distinct name instead (`maruhi login --token-name <name> --show-token`) — a later plain `maruhi login` on this machine rotates the default-name token and would cut that environment off"
        : "this token is now also this machine's active keychain token. If it is destined for another environment, run a plain `maruhi login` afterwards so this machine keeps a token of its own (the provisioned token is untouched — it has a different name) — sharing one token across environments muddles audit attribution, and revoking it cuts off both",
    );
  }
  yield* io.log(
    `The token expires on ${formatUtcDate(approved.expiresAtMs)} (UTC). Signing in again with the same token name (${input.tokenName}) rotates it and revokes the old one`,
  );
  yield* nextStepHint(input.origin, approved.userId, issuedToken);
});

const nextStepHint: (
  origin: string,
  userId: UserId,
  token: Redacted.Redacted<string>,
) => Effect.Effect<void, never, Keychain | CliIo | HttpClient.HttpClient> = Effect.fn(
  "login.nextStepHint",
)(
  function* (origin: string, userId: UserId, token: Redacted.Redacted<string>) {
    const keychain = yield* Keychain;
    const master = yield* keychain.get(masterKeyEntryName(origin, userId));
    const client = yield* makeApiClient({ baseUrl: origin, token });
    const status = yield* client.auth.recoveryStatus({});
    if (master === null) {
      yield* logNote(
        status.registered
          ? "no device key on this machine. Add it as a device (`maruhi device add` here, `maruhi device approve` on a device you have) or, if no device is left, restore with your recovery code: `maruhi key recover`"
          : "no device key yet. Generate one with `maruhi key generate`",
      );
    } else if (!status.registered) {
      yield* logNote(
        "no recovery code is registered. If you lose the key it cannot be restored — issue one with `maruhi key recovery`",
      );
    }
  },
  Effect.catch(() =>
    logNote(
      "skipped the next-step hint because the recovery registration status could not be checked (login itself is unaffected; check the status with `maruhi key show`)",
    ),
  ),
);

function envTokenNotice(status: EnvTokenStatus): string | null {
  switch (status.kind) {
    case "unset":
      return null;
    case "active":
      return "MARUHI_TOKEN is set, so the CLI stays authenticated with that token (the env-var token is not revoked here; manage it on the environment side)";
    case "placeholder":
      return `${redactedPlaceholderEnvTokenMessage} (the next command will fail as-is)`;
    case "originInvalid":
      return `MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN cannot be used, so the token is not used for authentication (${status.reason}). The next command will fail as-is — unset the env vars or fix the reported problem`;
    case "originMissing":
      return "MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN is not set, so the token is not used for authentication (the next command will fail as-is — unset MARUHI_TOKEN or set MARUHI_TOKEN_ORIGIN to the target server's origin)";
    case "originMismatch":
      return "MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN does not match this server, so the token is not used for authentication (the next command will fail as-is — unset the env vars or point MARUHI_TOKEN_ORIGIN at the target server)";
  }
}

export const logoutOp = Effect.fn("login.logoutOp")(function* (input: {
  readonly origin: string;
}): Effect.fn.Return<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const keychain = yield* Keychain;
  const entryName = tokenEntryName(input.origin);
  const stored = yield* keychain.get(entryName);
  if (stored === null) {
    return yield* Effect.fail(
      cliError(
        "No token for this server in the keychain (MARUHI_TOKEN is managed on the environment side)",
      ),
    );
  }
  const record = parseStoredToken(stored);
  if (record === null) {
    const redacted = hasRedactedPlaceholder(stored);
    yield* keychain.remove(entryName);
    return yield* Effect.fail(
      cliError(
        redacted
          ? `${redactedPlaceholderTokenMessage(keychain.kind)} (the unusable record has been deleted; the server-side revocation could not be performed)`
          : `${tokenRecordNoun(keychain.kind)} was corrupt, so it has been deleted (the server-side revocation could not be performed)`,
      ),
    );
  }
  const client = yield* makeApiClient({ baseUrl: input.origin, token: record.token });
  yield* keychain.remove(entryName);
  yield* client.auth.revokeToken({}).pipe(
    Effect.catchTag("Unauthorized", () => Effect.void),
    Effect.mapError(toCliError),
  );
  yield* io.log(
    `Signed out. The token was revoked and removed from ${describeStore(keychain.kind)}`,
  );
  const notice = envTokenNotice(yield* envTokenStatus(input.origin));
  if (notice !== null) {
    yield* logNote(notice);
  }
});
