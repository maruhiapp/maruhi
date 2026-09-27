// maruhi login / logout (AUTH_SPEC §4 / §6).
//
// login is a server-mediated web-flow handoff (§4):
// start → display verificationUrl and userCode (the browser auto-launch
// is attempted only on interactive terminals × non-agent) → poll. The
// CLI never talks to the identity provider directly.
//
// - flowToken is a CLI-only bearer credential (§4-1 (1)). It exists only
//   as a local variable and is never displayed, logged, or saved (it
//   rides only on poll's payload)
// - What is persisted is only the maruhi-issued token, and only to the
//   OS keychain
// - Re-running login rotates the same-named token (§6): the old token
//   auto-revokes server-side
// - logout revokes one's own token (§6's v1 scope) + removes it from the
//   keychain

import { MIN_CLI_POLL_INTERVAL_SECONDS } from "@maruhi/api-schema";
import { Duration, Effect, Option, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

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

// Operational caps for server-declared values: never sleep a long time
// on a hostile / misconfigured server's huge value without reaching the
// deadline check. Rounded with slack above the real values (the server's
// TTL of 15 minutes, interval of 5 seconds)
const MAX_POLL_INTERVAL_SECONDS = 900;
const DEFAULT_EXPIRES_IN_SECONDS = 900;
const MAX_EXPIRES_IN_SECONDS = 1800;

/**
 * Clamps the polling interval into [min, max] (the minimum is the
 * wire-shared MIN_CLI_POLL_INTERVAL_SECONDS — §4-1 (5). Only tests may
 * shorten it). 0 / negative / non-numeric go to the minimum (no busy
 * spin). When the minimum exceeds the maximum, the minimum wins.
 */
function clampInterval(seconds: number, minSeconds: number): number {
  if (!Number.isFinite(seconds) || seconds < minSeconds) {
    return minSeconds;
  }
  return Math.min(seconds, Math.max(MAX_POLL_INTERVAL_SECONDS, minSeconds));
}

/**
 * Whether the URL may be handed to the browser auto-launch (fail-closed).
 * verificationUrl is untrusted input from the server's response and the
 * display side neutralizes it with displayText — the side passing it to
 * the OS opener likewise never trusts the raw value. Since the OS's URL
 * handler dispatches arbitrary schemes, only http(s) is allowed, and
 * unparseable values are refused. A failure skips the auto-launch =
 * degrades to the manual-open guidance (the URL already displayed).
 */
function isOpenableUrl(raw: string): boolean {
  if (!URL.canParse(raw)) {
    return false;
  }
  const { protocol } = new URL(raw);
  return protocol === "https:" || protocol === "http:";
}

/**
 * The browser auto-launch UX branch (§4-1 (2) — a branch reusing
 * ADR-0016 decision 7's existing services, not a new security gate).
 * Attempted only for "interactive terminal × non-agent × URL check
 * passed (isOpenableUrl)". Failure, non-target, or a failed check all
 * complete via display + polling — this one fallback path covers every
 * environment.
 */
function maybeOpenBrowser(
  io: CliIoShape,
  verificationUrl: string,
): Effect.Effect<void, never, Stdio.Stdio> {
  return Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (agent.isAgent || !stdinIsTerminal || !stdoutIsTerminal || !isOpenableUrl(verificationUrl)) {
      return;
    }
    const opened = yield* io.openBrowser(verificationUrl);
    // The guidance goes to stderr (ruling D-2: interactive guidance takes
    // the same path as prompts. stdout carries only the login's result).
    // Not silent when the open fails either — steer to the URL already
    // displayed
    yield* io.logError(
      opened
        ? "Opened your browser. If nothing appeared, open the URL above manually"
        : "Could not open a browser automatically. Open the URL above manually",
    );
  });
}

/** Clamps expiresInSeconds into (0, max] (non-numeric / non-finite / non-positive → the default). */
function clampExpires(seconds: number): number {
  return Number.isFinite(seconds) && seconds > 0
    ? Math.min(seconds, MAX_EXPIRES_IN_SECONDS)
    : DEFAULT_EXPIRES_IN_SECONDS;
}

/**
 * Displaying the flow's validity window (ruling D-1). The value is
 * derived from the server response's expiresInSeconds (after
 * clampExpires = the same value the deadline judgment uses) — the CLI
 * holds no constant of its own (changing the server's TTL never makes
 * the CLI's guidance disagree). Floors to minutes; only sub-minute
 * values are spoken in seconds.
 */
function describeWindow(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return minutes >= 1 ? countNoun(minutes, "minute") : countNoun(Math.floor(seconds), "second");
}

/** The expiry wording (carries the server-declared window and states the next step in one sentence). */
function flowExpiredMessage(window: string): string {
  return `The sign-in request expired (it was valid for ${window}). Run \`maruhi login\` again`;
}

/**
 * login's pre-flight fail-fast (AUTH_SPEC §3 / hosted-design.md §2-2
 * (i)(ii)). Before calling `POST /auth/cli/start`, check `GET
 * /auth/config`'s `signupPolicy` advisory, and on an `invite` / `closed`
 * server show would-be new users the guidance "sign up on the web, then
 * `maruhi login`".
 *
 * - **A misuse guard, not authorization** (the server is the source of
 *   truth for acceptance — a CLI login never creates an account [ruling
 *   DH], so someone without an account always stops at the browser
 *   leg's sign-up guidance page. What is stopped here is a wasted
 *   browser round trip)
 * - An advisory fetch failure proceeds without stopping (a missing
 *   advisory must not break login — AUTH_SPEC §3)
 * - The interactive confirmation (the self-report of holding an
 *   existing account) only on "interactive terminal × non-agent". The
 *   judgment material comes via the Stdio / AgentProfileRef services
 *   (reusing ADR-0016 decision 7's existing services — never reading
 *   process.* directly). A non-interactive environment proceeds with
 *   just the displayed guidance (no prompt suspends a CI / agent login)
 */
function signupPolicyPreflight(
  client: MaruhiClient,
  io: CliIoShape,
): Effect.Effect<void, CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    const config = yield* client.auth.authConfig({}).pipe(Effect.option);
    const policy = Option.isNone(config) ? undefined : config.value.signupPolicy;
    if (policy !== "invite" && policy !== "closed") {
      return;
    }
    // The guidance goes to stderr (ruling D-2)
    yield* io.logError(
      policy === "invite"
        ? "This server is invite-only: CLI sign-in works only for existing accounts. If you don't have a maruhi account yet, sign up in your browser first using your sign-up invite link, then run `maruhi login` again"
        : "This server is not accepting new sign-ups: CLI sign-in works only for existing accounts",
    );
    // On a non-interactive environment proceed without the confirmation
    // (the guard's purpose is blocking a well-meaning waste and the
    // guidance UX — it is not authorization. Without an account the
    // server-side guidance page stops them)
    if (yield* interactiveHumanTerminal) {
      yield* confirmExistingAccount(io);
    }
  });
}

/** Whether interactive terminal × non-agent (reusing ADR-0016 decision 7's existing services). */
const interactiveHumanTerminal: Effect.Effect<boolean, never, Stdio.Stdio> = Effect.gen(
  function* () {
    const agent = yield* AgentProfileRef;
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    return !agent.isAgent && stdinIsTerminal && stdoutIsTerminal;
  },
);

/** The self-report confirmation of holding an existing account (no is the default — stops a would-be new user before start). */
function confirmExistingAccount(io: CliIoShape): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
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
}

/** One poll's outcome (a rate limit is not a failure — it adjusts the next interval). */
type PollOutcome =
  | { readonly kind: "pending" }
  | { readonly kind: "backoff"; readonly retryAfterSeconds: number }
  | {
      readonly kind: "approved";
      readonly token: string;
      readonly tokenId: string;
      readonly userId: string;
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
    // An expiry (typed — §4-2) stops polling and steers to re-login
    Effect.catchTag("CliFlowExpired", () => Effect.fail(cliError(flowExpiredMessage(window)))),
    // Uniform rejection (§4-2): a credential mismatch, re-polling a
    // consumed flow, etc. The reason cannot be told apart (the server
    // builds no oracle), so steer to re-login
    Effect.catchTag("CliFlowRejected", () =>
      Effect.fail(
        cliError("The sign-in flow was rejected by the server. Run `maruhi login` again"),
      ),
    ),
    // A 429 is not a failure (§4-1 (5) — the server may refuse excessive
    // polling). Back off by the indicated wait and continue
    Effect.catchTag("AuthRateLimited", (error) =>
      Effect.succeed<PollOutcome>({ kind: "backoff", retryAfterSeconds: error.retryAfterSeconds }),
    ),
    Effect.mapError(toCliError),
  );
}

/** `maruhi login`: start → browser approval → poll → keychain (AUTH_SPEC §4). */
export function loginOp(input: {
  readonly origin: string;
  readonly tokenName: string;
  /**
   * Display the issued PAT's raw value on the terminal exactly once
   * (AUTH_SPEC §6's "one terminal display at issuance" — ruling CK. For
   * feeding MARUHI_TOKEN on a lease-less environment). Assumes the
   * caller has already passed the displayability gate (ADR-0016 decision
   * 7 — the fail-closed two layers) **before communicating**.
   */
  readonly showToken: boolean;
  /**
   * Whether tokenName is this machine's default name (`cli:<hostname>`)
   * (ruling CM — the default name's source of truth is the caller's
   * argument layer, so it is not judged here). Used to branch the
   * identity-swap note: when provisioned under the default name,
   * recommending "a plain re-login" makes the same-name rotation **revoke
   * the very token just displayed**.
   */
  readonly tokenNameIsDefault: boolean;
  /** The explicit TTL (days. AUTH_SPEC §6 — W3a. Omitted = the server default of 90 days). */
  readonly expiresInDays?: number;
  /** The polling interval's floor (seconds. Shortened only by tests). */
  readonly minIntervalSeconds?: number;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const client = yield* makeApiClient({ baseUrl: input.origin });

    // The pre-flight fail-fast (AUTH_SPEC §3 — the signupPolicy advisory check. Before start)
    yield* signupPolicyPreflight(client, io);

    // Starting (§4-1 (1) — the server records nothing. The flow's credentials are only the two identifiers obtained here)
    const started = yield* client.authCli
      .cliStart({
        payload: {
          tokenName: input.tokenName,
          ...(input.expiresInDays === undefined ? {} : { expiresInDays: input.expiresInDays }),
        },
      })
      .pipe(Effect.mapError(toCliError));

    // The validity window is derived from the server's response (ruling D-1 — the same clamped value the deadline judgment uses)
    const expiresInSeconds = clampExpires(started.expiresInSeconds);
    const window = describeWindow(expiresInSeconds);
    // Interactive guidance goes to stderr (ruling D-2: the same path as
    // prompts. Visible even under `maruhi login > file`). Only the
    // login's **result** goes to stdout. verificationUrl / userCode are
    // server-sourced external strings — no control characters / ANSI are
    // streamed raw to the terminal (neutralized via displayText). The
    // vocabulary matches the approval page (DP4) (cli-pages.ts):
    // "Confirmation code" / "approve only on a match"
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

    // Acquisition (§4-1 (5)). The deadline is checked **before** the
    // sleep (when the next polling time passes the deadline the flow
    // expires during the wait)
    const minInterval = input.minIntervalSeconds ?? MIN_CLI_POLL_INTERVAL_SECONDS;
    const deadlineMs = Date.now() + expiresInSeconds * 1000;
    const initialInterval = clampInterval(started.pollIntervalSeconds, minInterval);
    const poll = (
      intervalSeconds: number,
    ): Effect.Effect<Extract<PollOutcome, { readonly kind: "approved" }>, CliError> =>
      Effect.gen(function* () {
        if (Date.now() + intervalSeconds * 1000 > deadlineMs) {
          return yield* Effect.fail(cliError(flowExpiredMessage(window)));
        }
        yield* Effect.sleep(Duration.seconds(intervalSeconds));
        const outcome = yield* pollOnce(client, started.flowId, started.flowToken, window);
        if (outcome.kind === "approved") {
          return outcome;
        }
        if (outcome.kind === "backoff") {
          return yield* poll(clampInterval(outcome.retryAfterSeconds, intervalSeconds));
        }
        return yield* poll(intervalSeconds);
      });
    const approved = yield* poll(initialInterval);

    const issuedToken = Redacted.make(approved.token, { label: "maruhi-token" });
    const record: StoredToken = {
      token: issuedToken,
      userId: approved.userId,
      tokenId: approved.tokenId,
      // The local judgment material for the approaching-expiry advance warning (ruling CL)
      expiresAtMs: approved.expiresAtMs,
    };
    // Never use JSON.stringify(record) — Redacted.toJSON() returns a
    // redaction and "<redacted>" would be written to the keychain
    // (keychain.ts's note)
    yield* keychain.set(tokenEntryName(input.origin), serializeStoredToken(record)).pipe(
      // If it cannot be saved, do not orphan the issued token: attempt
      // the server-side revocation before failing (the original error =
      // the keychain's failure takes precedence, while the revocation's
      // success or failure is reported accurately — never unconditionally
      // claim a successful revocation)
      Effect.catch((setError) =>
        Effect.gen(function* () {
          const authed = yield* makeApiClient({ baseUrl: input.origin, token: issuedToken });
          const revoked = yield* authed.auth.revokeToken({}).pipe(
            Effect.map(() => true),
            Effect.catch(() => Effect.succeed(false)),
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
      // The raw value's only display point (AUTH_SPEC §6 "one terminal
      // display at issuance" — ruling CK). It is unwrapped only for this
      // display, and the value flows nowhere besides the save above (the
      // keychain). It presumes the caller's value-display gate (the
      // fail-closed two layers) passed; on anything but an interactive
      // terminal (pipes / CI / agents) this point is never reached.
      // token is an unconstrained Schema.String on the wire (the server
      // may choose every byte), so emit it neutralized — but since the
      // value is copied, use escapeText (an allow-list — an honest Base62
      // value passes through, an injection becomes a visible escape
      // sequence), not displayText (a destructive replacement to U+FFFD)
      yield* io.log("");
      yield* io.log(`    ${escapeText(Redacted.value(issuedToken))}`);
      yield* io.log("");
      yield* io.log(
        "This value is not shown again (signing in again rotates it). To use it on a runtime without lease support, set MARUHI_TOKEN to this value and MARUHI_TOKEN_ORIGIN to the server origin, and clear your terminal scrollback afterwards",
      );
      // Surfacing the provisioned login's identity swap (ruling CM):
      // since the keychain's slot is per origin, this issuance also
      // replaced this machine's active token. The recovery instruction
      // branches on the issuance name: under the default name,
      // recommending "a plain re-login" makes the same-name rotation
      // **revoke the very token just displayed** and cut off the pasted
      // environment. Under the default name, "issue again under a
      // distinct name" is the right recovery
      yield* logNote(
        input.tokenNameIsDefault
          ? "this token was issued under this machine's default token name and is now the active keychain token. If it is destined for another environment, issue it under a distinct name instead (`maruhi login --token-name <name> --show-token`) — a later plain `maruhi login` on this machine rotates the default-name token and would cut that environment off"
          : "this token is now also this machine's active keychain token. If it is destined for another environment, run a plain `maruhi login` afterwards so this machine keeps a token of its own (the provisioned token is untouched — it has a different name) — sharing one token across environments muddles audit attribution, and revoking it cuts off both",
      );
    }
    // The expiry is fixed at issuance (AUTH_SPEC §6's default TTL —
    // W3a). Since it becomes a 401 on expiry, make when re-login is
    // needed visible at issuance time. The display goes through
    // display.ts's total formatter (the server's declared unbounded
    // number is never passed to Date#toISOString directly)
    yield* io.log(
      `The token expires on ${formatUtcDate(approved.expiresAtMs)} (UTC). Signing in again with the same token name (${input.tokenName}) rotates it and revokes the old one`,
    );
    yield* nextStepHint(input.origin, approved.userId, issuedToken);
  });
}

/**
 * The guidance for the next step after login (device addition / storage
 * reminder — the entry to CRYPTO_SPEC §8's flow). Auxiliary, so a status
 * check failure never turns a successful login into a failure. Still,
 * never swallow it silently (CLAUDE.md): on failure, state the skip in
 * one line.
 */
function nextStepHint(
  origin: string,
  userId: string,
  token: Redacted.Redacted<string>,
): Effect.Effect<void, never, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
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
  }).pipe(
    Effect.catch(() =>
      logNote(
        "skipped the next-step hint because the recovery registration status could not be checked (login itself is unaffected; check the status with `maruhi key show`)",
      ),
    ),
  );
}

/**
 * The guidance for MARUHI_TOKEN being left set after logout (null when
 * none remains).
 *
 * Every state besides `active` **fails without reaching the keychain**,
 * but the fixes differ (re-paste / add / match), so each cause gets its
 * own wording.
 */
function envTokenNotice(status: EnvTokenStatus): string | null {
  switch (status.kind) {
    case "unset":
      return null;
    case "active":
      return "MARUHI_TOKEN is set, so the CLI stays authenticated with that token (the env-var token is not revoked here; manage it on the environment side)";
    case "placeholder":
      return `${redactedPlaceholderEnvTokenMessage} (the next command will fail as-is)`;
    case "originInvalid":
      // The reason reuses the resolution side's wording as-is (rephrasing would disagree with the next failure)
      return `MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN cannot be used, so the token is not used for authentication (${status.reason}). The next command will fail as-is — unset the env vars or fix the reported problem`;
    case "originMissing":
      return "MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN is not set, so the token is not used for authentication (the next command will fail as-is — unset MARUHI_TOKEN or set MARUHI_TOKEN_ORIGIN to the target server's origin)";
    case "originMismatch":
      return "MARUHI_TOKEN is set, but MARUHI_TOKEN_ORIGIN does not match this server, so the token is not used for authentication (the next command will fail as-is — unset the env vars or point MARUHI_TOKEN_ORIGIN at the target server)";
  }
}

/** `maruhi logout`: revoke the presented token, then remove it from the keychain. */
export function logoutOp(input: {
  readonly origin: string;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
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
      // A corrupt record cannot call the revocation, but leaving it is unusable either — delete it
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
    // The keychain removal happens **before** the revocation: if removal
    // failed after revoking, the keychain would keep a token the server
    // already invalidated and every later command would 401 on that dead
    // token (recoverable only manually). With removal first, at worst a
    // live token remains server-side, collectable by re-login
    yield* keychain.remove(entryName);
    yield* client.auth.revokeToken({}).pipe(
      // An already-revoked (401) counts as success. Anything else (the
      // network etc.) fails and tells the user a live token may remain
      // server-side
      Effect.catchTag("Unauthorized", () => Effect.void),
      Effect.mapError(toCliError),
    );
    yield* io.log(
      `Signed out. The token was revoked and removed from ${describeStore(keychain.kind)}`,
    );
    // resolveSession prefers MARUHI_TOKEN over the keychain
    // (session.ts). A leftover env var means "logged out yet the CLI
    // keeps working", so surface it. The judgment is delegated to
    // envTokenStatus: a bespoke check here would reach a different
    // conclusion from session resolution ("you are authenticated" even
    // on a whitespace-only value or an origin mismatch)
    const notice = envTokenNotice(yield* envTokenStatus(input.origin));
    if (notice !== null) {
      yield* logNote(notice);
    }
  });
}
