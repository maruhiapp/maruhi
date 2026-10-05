// The send part of `maruhi sync`'s http driver (sync-http.ts): one
// request carrying the preset's bearer token, retrying transport
// failures and 429 / 502 / 503 / 504 (upserts and deletes are
// idempotent, so a re-send is safe) and honoring Retry-After up to a
// cap, plus the transport-failure description and `scrubbed` — the
// redaction that turns fragments extracted from a failure response
// into showable lines. Used by the response readers
// (sync-http-read.ts) and the run procedures (sync-http-run.ts).

import { Clock, Data, Duration, Effect, Schedule } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { isRecord } from "../json-record.ts";
import { CLI_VERSION } from "../version.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
import type { HttpOutcome, HttpTargetInput, IntegrationToken } from "./sync-http.ts";

const RETRIABLE_STATUSES = new Set([429, 502, 503, 504]);

/**
 * One attempt's retryable outcome: the fragment the failure message ends with,
 * and the `Retry-After` the response carried (null for a transport failure or
 * an unreadable header — the schedule then waits out the backoff instead).
 */
class SendRetryable extends Data.TaggedError("SendRetryable")<{
  readonly failure: string;
  readonly retryAfter: Duration.Duration | null;
}> {}

/** Interpreting `Retry-After` (seconds or an HTTP date). null if unreadable. */
function retryAfterOf(header: string | undefined, now: number): Duration.Duration | null {
  if (header === undefined) {
    return null;
  }
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Duration.seconds(seconds);
  }
  const at = Date.parse(header);
  return Number.isNaN(at) ? null : Duration.millis(Math.max(0, at - now));
}

/**
 * Sends one request with the preset's bearer token, retrying transport
 * failures and 429 / 502 / 503 / 504 (upserts and deletes are idempotent, so a
 * re-send is safe). The response body is returned whole for the caller to
 * interpret and scrub — never logged here.
 */
export function send(
  input: HttpTargetInput,
  request: HttpClientRequest.HttpClientRequest,
): Effect.Effect<HttpOutcome, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const prepared = request.pipe(
      HttpClientRequest.bearerToken(input.token),
      HttpClientRequest.setHeader("accept", "application/json"),
      HttpClientRequest.setHeader("user-agent", `maruhi-cli/${CLI_VERSION}`),
    );
    // Zero attempts means nothing is ever sent.
    if (input.retry.attempts <= 0) {
      return yield* Effect.fail(
        cliError(` (${input.retry.attempts} attempts). Check the network and retry`),
      );
    }
    const once = client.execute(prepared).pipe(
      Effect.flatMap((response) => Effect.map(response.text, (text) => ({ response, text }))),
      // A transport-layer failure (DNS, connection, TLS). The message is only a description of the destination; no body
      Effect.catch((error) =>
        Effect.fail(new SendRetryable({ failure: describeTransport(error), retryAfter: null })),
      ),
      Effect.flatMap(({ response, text }) =>
        RETRIABLE_STATUSES.has(response.status)
          ? Effect.flatMap(Clock.currentTimeMillis, (now) =>
              Effect.fail(
                new SendRetryable({
                  failure: `${input.preset.label} answered ${response.status}`,
                  retryAfter: retryAfterOf(response.headers["retry-after"], now),
                }),
              ),
            )
          : Effect.succeed({ status: response.status, text } satisfies HttpOutcome),
      ),
    );
    // Exponential backoff; a response's Retry-After overrides that step's
    // wait. The schedule output records the step number and the wait it
    // computed so the fallback can tell an over-cap Retry-After apart from
    // exhausted attempts (on the last attempt the cap is not evaluated, so
    // the failure counts toward the attempt total instead).
    const policy = Schedule.exponential(input.retry.baseDelay).pipe(
      Schedule.modifyDelay(
        ({ input: failure, duration }: Schedule.Metadata<Duration.Duration, SendRetryable>) =>
          Effect.succeed(failure.retryAfter ?? duration),
      ),
      Schedule.map(({ attempt, duration }) => ({ attempt, wait: duration })),
      Schedule.while(
        ({ attempt, duration }) =>
          attempt < input.retry.attempts &&
          Duration.isLessThanOrEqualTo(duration, input.retry.maxDelay),
      ),
    );
    return yield* Effect.retryOrElse(once, policy, (failure, stop) =>
      stop.attempt >= input.retry.attempts
        ? Effect.fail(
            cliError(
              `${failure.failure} (${input.retry.attempts} attempts). Check the network and retry`,
            ),
          )
        : Effect.fail(
            cliError(
              `${input.preset.label} asked to retry after ${Math.ceil(Duration.toSeconds(stop.wait))} seconds (Retry-After), longer than maruhi waits. Run \`maruhi sync apply\` again later`,
            ),
          ),
    );
  });
}

/** Describing a transport-layer failure (only the destination host and the error kind. No body or headers). */
function describeTransport(error: unknown): string {
  const tag = isRecord(error) && typeof error["_tag"] === "string" ? error["_tag"] : "error";
  const description =
    isRecord(error) && typeof error["description"] === "string" ? `: ${error["description"]}` : "";
  return `Could not reach the vendor API (${tag}${displayText(description)})`;
}

/** Extracts the showable fragments from a response body and redacts them (values, tokens). */
export function scrubbed(
  lines: readonly string[],
  writes: readonly SyncWrite[],
  token: IntegrationToken,
): string[] {
  return scrubVendorOutput(lines.join("\n"), writes, [token]);
}
