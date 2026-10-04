// The send part of `maruhi sync`'s http driver (sync-http.ts): one
// request carrying the preset's bearer token, retrying transport
// failures and 429 / 502 / 503 / 504 (upserts and deletes are
// idempotent, so a re-send is safe) and honoring Retry-After up to a
// cap, plus the transport-failure description and `scrubbed` — the
// redaction that turns fragments extracted from a failure response
// into showable lines. Used by the response readers
// (sync-http-read.ts) and the run procedures (sync-http-run.ts).

import { Duration, Effect } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { isRecord } from "../json-record.ts";
import { CLI_VERSION } from "../version.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
import type { HttpOutcome, HttpTargetInput, IntegrationToken } from "./sync-http.ts";

const RETRIABLE_STATUSES = new Set([429, 502, 503, 504]);

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
    let lastFailure = "";
    for (let attempt = 1; attempt <= input.retry.attempts; attempt += 1) {
      const outcome = yield* client.execute(prepared).pipe(
        Effect.flatMap((response) =>
          Effect.map(response.text, (text) => ({
            kind: "response" as const,
            status: response.status,
            retryAfter: retryAfterOf(response.headers["retry-after"], Date.now()),
            text,
          })),
        ),
        // A transport-layer failure (DNS, connection, TLS). The message is only a description of the destination; no body
        Effect.catch((error) =>
          Effect.succeed({ kind: "transport" as const, message: describeTransport(error) }),
        ),
      );
      if (outcome.kind === "response" && !RETRIABLE_STATUSES.has(outcome.status)) {
        return { status: outcome.status, text: outcome.text };
      }
      lastFailure =
        outcome.kind === "transport"
          ? outcome.message
          : `${input.preset.label} answered ${outcome.status}`;
      if (attempt === input.retry.attempts) {
        break;
      }
      const backoff = Duration.times(input.retry.baseDelay, 2 ** (attempt - 1));
      const wait =
        outcome.kind === "response" && outcome.retryAfter !== null ? outcome.retryAfter : backoff;
      if (Duration.isGreaterThan(wait, input.retry.maxDelay)) {
        return yield* Effect.fail(
          cliError(
            `${input.preset.label} asked to retry after ${Math.ceil(Duration.toSeconds(wait))} seconds (Retry-After), longer than maruhi waits. Run \`maruhi sync apply\` again later`,
          ),
        );
      }
      yield* Effect.sleep(wait);
    }
    return yield* Effect.fail(
      cliError(`${lastFailure} (${input.retry.attempts} attempts). Check the network and retry`),
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
