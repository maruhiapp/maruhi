import { Clock, Data, Duration, Effect, Schedule } from "effect";
import { HttpClient, HttpClientRequest } from "effect/http";

import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { isRecord } from "../json-record.ts";
import { CLI_VERSION } from "../version.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
import type { HttpOutcome, HttpTargetInput, IntegrationToken } from "./sync-http.ts";

const RETRIABLE_STATUSES = new Set([429, 502, 503, 504]);

class SendRetryable extends Data.TaggedError("SendRetryable")<{
  readonly failure: string;
  readonly retryAfter: Duration.Duration | null;
}> {}

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

export const send = Effect.fn("sync-http-send.send")(function* (
  input: HttpTargetInput,
  request: HttpClientRequest.HttpClientRequest,
): Effect.fn.Return<HttpOutcome, CliError, HttpClient.HttpClient> {
  const client = yield* HttpClient.HttpClient;
  const prepared = request.pipe(
    HttpClientRequest.bearerToken(input.token),
    HttpClientRequest.setHeader("accept", "application/json"),
    HttpClientRequest.setHeader("user-agent", `maruhi-cli/${CLI_VERSION}`),
  );
  if (input.retry.attempts <= 0) {
    return yield* Effect.fail(
      cliError(` (${input.retry.attempts} attempts). Check the network and retry`),
    );
  }
  const once = client.execute(prepared).pipe(
    Effect.flatMap((response) => Effect.map(response.text, (text) => ({ response, text }))),
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

function describeTransport(error: unknown): string {
  const tag = isRecord(error) && typeof error["_tag"] === "string" ? error["_tag"] : "error";
  const description =
    isRecord(error) && typeof error["description"] === "string" ? `: ${error["description"]}` : "";
  return `Could not reach the vendor API (${tag}${displayText(description)})`;
}

export function scrubbed(
  lines: readonly string[],
  writes: readonly SyncWrite[],
  token: IntegrationToken,
): string[] {
  return scrubVendorOutput(lines.join("\n"), writes, [token]);
}
