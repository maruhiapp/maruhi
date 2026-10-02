// Typed client derivation from api-schema (the implementation point of
// ADR-0005's "derive the typed client automatically from the schema definition").
//
// Auth is the Authorization: Bearer header (AUTH_SPEC §6). The token rides only
// on the request header and never appears in logs or errors.

import { maruhiApi } from "@maruhi/api-schema";
import { Duration, Effect, type Redacted } from "effect";
import { HttpClient, HttpClientError, HttpClientRequest } from "effect/http";
import { HttpApiClient } from "effect/http-api";

/** The typed maruhi API client derived from {@link maruhiApi}. */
export type MaruhiClient = HttpApiClient.ForApi<typeof maruhiApi>;

/**
 * How long one request may take before the server counts as not
 * answering (PF2 ruling E revision): a server that accepts the connection
 * and never answers would otherwise hold a read forever, and the mirror
 * fallback never fires. The largest answer (an export page) is 4 MiB.
 */
const REQUEST_TIMEOUT = Duration.seconds(30);

/** A request past the timeout is a transport failure (the `unreachable` class of failure.ts), never an answer. */
function withRequestTimeout(
  timeout: Duration.Duration,
): (client: HttpClient.HttpClient) => HttpClient.HttpClient {
  return HttpClient.transform<
    HttpClientError.HttpClientError,
    never,
    HttpClientError.HttpClientError,
    never
  >((effect, request) =>
    Effect.timeoutOrElse(effect, {
      duration: timeout,
      orElse: () =>
        Effect.fail(
          new HttpClientError.HttpClientError({
            reason: new HttpClientError.TransportError({
              request,
              description: `no answer within ${Duration.toSeconds(timeout)} s`,
            }),
          }),
        ),
    }),
  );
}

/**
 * Derives the typed client. `token` is attached as a Bearer header when
 * present (authConfig and the CLI login handoff — cliStart / cliPoll — are
 * the only unauthenticated calls the CLI makes).
 *
 * The upstream `bearerToken` accepts `Redacted` as-is (it unwraps inside
 * header assembly), so the CLI needs no unwrapping point — a hand-written
 * Authorization header (template expansion) would send the redacted form
 * verbatim, so it is not used.
 */
export function makeApiClient(options: {
  readonly baseUrl: string;
  readonly token?: Redacted.Redacted<string>;
  /** The per-request bound (default {@link REQUEST_TIMEOUT}; a probe may use a shorter one). */
  readonly timeout?: Duration.Duration;
}): Effect.Effect<MaruhiClient, never, HttpClient.HttpClient> {
  const token = options.token;
  const bounded = withRequestTimeout(options.timeout ?? REQUEST_TIMEOUT);
  return HttpApiClient.make(maruhiApi, {
    baseUrl: options.baseUrl,
    transformClient: (client) =>
      bounded(
        token === undefined
          ? client
          : HttpClient.mapRequest(client, HttpClientRequest.bearerToken(token)),
      ),
  });
}
