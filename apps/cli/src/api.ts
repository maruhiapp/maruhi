import { maruhiApi } from "@maruhi/api-schema";
import { Duration, Effect, type Redacted } from "effect";
import { HttpClient, HttpClientError, HttpClientRequest } from "effect/http";
import { HttpApiClient } from "effect/http-api";

export type MaruhiClient = HttpApiClient.ForApi<typeof maruhiApi>;

const REQUEST_TIMEOUT = Duration.seconds(30);
export const BODY_TIMEOUT = Duration.minutes(3);

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

export function makeApiClient(options: {
  readonly baseUrl: string;
  readonly token?: Redacted.Redacted<string>;
  readonly timeout?: Duration.Duration;
  readonly bodyTimeout?: Duration.Duration;
}): Effect.Effect<MaruhiClient, never, HttpClient.HttpClient> {
  const token = options.token;
  const bounded = withRequestTimeout(options.timeout ?? REQUEST_TIMEOUT);
  const bodyTimeout = options.bodyTimeout ?? BODY_TIMEOUT;
  return HttpApiClient.make(maruhiApi, {
    baseUrl: options.baseUrl,
    transformClient: (client) =>
      bounded(
        token === undefined
          ? client
          : HttpClient.mapRequest(client, HttpClientRequest.bearerToken(token)),
      ),
    transformResponse: (effect) =>
      Effect.timeoutOrElse(effect, {
        duration: bodyTimeout,
        orElse: () =>
          Effect.fail(
            new HttpClientError.HttpClientError({
              reason: new HttpClientError.TransportError({
                request: HttpClientRequest.get(options.baseUrl),
                description: `no complete answer within ${Duration.toSeconds(bodyTimeout)} s`,
              }),
            }),
          ),
      }),
  });
}
