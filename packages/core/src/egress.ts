import { Effect, Layer, Tracer } from "effect";
import { FetchHttpClient, HttpClient } from "effect/http";

export type EgressRequestInit = Omit<RequestInit, "body" | "headers" | "method" | "signal">;

const withEgressPolicy = (
  client: HttpClient.HttpClient,
  init: EgressRequestInit | undefined,
): HttpClient.HttpClient =>
  HttpClient.transform(client, (response) => {
    const quiet = Effect.provideService(response, Tracer.DisablePropagation, true);
    return init === undefined
      ? quiet
      : Effect.provideService(quiet, FetchHttpClient.RequestInit, init);
  });

export function egressHttpClientLayer(
  init?: EgressRequestInit,
): Layer.Layer<HttpClient.HttpClient> {
  return Layer.effect(
    HttpClient.HttpClient,
    Effect.map(HttpClient.HttpClient, (client) => withEgressPolicy(client, init)),
  ).pipe(Layer.provide(FetchHttpClient.layer));
}
