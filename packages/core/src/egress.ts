// The single place an effect HttpClient is built (the CLAUDE.md "say
// nothing" principle applied to the wire).
//
// Scope: effect HttpClients only. A few call sites still use the platform
// `fetch` directly (apps/cli/src/oidc-github.ts, apps/server/src/ops/ops-alerts.ts,
// and same-origin browser code); plain `fetch` adds no header of its own, so
// they are outside the trace-header concern this file addresses.
//
// effect's HttpClient adds `traceparent` / `b3` headers to every request by
// default (trace propagation). maruhi never forwards trace context: under a
// parent span every request of one command shares a trace id, so the maruhi
// server and the third parties a command talks to (GitHub, AWS, Cloudflare,
// OIDC issuers) would all receive a common correlation identifier. An
// outbound request carries only the headers its caller set.
//
// The policy is bound to the client itself (not to a runtime root), so it
// holds in every fiber that uses the client — detached fibers and new
// runtime roots included. `Tracer.DisablePropagation` is the stable switch:
// the client then creates no span and adds no trace header.
//
// Enforcement: oxlint `no-restricted-imports` (.oxlintrc.json) forbids
// FetchHttpClient / BunHttpClient in src outside this file, and
// packages/core/test/egress.test.ts pins that the client adds no header of
// its own and that no src file builds a client with HttpClient.make.

import { Effect, Layer, Tracer } from "effect";
import { FetchHttpClient, HttpClient } from "effect/http";

/** Fetch options a caller may fix for every request (e.g. `redirect: "manual"`). */
export type EgressRequestInit = Omit<RequestInit, "body" | "headers" | "method" | "signal">;

const withEgressPolicy = (client: HttpClient.HttpClient): HttpClient.HttpClient =>
  HttpClient.transform(client, (response) =>
    Effect.provideService(response, Tracer.DisablePropagation, true),
  );

/**
 * The outbound HttpClient: fetch-based, with no header of its own. `init`
 * fixes fetch options for every request made through this layer.
 */
export function egressHttpClientLayer(
  init?: EgressRequestInit,
): Layer.Layer<HttpClient.HttpClient> {
  const client = Layer.effect(
    HttpClient.HttpClient,
    Effect.map(HttpClient.HttpClient, withEgressPolicy),
  ).pipe(Layer.provide(FetchHttpClient.layer));
  return init === undefined
    ? client
    : client.pipe(Layer.provide(Layer.succeed(FetchHttpClient.RequestInit, init)));
}
