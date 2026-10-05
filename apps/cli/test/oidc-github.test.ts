// The OIDC issuance fetch (apps/cli/src/oidc-github.ts — AUTH_SPEC §14-1).
// A stub `FetchHttpClient.Fetch` pins the request's shape (method, the
// three headers, `redirect: "manual"`) and every failure's exact message.

import { egressHttpClientLayer } from "@maruhi/core";
import { Cause, Effect, Exit, Fiber, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vitest";

import { CliError, cliError } from "../src/errors.ts";
import { CliIo, type CliIoShape } from "../src/io.ts";
import {
  fetchGitHubOidcToken,
  OIDC_REQUEST_TOKEN_ENV,
  OIDC_REQUEST_URL_ENV,
} from "../src/oidc-github.ts";

const RUNNER_URL = "https://runner.example/_apis/oidc/token?api-version=2";
const RUNNER_TOKEN = "runner-request-token";
const AUDIENCE = "https://maruhi.example";
const FETCH_FAILED = "Failed to fetch the GitHub Actions OIDC token (check the runner's network)";
const UNINTERPRETABLE = "Cannot interpret the OIDC token response from the GitHub Actions runner";

interface RecordedCall {
  readonly url: string;
  readonly init: RequestInit | undefined;
}

/** The silent-off-TTY CliIo carrying the runner's two env vars. */
function io(vars: Readonly<Record<string, string | undefined>>): CliIoShape {
  return {
    log: () => Effect.void,
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array()),
    promptLine: () => Effect.fail(cliError("no interactive input in this test")),
    envVar: (name) => vars[name],
    agentProfile: () => ({ isAgent: false }),
    stderrIsTerminal: () => false,
    colorEnabled: () => false,
    openBrowser: () => Effect.succeed(false),
  };
}

const runnerEnv = io({
  [OIDC_REQUEST_URL_ENV]: RUNNER_URL,
  [OIDC_REQUEST_TOKEN_ENV]: RUNNER_TOKEN,
});

/**
 * Runs the issuance fetch against a stubbed `FetchHttpClient.Fetch`
 * (`handler` throws/rejects/answers like fetch would), returning the
 * Exit and the calls the stub saw.
 */
async function fetchWith(
  handler: (url: string, init: RequestInit | undefined) => Response | Promise<Response>,
  timeoutMs = 30_000,
): Promise<{ exit: Exit.Exit<Redacted.Redacted<string>, CliError>; calls: RecordedCall[] }> {
  const calls: RecordedCall[] = [];
  const stub = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(input), init });
    return handler(String(input), init);
  }) as typeof fetch;
  const exit = await Effect.runPromiseExit(
    fetchGitHubOidcToken(AUDIENCE, timeoutMs).pipe(
      Effect.provideService(CliIo, runnerEnv),
      Effect.provideService(FetchHttpClient.Fetch, stub),
    ),
  );
  return { exit, calls };
}

/** The CliError message a failure Exit carries (the test fails on anything else). */
function messageOf(exit: Exit.Exit<unknown, CliError>): string {
  if (!Exit.isFailure(exit)) {
    throw new Error("expected a failure Exit");
  }
  const squashed = Cause.squash(exit.cause);
  if (!(squashed instanceof CliError)) {
    throw new Error(`expected a CliError, got ${String(squashed)}`);
  }
  return squashed.message;
}

describe("the GitHub Actions OIDC issuance fetch", () => {
  it("returns the issued token for a 200 `{ value }` body", async () => {
    const { exit, calls } = await fetchWith(
      () => new Response(JSON.stringify({ value: "the-oidc-token" }), { status: 200 }),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    if (!Exit.isSuccess(exit)) {
      return;
    }
    expect(Redacted.value(exit.value)).toBe("the-oidc-token");
    expect(calls).toHaveLength(1);
    const request = calls[0]!;
    expect(request.url).toBe(`${RUNNER_URL}&audience=${encodeURIComponent(AUDIENCE)}`);
    expect(request.init?.method).toBe("GET");
    expect(request.init?.redirect).toBe("manual");
    // Exactly the three headers — nothing else (above all, no trace headers)
    expect(request.init?.headers).toEqual({
      accept: "application/json",
      authorization: `Bearer ${RUNNER_TOKEN}`,
      "user-agent": "maruhi-cli",
    });
  });

  it("fails with `HTTP <status>` on a 403", async () => {
    const { exit } = await fetchWith(() => new Response("denied", { status: 403 }));
    expect(messageOf(exit)).toBe(`${FETCH_FAILED}: HTTP 403`);
  });

  it("does not follow a 302 — the redirect target never sees the request", async () => {
    const { exit, calls } = await fetchWith(
      () => new Response("", { status: 302, headers: { location: "https://evil.example/" } }),
    );
    expect(calls).toHaveLength(1);
    expect(messageOf(exit)).toBe(`${FETCH_FAILED}: HTTP 302`);
  });

  it("fails with the 'Cannot interpret' message on an unparseable body (no body fragment reaches the error)", async () => {
    const { exit } = await fetchWith(() => new Response('{"value":"secret', { status: 200 }));
    expect(messageOf(exit)).toBe(UNINTERPRETABLE);
  });

  it.each([
    { body: JSON.stringify({ value: 42 }) },
    { body: JSON.stringify({ other: "x" }) },
    { body: JSON.stringify({ value: "" }) },
    { body: "[]" },
    { body: '"text"' },
  ])(
    "fails with the 'Cannot interpret' message on a wrong-shape body ($body)",
    async ({ body }) => {
      const { exit } = await fetchWith(() => new Response(body, { status: 200 }));
      expect(messageOf(exit)).toBe(UNINTERPRETABLE);
    },
  );

  it("fails with the fetch rejection's message on a transport rejection", async () => {
    const { exit } = await fetchWith(() => Promise.reject(new Error("socket hangup")));
    expect(messageOf(exit)).toBe(`${FETCH_FAILED}: socket hangup`);
  });

  // Under runCli an ambient HttpClient already sits in context, and
  // `Effect.provide` shares layer builds across provide calls: without
  // `{ local: true }` on the issuance fetch's provide, its
  // `FetchHttpClient.layer` resolves to the ambient build — which never
  // carries the RequestInit — and `redirect: "manual"` silently drops
  it('keeps `redirect: "manual"` when an ambient HttpClient already exists', async () => {
    const calls: RecordedCall[] = [];
    const stub = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      calls.push({ url: String(input), init });
      return new Response(JSON.stringify({ value: "the-oidc-token" }), { status: 200 });
    }) as typeof fetch;
    const exit = await Effect.runPromiseExit(
      fetchGitHubOidcToken(AUDIENCE).pipe(
        Effect.provideService(CliIo, runnerEnv),
        Effect.provideService(FetchHttpClient.Fetch, stub),
        // The ambient client the command environment carries
        Effect.provide(egressHttpClientLayer()),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init?.redirect).toBe("manual");
  });

  it("times out on the Effect clock with the same message as the pre-HttpClient abort", async () => {
    const calls: RecordedCall[] = [];
    const stub = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      calls.push({ url: String(input), init });
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    const program = Effect.gen(function* () {
      const fiber = yield* Effect.forkChild(
        Effect.exit(
          fetchGitHubOidcToken(AUDIENCE, 5_000).pipe(
            Effect.provideService(CliIo, runnerEnv),
            Effect.provideService(FetchHttpClient.Fetch, stub),
          ),
        ),
      );
      yield* TestClock.adjust("5 seconds");
      return yield* Fiber.join(fiber);
    }).pipe(Effect.provide(TestClock.layer()));
    const exit = await Effect.runPromise(program);
    expect(calls).toHaveLength(1);
    expect(messageOf(exit)).toBe(`${FETCH_FAILED}: The operation timed out.`);
  });
});
