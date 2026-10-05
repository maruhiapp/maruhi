import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import { Effect, Fiber, Layer } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";
import { describe, expect, it } from "vitest";

import { egressHttpClientLayer } from "../src/index.ts";

interface Captured {
  readonly headers: Record<string, string>;
  readonly redirect: RequestRedirect | undefined;
}

/** A fetch stub recording what reached the wire. */
function captureFetch(): { readonly fetch: typeof fetch; readonly seen: Captured[] } {
  const seen: Captured[] = [];
  const stub = (async (_url: unknown, init?: RequestInit) => {
    seen.push({
      headers: Object.fromEntries(new Headers(init?.headers)),
      redirect: init?.redirect,
    });
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  return { fetch: stub, seen };
}

const request = HttpClientRequest.get("https://egress.test/x").pipe(
  HttpClientRequest.setHeaders({ accept: "application/json", "x-caller": "set-by-caller" }),
);

/** Two requests under one parent span — one on the parent fiber, one forked. */
const twoRequests = Effect.gen(function* () {
  const client = yield* HttpClient.HttpClient;
  yield* client.execute(request);
  const forked = yield* Effect.forkChild(client.execute(request));
  yield* Fiber.join(forked);
}).pipe(Effect.withSpan("command"));

const run = (layer: Layer.Layer<HttpClient.HttpClient>, stub: typeof fetch) =>
  Effect.runPromise(
    twoRequests.pipe(Effect.provide(layer), Effect.provideService(FetchHttpClient.Fetch, stub)),
  );

describe("egressHttpClientLayer", () => {
  it("the stub sees effect's default trace headers on a plain client (control)", async () => {
    const { fetch, seen } = captureFetch();
    await run(FetchHttpClient.layer, fetch);
    expect(seen).toHaveLength(2);
    for (const { headers } of seen) {
      expect(Object.keys(headers)).toEqual(expect.arrayContaining(["traceparent", "b3"]));
    }
  });

  it("sends exactly the caller's headers — nothing of its own, in every fiber", async () => {
    const { fetch, seen } = captureFetch();
    await run(egressHttpClientLayer(), fetch);
    expect(seen).toHaveLength(2);
    for (const { headers } of seen) {
      expect(headers).toEqual({ accept: "application/json", "x-caller": "set-by-caller" });
    }
  });

  it("applies the fixed fetch options to every request", async () => {
    const { fetch, seen } = captureFetch();
    await run(egressHttpClientLayer({ redirect: "manual" }), fetch);
    expect(seen.map((entry) => entry.redirect)).toEqual(["manual", "manual"]);
    for (const { headers } of seen) {
      expect(headers).toEqual({ accept: "application/json", "x-caller": "set-by-caller" });
    }
  });
});

describe("outbound clients are built only in packages/core/src/egress.ts", () => {
  // The import of FetchHttpClient / BunHttpClient is pinned by oxlint
  // (.oxlintrc.json no-restricted-imports); a client built from scratch with
  // HttpClient.make / makeWith would bypass both, so it is pinned here
  const repoRoot = join(import.meta.dirname, "../../..");
  const sourceRoots = ["apps", "packages"].flatMap((group) =>
    readdirSync(join(repoRoot, group)).map((name) => join(repoRoot, group, name, "src")),
  );

  function sourceFiles(dir: string): string[] {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    return entries.flatMap((entry) => {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(path);
      return /\.(?:ts|tsx)$/.test(entry.name) ? [path] : [];
    });
  }

  it("no src file calls HttpClient.make or HttpClient.makeWith", () => {
    const offenders = sourceRoots
      .flatMap(sourceFiles)
      .filter((path) => /\bHttpClient\.make(?:With)?\s*\(/.test(readFileSync(path, "utf8")))
      .map((path) => relative(repoRoot, path));
    expect(offenders).toEqual([]);
  });
});
