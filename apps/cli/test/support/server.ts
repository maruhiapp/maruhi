// Wire-level HTTP mock server for tests (node:http).
//
// Why this was chosen (see the comparison in session-11.md): a wrangler dev
// spawn can't use the server's fake-github (the fetch override of
// @cloudflare/vitest-plugin) and needs D1 applied beforehand — while the CLI's
// core, client-side verification (§5.1 / §6.3), needs "a server that returns
// malformed responses", which a real server can't produce.
// Responses are assembled with real crypto (support/crypto.ts) and the wire
// shapes match the api-schema schemas.

import { createServer, type Server } from "node:http";

/**
 * The minimal structural type used for writing responses. Using @types/node's
 * ServerResponse directly breaks structural compatibility when multiple
 * @types/node versions coexist in the dependency tree — a method present in
 * only one of them (26.1 / 26.2's writeInformation) — so this is narrowed to
 * the 2 methods actually used, independent of the version skew.
 */
interface ResponseWriter {
  writeHead(status: number, headers: Record<string, string>): unknown;
  end(payload: string): unknown;
}

/** One recorded request (body is parsed JSON when the content type is JSON). */
export interface MockRequest {
  readonly method: string;
  readonly path: string;
  /** Query string (for asserting filters / cursors of the audit read API). Duplicate keys: last wins. */
  readonly query: Readonly<Record<string, string>>;
  readonly body: unknown;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

/** A canned response: `json` takes precedence over `bodyText`. */
export interface MockResponse {
  readonly status: number;
  readonly json?: unknown;
  readonly bodyText?: string;
  readonly contentType?: string;
  /** Extra headers (e.g. redirect Location). Use the dedicated field for content-type. */
  readonly headers?: Readonly<Record<string, string>>;
}

/** Returns a response to serve, or null to let the next handler try. */
export type MockHandler = (
  request: MockRequest,
) => MockResponse | null | Promise<MockResponse | null>;

async function readBody(stream: AsyncIterable<Uint8Array>): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseBody(raw: string, contentType: string): unknown {
  if (raw.length === 0) {
    return raw;
  }
  if (contentType.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function writeResponse(response: ResponseWriter, result: MockResponse): void {
  const payload = result.json !== undefined ? JSON.stringify(result.json) : (result.bodyText ?? "");
  response.writeHead(result.status, {
    ...result.headers,
    "content-type":
      result.contentType ?? (result.json !== undefined ? "application/json" : "text/plain"),
  });
  response.end(payload);
}

async function dispatch(
  chain: readonly MockHandler[],
  mockRequest: MockRequest,
  response: ResponseWriter,
): Promise<void> {
  try {
    for (const handler of chain) {
      const result = await handler(mockRequest);
      if (result !== null) {
        writeResponse(response, result);
        return;
      }
    }
    writeResponse(response, { status: 404, json: { error: "no handler" } });
  } catch (error) {
    // An assertion failure inside a handler gets a 500 rather than hanging the test
    writeResponse(response, {
      status: 500,
      bodyText: error instanceof Error ? error.message : "handler error",
    });
    throw error;
  }
}

/** An ephemeral-port HTTP server driven by a handler chain. */
export class MockServer {
  readonly origin: string;
  readonly requests: MockRequest[] = [];
  readonly #server: Server;

  private constructor(server: Server, origin: string) {
    this.#server = server;
    this.origin = origin;
  }

  static async start(handlers: readonly MockHandler[]): Promise<MockServer> {
    const chain = [...handlers];
    const server = createServer((request, response) => {
      void (async () => {
        const raw = await readBody(request);
        const url = new URL(request.url ?? "/", "http://localhost");
        const mockRequest: MockRequest = {
          method: request.method ?? "GET",
          path: url.pathname,
          query: Object.fromEntries(url.searchParams),
          body: parseBody(raw, String(request.headers["content-type"] ?? "")),
          headers: request.headers,
        };
        instance.requests.push(mockRequest);
        await dispatch(chain, mockRequest, response);
      })();
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("mock server address unavailable");
    }
    const instance = new MockServer(server, `http://127.0.0.1:${address.port}`);
    return instance;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.#server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
}

/** Handler matching an exact method + path. */
export function onRequest(
  method: string,
  path: string,
  respond: (request: MockRequest) => MockResponse | Promise<MockResponse>,
): MockHandler {
  return (request) =>
    request.method === method && request.path === path ? respond(request) : null;
}
