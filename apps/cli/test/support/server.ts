import { createServer, type Server } from "node:http";

interface ResponseWriter {
  writeHead(status: number, headers: Record<string, string>): unknown;
  end(payload: string): unknown;
}

export interface MockRequest {
  readonly method: string;
  readonly path: string;
  readonly query: Readonly<Record<string, string>>;
  readonly body: unknown;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

export interface MockResponse {
  readonly status: number;
  readonly json?: unknown;
  readonly bodyText?: string;
  readonly contentType?: string;
  readonly headers?: Readonly<Record<string, string>>;
}

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
    writeResponse(response, {
      status: 500,
      bodyText: error instanceof Error ? error.message : "handler error",
    });
    throw error;
  }
}

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

export function onRequest(
  method: string,
  path: string,
  respond: (request: MockRequest) => MockResponse | Promise<MockResponse>,
): MockHandler {
  return (request) =>
    request.method === method && request.path === path ? respond(request) : null;
}
