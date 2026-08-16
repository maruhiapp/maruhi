// テスト用のワイヤレベル HTTP モックサーバー(node:http)。
//
// 選定理由(session-11.md の比較参照): wrangler dev spawn はサーバーの
// fake-github(vitest-pool-workers の fetch 差し替え)が使えず D1 事前適用も
// 要る一方、CLI の本丸であるクライアント検証(§5.1 / §6.3)のテストには
// 「不正な応答を返すサーバー」が必要で、実サーバーでは作れない。
// 応答は実 crypto(support/crypto.ts)で組み立て、ワイヤ形は api-schema の
// スキーマに一致させる。

import { createServer, type Server } from "node:http";

/**
 * 応答書き込みに使う最小の構造型。@types/node の ServerResponse を直接使うと、
 * 依存ツリーに複数バージョンの @types/node が共存したときに「片方にだけある
 * メソッド」で構造不一致になる(26.1 / 26.2 の writeInformation)ため、
 * 実際に使う 2 メソッドだけへ絞ってバージョン差から独立させる。
 */
interface ResponseWriter {
  writeHead(status: number, headers: Record<string, string>): unknown;
  end(payload: string): unknown;
}

/** One recorded request (body is parsed JSON when the content type is JSON). */
export interface MockRequest {
  readonly method: string;
  readonly path: string;
  /** クエリ文字列(監査読み取り API のフィルタ・カーソル検査用)。重複キーは後勝ち。 */
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
    // ハンドラ内の assertion 失敗等はテストを吊らせず 500 で返す
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
  respond: (request: MockRequest) => MockResponse,
): MockHandler {
  return (request) =>
    request.method === method && request.path === path ? respond(request) : null;
}
