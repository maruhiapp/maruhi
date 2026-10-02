// Test clients for the forward proxy (proxy-server.ts): CONNECT + TLS over
// the tunnel (what every HTTPS client does behind HTTPS_PROXY), plain
// absolute-form requests (HTTP_PROXY), and a tiny origin that records
// what actually arrived. Node APIs only (vitest runs under Node).

import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import type net from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";

export interface ClientResponse {
  readonly status: number;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Buffer;
}

/** Sends `request` with `body` and resolves with the collected response. */
function send(
  request: http.ClientRequest,
  body: Buffer | string | undefined,
): Promise<ClientResponse> {
  return new Promise((resolve, reject) => {
    request.on("response", (response) => {
      void collect(response).then(resolve, reject);
    });
    request.on("error", reject);
    request.end(body);
  });
}

function collect(response: http.IncomingMessage): Promise<ClientResponse> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    response.on("data", (chunk: Buffer) => chunks.push(chunk));
    response.on("end", () =>
      resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }),
    );
    response.on("error", reject);
  });
}

/** CONNECT to `authority` through the proxy; resolves with the raw tunnel socket (or the proxy's refusal). */
export function openTunnel(
  proxyPort: number,
  authority: string,
): Promise<{ readonly socket: net.Socket } | { readonly refused: ClientResponse }> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: authority,
    });
    // Node emits 'connect' for every response to a CONNECT, whatever its
    // status; a refusal (403 / 502) carries its body on the raw socket
    request.on("connect", (response, socket, head) => {
      if (response.statusCode === 200) {
        resolve({ socket });
        return;
      }
      const chunks: Buffer[] = [head];
      socket.on("data", (chunk: Buffer) => chunks.push(chunk));
      socket.on("end", () =>
        resolve({
          refused: {
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks),
          },
        }),
      );
      socket.on("error", reject);
    });
    request.on("error", reject);
    request.end();
  });
}

/** TLS over an open tunnel, trusting `ca` for `servername`. */
export function secureTunnel(
  socket: net.Socket,
  servername: string,
  ca: readonly string[],
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername, ca: [...ca] }, () => resolve(secure));
    secure.on("error", reject);
  });
}

/** One HTTPS request over an existing TLS socket (Node's HTTP client on a supplied connection). */
export function requestOver(
  secure: tls.TLSSocket,
  input: {
    readonly method: string;
    readonly host: string;
    readonly path: string;
    readonly headers?: Record<string, string>;
    readonly body?: Buffer | string;
    readonly agent?: http.Agent;
  },
): Promise<ClientResponse> {
  // With no agent, Node honours `createConnection` (an agent of `false`
  // would make a default one and connect to localhost:80 instead)
  return send(
    http.request({
      createConnection: () => secure,
      ...(input.agent === undefined ? {} : { agent: input.agent }),
      method: input.method,
      path: input.path,
      headers: { host: input.host, ...input.headers },
    }),
    input.body,
  );
}

/** One HTTPS request through the proxy (CONNECT → TLS → request), the way curl or Bun does it. */
export async function httpsViaProxy(input: {
  readonly proxyPort: number;
  readonly ca: readonly string[];
  readonly url: string;
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: Buffer | string;
}): Promise<ClientResponse> {
  const url = new URL(input.url);
  const port = url.port === "" ? 443 : Number(url.port);
  const tunnel = await openTunnel(input.proxyPort, `${url.hostname}:${port}`);
  if ("refused" in tunnel) {
    return tunnel.refused;
  }
  const secure = await secureTunnel(tunnel.socket, url.hostname, input.ca);
  try {
    return await requestOver(secure, {
      method: input.method ?? "GET",
      host: url.host,
      path: `${url.pathname}${url.search}`,
      headers: input.headers ?? {},
      body: input.body ?? "",
    });
  } finally {
    secure.destroy();
  }
}

/** One plain-HTTP request through the proxy (absolute-form request target). */
export function httpViaProxy(input: {
  readonly proxyPort: number;
  readonly url: string;
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: Buffer | string;
}): Promise<ClientResponse> {
  const url = new URL(input.url);
  return send(
    http.request({
      host: "127.0.0.1",
      port: input.proxyPort,
      method: input.method ?? "GET",
      path: input.url,
      headers: { host: url.host, ...input.headers },
      agent: false,
    }),
    input.body ?? "",
  );
}

/** 4096 non-UTF-8 bytes (the byte-transparency specimen). */
function binaryBody(): Buffer {
  const bytes = Buffer.alloc(4096);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = (i * 7919) & 0xff;
  }
  return bytes;
}

/** What the origin saw for one request. */
export interface SeenRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: string;
}

export interface Origin {
  readonly port: number;
  readonly seen: SeenRequest[];
  readonly close: () => Promise<void>;
}

/**
 * A recording origin. `/echo` answers with a JSON of the authorization
 * header, URL, and body (so a real value sent to it comes straight back —
 * the response-scrubbing specimen); `/binary` answers 4096 non-UTF-8
 * bytes; `/big` answers a large body with `marker` repeated; anything
 * else answers `ok`.
 */
export async function startOrigin(input: {
  readonly tls?: { readonly key: string; readonly cert: string };
  readonly marker?: string;
}): Promise<Origin> {
  const seen: SeenRequest[] = [];
  type Responder = (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void;
  const responders: Record<string, Responder> = {
    "/echo": (req, res, body) => {
      res.setHeader("content-type", "application/json");
      // The credential echoed in a header as well (the header-scrubbing specimen)
      res.setHeader("x-echo-authorization", req.headers.authorization ?? "none");
      res.end(
        JSON.stringify({ authorization: req.headers.authorization ?? null, url: req.url, body }),
      );
    },
    "/binary": (_req, res) => {
      res.setHeader("content-type", "application/octet-stream");
      res.end(binaryBody());
    },
    "/gzip": (req, res) => {
      // Compresses whatever Accept-Encoding said (the scrubber must still see the value)
      res.setHeader("content-type", "text/plain");
      res.setHeader("content-encoding", "gzip");
      res.end(zlib.gzipSync(`compressed echo: ${req.headers.authorization ?? "none"}`));
    },
    "/big": (_req, res) => {
      res.setHeader("content-type", "text/plain");
      res.end(`${"x".repeat(200)} ${input.marker ?? ""}\n`.repeat(2000));
    },
  };
  const respond: Responder = (req, res, body) => {
    const path = (req.url ?? "").split("?")[0] ?? "";
    const responder = responders[path];
    if (responder === undefined) {
      res.end("ok");
    } else {
      responder(req, res, body);
    }
  };
  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      respond(req, res, body);
    });
  };
  const server =
    input.tls === undefined
      ? http.createServer(handler)
      : https.createServer({ key: input.tls.key, cert: input.tls.cert }, handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return {
    port: (server.address() as AddressInfo).port,
    seen,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
