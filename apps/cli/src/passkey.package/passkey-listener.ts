import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";

import { parseJsonRecord } from "../json-record-pure.ts";
import {
  CONFIRM_CODE_PATTERN,
  PRF_PAGE_CSS,
  PRF_PAGE_ERROR_CODES,
  PRF_PAGE_HTML,
  PRF_PAGE_JS,
  type PrfPageConfig,
  type PrfPagePost,
} from "./passkey-page.ts";

export const PRF_PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const MAX_BODY_BYTES = 4 * 1024;
const TOKEN_BYTES = 32;
const PRF_HEX_PATTERN = /^[0-9a-f]{64}$/;
const CREDENTIAL_ID_HEX_PATTERN = /^(?:[0-9a-f]{2}){1,1024}$/;
const MAX_CODE_ATTEMPTS = 5;

export type PrfListenerOutcome = PrfPagePost | { readonly error: "too-many-code-attempts" };

export interface PrfListener {
  readonly url: string;
  readonly port: number;
  readonly outcome: Promise<PrfListenerOutcome>;
  readonly close: () => Promise<void>;
}

export interface ParsedPrfPost {
  readonly code: string;
  readonly post: PrfPagePost;
}

export function parsePrfPost(text: string): ParsedPrfPost | null {
  const value = parseJsonRecord(text);
  if (typeof value === "string") {
    return null;
  }
  const code = value["code"];
  if (typeof code !== "string" || !CONFIRM_CODE_PATTERN.test(code)) {
    return null;
  }
  const error = value["error"];
  if (typeof error === "string") {
    const known = PRF_PAGE_ERROR_CODES.find((candidate) => candidate === error);
    return known === undefined || Object.keys(value).length !== 2
      ? null
      : { code, post: { error: known } };
  }
  const credentialIdHex = value["credentialIdHex"];
  const prfHex = value["prfHex"];
  if (
    typeof credentialIdHex !== "string" ||
    typeof prfHex !== "string" ||
    !CREDENTIAL_ID_HEX_PATTERN.test(credentialIdHex) ||
    !PRF_HEX_PATTERN.test(prfHex) ||
    Object.keys(value).length !== 3
  ) {
    return null;
  }
  return { code, post: { credentialIdHex, prfHex } };
}

function codeMatches(expected: string, given: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(given, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function newToken(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES))).toString("base64url");
}

const COMMON_HEADERS: Readonly<Record<string, string>> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  connection: "close",
};

function reply(
  response: ServerResponse,
  status: number,
  body: string,
  headers: Readonly<Record<string, string>> = {},
): void {
  response.writeHead(status, { ...COMMON_HEADERS, "content-type": "text/plain", ...headers });
  response.end(body);
}

function notFound(response: ServerResponse): void {
  reply(response, 404, "not found");
}

function serveAsset(name: string, config: PrfPageConfig, response: ServerResponse): void {
  switch (name) {
    case "":
      reply(response, 200, PRF_PAGE_HTML, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": PRF_PAGE_CSP,
      });
      return;
    case "app.js":
      reply(response, 200, PRF_PAGE_JS, { "content-type": "text/javascript; charset=utf-8" });
      return;
    case "style.css":
      reply(response, 200, PRF_PAGE_CSS, { "content-type": "text/css; charset=utf-8" });
      return;
    case "config.json":
      reply(response, 200, JSON.stringify(config), {
        "content-type": "application/json; charset=utf-8",
      });
      return;
    default:
      notFound(response);
  }
}

function readBody(request: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        request.destroy();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", () => {
      resolve(null);
    });
  });
}

type Route =
  | { readonly kind: "not-found" }
  | { readonly kind: "redirect" }
  | { readonly kind: "asset"; readonly name: string }
  | { readonly kind: "post" };

function tokenPath(
  url: string,
  token: string,
): { readonly rest: string; readonly trailingSlash: boolean } | null {
  const path = url.split("?")[0] ?? "/";
  const segments = path.split("/").filter((segment) => segment.length > 0);
  if (segments[0] !== token) {
    return null;
  }
  return { rest: segments.slice(1).join("/"), trailingSlash: path.endsWith("/") };
}

function routeRequest(
  request: IncomingMessage,
  expected: { readonly token: string; readonly expectedHost: string },
): Route {
  if (request.headers.host !== expected.expectedHost) {
    return { kind: "not-found" };
  }
  const resolved = tokenPath(request.url ?? "/", expected.token);
  if (resolved === null) {
    return { kind: "not-found" };
  }
  if (request.method === "GET") {
    return resolved.rest === "" && !resolved.trailingSlash
      ? { kind: "redirect" }
      : { kind: "asset", name: resolved.rest };
  }
  return request.method === "POST" && resolved.rest === "prf"
    ? { kind: "post" }
    : { kind: "not-found" };
}

export function startPrfListener(config: PrfPageConfig, confirmCode: string): Promise<PrfListener> {
  const token = newToken();
  const connections = new Set<Socket>();
  let settled = false;
  let codeAttempts = 0;
  let resolveOutcome!: (post: PrfListenerOutcome) => void;
  let rejectOutcome!: (error: Error) => void;
  const outcome = new Promise<PrfListenerOutcome>((resolve, reject) => {
    resolveOutcome = resolve;
    rejectOutcome = reject;
  });
  let expectedHost = "";

  const postIsAcceptable = (request: IncomingMessage): boolean =>
    !settled &&
    request.headers.origin === `http://${expectedHost}` &&
    (request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json");

  const recordCodeMismatch = (): void => {
    codeAttempts += 1;
    if (codeAttempts >= MAX_CODE_ATTEMPTS) {
      settled = true;
      resolveOutcome({ error: "too-many-code-attempts" });
    }
  };

  const handlePost = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (!postIsAcceptable(request)) {
      notFound(response);
      return;
    }
    const text = await readBody(request);
    const parsed = text === null ? null : parsePrfPost(text);
    if (parsed === null || settled) {
      notFound(response);
      return;
    }
    if (!codeMatches(confirmCode, parsed.code)) {
      recordCodeMismatch();
      notFound(response);
      return;
    }
    settled = true;
    reply(response, 204, "");
    resolveOutcome(parsed.post);
  };

  const server: Server = createServer({ keepAlive: false }, (request, response) => {
    const route = routeRequest(request, { token, expectedHost });
    switch (route.kind) {
      case "redirect":
        reply(response, 302, "", { location: `/${token}/` });
        return;
      case "asset":
        serveAsset(route.name, config, response);
        return;
      case "post":
        void handlePost(request, response);
        return;
      case "not-found":
        notFound(response);
    }
  });
  server.on("connection", (socket) => {
    connections.add(socket);
    socket.once("close", () => {
      connections.delete(socket);
    });
  });

  let closing: Promise<void> | null = null;
  const close = (): Promise<void> => {
    closing ??= new Promise<void>((done) => {
      server.close(() => {
        done();
      });
      for (const socket of connections) {
        socket.destroy();
      }
    });
    return closing;
  };

  return new Promise<PrfListener>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      server.on("error", (error) => {
        if (!settled) {
          settled = true;
          rejectOutcome(error);
        }
      });
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("listener has no TCP address"));
        return;
      }
      expectedHost = `localhost:${address.port}`;
      resolve({
        url: `http://${expectedHost}/${token}/`,
        port: address.port,
        outcome,
        close,
      });
    });
  });
}
