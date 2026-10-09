// The local listener that obtains a passkey's PRF (CRYPTO_SPEC §8.2
// / ADR-0018 decision 2 / integration-options.md supplement 20
// rulings A, B). **The CLI's first TCP listener**.
//
// It listens with `node:http` on a random 127.0.0.1 port (like
// `agent.ts`'s `node:net`, a real listener can be tested under vitest
// [Node]), serves the CLI-bundled page (passkey-page.ts), and
// receives the PRF output in one POST. The URL is
// `http://localhost:<port>/<token>/` (rpId = `localhost`, so even
// bound to 127.0.0.1 the hostname is localhost).
//
// Authentication (ruling A — the human-review spot):
//   - A one-time token in the URL path (32-byte random, base64url).
//     Both the page assets' GET and the POST are gated by the same
//     token (other localhost pages cannot enumerate this screen)
//   - `Host` exact match (`localhost:<port>` — DNS rebinding has a
//     different Host)
//   - POST requires an `Origin` exact match
//     (`http://localhost:<port>` — a localhost page on another port
//     has a different Origin. A JSON POST triggers a preflight, so
//     OPTIONS also falls to 404)
//   - Single consumption: the first correct POST settles the result;
//     after that, 404
//   - Failures return a uniform reasonless 404 (never disclose
//     whether it was the token, the Origin, or the body that
//     differed)
//   - The body is `application/json` and at most 4 KiB. The shape is
//     passkey-page.ts's PrfPagePost + `code`
//   - **Confirmation code** (ruling A revision 1): the token rides
//     on the browser launch's argv, readable by another UID's user
//     on the same machine. A POST must carry the 6-digit code
//     displayed on the terminal; a mismatch gets 404 and is **not
//     consumed** (the correct page's POST still passes later). Brute
//     force is cut off at MAX_CODE_ATTEMPTS, failing the ceremony
//     itself (fail-closed)
// The validity period is the listener's lifetime (the caller's
// `Effect.timeout`). close severs open connections before
// `server.close` (keep-alive delays close — the same precedent as
// agent.ts).
//
// Handling of values and key material: the PRF output exists only as
// the received Promise's value and never reaches logs, errors, or
// the page's DOM. The token shares the listener's lifetime.

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

/** The page assets' CSP (script-src 'self' baseline. No inline, eval, or third parties). */
export const PRF_PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** The POST body's cap (PRF hex 64 + credential id hex ≤ 2048 + JSON envelope is enough). */
const MAX_BODY_BYTES = 4 * 1024;
const TOKEN_BYTES = 32;
const PRF_HEX_PATTERN = /^[0-9a-f]{64}$/;
const CREDENTIAL_ID_HEX_PATTERN = /^(?:[0-9a-f]{2}){1,1024}$/;
/** The confirmation code may mismatch up to this many times (room for typos + a brute-force cutoff). */
const MAX_CODE_ATTEMPTS = 5;

/** The result the listener settles (the page's POST, or the brute-force cutoff). */
export type PrfListenerOutcome = PrfPagePost | { readonly error: "too-many-code-attempts" };

/** A running PRF listener (one ceremony; closes itself after the first accepted POST). */
export interface PrfListener {
  /** The URL to open in a browser (`http://localhost:<port>/<token>/`). */
  readonly url: string;
  readonly port: number;
  /**
   * Resolves with the page's accepted POST (or the attempt cap). Rejects only when the
   * server itself fails after it started listening. close() before it settles leaves it pending.
   */
  readonly outcome: Promise<PrfListenerOutcome>;
  /** Stops listening and destroys open connections (idempotent). */
  readonly close: () => Promise<void>;
}

/** The page's POST body: the confirmation code plus the ceremony result. */
export interface ParsedPrfPost {
  readonly code: string;
  readonly post: PrfPagePost;
}

/** Parses the page's POST body; null when malformed (the request is then answered 404). */
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

/** Constant-time comparison (different lengths = mismatch). */
function codeMatches(expected: string, given: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(given, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function newToken(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES))).toString("base64url");
}

/** Headers common to every response (close caching, sniffing, and Referer). */
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

/** The uniform reasonless 404. */
function notFound(response: ServerResponse): void {
  reply(response, 404, "not found");
}

/** Static assets (GET under the token). */
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

/** Reads the body with a cap (excess severs the connection). */
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

/** The routing result (the caller writes the response). */
type Route =
  | { readonly kind: "not-found" }
  | { readonly kind: "redirect" }
  | { readonly kind: "asset"; readonly name: string }
  | { readonly kind: "post" };

/** Resolves the path under the token (token mismatch = null). */
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

/**
 * Routes in the order: Host exact match → token → method / path.
 * The page's assets are relative references like `./app.js`, so
 * when the page is opened at `/<token>` without the trailing slash
 * it goes after `/app.js` and does not work (a common failure when
 * typing the URL by hand or pasting it through port forwarding).
 * Steer toward the correct form.
 */
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

/**
 * Starts the PRF listener on 127.0.0.1 with a fresh one-time token and serves
 * the passkey page for `config`. A POST is accepted only when it carries
 * `confirmCode` (shown in the terminal, typed into the page); the returned
 * `outcome` resolves with the first accepted POST, after which every further
 * request is answered 404. Mismatching codes are answered 404 without consuming
 * the ceremony, up to a small cap that then fails the ceremony.
 */
export function startPrfListener(config: PrfPageConfig, confirmCode: string): Promise<PrfListener> {
  const token = newToken();
  const connections = new Set<Socket>();
  let settled = false;
  let codeAttempts = 0;
  // Settled from outside the Promise (the executor runs synchronously, so the assignment is always done)
  let resolveOutcome!: (post: PrfListenerOutcome) => void;
  let rejectOutcome!: (error: Error) => void;
  const outcome = new Promise<PrfListenerOutcome>((resolve, reject) => {
    resolveOutcome = resolve;
    rejectOutcome = reject;
  });
  let expectedHost = "";

  /** Only reads POSTs with an Origin exact match + JSON (after settling, everything is 404). */
  const postIsAcceptable = (request: IncomingMessage): boolean =>
    !settled &&
    request.headers.origin === `http://${expectedHost}` &&
    (request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json");

  /** Counts code mismatches and cuts off the whole ceremony at the cap (fail-closed). */
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
    // If another POST settled before this one finished reading, discard it (single-use)
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
      // A failure of the server itself after listen is passed to
      // the caller as a ceremony failure (not left as an unhandled
      // "error"). A per-connection failure just closes the
      // connection in node:http
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
