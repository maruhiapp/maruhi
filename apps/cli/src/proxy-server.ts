// The forward proxy of `maruhi proxy run` (PF4 — pf4-design.md rulings
// P1 / P2 / P4 / P6 / P7).
//
// The child process is pointed at this proxy (`HTTPS_PROXY` /
// `HTTP_PROXY`) and trusts the run's ephemeral CA (proxy-cert.ts). What
// it holds for each brokered variable is a placeholder; the real value
// exists only in this process and is written **into the request** at the
// moment it leaves toward a host the rule names — never into the child,
// never into a log.
//
// Shape (verified under Bun 1.4.2 and Node 22 — the design record's P2):
//
//   child ──HTTPS_PROXY──▶ net.Server (parse one request head)
//     CONNECT host:port
//       rule names host:port  ▶ 200 ▶ tls.TLSSocket (leaf for host) ▶ loopback
//                               http.Server bound to that target ▶ handleRequest
//       no rule                ▶ 200 ▶ blind TCP tunnel to host:port (never
//                               inspected; refused when `unmatched` = block)
//     GET http://host/…  (absolute form — plain HTTP)
//       ▶ loopback http.Server (one, the target is in the URL) ▶ handleRequest
//     GET https://…  in plain text ▶ 400 (a downgrade is refused)
//
// Only hosts a rule names are intercepted: everything else keeps its own
// end-to-end TLS (certificate pinning, mTLS, HTTP/2 untouched). The
// loopback hop exists because Bun's node:http server cannot adopt a
// TLSSocket as a connection (measured); it costs one local round trip.
//
// handleRequest (the inspection, ruling P6):
//   1. find every placeholder in the request target, headers (a Basic
//      credential is decoded first), and body;
//   2. a placeholder of a credential whose rule does not name this host,
//      or found on a surface the rule does not allow, refuses the whole
//      request (403 with a message naming the variable and the rule —
//      fail closed, and the agent learns why);
//   3. substitute, forward upstream with the client's method, path, and
//      headers (hop-by-hop headers dropped, `Accept-Encoding: identity`
//      so the response can be read), stream the response back with every
//      real value replaced by its placeholder (the child never sees a
//      value an API echoes — ruling P7).
//
// Decisions (brokered / tunnelled / blocked / error) are reported through
// a callback with method, host, port, path, status, and variable names —
// never a header value or body (the Infisical activity-log field set,
// minus anything that could carry a value).

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

import { type BytePattern, makeStreamReplacer, replaceBytes } from "./byte-replace.ts";
import type { EphemeralCa } from "./proxy-cert.ts";
import type { Surface } from "./proxy-config.ts";
import {
  authorityOf,
  type BrokeredCredential,
  credentialsFor,
  type Target,
} from "./proxy-rules.ts";

/** One request's outcome, for the verbose log and the end-of-run summary. */
export type ProxyDecision =
  | {
      readonly kind: "brokered";
      readonly method: string;
      readonly target: Target;
      /** The request target as the client sent it (placeholders, never values). */
      readonly path: string;
      readonly status: number;
      /** Variables substituted into this request (names only). */
      readonly substituted: readonly string[];
    }
  | { readonly kind: "tunnelled"; readonly target: Target }
  | {
      readonly kind: "blocked";
      readonly method: string;
      readonly target: Target;
      readonly path: string;
      readonly reason: string;
    }
  | {
      readonly kind: "error";
      readonly method: string;
      readonly target: Target;
      readonly path: string;
      readonly reason: string;
    };

export interface ProxyOptions {
  readonly credentials: readonly BrokeredCredential[];
  /** Destinations no rule names: tunnel untouched, or refuse. */
  readonly unmatched: "allow" | "block";
  readonly ca: EphemeralCa;
  readonly onDecision?: (decision: ProxyDecision) => void;
  /**
   * Test seams. `connect` redirects where an upstream connection goes (the
   * tests stand up loopback origins for the rule's hosts); `ca` adds roots
   * the upstream leg trusts (the test origin's). Production passes neither:
   * upstream goes to the named host with the runtime's root store.
   */
  readonly upstream?: {
    readonly connect?: (target: Target) => { readonly host: string; readonly port: number };
    readonly ca?: readonly string[];
  };
}

export interface ProxyHandle {
  /** `http://127.0.0.1:<port>` — the value of HTTP_PROXY / HTTPS_PROXY for the child. */
  readonly url: string;
  readonly port: number;
  readonly close: () => Promise<void>;
}

/** The largest request body the proxy inspects (API calls; uploads belong to unbrokered hosts). */
const MAX_INSPECTED_BODY = 32 * 1024 * 1024;
const MAX_HEAD = 64 * 1024;
const HEAD_END = "\r\n\r\n";

// Headers that describe one hop and must not be forwarded (RFC 9110 §7.6.1)
const HOP_BY_HOP = new Set([
  "connection",
  "proxy-connection",
  "proxy-authorization",
  "proxy-authenticate",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const textEncoder = new TextEncoder();

/** A short plain-text response written straight to a raw socket (before any protocol handoff). */
function rawResponse(status: number, reason: string, body: string): string {
  const bytes = Buffer.byteLength(body);
  return `HTTP/1.1 ${status} ${reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${bytes}\r\nConnection: close\r\nProxy-Agent: maruhi\r\n\r\n${body}`;
}

/** Parses `host[:port]` (an IPv6 literal in brackets is refused — rules cannot name one). */
function parseAuthority(
  text: string,
  defaultPort: number,
): { readonly host: string; readonly port: number } | null {
  if (text.startsWith("[")) {
    return null;
  }
  const colon = text.lastIndexOf(":");
  const host = (colon >= 0 ? text.slice(0, colon) : text).toLowerCase();
  const portText = colon >= 0 ? text.slice(colon + 1) : String(defaultPort);
  if (host.length === 0 || !/^\d{1,5}$/.test(portText)) {
    return null;
  }
  const port = Number(portText);
  return port >= 1 && port <= 65535 ? { host, port } : null;
}

/** Splits an absolute-form request target into its target and origin-form path. */
function parseAbsoluteForm(
  url: string,
): { readonly target: Target; readonly path: string } | "https" | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol === "https:") {
    return "https";
  }
  if (parsed.protocol !== "http:") {
    return null;
  }
  const port = parsed.port === "" ? 80 : Number(parsed.port);
  return {
    target: { scheme: "http", host: parsed.hostname.toLowerCase(), port },
    path: `${parsed.pathname}${parsed.search}`,
  };
}

/** Pipes two sockets into each other and tears both down together. */
function bridge(a: net.Socket, b: net.Socket): void {
  const teardown = () => {
    a.destroy();
    b.destroy();
  };
  a.on("error", teardown);
  b.on("error", teardown);
  a.on("close", teardown);
  b.on("close", teardown);
  a.pipe(b);
  b.pipe(a);
}

/* -------------------------------------------------------------------------- */
/* Request inspection                                                           */
/* -------------------------------------------------------------------------- */

/** Where a placeholder was found, for the refusal wording. */
type Found = { readonly credential: BrokeredCredential; readonly surface: Surface };

function findIn(text: string, credentials: readonly BrokeredCredential[]): BrokeredCredential[] {
  return credentials.filter((credential) => text.includes(credential.placeholder));
}

function substituteText(text: string, values: ReadonlyMap<BrokeredCredential, string>): string {
  let out = text;
  for (const [credential, value] of values) {
    out = out.split(credential.placeholder).join(value);
  }
  return out;
}

const BASIC_PREFIX = /^basic\s+/i;

/** `Basic <base64>` → the decoded `user:password` text (null when not Basic or not base64). */
function decodeBasic(value: string): string | null {
  if (!BASIC_PREFIX.test(value)) {
    return null;
  }
  const encoded = value.replace(BASIC_PREFIX, "").trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    return null;
  }
  return Buffer.from(encoded, "base64").toString("utf8");
}

interface Inspection {
  /** Placeholders found in the request, by surface. */
  readonly found: readonly Found[];
}

/** Placeholders in the headers (a Basic credential is searched decoded as well). */
function findInHeaders(
  headers: Readonly<Record<string, string>>,
  credentials: readonly BrokeredCredential[],
): Found[] {
  const found: Found[] = [];
  for (const [name, value] of Object.entries(headers)) {
    const decoded = name === "authorization" ? decodeBasic(value) : null;
    const text = decoded === null ? value : `${value} ${decoded}`;
    for (const credential of findIn(text, credentials)) {
      found.push({ credential, surface: "header" });
    }
  }
  return found;
}

function findInBody(body: Buffer, credentials: readonly BrokeredCredential[]): Found[] {
  if (body.length === 0) {
    return [];
  }
  return credentials
    .filter((credential) => body.includes(credential.placeholder, 0, "latin1"))
    .map((credential) => ({ credential, surface: "body" as const }));
}

function inspectRequest(input: {
  readonly path: string;
  readonly query: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  readonly credentials: readonly BrokeredCredential[];
}): Inspection {
  const found: Found[] = [
    ...findIn(input.path, input.credentials).map((credential) => ({
      credential,
      surface: "path" as const,
    })),
    ...findIn(input.query, input.credentials).map((credential) => ({
      credential,
      surface: "query" as const,
    })),
    ...findInHeaders(input.headers, input.credentials),
    ...findInBody(input.body, input.credentials),
  ];
  return { found };
}

/** Current real values of the credentials that may be substituted into a request (only the ones the request uses). */
async function resolveValues(
  allowed: readonly BrokeredCredential[],
  needed: ReadonlySet<BrokeredCredential>,
): Promise<Map<BrokeredCredential, string>> {
  const values = new Map<BrokeredCredential, string>();
  for (const credential of allowed) {
    if (!needed.has(credential)) {
      continue;
    }
    const bytes = await credential.resolve();
    values.set(credential, Buffer.from(bytes).toString("utf8"));
  }
  return values;
}

/** The refusal for a placeholder used where its rule does not allow it (null = every use is allowed). */
function refusalFor(
  found: readonly Found[],
  allowed: readonly BrokeredCredential[],
  target: Target,
): string | null {
  for (const { credential, surface } of found) {
    if (!allowed.includes(credential)) {
      return `the placeholder for ${credential.name} is only substituted toward the hosts its rule names (this request is for ${authorityOf(target)}); the request was not sent`;
    }
    if (!credential.surfaces.includes(surface)) {
      return `the placeholder for ${credential.name} appears in the ${surface} of the request, but its rule allows only: ${credential.surfaces.join(", ")} (add "${surface}" to the rule's surfaces to allow it); the request was not sent`;
    }
  }
  return null;
}

async function readBody(req: http.IncomingMessage, cap: number): Promise<Buffer | "too-large"> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > cap) {
      return "too-large";
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/** Headers of the incoming request as single strings (repeated headers joined as Node does). */
function flattenHeaders(req: http.IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) {
      continue;
    }
    out[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return out;
}

function sendText(res: http.ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": String(Buffer.byteLength(body)),
    "proxy-agent": "maruhi",
  });
  res.end(body);
}

/** The request as it leaves toward the origin: substituted path, headers, and body. */
function buildUpstreamRequest(input: {
  readonly target: Target;
  readonly path: string;
  readonly query: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  readonly values: ReadonlyMap<BrokeredCredential, string>;
}): {
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly body: Buffer;
  readonly substituted: readonly string[];
} {
  const { values } = input;
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.headers)) {
    if (HOP_BY_HOP.has(name)) {
      continue;
    }
    headers[name] =
      name === "authorization"
        ? substituteAuthorization(value, values)
        : substituteText(value, values);
  }
  const bodyPatterns: BytePattern[] = [...values].map(([credential, value]) => ({
    from: textEncoder.encode(credential.placeholder),
    to: textEncoder.encode(value),
  }));
  const body = Buffer.from(replaceBytes(input.body, bodyPatterns));
  headers["host"] = authorityOf(input.target);
  // The response must be readable to be scrubbed (and HTTP/1.1 upstream keeps it simple)
  headers["accept-encoding"] = "identity";
  if (body.length > 0 || input.headers["content-length"] !== undefined) {
    headers["content-length"] = String(body.length);
  }
  return {
    path: substituteText(input.path, values) + substituteText(input.query, values),
    headers,
    body,
    substituted: [...values.keys()].map((credential) => credential.name).toSorted(),
  };
}

/** `Authorization`: a Basic credential is substituted decoded and re-encoded; anything else as text. */
function substituteAuthorization(
  value: string,
  values: ReadonlyMap<BrokeredCredential, string>,
): string {
  const decoded = decodeBasic(value);
  if (decoded === null) {
    return substituteText(value, values);
  }
  const substituted = substituteText(decoded, values);
  return substituted === decoded
    ? value
    : `Basic ${Buffer.from(substituted, "utf8").toString("base64")}`;
}

/**
 * Streams the origin's response back with every real value replaced by
 * its placeholder (byte domain). `done` receives the status, or "failed".
 */
function relayResponse(
  upstream: http.IncomingMessage,
  res: http.ServerResponse,
  scrub: readonly BytePattern[],
  done: (outcome: number | "failed") => void,
): void {
  // Response headers are scrubbed too (a token echoed in a header — the
  // same real → placeholder replacement as the body, on header text)
  const scrubHeader = (text: string): string =>
    scrub.reduce(
      (current, pattern) =>
        current
          .split(Buffer.from(pattern.from).toString("latin1"))
          .join(Buffer.from(pattern.to).toString("latin1")),
      text,
    );
  const responseHeaders: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(upstream.headers)) {
    // Length changes under scrubbing: let the server frame the body (chunked)
    if (value === undefined || HOP_BY_HOP.has(name) || name === "content-length") {
      continue;
    }
    responseHeaders[name] = Array.isArray(value) ? value.map(scrubHeader) : scrubHeader(value);
  }
  res.writeHead(upstream.statusCode ?? 502, responseHeaders);
  const replacer = makeStreamReplacer(scrub);
  upstream.on("data", (chunk: Buffer) => {
    const out = replacer.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length));
    if (out.length > 0) {
      res.write(Buffer.from(out));
    }
  });
  upstream.on("end", () => {
    const tail = replacer.flush();
    if (tail.length > 0) {
      res.write(Buffer.from(tail));
    }
    res.end();
    done(upstream.statusCode ?? 0);
  });
  upstream.on("error", () => {
    res.destroy();
    done("failed");
  });
}

/* -------------------------------------------------------------------------- */
/* The proxy                                                                    */
/* -------------------------------------------------------------------------- */

/** Starts the proxy on an ephemeral loopback port. */
export async function startProxy(options: ProxyOptions): Promise<ProxyHandle> {
  const decide = options.onDecision ?? (() => {});
  const connectTo =
    options.upstream?.connect ?? ((target: Target) => ({ host: target.host, port: target.port }));
  const upstreamCa = options.upstream?.ca;
  const servers: net.Server[] = [];

  const listen = (server: net.Server): Promise<number> =>
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        servers.push(server);
        resolve((server.address() as net.AddressInfo).port);
      });
    });

  /** Patterns scrubbing every brokered value out of a response (real → placeholder). */
  const scrubbers = async (): Promise<BytePattern[]> => {
    const patterns: BytePattern[] = [];
    for (const credential of options.credentials) {
      // A connector that has not minted yet has no value to scrub; one
      // that fails is reported on the request path, not here
      const bytes = await credential.resolve().catch(() => null);
      if (bytes !== null && bytes.length > 0) {
        patterns.push({ from: bytes, to: textEncoder.encode(credential.placeholder) });
      }
    }
    return patterns;
  };

  /**
   * One inspected request (over the MITM hop or plain absolute-form):
   * inspect → refuse or substitute → forward → scrub the response.
   */
  /** The inspected request, forwarded: substitution, upstream, scrubbed response. */
  const forward = (input: {
    readonly req: http.IncomingMessage;
    readonly res: http.ServerResponse;
    readonly target: Target;
    readonly requestPath: string;
    readonly path: string;
    readonly query: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly body: Buffer;
    readonly values: ReadonlyMap<BrokeredCredential, string>;
    readonly scrub: readonly BytePattern[];
  }): Promise<void> => {
    const { res, target, requestPath } = input;
    const method = input.req.method ?? "GET";
    const outgoing = buildUpstreamRequest(input);
    const where = connectTo(target);
    const request = (target.scheme === "https" ? https : http).request({
      host: where.host,
      port: where.port,
      servername: target.scheme === "https" ? target.host : undefined,
      ca: upstreamCa === undefined ? undefined : [...upstreamCa],
      method,
      path: outgoing.path,
      headers: outgoing.headers,
      // The run's values are not retried on another connection by the proxy
      agent: false,
    });
    return new Promise<void>((resolve) => {
      request.on("error", (error: NodeJS.ErrnoException) => {
        const reason = `cannot reach ${authorityOf(target)}${error.code === undefined ? "" : ` (${error.code})`}`;
        if (!res.headersSent) {
          sendText(res, 502, `maruhi proxy: ${reason}`);
        } else {
          res.destroy();
        }
        decide({ kind: "error", method, target, path: requestPath, reason });
        resolve();
      });
      request.on("response", (upstream) => {
        relayResponse(upstream, res, input.scrub, (outcome) => {
          decide(
            outcome === "failed"
              ? { kind: "error", method, target, path: requestPath, reason: "upstream read failed" }
              : {
                  kind: "brokered",
                  method,
                  target,
                  path: requestPath,
                  status: outcome,
                  substituted: outgoing.substituted,
                },
          );
          resolve();
        });
      });
      request.end(outgoing.body);
    });
  };

  /**
   * One inspected request (over the MITM hop or plain absolute-form):
   * inspect → refuse or substitute → forward → scrub the response.
   */
  const handleRequest = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
    target: Target,
    requestPath: string,
  ): Promise<void> => {
    const method = req.method ?? "GET";
    const blocked = (status: number, text: string, reason: string) => {
      sendText(res, status, `maruhi proxy: ${text}`);
      decide({ kind: "blocked", method, target, path: requestPath, reason });
    };
    const allowed = credentialsFor(options.credentials, target);
    if (req.headers["upgrade"] !== undefined) {
      blocked(
        501,
        `protocol upgrades (${req.headers["upgrade"]}) to a brokered host are not supported; the request was not sent`,
        "protocol upgrade",
      );
      return;
    }
    const body = await readBody(req, MAX_INSPECTED_BODY);
    if (body === "too-large") {
      blocked(
        413,
        `a request body over ${MAX_INSPECTED_BODY / (1024 * 1024)} MiB to a brokered host is not inspected; send large uploads to a host no rule names`,
        "body too large",
      );
      return;
    }
    const questionMark = requestPath.indexOf("?");
    const path = questionMark < 0 ? requestPath : requestPath.slice(0, questionMark);
    const query = questionMark < 0 ? "" : requestPath.slice(questionMark);
    const headers = flattenHeaders(req);
    const { found } = inspectRequest({
      path,
      query,
      headers,
      body,
      credentials: options.credentials,
    });
    const refusal = refusalFor(found, allowed, target);
    if (refusal !== null) {
      blocked(403, refusal, refusal);
      return;
    }
    const needed = new Set(found.map((entry) => entry.credential));
    let values: Map<BrokeredCredential, string>;
    let scrub: BytePattern[];
    try {
      values = await resolveValues(allowed, needed);
      scrub = await scrubbers();
    } catch (error) {
      const reason = error instanceof Error ? error.message : "credential unavailable";
      sendText(res, 502, `maruhi proxy: ${reason}; the request was not sent`);
      decide({ kind: "error", method, target, path: requestPath, reason });
      return;
    }
    await forward({ req, res, target, requestPath, path, query, headers, body, values, scrub });
  };

  /** Runs an async handler, turning an unexpected failure into a 500 (never an unhandled rejection). */
  const guarded = (
    req: http.IncomingMessage,
    res: http.ServerResponse,
    target: Target,
    requestPath: string,
  ): void => {
    handleRequest(req, res, target, requestPath).catch((error: unknown) => {
      const reason = error instanceof Error ? error.constructor.name : "failure";
      if (!res.headersSent) {
        sendText(res, 500, `maruhi proxy: internal error (${reason})`);
      } else {
        res.destroy();
      }
      decide({ kind: "error", method: req.method ?? "GET", target, path: requestPath, reason });
    });
  };

  // The MITM loopback servers, one per brokered authority (the handler
  // trusts the CONNECT target, never the Host header — ruling P6)
  const mitmServers = new Map<string, Promise<number>>();
  const mitmPortFor = (target: Target): Promise<number> => {
    const key = authorityOf(target);
    let pending = mitmServers.get(key);
    if (pending === undefined) {
      const server = http.createServer((req, res) => {
        // Inside the tunnel the client writes origin-form; an absolute-form
        // target is reduced to its path (the authority is the tunnel's)
        const raw = req.url ?? "/";
        const requestPath = raw.startsWith("/")
          ? raw
          : ((parseAbsoluteForm(raw) as { path: string } | null)?.path ?? raw);
        guarded(req, res, target, typeof requestPath === "string" ? requestPath : raw);
      });
      pending = listen(server);
      mitmServers.set(key, pending);
    }
    return pending;
  };

  // The plain-HTTP loopback server (absolute-form requests; the target is in the URL)
  const plainServer = http.createServer((req, res) => {
    const parsed = parseAbsoluteForm(req.url ?? "");
    if (parsed === null || parsed === "https") {
      sendText(
        res,
        400,
        parsed === "https"
          ? "maruhi proxy: an https URL sent in plain text is refused (use CONNECT, as every HTTPS client does)"
          : "maruhi proxy: a proxy request must use an absolute URL (http://host/path)",
      );
      return;
    }
    const allowed = credentialsFor(options.credentials, parsed.target);
    if (allowed.length === 0 && options.unmatched === "block") {
      sendText(
        res,
        403,
        `maruhi proxy: ${authorityOf(parsed.target)} is not named by any rule and this run blocks unmatched hosts; the request was not sent`,
      );
      decide({
        kind: "blocked",
        method: req.method ?? "GET",
        target: parsed.target,
        path: parsed.path,
        reason: "unmatched host (block)",
      });
      return;
    }
    guarded(req, res, parsed.target, parsed.path);
  });
  const plainPort = await listen(plainServer);

  /** One client connection to the proxy: read the first head, then dispatch. */
  const onConnection = (socket: net.Socket): void => {
    let head = Buffer.alloc(0);
    socket.on("error", () => socket.destroy());
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf(HEAD_END);
      if (end < 0) {
        if (head.length > MAX_HEAD) {
          socket.end(
            rawResponse(
              431,
              "Request Header Fields Too Large",
              "maruhi proxy: request head too large\n",
            ),
          );
        }
        return;
      }
      socket.off("data", onData);
      socket.pause();
      const rest = head.subarray(end + HEAD_END.length);
      const lines = head.subarray(0, end).toString("latin1").split("\r\n");
      const [method = "", requestTarget = ""] = (lines[0] ?? "").split(" ");
      if (method === "CONNECT") {
        void onConnect(socket, requestTarget, rest);
        return;
      }
      // Plain HTTP: hand the whole buffered bytes to the loopback server
      const upstream = net.connect(plainPort, "127.0.0.1", () => {
        upstream.write(head);
        socket.resume();
        bridge(socket, upstream);
      });
      upstream.on("error", () => socket.destroy());
    };
    socket.on("data", onData);
  };

  const onConnect = async (socket: net.Socket, authority: string, rest: Buffer): Promise<void> => {
    const parsed = parseAuthority(authority, 443);
    if (parsed === null) {
      socket.end(rawResponse(400, "Bad Request", "maruhi proxy: CONNECT needs host:port\n"));
      return;
    }
    const target: Target = { scheme: "https", ...parsed };
    const allowed = credentialsFor(options.credentials, target);
    if (allowed.length === 0) {
      if (options.unmatched === "block") {
        socket.end(
          rawResponse(
            403,
            "Forbidden",
            `maruhi proxy: ${authorityOf(target)} is not named by any rule and this run blocks unmatched hosts\n`,
          ),
        );
        decide({
          kind: "blocked",
          method: "CONNECT",
          target,
          path: "",
          reason: "unmatched host (block)",
        });
        return;
      }
      // Blind tunnel: never inspected, the client's own TLS end to end
      const where = connectTo(target);
      const upstream = net.connect(where.port, where.host, () => {
        socket.write(`HTTP/1.1 200 Connection Established\r\nProxy-Agent: maruhi\r\n\r\n`);
        if (rest.length > 0) {
          upstream.write(rest);
        }
        socket.resume();
        bridge(socket, upstream);
        decide({ kind: "tunnelled", target });
      });
      upstream.on("error", (error: NodeJS.ErrnoException) => {
        socket.end(
          rawResponse(
            502,
            "Bad Gateway",
            `maruhi proxy: cannot reach ${authorityOf(target)}${error.code === undefined ? "" : ` (${error.code})`}\n`,
          ),
        );
        decide({
          kind: "error",
          method: "CONNECT",
          target,
          path: "",
          reason: `cannot reach (${error.code ?? "?"})`,
        });
      });
      return;
    }
    // Brokered: terminate TLS with a leaf for this host, hand the plaintext to the bound loopback server
    try {
      const [leaf, mitmPort] = await Promise.all([
        options.ca.issue(target.host),
        mitmPortFor(target),
      ]);
      socket.write(`HTTP/1.1 200 Connection Established\r\nProxy-Agent: maruhi\r\n\r\n`);
      if (rest.length > 0) {
        // Bytes the client sent before our 200 (a TLS ClientHello sent eagerly)
        socket.unshift(rest);
      }
      const secure = new tls.TLSSocket(socket, {
        isServer: true,
        key: leaf.keyPem,
        cert: leaf.certPem,
        ALPNProtocols: ["http/1.1"],
      });
      secure.on("error", () => secure.destroy());
      const loop = net.connect(mitmPort, "127.0.0.1", () => {
        socket.resume();
        bridge(secure, loop);
      });
      loop.on("error", () => secure.destroy());
    } catch {
      socket.end(
        rawResponse(
          500,
          "Internal Server Error",
          "maruhi proxy: cannot set up the brokered connection\n",
        ),
      );
    }
  };

  const proxy = net.createServer(onConnection);
  const port = await listen(proxy);

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    close: async () => {
      await Promise.all(
        servers.map(
          (server) =>
            new Promise<void>((resolve) => {
              server.close(() => resolve());
              // Idle keep-alive connections would hold close() open
              if ("closeAllConnections" in server) {
                (server as http.Server).closeAllConnections();
              }
            }),
        ),
      );
    },
  };
}
