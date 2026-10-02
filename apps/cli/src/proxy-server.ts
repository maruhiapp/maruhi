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

import { timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { join } from "node:path";
import { pipeline, Transform } from "node:stream";
import tls from "node:tls";
import zlib from "node:zlib";

import {
  type BytePattern,
  makeStreamReplacer,
  replaceBytes,
  scrubPatterns,
} from "./byte-replace.ts";
import type { EphemeralCa } from "./proxy-cert.ts";
import type { Surface } from "./proxy-config.ts";
import {
  authorityOf,
  type BrokeredCredential,
  credentialsFor,
  hostHeaderOf,
  type Target,
} from "./proxy-rules.ts";

/** One request's outcome, for the verbose log and the end-of-run summary. */
export type ProxyDecision =
  | {
      readonly kind: "brokered";
      readonly method: string;
      readonly target: Target;
      /** The request path **without its query** (a query can carry a pass-through value the child put there — §19 D-7). */
      readonly path: string;
      readonly status: number;
      /** Variables substituted into this request (names only). */
      readonly substituted: readonly string[];
    }
  | {
      /** A plain-HTTP request toward a host no rule names: relayed through the inspection path, nothing substituted. */
      readonly kind: "relayed";
      readonly method: string;
      readonly target: Target;
      readonly path: string;
      readonly status: number;
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
  /**
   * The run's private directory (0700, removed at exit). The hop servers —
   * the per-host plaintext handlers behind the TLS termination and the
   * plain-HTTP handler — listen on Unix domain sockets inside it, so only
   * what the proxy itself bridges (after the credential check) and the
   * same OS user can reach them: a TCP loopback port would let any local
   * process, or another OS user on the host, send a placeholder straight
   * to a hop and have it substituted (review finding §21 R-2). Socket paths
   * are length-limited (104 bytes on macOS, 108 on Linux): a directory too
   * deep makes `startProxy` fail. Windows (named pipes) is outside support.
   */
  readonly hopDir: string;
  /**
   * The proxy credential every client must present (`Proxy-Authorization:
   * Basic`), carried as userinfo in the proxy URL the child receives. Keeps
   * other local processes off this run's proxy (§19 D-14b). Absent = open.
   */
  readonly credential?: { readonly user: string; readonly password: string } | undefined;
  /**
   * Where the proxy listens (default `127.0.0.1:0` — the loopback, an
   * ephemeral port). A sandbox on another network namespace reaches the
   * proxy through a reachable address (a Docker bridge, `0.0.0.0`); every
   * request still needs the run's credential.
   */
  readonly listen?: { readonly host: string; readonly port: number } | undefined;
  /**
   * The `host[:port]` the child is told to use in the proxy URL when it
   * differs from the bound address (`host.docker.internal` from a
   * container). Without a port the bound port is used.
   */
  readonly advertise?: string | undefined;
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
  /** `http://[user:password@]<advertised host>:<port>` — the value of HTTP_PROXY / HTTPS_PROXY for the child (carries the credential). */
  readonly url: string;
  /** The bound `host:port` — for messages (never the credential). */
  readonly address: string;
  /** The `host:port` the child is told (differs from `address` under `advertise`). */
  readonly advertised: string;
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
function rawResponse(status: number, reason: string, body: string, extraHeader = ""): string {
  const bytes = Buffer.byteLength(body);
  const extra = extraHeader === "" ? "" : `${extraHeader}\r\n`;
  return `HTTP/1.1 ${status} ${reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${bytes}\r\nConnection: close\r\nProxy-Agent: maruhi\r\n${extra}\r\n${body}`;
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
  // Lower-cased, and a trailing dot (an absolute DNS name) dropped so it matches the rule
  const host = (colon >= 0 ? text.slice(0, colon) : text).toLowerCase().replace(/\.$/, "");
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
    target: { scheme: "http", host: parsed.hostname.toLowerCase().replace(/\.$/, ""), port },
    path: `${parsed.pathname}${parsed.search}`,
  };
}

/** Inside a tunnel the client writes origin-form; an absolute-form target is reduced to its path. */
function originFormOf(raw: string): string {
  if (raw.startsWith("/")) {
    return raw;
  }
  try {
    const parsed = new URL(raw);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return raw;
  }
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
  // A value in the request target must be percent-encoded (a space, `&`,
  // `#`, `%`, `+` would change the URL's meaning or be refused by the HTTP
  // client — review finding §19 C-4); a header value must stay a single
  // Latin-1 line (a line break would be refused by the client; a value that
  // cannot be a header is reported, never mangled)
  const encoded = new Map(
    [...values].map(([credential, value]) => [credential, encodeURIComponent(value)]),
  );
  for (const [credential, value] of values) {
    if (!isHeaderSafe(value)) {
      throw new UnsendableValueError(credential.name);
    }
  }
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
  headers["host"] = hostHeaderOf(input.target);
  // The response must be readable to be scrubbed (and HTTP/1.1 upstream keeps it simple)
  headers["accept-encoding"] = "identity";
  if (body.length > 0 || input.headers["content-length"] !== undefined) {
    headers["content-length"] = String(body.length);
  }
  return {
    path: substituteText(input.path, encoded) + substituteText(input.query, encoded),
    headers,
    body,
    substituted: [...values.keys()].map((credential) => credential.name).toSorted(),
  };
}

/** A single Latin-1 line (what an HTTP header value may carry). */
function isHeaderSafe(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x0d || code === 0x0a || code > 0xff) {
      return false;
    }
  }
  return true;
}

/** A brokered value that cannot travel in a header (a line break or a non-Latin-1 character). */
class UnsendableValueError extends Error {
  constructor(readonly variable: string) {
    super("unsendable value");
  }
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

/** The request path without its query (what decisions carry). */
function pathOnly(requestPath: string): string {
  const questionMark = requestPath.indexOf("?");
  return questionMark < 0 ? requestPath : requestPath.slice(0, questionMark);
}

type Decompressor = zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress;

/**
 * The decompressor for a `Content-Encoding`: `null` for identity, a stream
 * for an encoding the proxy can undo, or `"unsupported"` (an unknown token
 * or a stack of encodings) — then the body cannot be scrubbed and the
 * response is refused rather than forwarded unread (fail closed — §19 D-12).
 */
const DECOMPRESSORS: Readonly<Record<string, () => Decompressor | "unsupported" | null>> = {
  "": () => null,
  identity: () => null,
  gzip: () => zlib.createGunzip(),
  "x-gzip": () => zlib.createGunzip(),
  deflate: () => zlib.createInflate(),
  br: () => zlib.createBrotliDecompress(),
  // Node 22.15+ and Bun ship it; older runtimes refuse the response
  zstd: () =>
    "createZstdDecompress" in zlib
      ? (zlib as unknown as { createZstdDecompress: () => Decompressor }).createZstdDecompress()
      : "unsupported",
};

function decompressorFor(
  encoding: string | string[] | undefined,
): Decompressor | "unsupported" | null {
  const value = (Array.isArray(encoding) ? encoding.join(",") : (encoding ?? ""))
    .trim()
    .toLowerCase();
  const make = DECOMPRESSORS[value];
  return make === undefined ? "unsupported" : make();
}

/**
 * The origin's response headers as forwarded: hop-by-hop and length
 * dropped (the body is re-framed), `Content-Encoding` dropped when the
 * body is decompressed here, and every value scrubbed (a token echoed in
 * a header — the same real → placeholder replacement as the body).
 */
function scrubbedResponseHeaders(
  headers: http.IncomingHttpHeaders,
  scrub: readonly BytePattern[],
  decompressed: boolean,
  /** The response carries no body to re-frame (HEAD / 204 / 304): keep its length header. */
  bodiless: boolean,
): Record<string, string | string[]> {
  const scrubHeader = (text: string): string =>
    scrub.reduce(
      (current, pattern) =>
        current
          .split(Buffer.from(pattern.from).toString("latin1"))
          .join(Buffer.from(pattern.to).toString("latin1")),
      text,
    );
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    const dropped =
      HOP_BY_HOP.has(name) ||
      (name === "content-length" && !bodiless) ||
      (decompressed && name === "content-encoding");
    if (value === undefined || dropped) {
      continue;
    }
    out[name] = Array.isArray(value) ? value.map(scrubHeader) : scrubHeader(value);
  }
  return out;
}

/**
 * Streams the origin's response back with every real value replaced by
 * its placeholder (byte domain). `done` receives the status, or "failed".
 */
function relayResponse(
  upstream: http.IncomingMessage,
  res: http.ServerResponse,
  scrub: readonly BytePattern[],
  method: string,
  done: (outcome: number | "failed") => void,
): void {
  const status = upstream.statusCode ?? 502;
  // No body to re-frame: a HEAD answer, 204, 304 — the origin's framing headers stay
  if (method === "HEAD" || status === 204 || status === 304) {
    upstream.resume();
    res.writeHead(status, scrubbedResponseHeaders(upstream.headers, scrub, false, true));
    res.end();
    done(status);
    return;
  }
  // The proxy asked for an identity response; a server that compresses
  // anyway would hide an echoed value from the scrubber, so a compressed
  // body is decompressed here and delivered as identity (fail closed for
  // the scrub — pf4-design.md §18 D)
  const decoder = decompressorFor(upstream.headers["content-encoding"]);
  if (decoder === "unsupported") {
    upstream.resume();
    sendText(
      res,
      502,
      `maruhi proxy: the response from the host used a content encoding the proxy cannot read (${String(upstream.headers["content-encoding"])}), so it could not be checked for echoed values and was not relayed`,
    );
    done("failed");
    return;
  }
  res.writeHead(status, scrubbedResponseHeaders(upstream.headers, scrub, decoder !== null, false));
  // scrubPatterns carries each line of a multi-line value: the carry-over may be cut at newlines
  const replacer = makeStreamReplacer(scrub, { cutAtNewline: true });
  const scrubbing = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      callback(
        null,
        Buffer.from(replacer.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length))),
      );
    },
    flush(callback) {
      callback(null, Buffer.from(replacer.flush()));
    },
  });
  // `pipeline` carries backpressure end to end (a slow client no longer
  // buffers the whole body in the proxy — review finding §19 C-6) and tears
  // every stage down on an error or on the client leaving
  const stages: NodeJS.ReadWriteStream[] = decoder === null ? [scrubbing] : [decoder, scrubbing];
  pipeline(upstream, ...stages, res, (error) => {
    done(error ? "failed" : status);
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

  const listenOn = (server: net.Server, host: string, port: number): Promise<number> =>
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        servers.push(server);
        resolve((server.address() as net.AddressInfo).port);
      });
    });
  // The hop servers speak plaintext and are never on a TCP port: a Unix
  // socket in the run's private directory (see ProxyOptions.hopDir)
  const listenHop = (server: net.Server, name: string): Promise<string> =>
    new Promise((resolve, reject) => {
      const path = join(options.hopDir, name);
      server.once("error", reject);
      server.listen(path, () => {
        server.off("error", reject);
        servers.push(server);
        resolve(path);
      });
    });

  /**
   * Patterns scrubbing every brokered value out of a response (real →
   * placeholder), from the values the credentials already hold — **never
   * minting** (a connector mints only for a request that uses its
   * placeholder — §19 D-1). The `maruhi sync` fragment rule applies (whole /
   * per line / JSON-escaped — §19 D-5).
   */
  const scrubbers = (): BytePattern[] =>
    options.credentials.flatMap((credential) =>
      scrubPatterns(credential.known(), credential.placeholder),
    );

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
    /** The credentials whose rules name this target (empty = a relayed plain request). */
    readonly allowed: readonly BrokeredCredential[];
  }): Promise<void> => {
    const { res, target, requestPath } = input;
    const method = input.req.method ?? "GET";
    const path = pathOnly(requestPath);
    let outgoing: ReturnType<typeof buildUpstreamRequest>;
    let request: http.ClientRequest;
    try {
      outgoing = buildUpstreamRequest(input);
      const where = connectTo(target);
      request = (target.scheme === "https" ? https : http).request({
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
    } catch (error) {
      // A value that cannot be sent as asked (the HTTP client refuses the
      // request before anything leaves — nothing was sent)
      const reason =
        error instanceof UnsendableValueError
          ? `the value of ${error.variable} cannot be sent in a header (it contains a line break or a non-Latin-1 character)`
          : `the request could not be built${(error as NodeJS.ErrnoException).code === undefined ? "" : ` (${(error as NodeJS.ErrnoException).code})`}`;
      sendText(res, 502, `maruhi proxy: ${reason}; the request was not sent`);
      decide({ kind: "error", method, target, path, reason });
      return Promise.resolve();
    }
    // The client left before the answer: stop reading the origin
    res.on("close", () => {
      if (!res.writableFinished) {
        request.destroy();
      }
    });
    return new Promise<void>((resolve) => {
      request.on("error", (error: NodeJS.ErrnoException) => {
        const reason = `cannot reach ${authorityOf(target)}${error.code === undefined ? "" : ` (${error.code})`}`;
        if (!res.headersSent) {
          sendText(res, 502, `maruhi proxy: ${reason}`);
        } else {
          res.destroy();
        }
        decide({ kind: "error", method, target, path, reason });
        resolve();
      });
      request.on("response", (upstream) => {
        relayResponse(upstream, res, input.scrub, method, (outcome) => {
          if (outcome === "failed") {
            decide({
              kind: "error",
              method,
              target,
              path,
              reason: "upstream response not relayed",
            });
          } else if (input.allowed.length === 0) {
            // Plain HTTP toward a host no rule names: inspected, nothing substituted
            decide({ kind: "relayed", method, target, path, status: outcome });
          } else {
            decide({
              kind: "brokered",
              method,
              target,
              path,
              status: outcome,
              substituted: outgoing.substituted,
            });
          }
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
      decide({ kind: "blocked", method, target, path: pathOnly(requestPath), reason });
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
      scrub = scrubbers();
    } catch (error) {
      const reason = error instanceof Error ? error.message : "credential unavailable";
      sendText(res, 502, `maruhi proxy: ${reason}; the request was not sent`);
      decide({ kind: "error", method, target, path: pathOnly(requestPath), reason });
      return;
    }
    await forward({
      req,
      res,
      target,
      requestPath,
      path,
      query,
      headers,
      body,
      values,
      scrub,
      allowed,
    });
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
      decide({
        kind: "error",
        method: req.method ?? "GET",
        target,
        path: pathOnly(requestPath),
        reason,
      });
    });
  };

  // The MITM loopback servers, one per brokered authority (the handler
  // trusts the CONNECT target, never the Host header — ruling P6)
  const mitmServers = new Map<string, Promise<string>>();
  let mitmCount = 0;
  const mitmPathFor = (target: Target): Promise<string> => {
    const key = authorityOf(target);
    let pending = mitmServers.get(key);
    if (pending === undefined) {
      const server = http.createServer((req, res) => {
        // The authority is the tunnel's (never the request's)
        guarded(req, res, target, originFormOf(req.url ?? "/"));
      });
      mitmCount += 1;
      pending = listenHop(server, `h${mitmCount}`);
      // A failed listen is not remembered (the next CONNECT tries again)
      pending.catch(() => mitmServers.delete(key));
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
        path: pathOnly(parsed.path),
        reason: "unmatched host (block)",
      });
      return;
    }
    guarded(req, res, parsed.target, parsed.path);
  });
  const plainPath = await listenHop(plainServer, "plain");

  // The expected `Proxy-Authorization` value (null = no credential required)
  const expectedAuthorization =
    options.credential === undefined
      ? null
      : Buffer.from(
          `Basic ${Buffer.from(`${options.credential.user}:${options.credential.password}`).toString("base64")}`,
          "latin1",
        );
  /** Whether the request head carries this run's proxy credential (constant-time compare). */
  const presentsCredential = (lines: readonly string[]): boolean => {
    if (expectedAuthorization === null) {
      return true;
    }
    const header = lines.find((line) => /^proxy-authorization:/i.test(line));
    if (header === undefined) {
      return false;
    }
    const given = Buffer.from(header.slice(header.indexOf(":") + 1).trim(), "latin1");
    return (
      given.length === expectedAuthorization.length && timingSafeEqual(given, expectedAuthorization)
    );
  };

  // Every client connection, so close() can end tunnels a grandchild left open (§19 C-3)
  const clients = new Set<net.Socket>();

  /** One client connection to the proxy: read the first head, then dispatch. */
  const onConnection = (socket: net.Socket): void => {
    clients.add(socket);
    socket.on("close", () => clients.delete(socket));
    let head = Buffer.alloc(0);
    socket.on("error", () => socket.destroy());
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf(HEAD_END);
      if (end < 0) {
        if (head.length > MAX_HEAD) {
          socket.off("data", onData);
          socket.end(
            rawResponse(
              431,
              "Request Header Fields Too Large",
              "maruhi proxy: request head too large\n",
            ),
            () => socket.destroy(),
          );
        }
        return;
      }
      socket.off("data", onData);
      socket.pause();
      const rest = head.subarray(end + HEAD_END.length);
      const lines = head.subarray(0, end).toString("latin1").split("\r\n");
      const [method = "", requestTarget = ""] = (lines[0] ?? "").split(" ");
      if (!presentsCredential(lines)) {
        socket.end(
          rawResponse(
            407,
            "Proxy Authentication Required",
            "maruhi proxy: this run's proxy credential is missing or wrong (it is the userinfo of HTTPS_PROXY / HTTP_PROXY as the command received them)\n",
            'Proxy-Authenticate: Basic realm="maruhi proxy run"',
          ),
        );
        return;
      }
      if (method === "CONNECT") {
        void onConnect(socket, requestTarget, rest);
        return;
      }
      // Plain HTTP: hand the whole buffered bytes to the loopback server
      const upstream = net.connect(plainPath, () => {
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
      const [leaf, mitmPath] = await Promise.all([
        options.ca.issue(target.host),
        mitmPathFor(target),
      ]);
      socket.write(`HTTP/1.1 200 Connection Established\r\nProxy-Agent: maruhi\r\n\r\n`);
      if (rest.length > 0) {
        // Bytes the client sent before our 200 (a TLS ClientHello sent eagerly)
        socket.unshift(rest);
      }
      // Order matters (review finding §19 C-13, measured under Node and
      // Bun): the socket stays paused until the loopback hop is connected
      // and `socket.resume()` runs inside that callback — resuming earlier
      // loses an eagerly sent ClientHello and the connection hangs
      const secure = new tls.TLSSocket(socket, {
        isServer: true,
        key: leaf.keyPem,
        cert: leaf.certPem,
        ALPNProtocols: ["http/1.1"],
      });
      secure.on("error", () => secure.destroy());
      const loop = net.connect(mitmPath, () => {
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
  const bind = options.listen ?? { host: "127.0.0.1", port: 0 };
  const port = await listenOn(proxy, bind.host, bind.port);

  const address = `${bind.host}:${port}`;
  const advertised =
    options.advertise === undefined
      ? address
      : options.advertise.includes(":")
        ? options.advertise
        : `${options.advertise}:${port}`;
  const userinfo =
    options.credential === undefined
      ? ""
      : `${encodeURIComponent(options.credential.user)}:${encodeURIComponent(options.credential.password)}@`;
  return {
    url: `http://${userinfo}${advertised}`,
    address,
    advertised,
    port,
    close: async () => {
      // Open tunnels and MITM connections would hold the listeners open
      // (a dev server the child started and left behind): end them
      for (const socket of clients) {
        socket.destroy();
      }
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
