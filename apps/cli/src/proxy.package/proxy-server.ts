import { timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { join } from "node:path";
import tls from "node:tls";

import { type BytePattern, scrubPatterns } from "../byte-replace.ts";
import type { EphemeralCa } from "./proxy-cert.ts";
import {
  checkHostLocal,
  formatAuthority,
  type HostLocalCheck,
  isLoopbackBind,
  type Lookup,
} from "./proxy-guard.ts";
import {
  authorityOf,
  type BrokeredCredential,
  credentialsFor,
  type Target,
} from "./proxy-rules.ts";
import {
  bridge,
  HEAD_END,
  MAX_HEAD,
  originFormOf,
  parseAbsoluteForm,
  parseAuthority,
  rawResponse,
} from "./proxy-server-connect.ts";
import { flattenHeaders, readBody, sendText } from "./proxy-server-http.ts";
import {
  buildUpstreamRequest,
  inspectRequest,
  refusalFor,
  resolveValues,
  UnsendableValueError,
  wirePatterns,
  withWireForms,
} from "./proxy-server-request.ts";
import { relayResponse } from "./proxy-server-response.ts";

export type ProxyDecision =
  | {
      readonly kind: "brokered";
      readonly method: string;
      readonly target: Target;
      readonly path: string;
      readonly status: number;
      readonly substituted: readonly string[];
    }
  | {
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
  readonly unmatched: "allow" | "block";
  readonly ca: EphemeralCa;
  readonly hopDir: string;
  readonly credential?: { readonly user: string; readonly password: string } | undefined;
  readonly listen?: { readonly host: string; readonly port: number } | undefined;
  readonly advertise?: { readonly host: string; readonly port: number } | undefined;
  readonly onDecision?: (decision: ProxyDecision) => void;
  readonly upstream?: {
    readonly connect?: (target: Target) => { readonly host: string; readonly port: number };
    readonly ca?: readonly string[];
    readonly lookup?: Lookup;
  };
}

export interface ProxyHandle {
  readonly url: string;
  readonly address: string;
  readonly advertised: string;
  readonly port: number;
  readonly close: () => Promise<void>;
}

const MAX_INSPECTED_BODY = 32 * 1024 * 1024;

function pinned(target: Target, check: HostLocalCheck): Target {
  return check.refused === undefined && check.address !== null
    ? { ...target, resolved: check.address }
    : target;
}

function pathOnly(requestPath: string): string {
  const questionMark = requestPath.indexOf("?");
  return questionMark < 0 ? requestPath : requestPath.slice(0, questionMark);
}

export async function startProxy(options: ProxyOptions): Promise<ProxyHandle> {
  const decide = options.onDecision ?? (() => {});
  const connectTo =
    options.upstream?.connect ??
    ((target: Target) => ({ host: target.resolved ?? target.host, port: target.port }));
  const upstreamCa = options.upstream?.ca;
  const servers: net.Server[] = [];
  const sandboxed = options.listen !== undefined && !isLoopbackBind(options.listen.host);
  const hostLocalCheck = (target: Target): Promise<HostLocalCheck> =>
    sandboxed
      ? checkHostLocal(target.host, options.upstream?.lookup)
      : Promise.resolve({ address: null });

  const listenOn = (server: net.Server, host: string, port: number): Promise<number> =>
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        servers.push(server);
        resolve((server.address() as net.AddressInfo).port);
      });
    });
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

  const scrubbers = (): BytePattern[] =>
    options.credentials.flatMap((credential) =>
      scrubPatterns(withWireForms(credential.known()), credential.placeholder),
    );

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
    readonly allowed: readonly BrokeredCredential[];
  }): Promise<void> => {
    const { res, target, requestPath } = input;
    const method = input.req.method ?? "GET";
    const path = pathOnly(requestPath);
    let outgoing: ReturnType<typeof buildUpstreamRequest>;
    let request: http.ClientRequest;
    let scrub: readonly BytePattern[] = input.scrub;
    try {
      outgoing = buildUpstreamRequest(input);
      scrub = [...input.scrub, ...wirePatterns(input.headers, outgoing.headers)];
      const where = connectTo(target);
      request = (target.scheme === "https" ? https : http).request({
        host: where.host,
        port: where.port,
        servername: target.scheme === "https" ? target.host : undefined,
        ca: upstreamCa === undefined ? undefined : [...upstreamCa],
        method,
        path: outgoing.path,
        headers: outgoing.headers,
        agent: false,
      });
    } catch (error) {
      const reason =
        error instanceof UnsendableValueError
          ? `the value of ${error.variable} cannot be sent in a header (it contains a line break or a non-Latin-1 character)`
          : `the request could not be built${(error as NodeJS.ErrnoException).code === undefined ? "" : ` (${(error as NodeJS.ErrnoException).code})`}`;
      sendText(res, 502, `maruhi proxy: ${reason}; the request was not sent`);
      decide({ kind: "error", method, target, path, reason });
      return Promise.resolve();
    }
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
        relayResponse(upstream, res, scrub, method, (outcome) => {
          if (outcome === "failed") {
            decide({
              kind: "error",
              method,
              target,
              path,
              reason: "upstream response not relayed",
            });
          } else if (input.allowed.length === 0) {
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

  const mitmServers = new Map<string, Promise<string>>();
  let mitmCount = 0;
  const mitmPathFor = (target: Target): Promise<string> => {
    const key = authorityOf(target);
    let pending = mitmServers.get(key);
    if (pending === undefined) {
      const server = http.createServer((req, res) => {
        guarded(req, res, target, originFormOf(req.url ?? "/"));
      });
      mitmCount += 1;
      pending = listenHop(server, `h${mitmCount}`);
      pending.catch(() => mitmServers.delete(key));
      mitmServers.set(key, pending);
    }
    return pending;
  };

  const plainRequest = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
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
    const refuse = (message: string, reason: string) => {
      sendText(res, 403, `maruhi proxy: ${message}; the request was not sent`);
      decide({
        kind: "blocked",
        method: req.method ?? "GET",
        target: parsed.target,
        path: pathOnly(parsed.path),
        reason,
      });
    };
    let target = parsed.target;
    if (credentialsFor(options.credentials, target).length === 0) {
      if (options.unmatched === "block") {
        refuse(
          `${authorityOf(target)} is not named by any rule and this run blocks unmatched hosts`,
          "unmatched host (block)",
        );
        return;
      }
      const check = await hostLocalCheck(target);
      if (check.refused !== undefined) {
        refuse(
          `${check.refused}; in sandbox mode the proxy reaches only destinations outside this machine unless a rule names them`,
          `host-local destination (sandbox mode): ${check.refused}`,
        );
        return;
      }
      target = pinned(target, check);
    }
    guarded(req, res, target, parsed.path);
  };
  const plainServer = http.createServer((req, res) => {
    void plainRequest(req, res);
  });
  const plainPath = await listenHop(plainServer, "plain");

  const expectedAuthorization =
    options.credential === undefined
      ? null
      : Buffer.from(
          `Basic ${Buffer.from(`${options.credential.user}:${options.credential.password}`).toString("base64")}`,
          "latin1",
        );
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

  const clients = new Set<net.Socket>();

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
      const check = await hostLocalCheck(target);
      if (check.refused !== undefined) {
        socket.end(
          rawResponse(
            403,
            "Forbidden",
            `maruhi proxy: ${check.refused}; in sandbox mode the proxy reaches only destinations outside this machine unless a rule names them\n`,
          ),
        );
        decide({
          kind: "blocked",
          method: "CONNECT",
          target,
          path: "",
          reason: `host-local destination (sandbox mode): ${check.refused}`,
        });
        return;
      }
      const where = connectTo(pinned(target, check));
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
    try {
      const [leaf, mitmPath] = await Promise.all([
        options.ca.issue(target.host),
        mitmPathFor(target),
      ]);
      socket.write(`HTTP/1.1 200 Connection Established\r\nProxy-Agent: maruhi\r\n\r\n`);
      if (rest.length > 0) {
        socket.unshift(rest);
      }
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

  const address = formatAuthority(bind.host, port);
  const advertised =
    options.advertise === undefined
      ? address
      : formatAuthority(
          options.advertise.host,
          options.advertise.port === 0 ? port : options.advertise.port,
        );
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
      for (const socket of clients) {
        socket.destroy();
      }
      await Promise.all(
        servers.map(
          (server) =>
            new Promise<void>((resolve) => {
              server.close(() => resolve());
              if ("closeAllConnections" in server) {
                (server as http.Server).closeAllConnections();
              }
            }),
        ),
      );
    },
  };
}
