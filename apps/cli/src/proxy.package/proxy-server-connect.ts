// The raw-wire level of the forward proxy (proxy-server.ts): the pieces
// that read or write bytes on the client socket before — or instead of —
// an HTTP server: the request-head limit, one plain-text response written
// straight to a socket, the CONNECT and absolute-form target parsers, and
// the two-way socket pipe of a tunnel or a loopback hop.

import net from "node:net";

import type { Target } from "./proxy-rules.ts";

export const MAX_HEAD = 64 * 1024;
export const HEAD_END = "\r\n\r\n";

/** A short plain-text response written straight to a raw socket (before any protocol handoff). */
export function rawResponse(
  status: number,
  reason: string,
  body: string,
  extraHeader = "",
): string {
  const bytes = Buffer.byteLength(body);
  const extra = extraHeader === "" ? "" : `${extraHeader}\r\n`;
  return `HTTP/1.1 ${status} ${reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${bytes}\r\nConnection: close\r\nProxy-Agent: maruhi\r\n${extra}\r\n${body}`;
}

/** Parses `host[:port]` (an IPv6 literal in brackets is refused — rules cannot name one). */
export function parseAuthority(
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
export function parseAbsoluteForm(
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
export function originFormOf(raw: string): string {
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
export function bridge(a: net.Socket, b: net.Socket): void {
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
