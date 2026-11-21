import net from "node:net";

import type { Target } from "./proxy-rules.ts";

export const MAX_HEAD = 64 * 1024;
export const HEAD_END = "\r\n\r\n";

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

export function parseAuthority(
  text: string,
  defaultPort: number,
): { readonly host: string; readonly port: number } | null {
  if (text.startsWith("[")) {
    return null;
  }
  const colon = text.lastIndexOf(":");
  const host = (colon >= 0 ? text.slice(0, colon) : text).toLowerCase().replace(/\.$/, "");
  const portText = colon >= 0 ? text.slice(colon + 1) : String(defaultPort);
  if (host.length === 0 || !/^\d{1,5}$/.test(portText)) {
    return null;
  }
  const port = Number(portText);
  return port >= 1 && port <= 65535 ? { host, port } : null;
}

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
