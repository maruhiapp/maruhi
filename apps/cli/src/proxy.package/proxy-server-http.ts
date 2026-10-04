// HTTP-message helpers shared by the proxy's layers (proxy-server.ts):
// reading a request body with a cap, the incoming headers as single
// strings, a plain-text response, and the hop-by-hop header set both the
// upstream request build and the response scrub drop.

import http from "node:http";

// Headers that describe one hop and must not be forwarded (RFC 9110 §7.6.1)
export const HOP_BY_HOP = new Set([
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

export async function readBody(
  req: http.IncomingMessage,
  cap: number,
): Promise<Buffer | "too-large"> {
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
export function flattenHeaders(req: http.IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) {
      continue;
    }
    out[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return out;
}

export function sendText(res: http.ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": String(Buffer.byteLength(body)),
    "proxy-agent": "maruhi",
  });
  res.end(body);
}
