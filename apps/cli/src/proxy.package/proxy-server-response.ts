// The relayed response of the forward proxy (proxy-server.ts): undoing a
// content encoding the origin used anyway, dropping the headers that
// cannot be re-framed, and streaming the body back with every real value
// replaced by its placeholder.

import http from "node:http";
import { pipeline, Transform } from "node:stream";
import zlib from "node:zlib";

import { type BytePattern, makeStreamReplacer } from "../byte-replace.ts";
import { HOP_BY_HOP, sendText } from "./proxy-server-http.ts";

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
export function relayResponse(
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
  const replacer = makeStreamReplacer(scrub);
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
