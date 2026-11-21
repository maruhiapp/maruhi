import http from "node:http";
import { pipeline, Transform } from "node:stream";
import zlib from "node:zlib";

import { type BytePattern, makeStreamReplacer } from "../byte-replace.ts";
import { HOP_BY_HOP, sendText } from "./proxy-server-http.ts";

type Decompressor = zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress;

const DECOMPRESSORS: Readonly<Record<string, () => Decompressor | "unsupported" | null>> = {
  "": () => null,
  identity: () => null,
  gzip: () => zlib.createGunzip(),
  "x-gzip": () => zlib.createGunzip(),
  deflate: () => zlib.createInflate(),
  br: () => zlib.createBrotliDecompress(),
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

function scrubbedResponseHeaders(
  headers: http.IncomingHttpHeaders,
  scrub: readonly BytePattern[],
  decompressed: boolean,
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

export function relayResponse(
  upstream: http.IncomingMessage,
  res: http.ServerResponse,
  scrub: readonly BytePattern[],
  method: string,
  done: (outcome: number | "failed") => void,
): void {
  const status = upstream.statusCode ?? 502;
  if (method === "HEAD" || status === 204 || status === 304) {
    upstream.resume();
    res.writeHead(status, scrubbedResponseHeaders(upstream.headers, scrub, false, true));
    res.end();
    done(status);
    return;
  }
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
  const stages: NodeJS.ReadWriteStream[] = decoder === null ? [scrubbing] : [decoder, scrubbing];
  pipeline(upstream, ...stages, res, (error) => {
    done(error ? "failed" : status);
  });
}
