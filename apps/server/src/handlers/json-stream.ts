// A JSON response body written in chunks (AUTH_SPEC §14-2 — the lease).
//
// The default response path keeps the whole serialized string and its UTF-8
// bytes alive together (HttpBody.text without nodejs_compat), so a ~36 MB
// lease peaked at three copies of its body in the worker isolate. Writing
// the top-level arrays element by element on demand keeps one chunk of
// serialized text at a time beside the value itself.

/** Text per chunk before it is encoded and handed to the runtime. */
const CHUNK_CHARS = 64 * 1024;

/**
 * The pieces of `JSON.stringify(value)`, in order: every top-level array is
 * emitted one element at a time, everything else whole. The concatenation
 * is exactly `JSON.stringify(value)` for a plain object (no `toJSON`).
 */
export function* jsonPieces(value: Readonly<Record<string, unknown>>): Generator<string> {
  let separator = "{";
  for (const [key, field] of Object.entries(value)) {
    if (!Array.isArray(field)) {
      const text = JSON.stringify(field);
      if (text !== undefined) {
        yield `${separator}${JSON.stringify(key)}:${text}`;
        separator = ",";
      }
      continue;
    }
    yield `${separator}${JSON.stringify(key)}:[`;
    separator = ",";
    for (const [index, element] of field.entries()) {
      yield `${index === 0 ? "" : ","}${JSON.stringify(element) ?? "null"}`;
    }
    yield "]";
  }
  yield separator === "{" ? "{}" : "}";
}

/** `JSON.stringify(value)` as a pull-driven byte stream of ~64 KiB chunks. */
export function jsonStream(value: Readonly<Record<string, unknown>>): ReadableStream<Uint8Array> {
  const pieces = jsonPieces(value);
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      let chunk = "";
      for (;;) {
        const next = pieces.next();
        if (next.done === true) {
          if (chunk !== "") {
            controller.enqueue(encoder.encode(chunk));
          }
          controller.close();
          return;
        }
        chunk += next.value;
        if (chunk.length >= CHUNK_CHARS) {
          controller.enqueue(encoder.encode(chunk));
          return;
        }
      }
    },
  });
}
