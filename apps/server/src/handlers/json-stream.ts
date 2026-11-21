const CHUNK_CHARS = 64 * 1024;

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
