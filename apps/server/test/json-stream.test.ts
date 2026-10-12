// The chunked JSON body (handlers/json-stream.ts — AUTH_SPEC §14-2's lease):
// its bytes are exactly JSON.stringify's, and no chunk holds much more than
// one piece of the value.

import { describe, expect, it } from "vitest";

import { jsonPieces, jsonStream } from "../src/handlers/json-stream.ts";

async function chunksOf(stream: ReadableStream<Uint8Array>): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return chunks;
    }
    chunks.push(value);
  }
}

describe("jsonStream (the lease body — AUTH_SPEC §14-2)", () => {
  it.each([
    ["an empty object", {}],
    ["scalars only", { a: 1, b: "x", c: null, d: true }],
    ["undefined fields are dropped like JSON.stringify", { a: undefined, b: 2, c: undefined }],
    ["empty and nested arrays", { a: [], b: [[1], { c: [2] }], d: 'é\u2028"\\' }],
    ["arrays first and last", { a: [1, 2], b: { x: 1 }, c: ["y", null] }],
    ["undefined and function array elements become null", { a: [undefined, () => 1, 3] }],
  ])("writes exactly JSON.stringify's text: %s", async (_label, value) => {
    expect([...jsonPieces(value)].join("")).toBe(JSON.stringify(value));
    const text = await new Response(jsonStream(value)).text();
    expect(text).toBe(JSON.stringify(value));
  });

  it("streams a large array in bounded chunks", async () => {
    const element = "a".repeat(10_000);
    const value = { head: "h", items: Array.from({ length: 1_000 }, () => element), tail: 1 };
    const chunks = await chunksOf(jsonStream(value));
    expect(new TextDecoder().decode(concat(chunks))).toBe(JSON.stringify(value));
    expect(chunks.length).toBeGreaterThan(100);
    for (const chunk of chunks) {
      expect(chunk.length).toBeLessThan(64 * 1024 + element.length + 16);
    }
  });
});

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
