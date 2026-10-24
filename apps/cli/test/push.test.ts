// Unit tests for push.package/push.ts's stdin normalization
// (normalizeStdinValue).

import { describe, expect, it } from "vitest";

import { normalizeStdinValue } from "../src/push.package/push.ts";

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("normalizeStdinValue", () => {
  it("removes only a single trailing newline (LF / CRLF)", () => {
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\r\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n\n")))).toBe("v\n");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v")))).toBe("v");
  });
});
