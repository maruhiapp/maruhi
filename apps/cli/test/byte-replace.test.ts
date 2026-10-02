// Tests for the byte-domain replacer (byte-replace.ts — PF4 and the
// run-output redaction): exact matching on raw bytes, longest first, the
// carry-over across chunk boundaries, the newline cut, byte transparency
// for non-UTF-8 output, and the shared scrub fragment rule.

import { describe, expect, it } from "vitest";

import {
  type BytePattern,
  makeStreamReplacer,
  MIN_FRAGMENT_LENGTH,
  replaceBytes,
  scrubPatterns,
} from "../src/byte-replace.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const pattern = (from: string, to: string): BytePattern => ({
  from: enc.encode(from),
  to: enc.encode(to),
});

/** Pushes `text` through the replacer in chunks of `size` bytes and returns the whole output. */
function stream(patterns: readonly BytePattern[], input: Uint8Array, size: number): Uint8Array {
  const replacer = makeStreamReplacer(patterns);
  const out: Uint8Array[] = [];
  for (let i = 0; i < input.length; i += size) {
    out.push(replacer.push(input.subarray(i, i + size)));
  }
  out.push(replacer.flush());
  const total = out.reduce((n, part) => n + part.length, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const part of out) {
    merged.set(part, offset);
    offset += part.length;
  }
  return merged;
}

describe("replaceBytes", () => {
  it("replaces every occurrence, longest pattern first", () => {
    const out = replaceBytes(enc.encode("a=secret12 b=secret c=secret12"), [
      pattern("secret", "[r]"),
      pattern("secret12", "[R]"),
    ]);
    expect(dec.decode(out)).toBe("a=[R] b=[r] c=[R]");
  });

  it("ignores empty patterns and leaves unmatched bytes untouched", () => {
    const input = new Uint8Array([0, 255, 128, 10, 13]);
    const out = replaceBytes(input, [{ from: new Uint8Array(0), to: enc.encode("x") }]);
    expect(Array.from(out)).toEqual([0, 255, 128, 10, 13]);
  });
});

describe("makeStreamReplacer", () => {
  const SECRET = "hunter2-very-long-secret";

  it("catches a pattern straddling every possible chunk boundary", () => {
    const input = enc.encode(`token=${SECRET}; again ${SECRET}\nend`);
    for (let size = 1; size <= input.length; size++) {
      const out = dec.decode(stream([pattern(SECRET, "[redacted]")], input, size));
      expect(out, `chunk size ${size}`).toBe("token=[redacted]; again [redacted]\nend");
    }
  });

  it("emits a completed line immediately when every pattern is single-line (the newline cut)", () => {
    const replacer = makeStreamReplacer([pattern(SECRET, "[redacted]")]);
    const first = replacer.push(enc.encode("line one\nline two with a tail"));
    // Everything up to and including the newline is confirmed; only the
    // tail (shorter than the pattern) may still begin a match
    expect(dec.decode(first).startsWith("line one\n")).toBe(true);
    expect(first.length).toBeGreaterThanOrEqual("line one\n".length);
    const rest = dec.decode(replacer.flush());
    expect(dec.decode(first) + rest).toBe("line one\nline two with a tail");
  });

  it("holds back across newlines when a pattern itself spans lines", () => {
    const pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----";
    const input = enc.encode(`x ${pem} y`);
    for (const size of [1, 7, 16, 64]) {
      const out = dec.decode(stream([pattern(pem, "[redacted]")], input, size));
      expect(out, `chunk size ${size}`).toBe("x [redacted] y");
    }
  });

  it("with cutAtNewline and per-line fragments, emits each line as it completes and redacts a PEM line by line", () => {
    const pem = "-----BEGIN KEY-----\nabcdefghijklmnop\n-----END KEY-----";
    const patterns = scrubPatterns([enc.encode(pem)], "[redacted]");
    const replacer = makeStreamReplacer(patterns, { cutAtNewline: true });
    const first = replacer.push(
      enc.encode("log line one\n-----BEGIN KEY-----\nabcdefghijklmnop\n--"),
    );
    // The two complete lines are out already (not held for the whole 3-line pattern)
    expect(dec.decode(first)).toBe("log line one\n[redacted]\n[redacted]\n");
    const rest =
      dec.decode(replacer.push(enc.encode("---END KEY-----\nafter\n"))) +
      dec.decode(replacer.flush());
    expect(rest).toBe("[redacted]\nafter\n");
  });

  it("is byte-transparent for non-UTF-8 output", () => {
    const binary = new Uint8Array(4096);
    for (let i = 0; i < binary.length; i++) {
      binary[i] = (i * 7919) & 0xff;
    }
    const out = stream([pattern(SECRET, "[redacted]")], binary, 100);
    expect(Array.from(out)).toEqual(Array.from(binary));
  });

  it("passes chunks through untouched when there is no pattern", () => {
    const replacer = makeStreamReplacer([]);
    const chunk = enc.encode("anything");
    expect(replacer.push(chunk)).toBe(chunk);
    expect(replacer.flush().length).toBe(0);
  });

  it("substitutes placeholders with values of a different length across chunks", () => {
    const input = enc.encode("Authorization: Bearer mhp_X_abcdefghijklmnopqrstuv\r\n");
    for (const size of [1, 3, 10, 29]) {
      const out = dec.decode(
        stream([pattern("mhp_X_abcdefghijklmnopqrstuv", "ghp_real")], input, size),
      );
      expect(out, `chunk size ${size}`).toBe("Authorization: Bearer ghp_real\r\n");
    }
  });
});

describe("scrubPatterns", () => {
  it("builds the whole / per-line / JSON-escaped fragments and drops the short ones", () => {
    const patterns = scrubPatterns([enc.encode('alpha"beta\nsecond-line\n')], "[redacted]");
    const froms = patterns.map((p) => dec.decode(p.from)).toSorted();
    expect(froms).toEqual(
      [
        'alpha"beta',
        'alpha"beta\nsecond-line\n',
        'alpha\\"beta',
        'alpha\\"beta\\nsecond-line\\n',
        "second-line",
      ].toSorted(),
    );
    expect(patterns.every((p) => dec.decode(p.to) === "[redacted]")).toBe(true);
  });

  it("never scrubs a value or a line shorter than the floor (§21 R-1: `3000`, `true`, a `{` line are ordinary text)", () => {
    expect(MIN_FRAGMENT_LENGTH).toBe(8);
    expect(scrubPatterns([enc.encode("3000"), enc.encode("true"), enc.encode("1")], "[x]")).toEqual(
      [],
    );
    // A JSON value: its `{` / `}` lines are dropped, its long lines kept
    const json = '{\n  "key": "sk-0123456789abcdef"\n}';
    const froms = scrubPatterns([enc.encode(json)], "[x]").map((p) => dec.decode(p.from));
    expect(froms).not.toContain("{");
    expect(froms).not.toContain("}");
    expect(froms).toContain('  "key": "sk-0123456789abcdef"');
    // Output that contains a short value stays byte-identical
    const patterns = scrubPatterns([enc.encode("1")], "[redacted]");
    expect(dec.decode(replaceBytes(enc.encode("v1.0 PORT=1"), patterns))).toBe("v1.0 PORT=1");
    // Exactly the floor is scrubbed
    expect(scrubPatterns([enc.encode("12345678")], "[x]")).toHaveLength(1);
  });

  it("keeps the raw bytes of a non-UTF-8 secret", () => {
    const raw = new Uint8Array([0xff, 0xfe, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46]);
    const patterns = scrubPatterns([raw], "[redacted]");
    expect(patterns).toHaveLength(1);
    expect(Array.from(patterns[0]?.from ?? [])).toEqual(Array.from(raw));
  });
});
