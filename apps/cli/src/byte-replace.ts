// Exact-match replacement over a byte stream (PF4 — `maruhi proxy run`'s
// request substitution and response scrubbing, and the run-output
// redaction of ROADMAP Phase 3 ⑤).
//
// Why bytes and not text (the ⑤ design, ruling (a)): a `TextDecoder`
// based match would re-encode the child's output, and its non-fatal
// default replaces invalid UTF-8 with U+FFFD — binary output (`run --
// pg_dump -Fc > dump`, `tar czf -`) would be corrupted. Patterns are
// UTF-8-encoded once and searched in the raw `Uint8Array` chunks; bytes
// that match no pattern pass through untouched, so the stream stays
// byte-transparent.
//
// Why a carry-over (ruling (a) again): a pattern straddling a chunk
// boundary would otherwise pass in two halves that match nothing. The
// replacer keeps the last (longest pattern − 1) bytes of each chunk
// unemitted until the next chunk arrives (or the stream ends), and only
// emits the confirmed prefix. The carry-over may be cut at a newline
// when every pattern is single-line (`lineBounded`): then the delay is
// bounded by the longest single-line pattern and live logs still stream
// line by line.
//
// Longest pattern first (the `maruhi sync` rule — sync-exec.ts): a short
// pattern must never consume part of a longer one and let the rest slip.

/** One replacement: `from` bytes become `to` bytes wherever they occur. */
export interface BytePattern {
  readonly from: Uint8Array;
  readonly to: Uint8Array;
}

const NEWLINE = 0x0a;

/** Index of `needle` in `haystack` at or after `start` (−1 when absent). */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, start: number): number {
  const first = needle[0];
  if (first === undefined) {
    return -1;
  }
  const last = haystack.length - needle.length;
  outer: for (let i = start; i <= last; i++) {
    if (haystack[i] !== first) {
      continue;
    }
    for (let j = 1; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Replaces every occurrence of every pattern in `input`, longest pattern
 * first (one whole buffer — no boundary handling). Patterns with an empty
 * `from` are ignored.
 */
export function replaceBytes(input: Uint8Array, patterns: readonly BytePattern[]): Uint8Array {
  let current = input;
  for (const pattern of sortedPatterns(patterns)) {
    let at = indexOfBytes(current, pattern.from, 0);
    if (at < 0) {
      continue;
    }
    const parts: Uint8Array[] = [];
    let cursor = 0;
    while (at >= 0) {
      parts.push(current.subarray(cursor, at), pattern.to);
      cursor = at + pattern.from.length;
      at = indexOfBytes(current, pattern.from, cursor);
    }
    parts.push(current.subarray(cursor));
    current = concatBytes(parts);
  }
  return current;
}

function sortedPatterns(patterns: readonly BytePattern[]): readonly BytePattern[] {
  return patterns
    .filter((pattern) => pattern.from.length > 0)
    .toSorted((a, b) => b.from.length - a.from.length);
}

/** Whether any pattern contains a newline byte (then a newline cannot be a safe cut). */
function anyMultiLine(patterns: readonly BytePattern[]): boolean {
  return patterns.some((pattern) => pattern.from.includes(NEWLINE));
}

/**
 * A stateful replacer for a chunked stream. `push` returns the bytes that
 * are confirmed (no pattern can still start inside them); `flush` returns
 * the carry-over at the end of the stream.
 */
export interface StreamReplacer {
  readonly push: (chunk: Uint8Array) => Uint8Array;
  readonly flush: () => Uint8Array;
}

/**
 * Builds a {@link StreamReplacer}. With no (non-empty) pattern, chunks pass
 * through as they are. The carry-over is (longest pattern − 1) bytes;
 * when no pattern spans a line, it is additionally cut at the last newline
 * (a pattern cannot straddle a newline it does not contain).
 */
export function makeStreamReplacer(patterns: readonly BytePattern[]): StreamReplacer {
  const sorted = sortedPatterns(patterns);
  const longest = sorted[0]?.from.length ?? 0;
  const lineBounded = !anyMultiLine(sorted);
  let pending = new Uint8Array(0);
  if (longest === 0) {
    return { push: (chunk) => chunk, flush: () => new Uint8Array(0) };
  }
  return {
    push(chunk) {
      const combined = pending.length === 0 ? chunk : concatBytes([pending, chunk]);
      // Replace over the whole buffer first: a match ending inside the
      // would-be carry-over is still confirmed when the buffer holds all
      // of it — only the tail that could be the *start* of a match waits
      const replaced = replaceBytes(combined, sorted);
      // The tail that may still begin a pattern: (longest − 1) bytes, cut
      // at the last newline when every pattern is single-line
      let hold = Math.min(longest - 1, replaced.length);
      if (lineBounded && hold > 0) {
        const tail = replaced.subarray(replaced.length - hold);
        const newlineAt = tail.lastIndexOf(NEWLINE);
        if (newlineAt >= 0) {
          hold = hold - newlineAt - 1;
        }
      }
      // What is held back is the *source* bytes of that tail, not the
      // replaced ones: a replacement's output must not be re-matched (a
      // `to` that happens to contain another pattern), and the held tail
      // is replaced again on the next push together with the new chunk.
      // Replacement never touches the last `hold` bytes when no pattern
      // ends there, so taking the tail from `replaced` equals the source
      // except when a match ended inside it — in which case the match
      // output is final and holding it is harmless (a `to` never contains
      // a `from` by the caller's construction: placeholders and
      // "[redacted]" are not secrets)
      pending = replaced.subarray(replaced.length - hold).slice();
      return replaced.subarray(0, replaced.length - hold);
    },
    flush() {
      const out = pending;
      pending = new Uint8Array(0);
      return out;
    },
  };
}

/**
 * Builds the pattern set that scrubs secrets out of a stream (the `maruhi
 * sync` fragment rule — sync-exec.ts's scrubVendorOutput, shared here):
 * each secret as a whole, each of its lines, and the JSON-escaped form of
 * each (a value echoed inside a JSON body appears as `\"`, `\\`, `\n`).
 * Empty fragments are dropped. `to` is the same replacement for every
 * fragment.
 */
export function scrubPatterns(
  secrets: readonly Uint8Array[],
  replacement: string,
): readonly BytePattern[] {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const to = encoder.encode(replacement);
  const seen = new Set<string>();
  const patterns: BytePattern[] = [];
  const add = (fragment: Uint8Array) => {
    if (fragment.length === 0) {
      return;
    }
    // Deduplicate by content (a short key avoids re-encoding the whole fragment as text)
    const key = Array.from(fragment).join(",");
    if (!seen.has(key)) {
      seen.add(key);
      patterns.push({ from: fragment, to });
    }
  };
  for (const secret of secrets) {
    add(secret);
    let text: string;
    try {
      text = decoder.decode(secret);
    } catch {
      // Not UTF-8 text: only the raw bytes can be matched
      continue;
    }
    for (const fragment of [text, ...text.split(/\r?\n/)]) {
      if (fragment.length === 0) {
        continue;
      }
      add(encoder.encode(fragment));
      add(encoder.encode(JSON.stringify(fragment).slice(1, -1)));
    }
  }
  return patterns;
}
