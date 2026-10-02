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
// replacer holds back exactly the source bytes that **could still begin a
// match longer than any match available now** — the tail of the buffer
// that is a proper prefix of some pattern — and emits everything else at
// once (review finding pf4-design.md §21 R-25 replaced a newline cut that
// assumed every line of a multi-line value was a pattern of its own; the
// 8-byte floor had made that false). Output that resembles no pattern
// streams immediately, mid-line included; an echoed multi-line value is
// held until it completes or diverges, bounded by the longest pattern.
//
// Longest pattern first (the `maruhi sync` rule — sync-exec.ts): a short
// pattern must never consume part of a longer one and let the rest slip.

/** One replacement: `from` bytes become `to` bytes wherever they occur. */
export interface BytePattern {
  readonly from: Uint8Array;
  readonly to: Uint8Array;
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

/** Whether `needle` occurs in `haystack` starting exactly at `at`. */
function matchesAt(haystack: Uint8Array, needle: Uint8Array, at: number): boolean {
  if (at + needle.length > haystack.length) {
    return false;
  }
  for (let j = 0; j < needle.length; j++) {
    if (haystack[at + j] !== needle[j]) {
      return false;
    }
  }
  return true;
}

/** The longest pattern (patterns sorted longest first) starting at `at`, or null. */
function longestMatchAt(
  haystack: Uint8Array,
  sorted: readonly BytePattern[],
  at: number,
): BytePattern | null {
  for (const pattern of sorted) {
    if (matchesAt(haystack, pattern.from, at)) {
      return pattern;
    }
  }
  return null;
}

function sortedPatterns(patterns: readonly BytePattern[]): readonly BytePattern[] {
  return patterns
    .filter((pattern) => pattern.from.length > 0)
    .toSorted((a, b) => b.from.length - a.from.length);
}

/**
 * Whether some pattern longer than `minLength` could still match at `at`
 * given more bytes: `input[at, end)` is a proper prefix of it. Only asked
 * inside the last (longest − 1) bytes, where a pattern can run past the end.
 */
function couldExtendAt(
  input: Uint8Array,
  sorted: readonly BytePattern[],
  at: number,
  minLength: number,
): boolean {
  const remaining = input.length - at;
  for (const pattern of sorted) {
    const { from } = pattern;
    if (from.length <= remaining || from.length <= minLength) {
      continue;
    }
    let j = 0;
    while (j < remaining && from[j] === input[at + j]) {
      j++;
    }
    if (j === remaining) {
      return true;
    }
  }
  return false;
}

/**
 * One left-to-right scan over `input`: at each position the **longest**
 * matching pattern wins and its `to` is emitted; replacement output is
 * never rescanned (a `to` cannot combine with following bytes into another
 * match — review finding pf4-design.md §19 C-11). When `final` is false
 * the scan stops at the first position from which a pattern **longer than
 * the longest match available there** could still be completed by bytes
 * not yet seen (the buffer's tail is a proper prefix of it); the source
 * bytes from there on are the caller's carry-over. A shorter match is
 * never taken while a longer one is still possible (§19 C-2).
 */
function scan(
  input: Uint8Array,
  sorted: readonly BytePattern[],
  final: boolean,
): { readonly out: Uint8Array; readonly stoppedAt: number } {
  const parts: Uint8Array[] = [];
  const end = input.length;
  const longest = sorted[0]?.from.length ?? 0;
  let i = 0;
  let literalStart = 0;
  while (i < end) {
    const match = longestMatchAt(input, sorted, i);
    if (!final && end - i < longest && couldExtendAt(input, sorted, i, match?.from.length ?? 0)) {
      break;
    }
    if (match === null) {
      i++;
      continue;
    }
    parts.push(input.subarray(literalStart, i), match.to);
    i += match.from.length;
    literalStart = i;
  }
  parts.push(input.subarray(literalStart, i));
  return { out: concatBytes(parts), stoppedAt: i };
}

/**
 * Replaces every occurrence of every pattern in `input` (one whole buffer —
 * no boundary handling). At each position the longest pattern wins, so a
 * short pattern never consumes part of a longer one. Patterns with an empty
 * `from` are ignored.
 */
export function replaceBytes(input: Uint8Array, patterns: readonly BytePattern[]): Uint8Array {
  const sorted = sortedPatterns(patterns);
  return sorted.length === 0 ? input : scan(input, sorted, true).out;
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
 * through as they are.
 *
 * Correctness argument: the scan runs over the **source** bytes (never over
 * replacement output — §19 C-2) and stops exactly where a longer match
 * could still begin; everything before that point would be scanned the
 * same way with the whole stream in hand, and everything from it is held
 * as source and rescanned with the next chunk. The hold is at most
 * (longest pattern − 1) bytes.
 */
export function makeStreamReplacer(patterns: readonly BytePattern[]): StreamReplacer {
  const sorted = sortedPatterns(patterns);
  let pending = new Uint8Array(0);
  if (sorted.length === 0) {
    return { push: (chunk) => chunk, flush: () => new Uint8Array(0) };
  }
  return {
    push(chunk) {
      const combined = pending.length === 0 ? chunk : concatBytes([pending, chunk]);
      const { out, stoppedAt } = scan(combined, sorted, false);
      pending = combined.subarray(stoppedAt).slice();
      return out;
    },
    flush() {
      const { out } = scan(pending, sorted, true);
      pending = new Uint8Array(0);
      return out;
    },
  };
}

/**
 * The shortest fragment that is scrubbed, in bytes. A shorter value (`3000`,
 * `true`, a `{` line of a JSON value) is ordinary text that would be
 * rewritten wherever it appears — in a log, in a dump redirected to a file,
 * in an API response — and carries no secret worth the corruption (review
 * finding pf4-design.md §21 R-1). Eight bytes is the floor at which an
 * incidental match in unrelated output stops being plausible.
 */
export const MIN_FRAGMENT_LENGTH = 8;

/**
 * Builds the pattern set that scrubs secrets out of a stream (the `maruhi
 * sync` fragment rule — sync-exec.ts's scrubVendorOutput, shared here):
 * each secret as a whole, each of its lines, and the JSON-escaped form of
 * each (a value echoed inside a JSON body appears as `\"`, `\\`, `\n`).
 * Fragments shorter than {@link MIN_FRAGMENT_LENGTH} bytes are dropped
 * (the whole value included: a short value is not redacted at all). `to`
 * is the same replacement for every fragment.
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
    if (fragment.length < MIN_FRAGMENT_LENGTH) {
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
