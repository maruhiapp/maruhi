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
 * One left-to-right scan over `input[0, limit)`: at each position the
 * **longest** matching pattern wins and its `to` is emitted; replacement
 * output is never rescanned (a `to` cannot combine with following bytes
 * into another match — review finding pf4-design.md §19 C-11). Scanning
 * stops at the first position ≥ `limit` not covered by a match; returns the
 * output and the index where the scan stopped (the source bytes from there
 * on are the caller's carry-over).
 */
function scan(
  input: Uint8Array,
  sorted: readonly BytePattern[],
  limit: number,
): { readonly out: Uint8Array; readonly stoppedAt: number } {
  const parts: Uint8Array[] = [];
  let i = 0;
  let literalStart = 0;
  while (i < limit) {
    const match = longestMatchAt(input, sorted, i);
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
  return sorted.length === 0 ? input : scan(input, sorted, input.length).out;
}

/** Whether any pattern contains a newline byte (then a newline cannot be a safe cut on its own). */
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
 * through as they are.
 *
 * Correctness argument (review finding §19 C-2 replaced the first version,
 * which held *replaced* bytes and could let a short match at the chunk
 * edge hide a longer pattern): the scan runs over the **source** bytes and
 * applies only matches that start before `cut = length − (longest − 1)`.
 * Every pattern starting before `cut` fits entirely in the buffer, so the
 * longest match found there is the one the whole-buffer scan would find.
 * Bytes from the stop position on are held **as source** and rescanned with
 * the next chunk. When no pattern spans a line (or the caller promises
 * per-line fragments — `cutAtNewline`), `cut` advances to just after the
 * last newline: a single-line pattern starting at or before a newline ends
 * before it, so everything up to the newline is final as well.
 */
export function makeStreamReplacer(
  patterns: readonly BytePattern[],
  options: {
    /**
     * Cut the carry-over at a newline even when a pattern spans lines. Only
     * correct when every multi-line pattern is accompanied by its per-line
     * fragments (scrubPatterns builds them): each line is then caught on its
     * own and the output shows one `[redacted]` per line — the ROADMAP ⑤
     * design's "live logs stream line by line even for PEM keys".
     */
    readonly cutAtNewline?: boolean;
  } = {},
): StreamReplacer {
  const sorted = sortedPatterns(patterns);
  const longest = sorted[0]?.from.length ?? 0;
  const lineBounded = options.cutAtNewline === true || !anyMultiLine(sorted);
  let pending = new Uint8Array(0);
  if (longest === 0) {
    return { push: (chunk) => chunk, flush: () => new Uint8Array(0) };
  }
  return {
    push(chunk) {
      const combined = pending.length === 0 ? chunk : concatBytes([pending, chunk]);
      let cut = Math.max(0, combined.length - (longest - 1));
      if (lineBounded) {
        const lastNewline = combined.lastIndexOf(NEWLINE);
        if (lastNewline + 1 > cut) {
          cut = lastNewline + 1;
        }
      }
      const { out, stoppedAt } = scan(combined, sorted, cut);
      pending = combined.subarray(stoppedAt).slice();
      return out;
    },
    flush() {
      const { out } = scan(pending, sorted, pending.length);
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
