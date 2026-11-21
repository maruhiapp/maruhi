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

export function replaceBytes(input: Uint8Array, patterns: readonly BytePattern[]): Uint8Array {
  const sorted = sortedPatterns(patterns);
  return sorted.length === 0 ? input : scan(input, sorted, true).out;
}

export interface StreamReplacer {
  readonly push: (chunk: Uint8Array) => Uint8Array;
  readonly flush: () => Uint8Array;
}

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

export const MIN_FRAGMENT_LENGTH = 8;

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
