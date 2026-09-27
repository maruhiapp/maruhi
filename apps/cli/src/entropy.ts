// Write-time client check for real-value contamination in schema
// fields (finding D) (ruling CW — fail-closed). When a
// "secret-looking high-entropy substring" is detected in the name /
// description input of `maruhi schema set` (and schema import in the
// future), an interactive environment warns and requires explicit
// confirmation, and a non-interactive environment refuses with a
// typed error absent an explicit flag. Meta is plaintext and
// server-visible; real-value contamination pokes a user-shaped hole
// in the zero-knowledge promise.
//
// The detector and thresholds are implementation details (the spec
// fixes only the requirement and the failure direction — design
// document §1-2). Here we take the standard detect-secrets
// heuristics:
//   - Shannon entropy ≥ 3.0 of a hex token (32 chars or more)
//   - Shannon entropy ≥ 3.5 of a long token (20 chars or more) of
//     mixed character classes (digits + upper/lowercase, or digits +
//     base64 symbols)
// A false positive costs "one confirmation / one explicit flag" while
// a miss is a real value in plaintext meta, so the thresholds lean
// toward detection (the fail-closed failure direction).
//
// A detection result **does not contain the input itself**: the
// caller's message flows to the terminal and logs, so it must not
// carry the suspect value (= possibly a secret). Returns only
// position and length.

/** One detection (does not carry the value itself — only length and kind). */
export interface EntropyFinding {
  /** Length of the detected substring (in characters). */
  readonly length: number;
  /** Detection basis (hex = a long hex sequence, mixed = a high-entropy sequence of mixed character classes). */
  readonly kind: "hex" | "mixed";
}

/** Token splitting: runs of the character classes secret values appear in (base64 / hex / URL-safe). */
const TOKEN_PATTERN = /[A-Za-z0-9+/=_-]+/g;

const HEX_TOKEN = /^[0-9a-fA-F]+$/;
const MIN_HEX_LENGTH = 32;
const MIN_MIXED_LENGTH = 20;
const HEX_ENTROPY_THRESHOLD = 3.0;
const MIXED_ENTROPY_THRESHOLD = 3.5;

/** Per-character Shannon entropy (bits/char). */
function shannonEntropyPerChar(token: string): number {
  const counts = new Map<string, number>();
  for (const char of token) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  const length = [...token].length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Judging mixed character classes: a random token (an API key, a
// base64 secret) almost always contains "digits + mixed
// upper/lowercase" or "digits + base64 symbols (+ / =)". Conversely,
// identifier-like legitimate input (DATABASE_URL, a camelCase name,
// English prose) satisfies neither (uppercase only + digits, no
// symbols, etc.)
function isMixedCharsetToken(token: string): boolean {
  const hasDigit = /\d/.test(token);
  if (!hasDigit) {
    return false;
  }
  const hasLower = /[a-z]/.test(token);
  const hasUpper = /[A-Z]/.test(token);
  const hasBase64Symbol = /[+/=]/.test(token);
  return (hasLower && hasUpper) || hasBase64Symbol;
}

function tokenFinding(token: string): EntropyFinding | null {
  // base64 padding only lowers the entropy, so strip it before judging
  const trimmed = token.replace(/=+$/, "");
  if (HEX_TOKEN.test(trimmed) && trimmed.length >= MIN_HEX_LENGTH) {
    if (shannonEntropyPerChar(trimmed.toLowerCase()) >= HEX_ENTROPY_THRESHOLD) {
      return { length: trimmed.length, kind: "hex" };
    }
    return null;
  }
  if (trimmed.length >= MIN_MIXED_LENGTH && isMixedCharsetToken(trimmed)) {
    if (shannonEntropyPerChar(trimmed) >= MIXED_ENTROPY_THRESHOLD) {
      return { length: trimmed.length, kind: "mixed" };
    }
  }
  return null;
}

/**
 * Scans free-form input (a schema-set name or description) for secret-like
 * high-entropy substrings (ruling CW). Returns the first finding, or null.
 * The finding never carries the matched text — only its length and kind —
 * so callers can build messages without echoing a possible secret.
 */
export function findHighEntropySubstring(text: string): EntropyFinding | null {
  for (const match of text.matchAll(TOKEN_PATTERN)) {
    const finding = tokenFinding(match[0]);
    if (finding !== null) {
      return finding;
    }
  }
  return null;
}
