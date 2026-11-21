export interface EntropyFinding {
  readonly length: number;
  readonly kind: "hex" | "mixed";
}

const TOKEN_PATTERN = /[A-Za-z0-9+/=_-]+/g;

const HEX_TOKEN = /^[0-9a-fA-F]+$/;
const MIN_HEX_LENGTH = 32;
const MIN_MIXED_LENGTH = 20;
const HEX_ENTROPY_THRESHOLD = 3.0;
const MIXED_ENTROPY_THRESHOLD = 3.5;

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

export function findHighEntropySubstring(text: string): EntropyFinding | null {
  for (const match of text.matchAll(TOKEN_PATTERN)) {
    const finding = tokenFinding(match[0]);
    if (finding !== null) {
      return finding;
    }
  }
  return null;
}
