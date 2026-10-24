// A minimal parser for the `.env` / `.env.example` format (the input
// layer of `maruhi schema import` — design doc §1-3 (1)).
//
// **Read only on the client side**. A value is wrapped in Redacted right
// after being read, and from then on it is used only for type inference
// (observing the value's **shape** — CRYPTO_SPEC §4.2's closed set) and
// deciding "real-value-ness". A value or a fragment of one is never
// emitted to the terminal, logs, or errors (keeping zero-knowledge — the
// value itself is only observed, never sent. Sending happens only
// through the value push of an activation the user explicitly selected
// per variable, which goes through push.ts's existing encryption
// boundary).
//
// The supported syntax is intentionally minimal (no new dependencies —
// CLAUDE.md):
//   - `KEY=VALUE` (split at the first `=`)
//   - `export KEY=VALUE` (strip the prefix)
//   - `#` comment lines (**the contiguous comments right before** → the
//     description candidate. A blank or non-comment line resets the
//     candidate)
//   - An inline `#` comment on an unquoted value (`PORT=8080 # listen
//     port`) is dropped (the same line as dotenv / `docker --env-file` —
//     comments are not carried into the push path as part of the value)
//   - Matching quotes ('…' / "…") around a value are stripped once.
//     Escapes, variable expansion, and multi-line quoted values are **not
//     interpreted**. What matters here is that simplifying interpretation
//     reaches not only type inference (observation only) but also **the
//     value push (activation) when the user explicitly selects it**: a
//     value that cannot be claimed to be interpreted faithfully (unclosed
//     quotes, escapes inside a quoted value / same-kind quotes) is
//     carried with `valueFaithful = false`, and schema import does not
//     propose the push at all (fail-closed — do not create a path that
//     encrypts and silently stores a misread value. Declarations and type
//     edits are corrected by the user's interactive approval as before)
//
// A line that cannot be accepted is dropped into skipped carrying **only
// its line number and a reason** (the line's content is not carried — a
// broken line may be a value itself).

import type { MetaVarType } from "@maruhi/crypto";
import { Redacted } from "effect";

/**
 * The form of variable names import accepts as candidates: a POSIX
 * environment variable name (leading letter or `_`, then letters, digits,
 * `_`). An `.env` name is premised on becoming a child process's
 * environment variable name, so a narrower set is required than the
 * server's display-name acceptance (AUTH_SPEC §12-1 — NFC, 256 chars).
 * ASCII-only trivially satisfies being in NFC.
 */
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * The name-length cap (same value as AUTH_SPEC §12-8's 256-char display
 * name). Renaming via edit (e) (schema-import.ts) also checks the same
 * cap before signing / sending — if only the parser checked, an over-cap
 * name arriving via editing would slip through to the server's slow 400
 * failure point (halting the whole import).
 */
export const MAX_NAME_LENGTH = 256;

/** Why a line was skipped (the content is not carried — display shows the reason and line number only). */
export type EnvFileSkipReason = "not-an-assignment" | "invalid-name" | "duplicate-name";

/** A skipped line (line numbers are 1-based). */
export interface EnvFileSkippedLine {
  readonly line: number;
  readonly reason: EnvFileSkipReason;
  /**
   * Carried only when the name alone may be shown (duplicate-name — a
   * duplicate of a valid name). The line content of invalid-name /
   * not-an-assignment may be a value and is not carried.
   */
  readonly name?: string;
}

/** One variable that could be interpreted (the value is Redacted — never used beyond observation). */
export interface EnvFileEntry {
  /** The NFC-normalized variable name (ASCII-only, so normalization is identity). */
  readonly name: string;
  /** The line number (1-based — for context display in the approval prompt). */
  readonly line: number;
  /** The value (Redacted right after reading — unwrapped only by observeValue's observation). */
  readonly value: Redacted.Redacted<string>;
  /**
   * true = this line-based parser can claim to have interpreted the
   * value faithfully (unquoted + inline comment removed, or a complete
   * quote containing no escapes / same-kind quotes). A value with false
   * is not passed through observeValue and no push is proposed
   * (fail-closed — see the header comment).
   */
  readonly valueFaithful: boolean;
  /** The description candidate assembled from the contiguous comments right before ("" = no candidate). */
  readonly descriptionCandidate: string;
}

/** parseEnvFile's result. */
export interface ParsedEnvFile {
  readonly entries: readonly EnvFileEntry[];
  readonly skipped: readonly EnvFileSkippedLine[];
}

/** The value interpretation result (faithful = false is the material for suppressing the push proposal — header comment). */
interface ParsedValue {
  readonly text: string;
  readonly faithful: boolean;
}

/**
 * Interpreting the value portion: stripping one pair of quotes and
 * removing an inline `#` comment on an unquoted value. Escapes, variable
 * expansion, and multi-line values are not interpreted — shapes that
 * cannot be claimed faithful (unclosed quotes, `\` / same-kind quotes
 * inside a quoted value) are returned with faithful = false.
 */
function parseValue(raw: string): ParsedValue {
  const first = raw[0];
  if (first === '"' || first === "'") {
    if (raw.length >= 2 && raw.endsWith(first)) {
      const inner = raw.slice(1, -1);
      // Escapes (dotenv's double quotes expand \n etc.) or an embedded
      // quote of the same kind cannot be faithfully reconstructed by this
      // parser
      return { text: inner, faithful: !inner.includes("\\") && !inner.includes(first) };
    }
    // The opening quote never closes (a multi-line quoted value / a broken line)
    return { text: raw, faithful: false };
  }
  // Unquoted: everything after a whitespace-then-`#` is an inline comment
  // (the same line as dotenv / docker --env-file). It is not carried into
  // the push path as part of the value
  return { text: raw.replace(/\s+#.*$/, "").trim(), faithful: true };
}

/**
 * Parses `.env` / `.env.example` text into schema candidates (design doc §1-3).
 * Values are wrapped in `Redacted` immediately; malformed lines carry only
 * their line number and a reason (the content may be a value).
 */
export function parseEnvFile(content: string): ParsedEnvFile {
  const entries: EnvFileEntry[] = [];
  const skipped: EnvFileSkippedLine[] = [];
  const seen = new Set<string>();
  /** The contiguous comment lines right before (the next assignment line's description candidate). */
  let comments: string[] = [];
  const lines = content.split(/\r?\n/);
  for (const [index, rawLine] of lines.entries()) {
    const lineNumber = index + 1;
    const line = rawLine.trim();
    if (line === "") {
      // A blank line delimits a comment block (a detached comment is not a candidate)
      comments = [];
      continue;
    }
    if (line.startsWith("#")) {
      comments.push(line.replace(/^#+\s?/, ""));
      continue;
    }
    const assignment = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const separator = assignment.indexOf("=");
    if (separator < 0) {
      skipped.push({ line: lineNumber, reason: "not-an-assignment" });
      comments = [];
      continue;
    }
    const name = assignment.slice(0, separator).trim().normalize("NFC");
    if (!ENV_NAME_PATTERN.test(name) || name.length > MAX_NAME_LENGTH) {
      skipped.push({ line: lineNumber, reason: "invalid-name" });
      comments = [];
      continue;
    }
    if (seen.has(name)) {
      // Do not silently pick last-wins or first-wins for a same name — a
      // duplicate is skipped with a reason and only the first occurrence
      // becomes a candidate (the name is valid, so it may be shown)
      skipped.push({ line: lineNumber, reason: "duplicate-name", name });
      comments = [];
      continue;
    }
    seen.add(name);
    const parsedValue = parseValue(assignment.slice(separator + 1).trim());
    entries.push({
      name,
      line: lineNumber,
      // The value is wrapped here — from here on only observeValue's observation unwraps it
      value: Redacted.make(parsedValue.text, { label: "env-file-value" }),
      valueFaithful: parsedValue.faithful,
      descriptionCandidate: comments.join(" ").trim(),
    });
    comments = [];
  }
  return { entries, skipped };
}

/* -------------------------------------------------------------------------- */
/* Observing values (type inference / real-value-ness — the value itself  */
/* never leaves)                                                        */
/* -------------------------------------------------------------------------- */

// The number shape uses the same test as run.ts's advisory type check
// (decimal notation only — "0x1f" / "Infinity" do not count as number).
// The checker is not shared because the import side is self-contained
// inside Redacted's observation boundary (a single regex on a string does
// not count as duplication)
const NUMBER_TEXT = /^-?(?:\d+)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

// Placeholder-ness: the conventional forms of `.env.example`. A value
// judged not real is not proposed for activation at all (the send default
// is always "do not", and this merely narrows the proposal UX — the
// consequence of a misjudgment is only "proposed / not proposed")
const PLACEHOLDER_PATTERNS = [
  /^<[^>]*>$/,
  /^\$\{[^}]*\}$/,
  /^(changeme|change-me|change_me|todo|tbd|placeholder|dummy|sample|xxx+|\.{3})$/i,
  /^your[-_]/i,
];

/** The observation result of a value (the value itself is not carried — only the type candidate and real-value-ness). */
export interface ObservedValue {
  /** Type inference (observing the value's shape — "" unspecified when not confident). */
  readonly varType: MetaVarType;
  /** Whether it looks like a real value (empty / placeholder conventional forms are false). */
  readonly looksReal: boolean;
}

/**
 * Observes one value's **shape** for type inference (CRYPTO_SPEC §4.2 closed
 * set) and placeholder-ness. The value itself never leaves this function —
 * only the inferred type and a boolean.
 */
export function observeValue(value: Redacted.Redacted<string>): ObservedValue {
  // Reason for unwrapping: observing the shape (type inference /
  // real-value-ness). The product is only a closed-set type name and a
  // boolean — the value or a fragment of it never leaves this function
  const text = Redacted.value(value).trim();
  if (text === "") {
    return { varType: "", looksReal: false };
  }
  const looksReal = !PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(text));
  if (text === "true" || text === "false") {
    return { varType: "boolean", looksReal };
  }
  if (NUMBER_TEXT.test(text)) {
    return { varType: "number", looksReal };
  }
  if (/^https?:\/\/\S+$/.test(text) && URL.canParse(text)) {
    return { varType: "url", looksReal };
  }
  // A value no shape can be confidently claimed for is "" unspecified
  // (any value could be a string, so inferring string adds no information
  // — the user can edit it at approval)
  return { varType: "", looksReal };
}
