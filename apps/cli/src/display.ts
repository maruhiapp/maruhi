// Sanitizing and display formatting for terminal output.
//
// A variable's display name, user_id, etc. are server-distributed,
// unauthenticated metadata (free-form strings) that may contain newlines
// and ANSI escapes. Streaming them raw to the terminal mixes fake lines
// and steering text into it (terminal injection), so control characters
// are replaced with a visible substitute before display. A value (--show)
// cannot be forged by the server (it is written with E2EE and tampering
// fails decryption), but a co-editor can write it, so the same
// neutralization applies as a separate threat. However, a value is
// something the user copies and uses, so when neutralization happens a
// warning makes explicit that "displayed = actual value" does not hold
// (showValues).

import { Effect, Redacted, type Stdio } from "effect";

import { ensureValueDisplayAllowed } from "./agent-gate.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";

// Unicode category Cc = C0 controls (NUL..US) + DEL + C1 controls
// (including ANSI CSI), plus those that **break the integrity of lines and
// ordering**:
//   U+202A..U+202E (bidirectional embedding/override) / U+2066..U+2069
//   (isolation)
//   U+200E / U+200F / U+061C (bidirectional marks)
//     — all can reorder the display on a terminal. Same threat as fake
//       lines / steering text, and crushing ANSI escapes alone does not
//       close it
//   U+200B (zero-width space) / U+FEFF (zero-width non-breaking space) /
//   U+2060..U+2064 (word joiner, invisible operators) / U+00AD (soft
//   hyphen) / U+180E
//     — all can be inserted **invisibly**. API_KEY and API<U+FEFF>KEY look
//       the same, and spelling does not need them
//   U+FFF9..U+FFFB (interlinear annotation) — creates a boundary between
//     body and annotation, so the display can be forked
//   U+2028 / U+2029 (line / paragraph separators) — some renderers treat
//     them as newlines
//
// Cf (format characters) is not crushed wholesale: ZWNJ (U+200C) / ZWJ
// (U+200D) are **required for legitimate display** of Persian, Devanagari,
// and emoji joins (they decide the joining of characters itself), and
// crushing them would break correct names. The ones listed above only
// manipulate order and visibility and spelling does not need them, so the
// line is drawn there. For the same reason, variation selectors that
// decide emoji presentation (U+FE00..U+FE0F) and the format prefixes of
// Arabic digits (U+0600..U+0605 etc.) are not crushed.
//
// This is **an enumeration (a deny-list) and does not close** — things a
// character class cannot distinguish remain, like look-alike characters.
// Where "the displayed string = the actual string" is strictly required,
// use {@link escapeText}'s allow-list instead of this function.
//
// **Using this on variable names is an intentional line**: `DАTАBАSЕ_URL`
// (А = Cyrillic U+0410) is indistinguishable from `DATABASE_URL` and
// passes displayText through. It still does not become an allow-list
// because that would crush every legitimate non-ASCII variable name and
// user_id into \u{...}, destroying the listing's readability. The
// allow-list is used only where a string is pointed to as an operation
// target (a keychain entry name), not in listings. Name forging via
// look-alike characters is **a known open hole**; to solve it, the fix
// belongs on the name-normalization / registration-time check side, not
// the display side.
//
// The display name (displayText) and the value (displayValue) carry the
// same danger, so this list is **held in one place** — written separately,
// a one-sided addition would linger unnoticed
const ORDER_BREAKING =
  "\\u00AD\\u061C\\u180E\\u200B\\u200E\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\u2028\\u2029\\uFEFF\\uFFF9-\\uFFFB";
const CONTROL_CHARS = new RegExp(`\\p{Cc}|[${ORDER_BREAKING}]`, "gu");
// The range escapeText passes through = printable ASCII
// (U+0020..U+007E) minus backslash and the quotation mark. Everything else
// is escaped uniformly. Backslash is needed for reversibility (an escaped
// notation and a string that originally looked the same must not
// collide); the quotation mark is needed so a display wrapped in
// quotation marks cannot be closed early
const ESCAPABLE = /[^\u0020-\u007E]|["\\]/gu;

/** Replaces control and order-breaking characters for safe terminal display. */
export function displayText(value: string): string {
  return value.replace(CONTROL_CHARS, "\uFFFD");
}

// ---------------------------------------------------------------------------
// Total display of server-declared unix ms
//
// serverTs / createdAtMs / expiresAtMs / updatedAtMs are unbounded wire
// numbers; passing something outside ECMA-262's Date range (±8.64e15 ms)
// to Date#toISOString becomes a RangeError defect, ending audit / invite /
// key show in a crash rather than a typed error. Display is made total:
// out-of-range degrades to a string stating "invalid timestamp" (one bad
// field must not drop the whole row or the whole command).
// ---------------------------------------------------------------------------

/** The absolute ceiling of unix ms that ECMA-262 allows a Date. */
const MAX_TIMESTAMP_MS = 8_640_000_000_000_000;

// Accepts only the standard form ("YYYY-MM-DDTHH:mm:ss.sssZ"): even inside
// the Date range, a year outside 0..9999 makes toISOString return the
// expanded-year form ("+010000-…" / "-…"), and a fixed-offset slice
// silently cuts out a different position (the "explicit degradation"
// promise breaks). Checking the form pins the slice's premise itself
const STANDARD_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** A standard-form ISO string when in range (year 0..9999), otherwise null. */
function isoOf(ms: number): string | null {
  if (!Number.isFinite(ms) || Math.abs(ms) > MAX_TIMESTAMP_MS) {
    return null;
  }
  const iso = new Date(ms).toISOString();
  return STANDARD_ISO.test(iso) ? iso : null;
}

/** The display for an out-of-range value (derived from a number, so no terminal sanitizing needed). */
function invalidTimestamp(ms: number): string {
  return `(invalid timestamp: ${ms})`;
}

/** unix ms → "YYYY-MM-DD HH:mm:ss UTC" (explicit display when out of range — total). */
export function formatUtcSeconds(ms: number): string {
  const iso = isoOf(ms);
  return iso === null ? invalidTimestamp(ms) : iso.slice(0, 19).replace("T", " ") + " UTC";
}

/** unix ms → "YYYY-MM-DD HH:mm UTC" (explicit display when out of range — total). */
export function formatUtcMinutes(ms: number): string {
  const iso = isoOf(ms);
  return iso === null ? invalidTimestamp(ms) : iso.slice(0, 16).replace("T", " ") + " UTC";
}

/** unix ms → "YYYY-MM-DD" (explicit display when out of range — total). */
export function formatUtcDate(ms: number): string {
  const iso = isoOf(ms);
  return iso === null ? invalidTimestamp(ms) : iso.slice(0, 10);
}

/**
 * English count phrase with a regular plural: `countNoun(1, "variable")` →
 * "1 variable", `countNoun(2, "variable")` → "2 variables".
 *
 * ADR-0017's switch to English increased the places that embed a count in
 * the wording. Writing the plural directly into a template yields "1
 * variables" — routing the counting side through here aligns singular and
 * plural (if an irregular noun is ever needed, add arguments then).
 */
export function countNoun(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

/** Enumerating projects with the count ("2 projects (a, b)" — shared by the ledger-key decision sentences). */
export function describeProjects(projectIds: readonly string[]): string {
  return `${countNoun(projectIds.length, "project")} (${projectIds.map(displayText).join(", ")})`;
}

/**
 * The range of "the N projects the server listed" (a sentence saying none
 * exists — DK K13-2. Shared by `device add` and the ledger-key decision —
 * K15-3).
 */
export function describeListed(count: number): string {
  return `no project the server lists for you (${count === 0 ? "none" : count} listed)`;
}

/** The verified range (a sentence saying all of them are so — DK K15-3): the N projects the server lists for you. */
export function describeListedScope(count: number): string {
  return `the ${countNoun(count, "project")} the server lists for you`;
}

/** The phrase for a ledger key without the reserve-key mark (DK K16-6 — CRYPTO_SPEC §8). */
export function describeUnmarkedLedgerKey(): string {
  return "was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one), so it is not used as your reserve key";
}

/**
 * Escapes everything outside printable ASCII as `\u{...}` (hex, at least four
 * digits — supplementary-plane code points take more), and `\` / `"` as `\\` /
 * `\"`, so the rendered text is exactly reconstructible.
 *
 * {@link displayText} crushes characters into the replacement character,
 * so **the user cannot reconstruct the original string**. Where the string
 * itself is pointed to as an operation target — "delete the entry with
 * this name" — it must not be crushed (that would guide a name that
 * cannot be deleted), so it is escaped into a shape that is safe to
 * stream to the terminal while keeping the original.
 *
 * **Why an allow-list**: enumerating dangerous characters and escaping
 * them does not close. Adding control characters, format characters, lone
 * surrogates, line separators still leaves look-alike characters (Latin
 * `a` U+0061 vs Cyrillic `а` U+0430 etc.), which a character class cannot
 * distinguish **because they look identical**. To truly establish
 * "displayed name = actual name", the only option is to pass through only
 * the range known to be safe and escape everything else uniformly. A
 * non-ASCII user_id becomes a verbose notation, but this function's
 * purpose is **identity as an operation target**, not readability — the
 * former is taken.
 */
export function escapeText(value: string): string {
  return value.replace(ESCAPABLE, (char) =>
    char === "\\" || char === '"'
      ? `\\${char}`
      : `\\u{${(char.codePointAt(0) ?? 0xff_fd).toString(16).padStart(4, "0")}}`,
  );
}

// For displaying values (pull --show): neutralize the carriers of
// terminal injection (ESC, BEL, C1, CR, etc.) while keeping only tab (\t)
// and newline (\n) so legitimate secrets (multi-line PEM keys etc.) are
// not broken. A value is stored by a co-editor (a legitimate writer), so
// this prevents a malicious value tampering with other members' terminals
// (a separate threat from server forgery). Order-breaking characters
// ({@link ORDER_BREAKING}) are the same threat; passing only the value
// through would break "displayed value = actual value" on the value side
// (the ZWNJ / ZWJ that spelling needs are kept, same as displayText)
const VALUE_CONTROL_CHARS = new RegExp(`[^\\P{Cc}\\t\\n]|[${ORDER_BREAKING}]`, "gu");

/** Neutralizes injection-capable control chars in a secret value, keeping \t and \n. */
function displayValue(value: string): string {
  return value.replace(VALUE_CONTROL_CHARS, "\uFFFD");
}

// ---------------------------------------------------------------------------
// Formatting helpers for command output
// ---------------------------------------------------------------------------

/** The target of a pull listing row (the display portion of pull.ts's DecryptedVariable). */
export interface DisplayableVariable {
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly value: Redacted.Redacted<Uint8Array>;
}

/**
 * One row of pull's metadata listing.
 *
 * Reason for unwrapping: reads **the byte length only** (the value does
 * not go on the row). This row is emitted regardless of --show, so it sits
 * before the value-display gate and must not mix the value itself into
 * the output here.
 */
export function formatPulledLine(variable: DisplayableVariable): string {
  const byteLength = Redacted.value(variable.value).byteLength;
  return `${displayText(variable.name)}\tversion=${variable.version}\tepoch=${variable.epoch}\t(${byteLength} bytes)`;
}

/** Displays the SHOULD warnings collected during verification (e.g. serving a non-NFC name — §12-1). */
export function logWarnings(warnings: readonly string[]): Effect.Effect<void, never, CliIo> {
  return Effect.forEach(warnings, (warning) => logWarning(warning), { discard: true });
}

const strictValueDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * The only decoding policy for value bytes → text (fatal). Invalid UTF-8
 * becomes null (the caller makes it an explicit error naming the
 * variable).
 *
 * Choosing the policy: run (env-var injection) requires fatal; letting
 * only the display side pass with replacement characters would produce
 * the asymmetry "shows under --show but fails under run" and a copy
 * accident of a value silently corrupted by a replacement character. Both
 * paths are unified to fatal.
 */
export function decodeValueText(value: Uint8Array): string | null {
  try {
    return strictValueDecoder.decode(value);
  } catch {
    // A fatal decoder's exception is treated as the "invalid UTF-8" verdict (the value is not carried)
    return null;
  }
}

/** The terminal display of values (pull --show). agent-gate.ts refuses whether display is allowed. */
export const showValues = Effect.fn("display.showValues")(function* (
  variables: readonly DisplayableVariable[],
): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio> {
  const io = yield* CliIo;
  // The check at the command entry (before decryption) is the mainline.
  // This post-decryption check is a defensive line so a future path
  // calling showValues directly cannot reach display without the entry
  // check. **Both** are aligned to the new gate (the TTY primary
  // boundary) — leaving one on the deny-list would let an unknown agent
  // slip through on the defensive-line side
  yield* ensureValueDisplayAllowed;
  // Decoding of every value completes before any output
  // (all-or-nothing). If even one value is invalid UTF-8, nothing is
  // shown and it fails — no partial output (only the first values left
  // on screen) is produced
  const lines: string[] = [];
  // Variables whose display was altered by neutralization (only names are collected; the value is not carried)
  const altered: string[] = [];
  for (const variable of variables) {
    // Reason for unwrapping: displaying the value is this command's
    // very function. Unwrap **only after passing
    // ensureValueDisplayAllowed above (the TTY primary boundary + the
    // agent secondary layer)** — unwrapping before the gate would
    // assemble the plaintext as an in-memory string even in an
    // environment that refuses
    const text = decodeValueText(Redacted.value(variable.value));
    if (text === null) {
      return yield* Effect.fail(
        cliError(
          `The value of variable ${displayText(variable.name)} is not valid UTF-8 and cannot be displayed (binary values are outside the scope of --show)`,
        ),
      );
    }
    const shown = displayValue(text);
    if (shown !== text) {
      altered.push(displayText(variable.name));
    }
    lines.push(...renderValue(displayText(variable.name), shown));
  }
  for (const line of lines) {
    yield* io.log(line);
  }
  // Neutralization is needed to prevent terminal injection, but done
  // **silently** the user cannot notice that "the on-screen string = the
  // actual value" broke (copying it pastes a corrupted value). Only when
  // neutralization happened, stderr names that the original is a
  // different thing and the means to pass the actual value (run's
  // env-var injection)
  if (altered.length > 0) {
    yield* logWarning(warnAlteredDisplay(altered));
  }
});

/** The marker put on each line of a multi-line value (a shape distinguishable from a `NAME=` line). */
const CONTINUATION = "| ";

/**
 * One variable's display lines.
 *
 * Newlines are needed by legitimate values (multi-line PEM keys etc.) and
 * are not crushed, but **streamed raw they let the value side forge
 * lines**: a co-editor who writes `x\nDATABASE_URL=...` into a value can
 * fabricate a row for a variable that does not exist (the value is E2EE,
 * so the server cannot forge it — but a writer can write it). Making it a
 * neutralization target would break real multi-line secrets, so instead
 * of crushing it is **framed with its provenance made explicit** — marking
 * line 2 onward shows which lines continue the value from the display
 * alone.
 */
function renderValue(name: string, shown: string): readonly string[] {
  // A trailing newline does not add a line (`"a\nb\n"` is 2 lines + a
  // trailing newline). A naive split would create an empty 3rd line and
  // shift the declared line count by one. Whether a newline is present is
  // part of the value, so it is stated in the heading rather than dropped
  const trailingNewline = shown.endsWith("\n");
  const parts = (trailingNewline ? shown.slice(0, -1) : shown).split("\n");
  if (parts.length === 1 && !trailingNewline) {
    return [`${name}=${shown}`];
  }
  const trailing = trailingNewline ? " with a trailing newline" : "";
  return [
    `${name}= (a ${parts.length}-line value${trailing}; the leading "${CONTINUATION}" on each line below is a marker added by maruhi)`,
    ...parts.map((line) => `${CONTINUATION}${line}`),
  ];
}

/**
 * The warning that neutralization changed the display (the values
 * themselves are not shown).
 *
 * `maruhi run` is shown as an escape route, but **it is not written as
 * universal**: a value containing NUL cannot ride an env var and run
 * itself refuses it (run.ts). Writing "use run and you can pass it"
 * unconditionally here would send the user to a procedure that refuses
 * them next.
 */
function warnAlteredDisplay(names: readonly string[]): string {
  return `the values of these variables contain characters unusable in terminal output (control characters or ordering-manipulation characters), shown as \uFFFD instead. The displayed strings do not match the actual values — do not copy and use them. To pass the actual values to a process, use \`maruhi run -- <command>\` (though values containing NUL cannot be passed as env vars, so run rejects them too): ${names.join(", ")}`;
}
