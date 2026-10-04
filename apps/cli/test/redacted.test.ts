// The regression that secret material is wrapped in `Redacted` (the 4th layer after ADR-0016's display gate).
//
// Following display.ts (terminal neutralization), failure.ts (error mapping),
// and "internal errors get only the type name", this 4th layer: tokens can
// never yield their raw value without unwrapping `Redacted` at the type level.
//
// What this pins, threefold:
//  3. The unwrap sites (`Redacted.value`) are kept countable
//
// #3 is close to the real aim: more than the redaction itself, "the unwrap sites have not grown" is what works.

import { readdir, readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

// ---------------------------------------------------------------------------
// 3. The inventory of unwrap sites
// ---------------------------------------------------------------------------

/**
 * Call sites of `Redacted.value(` (file → count).
 *
 * **Changes that grow this table are subject to review**. More than the
 * redaction itself, what matters is keeping the unwrap sites countable (the
 * inventory — notes §7). When adding one, leave "why unwrap here" in a
 * comment on the implementation side and update this table.
 */
const EXPECTED_UNWRAP_SITES: Readonly<Record<string, number>> = {
  // Wire boundary: the lease request's oidcToken field (A3 — AUTH_SPEC §14-2)
  "ci-lease.ts": 1,
  // ci rotate (PF7b): the leased credential and admin inputs handed to the connector in memory, and the lease token on the mint request
  "ci-rotate.ts": 5,
  "rotation-proposals.ts": 1,
  // Input to the HPKE wrap (a cryptographic boundary)
  "dek-wrap.ts": 1,
  // Byte length for list rows (the value is never shown) + --show's display (after the gate)
  "display.ts": 2,
  // Input to the DEK commitment calculation (a cryptographic boundary; the product is a hash)
  "env-create.ts": 1,
  // Observing the value's shape (schema import's type inference · value-
  // likeness — the products are a closed set of type names and booleans only;
  // the value and its fragments never leave)
  "env-file.ts": 1,
  "env-rotate.ts": 1,
  // Link-key derivation input (seed → non-extractable CryptoKey; a
  // cryptographic boundary) 1 + link display (after the agent gate) 1
  "invite.ts": 2,
  // Link-string assembly (the result is wrapped again) 1 + parsing the
  // accept input (a link; the seed is returned wrapped again) 1
  "invite-link.ts": 2,
  // Serialization = the only persistence path (token 1 + the master key's secret side 2)
  "keychain.ts": 3,
  // --show-token's issuance-time terminal display (the one place in AUTH_SPEC
  // §6 — after the display gate. Ruling CK)
  "login.ts": 1,
  // Reading the claims of our own OIDC token (decoding the payload segment — A3)
  "oidc-github.ts": 2,
  // The decryption key input (a cryptographic boundary)
  "pull.ts": 1,
  // The encryption key input and plaintext input (a cryptographic boundary) 2 +
  // the in-memory equality check of two plaintexts (VH — the lineage of an
  // identical re-push and `var rollback`'s no-op refusal; no display) 1
  "push.ts": 3,
  // Base32-encoding input (the product is wrapped again)
  "recovery-code.ts": 1,
  // The encode input for an explicitly chosen value push (the product is
  // Redacted again — handed to push.ts's cryptographic boundary)
  "schema-import.ts": 1,
  // Key-derivation inputs for wrap / unwrap (cryptographic boundary) 2 +
  // code display 1 + the save-confirmation match 1 + interpreting the entered code 1
  "recovery.ts": 5,
  // Right before writing to the vendor CLI's stdin (sync's exec driver — the
  // only path where a value leaves maruhi. Never lands on argv)
  "live.ts": 1,
  // Right before injection into the child process's env, and the fragments
  // of the run-output redaction (searched inside the ProcessRunner only)
  "run.ts": 3,
  // `proxy run`: a brokered value resolved per request toward the rule's
  // hosts, the same value as the response-scrub / redaction pattern
  // (`known`), and a connector's inputs consumed to mint a short-lived
  // credential
  "proxy-run.ts": 3,
  // Importing the master secret key (hex → non-extractable CryptoKey)
  "session.ts": 2,
  // Assembling sync's stdin body (JSON — the product is Redacted again) 1 +
  // redacting the vendor output on failure (find-and-replace the value
  // fragment 1 + the http driver's integration-token fragment 1 — neither remains in the product)
  "sync-exec.ts": 3,
  // http driver: right before putting the value into the request body's
  // entry (the path where the value leaves maruhi. The integration token is
  // never unwrapped — the upstream bearerToken takes it still Redacted)
  "sync-http.ts": 1,
  // Measuring the plaintext length (the product is only a length) 1 + the
  // pre-send constraint check (the products are booleans and variable names)
  // 1 + checking the integration token's shape (the product is Redacted again) 1
  "sync-plan.ts": 3,
  // Parsing the receipt JSON (a name → version mapping. Not a secret value)
  "sync-receipt.ts": 1,
  // `var rotate`: the admin inputs consumed by a connector to call the
  // issuer 1 + the current credential (primary 1, companions 1) handed to the
  // connector + the previous / current pair of `--finalize` (2 companions +
  // 2 primaries) — every product is sent to the issuer or wrapped again for
  // the push; nothing is displayed
  "var-rotate.ts": 8,
};

// The match for the spelling (`Redacted` + `.value`). It crosses whitespace
// so a formatter folding it into `Redacted\n  .value` is not missed —
// miscounting the folded shape would be fail-open. **Both** the counting side
// and the no-mentions side use this one (if only one side were lenient, an
// offsetting cancel-out becomes possible)
const SPELLING_PATTERN = /Redacted\s*\.\s*value/g;
// A string literal, so the comment markers may be written as-is (what it
// reads is under src/, not this test file itself)
const LINE_COMMENT = "//";
const BLOCK_OPEN = "/*";
const BLOCK_CLOSE = "*/";

/**
 * Paints the mask while consuming comment open/close tokens **indivisibly**.
 *
 * Read one character at a time, the open token's second character `*` would
 * pair with the `/` right after it and be misjudged as "closed right after
 * opening" — everything after counts as code (the `/` `*` `/` sequence; the
 * spelling can be hidden inside it). Consuming 2 characters together on open prevents this.
 */
function scanComments(source: string, mask: boolean[]): void {
  let index = 0;
  let inBlock = false;
  let inLine = false;
  while (index < source.length) {
    const pair = source.slice(index, index + 2);
    if (inBlock) {
      mask[index] = true;
      if (pair === BLOCK_CLOSE) {
        mask[index + 1] = true;
        index += 2;
        inBlock = false;
        continue;
      }
    } else if (inLine) {
      if (source[index] === "\n") {
        inLine = false;
        index += 1;
        continue;
      }
      mask[index] = true;
    } else if (pair === BLOCK_OPEN || pair === LINE_COMMENT) {
      mask[index] = true;
      mask[index + 1] = true;
      inBlock = pair === BLOCK_OPEN;
      inLine = pair === LINE_COMMENT;
      index += 2;
      continue;
    }
    index += 1;
  }
}

/**
 * A mask over the whole source: "is this position inside a comment" (1 pass).
 *
 * The point is judging over the **whole source**, not per line: the counting
 * side sees the entire file, so even a shape folded across lines like
 * `Redacted\n  .value` counts as one. A per-line check on only the judgment
 * side could never flag that shape as a violation — a "hidden slot" where
 * the count still grows would remain.
 *
 * String literals are not tracked. Tracking them needs quoting, escapes, and
 * nested template interpolation handled — getting that wrong would
 * **misread a comment as a string and miss a mention** = building a
 * fail-open. Untracked, the error always lands the other way (real code
 * following a comment marker inside a string gets flagged as a violation),
 * and it recovers at line end anyway — just split the line. For a guard,
 * erring on the flagging side is correct.
 */
function commentMask(source: string): readonly boolean[] {
  const mask = Array.from({ length: source.length }, () => false);
  scanComments(source, mask);
  return mask;
}

/** 1-based line numbers (position → line). */
function lineAt(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

/**
 * Line numbers where the spelling appears **inside a comment**.
 *
 * Uses the same source and the same match as the counting side
 * ({@link collectUnwrapSites}). If only one side were lenient, a shape
 * countable only on the lenient side becomes a "hidden slot" — swapping a
 * mention for a real unwrap later never moves the count: an offsetting cancel-out.
 *
 * **Scope**: what it protects is "honest changes stay countable", not
 * deliberate concealment (embedding in string literals, dynamic indirect
 * calls, etc. are not detected). It is scoped to accidentally-occurring
 * shapes — formatter line-folds, mentions in comments, aliasing.
 */
function commentMentions(source: string): readonly number[] {
  const mask = commentMask(source);
  const lines: number[] = [];
  for (const match of source.matchAll(SPELLING_PATTERN)) {
    if (mask[match.index] === true) {
      lines.push(lineAt(source, match.index));
    }
  }
  return lines;
}

/** Recursively lists .ts files under src/ (paths relative to src/, stable order). */
async function srcFiles(): Promise<readonly string[]> {
  const entries = await readdir(SRC_DIR, { recursive: true });
  return entries.filter((name) => name.endsWith(".ts")).toSorted();
}

/**
 * Counts occurrences of `Redacted.value` (file → count).
 *
 * The design policy is **err on the fail-closed side**. This table is the
 * only mechanism keeping "unwrap sites are countable", so a defect that
 * overlooks breaks the mechanism:
 *
 * - **Walk recursively**. Non-recursive, a directory added under src/ later
 *   would make every unwrap site inside it vanish from the table
 * - **Never drop comments**. Dropping them correctly needs lexing; a naive
 *   regex would erase a line-comment marker inside a string literal (e.g.
 *   session.ts's `https://`) and everything to end-of-line with it — an
 *   unwrap added on that line would become **invisible**. Mentions inside
 *   comments are forbidden separately by {@link commentMentions}, so plain
 *   counting is fine
 * - **Never require `(`**. A point-free pass like `map(Redacted.value)` is
 *   also an unwrap; requiring the paren would miss it
 * - **Key by basename**. Counts are keyed by the file name alone, so moving a
 *   file into a directory (`*.package/` etc.) never rewrites the ledger. Two
 *   unwrap-carrying files sharing one basename would collapse into a single
 *   key — the second count silently replacing the first — so that overlap is
 *   rejected, listing every collided relative path (fail-closed again: a
 *   same-name pair is fine as long as at most one of them unwraps)
 */
async function collectUnwrapSites(): Promise<Record<string, number>> {
  const files = await srcFiles();
  const counts: Record<string, number> = {};
  const collisions = new Map<string, string[]>();
  for (const name of files) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    const matches = source.match(SPELLING_PATTERN);
    if (matches !== null) {
      const rel = name.replaceAll("\\", "/");
      const base = basename(rel);
      const collided = collisions.get(base) ?? [];
      collisions.set(base, [...collided, rel]);
      counts[base] = matches.length;
    }
  }
  const duplicates = [...collisions].filter(([, rels]) => rels.length > 1);
  if (duplicates.length > 0) {
    throw new Error(
      `unwrap sites exist under a shared basename — the ledger key would collide: ${duplicates
        .map(([base, rels]) => `${base} (${rels.join(", ")})`)
        .join("; ")}`,
    );
  }
  return counts;
}

describe("the inventory of sites that unwrap Redacted", () => {
  it("the unwrap sites have not grown (to grow them, update EXPECTED_UNWRAP_SITES)", async () => {
    expect(await collectUnwrapSites()).toEqual(EXPECTED_UNWRAP_SITES);
  });

  it("the spelling always appears in code (no mentions inside comments allowed)", async () => {
    // Since counts collapse to one integer per file, a prose mention becomes
    // a "hidden slot": delete one mention and add one real unwrap and the
    // count never moves — the table passes through. Not only line-leading but
    // **end-of-line** comments must be banned too or the slot remains, so the
    // check is whether the occurrence sits inside a comment
    const offenders: string[] = [];
    for (const name of await srcFiles()) {
      const source = await readFile(join(SRC_DIR, name), "utf8");
      offenders.push(...commentMentions(source).map((line) => `${name}:${line}`));
    }
    // Since the scan does not track string literals, **real code** following
    // a comment marker inside a string like `https://` can also land on the
    // violation side (a false positive accepted in exchange for never
    // missing). Written so it is clear which side it fell on
    expect(
      offenders,
      "either a comment mentions the spelling, or real unwrap code follows a comment marker inside a string literal — if the latter, split the line",
    ).toEqual([]);
  });

  it("Redacted is never carried out under an alias · a deep import · destructuring (shapes that slip past the match)", async () => {
    // Every carry-out where the spelling never appears is invisible to the inventory:
    //   `import { Redacted as R }` → `R.value(x)`
    //   `import * as R from "effect/Redacted"` → `R.value(x)`
    //   `const { value } = Redacted` / `const R = Redacted`
    // Pinned to the discipline that only allows taking the `Redacted` namespace from `effect`
    const offenders: string[] = [];
    for (const name of await srcFiles()) {
      const source = await readFile(join(SRC_DIR, name), "utf8");
      if (/\bRedacted\s+as\s+\w+/.test(source)) {
        offenders.push(`${name}(aliased import)`);
      }
      // A deep import (`effect/Redacted`) lets the namespace name be freely
      // renamed — an unwrap could happen without the spelling. Blocked at the entry
      if (/from\s+"effect\/Redacted"/.test(source)) {
        offenders.push(`${name}(deep import of effect/Redacted)`);
      }
      // A local alias like `const R = Redacted` is the same (`R.value(x)` works from then on)
      if (/(?:const|let|var)\s+\w+\s*=\s*Redacted\s*[;\n]/.test(source)) {
        offenders.push(`${name}(local alias)`);
      }
      if (/\{[^}]*\bvalue\b[^}]*\}\s*=\s*Redacted\b/.test(source)) {
        offenders.push(`${name}(destructuring)`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the token is never unwrapped to ride Bearer (it uses the upstream bearerToken)", async () => {
    const source = await readFile(join(SRC_DIR, "api.ts"), "utf8");
    expect(source).not.toContain("Redacted.value");
    // Hand-assembling the header (template expansion) is the shape that would
    // send the redaction — pinned as not used
    expect(source).not.toMatch(/Bearer \$\{/);
  });
});
