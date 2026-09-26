// Unit tests for the verified-fingerprint book's (KF —
// known-fingerprints.ts) persistence layer.
//
// Properties pinned down:
//  1. record → lookup hits, and never mixes with another origin / another
//     user_id
//  2. A record on the same key overwrites (reflecting a legitimate key
//     update); other entries are kept
//  3. A corrupt file reads as corrupt (distinct from miss), and record does
//     not overwrite corruption
//  4. record rejects malformed keys/fingerprints before writing (prevents
//     next-load whole-file corruption)
//  5. Read failures other than ENOENT fail rather than folding into a miss
//     (prevents overwriting with an empty book / silently swallowing
//     change warnings)

import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { makeFileFingerprintBook } from "../src/known-fingerprints.ts";

const ORIGIN = "https://maruhi.example";
const USER_A = "user-alice-1111";
const USER_B = "user-bob-2222";
const FP_A = "aa".repeat(16);
const FP_B = "bb".repeat(16);

async function makeBook() {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-kf-test-"));
  const path = join(dir, "known-fingerprints.json");
  return { path, book: makeFileFingerprintBook(path) };
}

describe("verified-fingerprint book (known-fingerprints.ts)", () => {
  it("record → lookup hits, and never mixes with another origin / another user_id", async () => {
    const { book } = await makeBook();
    await Effect.runPromise(book.record(ORIGIN, USER_A, FP_A));

    const hit = await Effect.runPromise(book.lookup(ORIGIN, USER_A));
    if (hit.state !== "hit") throw new Error(`expected hit, got ${hit.state}`);
    expect(hit.entries.map((entry) => entry.fingerprintHex)).toEqual([FP_A]);
    expect(hit.entries[0]?.verifiedAtMs).toBeGreaterThan(0);

    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_B))).state).toBe("miss");
    expect((await Effect.runPromise(book.lookup("https://other.example", USER_A))).state).toBe(
      "miss",
    );
  });

  it("a missing file is a miss (fail-open)", async () => {
    const { book } = await makeBook();
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("miss");
  });

  it("a record for the same person adds to the fingerprint set, keeping other entries (read-merge-write — the DK device set)", async () => {
    const { book, path } = await makeBook();
    await Effect.runPromise(book.record(ORIGIN, USER_A, FP_A));
    await Effect.runPromise(book.record(ORIGIN, USER_B, FP_B));
    // USER_A's second device (the ceremony succeeding again) adds to the
    // set (doesn't erase the first)
    await Effect.runPromise(book.record(ORIGIN, USER_A, FP_B));

    const a = await Effect.runPromise(book.lookup(ORIGIN, USER_A));
    const b = await Effect.runPromise(book.lookup(ORIGIN, USER_B));
    if (a.state !== "hit" || b.state !== "hit") throw new Error("expected both hits");
    expect(a.entries.map((entry) => entry.fingerprintHex).toSorted()).toEqual(
      [FP_A, FP_B].toSorted(),
    );
    expect(b.entries.map((entry) => entry.fingerprintHex)).toEqual([FP_B]);
    // The file is readable JSON (the path for users to delete an entry and
    // force a fresh ceremony). v2 = a set
    const stored = JSON.parse(await readFile(path, "utf8")) as { v: number };
    expect(stored.v).toBe(2);
  });

  it("a v1 book (one fingerprint per person) reads as a one-element set and becomes v2 on the next record", async () => {
    const { book, path } = await makeBook();
    await writeFile(
      path,
      JSON.stringify({
        v: 1,
        known: { [ORIGIN]: { [USER_A]: { fingerprintHex: FP_A, verifiedAtMs: 1 } } },
      }),
    );
    const before = await Effect.runPromise(book.lookup(ORIGIN, USER_A));
    if (before.state !== "hit") throw new Error("expected hit");
    expect(before.entries).toEqual([{ fingerprintHex: FP_A, verifiedAtMs: 1 }]);
    await Effect.runPromise(book.record(ORIGIN, USER_A, FP_B));
    const stored = JSON.parse(await readFile(path, "utf8")) as { v: number };
    expect(stored.v).toBe(2);
    const after = await Effect.runPromise(book.lookup(ORIGIN, USER_A));
    if (after.state !== "hit") throw new Error("expected hit");
    expect(after.entries.map((entry) => entry.fingerprintHex).toSorted()).toEqual(
      [FP_A, FP_B].toSorted(),
    );
  });

  it("read failures other than ENOENT (EISDIR etc.) do not fold into a miss — lookup and record both fail", async () => {
    const { book, path } = await makeBook();
    await mkdir(path);

    const lookupFailed = await Effect.runPromise(
      book.lookup(ORIGIN, USER_A).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(lookupFailed).toContain("Cannot read the verified-fingerprint book");

    const recordFailed = await Effect.runPromise(
      book.record(ORIGIN, USER_A, FP_A).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(recordFailed).toContain("Cannot write the verified-fingerprint book");
  });

  it("a corrupt file reads as corrupt (distinct from miss), and record does not overwrite corruption", async () => {
    const { book, path } = await makeBook();
    await writeFile(path, "{ not json");

    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("corrupt");

    const failed = await Effect.runPromise(
      book.record(ORIGIN, USER_A, FP_A).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(failed).toContain("Cannot write the verified-fingerprint book");
    // The corrupt content stays as-is (never silently rebuilt)
    expect(await readFile(path, "utf8")).toBe("{ not json");
  });

  it("schema mismatches (bad fingerprints, bad keys) treat the whole book as corrupt", async () => {
    const { book, path } = await makeBook();
    await writeFile(
      path,
      JSON.stringify({
        v: 1,
        known: { [ORIGIN]: { [USER_A]: { fingerprintHex: "zz", verifiedAtMs: 1 } } },
      }),
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("corrupt");

    // The `__proto__` key (JSON.parse creates it as an own property) is
    // rejected as whole-file corruption by the leading-`_` ban (structural
    // exclusion of prototype pollution)
    await writeFile(
      path,
      `{"v":1,"known":{"${ORIGIN}":{"__proto__":{"fingerprintHex":"${FP_A}","verifiedAtMs":1}}}}`,
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("corrupt");
  });

  it("record rejects malformed keys/fingerprints before writing (won't corrupt the next load)", async () => {
    const { book } = await makeBook();
    for (const [origin, userId, fp] of [
      ["_underscore", USER_A, FP_A],
      [ORIGIN, "_user", FP_A],
      [ORIGIN, USER_A, "not-hex"],
    ] as const) {
      const failed = await Effect.runPromise(
        book.record(origin, userId, fp).pipe(
          Effect.map(() => null),
          Effect.catch((error) => Effect.succeed(error.message)),
        ),
      );
      expect(failed).toContain("Cannot write the verified-fingerprint book");
    }
    // A rejected write creates no file = subsequent loads stay healthy
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("miss");
  });
});
