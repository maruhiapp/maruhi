import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { makeFileFingerprintBook } from "../src/known-fingerprints.ts";
import { testUserId } from "./support/crypto.ts";

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
    await Effect.runPromise(book.record(ORIGIN, testUserId(USER_A), FP_A));

    const hit = await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)));
    if (hit.state !== "hit") throw new Error(`expected hit, got ${hit.state}`);
    expect(hit.entries.map((entry) => entry.fingerprintHex)).toEqual([FP_A]);
    expect(hit.entries[0]?.verifiedAtMs).toBeGreaterThan(0);

    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_B)))).state).toBe("miss");
    expect(
      (await Effect.runPromise(book.lookup("https://other.example", testUserId(USER_A)))).state,
    ).toBe("miss");
  });

  it("a missing file is a miss (fail-open)", async () => {
    const { book } = await makeBook();
    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)))).state).toBe("miss");
  });

  it("a user_id of 'constructor' (a legal book key, an inherited Object property) records and hits via own-property lookup", async () => {
    const { book } = await makeBook();
    await Effect.runPromise(book.record(ORIGIN, testUserId("constructor"), FP_A));

    const hit = await Effect.runPromise(book.lookup(ORIGIN, testUserId("constructor")));
    if (hit.state !== "hit") throw new Error(`expected hit, got ${hit.state}`);
    expect(hit.entries.map((entry) => entry.fingerprintHex)).toEqual([FP_A]);
  });

  it("a record for the same person adds to the fingerprint set, keeping other entries (read-merge-write — the DK device set)", async () => {
    const { book, path } = await makeBook();
    await Effect.runPromise(book.record(ORIGIN, testUserId(USER_A), FP_A));
    await Effect.runPromise(book.record(ORIGIN, testUserId(USER_B), FP_B));
    await Effect.runPromise(book.record(ORIGIN, testUserId(USER_A), FP_B));

    const a = await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)));
    const b = await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_B)));
    if (a.state !== "hit" || b.state !== "hit") throw new Error("expected both hits");
    expect(a.entries.map((entry) => entry.fingerprintHex).toSorted()).toEqual(
      [FP_A, FP_B].toSorted(),
    );
    expect(b.entries.map((entry) => entry.fingerprintHex)).toEqual([FP_B]);
    const stored = JSON.parse(await readFile(path, "utf8")) as { v: number };
    expect(stored.v).toBe(2);
  });

  it("read failures other than ENOENT (EISDIR etc.) do not fold into a miss — lookup and record both fail", async () => {
    const { book, path } = await makeBook();
    await mkdir(path);

    const lookupFailed = await Effect.runPromise(
      book.lookup(ORIGIN, testUserId(USER_A)).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(lookupFailed).toContain("Cannot read the verified-fingerprint book");

    const recordFailed = await Effect.runPromise(
      book.record(ORIGIN, testUserId(USER_A), FP_A).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(recordFailed).toContain("Cannot write the verified-fingerprint book");
  });

  it("a corrupt file reads as corrupt (distinct from miss), and record does not overwrite corruption", async () => {
    const { book, path } = await makeBook();
    await writeFile(path, "{ not json");

    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)))).state).toBe(
      "corrupt",
    );

    const failed = await Effect.runPromise(
      book.record(ORIGIN, testUserId(USER_A), FP_A).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(failed).toContain("Cannot write the verified-fingerprint book");
    expect(await readFile(path, "utf8")).toBe("{ not json");
  });

  it("schema mismatches (bad fingerprints, bad keys) treat the whole book as corrupt", async () => {
    const { book, path } = await makeBook();
    await writeFile(
      path,
      JSON.stringify({
        v: 2,
        known: { [ORIGIN]: { [USER_A]: { fingerprints: { zz: { verifiedAtMs: 1 } } } } },
      }),
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)))).state).toBe(
      "corrupt",
    );

    await writeFile(
      path,
      JSON.stringify({
        v: 1,
        known: { [ORIGIN]: { [USER_A]: { fingerprints: { [FP_A]: { verifiedAtMs: 1 } } } } },
      }),
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)))).state).toBe(
      "corrupt",
    );

    await writeFile(
      path,
      `{"v":2,"known":{"${ORIGIN}":{"__proto__":{"fingerprints":{"${FP_A}":{"verifiedAtMs":1}}}}}}`,
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)))).state).toBe(
      "corrupt",
    );
  });

  it("record rejects malformed keys/fingerprints before writing (won't corrupt the next load)", async () => {
    const { book } = await makeBook();
    for (const [origin, userId, fp] of [
      ["_underscore", USER_A, FP_A],
      [ORIGIN, "_user", FP_A],
      [ORIGIN, USER_A, "not-hex"],
    ] as const) {
      const failed = await Effect.runPromise(
        book.record(origin, testUserId(userId), fp).pipe(
          Effect.map(() => null),
          Effect.catch((error) => Effect.succeed(error.message)),
        ),
      );
      expect(failed).toContain("Cannot write the verified-fingerprint book");
    }
    expect((await Effect.runPromise(book.lookup(ORIGIN, testUserId(USER_A)))).state).toBe("miss");
  });
});
