// 検証済み指紋帳(KF — known-fingerprints.ts)の永続化層の単体テスト。
//
// 固定する性質:
//  1. record → lookup がヒットし、別 origin / 別 user_id とは混ざらない
//  2. 同一キーへの record は上書き(正当な鍵更新の反映)、他エントリは保持
//  3. 破損ファイルは corrupt(miss と区別)で、record は破損を上書きしない
//  4. 形式外のキー・指紋は record が手前で拒否する(次回ロードの全体破損を防ぐ)
//  5. ENOENT 以外の読み込み失敗は miss に畳まず失敗にする(空の帳での上書き・変更警告の黙殺を防ぐ)

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
  it("record → lookup がヒットし、別 origin / 別 user_id とは混ざらない", async () => {
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

  it("ファイル不在は miss(fail-open)", async () => {
    const { book } = await makeBook();
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("miss");
  });

  it("同じ人への record は指紋の集合に足し、他エントリは保持する(read-merge-write — DK の端末集合)", async () => {
    const { book, path } = await makeBook();
    await Effect.runPromise(book.record(ORIGIN, USER_A, FP_A));
    await Effect.runPromise(book.record(ORIGIN, USER_B, FP_B));
    // USER_A の 2 台目の端末(儀式の再成功)は集合に足す(1 台目を消さない)
    await Effect.runPromise(book.record(ORIGIN, USER_A, FP_B));

    const a = await Effect.runPromise(book.lookup(ORIGIN, USER_A));
    const b = await Effect.runPromise(book.lookup(ORIGIN, USER_B));
    if (a.state !== "hit" || b.state !== "hit") throw new Error("expected both hits");
    expect(a.entries.map((entry) => entry.fingerprintHex).toSorted()).toEqual(
      [FP_A, FP_B].toSorted(),
    );
    expect(b.entries.map((entry) => entry.fingerprintHex)).toEqual([FP_B]);
    // ファイルは可読 JSON(利用者がエントリを削除して儀式を強制できる導線)。v2 = 集合
    const stored = JSON.parse(await readFile(path, "utf8")) as { v: number };
    expect(stored.v).toBe(2);
  });

  it("ENOENT 以外の読み込み失敗(EISDIR 等)は miss に畳まず、lookup / record とも失敗する", async () => {
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

  it("破損ファイルは corrupt(miss と区別)で、record は破損を上書きしない", async () => {
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
    // 破損内容がそのまま残る(黙って作り直さない)
    expect(await readFile(path, "utf8")).toBe("{ not json");
  });

  it("スキーマ不一致(不正な指紋・不正なキー)は全体を corrupt として扱う", async () => {
    const { book, path } = await makeBook();
    await writeFile(
      path,
      JSON.stringify({
        v: 2,
        known: { [ORIGIN]: { [USER_A]: { fingerprints: { zz: { verifiedAtMs: 1 } } } } },
      }),
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("corrupt");

    // v2 以外の版は、中身が v2 の形でも読まない
    await writeFile(
      path,
      JSON.stringify({
        v: 1,
        known: { [ORIGIN]: { [USER_A]: { fingerprints: { [FP_A]: { verifiedAtMs: 1 } } } } },
      }),
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("corrupt");

    // `__proto__` キー(JSON.parse は own property として作る)は先頭 `_` の
    // 禁止で全体破損として拒否される(prototype 汚染の構造的排除)
    await writeFile(
      path,
      `{"v":2,"known":{"${ORIGIN}":{"__proto__":{"fingerprints":{"${FP_A}":{"verifiedAtMs":1}}}}}}`,
    );
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("corrupt");
  });

  it("形式外のキー・指紋は record が手前で拒否する(次回ロードを破損させない)", async () => {
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
    // 拒否された書き込みはファイルを作らない = 以後のロードは健全
    expect((await Effect.runPromise(book.lookup(ORIGIN, USER_A))).state).toBe("miss");
  });
});
