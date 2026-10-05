// Unit tests for the own-devices record's (own-devices.ts) persistence
// layer.
//
// Properties pinned down:
//  1. record → load hits (the recorded row is read back verbatim)
//  2. A missing file reads as `missing`, an undecodable file as `corrupt`
//  3. An **unreadable** file (EACCES / EISDIR / EIO) reads as `corrupt`,
//     not a failure — `load` is fail-open: recordedReserves (`key show`)
//     and staleReserveFingerprints (key recover) treat any non-`loaded`
//     state as "no records" and degrade rather than abort
//  4. record refuses to overwrite a corrupt file (strict decode — no
//     partial rebuilds)

import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { makeFileOwnDeviceStore, type OwnDeviceEntry } from "../src/own-devices.ts";

const ORIGIN = "https://maruhi.example";
const USER_A = "user-alice-1111";

const ENTRY: OwnDeviceEntry = {
  keyFingerprintHex: "aa".repeat(16),
  encPubHex: "bb".repeat(32),
  sigPubHex: "cc".repeat(32),
  roleCap: "member",
  scope: { kind: "all" },
  source: "reserve",
  label: null,
  addedByFingerprintHex: null,
  observedProjectId: null,
  recordedAtMs: 1_700_000_000_000,
  revokedAtMs: null,
};

async function makeStore() {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-own-devices-test-"));
  const path = join(dir, "own-devices.json");
  return { path, store: makeFileOwnDeviceStore(path) };
}

describe("own-devices record (own-devices.ts)", () => {
  it("record → load hits, a missing file reads as `missing`", async () => {
    const { store } = await makeStore();
    expect((await Effect.runPromise(store.load(ORIGIN, USER_A))).state).toBe("missing");

    await Effect.runPromise(store.record(ORIGIN, USER_A, ENTRY));
    const hit = await Effect.runPromise(store.load(ORIGIN, USER_A));
    if (hit.state !== "loaded") throw new Error(`expected loaded, got ${hit.state}`);
    expect(hit.devices).toEqual([ENTRY]);
  });

  it("an unreadable file (EISDIR) reads as `corrupt`, not a failure — the load path is fail-open", async () => {
    const { path, store } = await makeStore();
    await mkdir(path);

    // recordedReserves / staleReserveFingerprints consume `load` directly
    // and degrade on any non-`loaded` state — a merely unreadable file
    // must not fail `key show` / `key recover`
    expect((await Effect.runPromise(store.load(ORIGIN, USER_A))).state).toBe("corrupt");
  });

  it("a corrupt file reads as `corrupt` and record does not overwrite corruption", async () => {
    const { path, store } = await makeStore();
    await writeFile(path, "{ not json");

    expect((await Effect.runPromise(store.load(ORIGIN, USER_A))).state).toBe("corrupt");

    const failed = await Effect.runPromise(
      store.record(ORIGIN, USER_A, ENTRY).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(failed).toContain("Cannot write the own-devices record");
    // The corrupt content stays as-is (never silently rebuilt)
    expect(await readFile(path, "utf8")).toBe("{ not json");
  });
});
