// Unit tests for the invite-pin file's (pins.ts) persistence layer.
//
// Properties pinned down:
//  1. A pin the stored schema rejects (an environment id outside the
//     AUTH_SPEC §12-1 form) is refused at write time, and the existing file
//     stays byte-identical (it never becomes a file the next load reads as
//     corrupt)
//  2. An issued record keyed `__proto__` (JSON.parse creates it as an own
//     property, and the schema decoder keeps it as one) reads as corrupt —
//     the invite-id key rule rejects it rather than it vanishing into the
//     prototype
//  3. A file with a leading byte-order mark loads (the FileSystem read
//     decodes UTF-8 with the BOM stripped)

import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { type IssuedInvitePin, issuedPinOf, makeFilePinStore } from "../src/pins.ts";

const PROJECT = "ab".repeat(32);
const INVITE_A = "01JINVITEAAAAAAAAAAAAAAAAA";
const INVITE_B = "01JINVITEBBBBBBBBBBBBBBBBB";

function pin(environmentIds: readonly string[]): IssuedInvitePin {
  return {
    linkPubHex: "cd".repeat(32),
    role: "member",
    scopeKind: "listed",
    scopeEnvironmentIds: environmentIds,
    // Far inside the retention window (never swept by the next write)
    expiresAtMs: Date.now() + 60 * 60 * 1000,
    expectedGithubLogin: null,
  };
}

async function makeStore() {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-pins-test-"));
  return { path: join(dir, `${PROJECT}.json`), store: makeFilePinStore(dir) };
}

describe("invite-pin file (pins.ts)", () => {
  it("a pin the schema rejects (environment id `_bad`) is refused and the existing file stays byte-identical", async () => {
    const { path, store } = await makeStore();
    await Effect.runPromise(store.saveIssuedPin(PROJECT, INVITE_A, pin(["prod"])));
    const before = await readFile(path);

    const failed = await Effect.runPromise(
      store.saveIssuedPin(PROJECT, INVITE_B, pin(["_bad"])).pipe(
        Effect.map(() => null),
        Effect.catch((error) => Effect.succeed(error.message)),
      ),
    );
    expect(failed).toContain("Cannot write the invite-pin file");

    expect((await readFile(path)).equals(before)).toBe(true);
    const loaded = await Effect.runPromise(store.load(PROJECT));
    expect(loaded.state).toBe("loaded");
    expect(issuedPinOf(loaded.pins, INVITE_A)?.scopeEnvironmentIds).toEqual(["prod"]);
    expect(issuedPinOf(loaded.pins, INVITE_B)).toBeUndefined();
  });

  it("an issued record keyed `__proto__` reads as corrupt (kept as an own key, rejected by the invite-id rule)", async () => {
    const { path, store } = await makeStore();
    await Effect.runPromise(store.saveIssuedPin(PROJECT, INVITE_A, pin(["prod"])));
    const stored = await readFile(path, "utf8");
    // Rename the issued key in the raw text: JSON.stringify of an object
    // cannot produce an own `__proto__` key
    await writeFile(path, stored.replace(`"${INVITE_A}"`, `"__proto__"`));
    expect(await readFile(path, "utf8")).toContain(`"__proto__"`);

    const loaded = await Effect.runPromise(store.load(PROJECT));
    expect(loaded.state).toBe("corrupt");
    expect(loaded.pins).toBeNull();
  });

  it("a pin file with a leading byte-order mark loads", async () => {
    const { path, store } = await makeStore();
    await Effect.runPromise(store.saveIssuedPin(PROJECT, INVITE_A, pin(["prod"])));
    await writeFile(path, `﻿${await readFile(path, "utf8")}`);

    const loaded = await Effect.runPromise(store.load(PROJECT));
    expect(loaded.state).toBe("loaded");
    expect(issuedPinOf(loaded.pins, INVITE_A)?.scopeEnvironmentIds).toEqual(["prod"]);
  });
});
