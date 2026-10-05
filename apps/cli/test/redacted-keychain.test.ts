// The regression that secret material is wrapped in `Redacted` (the 4th layer after ADR-0016's display gate).
//
// Following display.ts (terminal neutralization), failure.ts (error mapping),
// and "internal errors get only the type name", this 4th layer: tokens can
// never yield their raw value without unwrapping `Redacted` at the type level.
//
// What this pins, threefold (split across redacted-output.test.ts #1,
// redacted-keychain.test.ts #2, and redacted.test.ts #3):
//  2. The keychain round trip (save → read-back → real use) is not broken by a
//     redacted save (`Redacted.toJSON()` returns "<redacted>", so stringifying a
//     record as-is saves a redaction with no type error — the biggest trap)

import { Effect, Exit, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import { afterEach, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import { runCli } from "../src/cli.ts";
import { displayText, escapeText } from "../src/display.ts";
import {
  classifyUnreadableMasterKey,
  corruptMasterKeyMessage,
  foreignMasterKeyMessage,
  hasRedactedPlaceholder,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  redactedPlaceholderMasterKeyMessage,
  redactedPlaceholderTokenMessage,
  tokenRecordNoun,
  serializeStoredMasterKey,
  serializeStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import { formatRecoveryCode, parseRecoveryCode } from "../src/recovery-code.ts";
import { ensureNoStoredMasterKey, loadMasterKeys, resolveSession } from "../src/session.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";
import { runCliWithClock } from "./support/test-clock.ts";

/** The exchange-response expiry fixture (AUTH_SPEC §6 — W3a: 2099-01-01T00:00:00Z). */
const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

// ---------------------------------------------------------------------------
// 2. The keychain round trip (save → read-back → real use)
// ---------------------------------------------------------------------------

/** The master key record's JSON (with only the given fields swapped). */
function masterRecordJson(overrides: Record<string, string>): string {
  return JSON.stringify({
    suite: "maruhi/v1",
    encPubHex: "aa".repeat(32),
    encSkHex: "bb".repeat(32),
    sigPubHex: "cc".repeat(32),
    sigSkSeedHex: "dd".repeat(32),
    ...overrides,
  });
}

describe("the keychain round trip is not broken by redacted serialization", () => {
  it("serializeStoredToken writes the raw value (it has not stepped into JSON.stringify's redacted save)", () => {
    const record = parseStoredToken(
      JSON.stringify({
        token: "maruhi_pat_real",
        userId: "u1",
        tokenId: "t1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    if (record === null) throw new Error("expected a parsed record");
    const serialized = serializeStoredToken(record);
    expect(serialized).toContain("maruhi_pat_real");
    expect(serialized).not.toContain("<redacted");
  });

  it("a master key record redacts only the secret side; the public side stays raw", () => {
    const record = parseStoredMasterKey(masterRecordJson({}));
    if (record === null) throw new Error("expected a parsed master-key record");
    const json = JSON.stringify(record);
    // The secret side never appears
    expect(json).not.toContain("bb".repeat(32));
    expect(json).not.toContain("dd".repeat(32));
    expect(`${record.encSkHex}`).toBe("<redacted:master-enc-sk>");
    expect(`${record.sigSkSeedHex}`).toBe("<redacted:master-sig-seed>");
    // The public side stays raw (used by signature context, FP calculation, and invite payloads)
    expect(json).toContain("aa".repeat(32));
    expect(json).toContain("cc".repeat(32));
  });

  it("serializeStoredMasterKey writes the raw value (the key is not lost to a redacted save)", () => {
    const record = parseStoredMasterKey(masterRecordJson({}));
    if (record === null) throw new Error("expected a parsed master-key record");
    const serialized = serializeStoredMasterKey(record);
    expect(serialized).toContain("bb".repeat(32));
    expect(serialized).toContain("dd".repeat(32));
    expect(serialized).not.toContain("<redacted");
    // Serialize → re-parse brings the secret side back (the round trip closes)
    const reparsed = parseStoredMasterKey(serialized);
    if (reparsed === null) throw new Error("expected a reparsed master-key record");
    expect(Redacted.value(reparsed.encSkHex)).toBe("bb".repeat(32));
    expect(Redacted.value(reparsed.sigSkSeedHex)).toBe("dd".repeat(32));
  });

  it("a recovery code redacts, and unwrapping returns the original secret", () => {
    const secret = new Uint8Array(32).fill(9);
    const code = formatRecoveryCode(Redacted.make(secret));
    expect(`${code}`).toBe("<redacted:recovery-code>");
    expect(JSON.stringify({ code })).not.toMatch(/[A-Z2-7]{4}-[A-Z2-7]{4}/);
    const parsed = parseRecoveryCode(Redacted.value(code));
    if (parsed === null) throw new Error("expected a parsed recovery secret");
    expect(`${parsed}`).toBe("<redacted:recovery-secret>");
    expect(Redacted.value(parsed)).toEqual(secret);
  });

  it("login's save → resolveSession's read-back → real use as a Bearer header", async () => {
    // Runs the 3 stages in one pass. If redaction mixes in anywhere, this is
    // where it fails as "saved but authentication fails" (a path type checking never catches)
    const authorizations: (string | undefined)[] = [];
    const maruhi = await start([
      onRequest("POST", "/auth/cli/start", () => ({
        status: 200,
        json: {
          flowId: "0123456789abcdef0123456789abcdef",
          flowToken: "v1.dGVzdC1mbG93.fixture-mac-value",
          userCode: "ABCD-1234",
          verificationUrl: "https://maruhi.example/auth/cli/verify?flow=x&vsig=y",
          expiresInSeconds: 900,
          pollIntervalSeconds: 0,
        },
      })),
      onRequest("POST", "/auth/cli/poll", () => ({
        status: 200,
        json: {
          status: "approved",
          token: "maruhi_pat_issued_real",
          tokenId: "tok_1",
          userId: "user-0001",
          expiresAtMs: EXPIRES_AT_MS,
        },
      })),
      onRequest("GET", "/auth/me", (request) => {
        const header = request.headers["authorization"];
        authorizations.push(typeof header === "string" ? header : undefined);
        return { status: 200, json: { userId: "user-0001", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });

    // (a) Save: login writes to the keychain
    const code = await runCliWithClock(["login"], env.layer);
    expect(code).toBe(0);
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    // No redaction saved = the next authentication is not dead
    expect(stored).toContain("maruhi_pat_issued_real");
    expect(stored).not.toContain("<redacted");

    // (b) Read-back: resolveSession restores it from the keychain
    const session = await Effect.runPromise(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Redacted.value(session.token)).toBe("maruhi_pat_issued_real");

    // (c) Real use: the restored token is actually sent as a Bearer header
    await Effect.runPromise(
      Effect.gen(function* () {
        const client = yield* makeApiClient({ baseUrl: maruhi.origin, token: session.token });
        return yield* client.auth.me({});
      }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    expect(authorizations).toEqual(["Bearer maruhi_pat_issued_real"]);
  });

  it("a record saved as redacted is rejected as a broken record at the read boundary", () => {
    // A forgotten unwrap at serialization is the one path types cannot stop.
    // Undetected on the read side it becomes a misattributed diagnosis —
    // "401 = revoked, please log in again" / "cannot read the key material" —
    // and the true cause (the save side) is never reached
    for (const placeholder of ["<redacted>", "<redacted:maruhi-token>"]) {
      expect(
        parseStoredToken(
          JSON.stringify({
            token: placeholder,
            userId: "u1",
            tokenId: "t1",
            expiresAtMs: 4_102_444_800_000,
          }),
        ),
      ).toBeNull();
    }
    expect(
      parseStoredMasterKey(masterRecordJson({ encSkHex: "<redacted:master-enc-sk>" })),
    ).toBeNull();
    expect(
      parseStoredMasterKey(masterRecordJson({ sigSkSeedHex: "<redacted:master-sig-seed>" })),
    ).toBeNull();
    // A normal record passes (the positive control — the detection is not over-eager)
    expect(parseStoredMasterKey(masterRecordJson({}))).not.toBeNull();
    expect(
      parseStoredToken(
        JSON.stringify({
          token: "maruhi_pat_x",
          userId: "u1",
          tokenId: "t1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    ).not.toBeNull();
  });

  it("a redacted save becomes a diagnosis whose recovery steps differ per record kind", async () => {
    // Folded into the generic "it is broken", neither the cause nor the
    // recovery gets across. Recoverability differs by record kind (a token
    // may heal via overwrite / a master key is blocked by the overwrite guard), so the wording splits there too
    expect(
      hasRedactedPlaceholder(
        JSON.stringify({
          token: "<redacted:maruhi-token>",
          userId: "u1",
          tokenId: "t1",
          expiresAtMs: 4_102_444_800_000,
        }),
      ),
    ).toBe(true);
    expect(hasRedactedPlaceholder(masterRecordJson({ encSkHex: "<redacted:master-enc-sk>" }))).toBe(
      true,
    );
    // It never fires on a normal record or on broken JSON
    expect(hasRedactedPlaceholder(masterRecordJson({}))).toBe(false);
    expect(hasRedactedPlaceholder("not json")).toBe(false);
    // The recovery differs by record kind. A token is overwritten by logging
    // in again, so it guides toward that; a master key is blocked by the
    // overwrite guard, so it guides toward manual deletion
    expect(redactedPlaceholderTokenMessage("os-keychain")).toContain(
      "`maruhi login` overwrites it",
    );
    expect(redactedPlaceholderTokenMessage("os-keychain")).toContain("The keychain record");
    // On an agent session it never points at a nonexistent keychain (the fix is the same)
    expect(redactedPlaceholderTokenMessage("agent")).toContain("held by this agent session");
    expect(redactedPlaceholderTokenMessage("agent")).not.toContain("keychain record");
    // The broken record's name follows the same pair (it fails if the agent side regresses to the keychain)
    expect(tokenRecordNoun("os-keychain")).toContain("keychain token record");
    expect(tokenRecordNoun("agent")).toContain("held by this agent session");
    expect(tokenRecordNoun("agent")).not.toContain("keychain");
    // Never flatly claims "always fixable" (if a bug remains in the current version it recurs)
    expect(redactedPlaceholderTokenMessage("os-keychain")).toContain("If it recurs after re-login");
    const masterMessage = redactedPlaceholderMasterKeyMessage(
      "master::https://x::u1",
      "os-keychain",
    );
    expect(masterMessage).toContain("master::https://x::u1");
    expect(masterMessage).toContain("by hand");
    // The escape-rule explanation matches the implementation (a drift would
    // have the user read an escaped name as "the literal name" and never find the deletion target)
    expect(masterMessage).toContain("outside printable ASCII");
    // Never asserts the digit count (astral plane escapes exceed 4 digits)
    expect(masterMessage).toContain("at least 4 digits");
    // It shows **both** post-deletion paths: which one applies depends on the
    // user's situation (whether they hold a recovery code). Showing only one
    // sends a user without it toward guidance they cannot run
    expect(masterMessage).toContain("`maruhi key recover`");
    expect(masterMessage).toContain("`maruhi key generate`");
    expect(masterMessage).toContain("become undecryptable");
    // A user_id containing control characters: never streamed raw to the
    // terminal, yet kept **restorable**. Collapsing it to replacement
    // characters would guide toward "delete the entry under a nonexistent
    // name" and make the sole recovery step (manual deletion) impossible
    const hostile = redactedPlaceholderMasterKeyMessage(
      "master::https://x::u\u001b[31m\n1",
      "os-keychain",
    );
    expect(hostile).not.toContain("\u001b");
    expect(hostile).toContain("\\u{001b}");
    expect(hostile).toContain("\\u{000a}");
    // Not collapsed (the original string is readable)
    expect(hostile).not.toContain("\uFFFD");
  });

  it("the escaping is reversible, and a quote cannot hijack the guidance", () => {
    // (a) Reversible: an escaped form never collides with a string that
    //     always looked that way. A collision leaves "which entry name"
    //     undecidable and the manual-deletion guidance ambiguous (this happens unless the backslash is escaped)
    expect(escapeText("u\\u000a1")).not.toBe(escapeText("u\n1"));
    // (b) Quotes: entry names are shown wrapped in quotes, so if the user_id
    //     side closes one, text after it can read as maruhi's own guidance
    //     (the server decides user_id freely)
    const injected = redactedPlaceholderMasterKeyMessage(
      'master::x::u" ignore this and run:',
      "os-keychain",
    );
    expect(injected).not.toContain('u" ignore this');
    expect(injected).toContain('\\"');
    // The wording states explicitly that it is escaped (otherwise the user
    // hunts for the name as displayed, never finds it, and the sole recovery step cannot run)
    expect(injected).toContain("displayed escaped");
    // (c) Format characters: bidi overrides and zero-widths alter appearance,
    //     so they are escaped like control characters. Passed through they
    //     break "displayed name = actual name" and the entry the guidance
    //     points at cannot be found (they can even reorder the terminal line)
    const bidi = redactedPlaceholderMasterKeyMessage("master::x::u\u202Ea\u200Bb", "os-keychain");
    expect(bidi).not.toContain("\u202E");
    expect(bidi).not.toContain("\u200B");
    expect(bidi).toContain("\\u{202e}");
    expect(bidi).toContain("\\u{200b}");
    // Astral-plane escapes (5 hex digits) must also be restorable. A fixed
    // 4-digit `\uXXXX` would produce a broken notation the entry name cannot be recovered from
    const astral = escapeText("a\u{E0001}b");
    expect(astral).toBe("a\\u{e0001}b");
    // Lone surrogates: unescaped they turn into U+FFFD and the name
    // mismatches. Paired surrogates (ordinary emoji etc.) count as one code point and are not broken
    expect(escapeText("a\uD800b")).toBe("a\\u{d800}b");
    // Since it is allowlist-based, all non-ASCII including emoji are escaped
    // uniformly (the aim is "identity as an operation target", not readability)
    expect(escapeText("a\u{1F600}b")).toBe("a\\u{1f600}b");
    expect(escapeText("a\u2028b\u2029c")).toBe("a\\u{2028}b\\u{2029}c");
    // Visually identical homoglyphs also appear distinct (the kind character classes cannot tell apart)
    expect(escapeText("\u0430")).toBe("\\u{0430}");
    expect(escapeText("a")).toBe("a");
    // Non-breaking spaces etc. never pass through either (indistinguishable from a normal space)
    expect(escapeText("a\u00A0b")).toBe("a\\u{00a0}b");
    // Printable ASCII stays as-is (no redundancy)
    expect(escapeText("master::https://x::u1")).toBe("master::https://x::u1");
  });

  it("reading from a keychain that saved redaction produces that diagnosis (the real path)", async () => {
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    // Reproduces a forgotten unwrap at serialization (= a save-side bug)
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "<redacted:maruhi-token>",
        userId: "u1",
        tokenId: "t1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    const exit = await Effect.runPromiseExit(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("The keychain record contains the redaction placeholder (<redacted>)");
    // Not the generic "it is broken" wording — a wording that names the cause
    expect(dump).not.toContain("The keychain token record is corrupt");
  });

  it("displayText also collapses order-breaking characters, but keeps legitimate format characters", () => {
    // A bidi override can reorder the display: collapsing only ANSI escapes
    // never closes "fake lines / injected guidance" (names can be forged in pull's list)
    expect(displayText("a\u202Eb")).toBe("a\uFFFDb");
    expect(displayText("a\u2066b")).toBe("a\uFFFDb");
    expect(displayText("a\u2028b")).toBe("a\uFFFDb");
    // Bidi marks and zero-width spaces alike (they only steer order · visibility; no spelling needs them)
    for (const hostile of ["\u200E", "\u200F", "\u061C", "\u200B"]) {
      expect(displayText(`a${hostile}b`)).toBe("a\uFFFDb");
    }
    // Same for format characters insertable invisibly (API_KEY and
    // API<U+FEFF>KEY can be made to look identical)
    for (const invisible of ["\uFEFF", "\u2060", "\u00AD", "\u180E", "\uFFF9"]) {
      expect(displayText(`a${invisible}b`)).toBe("a\uFFFDb");
    }
    // ZWNJ / ZWJ are kept — Persian, Devanagari, and emoji joins need them
    // (these decide character joining itself)
    expect(displayText("a\u200Cb")).toBe("a\u200Cb");
    expect(displayText("a\u200Db")).toBe("a\u200Db");
    // Variation selectors that decide an emoji's presentation are kept too (collapsing them changes the emoji)
    expect(displayText("\u2764\uFE0F")).toBe("\u2764\uFE0F");
  });

  it("a master key record written by a future version is never advised for deletion", () => {
    // A changed shape fails the current parse, but that is a valid key of
    // another version, not corruption. Advising "please delete it" leaves a
    // user without a recovery code unable to restore it
    const future = JSON.stringify({ suite: "maruhi/v2", kemPubHex: "aa", kemSkHex: "bb" });
    expect(parseStoredMasterKey(future)).toBeNull();
    expect(classifyUnreadableMasterKey(future)).toBe("foreign");
    const message = foreignMasterKeyMessage("maruhi/v2", "master::https://x::u1", "os-keychain");
    expect(message).toContain("keep this record");
    // The default is "do not delete". Yet it is no dead end either: the escape
    // is shown only in a **reversible** form (stash the value, then delete).
    // Conditioning on a recovery code would land on "deleted and unrestorable" exactly when the blob is the new format too
    expect(message).toContain("Copy down the value first");
    // The point of the escape is reversibility. **Replacing** the stash
    // instruction when adding the disposal one would erase what the stash is for (both are needed)
    expect(message).toContain("you can put it back");
    // The stash is the master secret key itself. Since it has the user make
    // one, it also says to destroy it (the no-key-material-left discipline
    // covers a manual stash the same way)
    // The disposal condition is **when hand-restoration is no longer needed**
    // — never worded to read as "`key recover` succeeding" (on this path
    // recover itself can fail)
    expect(message).toContain("once it is no longer needed");
    expect(message).toContain("master::https://x::u1");
    expect(message).toContain("Never delete without the copy");
    expect(message).not.toContain("if you have your recovery code");
    // It also states that the entry name is shown escaped (without it the name cannot be found)
    expect(message).toContain("the unescaped form");
    // A truly broken one is treated as corrupted as before (the deletion exit is shown)
    expect(classifyUnreadableMasterKey("not json")).toBe("corrupt");
    // Unreadable despite the current shape being complete = inner corruption (safe to delete)
    expect(classifyUnreadableMasterKey(masterRecordJson({ encSkHex: "" }))).toBe("corrupt");
    // Even with the current suite, **different field shapes** may be a future
    // format. SUITE_ID identifies the crypto suite, not the storage format's
    // version, so it never grounds a deletion recommendation
    expect(classifyUnreadableMasterKey('{"suite":"maruhi/v1","keys":{"enc":"aa"}}')).toBe(
      "foreign",
    );
    // Shapes that name no suite or nest the fields also fall on the
    // never-advise-deletion side (where a future format puts them is unknown
    // to today's implementation)
    expect(classifyUnreadableMasterKey('{"key":{"suite":"maruhi/v2"}}')).toBe("foreign");
    expect(classifyUnreadableMasterKey("{}")).toBe("foreign");
    // A shape that is not even a JSON object, though, falls on the corruption
    // side. Calling it "another format" would produce "do not delete, update
    // instead" guidance — and with updating unable to fix it, generate /
    // recover / show all stay blocked (no escape)
    for (const scalar of ["null", "123", '"str"', "true"]) {
      expect(classifyUnreadableMasterKey(scalar)).toBe("corrupt");
    }
    // An array stays on the keep side: a future version could use it as a
    // container holding several keys, so "not an object" alone never grounds deletion
    expect(classifyUnreadableMasterKey("[]")).toBe("foreign");
  });

  it("an unreadable master key record is also never a dead end", () => {
    // The overwrite guard only checks a record exists, so as long as an
    // unreadable record remains, generate / recover / show are all refused.
    // It guides toward the same exit as the redacted case (show the entry name and delete by hand)
    const message = corruptMasterKeyMessage("master::https://x::u1", "os-keychain");
    expect(message).toContain("master::https://x::u1");
    expect(message).toContain("by hand");
    // Even on the corruption side deletion stays **reversible**: since
    // parseStoredMasterKey never inspects the hex's contents, a well-formed
    // future-format record can fail at decodeHex and *look* corrupted (the key material may be fine)
    expect(message).toContain("Copy down the value first");
    expect(message).toContain("you can put it back");
    // Since it has the user make a stash, it also says to destroy it (the same obligation as the other-format side)
    // The disposal condition is **when hand-restoration is no longer needed**
    // — never worded to read as "`key recover` succeeding" (on this path
    // recover itself can fail)
    expect(message).toContain("once it is no longer needed");
    expect(message).toContain("`maruhi key recover`");
    expect(message).toContain("`maruhi key generate`");
  });

  it("never tells an unreadable master key 'a key exists' (non-redaction corruption takes the same exit)", async () => {
    // "Already exists" may be said only when a readable record actually
    // exists. Returning the refusal wording for an unreadable record
    // contradicts the facts and, showing no exit, blocks generate / recover /
    // show entirely
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const entryName = masterKeyEntryName(maruhi.origin, "u1");
    // Unreadable despite the current-format fields all **present** = inner
    // corruption (an incomplete shape may be a future format, so it never falls on the advise-deletion side)
    env.keychain.set(
      entryName,
      JSON.stringify({
        suite: "maruhi/v1",
        encPubHex: "zz",
        encSkHex: "",
        sigPubHex: "zz",
        sigSkSeedHex: "",
      }),
    );
    const session = {
      origin: maruhi.origin,
      userId: "u1",
      token: Redacted.make("maruhi_pat_stored"),
    };
    const exit = await Effect.runPromiseExit(
      ensureNoStoredMasterKey(session, "the device key already exists").pipe(
        Effect.provide(env.layer),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("Cannot read the keychain device-key record");
    expect(dump).toContain("by hand");
    expect(dump).not.toContain("the device key already exists");
  });

  it("with the shape in place but unreadable key material, it never says 'a key exists'", async () => {
    // A record that passes the storage-shape check (a non-empty string) yet
    // is broken as hex. Judging by shape alone returns "already exists"
    // while loadMasterKeys fails — a contradiction that also shows no exit
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const entryName = masterKeyEntryName(maruhi.origin, "u1");
    env.keychain.set(entryName, masterRecordJson({ encSkHex: "zzzz" }));
    const session = {
      origin: maruhi.origin,
      userId: "u1",
      token: Redacted.make("maruhi_pat_stored"),
    };
    const exit = await Effect.runPromiseExit(
      ensureNoStoredMasterKey(session, "the device key already exists").pipe(
        Effect.provide(env.layer),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).not.toContain("the device key already exists");
    expect(dump).toContain("by hand");
  });

  it("a redacted master key is not reported as 'a key exists' (the overwrite guard distinguishes too)", async () => {
    // This guard is where **both** key generate and key recover hit first.
    // Saying "already exists" reports an unusable key as existing, and the
    // entry name to delete never surfaces until another command
    const maruhi = await start([]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    const entryName = masterKeyEntryName(maruhi.origin, "u1");
    env.keychain.set(entryName, masterRecordJson({ encSkHex: "<redacted:master-enc-sk>" }));
    const session = {
      origin: maruhi.origin,
      userId: "u1",
      token: Redacted.make("maruhi_pat_stored"),
    };
    const exit = await Effect.runPromiseExit(
      ensureNoStoredMasterKey(session, "the device key already exists").pipe(
        Effect.provide(env.layer),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("contains the redaction placeholder (<redacted>)");
    expect(dump).toContain("by hand");
    expect(dump).not.toContain("the device key already exists");
  });

  it("key generate's save → loadMasterKeys' read-back → usable as a key", async () => {
    // The master-key side's keychain round trip. If redaction were saved, hex
    // decode or the WebCrypto import would fail — "saved but cannot decrypt"
    const maruhi = await start([
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
      onRequest("PUT", "/auth/recovery", () => ({ status: 204 })),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin });
    env.keychain.set(
      tokenEntryName(maruhi.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    // Answers the save-confirmation prompt (the displayed code's final group) lazily
    env.setPromptResponses([
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        if (line === undefined) throw new Error("recovery code line not found");
        const groups = line.trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);

    // (a) Save
    expect(await runCli(["key", "generate"], env.layer)).toBe(0);
    const stored = env.keychain.get(masterKeyEntryName(maruhi.origin, "user-0001"));
    expect(stored).toBeDefined();
    expect(stored).not.toContain("<redacted");

    // (b) Read-back + (c) real use: loadMasterKeys decodes the hex and imports
    // it as a non-extractable CryptoKey, so success = usable as a key
    const keys = await Effect.runPromise(
      loadMasterKeys({
        origin: maruhi.origin,
        userId: "user-0001",
        token: Redacted.make("maruhi_pat_stored"),
      }).pipe(Effect.provide(env.layer)),
    );
    // Matches the FP keygen displayed (the same key came back)
    expect(env.logs.join("\n")).toContain(`key fingerprint: ${keys.fingerprintHex}`);
    expect(keys.encKeyPair.privateKey.extractable).toBe(false);
    expect(keys.sigKeyPair.privateKey.extractable).toBe(false);
  });

  it("if MARUHI_TOKEN holds a redaction, it names the reason before any communication", async () => {
    // Once Redacted exists, pasting a redaction seen in output into the env
    // var believing it is the token is a realistic path. Sent as-is it 401s
    // and the user lands on guidance for a different cause ("may be expired · revoked" — session.ts's auth-failure wording)
    const requests: string[] = [];
    const maruhi = await start([
      onRequest("GET", "/auth/me", (request) => {
        requests.push(request.path);
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    // Pasted values routinely pick up surrounding whitespace/newlines, so it must not break on that
    env.setEnvVar("MARUHI_TOKEN", "  <redacted:maruhi-token>\n");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    const exit = await Effect.runPromiseExit(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const dump = JSON.stringify(exit);
    expect(dump).toContain("redaction placeholder (<redacted>) itself");
    expect(dump).not.toContain("Authentication with MARUHI_TOKEN failed");
    // Fails before any communication (makes neither a wasted round trip nor a misattributed 401)
    expect(requests).toEqual([]);
  });

  it("a token via the MARUHI_TOKEN path is also wrapped, and sent as the raw value", async () => {
    const authorizations: (string | undefined)[] = [];
    const maruhi = await start([
      onRequest("GET", "/auth/me", (request) => {
        const header = request.headers["authorization"];
        authorizations.push(typeof header === "string" ? header : undefined);
        return { status: 200, json: { userId: "user-env", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env_real");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    const session = await Effect.runPromise(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    // The plain string arriving from env is wrapped (wrapped at the origin)
    expect(`${session.token}`).toBe("<redacted:maruhi-token>");
    expect(Redacted.value(session.token)).toBe("maruhi_pat_env_real");
    expect(authorizations).toEqual(["Bearer maruhi_pat_env_real"]);
  });
});
