// The regression that secret material is wrapped in `Redacted` (the 4th layer after ADR-0016's display gate).
//
// Following display.ts (terminal neutralization), failure.ts (error mapping),
// and "internal errors get only the type name", this 4th layer: tokens can
// never yield their raw value without unwrapping `Redacted` at the type level.
//
// What this pins, threefold:
//  1. A careless `toString` / `JSON.stringify` / template expansion produces a redaction
//  2. The keychain round trip (save → read-back → real use) is not broken by a
//     redacted save (`Redacted.toJSON()` returns "<redacted>", so stringifying a
//     record as-is saves a redaction with no type error — the biggest trap)
//  3. The unwrap sites (`Redacted.value`) are kept countable
//
// #3 is close to the real aim: more than the redaction itself, "the unwrap sites have not grown" is what works.

import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Effect, Exit, Layer, Redacted, Stdio } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { afterEach, describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { makeApiClient } from "../src/api.ts";
import { runCli } from "../src/cli.ts";
import {
  displayText,
  type DisplayableVariable,
  escapeText,
  formatPulledLine,
  showValues,
} from "../src/display.ts";
import {
  buildInviteLink,
  type InviteLinkData,
  parseInviteAcceptInput,
} from "../src/invite-link.ts";
import { CliIo } from "../src/io.ts";
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

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

/** The exchange-response expiry fixture (AUTH_SPEC §6 — W3a: 2099-01-01T00:00:00Z). */
const EXPIRES_AT_MS = Date.UTC(2099, 0, 1);

/** The invite-link key seed (a test-only pattern value — CRYPTO_SPEC §6.5). */
const SEED_HEX = "d0".repeat(32);

/** Invite-link data with only the shape in place (signature verification is invite.test.ts's job). */
function sampleLinkData(): InviteLinkData {
  return {
    inviteId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    linkSeedHex: Redacted.make(SEED_HEX, { label: "invite-link-seed" }),
    projectId: "ab".repeat(32),
    headHashHex: "cd".repeat(32),
    headSeq: 1,
    inviterUserId: "user-inviter-11",
    inviterEncPubHex: "ef".repeat(32),
    inviterSigPubHex: "01".repeat(32),
    role: "member",
    scopeKind: "all",
    scopeEnvironmentIds: [],
    inviterLogin: null,
    issueSignatureHex: "02".repeat(64),
  };
}

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
// 1. Careless output still redacts
// ---------------------------------------------------------------------------

describe("secrets redact through naive output paths", () => {
  const SECRET = "maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123";

  it("toString / template expansion / String() never emit the raw value", () => {
    const token = Redacted.make(SECRET, { label: "maruhi-token" });
    expect(token.toString()).toBe("<redacted:maruhi-token>");
    expect(`${token}`).toBe("<redacted:maruhi-token>");
    expect(String(token)).toBe("<redacted:maruhi-token>");
    expect(`${token}`).not.toContain(SECRET);
  });

  it("JSON.stringify never emits the raw value (even embedded in a record)", () => {
    const record = {
      token: Redacted.make(SECRET, { label: "maruhi-token" }),
      userId: "u1",
      tokenId: "t1",
    };
    const json = JSON.stringify(record);
    expect(json).not.toContain(SECRET);
    expect(JSON.parse(json)).toEqual({
      token: "<redacted:maruhi-token>",
      userId: "u1",
      tokenId: "t1",
    });
  });

  it("an invite link (which embeds the link-key seed) also redacts when printed still wrapped", () => {
    const link = buildInviteLink({ origin: "https://maruhi.example", link: sampleLinkData() });
    expect(`${link}`).toBe("<redacted:invite-link>");
    expect(JSON.stringify({ link })).not.toContain(SEED_HEX);
    // Unwrapping yields the real link (the redaction breaks no functionality)
    expect(Redacted.value(link)).toContain(`k=${SEED_HEX}`);
  });

  it("a decrypted value (Uint8Array) also redacts — carelessly printing pull's result leaks nothing", () => {
    const value = Redacted.make(new TextEncoder().encode("plaintext-value"), {
      label: "variable-value",
    });
    const variable = { variableId: "v1", name: "SECRET", version: 1, epoch: 1, value };
    expect(`${value}`).toBe("<redacted:variable-value>");
    expect(JSON.stringify(variable)).not.toContain("plaintext-value");
    expect(JSON.stringify(variable)).toContain("<redacted:variable-value>");
    // The list row carries only the byte length (never the value itself)
    const line = formatPulledLine(variable);
    expect(line).toContain("(15 bytes)");
    expect(line).not.toContain("plaintext-value");
  });

  it("the parsed link's seed (k=) is also wrapped", () => {
    // Uses the shape arriving from the argument layer (Argument.Redacted) as-is (never unwrapped)
    const raw = buildInviteLink({ origin: "https://maruhi.example", link: sampleLinkData() });
    const parsed = parseInviteAcceptInput(raw);
    if (parsed.kind !== "link") throw new Error(`expected link, got ${parsed.kind}`);
    expect(`${parsed.link.linkSeedHex}`).toBe("<redacted:invite-link-seed>");
    expect(JSON.stringify(parsed.link)).not.toContain(SEED_HEX);
  });
});

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
      JSON.stringify({ token: "maruhi_pat_real", userId: "u1", tokenId: "t1" }),
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
    const code = await runCli(["login", "--poll-interval", "0"], env.layer);
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
        parseStoredToken(JSON.stringify({ token: placeholder, userId: "u1", tokenId: "t1" })),
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
      parseStoredToken(JSON.stringify({ token: "maruhi_pat_x", userId: "u1", tokenId: "t1" })),
    ).not.toBeNull();
  });

  it("a redacted save becomes a diagnosis whose recovery steps differ per record kind", async () => {
    // Folded into the generic "it is broken", neither the cause nor the
    // recovery gets across. Recoverability differs by record kind (a token
    // may heal via overwrite / a master key is blocked by the overwrite guard), so the wording splits there too
    expect(
      hasRedactedPlaceholder(
        JSON.stringify({ token: "<redacted:maruhi-token>", userId: "u1", tokenId: "t1" }),
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
      "`maruhi login` overwrites it correctly",
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
      JSON.stringify({ token: "<redacted:maruhi-token>", userId: "u1", tokenId: "t1" }),
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
      JSON.stringify({ token: "maruhi_pat_stored", userId: "user-0001", tokenId: "tok_1" }),
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

// ---------------------------------------------------------------------------
// 2b. Decrypted values are unwrapped only "behind" the display gate
// ---------------------------------------------------------------------------

/**
 * Makes one variable whose unwrap is **observable**.
 *
 * After `Redacted.wipeUnsafe`, `Redacted.value` throws a defect (the upstream
 * spec). That lets the test tell from outside "was it unwrapped": refused at
 * the gate fails as a typed error (CliError); past the gate it fails as a
 * defect. Used only inside the test — as handle invalidation, not zeroing
 * (production code never uses wipeUnsafe, so it never builds a defect path).
 */
function wipedVariable(): DisplayableVariable {
  const value = Redacted.make(new TextEncoder().encode("plaintext-value"), {
    label: "variable-value",
  });
  Redacted.wipeUnsafe(value);
  return { name: "SECRET", version: 1, epoch: 1, value };
}

describe("unwrapping decrypted values sits behind the display gate", () => {
  /** A CliIo that discards output (here we only check "it never reached display"). */
  const silentIo = Layer.succeed(CliIo, {
    log: () => Effect.void,
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array(0)),
    promptLine: () => Effect.succeed(""),
    envVar: () => undefined,
    agentProfile: () => ({ isAgent: false }),
    stderrIsTerminal: () => true,
    colorEnabled: () => false,
    openBrowser: () => Effect.succeed(false),
  });

  const showWiped = (input: {
    readonly isAgent: boolean;
    readonly stdinIsTerminal: boolean;
    readonly stdoutIsTerminal: boolean;
  }) =>
    Effect.runPromiseExit(
      showValues([wipedVariable()]).pipe(
        Effect.provide(
          Layer.mergeAll(
            silentIo,
            Layer.succeed(AgentProfileRef, { isAgent: input.isAgent }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(input.stdinIsTerminal),
              stdoutIsTerminal: Effect.succeed(input.stdoutIsTerminal),
            }),
          ),
        ),
      ),
    );

  it("on non-TTY / a known agent it fails with a typed error before unwrapping", async () => {
    // Unwrapped, it would defect (Unable to get redacted value). Failing as a
    // CliError instead = the decision settled before the gate
    for (const rejected of [
      { isAgent: false, stdinIsTerminal: true, stdoutIsTerminal: false },
      { isAgent: false, stdinIsTerminal: false, stdoutIsTerminal: true },
      { isAgent: true, stdinIsTerminal: true, stdoutIsTerminal: true },
    ]) {
      const exit = await showWiped(rejected);
      expect(Exit.isFailure(exit)).toBe(true);
      const dump = JSON.stringify(exit);
      // Failing as a typed error (Fail) = it settled at the gate. Had the
      // unwrap been reached, the wiped handle would throw a defect (Die) and this would change
      expect(dump).toContain('"_tag":"Fail"');
      expect(dump).not.toContain('"_tag":"Die"');
      expect(dump).not.toContain("plaintext-value");
    }
  });

  it("only a human's interactive terminal reaches the unwrap (the positive control — the gate is not swinging at air)", async () => {
    // With the same input through the gate, it now reaches the unwrap and
    // defects. Without this, the test above would also pass on an implementation that never unwraps at all
    const exit = await showWiped({
      isAgent: false,
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(exit)).toBe(true);
    // Evidence the unwrap on the wiped handle was reached (defect = Die)
    expect(JSON.stringify(exit)).toContain('"_tag":"Die"');
  });
});

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
  "oidc-github.ts": 1,
  // The decryption key input (a cryptographic boundary)
  "pull.ts": 1,
  // The encryption key input and plaintext input (a cryptographic boundary)
  "push.ts": 2,
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
  // Right before injection into the child process's env
  "run.ts": 2,
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
 */
async function collectUnwrapSites(): Promise<Record<string, number>> {
  const files = await srcFiles();
  const counts: Record<string, number> = {};
  for (const name of files) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    const matches = source.match(SPELLING_PATTERN);
    if (matches !== null) {
      // Keys are paths relative to src/ (a shape that distinguishes subdirectories)
      counts[name.replaceAll("\\", "/")] = matches.length;
    }
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
