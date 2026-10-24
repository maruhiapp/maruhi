// Unit tests for keychain.ts's record codecs: the stored token and master
// key records and their entry names.

import { Redacted } from "effect";
import { describe, expect, it } from "vitest";

import {
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  serializeStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import { testUserId } from "./support/crypto.ts";

describe("keychain record codecs", () => {
  it("round-trips token / device key records and detects corruption", () => {
    const token = { token: "maruhi_pat_x", userId: "u1", tokenId: "t1", expiresAtMs: 1 };
    const parsed = parseStoredToken(JSON.stringify(token));
    if (parsed === null) throw new Error("expected a parsed token record");
    // Always unwrap before comparing raw values (toEqual on wrapped values does not inspect the contents)
    expect(Redacted.value(parsed.token)).toBe("maruhi_pat_x");
    expect({ userId: parsed.userId, tokenId: parsed.tokenId }).toEqual({
      userId: "u1",
      tokenId: "t1",
    });
    // Round-trip against the storage side: serializeStoredToken → parseStoredToken
    // returns the raw value (if serialization wrote a redaction this fails here)
    const reparsed = parseStoredToken(serializeStoredToken(parsed));
    if (reparsed === null) throw new Error("expected a reparsed token record");
    expect(Redacted.value(reparsed.token)).toBe("maruhi_pat_x");
    expect(parseStoredToken("not json")).toBeNull();
    expect(parseStoredToken(JSON.stringify({ token: "x" }))).toBeNull();
    // The expiry is required (absence = corruption)
    expect(
      parseStoredToken(JSON.stringify({ token: "maruhi_pat_x", userId: "u1", tokenId: "t1" })),
    ).toBeNull();
    expect(parseStoredMasterKey(JSON.stringify({ suite: "maruhi/v1" }))).toBeNull();
  });

  it("keychain names are scoped by server origin (and userId)", () => {
    expect(tokenEntryName("https://a.example")).not.toBe(tokenEntryName("https://b.example"));
    expect(masterKeyEntryName("https://a.example", testUserId("u1"))).not.toBe(
      masterKeyEntryName("https://a.example", testUserId("u2")),
    );
  });
});
