import { Redacted } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { formatPulledLine } from "../src/display.ts";
import {
  buildInviteLink,
  type InviteLinkData,
  parseInviteAcceptInput,
} from "../src/invite-link.ts";
import { testProjectId, testUserId } from "./support/crypto.ts";
const SEED_HEX = "d0".repeat(32);

function sampleLinkData(): InviteLinkData {
  return {
    inviteId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    linkSeedHex: Redacted.make(SEED_HEX, { label: "invite-link-seed" }),
    projectId: testProjectId("ab".repeat(32)),
    headHashHex: "cd".repeat(32),
    headSeq: 1,
    inviterUserId: testUserId("user-inviter-11"),
    inviterEncPubHex: "ef".repeat(32),
    inviterSigPubHex: "01".repeat(32),
    role: "member",
    scopeKind: "all",
    scopeEnvironmentIds: [],
    inviterLogin: null,
    issueSignatureHex: "02".repeat(64),
  };
}

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
    const line = formatPulledLine(variable);
    expect(line).toContain("(15 bytes)");
    expect(line).not.toContain("plaintext-value");
  });

  it("the parsed link's seed (k=) is also wrapped", () => {
    const raw = buildInviteLink({ origin: "https://maruhi.example", link: sampleLinkData() });
    const parsed = parseInviteAcceptInput(raw);
    if (parsed.kind !== "link") throw new Error(`expected link, got ${parsed.kind}`);
    expect(`${parsed.link.linkSeedHex}`).toBe("<redacted:invite-link-seed>");
    expect(JSON.stringify(parsed.link)).not.toContain(SEED_HEX);
  });
});
