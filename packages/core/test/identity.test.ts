// The UserId / ProviderUserId brands (identity.ts). The type-level half is
// enforced by `tsc --noEmit` (the typecheck step of the quality gate): each
// `@ts-expect-error` line below must stay a compile error, so a change that
// lets a provider identity into an internal-user-id position fails the gate
// (an unused `@ts-expect-error` is itself an error). The runtime half pins
// that the brands are type-only: decoding mints without changing the value.

import type { AddMemberPayload, ChainActor } from "@maruhi/crypto";
import { Schema } from "effect";
import { describe, expect, expectTypeOf, it } from "vitest";

import type { AuditActor, AuditEventRecord } from "../src/audit.ts";
import type {
  AuthenticatedPrincipal,
  SessionServiceShape,
  TokenServiceShape,
} from "../src/auth.ts";
import {
  decodeProviderUserId,
  decodeUserId,
  type ProviderUserId,
  ProviderUserIdSchema,
  type UserId,
  UserIdSchema,
} from "../src/identity.ts";

/** GitHub's numeric id, as the provider dance returns it (AUTH_SPEC §3-2). */
const providerSubject: ProviderUserId = decodeProviderUserId("583231");
/** The display login: a plain string (AUTH_SPEC §2 — a snapshot, never an identifier). */
const providerLogin = "octocat";
const internalUserId: UserId = decodeUserId("01J9Z3K4M5N6P7Q8R9S0T1V2W3");
const FP = "ab".repeat(16);

describe("UserId brand (CLAUDE.md identity rule)", () => {
  it("refuses a provider identity in an audit-log actor or target", () => {
    const actors: readonly AuditActor[] = [
      { userId: internalUserId },
      // @ts-expect-error a provider subject is not an internal user id
      { userId: providerSubject },
      // @ts-expect-error a provider login is not an internal user id
      { userId: providerLogin },
    ];
    const rows: readonly AuditEventRecord[] = [
      // @ts-expect-error a provider subject is not an audit target
      { event: "x", serverTs: 1, actorType: "user", targetUserId: providerSubject },
    ];
    expect(actors).toHaveLength(3);
    expect(rows).toHaveLength(1);
  });

  it("refuses a provider identity in a membership-log entry", () => {
    const actors: readonly ChainActor[] = [
      { userId: internalUserId, keyFingerprintHex: FP },
      // @ts-expect-error a provider subject cannot sign as a chain actor
      { userId: providerSubject, keyFingerprintHex: FP },
    ];
    const targets: readonly Pick<AddMemberPayload, "targetUserId">[] = [
      // @ts-expect-error a GitHub login cannot be an add_member target
      { targetUserId: providerLogin },
    ];
    expect(actors).toHaveLength(2);
    expect(targets).toHaveLength(1);
  });

  it("refuses a provider identity in the session / token plumbing", () => {
    const principals: readonly AuthenticatedPrincipal[] = [
      // @ts-expect-error a request principal is an internal user, never a provider subject
      { kind: "session", userId: providerSubject, authMethod: "github_oauth" },
    ];
    const issue = (sessions: SessionServiceShape, tokens: TokenServiceShape) => [
      sessions.issueSession(internalUserId, "github_oauth"),
      // @ts-expect-error a session is issued for an internal user, never for a provider subject
      sessions.issueSession(providerSubject, "github_oauth"),
      // @ts-expect-error a token is issued for an internal user, never for a provider login
      tokens.issueToken(providerLogin, "ci", [], 1),
    ];
    expect(principals).toHaveLength(1);
    expect(issue).toBeTypeOf("function");
    expectTypeOf<Parameters<SessionServiceShape["issueSession"]>[0]>().toEqualTypeOf<UserId>();
  });

  it("keeps the two identities apart in both directions", () => {
    // @ts-expect-error an internal user id is not a provider lookup key
    const subject: ProviderUserId = internalUserId;
    expect(subject).toBe(internalUserId);
    expectTypeOf<ProviderUserId>().not.toExtend<UserId>();
    expectTypeOf<UserId>().not.toExtend<ProviderUserId>();
  });
});

describe("minting at the wire", () => {
  it("decodes a user-id field into a UserId without changing the value", () => {
    const decoded = Schema.decodeUnknownSync(UserIdSchema)("user-owner-0001");
    expectTypeOf(decoded).toEqualTypeOf<UserId>();
    expect(decoded).toBe("user-owner-0001");
    expect(Schema.encodeSync(UserIdSchema)(decoded)).toBe("user-owner-0001");
  });

  it("decodes a provider subject into a ProviderUserId, never into a UserId", () => {
    const decoded = Schema.decodeUnknownSync(ProviderUserIdSchema)("583231");
    expectTypeOf(decoded).toEqualTypeOf<ProviderUserId>();
    expect(decoded).toBe("583231");
  });

  it("still refuses a non-string on the wire", () => {
    expect(() => Schema.decodeUnknownSync(UserIdSchema)(583231)).toThrow();
  });
});
