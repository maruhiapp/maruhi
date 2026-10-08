// The per-event audit payloads (audit-payloads.ts — AUDIT_SPEC §3). The
// type-level half is enforced by `tsc --noEmit` (the typecheck step of the
// quality gate): each `@ts-expect-error` line below must stay a compile
// error, so a change that lets a key AUDIT_SPEC does not list — a provider
// identity above all (§1-2) — into an audit payload fails the gate (an unused
// `@ts-expect-error` is itself an error). The runtime half pins the stores'
// check, which holds the same shape against a value that escaped the types
// (a widened object, an assertion).

import type { ChainEntry, ChainOperation } from "@maruhi/crypto";
import {
  testKeyFingerprintHex,
  testUserId,
  toTypedEntry,
  vectorEntries,
} from "@maruhi/crypto/test-support";
import { describe, expect, it } from "vitest";

import {
  assertProjectAuditPayload,
  assertUserOrgAuditPayload,
  type AuditText,
  type ProjectAuditEventPayload,
  type UserOrgAuditEventPayload,
} from "../src/audit-payloads.ts";
import {
  type AuditEventRecord,
  type AuditEventRecordOf,
  chainMirrorEvents,
  indexProposals,
} from "../src/audit.ts";
import { decodeKeyFingerprintHex, decodeProviderUserId, decodeUserId } from "../src/identity.ts";
import { decodeEnvironmentId } from "../src/project.ts";

const providerSubject = decodeProviderUserId("583231");
const providerLogin = "octocat";
const userId = decodeUserId("01J9Z3K4M5N6P7Q8R9S0T1V2W3");
const fp = decodeKeyFingerprintHex("ab".repeat(16));
const columns = { serverTs: 1, actorType: "user", actorUserId: userId } as const;

describe("project event payloads (AUDIT_SPEC §3.3–§3.5) — compile time", () => {
  it("holds only the attributes the spec lists for the event", () => {
    const rows: AuditEventRecord[] = [
      { ...columns, event: "env.created", payload: { name: "production" } },
      // @ts-expect-error a provider login is not an attribute of env.created
      { ...columns, event: "env.created", payload: { name: "production", login: providerLogin } },
      {
        ...columns,
        event: "var.read",
        // @ts-expect-error a provider subject is not an attribute of var.read
        payload: { variables: [], providerUserId: providerSubject },
      },
      // @ts-expect-error var.read's payload is the enumeration, not a name snapshot
      { ...columns, event: "var.read", payload: { name: "API_KEY" } },
      // @ts-expect-error var.read always writes its enumeration
      { ...columns, event: "var.read" },
      // @ts-expect-error var.deleted writes no payload
      { ...columns, event: "var.deleted", payload: { name: "API_KEY" } },
      // @ts-expect-error an event AUDIT_SPEC does not define cannot be written
      { ...columns, event: "auth.login_succeeded", payload: { sessionId: "x" } },
      // @ts-expect-error an unknown event cannot be written
      { ...columns, event: "x" },
    ];
    expect(rows).toHaveLength(8);
  });

  it("refuses a provider subject in a free-text attribute", () => {
    const plain: AuditText = "production";
    // @ts-expect-error a provider subject is never audit text (§1-2)
    const subject: AuditText = providerSubject;
    // The exclusion's limit (AuditText's doc): a union with a plain string
    // widens to string, which is audit text — the runtime check and the
    // per-event key set are what close a payload, not this exclusion
    const widened: AuditText = [providerSubject, "x"][0] ?? "x";
    const text = [plain, subject, widened];
    const rows: AuditEventRecord[] = [
      // @ts-expect-error not as a name snapshot
      { ...columns, event: "var.renamed", payload: { name: providerSubject } },
      {
        ...columns,
        event: "rotation.proposed",
        actorType: "system",
        payload: {
          proposalId: "p",
          // @ts-expect-error not as an identifier list's element
          variableIds: [providerSubject],
          claimsDigest: "d",
          grantChainSeq: 1,
          connector: "exec",
        },
      },
    ];
    expect([text, rows]).toHaveLength(2);
  });

  it("refuses a plain string where the payload names a key fingerprint", () => {
    const rows: AuditEventRecord[] = [
      {
        ...columns,
        event: "chain.device_added",
        payload: {
          // @ts-expect-error the added device is named by a minted fingerprint
          deviceKeyFingerprint: "cd".repeat(16),
          roleCap: "member",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
      {
        ...columns,
        event: "chain.device_revoked",
        // @ts-expect-error the revoked devices are named by minted fingerprints
        payload: { deviceKeyFingerprints: [providerLogin] },
      },
      {
        ...columns,
        event: "rotation.recommended",
        actorType: "system",
        payload: {
          basis: "read",
          triggerChainSeq: 3,
          trigger: "revoke_device",
          // @ts-expect-error the revoked fingerprints are minted ones
          revokedDeviceKeyFingerprints: ["cd".repeat(16)],
        },
      },
      { ...columns, event: "chain.device_revoked", payload: { deviceKeyFingerprints: [fp] } },
    ];
    expect(rows).toHaveLength(4);
  });

  it("closes every attribute that carries server vocabulary", () => {
    const rows: AuditEventRecord[] = [
      {
        ...columns,
        event: "server.lease_denied",
        actorType: "system",
        payload: { reason: "token-replayed", claimsDigest: "d" },
      },
      {
        ...columns,
        event: "server.lease_denied",
        actorType: "system",
        // @ts-expect-error a lease denial reason is a closed code
        payload: { reason: providerLogin },
      },
      {
        ...columns,
        event: "chain.proposed",
        // @ts-expect-error the inner op is a proposable chain op
        payload: { innerOp: "approve", expiresAtMs: 1 },
      },
      {
        ...columns,
        event: "rotation.proposed",
        actorType: "system",
        payload: {
          proposalId: "p",
          variableIds: [],
          claimsDigest: "d",
          grantChainSeq: 1,
          // @ts-expect-error the connector is the rotation config's vocabulary
          connector: "octocat",
        },
      },
    ];
    expect(rows).toHaveLength(4);
    expect(() =>
      assertProjectAuditPayload({ event: "server.lease_denied", payload: { reason: "because" } }),
    ).toThrow();
    expect(() =>
      assertUserOrgAuditPayload({
        event: "auth.login_failed",
        payload: { authMethod: "password", reason: "state-mismatch" },
      }),
    ).toThrow();
  });

  it("narrows by the event name", () => {
    const row = {} as AuditEventRecord;
    if (row.event === "rotation.recommended") {
      const basis: "read" | "readable" = row.payload.basis;
      expect(basis).toBeUndefined();
    }
    const recommended = {} as AuditEventRecordOf<"rotation.recommended">;
    // @ts-expect-error a rotation.recommended row carries no name snapshot
    expect(recommended.payload?.name).toBeUndefined();
    const payload: ProjectAuditEventPayload = { event: "var.version_pushed" };
    expect(payload.event).toBe("var.version_pushed");
  });
});

describe("user / org event payloads (AUDIT_SPEC §3.1–§3.2) — compile time", () => {
  it("never carries the provider's identity, only the kind names §1-2 allows", () => {
    const events: UserOrgAuditEventPayload[] = [
      { event: "auth.identity_linked", payload: { provider: "github" } },
      {
        event: "auth.identity_linked",
        // @ts-expect-error the provider subject is never recorded (§3.1)
        payload: { provider: "github", providerUserId: providerSubject },
      },
      // @ts-expect-error nor the login
      { event: "auth.identity_linked", payload: { provider: "github", login: providerLogin } },
      // @ts-expect-error the provider is a kind name from the closed set
      { event: "auth.identity_linked", payload: { provider: providerLogin } },
      {
        event: "auth.login_failed",
        payload: { authMethod: "github_oauth", reason: "state-mismatch" },
      },
      {
        event: "auth.login_failed",
        payload: {
          authMethod: "github_oauth",
          reason: "state-mismatch",
          // @ts-expect-error a failed login never records the presented external id (§3.1)
          githubId: providerSubject,
        },
      },
      {
        event: "auth.signup_denied",
        // @ts-expect-error a denied signup's reason is one of the three kinds
        payload: { authMethod: "github_oauth", reason: providerLogin },
      },
      {
        event: "auth.login_failed",
        // @ts-expect-error a failure reason is a closed code, never free text
        payload: { authMethod: "cli_handoff", reason: providerLogin },
      },
      {
        event: "auth.login_failed",
        // @ts-expect-error the auth method is a kind name from the closed set
        payload: { authMethod: providerLogin, reason: "state-mismatch" },
      },
      { event: "org.created", payload: { personal: true } },
      // @ts-expect-error a personal org's name derives from the login, so it is never copied (§3.2)
      { event: "org.created", payload: { personal: true, name: providerLogin } },
      {
        event: "invite.accepted",
        // @ts-expect-error the accepting key is named by a minted fingerprint
        payload: { inviteId: "i", inviteeKeyFingerprintHex: "cd".repeat(16) },
      },
      {
        event: "invite.accepted",
        // @ts-expect-error the backing source's login is never written (§3.2 — IV)
        payload: { inviteId: "i", inviteeKeyFingerprintHex: fp, backingLogin: providerLogin },
      },
      {
        event: "auth.key_handoff_approved",
        payload: {
          requestId: "r",
          source: "g",
          shareIndex: 1,
          // @ts-expect-error the approver's device is named by a minted fingerprint
          approverKeyFingerprintHex: "cd".repeat(16),
        },
      },
      // @ts-expect-error a project event is not a user / org event
      { event: "var.read", payload: { variables: [] } },
    ];
    expect(events).toHaveLength(15);
  });
});

describe("the stores' payload check (runtime)", () => {
  it("accepts every payload the spec lists", () => {
    expect(() =>
      assertProjectAuditPayload({ event: "env.created", payload: { name: "production" } }),
    ).not.toThrow();
    expect(() => assertProjectAuditPayload({ event: "var.deleted" })).not.toThrow();
    expect(() =>
      assertUserOrgAuditPayload({
        event: "auth.token_created",
        payload: { tokenId: "t", name: "ci", scopes: [{ project: "*", permission: "read" }] },
      }),
    ).not.toThrow();
  });

  it("rejects a key the spec does not list even when it escaped the types (a widened object)", () => {
    // Structural typing lets a wider object through: this compiles
    const snapshot = { name: "production", login: providerLogin };
    const row: AuditEventRecord = { ...columns, event: "env.created", payload: snapshot };
    expect(() => assertProjectAuditPayload(row)).toThrow(
      "audit invariant violation: the env.created payload is not the AUDIT_SPEC §3 shape",
    );
    const linked = { provider: "github" as const, providerUserId: "583231" };
    const event: UserOrgAuditEventPayload = { event: "auth.identity_linked", payload: linked };
    expect(() => assertUserOrgAuditPayload(event)).toThrow("auth.identity_linked");
  });

  it("names the event and never the offending value", () => {
    try {
      assertProjectAuditPayload({
        event: "env.renamed",
        payload: { name: 1, login: providerLogin },
      });
      expect.unreachable();
    } catch (error) {
      expect(String(error)).toContain("env.renamed");
      expect(String(error)).not.toContain(providerLogin);
    }
  });

  it("rejects a missing payload, a payload on a payload-less event, and a malformed fingerprint", () => {
    expect(() => assertProjectAuditPayload({ event: "var.read" })).toThrow();
    expect(() => assertProjectAuditPayload({ event: "var.deleted", payload: {} })).toThrow();
    expect(() =>
      assertProjectAuditPayload({
        event: "chain.device_revoked",
        payload: { deviceKeyFingerprints: ["AB".repeat(16)] },
      }),
    ).toThrow();
    expect(() =>
      assertUserOrgAuditPayload({ event: "auth.recovery_blob_fetched", payload: { login: "x" } }),
    ).toThrow();
  });

  it("rejects an event outside the store's map", () => {
    expect(() => assertProjectAuditPayload({ event: "auth.login_succeeded" })).toThrow(
      "auth.login_succeeded is not a project event",
    );
    expect(() => assertUserOrgAuditPayload({ event: "var.read" })).toThrow(
      "var.read is not a user / org event",
    );
    expect(() => assertProjectAuditPayload({ event: "toString" })).toThrow("not a project event");
  });
});

describe("the chain mirror writes only spec'd payloads (§3.4)", () => {
  const actor = { userId: testUserId("user-owner-0001"), keyFingerprintHex: fp };
  const extra = (seq: number, operation: ChainOperation): ChainEntry => ({
    ...operation,
    suite: "maruhi/v1",
    seq,
    prevHashHex: "00".repeat(32),
    actor,
    timestampMs: 1_000 + seq,
    signatureHex: "00".repeat(64),
  });

  it("maps every vector entry, applied rows included, to rows the store accepts", () => {
    const entries = vectorEntries.map(toTypedEntry);
    const hashes = new Map(vectorEntries.map((entry) => [entry.seq, entry.entry_hash_hex]));
    // Nothing pending: the approved proposal counts as completed, so the applied row is mapped too
    const index = indexProposals(entries, (seq) => hashes.get(seq), new Set());
    const rows = [
      ...entries.flatMap((entry) => chainMirrorEvents(entry, 1, index)),
      ...[
        extra(100, {
          op: "add_device",
          payload: {
            encPubHex: "11".repeat(32),
            sigPubHex: "22".repeat(32),
            roleCap: "member",
            scopeKind: "listed",
            scopeEnvironmentIds: [decodeEnvironmentId("env-1")],
          },
        }),
        extra(101, {
          op: "revoke_device",
          payload: {
            targetUserId: actor.userId,
            deviceFingerprintsHex: [testKeyFingerprintHex("cd".repeat(16))],
          },
        }),
        extra(102, {
          op: "delete_environment",
          payload: { environmentId: decodeEnvironmentId("env-1") },
        }),
        extra(103, {
          op: "checkpoint",
          payload: { environments: [], auditHeadHashHex: "ef".repeat(32) },
        }),
      ].flatMap((entry) =>
        chainMirrorEvents(entry, 1, index, { addedDeviceKeyFingerprintHex: fp }),
      ),
    ];
    const mapped = new Set(rows.map((row) => row.event));
    expect(mapped).toContain("chain.approved");
    expect(rows.some((row) => row.payload !== undefined && "viaProposalSeq" in row.payload)).toBe(
      true,
    );
    for (const row of rows) {
      expect(() => assertProjectAuditPayload(row), row.event).not.toThrow();
    }
  });
});
