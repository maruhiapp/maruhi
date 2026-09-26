// ES K3 — the rotation-needed detection's per-environment access
// windows and the change_role variants (AUDIT_SPEC §3.3 / §3.4 /
// §4.1 / §4.2 Q1 = CRYPTO_SPEC §7. Design record
// docs/notes/es-design.md §9 K3-E).
//
// Rules pinned:
//   - candidate set = per-environment access windows (§4.1 step 2):
//     remove_member's candidates are only the variables of the
//     environments the target held in scope (environments outside
//     scope are not candidates)
//   - change_role variants: narrowing = the removed environments,
//     demotion = every environment of the target's scope, promotion /
//     widening = no detection. trigger = change_role, origin = that
//     change_role's seq
//   - a removal's candidates are every window within the membership
//     interval (including past windows a narrowing closed — multiple
//     rows for the same pair)
//   - window reconstruction works from the chain mirror's payload
//     alone (scopeKind / scopeEnvironmentIds / newRole — §3.4)
//     (§4.2 Q1 — including role_changed)
//   - every variant's rotation.recommended carries trigger; pre-K3
//     rows are backfilled from target

import { describe, expect, it } from "vitest";

import type { AuditRotationRead, SeqRange } from "../src/audit-store.ts";
import {
  deriveEffectiveFlags,
  detectMemberRemoval,
  detectRoleChange,
  detectServerRevocation,
} from "../src/rotation-detect.ts";
import {
  addMemberOperation,
  changeRoleOperation,
  createVariableStatement,
  encryptValue,
  metaSignedBytesHashOf,
} from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  manifestForVariableOp,
  OWNER,
  projectId,
  READER,
  requestJson,
  seedMemberToken,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token } from "./support/data-scenario.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

const DEV = "user-devmember-0010";
const OTHER = "env-other-0002";
const VAR_ENV = "var-env-secret";
const VAR_OTHER = "var-other-secret";

interface WireRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly triggerChainSeq: number;
  readonly trigger?: string;
}

async function readFlags(asUserId: string = READER): Promise<readonly WireRotationFlag[]> {
  const response = await requestJson("GET", "/rotation/flags", token(asUserId));
  expect(response.status).toBe(200);
  return ((await response.json()) as { flags: readonly WireRotationFlag[] }).flags;
}

async function pullAs(userId: string, environmentId: string): Promise<void> {
  const response = await requestJson("GET", `/environments/${environmentId}/pull`, token(userId));
  expect(response.status).toBe(200);
}

/** OWNER creates a variable in any environment (value v1 + statement + manifest). */
async function createVariableAsOwner(input: {
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly variableId: string;
  readonly name: string;
}): Promise<void> {
  const value = await encryptValue(
    input.dek,
    {
      projectId,
      environmentId: input.environmentId,
      epoch: 1,
      variableId: input.variableId,
      version: 1,
    },
    `${input.name}-plaintext`,
    { writerUserId: OWNER, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: OWNER,
    projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: input.environmentId,
    issuerUserId: OWNER,
    entry: {
      variableId: input.variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
    },
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.environmentId}/variables`,
    token(OWNER),
    { statement, value, manifest },
  );
  expect(response.status).toBe(200);
  fixture.manifests.set(input.environmentId, state);
}

/**
 * Create 2 environments + 1 variable each, and add DEV as member,
 * listed{scope}.
 * The return value is the add_member's seq on the chain.
 */
async function setupTwoEnvironments(scope: readonly string[]): Promise<number> {
  const envDek = await createEnvironmentOk(fixture, ENV, "App");
  const otherDek = await createEnvironmentOk(fixture, OTHER, "Other");
  await createVariableAsOwner({ environmentId: ENV, dek: envDek, variableId: VAR_ENV, name: "E" });
  await createVariableAsOwner({
    environmentId: OTHER,
    dek: otherDek,
    variableId: VAR_OTHER,
    name: "O",
  });
  await seedMemberToken(fixture, DEV, 9010);
  await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", scope));
  return fixture.head.seq;
}

async function changeRole(
  role: "owner" | "admin" | "member" | "reader",
  scope?: readonly string[],
): Promise<number> {
  await appendOperation(fixture, OWNER, changeRoleOperation(DEV, role, scope));
  return fixture.head.seq;
}

async function removeDev(): Promise<number> {
  await appendOperation(fixture, OWNER, { op: "remove_member", payload: { targetUserId: DEV } });
  return fixture.head.seq;
}

const byPair = (flags: readonly WireRotationFlag[]) =>
  new Map(flags.map((flag) => [`${flag.environmentId}/${flag.variableId}`, flag]));

describe("rotation-needed detection: per-environment access windows (§4.1 step 2 — remove_member)", () => {
  it("removing a listed{ENV} member candidates only ENV's variables — environments outside scope are not candidates", async () => {
    await setupTwoEnvironments([ENV]);
    await pullAs(DEV, ENV);
    const removalSeq = await removeDev();
    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({
      environmentId: ENV,
      variableId: VAR_ENV,
      basis: "read",
      targetUserId: DEV,
      triggerChainSeq: removalSeq,
      trigger: "remove_member",
    });
  });

  it("a removal's candidates include past windows closed by a narrowing (the narrowing's row and the removal's row sit on the same pair)", async () => {
    await setupTwoEnvironments([ENV, OTHER]);
    const narrowSeq = await changeRole("member", [ENV]);
    const removalSeq = await removeDev();
    const flags = await readFlags();
    const other = flags.filter((flag) => flag.variableId === VAR_OTHER);
    expect(other.map((flag) => [flag.trigger, flag.triggerChainSeq])).toEqual(
      expect.arrayContaining([
        ["change_role", narrowSeq],
        ["remove_member", removalSeq],
      ]),
    );
    expect(other).toHaveLength(2);
    expect(flags.filter((flag) => flag.variableId === VAR_ENV)).toHaveLength(1);
  });
});

describe("rotation-needed detection: the change_role variants (§4.1 — demotion / narrowing)", () => {
  it("narrowing candidates only the removed environments, with trigger = change_role and origin = that change_role's seq, distinguishing read / readable", async () => {
    await setupTwoEnvironments([ENV, OTHER]);
    await pullAs(DEV, OTHER);
    const narrowSeq = await changeRole("member", [ENV]);
    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({
      environmentId: OTHER,
      variableId: VAR_OTHER,
      basis: "read",
      targetUserId: DEV,
      triggerChainSeq: narrowSeq,
      trigger: "change_role",
    });
    // Recording details (§3.3): actor = system, trigger in the payload, seq right after the mirror row
    const events = await readAuditEvents(projectId);
    const recommended = events.filter((event) => event["event"] === "rotation.recommended");
    expect(recommended).toHaveLength(1);
    const payload = JSON.parse(String(recommended[0]?.["payload"])) as Record<string, unknown>;
    expect(payload).toMatchObject({
      basis: "read",
      triggerChainSeq: narrowSeq,
      trigger: "change_role",
    });
    expect(recommended[0]?.["actor_type"]).toBe("system");
    const mirror = events.find((event) => event["event"] === "chain.role_changed");
    expect(Number(recommended[0]?.["seq"])).toBe(Number(mirror?.["seq"]) + 1);
  });

  it("demotion (member → reader) candidates every environment of the target's scope (detected even while the member keeps receiving DEKs as a reader)", async () => {
    await setupTwoEnvironments([ENV, OTHER]);
    const demoteSeq = await changeRole("reader", [ENV, OTHER]);
    const flags = byPair(await readFlags());
    expect(flags.size).toBe(2);
    for (const key of [`${ENV}/${VAR_ENV}`, `${OTHER}/${VAR_OTHER}`]) {
      expect(flags.get(key)).toMatchObject({
        basis: "readable",
        targetUserId: DEV,
        triggerChainSeq: demoteSeq,
        trigger: "change_role",
      });
    }
    // The demoted member stays enrolled: a later removal makes the same environments candidates again (the window did not close)
    await removeDev();
    expect((await readFlags()).filter((flag) => flag.trigger === "remove_member")).toHaveLength(2);
  });

  it("promotion, widening, and scope-unchanged role changes are not detected; a narrowing after widening is detected on the window from the widening's seq", async () => {
    await setupTwoEnvironments([ENV]);
    const widenSeq = await changeRole("admin", [ENV, OTHER]);
    expect(await readFlags()).toHaveLength(0);
    await changeRole("member", [ENV, OTHER]);
    expect(await readFlags()).toHaveLength(0);
    const narrowSeq = await changeRole("member", [ENV]);
    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({
      environmentId: OTHER,
      variableId: VAR_OTHER,
      basis: "readable",
      triggerChainSeq: narrowSeq,
      trigger: "change_role",
    });
    expect(narrowSeq).toBeGreaterThan(widenSeq);
  });

  it("a simultaneous demotion and narrowing still yields 1 row per (variable × environment) (§3.3's granularity)", async () => {
    await setupTwoEnvironments([ENV, OTHER]);
    await changeRole("reader", [ENV]);
    const flags = await readFlags();
    expect(flags).toHaveLength(2);
    expect(new Set(flags.map((flag) => `${flag.environmentId}/${flag.variableId}`)).size).toBe(2);
  });
});

describe("the window-reconstruction material (AUDIT_SPEC §3.4's mirror payload / §4.2 Q1)", () => {
  it("the chain.member_added / chain.role_changed mirror rows copy the scope (detection reads only this payload)", async () => {
    await setupTwoEnvironments([ENV, OTHER]);
    await changeRole("member", [ENV]);
    const rows = await queryProjectDo(
      projectId,
      "SELECT event, payload FROM audit_events WHERE target_user_id = ? AND event IN ('chain.member_added', 'chain.role_changed') ORDER BY seq",
      DEV,
    );
    expect(rows.map((row) => row["event"])).toEqual(["chain.member_added", "chain.role_changed"]);
    expect(JSON.parse(String(rows[0]?.["payload"]))).toEqual({
      role: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV, OTHER],
    });
    expect(JSON.parse(String(rows[1]?.["payload"]))).toEqual({
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV],
    });
  });
});

// ---------------------------------------------------------------------------
// Pure-function unit tests (no DO): the window derivation's fail-safes and trigger backfill
// ---------------------------------------------------------------------------

function fakeRead(input: {
  readonly membership: AuditRotationRead["membershipEventsFor"] extends (id: string) => infer R
    ? R
    : never;
  readonly lifecycles: ReturnType<AuditRotationRead["variableLifecycles"]>;
  readonly reads?: ReturnType<AuditRotationRead["variableReadsBy"]>;
}): AuditRotationRead {
  return {
    membershipEventsFor: () => input.membership,
    deviceEventsFor: () => [],
    serverGrantEventsFor: () => [],
    variableLifecycles: () => input.lifecycles,
    variableReadsBy: () => input.reads ?? [],
    serverAccessEventsBy: () => [],
    rotationFlagEvents: () => [],
  };
}

/** For the revoke_server variant's pure-function tests: a read surface holding only grant intervals and lease-issuance rows. */
const grantRead = (
  events: readonly {
    seq: number;
    event: string;
    scopeEnvironmentIds: readonly string[] | null;
  }[],
  access: readonly { seq: number; environmentId: string }[],
): AuditRotationRead => ({
  membershipEventsFor: () => [],
  deviceEventsFor: () => [],
  serverGrantEventsFor: () => events,
  variableLifecycles: () => [
    { seq: 1, event: "var.created", environmentId: "env-a", variableId: "v" },
    { seq: 1, event: "var.created", environmentId: "env-b", variableId: "w" },
  ],
  variableReadsBy: () => [],
  serverAccessEventsBy: () =>
    access.map((row) => ({ ...row, event: "server.lease_issued", variableId: null })),
  rotationFlagEvents: () => [],
});

describe("the window derivation's fail-safes and trigger backfill (pure functions)", () => {
  it("a member_added row whose scope cannot be read opens a window as `all` (detection errs on the side of not missing — K3-F)", () => {
    const events = detectMemberRemoval({
      read: fakeRead({
        membership: [
          { seq: 2, event: "chain.member_added", role: "member", scope: null },
          { seq: 10, event: "chain.member_removed", role: null, scope: null },
        ],
        lifecycles: [
          { seq: 5, event: "var.created", environmentId: "env-a", variableId: "v" },
          { seq: 6, event: "var.created", environmentId: "env-b", variableId: "w" },
        ],
      }),
      targetUserId: "u",
      triggerChainSeq: 9,
      nowMs: 1,
    });
    expect(events.map((event) => event.environmentId).toSorted()).toEqual(["env-a", "env-b"]);
    for (const event of events) {
      expect(event.payload).toMatchObject({ trigger: "remove_member", triggerChainSeq: 9 });
    }
  });

  it("a listed window opens/closes at scope transitions; reads outside the window do not count as read", () => {
    const events = detectRoleChange({
      read: fakeRead({
        membership: [
          {
            seq: 2,
            event: "chain.member_added",
            role: "member",
            scope: { kind: "listed", environmentIds: ["env-a"] },
          },
          {
            seq: 8,
            event: "chain.role_changed",
            role: "member",
            scope: { kind: "listed", environmentIds: ["env-a", "env-b"] },
          },
          {
            seq: 12,
            event: "chain.role_changed",
            role: "member",
            scope: { kind: "listed", environmentIds: ["env-a"] },
          },
        ],
        lifecycles: [
          { seq: 3, event: "var.created", environmentId: "env-b", variableId: "w" },
          { seq: 4, event: "var.created", environmentId: "env-a", variableId: "v" },
        ],
        // the seq 5 read is outside env-b's window (8-12) = assumed a pre-K3 / malformed row
        reads: [
          { seq: 5, environmentId: "env-b", variableId: "w" },
          { seq: 9, environmentId: "env-b", variableId: "w" },
        ],
      }),
      targetUserId: "u",
      triggerChainSeq: 11,
      nowMs: 1,
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      environmentId: "env-b",
      variableId: "w",
      payload: { basis: "read", trigger: "change_role", triggerChainSeq: 11 },
    });
  });

  it("windows across a re-addition are separate intervals: reads during the absence do not count, and both intervals' candidates are included (§4.1 step 1)", () => {
    const listedA = { kind: "listed" as const, environmentIds: ["env-a"] };
    const events = detectMemberRemoval({
      read: fakeRead({
        membership: [
          { seq: 2, event: "chain.member_added", role: "member", scope: listedA },
          { seq: 4, event: "chain.member_removed", role: null, scope: null },
          { seq: 6, event: "chain.member_added", role: "member", scope: listedA },
          { seq: 10, event: "chain.member_removed", role: null, scope: null },
        ],
        lifecycles: [
          { seq: 1, event: "var.created", environmentId: "env-a", variableId: "v" },
          // a variable that existed only during the absence (overlaps no window)
          { seq: 5, event: "var.created", environmentId: "env-a", variableId: "gap" },
          { seq: 5, event: "var.deleted", environmentId: "env-a", variableId: "gap" },
        ],
        reads: [{ seq: 5, environmentId: "env-a", variableId: "v" }],
      }),
      targetUserId: "u",
      triggerChainSeq: 9,
      nowMs: 1,
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ variableId: "v", payload: { basis: "readable" } });
  });

  it("Q3 receives the envelope of the chosen windows (the open interval min-start to max-end), and the result equals the unfiltered case", () => {
    const listedA = { kind: "listed" as const, environmentIds: ["env-a"] };
    const reads = [
      { seq: 1, environmentId: "env-a", variableId: "v" },
      { seq: 3, environmentId: "env-a", variableId: "v" },
      { seq: 5, environmentId: "env-a", variableId: "late" },
      { seq: 12, environmentId: "env-a", variableId: "late" },
    ];
    const ranges: (SeqRange | undefined)[] = [];
    const run = (honourRange: boolean) =>
      detectMemberRemoval({
        read: {
          ...fakeRead({
            membership: [
              { seq: 2, event: "chain.member_added", role: "member", scope: listedA },
              { seq: 4, event: "chain.member_removed", role: null, scope: null },
              { seq: 6, event: "chain.member_added", role: "member", scope: listedA },
              { seq: 10, event: "chain.member_removed", role: null, scope: null },
            ],
            lifecycles: [
              { seq: 1, event: "var.created", environmentId: "env-a", variableId: "v" },
              { seq: 5, event: "var.created", environmentId: "env-a", variableId: "late" },
            ],
          }),
          variableReadsBy: (_actor, range) => {
            ranges.push(range);
            return honourRange && range !== undefined
              ? reads.filter((row) => range.afterSeq < row.seq && row.seq < range.beforeSeq)
              : reads;
          },
        },
        targetUserId: "u",
        triggerChainSeq: 9,
        nowMs: 1,
      });
    const bounded = run(true);
    const unbounded = run(false);
    // windows = (2, 4) and (6, 10) — the envelope is (2, 10)
    expect(ranges[0]).toEqual({ afterSeq: 2, beforeSeq: 10 });
    expect(bounded).toEqual(unbounded);
    // v was read at seq 3 inside window (2, 4); late only outside windows (5 = during the absence, 12 = after removal)
    expect(
      bounded.map((event) => [event.variableId, (event.payload as { basis: string }).basis]),
    ).toEqual([
      ["v", "read"],
      ["late", "readable"],
    ]);
  });

  it("a role_changed that appears outside any membership interval opens a window as open (on broken input still err on the side of not missing)", () => {
    const events = detectMemberRemoval({
      read: fakeRead({
        membership: [
          {
            seq: 3,
            event: "chain.role_changed",
            role: "member",
            scope: { kind: "listed", environmentIds: ["env-a"] },
          },
          { seq: 8, event: "chain.member_removed", role: null, scope: null },
        ],
        lifecycles: [{ seq: 1, event: "var.created", environmentId: "env-a", variableId: "v" }],
      }),
      targetUserId: "u",
      triggerChainSeq: 7,
      nowMs: 1,
    });
    expect(events.map((event) => event.variableId)).toEqual(["v"]);
  });

  it("a role_changed whose role cannot be read is treated as a demotion (err on the side of not missing)", () => {
    const listedA = { kind: "listed" as const, environmentIds: ["env-a"] };
    const events = detectRoleChange({
      read: fakeRead({
        membership: [
          { seq: 2, event: "chain.member_added", role: null, scope: listedA },
          { seq: 6, event: "chain.role_changed", role: null, scope: listedA },
        ],
        lifecycles: [{ seq: 1, event: "var.created", environmentId: "env-a", variableId: "v" }],
      }),
      targetUserId: "u",
      triggerChainSeq: 5,
      nowMs: 1,
    });
    expect(events.map((event) => event.variableId)).toEqual(["v"]);
  });

  it("the revoke_server variant: revoke → re-grant → revoke are separate windows; a narrowing re-grant does not close a window (union)", () => {
    // leases during the revocation (seq 5) do not count → readable
    const regranted = detectServerRevocation({
      read: grantRead(
        [
          { seq: 2, event: "chain.server_granted", scopeEnvironmentIds: ["env-a"] },
          { seq: 4, event: "chain.server_revoked", scopeEnvironmentIds: [] },
          { seq: 6, event: "chain.server_granted", scopeEnvironmentIds: ["env-a"] },
          { seq: 10, event: "chain.server_revoked", scopeEnvironmentIds: [] },
        ],
        [{ seq: 5, environmentId: "env-a" }],
      ),
      serverKeyFingerprintHex: "ab".repeat(16),
      triggerChainSeq: 9,
      nowMs: 1,
    });
    expect(regranted.map((event) => [event.variableId, event.payload?.["basis"]])).toEqual([
      ["v", "readable"],
    ]);
    // a narrowing re-grant (the consensus rules would reject it, but detection is fail-safe): env-b's window stays open until revocation
    const narrowed = detectServerRevocation({
      read: grantRead(
        [
          { seq: 2, event: "chain.server_granted", scopeEnvironmentIds: ["env-a", "env-b"] },
          { seq: 4, event: "chain.server_granted", scopeEnvironmentIds: ["env-a"] },
          { seq: 8, event: "chain.server_revoked", scopeEnvironmentIds: [] },
        ],
        [{ seq: 6, environmentId: "env-b" }],
      ),
      serverKeyFingerprintHex: "ab".repeat(16),
      triggerChainSeq: 7,
      nowMs: 1,
    });
    expect(
      narrowed.map((event) => [event.variableId, event.payload?.["basis"]]).toSorted(),
    ).toEqual([
      ["v", "readable"],
      ["w", "read"],
    ]);
  });

  it("an interval containing a grant row whose scope cannot be read opens windows for all environments (the grant axis also errs on the side of not missing)", () => {
    const events = detectServerRevocation({
      read: grantRead(
        [
          { seq: 2, event: "chain.server_granted", scopeEnvironmentIds: null },
          { seq: 8, event: "chain.server_revoked", scopeEnvironmentIds: [] },
        ],
        [],
      ),
      serverKeyFingerprintHex: "ab".repeat(16),
      triggerChainSeq: 7,
      nowMs: 1,
    });
    expect(events.map((event) => event.variableId).toSorted()).toEqual(["v", "w"]);
  });

  it("a change_role whose trigger row's scope cannot be read cannot identify the removed part, so all pre-trigger windows become candidates", () => {
    const events = detectRoleChange({
      read: fakeRead({
        membership: [
          {
            seq: 2,
            event: "chain.member_added",
            role: "member",
            scope: { kind: "listed", environmentIds: ["env-a"] },
          },
          { seq: 6, event: "chain.role_changed", role: "member", scope: null },
        ],
        lifecycles: [{ seq: 1, event: "var.created", environmentId: "env-a", variableId: "v" }],
      }),
      targetUserId: "u",
      triggerChainSeq: 5,
      nowMs: 1,
    });
    expect(events.map((event) => event.variableId)).toEqual(["v"]);
  });

  it("pre-K3 rotation.recommended rows (no trigger) are backfilled from the target column", () => {
    const base = {
      serverTs: 1,
      event: "rotation.recommended",
      environmentId: "env-a",
      variableId: "v",
    };
    const flags = deriveEffectiveFlags([
      {
        ...base,
        seq: 1,
        targetUserId: "u",
        targetKeyFingerprintHex: null,
        payload: { basis: "read", triggerChainSeq: 3 },
      },
      {
        ...base,
        seq: 2,
        variableId: "w",
        targetUserId: null,
        targetKeyFingerprintHex: "ab".repeat(16),
        payload: { basis: "readable", triggerChainSeq: 4 },
      },
      {
        ...base,
        seq: 3,
        variableId: "x",
        targetUserId: "u",
        targetKeyFingerprintHex: null,
        payload: { basis: "readable", triggerChainSeq: 5, trigger: "change_role" },
      },
    ]);
    expect(flags.map((flag) => [flag.variableId, flag.trigger])).toEqual([
      ["v", "remove_member"],
      ["w", "revoke_server"],
      ["x", "change_role"],
    ]);
  });
});
