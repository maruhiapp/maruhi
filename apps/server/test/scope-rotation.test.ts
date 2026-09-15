// ES K3 — 要ローテーション検出の環境別アクセス窓と change_role 変種(AUDIT_SPEC §3.3 /
// §3.4 / §4.1 / §4.2 Q1 = CRYPTO_SPEC §7。設計録 docs/notes/es-design.md §9 K3-E)。
//
// 固定する規則:
//   - 候補集合 = 環境別のアクセス窓(§4.1 手順 2): remove_member の候補は対象が
//     scope に持っていた環境の変数だけ(scope 外の環境は候補にならない)
//   - change_role 変種: 縮小 = 縮小分の環境、降格 = 対象 scope の全環境、昇格 /
//     拡大は検出なし。trigger = change_role、起点 = 当該 change_role の seq
//   - remove の候補は在籍区間内の全窓(縮小で閉じた過去の窓を含む — 同対の複数行)
//   - 窓の復元はチェーンミラーの payload(scopeKind / scopeEnvironmentIds / newRole —
//     §3.4)だけから成立する(§4.2 Q1 — role_changed を含む)
//   - 3 変種すべての rotation.recommended が trigger を持ち、K3 前の行は target から補完する

import { describe, expect, it } from "vitest";

import type { AuditRotationRead } from "../src/audit-store.ts";
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

/** OWNER が任意環境に変数を作る(値 v1 + ステートメント + マニフェスト)。 */
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
 * 2 環境 + 各 1 変数を作り、DEV を member・listed{scope} で追加する。
 * 返り値はチェーン上の add_member の seq。
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

describe("要ローテーション検出: 環境別アクセス窓(§4.1 手順 2 — remove_member)", () => {
  it("listed{ENV} のメンバー削除は ENV の変数だけを候補にし、scope 外の環境は候補にしない", async () => {
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

  it("縮小で閉じた過去の窓も remove の候補に含める(縮小時の行と remove 時の行が同対に並ぶ)", async () => {
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

describe("要ローテーション検出: change_role 変種(§4.1 — 降格・縮小)", () => {
  it("縮小は縮小分の環境だけを候補にし、trigger = change_role・起点 = 当該 change_role の seq、read / readable を区別する", async () => {
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
    // 記録細則(§3.3): actor = system、payload に trigger、ミラー行の直後 seq
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

  it("降格(member → reader)は対象 scope の全環境を候補にする(reader として DEK を受け取り続けても検出する)", async () => {
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
    // 降格者は在籍を続ける: その後の削除で同じ環境が再び候補になる(窓は閉じていない)
    await removeDev();
    expect((await readFlags()).filter((flag) => flag.trigger === "remove_member")).toHaveLength(2);
  });

  it("昇格・拡大・scope 不変の role 変更は検出しない。拡大後に縮小すれば拡大 seq からの窓で検出する", async () => {
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

  it("降格と縮小が同時でも 1 (variable × environment) 1 行(§3.3 の粒度)", async () => {
    await setupTwoEnvironments([ENV, OTHER]);
    await changeRole("reader", [ENV]);
    const flags = await readFlags();
    expect(flags).toHaveLength(2);
    expect(new Set(flags.map((flag) => `${flag.environmentId}/${flag.variableId}`)).size).toBe(2);
  });
});

describe("窓の復元材料(AUDIT_SPEC §3.4 のミラー payload / §4.2 Q1)", () => {
  it("chain.member_added / chain.role_changed のミラー行が scope を写す(検出はこの payload だけを読む)", async () => {
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
// 純関数のユニットテスト(DO なし): 窓導出の fail-safe と trigger の補完
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
    serverGrantEventsFor: () => [],
    variableLifecycles: () => input.lifecycles,
    variableReadsBy: () => input.reads ?? [],
    serverAccessEventsBy: () => [],
    rotationFlagEvents: () => [],
  };
}

/** revoke_server 変種の純関数テスト用: grant 区間とリース発行行だけを持つ読み取り面。 */
const grantRead = (
  events: readonly { seq: number; event: string; scopeEnvironmentIds: readonly string[] }[],
  access: readonly { seq: number; environmentId: string }[],
): AuditRotationRead => ({
  membershipEventsFor: () => [],
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

describe("窓導出の fail-safe と trigger の補完(純関数)", () => {
  it("scope を読めない member_added 行は all として窓を開く(検出は見逃さない側 — K3-F)", () => {
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

  it("listed の窓は scope の遷移点で開閉し、窓の外の読み取りは read に数えない", () => {
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
        // seq 5 の読み取りは env-b の窓(8〜12)の外 = K3 前の行 / 不正な行の想定
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

  it("再追加を跨ぐ窓は別区間: 不在の間の読み取りは数えず、両区間の候補を含む(§4.1 手順 1)", () => {
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
          // 不在の間だけ存在した変数(どの窓とも重ならない)
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

  it("在籍区間の外に現れた role_changed は open として窓を開く(壊れた入力でも見逃さない側)", () => {
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

  it("role が読めない role_changed は降格として扱う(見逃さない側)", () => {
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

  it("revoke_server 変種: 失効 → 再 grant → 再失効は別の窓、縮小する再 grant は窓を閉じない(和集合)", () => {
    // 失効中(seq 5)のリースは数えない → readable
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
    // 縮小する再 grant(合意規則は拒否するが検出側は fail-safe): env-b の窓は失効まで開いたまま
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

  it("K3 前の rotation.recommended 行(trigger なし)は target 列から補完する", () => {
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
