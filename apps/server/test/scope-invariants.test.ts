// ES K3 — scope が変えないもの(設計録 docs/notes/es-design.md §9 / §1-4):
//   - リース経路(AUTH_SPEC §14-1): メンバーの scope はリースに関与しない。環境制限は
//     grant の scope_environments だけが担う
//   - 可視性クラス(AUDIT_SPEC §6): scope 外環境のクラス 1 イベント・要ローテーション
//     フラグは listed メンバーにも見える(可視性述語に環境軸を入れない)

import { describe, expect, it } from "vitest";

import { fetchEvents } from "./support/audit-read-scenario.ts";
import { addMemberOperation } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  requestJson,
  seedMemberToken,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import {
  backfillServerWrap,
  grantServer,
  requestLease,
  workloadKeyPair,
} from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";

registerDataScenario();

const DEV = "user-devmember-0010";
const DEVADMIN = "user-devadmin-0011";
const OTHER = "env-other-0002";

describe("リース経路は不変(AUTH_SPEC §14-1)", () => {
  it("listed{} / listed{OTHER} のメンバーがいてもリースは grant の scope だけで決まる", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    // ENV を scope に持たないメンバー(完全集合にも入らない)
    await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [OTHER]));
    await grantServer({ scope: [ENV] });
    await backfillServerWrap(1, dek);
    const workload = await workloadKeyPair();
    const response = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: workload.publicKeyHex,
    });
    expect(response.status).toBe(200);
  });
});

describe("可視性クラスは不変(AUDIT_SPEC §6)", () => {
  it("scope 外環境の var.* / env.* / chain.* と要ローテーションフラグは listed メンバーにも見える", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedMemberToken(fixture, DEV, 9010);
    // DEV は OTHER だけ — ENV は scope 外
    await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [OTHER]));
    // ENV(DEV の scope 外)の変数に対するフラグ: all メンバーの削除で検出される
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });

    const { status, events } = await fetchEvents(token(DEV), { limit: "200" });
    expect(status).toBe(200);
    const names = events.map((event) => event.event);
    expect(names).toEqual(
      expect.arrayContaining([
        "chain.environment_created",
        "env.created",
        "var.created",
        "chain.member_removed",
        "rotation.recommended",
      ]),
    );
    expect(
      events.some((event) => event.event === "var.created" && event.environmentId === ENV),
    ).toBe(true);
    const flags = await requestJson("GET", "/rotation/flags", token(DEV));
    expect(flags.status).toBe(200);
    const body = (await flags.json()) as { flags: { environmentId: string }[] };
    expect(body.flags.some((flag) => flag.environmentId === ENV)).toBe(true);
  });

  it("要ローテーションフラグの取り下げは admin の判断で scope を問わない(§3.3 / §4.1-5 — 環境座標を持つ唯一の非 scope 経路)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await seedMemberToken(fixture, DEVADMIN, 9011);
    await appendOperation(fixture, OWNER, addMemberOperation(DEVADMIN, "admin", [OTHER]));
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    // ENV は DEVADMIN の scope 外だが、取り下げ(admin × admin スコープ)は通る
    const dismissed = await requestJson("POST", "/rotation/dismissals", token(DEVADMIN), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(dismissed.status).toBe(204);
    const flags = await requestJson("GET", "/rotation/flags", token(DEVADMIN));
    expect(((await flags.json()) as { flags: unknown[] }).flags).toHaveLength(0);
  });
});
