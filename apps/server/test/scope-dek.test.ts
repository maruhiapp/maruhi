// ES K3 — DEK ラップの受信者集合 R(E)(CRYPTO_SPEC §6.2 / §6.3、AUTH_SPEC §12-4 /
// §12-6。設計録 docs/notes/es-design.md §9 K3-D)。
//
// 固定する規則:
//   - 完全集合(環境作成・rotate 複合・初回登録)の対象 = R(E) = { m | E ∈ scope(m) } ∪
//     { grant | E ∈ scope_environments } — scope 外メンバーを含めると 422
//     scope-out-of-range、欠くと 422 recipient-missing
//   - 追記経路(バックフィル)の受信者判定: scope 外の現メンバー宛は 422
//     scope-out-of-range(受信者クラス member でも同じ理由コード)
//   - 登録者(署名者 = 呼び出し主体)の scope は §12-3 の 403 が先(受信者軸の 422 より前)
//   - listed{} のメンバーはどの環境の受信者にもならない(CRYPTO_SPEC §6.2 の構造規則 (3))

import type { ChainState, MemberScope } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { expectedWrapRecipientCount } from "../src/dek-wraps.ts";
import {
  addMemberOperation,
  commitmentOf,
  makeDek,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
  seedMemberToken,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token } from "./support/data-scenario.ts";

registerDataScenario();

const DEV = "user-devmember-0010";
const NOBODY = "user-prodreader-0012";
const OTHER = "env-other-0002";

async function expectDekRejected(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(422);
  expect(((await response.json()) as { reason: string }).reason).toBe(reason);
}

async function setupListed(): Promise<{ envDek: Uint8Array; otherDek: Uint8Array }> {
  const envDek = await createEnvironmentOk(fixture, ENV, "App");
  const otherDek = await createEnvironmentOk(fixture, OTHER, "Other");
  await seedMemberToken(fixture, DEV, 9010);
  await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [ENV]));
  return { envDek, otherDek };
}

describe("R(E) — 完全集合(環境作成 / rotate 複合 — §12-4)", () => {
  it("環境作成の完全集合は scope に E を含むメンバーだけ: listed 外を含めると 422 scope-out-of-range、除けば 200", async () => {
    await setupListed();
    // DEV は listed{ENV} なので新環境 env-new-0003 の受信者ではない
    const withDev = makeDek();
    const overfull = await createEnvironmentComposite(fixture, {
      environmentId: "env-new-0003",
      name: "New",
      deks: await wrapDekForAll({
        projectId,
        environmentId: "env-new-0003",
        epoch: 1,
        dek: withDev,
        recipientUserIds: [...ALL_MEMBERS, DEV],
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, "env-new-0003", 1, withDev),
    });
    await expectDekRejected(overfull, "scope-out-of-range");
    const dek = makeDek();
    const exact = await createEnvironmentComposite(fixture, {
      environmentId: "env-new-0003",
      name: "New",
      deks: await wrapDekForAll({
        projectId,
        environmentId: "env-new-0003",
        epoch: 1,
        dek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, "env-new-0003", 1, dek),
    });
    expect(exact.status).toBe(200);
  });

  it("rotate 複合の完全集合は R(E): scope 内メンバーを欠くと 422 recipient-missing、揃えば 200", async () => {
    await setupListed();
    const dek = makeDek();
    const missing = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek),
      actorUserId: OWNER,
    });
    await expectDekRejected(missing, "recipient-missing");
    const complete = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek,
        recipientUserIds: [...ALL_MEMBERS, DEV],
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek),
      actorUserId: OWNER,
    });
    expect(complete.status).toBe(200);
    // scope 外の環境(OTHER)の rotate は DEV を含めない
    const otherDek = makeDek();
    const other = await rotateEnvironmentComposite(fixture, {
      environmentId: OTHER,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: OTHER,
        epoch: 2,
        dek: otherDek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, OTHER, 2, otherDek),
      actorUserId: OWNER,
    });
    expect(other.status).toBe(200);
  });
});

describe("R(E) — 追記経路(バックフィル — §12-6)", () => {
  it("scope 外の現メンバー宛は 422 scope-out-of-range、scope 内宛は 204(add_member 後のバックフィル)", async () => {
    const { envDek, otherDek } = await setupListed();
    const outOfScope = await requestJson("POST", `/environments/${OTHER}/deks`, token(OWNER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: OTHER,
          epoch: 1,
          dek: otherDek,
          recipientUserId: DEV,
          signerUserId: OWNER,
        }),
      ],
    });
    await expectDekRejected(outOfScope, "scope-out-of-range");
    const inScope = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: ENV,
          epoch: 1,
          dek: envDek,
          recipientUserId: DEV,
          signerUserId: OWNER,
        }),
      ],
    });
    expect(inScope.status).toBe(204);
    // 受信者は自分宛ラップを取得できる(scope 内)
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(DEV));
    expect(mine.status).toBe(200);
    expect(((await mine.json()) as { deks: unknown[] }).deks).toHaveLength(1);
  });

  it("登録者(署名者 = 呼び出し主体)の scope は 403 が先: scope 外の環境へは受信者の判定に到達しない", async () => {
    const { otherDek } = await setupListed();
    // DEV(listed{ENV})が OTHER へ、scope 内の受信者(OWNER)宛を登録しようとする
    const response = await requestJson("POST", `/environments/${OTHER}/deks`, token(DEV), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: OTHER,
          epoch: 1,
          dek: otherDek,
          recipientUserId: OWNER,
          signerUserId: DEV,
        }),
      ],
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("insufficient-scope");
  });

  it("listed{} のメンバーはどの環境の受信者にもならない(完全集合に含めず、宛先にもできない)", async () => {
    const envDek = await createEnvironmentOk(fixture, ENV, "App");
    await appendOperation(fixture, OWNER, addMemberOperation(NOBODY, "reader", []));
    // 新環境の完全集合は従来の 3 人のまま
    await createEnvironmentOk(fixture, OTHER, "Other");
    const wrap = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: ENV,
          epoch: 1,
          dek: envDek,
          recipientUserId: NOBODY,
          signerUserId: OWNER,
        }),
      ],
    });
    await expectDekRejected(wrap, "scope-out-of-range");
  });
});

const memberOf = (userId: string, scope: MemberScope) =>
  [
    userId,
    {
      userId,
      role: "member" as const,
      scope,
      encPubHex: "11".repeat(32),
      sigPubHex: "22".repeat(32),
      keyFingerprintHex: "33".repeat(16),
    },
  ] as const;

describe("expectedWrapRecipientCount — R(E) の 1 定義(CRYPTO_SPEC §6.2)", () => {
  it("member は E ∈ scope のときだけ数え、grant は開示スコープで数える(受信者クラスを跨いで同一の述語)", () => {
    const fp = "ab".repeat(16);
    const state: ChainState = {
      members: new Map([
        memberOf("user-all", { kind: "all" }),
        memberOf("user-dev", { kind: "listed", environmentIds: ["env-dev"] }),
        memberOf("user-none", { kind: "listed", environmentIds: [] }),
      ]),
      serverGrants: new Map([
        [
          fp,
          {
            serverKeyFingerprintHex: fp,
            serverEncPubHex: "44".repeat(32),
            grantSeq: 1,
            scopeEnvironmentIds: ["env-prod"],
            leasePolicy: [],
          },
        ],
      ]),
      environments: new Map(),
      checkpoints: new Map(),
      approvalPolicy: null,
      pendingProposals: new Map(),
      headSeq: 1,
      headHashHex: "00".repeat(32),
    };
    // env-dev: all + dev
    expect(expectedWrapRecipientCount(state, "env-dev")).toBe(2);
    // env-prod: all + grant(dev は scope 外、none は listed{})
    expect(expectedWrapRecipientCount(state, "env-prod")).toBe(2);
    // 未知の環境: all のみ(将来分を含む U — 集合代数の `all`)
    expect(expectedWrapRecipientCount(state, "env-future")).toBe(1);
  });
});
