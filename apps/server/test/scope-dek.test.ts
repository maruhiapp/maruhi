// ES K3 — the DEK-wrap recipient set R(E) (CRYPTO_SPEC §6.2 / §6.3,
// AUTH_SPEC §12-4 / §12-6; design record docs/notes/es-design.md §9 K3-D).
//
// Pinned rules:
//   - The target of the complete set (environment creation, rotate compound,
//     initial registration) = R(E) = { m | E ∈ scope(m) } ∪
//     { grant | E ∈ scope_environments } — including an out-of-scope member
//     is 422 scope-out-of-range; omitting one is 422 recipient-missing
//   - Recipient judgment on the append path (backfill): addressing a current
//     out-of-scope member is 422 scope-out-of-range (same reason code even
//     for recipient class member)
//   - The registrant's (signer = calling principal) scope hits §12-3's 403
//     first (before the recipient-axis 422)
//   - A listed{} member is a recipient of no environment (CRYPTO_SPEC §6.2
//     structural rule (3))

import type { ChainState, MemberScope } from "@maruhi/crypto";
import { testKeyFingerprintHex, testUserId } from "@maruhi/crypto/test-support";
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

const DEV = testUserId("user-devmember-0010");
const NOBODY = testUserId("user-prodreader-0012");
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

describe("R(E) — the complete set (environment creation / rotate compound — §12-4)", () => {
  it("the complete set at environment creation is only members whose scope contains E: including a non-listed member is 422 scope-out-of-range, excluding them is 200", async () => {
    await setupListed();
    // DEV is listed{ENV}, so it is not a recipient of the new environment
    // env-new-0003
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

  it("the complete set of a rotate compound is R(E): omitting an in-scope member is 422 recipient-missing, including all is 200", async () => {
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
    // Rotating the out-of-scope environment (OTHER) does not include DEV
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

describe("R(E) — the append path (backfill — §12-6)", () => {
  it("addressing a current out-of-scope member is 422 scope-out-of-range, addressing an in-scope one is 204 (backfill after add_member)", async () => {
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
    // The recipient can fetch the wrap addressed to it (in scope)
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(DEV));
    expect(mine.status).toBe(200);
    expect(((await mine.json()) as { deks: unknown[] }).deks).toHaveLength(1);
  });

  it("the reason-code order for member recipients is identify -> key -> scope (out-of-scope with a key mismatch is recipient-key-mismatch — the same order across classes)", async () => {
    const { otherDek } = await setupListed();
    const response = await requestJson("POST", `/environments/${OTHER}/deks`, token(OWNER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: OTHER,
          epoch: 1,
          dek: otherDek,
          recipientUserId: DEV,
          recipientEncPubHex: "ee".repeat(32),
          signerUserId: OWNER,
        }),
      ],
    });
    await expectDekRejected(response, "recipient-key-mismatch");
  });

  it("the registrant's (signer = calling principal) scope hits 403 first: for an out-of-scope environment it never reaches recipient judgment", async () => {
    const { otherDek } = await setupListed();
    // DEV (listed{ENV}) tries to register a wrap on OTHER addressed to an
    // in-scope recipient (OWNER)
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

  it("a listed{} member is a recipient of no environment (not in the complete set, nor an addressable target)", async () => {
    const envDek = await createEnvironmentOk(fixture, ENV, "App");
    await appendOperation(fixture, OWNER, addMemberOperation(NOBODY, "reader", []));
    // The new environment's complete set stays the original 3 members
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
      userId: testUserId(userId),
      role: "member" as const,
      scope,
      // The single first key = one device (cap is structurally (owner, all)
      // — CRYPTO_SPEC §6.2 DK)
      devices: new Map([
        [
          "33".repeat(16),
          {
            keyFingerprintHex: testKeyFingerprintHex("33".repeat(16)),
            encPubHex: "11".repeat(32),
            sigPubHex: "22".repeat(32),
            roleCap: "owner" as const,
            scope: { kind: "all" as const },
            addedSeq: 1,
          },
        ],
      ]),
    },
  ] as const;

describe("expectedWrapRecipientCount — the single definition of R(E) (CRYPTO_SPEC §6.2)", () => {
  it("counts members only when E ∈ scope and grants by disclosure scope (the same predicate across recipient classes)", () => {
    const fp = testKeyFingerprintHex("ab".repeat(16));
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
    // env-prod: all + grant (dev is out of scope, none is listed{})
    expect(expectedWrapRecipientCount(state, "env-prod")).toBe(2);
    // Unknown environment: all only (U includes future ones — the set
    // algebra's `all`)
    expect(expectedWrapRecipientCount(state, "env-future")).toBe(1);
  });
});
