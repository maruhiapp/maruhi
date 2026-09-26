// ES K3 — scope authorization for environment-targeted ops
// (AUTH_SPEC §9-2 / §12-3 / §12-7 = the acceptance surface of the
// scope derived by CRYPTO_SPEC §6.2's verification state. Design
// record docs/notes/es-design.md §9 K3-A / K3-B / K3-C / K3-G).
// Verifies the HttpApi via SELF on @cloudflare/vitest-plugin (real
// workerd environment).
//
// Rules pinned (each row of the §12-3 table, one at a time):
//   1. pull with values / fetch DEKs addressed to self = environment ∈
//      scope (403 insufficient-scope)
//   2. metadata-only pull / environment list = unrestricted (all
//      environments; no advisory scope field is returned — §12-7)
//   3. variable create / push / rename / delete, environment rename,
//      DEK-wrap registration = environment ∈ scope
//   4. environment creation = scope = all
//   5. environment deletion / DEK-wrap deletion = environment ∈ scope
//      (admin)
//   - judgment order: role 403 → scope 403 → existence 404 (for a
//     listed principal a nonexistent environment is also 403)
//   - rotate / checkpoint 403s precede the consensus rule
//     environment-out-of-scope (422)
//   - the scope axis (3′) of the dual judgment at authorization time
//     folds into chain-head-state-mismatch (K3-B)

import type { ChainOperation } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import {
  addMemberOperation,
  changeRoleOperation,
  checkpointOperation,
  commitmentOf,
  createVariableStatement,
  encryptValue,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valueSignedBytesHashOf,
  valuesDigestOf,
  wrapDekForAll,
  wrapDekTo,
  type WireEncryptedPayload,
  type WireVariableMetaStatement,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
  seedMemberToken,
  storedCheckpointValues,
  tokenOf,
} from "./support/data-fixture.ts";
import {
  aadFor,
  ENV,
  fixture,
  registerDataScenario,
  token,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** A listed member (vector key — vectorKeyOf in data-crypto.ts). */
const DEV = "user-devmember-0010";
const DEVADMIN = "user-devadmin-0011";
const OTHER = "env-other-0002";
const GHOST = "env-ghost-9999";

async function expectForbidden(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(403);
  expect(((await response.json()) as { reason: string }).reason).toBe(reason);
}

const expectScopeForbidden = (response: Response): Promise<void> =>
  expectForbidden(response, "insufficient-scope");

/**
 * Create two environments (ENV / OTHER) and add DEV as member,
 * listed{ENV}. Since a listed scope can only enumerate created
 * environments (the consensus rule unknown-environment), environment
 * creation comes first. The existing environments' wrap-complete set
 * stays the pre-addition R(E) (= ALL_MEMBERS).
 */
async function setupListed(): Promise<{ envDek: Uint8Array; otherDek: Uint8Array }> {
  const envDek = await createEnvironmentOk(fixture, ENV, "App");
  const otherDek = await createEnvironmentOk(fixture, OTHER, "Other");
  await seedMemberToken(fixture, DEV, 9010);
  await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [ENV]));
  return { envDek, otherDek };
}

/** Any principal creates a variable in any environment (value v1 + statement + manifest). */
async function createVariableAs(input: {
  readonly writer: string;
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly variableId: string;
  readonly name: string;
}): Promise<{ value: WireEncryptedPayload; statement: WireVariableMetaStatement }> {
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
    { writerUserId: input.writer, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: input.writer,
    projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: input.environmentId,
    issuerUserId: input.writer,
    entry: {
      variableId: input.variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, input.writer),
    },
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.environmentId}/variables`,
    token(input.writer),
    { statement, value, manifest },
  );
  expect(response.status).toBe(200);
  fixture.manifests.set(input.environmentId, state);
  return { value, statement };
}

/** Call generic append raw (appendOperation asserts 200, so this is for negatives). */
async function appendRaw(actorUserId: string, operation: ChainOperation): Promise<Response> {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
    operation,
  });
  return SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
}

/** A standalone checkpoint notarizing the environment's current state (recorded manifest + value enumeration). */
async function checkpointFor(environmentId: string, epoch: number): Promise<ChainOperation> {
  const last = fixture.manifests.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for ${environmentId}`);
  }
  return checkpointOperation({
    environmentId,
    epoch,
    manifestVersion: last.manifest.manifestVersion,
    manifestSigHashHex: await manifestSignedBytesHashOf(
      projectId,
      last.manifest,
      last.issuerUserId,
    ),
    valuesDigestHex: await valuesDigestOf(await storedCheckpointValues(environmentId)),
  });
}

/** An environment meta-statement (unsigned dummy — the 403 settles before signature verification). */
function unsignedEnvStatement(environmentId: string, name: string, status: "active" | "deleted") {
  return {
    suite: "maruhi/v1",
    environmentId,
    name,
    status,
    metaVersion: 2,
    prevMetaSigHashHex: "cd".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

describe("scope authorization — reads (§12-3 rows 1-2 / §12-7)", () => {
  it("pull with values and fetching DEKs addressed to self require environment ∈ scope: 200 inside, 403 insufficient-scope outside (and no var.read recorded)", async () => {
    await setupListed();
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(DEV))).status).toBe(200);
    await expectScopeForbidden(await requestJson("GET", `/environments/${OTHER}/pull`, token(DEV)));
    expect((await requestJson("GET", `/environments/${ENV}/deks`, token(DEV))).status).toBe(200);
    await expectScopeForbidden(await requestJson("GET", `/environments/${OTHER}/deks`, token(DEV)));
    // fail-closed: a rejected pull records no var.read (§12-7's
    // recording condition = having returned ciphertext; outside scope
    // returns nothing)
    const reads = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read' AND actor_user_id = ? AND environment_id = ?",
      DEV,
      OTHER,
    );
    expect(reads[0]?.["n"]).toBe(0);
  });

  it("metadata-only pull and the environment list ignore scope and return no advisory scope field (§12-7)", async () => {
    await setupListed();
    const metadata = await requestJson("GET", `/environments/${OTHER}/pull/metadata`, token(DEV));
    expect(metadata.status).toBe(200);
    const list = await requestJson("GET", "/environments", token(DEV));
    expect(list.status).toBe(200);
    const body = (await list.json()) as { environments: Record<string, unknown>[] };
    expect(body.environments.map((environment) => environment["environmentId"]).toSorted()).toEqual(
      [ENV, OTHER].toSorted(),
    );
    for (const environment of body.environments) {
      // The client derives its own scope from the verified chain —
      // the server-declared "inside scope" is not an input to the
      // verification rules (§12-7)
      expect(Object.keys(environment).toSorted()).toEqual(
        ["currentEpoch", "environmentId", "statement"].toSorted(),
      );
    }
  });
});

describe("scope authorization — writes (§12-3 rows 3-5)", () => {
  it("variable create / push / rename / delete, environment rename, and DEK-wrap registration require environment ∈ scope (403 outside, accepted inside)", async () => {
    const { envDek } = await setupListed();
    const otherAad = (version: number, variableId = VAR) =>
      aadFor(1, version, { environmentId: OTHER, variableId });
    // Create (same path whether declared / active)
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/variables`, token(DEV), {
        statement: { ...unsignedVariableStatement("var-x", "X"), environmentId: OTHER },
        value: unsignedPayload(otherAad(1, "var-x")),
        manifest: unsignedManifest(OTHER),
      }),
    );
    // push (scope precedes regardless of the variable's existence)
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/variables/${VAR}/versions`, token(DEV), {
        value: unsignedPayload(otherAad(2)),
      }),
    );
    // Rename / schema re-issuance
    await expectScopeForbidden(
      await requestJson("PATCH", `/environments/${OTHER}/variables/${VAR}`, token(DEV), {
        statement: {
          ...unsignedVariableStatement(VAR, "RENAMED"),
          environmentId: OTHER,
          metaVersion: 2,
          prevMetaSigHashHex: "cd".repeat(32),
        },
        manifest: unsignedManifest(OTHER),
      }),
    );
    // Delete
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}/variables/${VAR}`, token(DEV), {
        statement: {
          ...unsignedVariableStatement(VAR, "DATABASE_URL"),
          environmentId: OTHER,
          status: "deleted",
          metaVersion: 2,
          prevMetaSigHashHex: "cd".repeat(32),
        },
        manifest: unsignedManifest(OTHER),
      }),
    );
    // Environment rename
    await expectScopeForbidden(
      await requestJson("PATCH", `/environments/${OTHER}`, token(DEV), {
        statement: unsignedEnvStatement(OTHER, "Renamed", "active"),
        manifest: unsignedManifest(OTHER),
      }),
    );
    // DEK-wrap registration (registrar = signer = the calling
    // principal's scope — §12-6's end = the same judgment as §12-3 →
    // 403. Before the recipient-axis 422)
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/deks`, token(DEV), {
        deks: [
          await wrapDekTo({
            projectId,
            environmentId: OTHER,
            epoch: 1,
            dek: makeDek(),
            recipientUserId: DEV,
            signerUserId: DEV,
          }),
        ],
      }),
    );
    // A write inside scope is accepted (the listed member's positive case)
    await createVariableAs({
      writer: DEV,
      environmentId: ENV,
      dek: envDek,
      variableId: "var-dev",
      name: "DEV_ONLY",
    });
  });

  it("environment deletion and DEK-wrap deletion require admin × environment ∈ scope (403 outside for a listed admin)", async () => {
    await setupListed();
    await seedMemberToken(fixture, DEVADMIN, 9011);
    await appendOperation(fixture, OWNER, addMemberOperation(DEVADMIN, "admin", [ENV]));
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}`, token(DEVADMIN), {
        statement: unsignedEnvStatement(OTHER, "Other", "deleted"),
      }),
    );
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}/deks`, token(DEVADMIN), {
        wraps: [{ epoch: 1, recipientUserId: OWNER }],
      }),
    );
    // Environment deletion inside scope is accepted (the admin's positive case)
    expect((await deleteEnvironmentRequest(fixture, ENV, DEVADMIN)).status).toBe(204);
  });

  it("judgment order: role 403 → scope 403 → existence 404 (a nonexistent environment is also 403 for a listed principal; 404 for an `all` principal)", async () => {
    await setupListed();
    // role first: member DEV performs an admin operation (environment deletion) on something out of scope
    await expectForbidden(
      await requestJson("DELETE", `/environments/${OTHER}`, token(DEV), {
        statement: unsignedEnvStatement(OTHER, "Other", "deleted"),
      }),
      "insufficient-role",
    );
    // scope precedes existence: an uncreated environment id cannot be in a listed scope
    await expectScopeForbidden(await requestJson("GET", `/environments/${GHOST}/pull`, token(DEV)));
    const ghostRotate = await rotateEnvironmentComposite(fixture, {
      environmentId: GHOST,
      newEpoch: 2,
      deks: [],
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(ghostRotate);
    // An `all` principal still gets existence 404 (invariance on a K3-only deployment)
    expect((await requestJson("GET", `/environments/${GHOST}/pull`, token(MEMBER))).status).toBe(
      404,
    );
  });
});

describe("scope authorization — paths involving a chain op (§9-2 / §12-3 row 4; the 403 precedes the consensus-rule 422 — K3-G)", () => {
  it("environment creation requires scope = all (listed member / admin get 403); rotate requires environment ∈ scope", async () => {
    await setupListed();
    const creation = await createEnvironmentComposite(fixture, {
      environmentId: "env-new-0003",
      name: "New",
      deks: await wrapDekForAll({
        projectId,
        environmentId: "env-new-0003",
        epoch: 1,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: DEV,
      }),
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(creation);
    const otherRotate = await rotateEnvironmentComposite(fixture, {
      environmentId: OTHER,
      newEpoch: 2,
      deks: [],
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(otherRotate);
    // A rotate inside scope is accepted. The complete set is R(ENV) = all `all`-scope members + DEV
    const dek = makeDek();
    const rotated = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek,
        recipientUserIds: [...ALL_MEMBERS, DEV],
        signerUserId: DEV,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek),
      actorUserId: DEV,
    });
    expect(rotated.status).toBe(200);
  });

  it("a standalone checkpoint requires every tuple's environment ∈ scope (a tuple outside scope is 403; all-inside is accepted)", async () => {
    await setupListed();
    await expectScopeForbidden(await appendRaw(DEV, await checkpointFor(OTHER, 1)));
    await appendOperation(fixture, DEV, await checkpointFor(ENV, 1));
  });
});

describe("the scope axis of the dual judgment at authorization time (§12-3 / CRYPTO_SPEC §6.3's 3′ — K3-B)", () => {
  it("a value / meta / manifest that is inside scope at acceptance time but outside scope at the declared head is 422 chain-head-state-mismatch (same fold as the role axis)", async () => {
    const { otherDek } = await setupListed();
    const created = await createVariableAs({
      writer: OWNER,
      environmentId: OTHER,
      dek: otherDek,
      variableId: "var-o",
      name: "OTHER_SECRET",
    });
    // The head before the widening (DEV's scope is {ENV})
    const oldHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, changeRoleOperation(DEV, "member", [ENV, OTHER]));

    // Value: at acceptance time (the current head) OTHER ∈ scope so
    // it passes the 403, but at the declared head (pre-widening) it is
    // outside scope → rejected by 3′
    const stale = await encryptValue(
      otherDek,
      { projectId, environmentId: OTHER, epoch: 1, variableId: "var-o", version: 2 },
      "stale-head",
      {
        writerUserId: DEV,
        head: oldHead,
        prevValueSigHashHex: await valueSignedBytesHashOf(created.value, OWNER),
      },
    );
    const staleValue = await requestJson(
      "POST",
      `/environments/${OTHER}/variables/var-o/versions`,
      token(DEV),
      { value: stale },
    );
    expect(staleValue.status).toBe(422);
    expect(((await staleValue.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // Meta: the rename statement's declared head is pre-widening
    const staleStatement = await signMetaStatementAs(DEV, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: OTHER,
      variableId: "var-o",
      name: "OTHER_SECRET_RENAMED",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, created.statement, OWNER),
      chainHeadHashHex: oldHead.hashHex,
      chainHeadSeq: oldHead.seq,
    });
    const { manifest: freshManifest } = await manifestForVariableOp(fixture, {
      environmentId: OTHER,
      issuerUserId: DEV,
      entry: {
        variableId: "var-o",
        status: "active",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, staleStatement, DEV),
      },
    });
    const staleMeta = await requestJson(
      "PATCH",
      `/environments/${OTHER}/variables/var-o`,
      token(DEV),
      { statement: staleStatement, manifest: freshManifest },
    );
    expect(staleMeta.status).toBe(422);
    expect(((await staleMeta.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // Manifest: the statement is at the current head while only the manifest declares the pre-widening head
    const freshStatement = await signMetaStatementAs(DEV, projectId, {
      ...staleStatement,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const { manifest: baseManifest } = await manifestForVariableOp(fixture, {
      environmentId: OTHER,
      issuerUserId: DEV,
      entry: {
        variableId: "var-o",
        status: "active",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, freshStatement, DEV),
      },
    });
    const { signatureHex: _signatureHex, ...unsignedManifestBody } = baseManifest;
    const staleManifest = await signEnvManifestAs(DEV, projectId, {
      ...unsignedManifestBody,
      chainHeadHashHex: oldHead.hashHex,
      chainHeadSeq: oldHead.seq,
    });
    const staleManifestResponse = await requestJson(
      "PATCH",
      `/environments/${OTHER}/variables/var-o`,
      token(DEV),
      { statement: freshStatement, manifest: staleManifest },
    );
    expect(staleManifestResponse.status).toBe(422);
    expect(((await staleManifestResponse.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // The same write declaring the current head is accepted (inside
    // scope both at acceptance and at the declared head — confirming
    // that only 3′ was dropping it)
    const fresh = await encryptValue(
      otherDek,
      { projectId, environmentId: OTHER, epoch: 1, variableId: "var-o", version: 2 },
      "fresh-head",
      {
        writerUserId: DEV,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(created.value, OWNER),
      },
    );
    const freshValue = await requestJson(
      "POST",
      `/environments/${OTHER}/variables/var-o/versions`,
      token(DEV),
      { value: fresh },
    );
    expect(freshValue.status).toBe(200);
  });
});
