// Integration tests for rotation-needed detection (AUDIT_SPEC
// §4.1) + the flag view / dismissals (§6 / §7) + recipient-key
// consistency (the B1a addendum to AUTH_SPEC §12-6 — a 409 carrying
// the stored recipient enc public key of the occupied wrap, and the
// re-add sweep). Verifies the HttpApi and DO SQLite via SELF on
// @cloudflare/vitest-plugin (the real workerd environment).
//
// What this suite pins (mapped to the mutated claims):
// - the candidate set = the overlap of membership intervals and
//   existence windows (variables outside the interval are excluded;
//   deleted variables are included; re-added memberships union
//   intervals)
// - the basis rank: var.read inside the membership interval = read;
//   everything else = readable
// - the rotation.recommended recording rules (§3.3): one row per
//   pair, actor = system, the chain_seq column is not used, the
//   payload carries basis / triggerChainSeq, and the row lands at
//   the seq right after the mirror's same acceptance
// - resolution derivation (§4.1-5): a markerless push and a
//   dismissal resolve, a push carrying the re-encryption marker
//   does not, resolution is seq-ordered (re-detection after a
//   dismissal revives)
// - visibility (§6): the flag view is class 1 (reader allowed), a
//   non-member gets 404. Dismissal requires admin or above (member
//   = 403), no live flag → 404, all-or-nothing, duplicate pairs
//   fold, empty list = 400
// - the revoke_server variant: candidates are within the grant
//   scope only; (a) is an in-interval server.lease_issued (the
//   active variables at issuance); an expanded re-grant is a
//   "per-environment disclosure window" (starting at the widening
//   seq — neither pinned to the first scope nor brought forward to
//   the interval's start)
// - recipient-key consistency (the §12-6 B1a addendum): a 409
//   carries the stored enc public key of the occupied wrap /
//   accepting add_member sweeps wraps addressed to the old key
//   (dek.deleted with actor = system + a cause payload; a re-add
//   under the same key sweeps nothing and other members' wraps are
//   untouched)

import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { JSON_HEADERS } from "./support/auth.ts";
import {
  createVariableStatement,
  encryptValue,
  makeDek,
  metaSignedBytesHashOf,
  signMetaStatementAs,
  valueSignedBytesHashOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
  type WireEncryptedPayload,
  type WireVariableMetaStatement,
} from "./support/data-crypto.ts";
import { commitmentOf } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentOk,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { deploymentKey, LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

interface WireRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  /** AUDIT_SPEC §3.3's trigger (2026-09-14 ES — all 3 variants). */
  readonly trigger?: "remove_member" | "change_role" | "revoke_server";
}

async function readFlags(asUserId: string = READER): Promise<readonly WireRotationFlag[]> {
  const response = await requestJson("GET", "/rotation/flags", token(asUserId));
  expect(response.status).toBe(200);
  return ((await response.json()) as { flags: readonly WireRotationFlag[] }).flags;
}

/** Append remove_member to the chain and return its chain seq. */
async function removeMember(targetUserId: string): Promise<number> {
  await appendOperation(fixture, OWNER, {
    op: "remove_member",
    payload: { targetUserId },
  });
  return fixture.head.seq;
}

/** Re-add under the vector-pinned keys (re-joining with the same keys). */
async function readdWithSameKeys(targetUserId: string, role: "member" | "reader"): Promise<void> {
  const keys = vectorKeyOf(targetUserId);
  await appendOperation(fixture, OWNER, {
    op: "add_member",
    payload: {
      targetUserId,
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      role,
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  });
}

/** A bulk pull as the target member (the var.read recording path — §12-7). */
async function pullAs(userId: string): Promise<void> {
  const response = await requestJson("GET", `/environments/${ENV}/pull`, token(userId));
  expect(response.status).toBe(200);
}

/** OWNER creates a variable in an arbitrary environment (since createVariableOk pins writer = MEMBER). */
async function createVariableAsOwner(input: {
  readonly dek: Uint8Array;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
}): Promise<WireVariableMetaStatement> {
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
  return statement;
}

/** OWNER's v(N) push on VAR (including the value signature's prev chain). */
async function pushNextVersion(input: {
  readonly dek: Uint8Array;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly reencryption?: boolean;
}): Promise<WireEncryptedPayload> {
  const value = await encryptValue(
    input.dek,
    { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: input.version },
    `value-v${input.version}`,
    { writerUserId: OWNER, head: fixture.head, prevValueSigHashHex: input.prevValueSigHashHex },
  );
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables/${VAR}/versions`,
    token(OWNER),
    { value, ...(input.reencryption === true ? { reencryption: true } : {}) },
  );
  expect(response.status).toBe(200);
  return value;
}

describe("rotation-needed detection: remove_member (AUDIT_SPEC §4.1)", () => {
  it("records one row per pair — read for a variable read inside the interval, readable for unread candidates", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER fetches the ciphertext (records var.read), then a
    // second, unread variable is created
    await pullAs(MEMBER);
    await createVariableOk(dek, "var-api-key", "API_KEY", "sk-alpha");
    const removalSeq = await removeMember(MEMBER);

    const flags = await readFlags();
    expect(flags).toHaveLength(2);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      environmentId: ENV,
      basis: "read",
      targetUserId: MEMBER,
      triggerChainSeq: removalSeq,
      trigger: "remove_member",
    });
    expect(byVariable.get("var-api-key")).toMatchObject({
      environmentId: ENV,
      basis: "readable",
      targetUserId: MEMBER,
      triggerChainSeq: removalSeq,
      trigger: "remove_member",
    });

    // Recording rules (§3.3): actor = system; the chain_seq column
    // is not used (carried in the payload)
    const events = await readAuditEvents(projectId);
    const recommended = events.filter((event) => event["event"] === "rotation.recommended");
    expect(recommended).toHaveLength(2);
    for (const event of recommended) {
      expect(event["actor_type"]).toBe("system");
      expect(event["actor_user_id"]).toBeNull();
      expect(event["chain_seq"]).toBeNull();
      expect(event["target_user_id"]).toBe(MEMBER);
      const payload = JSON.parse(String(event["payload"])) as Record<string, unknown>;
      expect(payload["triggerChainSeq"]).toBe(removalSeq);
      expect(["read", "readable"]).toContain(payload["basis"]);
    }
    // The detection rows sit at the seq right after the mirror
    // (chain.member_removed) (a same-acceptance append — §4.1-4)
    const mirror = events.find((event) => event["event"] === "chain.member_removed");
    expect(mirror).toBeDefined();
    expect(Math.min(...recommended.map((event) => Number(event["seq"])))).toBe(
      Number(mirror?.["seq"]) + 1,
    );
  });

  it("deleted variables are still candidates, only dismissal resolves, and re-detection after a dismissal revives (§4.1-2 / -5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await pullAs(MEMBER);
    // Deleting the variable does not erase past readability (the
    // upstream credential is not revoked)
    expect((await deleteVariableRequest(VAR, OWNER)).status).toBe(204);
    await removeMember(MEMBER);
    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({ variableId: VAR, basis: "read" });

    // A deleted variable cannot be pushed — the only resolution
    // path is dismissal (admin)
    const dismissed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(dismissed.status).toBe(204);
    expect(await readFlags()).toHaveLength(0);
    const events = await readAuditEvents(projectId);
    const dismissedRows = events.filter((event) => event["event"] === "rotation.dismissed");
    expect(dismissedRows).toHaveLength(1);
    expect(dismissedRows[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: OWNER,
      environment_id: ENV,
      variable_id: VAR,
    });

    // Resolution is seq-ordered (§4.1-5): detection on the post-
    // dismissal re-add → re-remove revives
    await readdWithSameKeys(MEMBER, "member");
    await removeMember(MEMBER);
    expect(await readFlags()).toHaveLength(1);
  });

  it("the interval union of a re-add: candidates cover every interval; a variable overlapping none is excluded (§4.1-1 / -2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);

    // A variable that existed only during the absence (created by
    // OWNER, deleted before the re-add)
    const gapVar = "var-gap-secret";
    const gapStatement = await createVariableAsOwner({
      dek,
      environmentId: ENV,
      variableId: gapVar,
      name: "GAP_SECRET",
    });
    const gapDeleteStatement = await signMetaStatementAs(OWNER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: gapVar,
      name: "GAP_SECRET",
      status: "deleted" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, gapStatement, OWNER),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const gapDelete = await manifestForVariableOp(fixture, {
      environmentId: ENV,
      issuerUserId: OWNER,
      entry: {
        variableId: gapVar,
        status: "deleted",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, gapDeleteStatement, OWNER),
      },
    });
    expect(
      (
        await requestJson("DELETE", `/environments/${ENV}/variables/${gapVar}`, token(OWNER), {
          statement: gapDeleteStatement,
          manifest: gapDelete.manifest,
        })
      ).status,
    ).toBe(204);
    fixture.manifests.set(ENV, gapDelete.state);

    // Re-add (same keys) → re-remove
    await readdWithSameKeys(MEMBER, "member");
    await removeMember(MEMBER);

    const flags = await readFlags();
    // VAR is detected at both removals (2 live flag rows on one
    // pair — the interval union). The gap variable overlaps no
    // membership interval and is never detected
    expect(flags.filter((flag) => flag.variableId === VAR)).toHaveLength(2);
    expect(flags.filter((flag) => flag.variableId === gapVar)).toHaveLength(0);
  });

  it("resolution derivation: a markerless push resolves, a re-encryption-marked push does not (§4.1-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    expect(await readFlags()).toHaveLength(1);

    // A push carrying the re-encryption marker (equivalent to
    // re-pushing the mandated rotation) does not resolve
    const v2 = await pushNextVersion({
      dek,
      version: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      reencryption: true,
    });
    expect(await readFlags()).toHaveLength(1);
    // The marker lands in the audit payload (AUDIT_SPEC §3.3)
    const events = await readAuditEvents(projectId);
    const markedPush = events.find(
      (event) => event["event"] === "var.version_pushed" && Number(event["version"]) === 2,
    );
    expect(JSON.parse(String(markedPush?.["payload"])) as Record<string, unknown>).toMatchObject({
      reencryption: true,
    });

    // A markerless push (= rotated the upstream credential and
    // stored a new value) resolves
    await pushNextVersion({
      dek,
      version: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(v2, OWNER),
    });
    expect(await readFlags()).toHaveLength(0);
  });

  it("visibility: the flag view is class 1 (reader allowed); a non-member gets 404 (§6 / §11-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    // Readers can see it too (detection's purpose is prompting
    // everyone — limiting it to admins would not work)
    expect(await readFlags(READER)).toHaveLength(1);
    const stranger = await requestJson("GET", "/rotation/flags", token(STRANGER));
    expect(stranger.status).toBe(404);
  });
});

describe("the dismissal operation (AUDIT_SPEC §3.3 / §7)", () => {
  it("denies below admin with 403, rejects any pair without a live flag with 404 and all-or-nothing, and folds duplicate pairs into one row", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Remove READER while keeping MEMBER (the dismissal-permission
    // check needs a member)
    await removeMember(READER);
    expect(await readFlags(OWNER)).toHaveLength(1);

    // A chain-role member cannot dismiss (admin or above — the same
    // level as wrap deletion)
    const asMember = await requestJson("POST", "/rotation/dismissals", token(MEMBER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(asMember.status).toBe(403);

    // A request containing a pair with no live flag rejects the
    // whole thing with 404 (no silent success)
    const mixed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [
        { environmentId: ENV, variableId: VAR },
        { environmentId: ENV, variableId: "var-not-flagged" },
      ],
    });
    expect(mixed.status).toBe(404);
    await expect(mixed.json()).resolves.toMatchObject({
      _tag: "RotationFlagNotFound",
      variableId: "var-not-flagged",
    });
    // all-or-nothing: even the live pair is not dismissed and no
    // audit row is appended
    expect(await readFlags(OWNER)).toHaveLength(1);
    const before = await readAuditEvents(projectId);
    expect(before.filter((event) => event["event"] === "rotation.dismissed")).toHaveLength(0);

    // Duplicate entries of the same pair fold to one row
    // (idempotent per pair)
    const deduped = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [
        { environmentId: ENV, variableId: VAR },
        { environmentId: ENV, variableId: VAR },
      ],
    });
    expect(deduped.status).toBe(204);
    const after = await readAuditEvents(projectId);
    expect(after.filter((event) => event["event"] === "rotation.dismissed")).toHaveLength(1);
    expect(await readFlags(OWNER)).toHaveLength(0);

    // An empty list is a Schema-validation 400 (a call shape with
    // no meaning)
    const empty = await requestJson("POST", "/rotation/dismissals", token(OWNER), { targets: [] });
    expect(empty.status).toBe(400);
  });
});

describe("rotation-needed detection: the revoke_server variant (AUDIT_SPEC §4.1)", () => {
  it("candidates stay within the grant scope; the variables active at lease issuance become read", async () => {
    // Prepare ENV (in scope) and env-out (out of scope)
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const outEnv = "env-out-of-scope";
    const outDek = makeDek();
    const outDeks = await wrapDekForAll({
      projectId,
      environmentId: outEnv,
      epoch: 1,
      dek: outDek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    expect(
      (
        await createEnvironmentComposite(fixture, {
          environmentId: outEnv,
          name: "Out",
          deks: outDeks,
          dekCommitmentHex: await commitmentOf(projectId, outEnv, 1, outDek),
        })
      ).status,
    ).toBe(200);
    const outVar = "var-out-of-scope";
    await createVariableAsOwner({
      dek: outDek,
      environmentId: outEnv,
      variableId: outVar,
      name: "OUT_SECRET",
    });

    // grant (scope = ENV only) + server-bound backfill + lease issuance
    const key = await deploymentKey();
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [ENV],
        leasePolicy: [
          {
            issuerUrl: OIDC_ISSUER,
            audience: LEASE_AUDIENCE,
            claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
          },
        ],
      },
    });
    const serverWrap = await wrapDekToServer({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      serverKeyFingerprintHex: key.fingerprintHex,
      serverEncPubHex: key.encPubHex,
      signerUserId: OWNER,
    });
    expect(
      (await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), { deks: [serverWrap] }))
        .status,
    ).toBe(204);
    const workload = await generateEncryptionKeyPair();
    const ephemeralPubHex = encodeHex(await exportEncryptionPublicKey(workload.publicKey));
    const lease = await SELF.fetch(
      `https://maruhi.test/projects/${projectId}/environments/${ENV}/lease`,
      {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ oidcToken: await makeOidcToken(), ephemeralPubHex }),
      },
    );
    expect(lease.status).toBe(200);

    // A variable created after the lease issuance (nonexistent at
    // issuance → readable)
    await createVariableOk(dek, "var-after-lease", "AFTER_LEASE", "later-secret");

    // Revocation → detection (the variant): in-scope only, and (a)
    // is the variables active at lease issuance
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: key.fingerprintHex },
    });
    const revokeSeq = fixture.head.seq;

    const flags = await readFlags(OWNER);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      environmentId: ENV,
      basis: "read",
      targetServerKeyFingerprintHex: key.fingerprintHex,
      triggerChainSeq: revokeSeq,
      trigger: "revoke_server",
    });
    expect(byVariable.get("var-after-lease")).toMatchObject({
      environmentId: ENV,
      basis: "readable",
      trigger: "revoke_server",
    });
    // Variables in the out-of-scope environment are not candidates
    // (step 2 of the §4.1 variant)
    expect(byVariable.has(outVar)).toBe(false);
    // The member variant's column (target_user_id) is not used
    expect(flags.every((flag) => flag.targetUserId === undefined)).toBe(true);
  });

  it("an environment added by an expanded re-grant is detected under a 'disclosure window from the widening seq' (the §4.1 variant)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Prepare an environment that joins via widening later, and a
    // variable deleted **before** the widening
    const widenEnv = "env-widened";
    const widenDek = makeDek();
    const widenDeks = await wrapDekForAll({
      projectId,
      environmentId: widenEnv,
      epoch: 1,
      dek: widenDek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    expect(
      (
        await createEnvironmentComposite(fixture, {
          environmentId: widenEnv,
          name: "Widened",
          deks: widenDeks,
          dekCommitmentHex: await commitmentOf(projectId, widenEnv, 1, widenDek),
        })
      ).status,
    ).toBe(200);
    const preVar = "var-deleted-before-widen";
    const preStatement = await createVariableAsOwner({
      dek: widenDek,
      environmentId: widenEnv,
      variableId: preVar,
      name: "PRE_WIDEN",
    });

    const key = await deploymentKey();
    const leasePolicy = [
      {
        issuerUrl: OIDC_ISSUER,
        audience: LEASE_AUDIENCE,
        claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
      },
    ];
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [ENV],
        leasePolicy,
      },
    });
    // Delete preVar after the first grant and before the widening
    // (its existence window closes just short of the window)
    const preDelete = await signMetaStatementAs(OWNER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: widenEnv,
      variableId: preVar,
      name: "PRE_WIDEN",
      status: "deleted" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, preStatement, OWNER),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const preDeleteManifest = await manifestForVariableOp(fixture, {
      environmentId: widenEnv,
      issuerUserId: OWNER,
      entry: {
        variableId: preVar,
        status: "deleted",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, preDelete, OWNER),
      },
    });
    expect(
      (
        await requestJson("DELETE", `/environments/${widenEnv}/variables/${preVar}`, token(OWNER), {
          statement: preDelete,
          manifest: preDeleteManifest.manifest,
        })
      ).status,
    ).toBe(204);
    fixture.manifests.set(widenEnv, preDeleteManifest.state);
    // The expanded re-grant (the chain's consensus rule accepts
    // only a widening to the same key FP — CRYPTO_SPEC §6.2)
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [ENV, widenEnv],
        leasePolicy,
      },
    });
    // A variable living inside the window (created after the widening)
    const widenVar = "var-in-window";
    await createVariableAsOwner({
      dek: widenDek,
      environmentId: widenEnv,
      variableId: widenVar,
      name: "IN_WINDOW",
    });
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: key.fingerprintHex },
    });

    const flags = await readFlags(OWNER);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    // A variable in the widened environment is detected (pinning
    // to the first scope would fail open)
    expect(byVariable.get(widenVar)).toMatchObject({
      environmentId: widenEnv,
      basis: "readable",
      targetServerKeyFingerprintHex: key.fingerprintHex,
    });
    // The first scope's environment is detected as before
    expect(byVariable.get(VAR)).toMatchObject({ environmentId: ENV, basis: "readable" });
    // A variable deleted before the widening does not overlap the
    // window (the window is not brought forward to the interval's
    // start — doing so would wrongly detect preVar, which existed
    // between grant #1 and the widening)
    expect(byVariable.has(preVar)).toBe(false);
  });
});

describe("recipient-key consistency (AUTH_SPEC §12-6 — the B1a addendum)", () => {
  it("an overwrite-forbidden 409 carries the occupied wrap's stored recipient enc public key", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // Appending to the existing slot (ENV, 1, MEMBER) is 409 + the
    // stored enc public key
    const duplicate = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserId: MEMBER,
      signerUserId: OWNER,
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [duplicate],
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "DekWrapExists",
      epoch: 1,
      recipientUserId: MEMBER,
      storedRecipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
    });
  });

  it("accepting a re-add under different keys sweeps the old-key wraps and records dek.deleted (system + cause)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await rotateEnvironmentOk(fixture, OWNER, ENV, 2);
    await removeMember(MEMBER);
    const wrapsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsBefore[0]?.["n"])).toBe(2);

    // A re-add under a different key (re-joining after the
    // acceptance key changed) — the 2 wraps addressed to the old key
    // are deleted at acceptance
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: MEMBER,
        encPubHex: "11".repeat(32),
        sigPubHex: "22".repeat(32),
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    const readdSeq = fixture.head.seq;
    const wrapsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsAfter[0]?.["n"])).toBe(0);
    // Other members' legitimate wraps are untouched (the
    // overwrite-forbidden invariant holds)
    const others = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id != ?",
      MEMBER,
    );
    expect(Number(others[0]?.["n"])).toBe(2 * (ALL_MEMBERS.length - 1));

    const events = await readAuditEvents(projectId);
    const deleted = events.filter((event) => event["event"] === "dek.deleted");
    expect(deleted).toHaveLength(2);
    for (const event of deleted) {
      expect(event["actor_type"]).toBe("system");
      expect(event["target_user_id"]).toBe(MEMBER);
      expect(JSON.parse(String(event["payload"])) as Record<string, unknown>).toEqual({
        cause: "member-readded",
        triggerChainSeq: readdSeq,
      });
    }
  });

  it("a re-add under the same key sweeps nothing (the existing wraps return to live use as-is)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await removeMember(READER);
    await readdWithSameKeys(READER, "reader");
    const wraps = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      READER,
    );
    expect(Number(wraps[0]?.["n"])).toBe(1);
    const events = await readAuditEvents(projectId);
    expect(events.filter((event) => event["event"] === "dek.deleted")).toHaveLength(0);
  });
});
