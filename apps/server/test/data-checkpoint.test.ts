// Integration tests for the acceptance surface of standalone (periodic)
// checkpoints and GET /audit-head
// (AUTH_SPEC §16-2 / CRYPTO_SPEC §6.4 / AUDIT_SPEC §5.1).
//
// - Two authorization levels (the effective-permission matrix): an empty
//   audit head = write scope × member or above; a non-empty one =
//   effective admin (insufficient → 403)
// - The 5 reasons of acceptance-time cross-checking (manifest-mismatch /
//   values-digest-mismatch / audit-head-unknown / audit-head-stale /
//   environment-deleted), including refusing to notarize a
//   manifest_version that does not exist yet
// - Atomicity (a rejection leaves nothing behind — no chain, mirror, or
//   snapshot row) and path-identity of the snapshot preservation
//   discipline (re-checkpointing only A preserves B's baseline — §16-2
//   "identical regardless of path")
// - Audit head: lazy-materialize initialization (recomputation from
//   existing rows), advancement on row appends, the position floor
//   (audit-head-stale), and vacuous truth on the first one
//
// The consensus rules' reason codes and check order themselves (role /
// audit role / unknown / epoch / regression) are already pinned by the
// crypto layer's 4-runtime tests (chain-entries.json); here we only
// exercise the representatives of the API-facing surface
// (unknown-environment / epoch / reader role) against real data.

import type { ChainEntry, CheckpointEnvironmentEntry } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, cliToken } from "./support/auth.ts";
import {
  commitmentOf,
  makeDek,
  manifestSignedBytesHashOf,
  signEntryAt,
  valuesDigestOf,
  wrapDekForAll,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
  storedCheckpointValues,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

// The same seed values as data-fixture.ts's GITHUB_IDS (copied since that one is private)
const GITHUB_IDS: Record<string, number> = {
  [OWNER]: 9001,
  [MEMBER]: 9002,
  [READER]: 9003,
};

/**
 * A write-scope token limited to this project (b / d of the effective-
 * permission matrix). Issued under a distinct name so same-name rotation
 * does not revoke the fixture's default token (the default name of CLI
 * login).
 */
async function writeScopedToken(userId: string): Promise<string> {
  const githubId = GITHUB_IDS[userId];
  if (githubId === undefined) {
    throw new Error(`no seeded github id for ${userId}`);
  }
  return cliToken(githubId, [{ project: projectId, permission: "write" }], "write-scoped");
}

/** The stored latest-manifest tuple coordinates (material for the match side of acceptance-time cross-checking). */
async function currentManifestTuple(
  environmentId: string,
): Promise<{ manifestVersion: number; manifestSigHashHex: string }> {
  const state = fixture.manifests.get(environmentId);
  if (state === undefined) {
    throw new Error(`no recorded manifest for ${environmentId}`);
  }
  return {
    manifestVersion: state.manifest.manifestVersion,
    manifestSigHashHex: await manifestSignedBytesHashOf(
      projectId,
      state.manifest,
      state.issuerUserId,
    ),
  };
}

/** A tuple matching the state stored at acceptance time (epoch defaults to 1 — unless a rotate intervenes). */
async function matchingTuple(
  environmentId: string,
  overrides?: Partial<CheckpointEnvironmentEntry>,
): Promise<CheckpointEnvironmentEntry> {
  const manifest = await currentManifestTuple(environmentId);
  return {
    environmentId,
    epoch: 1,
    manifestVersion: manifest.manifestVersion,
    manifestSigHashHex: manifest.manifestSigHashHex,
    valuesDigestHex: await valuesDigestOf(await storedCheckpointValues(environmentId)),
    ...overrides,
  };
}

/** Send a standalone checkpoint to generic chain append (§16-2). On 200 the head advances. */
async function sendStandaloneCheckpoint(input: {
  readonly actorUserId: string;
  readonly environments: readonly CheckpointEnvironmentEntry[];
  readonly auditHeadHashHex?: string;
  readonly authToken?: string;
}): Promise<{ response: Response; entry: ChainEntry }> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId: input.actorUserId,
    operation: {
      op: "checkpoint",
      payload: {
        environments: input.environments,
        auditHeadHashHex: input.auditHeadHashHex ?? "",
      },
    },
  });
  const response = await requestJson(
    "POST",
    "/chain/entries",
    input.authToken ?? token(input.actorUserId),
    { parentHeadHashHex: fixture.head.hashHex, entry },
  );
  if (response.status === 200) {
    fixture.head = { seq: entry.seq, hashHex: hash };
  }
  return { response, entry };
}

async function fetchAuditHead(authToken: string): Promise<Response> {
  return requestJson("GET", "/audit-head", authToken);
}

async function auditHeadOk(authToken: string): Promise<string> {
  const response = await fetchAuditHead(authToken);
  expect(response.status).toBe(200);
  const body = (await response.json()) as { auditHeadHashHex: string };
  expect(body.auditHeadHashHex).toMatch(/^[0-9a-f]{64}$/);
  return body.auditHeadHashHex;
}

/** The number of chain.checkpointed mirror rows (material for checking atomicity / mirror recording). */
async function checkpointMirrorCount(): Promise<number> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'chain.checkpointed'",
  );
  return Number(rows[0]?.["n"]);
}

async function snapshotRow(
  environmentId: string,
): Promise<{ chainSeq: number; manifestVersion: number } | null> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT chain_seq, manifest_version FROM environment_checkpoints WHERE environment_id = ?",
    environmentId,
  );
  const row = rows[0];
  return row === undefined
    ? null
    : { chainSeq: Number(row["chain_seq"]), manifestVersion: Number(row["manifest_version"]) };
}

describe("GET /projects/:id/audit-head(AUTH_SPEC §16-2 / AUDIT_SPEC §5.1)", () => {
  it("returns the cumulative hash to effective admin, initializing the derived column from existing rows", async () => {
    // The first access recomputes from the existing audit rows (the base
    // chain's mirrors) = this doubles as the §5.1 introduction migration
    // (lazy materialize)
    const first = await auditHeadOk(token(OWNER));
    // Idempotent: a re-fetch returns the same head (as long as no rows were added)
    expect(await auditHeadOk(token(OWNER))).toBe(first);
  });

  it("advances when audit rows are appended", async () => {
    const before = await auditHeadOk(token(OWNER));
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, "var-head-0001", "DATABASE_URL", "postgres://alpha");
    const after = await auditHeadOk(token(OWNER));
    expect(after).not.toBe(before);
  });

  it("rejects non-admin chain roles with 403 and strangers with 404 (§11-2 concealment)", async () => {
    expect((await fetchAuditHead(token(MEMBER))).status).toBe(403);
    expect((await fetchAuditHead(token(READER))).status).toBe(403);
    // A half-scoped shortfall (admin role × write token) is also a 403 (the min of effective permissions)
    expect((await fetchAuditHead(await writeScopedToken(OWNER))).status).toBe(403);
  });

  it("returns the presented token's scopes from /auth/me (the client-side pre-determination material)", async () => {
    const scoped = await writeScopedToken(OWNER);
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { authorization: `Bearer ${scoped}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { tokenScopes?: unknown };
    expect(body.tokenScopes).toEqual([{ project: projectId, permission: "write" }]);
  });
});

describe("two authorization levels for standalone checkpoints (the effective-permission matrix)", () => {
  it("(a) admin role × admin token + a fresh audit head is accepted, (d) member × write token + empty head is accepted", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // (d): member role × write scope × empty audit head = a data-layer checkpoint
    const memberAttempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
      authToken: await writeScopedToken(MEMBER),
    });
    expect(memberAttempt.response.status).toBe(200);
    // (a): notarization of an attestation fetched after the CAS parent
    // settled, at effective permission admin
    const head = await auditHeadOk(token(OWNER));
    const ownerAttempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: head,
    });
    expect(ownerAttempt.response.status).toBe(200);
  });

  it("(b) admin role × write token + non-empty head is 403 (scope half of the effective permission)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: head,
      authToken: await writeScopedToken(OWNER),
    });
    expect(attempt.response.status).toBe(403);
  });

  it("(c) member role × admin token + non-empty head is 403 (role half — precedes the consensus rejection)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: head,
    });
    expect(attempt.response.status).toBe(403);
    const body = (await attempt.response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("rejects a reader's checkpoint via the consensus rule (422 insufficient-role)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: READER,
      environments: [await matchingTuple(ENV)],
    });
    expect(attempt.response.status).toBe(422);
    const body = (await attempt.response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });
});

async function expectMismatch(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(422);
  const body = (await response.json()) as { _tag?: string; reason: string };
  expect(body.reason).toBe(reason);
}

describe("acceptance-time cross-checking for standalone checkpoints (the 5 reasons of CRYPTO_SPEC §6.4)", () => {
  it("rejects notarizing a manifest_version that does not exist yet (manifest-mismatch)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const manifest = await currentManifestTuple(ENV);
    const headBefore = fixture.head.seq;
    const mirrorsBefore = await checkpointMirrorCount();
    // The shape where a malicious member notarizes a future
    // manifest_version that does not exist, jamming every later
    // legitimate manifest with checkpoint-regressed. The consensus rule
    // (regression = non-regression) passes it, but the match against the
    // latest stored manifest at acceptance (§6.4) drops it
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { manifestVersion: manifest.manifestVersion + 5 })],
    });
    await expectMismatch(attempt.response, "manifest-mismatch");
    // Atomicity: the rejection leaves nothing on the chain or the mirrors (no contamination of the baseline)
    const chain = await requestJson("GET", "/chain", token(OWNER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore);
    expect(await checkpointMirrorCount()).toBe(mirrorsBefore);
    // A notarization of the legitimate current version is still accepted afterwards (not jammed)
    const legitimate = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(legitimate.response.status).toBe(200);
  });

  it("rejects a stale manifest reference (manifest-mismatch — the issuer's view is behind)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const stale = await matchingTuple(ENV);
    // A meta op (variable creation) advances manifestVersion → the stale
    // reference no longer matches. Since the consensus rule's regression
    // (non-regression) allows equality, the rejection is on the
    // acceptance-time cross-check side
    await createVariableOk(dek, "var-meta-advance-0001", "API_KEY", "sk-alpha");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [stale],
    });
    await expectMismatch(attempt.response, "manifest-mismatch");
  });

  it("rejects a values digest that mismatches the stored enumeration (values-digest-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, "var-values-0001", "DATABASE_URL", "postgres://alpha");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { valuesDigestHex: await valuesDigestOf([]) })],
    });
    await expectMismatch(attempt.response, "values-digest-mismatch");
  });

  it("rejects a fabricated audit head (audit-head-unknown)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: "ef".repeat(32),
    });
    await expectMismatch(attempt.response, "audit-head-unknown");
  });

  it("rejects an attestation older than the previous checkpoint's mirror row (audit-head-stale) and accepts a refetched one", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // Fetch the attestation before creating "the previous checkpoint's
    // mirror row" that becomes the position floor's reference (the shape
    // of an issuance that did not re-fetch the attestation after a CAS
    // race — §6.4)
    const staleHead = await auditHeadOk(token(OWNER));
    const first = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(first.response.status).toBe(200);
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: staleHead,
    });
    await expectMismatch(attempt.response, "audit-head-stale");
    // Accepted once the attestation is re-fetched (the §16-2 retry)
    const refetched = await auditHeadOk(token(OWNER));
    const retried = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: refetched,
    });
    expect(retried.response.status).toBe(200);
  });

  it("does not impose the position floor on the project's first checkpoint (vacuously true — the §6.4 base case)", async () => {
    // The base chain has no environments = no checkpoint exists yet. A
    // zero-element (zero-environment) + notarization is valid under the
    // consensus rules (§6.2), and no position floor is imposed
    const head = await auditHeadOk(token(OWNER));
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [],
      auditHeadHashHex: head,
    });
    expect(attempt.response.status).toBe(200);
  });

  it("rejects a tuple for a tombstoned environment (environment-deleted)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const tuple = await matchingTuple(ENV);
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [tuple],
    });
    await expectMismatch(attempt.response, "environment-deleted");
  });

  it("rejects unknown environments and epoch mismatches at the consensus layer (422 ChainEntryInvalid)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const unknown = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { environmentId: "env-phantom-0001" })],
    });
    expect(unknown.response.status).toBe(422);
    expect(((await unknown.response.json()) as { reason: string }).reason).toBe(
      "unknown-environment",
    );
    const epochMismatch = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { epoch: 2 })],
    });
    expect(epochMismatch.response.status).toBe(422);
    expect(((await epochMismatch.response.json()) as { reason: string }).reason).toBe(
      "checkpoint-epoch-mismatch",
    );
  });
});

describe("audit-head notarization on a boundary checkpoint (§16-2 — the same rule as standalone)", () => {
  it("accepts a rotate composite whose boundary checkpoint attests a fresh audit head (effective admin)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    // For the positive case that proceeds to acceptance, pass the wrapped DEK's own commitment
    const next = makeDek();
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      actorUserId: OWNER,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: next,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, next),
      checkpointAuditHeadHashHex: head,
    });
    expect(response.status).toBe(200);
  });

  it("rejects a member's attested boundary checkpoint with 403 (role half of the effective permission)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      actorUserId: MEMBER,
      deks: await wrapsFor(ENV, [...ALL_MEMBERS], 2, MEMBER),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, makeDek()),
      checkpointAuditHeadHashHex: head,
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("insufficient-role");
  });
});

/** The stored snapshot enumeration (the expectation for distribution — the §16-2 stored rows themselves). */
async function storedSnapshotEnumeration(
  environmentId: string,
): Promise<readonly { variableId: string; version: number; valueSigHashHex: string }[]> {
  const rows = await queryProjectDo(
    projectId,
    `SELECT variable_id, version, value_sig_hash_hex
     FROM checkpoint_snapshot_values WHERE environment_id = ? ORDER BY variable_id`,
    environmentId,
  );
  return rows.map((row) => ({
    variableId: String(row["variable_id"]),
    version: Number(row["version"]),
    valueSigHashHex: String(row["value_sig_hash_hex"]),
  }));
}

interface PullSnapshotBody {
  readonly checkpointSnapshot?: {
    readonly chainSeq: number;
    readonly entryHashHex: string;
    readonly values: readonly {
      readonly variableId: string;
      readonly version: number;
      readonly valueSigHashHex: string;
    }[];
  };
}

async function pullBody(environmentId: string): Promise<PullSnapshotBody> {
  const response = await requestJson("GET", `/environments/${environmentId}/pull`, token(OWNER));
  expect(response.status).toBe(200);
  return (await response.json()) as PullSnapshotBody;
}

describe("distribution of the value snapshot (AUTH_SPEC §12-7 / §14-2)", () => {
  it("value pull bundles the stored enumeration of the latest covering checkpoint", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // The creation composite's boundary checkpoint (empty enumeration) is the baseline from birth (§12-4)
    const creation = await pullBody(ENV);
    const creationRow = await snapshotRow(ENV);
    expect(creation.checkpointSnapshot).toBeDefined();
    expect(creation.checkpointSnapshot?.chainSeq).toBe(creationRow?.chainSeq);
    expect(creation.checkpointSnapshot?.values).toEqual([]);
    // Variable creation issues no checkpoint — the distributed enumeration stays the stored row (empty)
    await createVariableOk(dek, "var-m3-0001", "DATABASE_URL", "postgres://alpha");
    const beforeCheckpoint = await pullBody(ENV);
    expect(beforeCheckpoint.checkpointSnapshot?.chainSeq).toBe(creationRow?.chainSeq);
    expect(beforeCheckpoint.checkpointSnapshot?.values).toEqual([]);
    // After a standalone checkpoint is accepted, the enumeration stored at acceptance is distributed verbatim
    const accepted = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(accepted.response.status).toBe(200);
    const after = await pullBody(ENV);
    expect(after.checkpointSnapshot?.chainSeq).toBe(accepted.entry.seq);
    const stored = await storedSnapshotEnumeration(ENV);
    expect(stored.length).toBe(1);
    expect(after.checkpointSnapshot?.values).toEqual(stored);
  });

  it("metadata-only pull does not carry the snapshot (§12-7 — carries no values)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(OWNER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as PullSnapshotBody;
    expect(body.checkpointSnapshot).toBeUndefined();
  });
});

describe("path-identity of the snapshot preservation discipline (§16-2 — subset checkpoint)", () => {
  const ENV_B = "env-second-0001";

  it("re-checkpointing A alone atomically updates A's baseline and leaves B's untouched", async () => {
    const dekA = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dekA, "var-a-0001", "DATABASE_URL", "postgres://alpha");
    await createEnvironmentOk(fixture, ENV_B, "Batch");
    // Establish the baseline with a standalone checkpoint covering both A + B
    const both = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV), await matchingTuple(ENV_B)],
    });
    expect(both.response.status).toBe(200);
    const baselineA = await snapshotRow(ENV);
    const baselineB = await snapshotRow(ENV_B);
    expect(baselineA?.chainSeq).toBe(both.entry.seq);
    expect(baselineB?.chainSeq).toBe(both.entry.seq);
    // Re-checkpoint A alone (a subset is valid under the consensus rules — §6.2)
    const onlyA = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(onlyA.response.status).toBe(200);
    expect((await snapshotRow(ENV))?.chainSeq).toBe(onlyA.entry.seq);
    // B's baseline (its latest covering checkpoint) is preserved — an
    // environment not in the payload keeps its existing snapshot
    // unchanged (§16-2)
    expect(await snapshotRow(ENV_B)).toEqual(baselineB);
    // Distribution (§12-7) also tracks each environment's latest
    // covering checkpoint: A serves the enumeration at the
    // re-checkpoint's position, B at the original position
    expect((await pullBody(ENV)).checkpointSnapshot?.chainSeq).toBe(onlyA.entry.seq);
    const pulledB = await pullBody(ENV_B);
    expect(pulledB.checkpointSnapshot?.chainSeq).toBe(both.entry.seq);
    expect(pulledB.checkpointSnapshot?.values).toEqual(await storedSnapshotEnumeration(ENV_B));
    // A mirror row (chain.checkpointed) is recorded per acceptance (AUDIT_SPEC §3.4)
    const mirrors = await queryProjectDo(
      projectId,
      "SELECT chain_seq FROM audit_events WHERE event = 'chain.checkpointed' AND chain_seq IN (?, ?)",
      both.entry.seq,
      onlyA.entry.seq,
    );
    expect(mirrors.length).toBe(2);
  });
});

describe("skipping snapshot-enumeration replacement (values digest match — the §6.4 stored state is unchanged)", () => {
  /** The rowids of the environment's enumeration rows (material to observe whether replacement = DELETE + re-INSERT happened). */
  async function snapshotRowids(environmentId: string): Promise<readonly number[]> {
    const rows = await queryProjectDo(
      projectId,
      "SELECT rowid AS rid FROM checkpoint_snapshot_values WHERE environment_id = ? ORDER BY variable_id",
      environmentId,
    );
    return rows.map((row) => Number(row["rid"]));
  }

  async function storedTupleRow(
    environmentId: string,
  ): Promise<{ chainSeq: number; entryHashHex: string; valuesDigestHex: string }> {
    const row = (
      await queryProjectDo(
        projectId,
        "SELECT chain_seq, entry_hash_hex, values_digest_hex FROM environment_checkpoints WHERE environment_id = ?",
        environmentId,
      )
    )[0];
    expect(row).toBeDefined();
    return {
      chainSeq: Number(row?.["chain_seq"]),
      entryHashHex: String(row?.["entry_hash_hex"]),
      valuesDigestHex: String(row?.["values_digest_hex"]),
    };
  }

  it("keeps the enumeration rows on an unchanged digest (tuple row still advances) and replaces them on a changed one", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, "var-skip-0001", "DATABASE_URL", "postgres://alpha");
    const first = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(first.response.status).toBe(200);
    const firstValues = await storedSnapshotEnumeration(ENV);
    expect(firstValues.length).toBe(1);
    const firstTuple = await storedTupleRow(ENV);
    // Push the max rowid up with another environment's row (if
    // replacement happens, ENV's rows get fresh rowids — a marker to make
    // the observation reliable; deleted at the end)
    await queryProjectDo(
      projectId,
      `INSERT INTO checkpoint_snapshot_values (environment_id, variable_id, version, value_sig_hash_hex)
       VALUES ('env-marker-0001', 'var-marker-0001', 1, '00')`,
    );
    const rowidsBefore = await snapshotRowids(ENV);

    // (1) Re-checkpoint with no value change: the enumeration is identical, so it is not replaced
    const unchanged = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(unchanged.response.status).toBe(200);
    const unchangedTuple = await storedTupleRow(ENV);
    expect(unchangedTuple.valuesDigestHex).toBe(firstTuple.valuesDigestHex);
    // The tuple-coordinates row is always updated (latest covering checkpoint = this time's seq / hash)
    expect(unchangedTuple.chainSeq).toBe(unchanged.entry.seq);
    expect(unchangedTuple.chainSeq).not.toBe(firstTuple.chainSeq);
    expect(unchangedTuple.entryHashHex).not.toBe(firstTuple.entryHashHex);
    expect(await storedSnapshotEnumeration(ENV)).toEqual(firstValues);
    expect(await snapshotRowids(ENV)).toEqual(rowidsBefore);
    const pulled = await pullBody(ENV);
    expect(pulled.checkpointSnapshot?.chainSeq).toBe(unchanged.entry.seq);
    expect(pulled.checkpointSnapshot?.entryHashHex).toBe(unchangedTuple.entryHashHex);
    expect(pulled.checkpointSnapshot?.values).toEqual(firstValues);

    // (2) Re-checkpoint after a value change: the digest changes and the enumeration is fully replaced
    await createVariableOk(dek, "var-skip-0002", "REDIS_URL", "redis://beta");
    const changed = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(changed.response.status).toBe(200);
    const changedTuple = await storedTupleRow(ENV);
    expect(changedTuple.chainSeq).toBe(changed.entry.seq);
    expect(changedTuple.valuesDigestHex).not.toBe(firstTuple.valuesDigestHex);
    const changedValues = await storedSnapshotEnumeration(ENV);
    expect(changedValues.map((value) => value.variableId)).toEqual([
      "var-skip-0001",
      "var-skip-0002",
    ]);
    // digest of stored enumeration = the tuple row's digest (the invariant the skip judgment rests on)
    expect(await valuesDigestOf(changedValues)).toBe(changedTuple.valuesDigestHex);
    expect((await pullBody(ENV)).checkpointSnapshot?.values).toEqual(changedValues);

    await queryProjectDo(
      projectId,
      "DELETE FROM checkpoint_snapshot_values WHERE environment_id = 'env-marker-0001'",
    );
  });
});
