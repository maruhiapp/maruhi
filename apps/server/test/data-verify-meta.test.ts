// Integration tests for the data-plane API (AUTH_SPEC §12) —
// acceptance verification of meta statements (the §12-5 meta rules =
// CRYPTO_SPEC §4.2).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// The shared fixture and helpers live in support/data-scenario.ts.

import type { ChainEntry } from "@maruhi/crypto";
import { verifyChainWithHistory, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { MAX_VERSIONS_PER_VARIABLE } from "../src/policy.ts";
import { metaVersionsExceeded } from "../src/quotas.ts";
import { metaSignedBytesHashOf, signMetaStatementAs, vectorKeyOf } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  hashOf,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
  varStatements,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** Side-effect-freeness on rejection: statement rows, the variable-name cache, and audits do not change. */
async function expectNoMetaSideEffects(expectedMetaVersions: readonly number[]): Promise<void> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? ORDER BY meta_version",
    ENV,
    VAR,
  );
  expect(rows.map((row) => row["meta_version"])).toEqual([...expectedMetaVersions]);
  // The invariant against the count of accepted meta ops (the rename
  // path branches into var.renamed / var.schema_reissued on whether the
  // name changed — AUDIT_SPEC §3.3. Count both so the invariant does
  // not silently break if a name-unchanged acceptance case is added
  // later)
  const renamedAudits = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n FROM audit_events WHERE event IN ('var.renamed', 'var.schema_reissued', 'var.deleted')",
  );
  expect(renamedAudits[0]?.["n"]).toBe(Math.max(0, expectedMetaVersions.length - 1));
}

describe("acceptance verification of meta statements (the §12-5 meta rules = CRYPTO_SPEC §4.2)", () => {
  it("accepts the create → rename → delete statement chain and keeps distributing the tombstone", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Snapshot the creation statement (metaVersion 1) before the rename overwrites it
    const created = varStatements.get(VAR);
    if (created === undefined) throw new Error("missing recorded statement");
    const renamed = await renameVariableRequest(VAR, "DB_URL", MEMBER);
    expect(renamed.status).toBe(204);

    // A pull after the rename distributes the metaVersion-2 statement + author
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: {
        statement: {
          name: string;
          status: string;
          metaVersion: number;
          prevMetaSigHashHex: string;
          authorUserId: string;
        };
      }[];
      deletedVariables: unknown[];
    };
    expect(body.variables[0]?.statement).toMatchObject({
      name: "DB_URL",
      status: "active",
      metaVersion: 2,
      authorUserId: MEMBER,
    });
    expect(body.deletedVariables).toEqual([]);

    // Deletion: tombstone + all versions deleted. The deleted
    // statement (name keeps the just-prior active name) keeps being
    // stored and distributed (§12-5)
    const removed = await deleteVariableRequest(VAR, MEMBER);
    expect(removed.status).toBe(204);
    const afterDelete = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const deletedBody = (await afterDelete.json()) as {
      variables: unknown[];
      deletedVariables: {
        variableId: string;
        name: string;
        status: string;
        metaVersion: number;
        authorUserId: string;
        authorKeyFingerprintHex: string;
      }[];
    };
    expect(deletedBody.variables).toEqual([]);
    expect(deletedBody.deletedVariables).toEqual([
      expect.objectContaining({
        variableId: VAR,
        name: "DB_URL",
        status: "deleted",
        metaVersion: 3,
        authorUserId: MEMBER,
        authorKeyFingerprintHex: vectorKeyOf(MEMBER).key_fingerprint_hex,
      }),
    ]);

    // Statement rows (the §12-5 stored rows): per metaVersion they
    // keep the author, declared head, prev, and server-recomputed hash
    const rows = await queryProjectDo(
      projectId,
      `SELECT meta_version, name, status, prev_meta_sig_hash_hex, signed_bytes_hash_hex, author_user_id, author_key_fingerprint
       FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? ORDER BY meta_version`,
      ENV,
      VAR,
    );
    expect(rows.map((row) => [row["meta_version"], row["name"], row["status"]])).toEqual([
      [1, "DATABASE_URL", "active"],
      [2, "DB_URL", "active"],
      [3, "DB_URL", "deleted"],
    ]);
    expect(rows[0]?.["signed_bytes_hash_hex"]).toBe(
      await metaSignedBytesHashOf(projectId, created.statement, MEMBER),
    );
    expect(rows.every((row) => row["author_user_id"] === MEMBER)).toBe(true);
  });

  it("enforces the metaVersion CAS: only latest + 1, returning the number only (409 §12-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const created = varStatements.get(VAR);
    if (created === undefined) throw new Error("missing recorded statement");
    // Attesting metaVersion 3 (latest is 1) → 409 currentMetaVersion
    // 1. The winner's signed_bytes hash is not carried (the §12-5 409
    // discipline)
    const stale = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 3,
      prevMetaSigHashHex: "cd".repeat(32),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: stale, manifest: unsignedManifest() },
    );
    expect(response.status).toBe(409);
    const staleBody = (await response.json()) as Record<string, unknown>;
    expect(staleBody).toMatchObject({ currentMetaVersion: 1 });
    expect(Object.keys(staleBody).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);
    await expectNoMetaSideEffects([1]);
  });

  it("rejects non-NFC names with 422 NameNotNfc on every statement path (§12-1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // An NFD (combining-character) name — the server only inspects, never normalizes (compatible with byte-exact signatures)
    const nfdName = "CAFE\u0301_URL";
    expect(nfdName.normalize("NFC")).not.toBe(nfdName);

    // Variable creation
    const created = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, nfdName),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(created.status).toBe(422);
    expect((await created.json()) as Record<string, unknown>).toMatchObject({
      _tag: "NameNotNfc",
    });
    await expectNoMetaSideEffects([]);

    // Variable rename
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: await nextVariableStatement({
          variableId: VAR,
          name: nfdName,
          status: "active",
          authorUserId: MEMBER,
        }),
        manifest: unsignedManifest(),
      },
    );
    expect(renamed.status).toBe(422);
    await expectNoMetaSideEffects([1]);

    // Composite environment creation (bundled statement) — the chain entry is not appended either (atomicity)
    const headBefore = fixture.head;
    const response = await createEnvironmentWith(
      fixture,
      "env-nfd-0002",
      nfdName,
      await wrapsFor("env-nfd-0002", ALL_MEMBERS),
    );
    expect(response.status).toBe(422);
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
  });

  it("requires the delete statement to keep the last active name (422 PayloadMismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const wrongName = await nextVariableStatement({
      variableId: VAR,
      name: "SOMETHING_ELSE",
      status: "deleted",
      authorUserId: MEMBER,
    });
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: wrongName, manifest: unsignedManifest() },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("name");
    // The variable was not deleted
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(((await pull.json()) as { variables: unknown[] }).variables.length).toBe(1);
    await expectNoMetaSideEffects([1]);
  });

  it("rejects a statement signed by someone other than the caller (422 signature-invalid)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER carries in a rename signed by OWNER → the verification
    // key is the calling principal's (MEMBER's) acceptance-time chain
    // key, so it fails (refusing to carry someone else's signature)
    const ownerSigned = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: OWNER,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: ownerSigned, manifest: unsignedManifest() },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    await expectNoMetaSideEffects([1]);
  });

  it("rejects statements whose declared head predates the author's membership or is unknown (§12-5 items 2-3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const created = varStatements.get(VAR);
    if (created === undefined) throw new Error("missing recorded statement");
    const prevHash = await metaSignedBytesHashOf(projectId, created.statement, MEMBER);

    // (a) Declared head = genesis (seq 1). Since MEMBER's add_member
    // is seq 2, they were not a member at that head →
    // chain-head-state-mismatch. Meta does not check the environment's
    // existence (the §12-4 asymmetry), so the rejection reason reduces
    // to membership only
    const beforeMembership = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: prevHash,
      chainHeadHashHex: await hashOf(1),
      chainHeadSeq: 1,
    });
    const notMember = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: beforeMembership, manifest: unsignedManifest() },
    );
    expect(notMember.status).toBe(422);
    expect(((await notMember.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // (b) An existent seq × mismatched hash → chain-head-unknown
    const unknownHead = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: prevHash,
      chainHeadHashHex: "ee".repeat(32),
      chainHeadSeq: fixture.head.seq,
    });
    const mismatch = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: unknownHead, manifest: unsignedManifest() },
    );
    expect(mismatch.status).toBe(422);
    expect(((await mismatch.json()) as { reason: string }).reason).toBe("chain-head-unknown");

    // (c) A prev mismatch (signature valid) → chain-head-state-mismatch
    const wrongPrev = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: "cd".repeat(32),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const prevMismatch = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: wrongPrev, manifest: unsignedManifest() },
    );
    expect(prevMismatch.status).toBe(422);
    expect(((await prevMismatch.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoMetaSideEffects([1]);
  });

  it("distributes a removed author's statement, verifiable at its in-tenure head (the §6.3 client-side verification)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: {
        variableId: string;
        statement: {
          suite: "maruhi/v1";
          name: string;
          status: "active" | "deleted";
          metaVersion: number;
          prevMetaSigHashHex: string;
          chainHeadHashHex: string;
          chainHeadSeq: number;
          signatureHex: string;
          authorUserId: string;
          authorKeyFingerprintHex: string;
        };
      }[];
    };
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing pulled variable");
    // The author info is distributed as of acceptance time (not re-derived from the current member set)
    expect(pulled.statement.authorUserId).toBe(MEMBER);

    // Client-side verification (§6.3): even on the full chain after
    // removal, the declared head lies within the membership interval so
    // it verifies under the key of that time
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedMetaStatement({
      history: verified.value.history,
      context: {
        suite: pulled.statement.suite,
        projectId,
        environmentId: ENV,
        target: { kind: "variable", variableId: pulled.variableId },
        name: pulled.statement.name,
        status: pulled.statement.status,
        metaVersion: pulled.statement.metaVersion,
        prevMetaSigHashHex: pulled.statement.prevMetaSigHashHex,
        authorUserId: pulled.statement.authorUserId,
        chainHeadHashHex: pulled.statement.chainHeadHashHex,
        chainHeadSeq: pulled.statement.chainHeadSeq,
      },
      authorKeyFingerprintHex: pulled.statement.authorKeyFingerprintHex,
      signatureHex: pulled.statement.signatureHex,
    });
    expect(result.ok).toBe(true);
  });

  it("lists deleted environments with their tombstone statement (§12-4's continued distribution)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);
    const list = await requestJson("GET", "/environments", token(READER));
    const body = (await list.json()) as {
      environments: {
        environmentId: string;
        statement: { name: string; status: string; metaVersion: number; authorUserId: string };
      }[];
    };
    expect(body.environments.length).toBe(2);
    const deleted = body.environments.find((e) => e.environmentId === ENV);
    expect(deleted?.statement).toMatchObject({
      name: "App",
      status: "deleted",
      metaVersion: 2,
      authorUserId: OWNER,
    });
    // A pull on a deleted environment is a 404 as before (tombstone)
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(404);
  });

  it("requires the composite statement to declare the pre-append head (§12-4)", async () => {
    // Create one environment first to advance the head and produce a "stale existent head"
    await createEnvironmentOk(fixture, ENV, "App");
    const staleHead = { seq: fixture.head.seq - 1, hashHex: await hashOf(fixture.head.seq - 1) };
    const deks = await wrapsFor("env-app-0002", ALL_MEMBERS);
    const headBefore = fixture.head;
    const staleStatement = await createEnvironmentStatement({
      authorUserId: OWNER,
      environmentId: "env-app-0002",
      name: "Staging",
      head: staleHead,
    });
    const response = await createEnvironmentComposite(fixture, {
      environmentId: "env-app-0002",
      name: "Staging",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      statement: staleStatement,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("statementChainHead");
    // Atomicity: no trace is left on the chain or the environment row
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
  });

  it("retries a composite creation after a head CAS conflict by re-signing both entry and statement (§12-4)", async () => {
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const stale = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: projectId, // the genesis hash = a stale head
    });
    // The CAS drops it first (the statement's declared head is stale too, but the 409 prompts a retry)
    expect(stale.status).toBe(409);
    const headBefore = { ...fixture.head };
    // The retry re-signs both the entry (changed prev) and the
    // statement (changed declared head) (the fixture helper rebuilds
    // both — §12-4)
    const retried = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
    // The stored statement's declared head is the pre-append current head (= re-signed)
    const rows = await queryProjectDo(
      projectId,
      "SELECT chain_head_seq, chain_head_hash_hex FROM environment_meta_statements WHERE environment_id = ?",
      ENV,
    );
    expect(rows[0]).toEqual({
      chain_head_seq: headBefore.seq,
      chain_head_hash_hex: headBefore.hashHex,
    });
  });

  it("caps meta versions per variable (422 meta-versions — §12-8 applied per the provisional ruling)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Since 1,000 real renames are unrealistic, raise
    // latest_meta_version directly and seed a statement row just below
    // the cap (the predecessor the prev check needs) (the seeded state
    // also preserves the storage invariant that a latest_meta_version
    // row always exists — the premise of findVariable's status JOIN)
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      "UPDATE variable_meta_statements SET meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: await signMetaStatementAs(MEMBER, projectId, {
          suite: "maruhi/v1" as const,
          environmentId: ENV,
          variableId: VAR,
          name: "DB_URL",
          status: "active" as const,
          metaVersion: MAX_VERSIONS_PER_VARIABLE + 1,
          prevMetaSigHashHex: "cd".repeat(32),
          chainHeadHashHex: fixture.head.hashHex,
          chainHeadSeq: fixture.head.seq,
        }),
        manifest: unsignedManifest(),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "meta-versions",
      limit: MAX_VERSIONS_PER_VARIABLE,
    });
  });

  it("accepts the delete statement even at the meta version cap (deleted is outside the cap)", async () => {
    // If the cap also blocked deletions, a resource that hit the cap
    // via rename spam would become permanently undeletable under any
    // role. A tombstone is the chain's terminus and adds at most one
    // row, so it is outside the cap
    expect(metaVersionsExceeded(MAX_VERSIONS_PER_VARIABLE, "active")).toBe(true);
    expect(metaVersionsExceeded(MAX_VERSIONS_PER_VARIABLE - 1, "active")).toBe(false);
    expect(metaVersionsExceeded(MAX_VERSIONS_PER_VARIABLE, "deleted")).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Since 1,000 real renames are unrealistic, raise latest and the
    // latest statement row's meta_version directly to seed the
    // cap-reached state (prev reuses the stored server-recomputed
    // hash)
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      "UPDATE variable_meta_statements SET meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    const anchorRows = await queryProjectDo(
      projectId,
      "SELECT signed_bytes_hash_hex FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    const prevHash = anchorRows[0]?.signed_bytes_hash_hex;
    if (typeof prevHash !== "string") {
      throw new Error("seeded meta statement row missing");
    }
    const deleteStatement = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      // A deleted's name keeps the just-prior active name (§4.2)
      name: "DATABASE_URL",
      status: "deleted" as const,
      metaVersion: MAX_VERSIONS_PER_VARIABLE + 1,
      prevMetaSigHashHex: prevHash,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    // Even at the cap, the bundled manifest (tombstone-including
    // digest) is required as usual (the manifest itself is outside the
    // row-count cap — §12-8: retention is the latest copy only)
    const { manifest } = await manifestForStatement(deleteStatement, MEMBER);
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: deleteStatement, manifest },
    );
    expect(removed.status).toBe(204);
    // The tombstone statement keeps being stored and distributed (§12-5)
    const tombstones = await queryProjectDo(
      projectId,
      "SELECT status, meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? AND status = 'deleted'",
      ENV,
      VAR,
    );
    expect(tombstones).toEqual([
      { status: "deleted", meta_version: MAX_VERSIONS_PER_VARIABLE + 1 },
    ]);
  });
});
