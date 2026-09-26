// Integration tests for the data-plane API (AUTH_SPEC §12) — variable
// push→pull→client-side decrypt and the metadata-only mode (AUTH_SPEC
// §12-5 / §12-7).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// The shared fixture and helpers live in support/data-scenario.ts.

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { verifyChainWithHistory, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_VALUE_CIPHERTEXT_BYTES,
  MAX_VERSIONS_PER_VARIABLE,
} from "../src/policy.ts";
import { projectBytesExceeded } from "../src/quotas.ts";
import { cliToken, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  unwrapAndDecrypt,
  valueSignedBytesHashOf,
  vectorKeyOf,
} from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  dataUrl,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("variable push→pull→client-side decrypt (§12-5 / §12-7)", () => {
  it("round-trips a value end to end: encrypt → create → pull → unwrap DEK → decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      environmentId: string;
      currentEpoch: number;
      statement: { name: string; status: string; authorUserId: string };
      variables: {
        variableId: string;
        statement: {
          variableId: string;
          name: string;
          status: string;
          metaVersion: number;
          authorUserId: string;
          authorKeyFingerprintHex: string;
        };
        value: WireEncryptedPayload;
      }[];
      deletedVariables: unknown[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(body.currentEpoch).toBe(1);
    expect(body.variables.length).toBe(1);
    expect(body.deks.length).toBe(1);
    // pull carries the statement + author info, not a bare name (§12-2 / §12-7)
    expect(body.statement).toMatchObject({ name: "App", status: "active", authorUserId: OWNER });
    expect(body.deletedVariables).toEqual([]);
    const [variable] = body.variables;
    const [wrappedDek] = body.deks;
    if (variable === undefined || wrappedDek === undefined) throw new Error("missing pull data");
    expect(variable.value.aad).toEqual(aadFor(1, 1));
    expect(variable.statement).toMatchObject({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      metaVersion: 1,
      authorUserId: MEMBER,
      authorKeyFingerprintHex: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });

    // The reader's client-side decryption (the E2EE round trip)
    const plaintext = await unwrapAndDecrypt({
      recipientUserId: READER,
      wrapped: wrappedDek,
      projectId,
      environmentId: ENV,
      payload: variable.value,
    });
    expect(plaintext).toBe("postgres://alpha");

    // Pushing a new version makes pull return only the latest (prev
    // chains to v1's signed_bytes hash — §4.1)
    const v1 = variable.value;
    const v2 = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "postgres://beta",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(push.status).toBe(200);
    await expect(push.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 1 });

    const second = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const secondBody = (await second.json()) as typeof body;
    const latest = secondBody.variables[0];
    const latestDek = secondBody.deks[0];
    if (latest === undefined || latestDek === undefined) throw new Error("missing pull data");
    expect(latest.value.aad.version).toBe(2);
    const decrypted = await unwrapAndDecrypt({
      recipientUserId: READER,
      wrapped: latestDek,
      projectId,
      environmentId: ENV,
      payload: latest.value,
    });
    expect(decrypted).toBe("postgres://beta");
  });

  it("rejects declared AAD components that mismatch the storage coordinates (422 §12-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const cases: readonly [Partial<WireEncryptedPayload["aad"]>, string][] = [
      [{ environmentId: "env-app-0002" }, "environmentId"],
      [{ variableId: "var-other" }, "variableId"],
      [{ projectId: "ab".repeat(32) }, "projectId"],
    ];
    for (const [override, field] of cases) {
      const response = await requestJson(
        "POST",
        `/environments/${ENV}/variables/${VAR}/versions`,
        token(MEMBER),
        { value: await fakePayload(MEMBER, aadFor(1, 2, override)) },
      );
      expect(response.status).toBe(422);
      const body = (await response.json()) as { field: string };
      expect(body.field).toBe(field);
    }
  });

  it("enforces the version CAS: only latest + 1 is accepted (409 §12-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // Re-attesting a known version (1) → 409 currentVersion 1
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 1)) },
    );
    expect(stale.status).toBe(409);
    // The 409 returns only currentVersion (the number) — the winner's
    // signed_bytes hash is not carried (no chain-signing onto an
    // unverified value — §12-5)
    const staleBody = (await stale.json()) as Record<string, unknown>;
    expect(staleBody).toMatchObject({ currentVersion: 1 });
    expect(Object.keys(staleBody).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);

    // A skipped number (3) is also rejected
    const skipped = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 3)) },
    );
    expect(skipped.status).toBe(409);
    await expect(skipped.json()).resolves.toMatchObject({ currentVersion: 1 });
  });

  it("creation requires version 1 (409 currentVersion 0)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 2)),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({ currentVersion: 0 });
  });

  it("serializes concurrent pushes: exactly one winner, no lost or interleaved writes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const prevHash = await valueSignedBytesHashOf(v1, MEMBER);

    const contenders = await Promise.all(
      Array.from({ length: 8 }, (_v, index) =>
        encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
          `postgres://contender-${index}`,
          { writerUserId: MEMBER, head: fixture.head, prevValueSigHashHex: prevHash },
        ),
      ),
    );
    const responses = await Promise.all(
      contenders.map((value) =>
        requestJson("POST", `/environments/${ENV}/variables/${VAR}/versions`, token(MEMBER), {
          value,
        }),
      ),
    );
    const statuses = responses.map((response) => response.status);
    expect(statuses.filter((status) => status === 200).length).toBe(1);
    expect(statuses.filter((status) => status === 409).length).toBe(7);
    for (const response of responses.filter((r) => r.status === 409)) {
      await expect(response.json()).resolves.toMatchObject({ currentVersion: 2 });
    }

    // No gaps or interleaving: version rows are only 1,2; latest is 2; the winner's ciphertext is stored
    const rows = await queryProjectDo(
      projectId,
      "SELECT version, ciphertext_hex FROM variable_versions WHERE environment_id = ? AND variable_id = ? ORDER BY version",
      ENV,
      VAR,
    );
    expect(rows.map((row) => row["version"])).toEqual([1, 2]);
    const winnerIndex = statuses.indexOf(200);
    expect(rows[1]?.["ciphertext_hex"]).toBe(contenders[winnerIndex]?.ciphertextHex);
    const variableRow = await queryProjectDo(
      projectId,
      "SELECT latest_version FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(variableRow[0]?.["latest_version"]).toBe(2);
  });

  it("accepts concurrent pushes to different variables", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const ids = ["var-a", "var-b", "var-c"];
    const firstVersions = new Map<string, WireEncryptedPayload>();
    for (const id of ids) {
      firstVersions.set(id, await createVariableOk(dek, id, `NAME_${id}`, `value-${id}`));
    }
    const values = await Promise.all(
      ids.map(async (id) => {
        const v1 = firstVersions.get(id);
        if (v1 === undefined) throw new Error("missing first version");
        return encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: id, version: 2 },
          `next-${id}`,
          {
            writerUserId: MEMBER,
            head: fixture.head,
            prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
          },
        );
      }),
    );
    const responses = await Promise.all(
      ids.map((id, index) =>
        requestJson("POST", `/environments/${ENV}/variables/${id}/versions`, token(MEMBER), {
          value: values[index],
        }),
      ),
    );
    expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
  });

  it("rejects pushes from readers with 403 insufficient-role (§6.2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(READER),
      { value: await fakePayload(READER, aadFor(1, 2)) },
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("enforces min(token scope, chain role) (§9-2 / §12-3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // A member's read scope: pull allowed, push denied (403 insufficient-permission)
    const readScope: readonly TokenScope[] = [{ project: projectId, permission: "read" }];
    const readToken = await cliToken(9002, readScope);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, readToken);
    expect(pull.status).toBe(200);
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      readToken,
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(push.status).toBe(403);
    expect(((await push.json()) as { reason: string }).reason).toBe("insufficient-permission");

    // A reader's write scope: even with sufficient scope the chain role binds (403 insufficient-role)
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const readerWrite = await cliToken(9003, writeScope);
    const readerPush = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      readerWrite,
      { value: await fakePayload(READER, aadFor(1, 2)) },
    );
    expect(readerPush.status).toBe(403);
    expect(((await readerPush.json()) as { reason: string }).reason).toBe("insufficient-role");

    // An out-of-scope project is existence-hidden (404)
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scoped = await cliToken(9002, otherScope);
    const concealed = await requestJson("GET", `/environments/${ENV}/pull`, scoped);
    expect(concealed.status).toBe(404);

    // Environment deletion requires the admin scope (403 under write.
    // The scope check precedes signature verification — §12-3 — so an
    // unsigned dummy statement suffices)
    const memberWrite = await cliToken(9001, writeScope);
    const removal = await requestJson("DELETE", `/environments/${ENV}`, memberWrite, {
      statement: {
        suite: "maruhi/v1",
        environmentId: ENV,
        name: "App",
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "cd".repeat(32),
        chainHeadHashHex: fixture.head.hashHex,
        chainHeadSeq: fixture.head.seq,
        signatureHex: "00".repeat(64),
      },
    });
    expect(removal.status).toBe(403);
    expect(((await removal.json()) as { reason: string }).reason).toBe("insufficient-permission");
  });

  it("handles variable conflicts: duplicate id, retired id, duplicate name, rename", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const duplicate = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "OTHER"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(duplicate.status).toBe(409);
    expect(((await duplicate.json()) as { reason: string }).reason).toBe("exists");

    const sameName = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, "var-other", "DATABASE_URL"),
      value: await fakePayload(MEMBER, { ...aadFor(1, 1), variableId: "var-other" }),
      manifest: unsignedManifest(),
    });
    expect(sameName.status).toBe(409);
    expect(((await sameName.json()) as { reason: string }).reason).toBe("duplicate-name");

    // AAD mismatch on the attestation at creation (§12-2): a mismatch between the statement's variableId and the aad is a 422
    const createMismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      {
        statement: await variableStatementFor(MEMBER, "var-other", "OTHER"),
        value: await fakePayload(MEMBER, aadFor(1, 1)),
        manifest: unsignedManifest(),
      },
    );
    expect(createMismatch.status).toBe(422);
    expect(((await createMismatch.json()) as { field: string }).field).toBe("variableId");

    // Rename is also subject to name uniqueness (§12-1)
    await createVariableOk(dek, "var-other", "OTHER", "other-value");
    const renameConflict = await renameVariableRequest("var-other", "DATABASE_URL", MEMBER);
    expect(renameConflict.status).toBe(409);
    expect(((await renameConflict.json()) as { reason: string }).reason).toBe("duplicate-name");

    const renamed = await renameVariableRequest(VAR, "DB_URL", MEMBER);
    expect(renamed.status).toBe(204);

    const removed = await deleteVariableRequest(VAR, MEMBER);
    expect(removed.status).toBe(204);
    const versions = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variable_versions WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(versions.length).toBe(0);

    // Reuse of a deleted ID is rejected (§12-1)
    const retired = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "REBORN"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(retired.status).toBe(409);
    expect(((await retired.json()) as { reason: string }).reason).toBe("retired");

    // A push to a deleted variable is a 404
    const pushDeleted = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(pushDeleted.status).toBe(404);
  });

  it("rejects an oversized ciphertext with 413 (§12-8)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "BIG"),
      value: await fakePayload(MEMBER, aadFor(1, 1), {
        ciphertextBytes: MAX_VALUE_CIPHERTEXT_BYTES + 1,
      }),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      limitBytes: MAX_VALUE_CIPHERTEXT_BYTES,
    });
  });

  it("caps versions per variable (422 §12-8)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Since 1,000 real pushes are unrealistic, raise latest_version
    // directly and seed a version row just below the cap (the
    // predecessor the prev check needs) (the quantity policy sits after
    // the value signature — ruling D — so a shape that passes signature
    // verification is required)
    const seededHash = "aa".repeat(32);
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
          prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
          signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
       VALUES (?, ?, ?, 'maruhi/v1', 1, ?, ?, 48, ?, ?, 1, ?, ?, ?, ?, 0)`,
      ENV,
      VAR,
      MAX_VERSIONS_PER_VARIABLE,
      "00".repeat(12),
      "ab".repeat(48),
      "bb".repeat(32),
      projectId,
      "00".repeat(64),
      seededHash,
      MEMBER,
      vectorKeyOf(MEMBER).key_fingerprint_hex,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      {
        value: await fakePayload(MEMBER, aadFor(1, MAX_VERSIONS_PER_VARIABLE + 1), {
          prevValueSigHashHex: seededHash,
        }),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "versions",
      limit: MAX_VERSIONS_PER_VARIABLE,
    });
  });

  it("caps cumulative project ciphertext bytes (422 §12-8, unit + plumbing)", async () => {
    // The pure-function judgment (do not actually generate 1 GiB)
    expect(projectBytesExceeded(MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES, 1)).toBe(true);
    expect(projectBytesExceeded(MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES - 10, 10)).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Verify the plumbing by raising only the stored byte count to the cap's level
    await queryProjectDo(
      projectId,
      "UPDATE variable_versions SET ciphertext_bytes = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
      ENV,
      VAR,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      {
        value: await fakePayload(MEMBER, aadFor(1, 2), {
          prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
        }),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "project-ciphertext-bytes",
      limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
    });
  });
});

describe("metadata-only mode (§12-7 — returns no values or DEKs)", () => {
  it("returns the statement-only material: environment + active + tombstones, no values, no deks", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-second", "REDIS_URL", "redis://alpha");
    const renamed = await renameVariableRequest(VAR, "DB_URL", MEMBER);
    expect(renamed.status).toBe(204);
    const removed = await deleteVariableRequest("var-second", MEMBER);
    expect(removed.status).toBe(204);

    const response = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      environmentId: string;
      currentEpoch: number;
      statement: { name: string; status: string; authorUserId: string };
      variables: {
        variableId: string;
        name: string;
        status: string;
        metaVersion: number;
        prevMetaSigHashHex: string;
        chainHeadHashHex: string;
        chainHeadSeq: number;
        signatureHex: string;
        authorUserId: string;
        authorKeyFingerprintHex: string;
        suite: "maruhi/v1";
      }[];
      deletedVariables: { variableId: string; name: string; status: string }[];
    };
    expect(body.environmentId).toBe(ENV);
    expect(body.currentEpoch).toBe(1);
    expect(body.statement).toMatchObject({ name: "App", status: "active", authorUserId: OWNER });
    // Active variables carry only the latest statement (after the
    // rename = metaVersion 2). No fragment of a value (ciphertext) is
    // bundled anywhere
    expect(body.variables).toEqual([
      expect.objectContaining({
        variableId: VAR,
        name: "DB_URL",
        status: "active",
        metaVersion: 2,
        authorUserId: MEMBER,
        authorKeyFingerprintHex: vectorKeyOf(MEMBER).key_fingerprint_hex,
      }),
    ]);
    expect(body.deletedVariables).toEqual([
      expect.objectContaining({ variableId: "var-second", name: "REDIS_URL", status: "deleted" }),
    ]);
    expect(body).not.toHaveProperty("deks");
    const raw = JSON.stringify(body);
    for (const forbidden of ["ciphertextHex", "nonceHex", "encHex", "prevValueSigHashHex"]) {
      expect(raw).not.toContain(forbidden);
    }

    // The distributed statement passes the §6.3 client-side
    // verification (the obligation to bundle verification material is
    // the same as the valued pull — §12-7)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing statement");
    const result = await verifyDistributedMetaStatement({
      history: verified.value.history,
      context: {
        suite: pulled.suite,
        projectId,
        environmentId: ENV,
        target: { kind: "variable", variableId: pulled.variableId },
        name: pulled.name,
        status: pulled.status as "active" | "deleted",
        metaVersion: pulled.metaVersion,
        prevMetaSigHashHex: pulled.prevMetaSigHashHex,
        authorUserId: pulled.authorUserId,
        chainHeadHashHex: pulled.chainHeadHashHex,
        chainHeadSeq: pulled.chainHeadSeq,
      },
      authorKeyFingerprintHex: pulled.authorKeyFingerprintHex,
      signatureHex: pulled.signatureHex,
    });
    expect(result.ok).toBe(true);
  });

  it("authorizes like the bulk pull (read × reader) and conceals like it (§12-3 / §11-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // Obtainable with reader (chain role) + read scope (the same row as pull — §12-3)
    const readScope: readonly TokenScope[] = [{ project: projectId, permission: "read" }];
    const readToken = await cliToken(9003, readScope);
    const allowed = await requestJson("GET", `/environments/${ENV}/pull/metadata`, readToken);
    expect(allowed.status).toBe(200);

    // Non-members get a 404 (existence hiding — §11-2)
    const stranger = await requestJson(
      "GET",
      `/environments/${ENV}/pull/metadata`,
      token(STRANGER),
    );
    expect(stranger.status).toBe(404);

    // An out-of-scope project is also 404 (existence hiding precedes via the scope check)
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scoped = await cliToken(9002, otherScope);
    const concealed = await requestJson("GET", `/environments/${ENV}/pull/metadata`, scoped);
    expect(concealed.status).toBe(404);

    // A deleted environment is a 404 (same as pull). Since READER's
    // token was replaced by readToken's re-issuance, readToken is used
    // from here on
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);
    const gone = await requestJson("GET", `/environments/${ENV}/pull/metadata`, readToken);
    expect(gone.status).toBe(404);
  });
});

describe("rejection of session-principal valued bulk pulls (the §5 capability restriction — W2b; §12-7)", () => {
  it("rejects session pulls with values regardless of the CSRF header; bearer and metadata-only stay open", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const session = await loginSession(9001);
    const headers = sessionHeaders(session);

    // A valued bulk pull is §5's explicit rejection surface (W2b —
    // audit-trail contamination via a session = eliminate the very
    // surface SECURITY_REVIEW L-1 occurs on). Since the capability
    // judgment precedes the CSRF check, it is uniformly
    // session-not-allowed even without a CSRF header
    const withoutCsrf = await SELF.fetch(dataUrl(`/environments/${ENV}/pull`), {
      headers: { cookie: headers["cookie"] ?? "" },
    });
    expect(withoutCsrf.status).toBe(403);
    const body = (await withoutCsrf.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("session-not-allowed");

    // Attaching a CSRF header yourself gives the same (same-origin XSS
    // can attach headers — design document §6. Closing this surface is
    // W2b's purpose)
    const withCsrf = await SELF.fetch(dataUrl(`/environments/${ENV}/pull`), { headers });
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as Record<string, unknown>)["reason"]).toBe(
      "session-not-allowed",
    );

    // A rejected pull records not a single var.read row (do not record
    // as read what was not read — AUDIT_SPEC §3.3)
    const reads = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(reads[0]?.["n"]).toBe(0);

    // Bearer (token principal) is unaffected (§5 — the CLI and maruhi ui are token principals)
    const bearerPull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(bearerPull.status).toBe(200);
    const readsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(readsAfter[0]?.["n"]).toBe(1);

    // Metadata-only mode is in §5's allowed enumeration (reads) and
    // records no var.read, so no CSRF header is needed either (session
    // + headerless is a 200)
    const metadata = await SELF.fetch(dataUrl(`/environments/${ENV}/pull/metadata`), {
      headers: { cookie: headers["cookie"] ?? "" },
    });
    expect(metadata.status).toBe(200);
  });
});
