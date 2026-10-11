// Integration tests for the per-environment current-ciphertext cap
// (AUTH_SPEC §12-8 — 2026-10-11 Sc-3): the latest version of every active
// variable of one environment sums to at most 8 MiB, judged on push,
// creation with a value and activation (grow-only), and a full
// environment's pull and lease fit the DO RPC frame.
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment). The fixture lives in support/data-scenario.ts.

import { describe, expect, it } from "vitest";

import {
  MAX_ENVIRONMENT_CIPHERTEXT_BYTES,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_VALUE_CIPHERTEXT_BYTES,
} from "../src/policy.ts";
import { environmentBytesExceeded } from "../src/quotas.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  valueSignedBytesHashOf,
} from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
} from "./support/data-fixture.ts";
import {
  aadFor,
  activateVariableRequest,
  createVariableOk,
  declareVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  manifestForStatement,
  registerDataScenario,
  token,
  VAR,
  variableStatementFor,
} from "./support/data-scenario.ts";
import { readyProject, requestLease, workloadKeyPair } from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

const CAP = MAX_ENVIRONMENT_CIPHERTEXT_BYTES;
const FILLER = "var-filler-0001";
/** workerd refuses a DO RPC result serialized above this (the reason for the cap). */
const RPC_FRAME_BYTES = 32 * 1024 * 1024;

/** Sets the metered size of a variable's latest version (the values themselves stay small). */
async function setLatestBytes(variableId: string, bytes: number, environmentId = ENV) {
  await queryProjectDo(
    projectId,
    `UPDATE variable_versions SET ciphertext_bytes = ?
     WHERE environment_id = ? AND variable_id = ?
       AND version = (SELECT latest_version FROM variables
                      WHERE environment_id = ? AND variable_id = ?)`,
    bytes,
    environmentId,
    variableId,
    environmentId,
    variableId,
  );
}

async function latestVersionOf(variableId: string): Promise<number> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT latest_version FROM variables WHERE environment_id = ? AND variable_id = ?",
    ENV,
    variableId,
  );
  return Number(rows[0]?.["latest_version"]);
}

/** Pushes the next version of VAR with a fake ciphertext of the given size. */
async function pushVar(input: {
  readonly version: number;
  readonly prev: WireEncryptedPayload;
  readonly bytes: number;
  readonly signer?: string;
}) {
  const value = await fakePayload(input.signer ?? MEMBER, aadFor(1, input.version), {
    ciphertextBytes: input.bytes,
    prevValueSigHashHex: await valueSignedBytesHashOf(input.prev, MEMBER),
  });
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables/${VAR}/versions`,
    token(MEMBER),
    { value },
  );
  return { response, value };
}

async function expectEnvironmentLimit(response: Response): Promise<void> {
  expect(response.status).toBe(422);
  await expect(response.json()).resolves.toEqual({
    _tag: "DataLimitExceeded",
    resource: "environment-ciphertext-bytes",
    limit: CAP,
  });
}

describe("the per-environment current-ciphertext cap (§12-8 — Sc-3)", () => {
  it("the judgment: the replaced latest leaves the sum, and only growth past the cap is refused", () => {
    expect(environmentBytesExceeded(CAP - 10, 0, 10)).toBe(false);
    expect(environmentBytesExceeded(CAP - 10, 0, 11)).toBe(true);
    // A replacement counts the difference, not the whole new value
    expect(environmentBytesExceeded(CAP, 100, 100)).toBe(false);
    expect(environmentBytesExceeded(CAP, 100, 101)).toBe(true);
    // Above the cap (a lowered constant, an import): non-growing writes land
    expect(environmentBytesExceeded(CAP + 1_000, 100, 100)).toBe(false);
    expect(environmentBytesExceeded(CAP + 1_000, 100, 16)).toBe(false);
    expect(environmentBytesExceeded(CAP + 1_000, 16, 17)).toBe(true);
  });

  it("a push reaching the cap exactly lands; one byte past it is refused with no trace", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, FILLER, "FILLER", "filler");
    await setLatestBytes(FILLER, CAP - 48);

    const atCap = await pushVar({ version: 2, prev: v1, bytes: 48 });
    expect(atCap.response.status).toBe(200);

    const past = await pushVar({ version: 3, prev: atCap.value, bytes: 49 });
    await expectEnvironmentLimit(past.response);
    expect(await latestVersionOf(VAR)).toBe(2);
    const pushedRows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.version_pushed' AND version = 3",
    );
    expect(Number(pushedRows[0]?.["n"])).toBe(0);
  });

  it("above the cap a same-size or smaller value lands (a re-encryption converges); growth is refused", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await setLatestBytes(VAR, 32);
    await createVariableOk(dek, FILLER, "FILLER", "filler");
    await setLatestBytes(FILLER, CAP + 1_000);

    const same = await pushVar({ version: 2, prev: v1, bytes: 32 });
    expect(same.response.status).toBe(200);
    const smaller = await pushVar({ version: 3, prev: same.value, bytes: 16 });
    expect(smaller.response.status).toBe(200);
    const larger = await pushVar({ version: 4, prev: smaller.value, bytes: 17 });
    await expectEnvironmentLimit(larger.response);
    expect(await latestVersionOf(VAR)).toBe(3);
  });

  it("creation with a value and activation are judged; a declared creation is not; deletion frees", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, FILLER, "FILLER", "filler");
    await setLatestBytes(FILLER, CAP - 8);

    const created = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      // The 16-byte tag alone exceeds the 8 bytes left
      ...(await creationBody(dek)),
    });
    await expectEnvironmentLimit(created);

    await declareVariableOk({ variableId: "var-declared-01", name: "DECLARED" });
    const activation = await activateVariableRequest({
      variableId: "var-declared-01",
      actorUserId: MEMBER,
      dek,
      plaintext: "x",
    });
    await expectEnvironmentLimit(activation);

    expect((await deleteVariableRequest(FILLER, MEMBER)).status).toBe(204);
    const afterDelete = await activateVariableRequest({
      variableId: "var-declared-01",
      actorUserId: MEMBER,
      dek,
      plaintext: "x",
    });
    expect(afterDelete.status).toBe(200);
  });

  it("counts only the latest version of the environment's active variables", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const v2 = await pushVar({ version: 2, prev: v1, bytes: 48 });
    expect(v2.response.status).toBe(200);
    // History: VAR's version 1
    await queryProjectDo(
      projectId,
      `UPDATE variable_versions SET ciphertext_bytes = ?
       WHERE environment_id = ? AND variable_id = ? AND version = 1`,
      CAP,
      ENV,
      VAR,
    );
    // A deleted variable
    await createVariableOk(dek, FILLER, "FILLER", "filler");
    await setLatestBytes(FILLER, CAP);
    expect((await deleteVariableRequest(FILLER, MEMBER)).status).toBe(204);
    // Another environment's current value (rows only — the meter reads no environment row)
    await queryProjectDo(
      projectId,
      `INSERT INTO variables SELECT 'env-other-0001', 'var-other-0001', name, latest_meta_version,
         latest_version, created_at, deleted_at FROM variables WHERE environment_id = ? AND variable_id = ?`,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_versions SELECT 'env-other-0001', 'var-other-0001', version, suite, epoch,
         nonce_hex, ciphertext_hex, ?, prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq,
         signature_hex, signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at
       FROM variable_versions WHERE environment_id = ? AND variable_id = ? AND version = 2`,
      CAP,
      ENV,
      VAR,
    );

    const v3 = await pushVar({ version: 3, prev: v2.value, bytes: MAX_VALUE_CIPHERTEXT_BYTES });
    expect(v3.response.status).toBe(200);
  });

  it("is judged after the value signature and before the project's cumulative cap", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const v2 = await pushVar({ version: 2, prev: v1, bytes: 48 });
    expect(v2.response.status).toBe(200);
    await createVariableOk(dek, FILLER, "FILLER", "filler");
    await setLatestBytes(FILLER, CAP);

    const foreignSignature = await pushVar({
      version: 3,
      prev: v2.value,
      bytes: 64,
      signer: OWNER,
    });
    expect(foreignSignature.response.status).toBe(422);
    expect(((await foreignSignature.response.json()) as { reason: string }).reason).toBe(
      "signature-invalid",
    );

    // Both caps exceeded (the project's through VAR's history): the environment's answers
    await queryProjectDo(
      projectId,
      `UPDATE variable_versions SET ciphertext_bytes = ?
       WHERE environment_id = ? AND variable_id = ? AND version = 1`,
      MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
      ENV,
      VAR,
    );
    await expectEnvironmentLimit(
      (await pushVar({ version: 3, prev: v2.value, bytes: 64 })).response,
    );
  });

  it("an environment at the cap answers its pull and lease in half the RPC frame, and a read is never refused for the cap", async () => {
    await readyProject();
    // VAR's own value puts the environment just above the cap: reads still answer
    await cloneFullValues(CAP / MAX_VALUE_CIPHERTEXT_BYTES);

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER));
    expect(pull.status).toBe(200);
    const pullBody = await pull.text();
    expect(pullBody.length).toBeGreaterThan(2 * CAP);
    expect(pullBody.length).toBeLessThan(RPC_FRAME_BYTES / 2 + 1024 * 1024);

    const { publicKeyHex } = await workloadKeyPair();
    const lease = await requestLease({
      oidcToken: await makeOidcToken(),
      ephemeralPubHex: publicKeyHex,
    });
    expect(lease.status).toBe(200);
    const leaseBody = await lease.text();
    expect(leaseBody.length).toBeGreaterThan(2 * CAP);
    expect(leaseBody.length).toBeLessThan(RPC_FRAME_BYTES / 2 + 1024 * 1024);
  });
});

/** A creation request whose value is the 16-byte tag plus one byte (a real signature). */
async function creationBody(dek: Uint8Array) {
  const variableId = "var-created-01";
  const value = await encryptValue(
    dek,
    {
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId(variableId),
      version: 1,
    },
    "x",
    { writerUserId: MEMBER, head: fixture.head },
  );
  const statement = await variableStatementFor(MEMBER, variableId, "CREATED");
  const { manifest } = await manifestForStatement(statement, MEMBER);
  return { statement, value, manifest };
}

/** Clones VAR into `count` variables of real 64 KiB ciphertexts (the rows a pull serializes). */
async function cloneFullValues(count: number): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    const variableId = `var-full-${String(index).padStart(4, "0")}`;
    await queryProjectDo(
      projectId,
      `INSERT INTO variables SELECT environment_id, ?, name || ?, latest_meta_version,
         latest_version, created_at + ?, deleted_at FROM variables
       WHERE environment_id = ? AND variable_id = ?`,
      variableId,
      `_${index}`,
      index + 1,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_meta_statements SELECT environment_id, ?, meta_version, suite,
         name || ?, status, prev_meta_sig_hash_hex, chain_head_hash_hex, chain_head_seq,
         signature_hex, signed_bytes_hash_hex, author_user_id, author_key_fingerprint, created_at,
         layout_version, var_type, required, description, max_age_days
       FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?`,
      variableId,
      `_${index}`,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_versions SELECT environment_id, ?, version, suite, epoch, nonce_hex,
         lower(hex(randomblob(?))), ?, prev_value_sig_hash_hex, chain_head_hash_hex,
         chain_head_seq, signature_hex, signed_bytes_hash_hex, writer_user_id,
         writer_key_fingerprint, created_at
       FROM variable_versions WHERE environment_id = ? AND variable_id = ?`,
      variableId,
      MAX_VALUE_CIPHERTEXT_BYTES,
      MAX_VALUE_CIPHERTEXT_BYTES,
      ENV,
      VAR,
    );
  }
}
