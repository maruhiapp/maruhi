// Integration tests for the data-plane API (AUTH_SPEC §12) — suite
// persistence, quantity policy, judgment order, and error-contract
// derivation (AUTH_SPEC §12-2 / §12-3 / §12-8).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// The shared fixture and helpers live in support/data-scenario.ts.

import {
  auditGroup,
  deksGroup,
  DekWrapExistsError,
  environmentsGroup,
  membershipGroup,
  rotationGroup,
  schemaPolicyGroup,
  variablesGroup,
} from "@maruhi/api-schema";
import { Cause, Effect, Exit } from "effect";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";
import { describe, expect, it } from "vitest";

import { dataRejectionError, unwrapDataOutcome } from "../src/data-http.ts";
import type { DataRejection } from "../src/data-plane.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_DEK_WRAPS_PER_REQUEST,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
} from "../src/policy.ts";
import { wrapRowsExceeded } from "../src/quotas.ts";
import { makeDek, signEntryAt, wrapDekForAll } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fakePayload,
  fixture,
  registerDataScenario,
  token,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
  variableStatementFor,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("suite persistence and the wire (§12-2 / CRYPTO_SPEC §2 design principle 4)", () => {
  it("stores the suite on versions and wraps and returns it on every distribution path", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const versionRows = await queryProjectDo(
      projectId,
      "SELECT suite FROM variable_versions WHERE environment_id = ?",
      ENV,
    );
    expect(versionRows.map((row) => row["suite"])).toEqual(["maruhi/v1"]);
    const wrapRows = await queryProjectDo(
      projectId,
      "SELECT DISTINCT suite FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    expect(wrapRows.map((row) => row["suite"])).toEqual(["maruhi/v1"]);

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: { suite: string } }[];
      deks: { suite: string }[];
    };
    expect(body.variables[0]?.value.suite).toBe("maruhi/v1");
    expect(body.deks[0]?.suite).toBe("maruhi/v1");
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    const mineBody = (await mine.json()) as { deks: { suite: string }[] };
    expect(mineBody.deks[0]?.suite).toBe("maruhi/v1");
  });

  it("rejects wraps without a suite or with an unpinned suite (400 Schema)", async () => {
    const base = await wrapsFor(ENV, ALL_MEMBERS);
    const stripped = base.map(({ suite: _suite, ...rest }) => rest);
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const compositeBase = {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
    };
    const missing = await requestJson("POST", "/environments", token(OWNER), {
      ...compositeBase,
      deks: stripped,
    });
    expect(missing.status).toBe(400);
    const wrong = await requestJson("POST", "/environments", token(OWNER), {
      ...compositeBase,
      deks: base.map((wrap) => ({ ...wrap, suite: "maruhi/v2" })),
    });
    expect(wrong.status).toBe(400);
  });
});

describe("quantity policy (the rest of §12-8: environment / variable / wrap counts)", () => {
  // Since real generation is unrealistic, rows are seeded directly via SQL to verify the judgment plumbing
  it("caps active environments (422 environments)", async () => {
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at)
       SELECT 'env-seed-' || n, 'seed-' || n, 1, 0, NULL FROM seq`,
      MAX_ACTIVE_ENVIRONMENTS,
    );
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "environments",
      limit: MAX_ACTIVE_ENVIRONMENTS,
    });
  });

  it("caps environment rows including tombstones (422 environment-rows)", async () => {
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO environments (environment_id, name, latest_meta_version, created_at, deleted_at)
       SELECT 'env-seed-' || n, 'seed-' || n, 1, 0, 1 FROM seq`,
      MAX_ENVIRONMENT_ROWS,
    );
    const response = await createEnvironmentWith(fixture, ENV, "App", []);
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "environment-rows",
      limit: MAX_ENVIRONMENT_ROWS,
    });
  });

  it("caps active variables per environment (422 variables)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       SELECT ?, 'var-seed-' || n, 'SEED_' || n, 1, 1, 0, NULL FROM seq`,
      MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
      ENV,
    );
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "variables",
      limit: MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
    });
  });

  it("caps variable rows including tombstones (422 variable-rows)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO variables (environment_id, variable_id, name, latest_meta_version, latest_version, created_at, deleted_at)
       SELECT ?, 'var-seed-' || n, 'SEED_' || n, 1, 1, 0, 1 FROM seq`,
      MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
      ENV,
    );
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "variable-rows",
      limit: MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
    });
  });

  it("caps DEK wraps per request (422 dek-wraps-per-request)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // The count cap is judged before recipient verification and signature verification, so a structurally-correct fake suffices
    const deks = Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: `u${index}`,
      recipientEncPubHex: "ab".repeat(32),
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
      signatureHex: "00".repeat(64),
    }));
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    });
  });

  it("caps cumulative dek-wrap rows across every insertion path (422 §12-8, unit + plumbing)", async () => {
    // The pure-function judgment (registering a million rows is unrealistic — same shape as projectBytesExceeded)
    expect(wrapRowsExceeded(MAX_PROJECT_DEK_WRAP_ROWS, 1)).toBe(true);
    expect(wrapRowsExceeded(MAX_PROJECT_DEK_WRAP_ROWS - 3, 3)).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // Fill to exactly the cap: the existing 3 rows (the epoch-1 complete set) + seeded rows
    await queryProjectDo(
      projectId,
      `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
       INSERT INTO dek_wraps
         (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       SELECT 'env-wrap-seed', n, 'u-seed', 'maruhi/v1', '', '', '', '', '', '', 0 FROM seq`,
      MAX_PROJECT_DEK_WRAP_ROWS - 3,
    );

    // Path 1: the bundled set of a composite rotation (§12-4) is also
    // bound by the cap; on overflow the chain entry itself is rejected
    // (atomicity)
    const headBefore = fixture.head;
    const rotation = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(rotation.status).toBe(422);
    await expect(rotation.json()).resolves.toMatchObject({
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);

    // Path 2: the composite environment creation (the bundled epoch-1 set) is bound by the same cap
    const created = await createEnvironmentWith(
      fixture,
      "env-wrap-limit",
      "Limit",
      await wrapsFor("env-wrap-limit", ALL_MEMBERS),
    );
    expect(created.status).toBe(422);
    await expect(created.json()).resolves.toMatchObject({
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });

    // Path 3: the registration API (repair re-registration — §12-6) is bound by the same cap
    const removedOne = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removedOne.status).toBe(204);
    // Releasing 3 rows → headroom of 3 rows to the cap. Add 4 rows (seed +1) to exceed the cap again
    await queryProjectDo(
      projectId,
      `INSERT INTO dek_wraps
         (environment_id, epoch, recipient_user_id, suite, recipient_enc_pub_hex, enc_hex, ciphertext_hex,
          signature_hex, signer_user_id, signer_key_fingerprint, created_at)
       VALUES ('env-wrap-seed', 0, 'u-seed-extra', 'maruhi/v1', '', '', '', '', '', '', 0)`,
    );
    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const reRegistered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: complete,
    });
    expect(reRegistered.status).toBe(422);
    await expect(reRegistered.json()).resolves.toMatchObject({
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });

    // Deletion (the repair path) frees rows: removing the extra seed lets the complete set through again
    await queryProjectDo(
      projectId,
      "DELETE FROM dek_wraps WHERE recipient_user_id = 'u-seed-extra'",
    );
    const retried = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: complete,
    });
    expect(retried.status).toBe(204);
  });
});

describe("judgment order and the Schema boundary (§12-3 / §12-2)", () => {
  it("the AAD self-consistency check (422) precedes existence hiding (404) (the §12-3 exception provision)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // Even a non-member gets a 422 when the AAD disagrees with the
    // request itself (carries no existence information). Both stop at
    // authorization judgment and never reach value-signature
    // verification (§12-3 judgment order), so an unsigned fake suffices
    // (STRANGER holds no vector key)
    const mismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(STRANGER),
      { value: unsignedPayload(aadFor(1, 2, { variableId: "var-other" })) },
    );
    expect(mismatch.status).toBe(422);
    // If the AAD is self-consistent, a non-member gets a 404 (§11-2)
    const consistent = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(STRANGER),
      { value: unsignedPayload(aadFor(1, 2)) },
    );
    expect(consistent.status).toBe(404);
  });

  it("rejects a malformed composite parentHeadHashHex with 400 (Schema)", async () => {
    // The CAS parent-head format is pinned as Sha256Hex: a malformed
    // one never reaches 409 (ChainHeadConflict) and falls at the schema
    // boundary's 400
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: "env-head-form", dekCommitmentHex: "ab".repeat(32) },
      },
    });
    for (const bad of ["ab".repeat(31), "AB".repeat(32), "not-hex"]) {
      const response = await requestJson("POST", "/environments", token(OWNER), {
        parentHeadHashHex: bad,
        entry,
        statement: {
          suite: "maruhi/v1",
          environmentId: "env-head-form",
          name: "HeadForm",
          status: "active",
          metaVersion: 1,
          prevMetaSigHashHex: "",
          chainHeadHashHex: fixture.head.hashHex,
          chainHeadSeq: fixture.head.seq,
          signatureHex: "00".repeat(64),
        },
        deks: [],
      });
      expect(response.status).toBe(400);
    }
  });

  it("rejects malformed ids and payloads with 400 (Schema)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // A malformed environment_id (leading hyphen / 65 chars) is a 400
    for (const badId of ["-bad", "a".repeat(65)]) {
      const response = await requestJson("GET", `/environments/${badId}/pull`, token(READER));
      expect(response.status).toBe(400);
    }
    // The §12-1 acceptance-policy format is enforced on the
    // environment_id inside a composite create's entry too (400): since
    // compositing moved the ID's carriage inside a chain entry and it
    // has no URL coordinate, a laxer format would give rise to
    // environments unreachable from the later endpoints that take a URL
    // param (rotate / rename / delete / pull)
    for (const badId of ["-bad", "a".repeat(65), "my env/💥"]) {
      const { entry } = await signEntryAt({
        seq: fixture.head.seq + 1,
        prevHashHex: fixture.head.hashHex,
        actorUserId: OWNER,
        operation: {
          op: "create_environment",
          payload: { environmentId: badId, dekCommitmentHex: "ab".repeat(32) },
        },
      });
      const response = await requestJson("POST", "/environments", token(OWNER), {
        parentHeadHashHex: fixture.head.hashHex,
        entry,
        // The statement side is also a 400 under the same
        // acceptance-policy format (EnvironmentIdSchema) (kept aligned
        // with the entry to pin the Schema boundary). Signature
        // verification is never reached
        statement: {
          suite: "maruhi/v1",
          environmentId: badId,
          name: `Bad-${badId.length}`,
          status: "active",
          metaVersion: 1,
          prevMetaSigHashHex: "",
          chainHeadHashHex: fixture.head.hashHex,
          chainHeadSeq: fixture.head.seq,
          signatureHex: "00".repeat(64),
        },
        deks: [],
      });
      expect(response.status).toBe(400);
    }
    // Malformed EncryptedPayloads: suite mismatch / uppercase-hex nonce
    // / ciphertext shorter than the tag / signature-block format
    // violations (uppercase signature / bad prev length / bad head-hash
    // length / chainHeadSeq 0) — all are Schema 400s (before signature
    // verification)
    const base = unsignedPayload(aadFor(1, 1));
    const badPayloads = [
      { ...base, suite: "maruhi/v2" },
      { ...base, nonceHex: "AB".repeat(12) },
      { ...base, ciphertextHex: "ab".repeat(15) },
      { ...base, signatureHex: "AB".repeat(64) },
      { ...base, signatureHex: "ab".repeat(63) },
      { ...base, prevValueSigHashHex: "ab".repeat(31) },
      { ...base, chainHeadHashHex: "ab".repeat(31) },
      { ...base, chainHeadSeq: 0 },
    ];
    for (const value of badPayloads) {
      const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
        statement: unsignedVariableStatement(VAR, "DATABASE_URL"),
        value,
        manifest: unsignedManifest(),
      });
      expect(response.status).toBe(400);
    }
  });
});

const rejectedOutcome = (rejection: DataRejection) => ({ kind: "rejected", rejection }) as const;

/**
 * The tag set of an endpoint's declared errors. Read from the
 * identifier annotation (Schema.TaggedError grants it identical to the
 * tag) as a path independent of the runtime judgment (Schema.is). If an
 * effect update changes the annotation's shape, fail here explicitly to
 * prompt re-verification of the contract derivation.
 */
const declaredTagsOf = (endpoint: HttpApiEndpoint.Top): ReadonlySet<string> =>
  new Set(
    Array.from(endpoint.error, (schema) => {
      const identifier = (schema.ast.annotations as Record<string, unknown> | undefined)?.[
        "identifier"
      ];
      if (typeof identifier !== "string") {
        throw new Error(
          "declared error schema without a string identifier annotation — " +
            "re-verify the error-contract derivation (Schema.is / endpoint.error) " +
            "against the new effect version",
        );
      }
      return identifier;
    }),
  );

describe("deriving the error contract from declarations (data-http.ts unwrapDataOutcome)", () => {
  // DO rejections are screened by a set derived from the endpoint's
  // contract declarations (api-schema's error: [...]) — no hand-written
  // allowed list exists. Here the correspondence to the declarations
  // itself is pinned at the mapping level. dek-wrap-exists is in fact
  // unreachable from composite create / rotate under the current chain
  // rules (duplicate-environment / epoch monotonicity), so the contract
  // is verified in this unit rather than via HTTP integration

  it("dek-wrap-exists is returned as a contract error of create / rotate (409 DekWrapExists)", () => {
    // If it were absent from the declarations, the structure would fall
    // to defect (500) the moment the chain rules loosen — so it is
    // included in the declarations and returned as a typed 409 error
    for (const endpoint of [
      environmentsGroup.endpoints.create,
      environmentsGroup.endpoints.rotate,
    ] as const) {
      const error = Effect.runSync(
        Effect.flip(
          unwrapDataOutcome(
            rejectedOutcome({
              kind: "dek-wrap-exists",
              epoch: 2,
              recipientUserId: READER,
              storedRecipientEncPubHex: "ab".repeat(32),
            }),
            projectId,
            endpoint,
          ),
        ),
      );
      expect(error).toBeInstanceOf(DekWrapExistsError);
      // The 409 carries the occupying wrap's stored recipient enc
      // public key (AUTH_SPEC §12-6 — material for the re-add backfill's
      // repair judgment)
      expect(error).toMatchObject({
        epoch: 2,
        recipientUserId: READER,
        storedRecipientEncPubHex: "ab".repeat(32),
      });
    }
  });

  it("an out-of-contract rejection stays a defect (500) (invariant violations never leak into typed errors)", () => {
    // variables.pull's declarations are only ProjectNotFound / Forbidden
    // / EnvironmentNotFound. If a version-conflict rejection ever leaks,
    // it dies as an implementation bug
    const exit = Effect.runSyncExit(
      unwrapDataOutcome(
        rejectedOutcome({ kind: "version-conflict", currentVersion: 3 }),
        projectId,
        variablesGroup.endpoints.pull,
      ),
    );
    expect(Exit.isFailure(exit) && Cause.hasDies(exit.cause)).toBe(true);
  });

  it("the §11-2 existence-hiding fold (not-member → 404 ProjectNotFound) is also within the declarations", () => {
    const error = Effect.runSync(
      Effect.flip(
        unwrapDataOutcome(
          rejectedOutcome({ kind: "not-member" }),
          projectId,
          variablesGroup.endpoints.pull,
        ),
      ),
    );
    expect(error).toMatchObject({ _tag: "ProjectNotFound", projectId });
  });

  // A representative rejection per kind (every field a valid value
  // within the Schema vocabulary). `satisfies` type-forces coverage of
  // all DataRejection kinds — adding a kind fails compilation unless it
  // is added here
  const representativeRejections = {
    "not-initialized": { kind: "not-initialized" },
    "not-member": { kind: "not-member" },
    "insufficient-role": { kind: "insufficient-role" },
    "insufficient-scope": { kind: "insufficient-scope" },
    "environment-not-found": { kind: "environment-not-found", environmentId: "env-contract" },
    "environment-conflict": {
      kind: "environment-conflict",
      environmentId: "env-contract",
      reason: "duplicate-name",
    },
    "composite-required": { kind: "composite-required", op: "create_environment" },
    "device-limit": { kind: "device-limit", limit: 16 },
    "proposal-limit": { kind: "proposal-limit", reason: "pending-proposals", limit: 32 },
    "checkpoint-state-mismatch": {
      kind: "checkpoint-state-mismatch",
      reason: "values-digest-mismatch",
    },
    "chain-head-conflict": {
      kind: "chain-head-conflict",
      currentHeadSeq: 4,
      currentHeadHashHex: "ab".repeat(32),
    },
    "chain-entry-invalid": { kind: "chain-entry-invalid", seq: 2, reason: "bad-signature" },
    "chain-entry-too-large": { kind: "chain-entry-too-large", limitBytes: 1024 },
    "chain-capacity-exceeded": {
      kind: "chain-capacity-exceeded",
      maxEntries: 10,
      maxTotalBytes: 1024,
    },
    "payload-mismatch": { kind: "payload-mismatch", field: "environmentId" },
    "variable-not-found": { kind: "variable-not-found", variableId: "var-contract" },
    "variable-conflict": {
      kind: "variable-conflict",
      variableId: "var-contract",
      reason: "duplicate-name",
    },
    "version-conflict": { kind: "version-conflict", currentVersion: 3 },
    "epoch-conflict": { kind: "epoch-conflict", currentEpoch: 2 },
    "value-rejected": { kind: "value-rejected", reason: "signature-invalid" },
    "meta-rejected": { kind: "meta-rejected", reason: "signature-invalid" },
    "schema-policy-rejected": { kind: "schema-policy-rejected", reason: "schema-policy-disabled" },
    "activation-required": { kind: "activation-required", variableId: "var-contract" },
    "description-rejected": { kind: "description-rejected", reason: "too-long" },
    "meta-version-conflict": { kind: "meta-version-conflict", currentMetaVersion: 2 },
    "manifest-rejected": { kind: "manifest-rejected", reason: "manifest-digest-mismatch" },
    "manifest-version-conflict": {
      kind: "manifest-version-conflict",
      currentManifestVersion: 2,
    },
    "name-not-nfc": { kind: "name-not-nfc" },
    "dek-wrap-rejected": { kind: "dek-wrap-rejected", reason: "duplicate-recipient" },
    "dek-wrap-exists": {
      kind: "dek-wrap-exists",
      epoch: 2,
      recipientUserId: READER,
      storedRecipientEncPubHex: "ab".repeat(32),
    },
    "dek-wrap-not-found": { kind: "dek-wrap-not-found", epoch: 2, recipientUserId: READER },
    "rotation-flag-not-found": {
      kind: "rotation-flag-not-found",
      environmentId: "env-contract",
      variableId: "var-contract",
    },
    "limit-exceeded": { kind: "limit-exceeded", resource: "variables", limit: 100 },
    "attestation-rejected": { kind: "attestation-rejected", reason: "signature-invalid" },
    "attestation-regression": { kind: "attestation-regression", storedSeq: 5 },
    "attestation-rate-limited": { kind: "attestation-rate-limited", retryAfterSeconds: 60 },
    "audit-head-not-ready": { kind: "audit-head-not-ready" },
  } as const satisfies {
    readonly [K in DataRejection["kind"]]: Extract<DataRejection, { kind: K }>;
  };

  // The golden table of kind → expected error tag (pinning the
  // rejectionErrors mapping of data-http.ts). `satisfies` type-forces
  // coverage of all kinds
  const expectedTagByKind = {
    "not-initialized": "ProjectNotFound",
    "not-member": "ProjectNotFound",
    "insufficient-role": "Forbidden",
    "insufficient-scope": "Forbidden",
    "environment-not-found": "EnvironmentNotFound",
    "environment-conflict": "EnvironmentConflict",
    "composite-required": "CompositeRequired",
    "device-limit": "DeviceLimit",
    "proposal-limit": "ProposalLimit",
    "checkpoint-state-mismatch": "CheckpointStateMismatch",
    "chain-head-conflict": "ChainHeadConflict",
    "chain-entry-invalid": "ChainEntryInvalid",
    "chain-entry-too-large": "ChainEntryTooLarge",
    "chain-capacity-exceeded": "ChainCapacityExceeded",
    "payload-mismatch": "PayloadMismatch",
    "variable-not-found": "VariableNotFound",
    "variable-conflict": "VariableConflict",
    "version-conflict": "VersionConflict",
    "epoch-conflict": "EpochConflict",
    "value-rejected": "ValueSignatureRejected",
    "meta-rejected": "MetaStatementRejected",
    "schema-policy-rejected": "SchemaPolicyRejected",
    "activation-required": "ActivationRequired",
    "description-rejected": "SchemaDescriptionRejected",
    "meta-version-conflict": "MetaVersionConflict",
    "manifest-rejected": "ManifestRejected",
    "manifest-version-conflict": "ManifestVersionConflict",
    "name-not-nfc": "NameNotNfc",
    "dek-wrap-rejected": "DekWrapRejected",
    "dek-wrap-exists": "DekWrapExists",
    "dek-wrap-not-found": "DekWrapNotFound",
    "rotation-flag-not-found": "RotationFlagNotFound",
    "limit-exceeded": "DataLimitExceeded",
    "attestation-rejected": "AttestationRejected",
    "attestation-regression": "AttestationRegression",
    "attestation-rate-limited": "AttestationRateLimited",
    "audit-head-not-ready": "AuditHeadNotReady",
  } as const satisfies Record<DataRejection["kind"], string>;

  // Every data-plane + chain endpoint × every rejection kind (the chain
  // API — membership — also reports rejections as DataRejection and goes
  // through the same unwrapDataOutcome. The worker ↔ DO correspondence
  // is what this table pins)
  const contractCases = Object.entries({
    membership: membershipGroup,
    environments: environmentsGroup,
    variables: variablesGroup,
    deks: deksGroup,
    rotation: rotationGroup,
    schemaPolicy: schemaPolicyGroup,
    // audit.self does not go through the DO (D1 only), but as a
    // mapping/declaration correspondence table it is pinned under the
    // same discipline (every rejection absent from the declarations
    // becomes a die judgment)
    audit: auditGroup,
  }).flatMap(([groupName, group]) =>
    Object.entries(group.endpoints).flatMap(([endpointName, endpoint]) =>
      Object.values(representativeRejections).map((rejection) => ({
        endpointLabel: `${groupName}.${endpointName}`,
        endpoint: endpoint as HttpApiEndpoint.Top,
        rejection: rejection as DataRejection,
      })),
    ),
  );

  /** The measured / expected judgment of one combination (in the form "label: fail|die"; for the toEqual diff). */
  const judgeContractCase = (contractCase: (typeof contractCases)[number]) => {
    const { endpoint, rejection, endpointLabel } = contractCase;
    const label = `${endpointLabel} ← ${rejection.kind}`;
    const exit = Effect.runSyncExit(
      unwrapDataOutcome(rejectedOutcome(rejection), projectId, endpoint),
    );
    const died = Exit.isFailure(exit) && Cause.hasDies(exit.cause);
    if (!died) {
      // When within the contract, the returned failure value itself also carries the tag the mapping prescribes
      const failed = Effect.runSync(
        Effect.flip(unwrapDataOutcome(rejectedOutcome(rejection), projectId, endpoint)),
      );
      expect(failed, label).toMatchObject({ _tag: expectedTagByKind[rejection.kind] });
    }
    return {
      observed: `${label}: ${died ? "die" : "fail"}`,
      expected: `${label}: ${declaredTagsOf(endpoint).has(expectedTagByKind[rejection.kind]) ? "fail" : "die"}`,
    };
  };

  it("the DataRejection → error-class mapping (rejectionErrors) follows the golden table", () => {
    for (const rejection of Object.values(representativeRejections)) {
      expect(dataRejectionError(rejection, projectId), rejection.kind).toMatchObject({
        _tag: expectedTagByKind[rejection.kind],
      });
    }
  });

  it("the fail / die judgments of every data-plane endpoint × every rejection kind strictly match the declarations", () => {
    // A drift detector against effect updates (changes in the meaning of Schema.is / endpoint.error)
    const results = contractCases.map(judgeContractCase);
    // Make mismatched (endpoint, kind) pairs directly readable in the toEqual diff
    expect(results.map((result) => result.observed)).toEqual(
      results.map((result) => result.expected),
    );
    // The defense line against a broken enumeration spinning freely
    // (an unconditional pass). Update this count when endpoints are
    // added (membership 5 / environments 5 / variables 7 / deks 3 /
    // rotation 2 / schemaPolicy 2 / audit 4)
    expect(new Set(contractCases.map((contractCase) => contractCase.endpointLabel)).size).toBe(28);
  });
});
