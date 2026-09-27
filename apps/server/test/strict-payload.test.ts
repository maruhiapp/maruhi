// Pinned tests for the effectiveness of strict acceptance
// (AUTH_SPEC §12-10 (1)).
//
// The targets are every implemented endpoint's payload route among
// the surfaces §12-10 (1) enumerates
// (SECURITY_CRITICAL_PAYLOAD_ENDPOINTS in
// packages/api-schema/src/strict.ts). Each surface verifies over
// the real workerd acceptance path that "a request containing an
// unknown field is actually rejected with 400" — it does not test
// the annotation's **presence** (so that if the schema annotation
// stopped being read by the parser, it is detected from the
// behavior side).
// The enforcement is only the payload-schema wrapper
// (`strictPayload`). The endpoint's `HttpApi.ParseOptions` would
// pass the same options to success/error encoding, turning a
// TaggedError's stack metadata into HTTP 500 — not used here.
//
// Each test is built from two sends of the same body:
// 1. probe = clean body + an unknown field → 400
// 2. control = the clean body itself → non-400 (proof the decode
//    passed)
//
// Since the two sends differ only in the unknown field, the probe's
// 400 is certainly caused by that field (if the 400 had a different
// cause, the control would be 400 too).
// A Schema 400's response body is empty (upstream renders
// HttpApiSchemaError as an "empty 400"), so no body is checked.
// Happy-path completion is covered by existing suites.
//
// Bodies that must not reach signature verification use
// data-scenario's unsigned dummy (a zero signature, valid in form
// only) — enough to prove the 400 settles at the Schema stage.

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import { vectorKeyNamed } from "./support/data-crypto.ts";
import { dataUrl, OWNER, projectId } from "./support/data-fixture.ts";
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

registerDataScenario();

const PROBE_KEY = "__maruhiStrictProbe";

/**
 * Pins probe (clean + unknown field) = 400 and control (clean) =
 * non-400. Returns the control's actual status (the caller can also
 * assert the handler stage's typical result).
 */
async function expectStrictReject(
  send: (body: Record<string, unknown>) => Promise<Response>,
  clean: Record<string, unknown>,
): Promise<number> {
  const probe = await send({ ...clean, [PROBE_KEY]: true });
  expect(probe.status).toBe(400);
  const control = await send(clean);
  expect(control.status).not.toBe(400);
  return control.status;
}

/**
 * Propagation into nesting: for a clean body that already passed as
 * the control (non-400), the shape with an unknown field embedded
 * only at a nested position must fail with 400 (call after
 * expectStrictReject).
 */
async function expectNestedReject(
  send: (body: Record<string, unknown>) => Promise<Response>,
  nested: Record<string, unknown>,
): Promise<void> {
  const probe = await send(nested);
  expect(probe.status).toBe(400);
}

const sendJson =
  (method: string, url: string, headers: Record<string, string>) =>
  (body: Record<string, unknown>): Promise<Response> =>
    SELF.fetch(url, {
      method,
      headers: { ...JSON_HEADERS, ...headers },
      body: JSON.stringify(body),
    });

// A zero-signature entry valid in form only (a control on the premise that signature verification = 422 is reached)
const unsignedEntry = (op: string, payload: Record<string, unknown>): Record<string, unknown> => ({
  suite: "maruhi/v1",
  seq: fixture.head.seq + 1,
  prevHashHex: fixture.head.hashHex,
  op,
  actor: { userId: OWNER, keyFingerprintHex: "ab".repeat(16) },
  payload,
  timestampMs: 1754006400000,
  signatureHex: "00".repeat(64),
});

const unsignedEnvStatement = (
  lifecycle:
    | { status: "active"; metaVersion: 1; prevMetaSigHashHex: "" }
    | { status: "active" | "deleted"; metaVersion: number; prevMetaSigHashHex: string },
): Record<string, unknown> => ({
  suite: "maruhi/v1",
  environmentId: ENV,
  name: "App",
  ...lifecycle,
  chainHeadHashHex: fixture.head.hashHex,
  chainHeadSeq: fixture.head.seq,
  signatureHex: "00".repeat(64),
});

describe("chain append (§11-4)", () => {
  it("init rejects an unknown field with 400", async () => {
    const send = sendJson("POST", `${BASE}/projects`, bearer(token(OWNER)));
    await expectStrictReject(send, {
      orgId: "org-strict-0001",
      entry: unsignedEntry("genesis", { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) }),
    });
  });

  it("append rejects an unknown field with 400 (root and nested entry payload)", async () => {
    const send = sendJson(
      "POST",
      `${BASE}/projects/${projectId}/chain/entries`,
      bearer(token(OWNER)),
    );
    const entry = unsignedEntry("remove_member", { targetUserId: "user-member-0002" });
    const clean = { parentHeadHashHex: fixture.head.hashHex, entry };
    await expectStrictReject(send, clean);
    // Propagation into a nested position (entry.payload)
    await expectNestedReject(send, {
      ...clean,
      entry: {
        ...entry,
        payload: { targetUserId: "user-member-0002", [PROBE_KEY]: true },
      },
    });
  });
});

describe("head-attestation submission (§16-1)", () => {
  it("attest rejects an unknown field with 400", async () => {
    const send = sendJson(
      "PUT",
      `${BASE}/projects/${projectId}/head-attestation`,
      bearer(token(OWNER)),
    );
    // The zero-signature control passes Schema and falls to the
    // acceptance check's 422 (signature-invalid). A non-400 alone
    // would miss error-encoding 500s, so pin the declared status
    // too.
    const status = await expectStrictReject(send, {
      suite: "maruhi/v1",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: "00".repeat(64),
    });
    expect(status).toBe(422);
  });
});

// A zero-signature boundary checkpoint valid in form only (§12-4's mandatory bundling)
const unsignedCheckpoint = (epoch: number, manifestVersion: number): Record<string, unknown> =>
  unsignedEntry("checkpoint", {
    environments: [
      {
        environmentId: ENV,
        epoch,
        manifestVersion,
        manifestSigHashHex: "ab".repeat(32),
        valuesDigestHex: "cd".repeat(32),
      },
    ],
    auditHeadHashHex: "",
  });

describe("environment create / rotation composite (§12-4)", () => {
  it("create rejects an unknown field with 400 (root and nested entry payload)", async () => {
    const send = sendJson("POST", dataUrl("/environments"), bearer(token(OWNER)));
    const entryPayload = { environmentId: ENV, dekCommitmentHex: "12".repeat(32) };
    const clean = {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("create_environment", entryPayload),
      statement: unsignedEnvStatement({ status: "active", metaVersion: 1, prevMetaSigHashHex: "" }),
      deks: [],
      manifest: {
        ...unsignedManifest(),
        variablesDigestHex: "ab".repeat(32),
      },
      checkpoint: unsignedCheckpoint(1, 1),
    };
    await expectStrictReject(send, clean);
    await expectNestedReject(send, {
      ...clean,
      entry: unsignedEntry("create_environment", { ...entryPayload, [PROBE_KEY]: true }),
    });
    // strict also propagates into the composite's checkpoint field
    await expectNestedReject(send, {
      ...clean,
      checkpoint: { ...(clean.checkpoint as Record<string, unknown>), [PROBE_KEY]: true },
    });
  });

  it("rotate rejects an unknown field with 400 (root and nested manifest)", async () => {
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/rotate`), bearer(token(OWNER)));
    const clean = {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("rotate_epoch", {
        environmentId: ENV,
        newEpoch: 2,
        reason: "test",
        dekCommitmentHex: "12".repeat(32),
      }),
      deks: [],
      manifest: {
        ...unsignedManifest(),
        epoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: "cd".repeat(32),
      },
      checkpoint: unsignedCheckpoint(2, 2),
    };
    await expectStrictReject(send, clean);
    await expectNestedReject(send, {
      ...clean,
      manifest: { ...(clean.manifest as Record<string, unknown>), [PROBE_KEY]: true },
    });
    // strict also propagates inside the checkpoint field: both the
    // entry payload and its environment-tuple nested positions
    const cleanCheckpoint = clean.checkpoint as Record<string, unknown>;
    const checkpointPayload = cleanCheckpoint["payload"] as Record<string, unknown>;
    await expectNestedReject(send, {
      ...clean,
      checkpoint: {
        ...cleanCheckpoint,
        payload: { ...checkpointPayload, [PROBE_KEY]: true },
      },
    });
    const environments = checkpointPayload["environments"] as readonly Record<string, unknown>[];
    await expectNestedReject(send, {
      ...clean,
      checkpoint: {
        ...cleanCheckpoint,
        payload: {
          ...checkpointPayload,
          environments: [{ ...environments[0], [PROBE_KEY]: true }],
        },
      },
    });
  });

  it("rejects a composite without the boundary checkpoint field with 400 (fail-closed for older CLIs)", async () => {
    // §12-4's mandatory bundling: a create / rotate composite from
    // an old CLI that does not know checkpoint fails closed as a
    // Schema-stage 400 (the consequence of session-33 ruling E-3 —
    // SELF_HOSTING's update ordering covers the operational side).
    // Per the file-top convention, probe / control are paired within
    // this test (if it depended on a prior test's clean, a change on
    // the prior side would silently lose the guarantee that the 400
    // is caused by the missing checkpoint): the only difference is
    // the presence of the checkpoint field
    const create = sendJson("POST", dataUrl("/environments"), bearer(token(OWNER)));
    const createClean = {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("create_environment", {
        environmentId: ENV,
        dekCommitmentHex: "12".repeat(32),
      }),
      statement: unsignedEnvStatement({ status: "active", metaVersion: 1, prevMetaSigHashHex: "" }),
      deks: [],
      manifest: { ...unsignedManifest(), variablesDigestHex: "ab".repeat(32) },
    };
    expect((await create(createClean)).status).toBe(400);
    expect(
      (await create({ ...createClean, checkpoint: unsignedCheckpoint(1, 1) })).status,
    ).not.toBe(400);

    const rotate = sendJson("POST", dataUrl(`/environments/${ENV}/rotate`), bearer(token(OWNER)));
    const rotateClean = {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("rotate_epoch", {
        environmentId: ENV,
        newEpoch: 2,
        reason: "test",
        dekCommitmentHex: "12".repeat(32),
      }),
      deks: [],
      manifest: {
        ...unsignedManifest(),
        epoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: "cd".repeat(32),
      },
    };
    expect((await rotate(rotateClean)).status).toBe(400);
    expect(
      (await rotate({ ...rotateClean, checkpoint: unsignedCheckpoint(2, 2) })).status,
    ).not.toBe(400);
  });
});

describe("meta operations (§12-5 — environments)", () => {
  it("environment rename rejects an unknown field with 400", async () => {
    const send = sendJson("PATCH", dataUrl(`/environments/${ENV}`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      statement: unsignedEnvStatement({
        status: "active",
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      }),
      manifest: unsignedManifest(),
    });
  });

  it("environment delete rejects an unknown field with 400", async () => {
    const send = sendJson("DELETE", dataUrl(`/environments/${ENV}`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      statement: unsignedEnvStatement({
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      }),
    });
  });
});

describe("value push / meta operations (§12-5 — variables)", () => {
  it("variable create rejects an unknown field with 400", async () => {
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/variables`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      statement: unsignedVariableStatement(VAR, "DATABASE_URL"),
      value: unsignedPayload(aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
  });

  it("declared create (union branch — §12-5) rejects an unknown field with 400", async () => {
    // Pinning on the v2 branch that strict annotations propagate
    // across the Union (§12-10 (1)). The control is the handler
    // stage's 4xx (non-400) = proof the decode passed
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/variables`), bearer(token(OWNER)));
    const statement = {
      ...unsignedVariableStatement(VAR, "DATABASE_URL"),
      status: "declared",
      layoutVersion: 2,
      varType: "string",
      required: true,
      description: "",
    };
    await expectStrictReject(send, { statement, manifest: unsignedManifest() });
    await expectNestedReject(send, {
      statement: { ...statement, [PROBE_KEY]: true },
      manifest: unsignedManifest(),
    });
  });

  it("variable activate rejects an unknown field with 400", async () => {
    const send = sendJson(
      "POST",
      dataUrl(`/environments/${ENV}/variables/${VAR}/activate`),
      bearer(token(OWNER)),
    );
    const statement = {
      ...unsignedVariableStatement(VAR, "DATABASE_URL"),
      metaVersion: 2,
      prevMetaSigHashHex: "ab".repeat(32),
      layoutVersion: 2,
      varType: "string",
      required: true,
      description: "",
    };
    await expectStrictReject(send, {
      value: unsignedPayload(aadFor(1, 1)),
      statement,
      manifest: unsignedManifest(),
    });
  });

  it("push rejects an unknown field with 400 (root and nested value AAD)", async () => {
    const send = sendJson(
      "POST",
      dataUrl(`/environments/${ENV}/variables/${VAR}/versions`),
      bearer(token(OWNER)),
    );
    const value = unsignedPayload(aadFor(1, 2));
    await expectStrictReject(send, { value });
    await expectNestedReject(send, {
      value: { ...value, aad: { ...value.aad, [PROBE_KEY]: true } },
    });
  });

  it("variable rename rejects an unknown field with 400", async () => {
    const send = sendJson(
      "PATCH",
      dataUrl(`/environments/${ENV}/variables/${VAR}`),
      bearer(token(OWNER)),
    );
    await expectStrictReject(send, {
      statement: {
        ...unsignedVariableStatement(VAR, "DATABASE_URL_2"),
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      },
      manifest: unsignedManifest(),
    });
  });

  it("variable delete rejects an unknown field with 400", async () => {
    const send = sendJson(
      "DELETE",
      dataUrl(`/environments/${ENV}/variables/${VAR}`),
      bearer(token(OWNER)),
    );
    await expectStrictReject(send, {
      statement: {
        ...unsignedVariableStatement(VAR, "DATABASE_URL"),
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      },
      manifest: unsignedManifest(),
    });
  });
});

describe("DEK wrap registration (§12-6)", () => {
  it("register rejects an unknown field with 400 (root and nested wrap)", async () => {
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/deks`), bearer(token(OWNER)));
    const wrap = {
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: OWNER,
      recipientEncPubHex: "ab".repeat(32),
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
      signatureHex: "00".repeat(64),
    };
    await expectStrictReject(send, { deks: [wrap] });
    await expectNestedReject(send, { deks: [{ ...wrap, [PROBE_KEY]: true }] });
  });
});

describe("recovery-blob registration (§13-2)", () => {
  it("recovery put rejects an unknown field with 400 (clean body still succeeds)", async () => {
    const send = sendJson("PUT", `${BASE}/auth/recovery`, bearer(token(OWNER)));
    const status = await expectStrictReject(send, {
      suite: "maruhi/v1",
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(16),
    });
    // The control passes all the way to real acceptance (a
    // backcheck that the probe changed no state)
    expect(status).toBe(204);
  });
});

describe("the device registry (§13-11)", () => {
  it("device register rejects an unknown field with 400 (clean body still succeeds)", async () => {
    const keys = vectorKeyNamed("user-owner-0001@phone");
    const send = sendJson(
      "PUT",
      `${BASE}/auth/devices/${keys.key_fingerprint_hex}`,
      bearer(token(OWNER)),
    );
    const status = await expectStrictReject(send, {
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      label: "phone",
    });
    expect(status).toBe(204);
  });

  it("device add request rejects an unknown field with 400 (clean body still succeeds)", async () => {
    const keys = vectorKeyNamed("user-owner-0001@reserve");
    const send = sendJson("POST", `${BASE}/auth/devices/requests`, bearer(token(OWNER)));
    const status = await expectStrictReject(send, {
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      label: "reserve",
    });
    expect(status).toBe(200);
  });
});

describe("lease requests (§14)", () => {
  it("lease issue rejects an unknown field with 400", async () => {
    // The only unauthenticated surface (the credential is the OIDC
    // token itself — §14-1)
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/lease`), {});
    await expectStrictReject(send, {
      oidcToken: "aa.bb.cc",
      ephemeralPubHex: "ab".repeat(32),
    });
  });
});

describe("invite creation / acceptance (§15-2)", () => {
  it("invite issue rejects an unknown field with 400", async () => {
    const send = sendJson("POST", `${BASE}/projects/${projectId}/invites`, bearer(token(OWNER)));
    await expectStrictReject(send, {
      id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
      linkPubHex: "ab".repeat(32),
      headHashHex: "cd".repeat(32),
      headSeq: 3,
      issueSignatureHex: "00".repeat(64),
    });
  });

  it("invite accept rejects an unknown field with 400", async () => {
    const send = sendJson("POST", `${BASE}/invites/accept`, bearer(token(OWNER)));
    await expectStrictReject(send, {
      linkPubHex: "ab".repeat(32),
      encPubHex: "ab".repeat(32),
      sigPubHex: "cd".repeat(32),
      acceptSignatureHex: "00".repeat(64),
      linkSignatureHex: "11".repeat(64),
    });
  });
});
