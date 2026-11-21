import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

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
    | { status: "active"; metaVersion: number; prevMetaSigHashHex: string },
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
    const status = await expectStrictReject(send, {
      suite: "maruhi/v1",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: "00".repeat(64),
    });
    expect(status).toBe(422);
  });
});

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

  it("rejects a composite without the required boundary checkpoint field with 400", async () => {
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

  it("environment delete rejects an unknown field with 400 (root and nested entry)", async () => {
    const send = sendJson("DELETE", dataUrl(`/environments/${ENV}`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("delete_environment", { environmentId: ENV }),
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
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/variables`), bearer(token(OWNER)));
    const statement = {
      ...unsignedVariableStatement(VAR, "DATABASE_URL"),
      status: "declared",
      layoutVersion: 3,
      varType: "string",
      required: true,
      description: "",
      maxAgeDays: null,
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
      layoutVersion: 3,
      varType: "string",
      required: true,
      description: "",
      maxAgeDays: null,
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
      recipientClass: "member",
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
