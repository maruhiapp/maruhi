// Integration tests for sealed value proposals (CRYPTO_SPEC §5.3 /
// AUTH_SPEC §14-5 / AUDIT_SPEC §3.3 — PF7b). Verifies the HttpApi and DO
// SQLite via SELF on @cloudflare/vitest-plugin (the real workerd
// environment).
//
// What this suite pins:
// - the mint shares the lease's credential and authorization (no grant =
//   the same uniform 404; a copy of the token with another key = 401
//   token-replayed) and touches no server wrap (no backfill is needed)
// - the recipient set is exactly W(E) = member-or-above devices in scope
//   (a missing member, an extra reader, a duplicate device = 422
//   recipients-mismatch); readers never see proposals (403), strangers
//   get 404, a listed member of another environment sees nothing
// - the §14-5 acceptance checks and their reason codes; the mint window
//   is consumed only on success
// - members list only their own wraps and can open them with their
//   device key; acceptance verifies the member's own push (version >
//   base, stored) and both resolutions delete the rows and leave the
//   audit rows (rotation.proposed actor system with the claims digest
//   and grant seq; rotation.proposal_accepted / _rejected actor member)
// - an expired proposal is neither listed nor resolvable
// - the environment's deletion removes its proposals in the same
//   transaction, closing each one's history (a pending one cancelled by the
//   deleting member, an expired-but-unswept one expired), so even a member
//   whose scope is `all` no longer lists or resolves them (AUTH_SPEC §12-4)

import {
  encodeHex,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  openProposedValue,
  sealProposedValue,
} from "@maruhi/crypto";
import { testUserId } from "@maruhi/crypto/test-support";
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  MAX_PENDING_ROTATION_PROPOSALS,
  MAX_ROTATION_PROPOSALS_PER_WINDOW,
} from "../src/policy.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import {
  addMemberOperation,
  encryptValue,
  hexBytes,
  valueSignedBytesHashOf,
  vectorKeyNamed,
  vectorKeyOf,
} from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  seedMemberToken,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { claimsDigestOf, grantServer, workloadKeyPair } from "./support/lease-scenario.ts";
import { makeOidcToken } from "./support/lease.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

/**
 * One ephemeral key per test: the fake issuer mints byte-identical tokens
 * within a second (same claims, same iat), so two mints in one test must
 * present the same key or the second trips the first-come binding
 * (§14-1) — exactly what a real job does (one token, one key)
 */
let workload: Awaited<ReturnType<typeof workloadKeyPair>>;
beforeEach(async () => {
  workload = await workloadKeyPair();
});

const PROPOSAL_ID = "00112233445566778899aabbccddeeff";
const NEW_VALUE = "postgres://app_b:rotated-dummy@db.example:5432/shop";
const utf8 = (text: string) => new TextEncoder().encode(text);

/** The recipient set W(E) of the fixture: owner + member (the reader is excluded — §5.3). */
const WRITERS = [OWNER, MEMBER] as const;

interface WireWrap {
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** Seals `plaintext` to one member's device key under the §5.3 info (the minting client's step). */
async function sealTo(input: {
  readonly proposalId: string;
  readonly variableId: string;
  readonly baseVersion: number;
  readonly recipientUserId: string;
  readonly plaintext: string;
  /** A device other than the user's primary vector key (an added device's enc key). */
  readonly encPubHex?: string;
}): Promise<WireWrap> {
  const encPubHex = input.encPubHex ?? vectorKeyOf(input.recipientUserId).enc_pub_hex;
  const publicKey = await importEncryptionPublicKey(hexBytes(encPubHex));
  if (!publicKey.ok) {
    throw new Error("recipient public key import failed");
  }
  const sealed = await sealProposedValue({
    recipientPublicKey: publicKey.value,
    value: utf8(input.plaintext),
    context: {
      projectId,
      environmentId: ENV,
      proposalId: input.proposalId,
      variableId: input.variableId,
      baseVersion: input.baseVersion,
      recipientUserId: input.recipientUserId,
    },
  });
  if (!sealed.ok) {
    throw new Error("seal failed");
  }
  return {
    recipientUserId: input.recipientUserId,
    recipientEncPubHex: encPubHex,
    encHex: encodeHex(sealed.value.enc),
    ciphertextHex: encodeHex(sealed.value.ciphertext),
  };
}

/** Opens a distributed wrap with the member's device key (the accepting client's step). */
async function openAs(userId: string, proposalId: string, variableId: string, wrap: WireWrap) {
  const baseVersion = 1;
  const keys = vectorKeyOf(userId);
  const pair = await importEncryptionKeyPair({
    publicKey: hexBytes(keys.enc_pub_hex),
    privateKey: hexBytes(keys.enc_sk_seed_hex),
  });
  if (!pair.ok) {
    throw new Error("key pair import failed");
  }
  const opened = await openProposedValue({
    recipientKeyPair: pair.value,
    sealed: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
    context: {
      projectId,
      environmentId: ENV,
      proposalId,
      variableId,
      baseVersion,
      recipientUserId: userId,
    },
  });
  return opened.ok ? new TextDecoder().decode(opened.value) : null;
}

interface ProposalOptions {
  readonly proposalId?: string;
  readonly variableId?: string;
  readonly baseVersion?: number;
  readonly recipients?: readonly string[];
  readonly expiresInDays?: number;
  readonly wraps?: readonly WireWrap[];
}

/** A well-formed proposal of one variable sealed to W(E) unless overridden. */
async function proposalFor(options: ProposalOptions = {}) {
  const proposalId = options.proposalId ?? PROPOSAL_ID;
  const variableId = options.variableId ?? VAR;
  const wraps =
    options.wraps ??
    (await Promise.all(
      (options.recipients ?? WRITERS).map((recipientUserId) =>
        sealTo({
          proposalId,
          variableId,
          baseVersion: options.baseVersion ?? 1,
          recipientUserId,
          plaintext: NEW_VALUE,
        }),
      ),
    ));
  return {
    proposalId,
    connector: "exec",
    facts: ["./scripts/rotate.sh: new credential produced"],
    expiresInDays: options.expiresInDays ?? 7,
    variables: [{ variableId, baseVersion: options.baseVersion ?? 1, wraps }],
  };
}

/** W(E) of the fixture's environment: the writers' device enc keys. */
const writerRecipients = () =>
  WRITERS.map((userId) => ({ userId, encPubHex: vectorKeyOf(userId).enc_pub_hex }));

/**
 * The pre-flight of a mint (AUTH_SPEC §14-5 — the mint's checks before the
 * issuer is touched). The recipient set defaults to W(E).
 */
async function preflight(input: {
  readonly variables: readonly { variableId: string; baseVersion: number }[];
  readonly oidcToken?: string;
  readonly recipients?: readonly { userId: string; encPubHex: string }[];
}): Promise<Response> {
  return SELF.fetch(
    `https://maruhi.test/projects/${projectId}/environments/${ENV}/rotation-proposals/preflight`,
    {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        oidcToken: input.oidcToken ?? (await makeOidcToken()),
        ephemeralPubHex: workload.publicKeyHex,
        variables: input.variables,
        recipients: input.recipients ?? writerRecipients(),
      }),
    },
  );
}

async function mint(input: {
  readonly proposal: unknown;
  readonly oidcToken?: string;
  readonly ephemeralPubHex?: string;
}): Promise<Response> {
  const ephemeralPubHex = input.ephemeralPubHex ?? workload.publicKeyHex;
  return SELF.fetch(
    `https://maruhi.test/projects/${projectId}/environments/${ENV}/rotation-proposals`,
    {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        oidcToken: input.oidcToken ?? (await makeOidcToken()),
        ephemeralPubHex,
        proposal: input.proposal,
      }),
    },
  );
}

interface ListedProposal {
  readonly proposalId: string;
  readonly environmentId: string;
  readonly connector: string;
  readonly facts: readonly string[];
  readonly claimsDigestHex: string;
  readonly grantChainSeq: number;
  readonly variables: readonly {
    readonly variableId: string;
    readonly baseVersion: number;
    readonly wraps: readonly WireWrap[];
  }[];
}

async function listAs(userId: string): Promise<Response> {
  return requestJson("GET", "/rotation/proposals", token(userId));
}

async function proposalsOf(userId: string): Promise<readonly ListedProposal[]> {
  const response = await listAs(userId);
  await expectStatus(response, 200);
  return ((await response.json()) as { proposals: readonly ListedProposal[] }).proposals;
}

function resolveAs(userId: string, proposalId: string, body: unknown): Promise<Response> {
  return requestJson("POST", `/rotation/proposals/${proposalId}/resolution`, token(userId), body);
}

/** An environment with one variable, granted for leasing (no server-wrap backfill — the mint needs none). */
async function grantedProject() {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  await grantServer({ scope: [ENV] });
  return { dek, v1 };
}

/** Pins a status and, on a mismatch, shows the body (the reason code) in the failure. */
async function expectStatus(response: Response, status: number): Promise<void> {
  if (response.status !== status) {
    throw new Error(
      `expected HTTP ${status}, got ${response.status}: ${await response.clone().text()}`,
    );
  }
}

async function expectRejected(response: Response, reason: string): Promise<void> {
  await expectStatus(response, 422);
  expect(await response.json()).toMatchObject({ _tag: "RotationProposalRejected", reason });
}

describe("sealed value proposals: mint, list, accept (AUTH_SPEC §14-5 / CRYPTO_SPEC §5.3)", () => {
  it("stores a proposal sealed to W(E), distributes each member only its own wraps, and a member accepts it after pushing", async () => {
    const { dek, v1 } = await grantedProject();
    const minted = await mint({ proposal: await proposalFor() });
    await expectStatus(minted, 200);
    expect(await minted.json()).toMatchObject({ proposalId: PROPOSAL_ID });

    // The audit row (AUDIT_SPEC §3.3): actor system, the lease's attribution
    const proposed = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "rotation.proposed",
    );
    expect(proposed).toHaveLength(1);
    expect(proposed[0]).toMatchObject({ actor_type: "system", environment_id: ENV });
    const payload = JSON.parse(String(proposed[0]?.["payload"])) as Record<string, unknown>;
    expect(payload["proposalId"]).toBe(PROPOSAL_ID);
    expect(payload["variableIds"]).toEqual([VAR]);
    expect(payload["claimsDigest"]).toBe(await claimsDigestOf());
    expect(payload["connector"]).toBe("exec");
    const granted = await queryProjectDo(
      projectId,
      "SELECT chain_seq FROM audit_events WHERE event = 'chain.server_granted'",
    );
    expect(payload["grantChainSeq"]).toBe(granted[0]?.["chain_seq"]);

    // Each member sees only its own wraps and can open them with its device key
    const forMember = await proposalsOf(MEMBER);
    expect(forMember).toHaveLength(1);
    const listed = forMember[0];
    expect(listed).toMatchObject({
      proposalId: PROPOSAL_ID,
      environmentId: ENV,
      connector: "exec",
      claimsDigestHex: await claimsDigestOf(),
    });
    expect(listed?.variables[0]?.wraps.map((wrap) => wrap.recipientUserId)).toEqual([MEMBER]);
    const wrap = listed?.variables[0]?.wraps[0];
    expect(wrap).toBeDefined();
    if (wrap === undefined) {
      return;
    }
    expect(await openAs(MEMBER, PROPOSAL_ID, VAR, wrap)).toBe(NEW_VALUE);
    // The owner's copy is a different Seal of the same value
    const forOwner = await proposalsOf(OWNER);
    expect(forOwner[0]?.variables[0]?.wraps.map((own) => own.recipientUserId)).toEqual([OWNER]);
    // A reader is never a recipient (403); a non-member gets the uniform 404
    expect((await listAs(READER)).status).toBe(403);
    expect((await listAs(STRANGER)).status).toBe(404);
    // Nothing a member sees decrypts under another member's key
    expect(await openAs(OWNER, PROPOSAL_ID, VAR, wrap)).toBeNull();

    // Acceptance = the member's own push (§4.1), then the resolution naming it
    const v2 = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      NEW_VALUE,
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const pushed = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(pushed.status).toBe(200);
    const accepted = await resolveAs(MEMBER, PROPOSAL_ID, {
      outcome: "accepted",
      versions: [{ variableId: VAR, version: 2 }],
    });
    expect(accepted.status).toBe(204);
    expect(await proposalsOf(MEMBER)).toEqual([]);
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM rotation_proposal_wraps WHERE proposal_id = ?",
      PROPOSAL_ID,
    );
    expect(rows[0]?.["n"]).toBe(0);
    const resolved = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "rotation.proposal_accepted",
    );
    expect(resolved).toHaveLength(1);
    expect(resolved[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: MEMBER,
      environment_id: ENV,
    });
    expect(JSON.parse(String(resolved[0]?.["payload"]))).toMatchObject({
      proposalId: PROPOSAL_ID,
      versions: [{ variableId: VAR, version: 2 }],
    });
  });

  it("refuses a recipient set that is not exactly W(E): a missing member, an extra reader, a duplicate device", async () => {
    await grantedProject();
    await expectRejected(
      await mint({ proposal: await proposalFor({ recipients: [OWNER] }) }),
      "recipients-mismatch",
    );
    await expectRejected(
      await mint({ proposal: await proposalFor({ recipients: [OWNER, MEMBER, READER] }) }),
      "recipients-mismatch",
    );
    await expectRejected(
      await mint({ proposal: await proposalFor({ recipients: [OWNER, MEMBER, MEMBER] }) }),
      "recipients-mismatch",
    );
    // The reader's own copy was never stored (nothing to list)
    expect(await proposalsOf(MEMBER)).toEqual([]);
  });

  it("applies the §14-5 acceptance checks: stale base, inactive variable, duplicate id, far expiry — and the window counts only stored proposals", async () => {
    await grantedProject();
    await expectRejected(
      await mint({ proposal: await proposalFor({ baseVersion: 2 }) }),
      "base-version-stale",
    );
    await expectRejected(
      await mint({ proposal: await proposalFor({ variableId: "var-nope" }) }),
      "variable-inactive",
    );
    // The lifetime is a bounded duration on the wire (1 to 30 days): out of
    // range is a payload refusal, never a reason after the issuer was touched
    expect((await mint({ proposal: await proposalFor({ expiresInDays: 31 }) })).status).toBe(400);
    expect((await mint({ proposal: await proposalFor({ expiresInDays: 0 }) })).status).toBe(400);
    const windows = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'proposed'",
    );
    expect(windows).toEqual([]);
    await expectStatus(await mint({ proposal: await proposalFor() }), 200);
    await expectRejected(await mint({ proposal: await proposalFor() }), "duplicate-id");
    const consumed = await queryProjectDo(
      projectId,
      "SELECT count FROM lease_windows WHERE kind = 'proposed'",
    );
    expect(consumed[0]?.["count"]).toBe(1);
  });

  it("shares the lease's authorization: no grant is the uniform 404, and a copy of the token with another key is 401 token-replayed", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await mint({ proposal: await proposalFor() })).status).toBe(404);
    await grantServer({ scope: [ENV] });
    const oidcToken = await makeOidcToken();
    const legit = await workloadKeyPair();
    expect(
      (
        await mint({
          proposal: await proposalFor(),
          oidcToken,
          ephemeralPubHex: legit.publicKeyHex,
        })
      ).status,
    ).toBe(200);
    const thief = await workloadKeyPair();
    const replayed = await mint({
      proposal: await proposalFor({ proposalId: "ffeeddccbbaa99887766554433221100" }),
      oidcToken,
      ephemeralPubHex: thief.publicKeyHex,
    });
    expect(replayed.status).toBe(401);
    expect(await replayed.json()).toMatchObject({ reason: "token-replayed" });
  });

  it("resolution: an acceptance naming no newer stored version is 422, a rejection deletes the rows with its audit row, and the id is 404 afterwards", async () => {
    await grantedProject();
    await expectStatus(await mint({ proposal: await proposalFor() }), 200);
    await expectRejected(
      await resolveAs(MEMBER, PROPOSAL_ID, {
        outcome: "accepted",
        versions: [{ variableId: VAR, version: 1 }],
      }),
      "version-missing",
    );
    await expectRejected(
      await resolveAs(MEMBER, PROPOSAL_ID, {
        outcome: "accepted",
        versions: [{ variableId: VAR, version: 2 }],
      }),
      "version-missing",
    );
    // A reader cannot resolve (member or above)
    expect((await resolveAs(READER, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(403);
    expect((await resolveAs(MEMBER, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(204);
    expect(await proposalsOf(MEMBER)).toEqual([]);
    const rejected = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "rotation.proposal_rejected",
    );
    expect(rejected).toHaveLength(1);
    expect(rejected[0]).toMatchObject({ actor_type: "user", actor_user_id: MEMBER });
    const again = await resolveAs(MEMBER, PROPOSAL_ID, { outcome: "rejected" });
    expect(again.status).toBe(404);
    expect(await again.json()).toMatchObject({ _tag: "RotationProposalNotFound" });
  });

  it("keeps the minted variable order (companions first) and refuses a repeated variable", async () => {
    const { dek } = await grantedProject();
    const USER_VAR = "var-database-user-0002";
    await createVariableOk(dek, USER_VAR, "DATABASE_USER", "app_a");
    const sealAll = (variableId: string, plaintext: string) =>
      Promise.all(
        WRITERS.map((recipientUserId) =>
          sealTo({
            proposalId: PROPOSAL_ID,
            variableId,
            baseVersion: 1,
            recipientUserId,
            plaintext,
          }),
        ),
      );
    // The ids sort the other way round (USER_VAR > VAR), so an id-ordered
    // store would invert the push order
    expect(USER_VAR > VAR).toBe(true);
    const minted = await mint({
      proposal: {
        proposalId: PROPOSAL_ID,
        connector: "postgres",
        facts: ["role app_b now in use"],
        expiresInDays: 1,
        variables: [
          { variableId: USER_VAR, baseVersion: 1, wraps: await sealAll(USER_VAR, "app_b") },
          { variableId: VAR, baseVersion: 1, wraps: await sealAll(VAR, NEW_VALUE) },
        ],
      },
    });
    await expectStatus(minted, 200);
    const listed = await proposalsOf(MEMBER);
    expect(listed[0]?.variables.map((variable) => variable.variableId)).toEqual([USER_VAR, VAR]);
    expect(listed[0]?.connector).toBe("postgres");
    // The rows carry the position
    const rows = await queryProjectDo(
      projectId,
      "SELECT variable_id, position FROM rotation_proposal_variables WHERE proposal_id = ? ORDER BY position",
      PROPOSAL_ID,
    );
    expect(rows.map((row) => [row["variable_id"], row["position"]])).toEqual([
      [USER_VAR, 0],
      [VAR, 1],
    ]);
    await expectRejected(
      await mint({
        proposal: {
          proposalId: "ffeeddccbbaa99887766554433221100",
          connector: "postgres",
          facts: [],
          expiresInDays: 1,
          variables: [
            { variableId: VAR, baseVersion: 1, wraps: await sealAll(VAR, NEW_VALUE) },
            { variableId: VAR, baseVersion: 1, wraps: await sealAll(VAR, NEW_VALUE) },
          ],
        },
      }),
      "duplicate-variable",
    );
  });

  it("W(E) is judged per device: a second device of the owner is a recipient, a reader-capped one is not", async () => {
    await grantedProject();
    const phone = vectorKeyNamed("user-owner-0001@phone");
    const readerCap = vectorKeyNamed("user-owner-0015@reader-cap");
    const addDevice = (keys: typeof phone, roleCap: "owner" | "reader") =>
      appendOperation(fixture, OWNER, {
        op: "add_device",
        payload: {
          encPubHex: keys.enc_pub_hex,
          sigPubHex: keys.sig_pub_hex,
          roleCap,
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      });
    await addDevice(phone, "owner");
    await addDevice(readerCap, "reader");
    const wrapsFor = (devices: readonly { userId: string; encPubHex?: string }[]) =>
      Promise.all(
        devices.map((device) =>
          sealTo({
            proposalId: PROPOSAL_ID,
            variableId: VAR,
            baseVersion: 1,
            recipientUserId: device.userId,
            plaintext: NEW_VALUE,
            ...(device.encPubHex === undefined ? {} : { encPubHex: device.encPubHex }),
          }),
        ),
      );
    // Without the phone: a member is left out → refused
    await expectRejected(
      await mint({
        proposal: await proposalFor({
          wraps: await wrapsFor([{ userId: OWNER }, { userId: MEMBER }]),
        }),
      }),
      "recipients-mismatch",
    );
    // With the reader-capped device: an extra recipient → refused
    await expectRejected(
      await mint({
        proposal: await proposalFor({
          wraps: await wrapsFor([
            { userId: OWNER },
            { userId: OWNER, encPubHex: phone.enc_pub_hex },
            { userId: OWNER, encPubHex: readerCap.enc_pub_hex },
            { userId: MEMBER },
          ]),
        }),
      }),
      "recipients-mismatch",
    );
    // Exactly W(E): the owner's two member-or-above devices and the member
    await expectStatus(
      await mint({
        proposal: await proposalFor({
          wraps: await wrapsFor([
            { userId: OWNER },
            { userId: OWNER, encPubHex: phone.enc_pub_hex },
            { userId: MEMBER },
          ]),
        }),
      }),
      200,
    );
    // The owner lists both of its own wraps (every device of the caller)
    const forOwner = await proposalsOf(OWNER);
    expect(
      forOwner[0]?.variables[0]?.wraps.map((wrap) => wrap.recipientEncPubHex).toSorted(),
    ).toEqual([vectorKeyOf(OWNER).enc_pub_hex, phone.enc_pub_hex].toSorted());
  });

  it("stores the expiry as the server's instant, caps the pending count, and rate-limits the mint window with a lease_denied row", async () => {
    const { dek } = await grantedProject();
    const before = Date.now();
    const first = await mint({ proposal: await proposalFor({ expiresInDays: 3 }) });
    await expectStatus(first, 200);
    const receipt = (await first.json()) as { expiresAtMs: number };
    const threeDays = 3 * 24 * 60 * 60 * 1000;
    expect(receipt.expiresAtMs).toBeGreaterThanOrEqual(before + threeDays);
    expect(receipt.expiresAtMs).toBeLessThanOrEqual(Date.now() + threeDays);
    await queryProjectDo(projectId, "DELETE FROM rotation_proposals");
    await queryProjectDo(projectId, "DELETE FROM lease_windows WHERE kind = 'proposed'");
    // Fill the pending slots (distinct ids, one variable each — a variable
    // holds one pending proposal at a time), then one more is refused
    for (let i = 0; i < MAX_PENDING_ROTATION_PROPOSALS; i += 1) {
      const proposalId = i.toString(16).padStart(32, "0");
      const variableId = i === 0 ? VAR : `var-slot-${i.toString().padStart(14, "0")}`;
      if (i > 0) {
        await createVariableOk(dek, variableId, `SLOT_${i}`, `value-${i}`);
      }
      await expectStatus(
        await mint({ proposal: await proposalFor({ proposalId, variableId }) }),
        200,
      );
    }
    await createVariableOk(dek, "var-slot-overflow", "SLOT_OVERFLOW", "value-overflow");
    await expectRejected(
      await mint({
        proposal: await proposalFor({
          proposalId: "f".repeat(32),
          variableId: "var-slot-overflow",
        }),
      }),
      "pending-limit",
    );
    // The window: exhausted = 429 after authorization, with a denied row (reason only)
    await queryProjectDo(
      projectId,
      "UPDATE lease_windows SET count = ?, window_start = ? WHERE kind = 'proposed'",
      MAX_ROTATION_PROPOSALS_PER_WINDOW,
      Date.now(),
    );
    const limited = await mint({ proposal: await proposalFor({ proposalId: "e".repeat(32) }) });
    expect(limited.status).toBe(429);
    const denied = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "server.lease_denied",
    );
    expect(denied).toHaveLength(1);
    expect(JSON.parse(String(denied[0]?.["payload"]))).toMatchObject({ reason: "rate-limited" });
  });

  it("the pre-flight answers the mint's checks without storing anything: ok, then variable-pending once a proposal is stored, stale base, and the uniform 404 without a grant", async () => {
    // No grant: the same uniform 404 as the lease (existence concealment)
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    expect((await preflight({ variables: [{ variableId: VAR, baseVersion: 1 }] })).status).toBe(
      404,
    );
    await grantServer({ scope: [ENV] });
    await expectStatus(await preflight({ variables: [{ variableId: VAR, baseVersion: 1 }] }), 200);
    // The recipient set the job will seal to is checked here too (ruling O
    // revision, round 4): exactly W(E) passes (above), a missing writer is
    // refused before the issuer is touched
    const writers = writerRecipients();
    await expectRejected(
      await preflight({
        variables: [{ variableId: VAR, baseVersion: 1 }],
        recipients: writers.slice(0, 1),
      }),
      "recipients-mismatch",
    );
    await expectRejected(
      await preflight({ variables: [{ variableId: VAR, baseVersion: 2 }] }),
      "base-version-stale",
    );
    await expectRejected(
      await preflight({ variables: [{ variableId: "var-unknown-0000000000", baseVersion: 1 }] }),
      "variable-inactive",
    );
    // Nothing was stored or counted by the pre-flights
    expect(await proposalsOf(MEMBER)).toEqual([]);
    expect(
      await queryProjectDo(projectId, "SELECT count FROM lease_windows WHERE kind = 'proposed'"),
    ).toEqual([]);
    expect(
      (await readAuditEvents(projectId)).filter((event) => event["event"] === "rotation.proposed"),
    ).toEqual([]);
    // A stored proposal makes the same variable pending for the next job —
    // at the mint as well as at the pre-flight (two jobs that both
    // pre-flighted before either minted — ruling O revision, round 4)
    await expectStatus(await mint({ proposal: await proposalFor() }), 200);
    await expectRejected(
      await preflight({ variables: [{ variableId: VAR, baseVersion: 1 }] }),
      "variable-pending",
    );
    await expectRejected(
      await mint({ proposal: await proposalFor({ proposalId: "f".repeat(32) }) }),
      "variable-pending",
    );
    expect(await proposalsOf(MEMBER)).toHaveLength(1);
    // The expiry sweep (on a pre-flight too) leaves the proposal's history
    // as an audit row and frees the variable
    await queryProjectDo(
      projectId,
      "UPDATE rotation_proposals SET expires_at = ? WHERE proposal_id = ?",
      Date.now() - 1000,
      PROPOSAL_ID,
    );
    await expectStatus(await preflight({ variables: [{ variableId: VAR, baseVersion: 1 }] }), 200);
    const expired = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "rotation.proposal_expired",
    );
    expect(expired).toHaveLength(1);
    expect(expired[0]).toMatchObject({ actor_type: "system", environment_id: ENV });
    expect(JSON.parse(String(expired[0]?.["payload"]))).toEqual({
      proposalId: PROPOSAL_ID,
      expiresAtMs: expect.any(Number),
    });
    expect(await proposalsOf(MEMBER)).toEqual([]);
    // An exhausted mint window is read by the pre-flight (nothing consumed)
    await queryProjectDo(
      projectId,
      "UPDATE lease_windows SET count = ?, window_start = ? WHERE kind = 'proposed'",
      MAX_ROTATION_PROPOSALS_PER_WINDOW,
      Date.now(),
    );
    const limited = await preflight({ variables: [{ variableId: VAR, baseVersion: 1 }] });
    expect(limited.status).toBe(429);
    await expect(limited.json()).resolves.toMatchObject({ _tag: "LeaseRateLimited" });
  });

  it("an expired proposal is not listed but is still resolvable until swept, and a listed member of another environment sees nothing", async () => {
    await grantedProject();
    // A member listed on another environment is not in W(ENV) and sees no proposal there
    const DEV = testUserId("user-devmember-0010");
    await createEnvironmentOk(fixture, "env-other", "Other");
    await seedMemberToken(fixture, DEV, 9010);
    await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", ["env-other"]));
    await expectStatus(await mint({ proposal: await proposalFor() }), 200);
    expect(await proposalsOf(DEV)).toEqual([]);
    expect(await proposalsOf(MEMBER)).toHaveLength(1);
    // Out of scope, the resolution is the same 404 as unknown / resolved /
    // expired (the environment is known only from the stored row)
    expect((await resolveAs(DEV, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(404);
    expect(await proposalsOf(MEMBER)).toHaveLength(1);
    await queryProjectDo(
      projectId,
      "UPDATE rotation_proposals SET expires_at = ? WHERE proposal_id = ?",
      Date.now() - 1000,
      PROPOSAL_ID,
    );
    // A member who began the resolution before the expiry reaches the row
    // until a sweep drops it: the outcome is theirs, not "nobody's"
    expect((await resolveAs(MEMBER, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(204);
    const events = (await readAuditEvents(projectId)).map((event) => event["event"]);
    expect(events).toContain("rotation.proposal_rejected");
    expect(events).not.toContain("rotation.proposal_expired");
    expect((await resolveAs(MEMBER, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(404);
    // The id is free again
    await expectStatus(await mint({ proposal: await proposalFor() }), 200);
    // The member list sweeps too (ruling P revision, round 4): a project
    // whose rotation job is gone still closes its expired proposals' history
    // on the next `rotation proposals` / `--fail-on-pending`, and the
    // sealed values leave the §12-8 meter
    await queryProjectDo(
      projectId,
      "UPDATE rotation_proposals SET expires_at = ? WHERE proposal_id = ?",
      Date.now() - 1000,
      PROPOSAL_ID,
    );
    expect(await proposalsOf(MEMBER)).toEqual([]);
    expect(
      (await readAuditEvents(projectId)).filter(
        (event) => event["event"] === "rotation.proposal_expired",
      ),
    ).toHaveLength(1);
    expect(await queryProjectDo(projectId, "SELECT proposal_id FROM rotation_proposals")).toEqual(
      [],
    );
    expect((await resolveAs(MEMBER, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(404);
  });
  it("the environment's deletion removes its proposals and closes each one's history: cancelled by the deleting member, or expired when already past its expiry", async () => {
    const { dek } = await grantedProject();
    const USER_VAR = "var-database-user-0002";
    await createVariableOk(dek, USER_VAR, "DATABASE_USER", "app_a");
    const EXPIRED_ID = "ffeeddccbbaa99887766554433221100";
    await expectStatus(await mint({ proposal: await proposalFor() }), 200);
    await expectStatus(
      await mint({
        proposal: await proposalFor({ proposalId: EXPIRED_ID, variableId: USER_VAR }),
      }),
      200,
    );
    // The second one is past its expiry and no sweep has dropped it yet
    const expiredAtMs = Date.now() - 1000;
    await queryProjectDo(
      projectId,
      "UPDATE rotation_proposals SET expires_at = ? WHERE proposal_id = ?",
      expiredAtMs,
      EXPIRED_ID,
    );
    expect(await proposalsOf(OWNER)).toHaveLength(1);
    await expectStatus(await deleteEnvironmentRequest(fixture, ENV, OWNER), 204);
    for (const table of [
      "rotation_proposals",
      "rotation_proposal_variables",
      "rotation_proposal_wraps",
    ]) {
      expect(await queryProjectDo(projectId, `SELECT 1 FROM ${table}`)).toEqual([]);
    }
    const events = await readAuditEvents(projectId);
    const cancelled = events.filter((event) => event["event"] === "rotation.proposal_cancelled");
    expect(cancelled).toHaveLength(1);
    expect(cancelled[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: OWNER,
      actor_key_fingerprint: vectorKeyOf(OWNER).key_fingerprint_hex,
      environment_id: ENV,
    });
    expect(JSON.parse(String(cancelled[0]?.["payload"]))).toMatchObject({
      proposalId: PROPOSAL_ID,
    });
    const expired = events.filter((event) => event["event"] === "rotation.proposal_expired");
    expect(expired).toHaveLength(1);
    expect(expired[0]).toMatchObject({ actor_type: "system", environment_id: ENV });
    expect(JSON.parse(String(expired[0]?.["payload"]))).toEqual({
      proposalId: EXPIRED_ID,
      expiresAtMs: expiredAtMs,
    });
    // Both closing rows sit before env.deleted, in the deletion's transaction
    const order = events.map((event) => event["event"]);
    expect(order.indexOf("rotation.proposal_cancelled")).toBeLessThan(order.indexOf("env.deleted"));
    // The owner's scope is `all`, which a scope filter alone would still
    // match: the rows are gone, so nothing is listed and nothing resolves
    expect(await proposalsOf(OWNER)).toEqual([]);
    expect((await resolveAs(OWNER, PROPOSAL_ID, { outcome: "rejected" })).status).toBe(404);
    expect(
      (await readAuditEvents(projectId)).filter(
        (event) => event["event"] === "rotation.proposal_rejected",
      ),
    ).toEqual([]);
  });
});
