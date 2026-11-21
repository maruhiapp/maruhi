import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { importSigningKeyPair, signHeadAttestation } from "@maruhi/crypto";
import { testUserId } from "@maruhi/crypto/test-support";
import { vectorKeys } from "@maruhi/crypto/test-support";
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW } from "../src/policy.ts";
import { BASE, bearer, cliToken, JSON_HEADERS, reseedAuthDb, seedUser } from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { hexBytes, resignEntryAt, signEntryAt } from "./support/data-crypto.ts";
import { testProjectId } from "./support/data-crypto.ts";
import { resetProjectDo } from "./support/project-do.ts";

const ORG = "org-attest-0001";
const OWNER = testUserId("user-owner-0001");
const MEMBER = testUserId("user-member-0002");
const READER = testUserId("user-admin-0003");
const GITHUB_IDS: Record<string, number> = { [OWNER]: 9001, [MEMBER]: 9002, [READER]: 9003 };

let tokens: Record<string, string> = {};

function tokenFor(userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no seeded token for ${userId}`);
  }
  return token;
}

interface Head {
  readonly seq: number;
  readonly hashHex: string;
}

async function setupChain(): Promise<Head> {
  const genesis = vectorEntries[0];
  const addMember = vectorEntries[1];
  const addReader = vectorEntries[5];
  if (genesis === undefined || addMember === undefined || addReader === undefined) {
    throw new Error("missing vector entries");
  }
  const init = await SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenFor(OWNER)) },
    body: JSON.stringify({ orgId: ORG, entry: toWireEntry(genesis) }),
  });
  expect(init.status).toBe(200);
  const second = await appendEntry(genesis.entry_hash_hex, toWireEntry(addMember));
  expect(second.status).toBe(200);
  const reader = await resignEntryAt(toWireEntry(addReader), 3, addMember.entry_hash_hex);
  const third = await appendEntry(addMember.entry_hash_hex, reader.entry);
  expect(third.status).toBe(200);
  return { seq: 3, hashHex: reader.hash };
}

const appendEntry = (
  parentHeadHashHex: string,
  entry: ChainEntry,
  headers?: Record<string, string>,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify({ parentHeadHashHex, entry }),
  });

async function signAttestation(attesterUserId: string, head: Head): Promise<string> {
  const keys = vectorKeys[attesterUserId];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${attesterUserId}`);
  }
  const pair = await importSigningKeyPair({
    publicKey: hexBytes(keys.sig_pub_hex),
    privateSeed: hexBytes(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    throw new Error("key import failed");
  }
  const signed = await signHeadAttestation({
    context: {
      suite: "maruhi/v1",
      projectId: testProjectId(vectorProjectId),
      attesterUserId: testUserId(attesterUserId),
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
    },
    signingKey: pair.value.privateKey,
  });
  if (!signed.ok) {
    throw new Error("attestation signing failed");
  }
  return signed.value;
}

const putAttestation = (
  body: Record<string, unknown>,
  headers: Record<string, string>,
  projectId: string = vectorProjectId,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/head-attestation`, {
    method: "PUT",
    headers: { ...JSON_HEADERS, ...headers },
    body: JSON.stringify(body),
  });

async function submitAttestation(
  attesterUserId: string,
  head: Head,
  headers?: Record<string, string>,
): Promise<Response> {
  const signatureHex = await signAttestation(attesterUserId, head);
  return putAttestation(
    { suite: "maruhi/v1", chainHeadHashHex: head.hashHex, chainHeadSeq: head.seq, signatureHex },
    headers ?? bearer(tokenFor(attesterUserId)),
  );
}

interface WireAttestation {
  readonly suite: string;
  readonly attesterUserId: string;
  readonly attesterKeyFingerprintHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

async function fetchAttestations(asUserId: string = OWNER): Promise<readonly WireAttestation[]> {
  const response = await SELF.fetch(`${BASE}/projects/${vectorProjectId}/chain`, {
    headers: bearer(tokenFor(asUserId)),
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { attestations?: readonly WireAttestation[] };
  expect(body.attestations).toBeDefined();
  return body.attestations ?? [];
}

beforeEach(async () => {
  const [issued] = await Promise.all([
    reseedAuthDb(GITHUB_IDS, { orgId: ORG, userId: OWNER }),
    resetProjectDo(vectorProjectId),
  ]);
  tokens = issued;
});

describe("PUT /projects/:projectId/head-attestation (acceptance — §6.4 / §16-1)", () => {
  it("a reader can submit under a read-scope token and lands on the distribution with attester info (acceptance time is not carried)", async () => {
    const head = await setupChain();
    const readOnly: readonly TokenScope[] = [
      { project: testProjectId(vectorProjectId), permission: "read" },
    ];
    const readToken = await cliToken(GITHUB_IDS[READER] ?? 0, readOnly);
    const response = await submitAttestation(READER, head, bearer(readToken));
    expect(response.status).toBe(204);

    const attestations = await fetchAttestations();
    expect(attestations).toHaveLength(1);
    const readerKeys = vectorKeys[READER];
    expect(attestations[0]).toMatchObject({
      suite: "maruhi/v1",
      attesterUserId: READER,
      attesterKeyFingerprintHex: readerKeys?.key_fingerprint_hex,
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
    });
    expect(Object.keys(attestations[0] ?? {}).toSorted()).toEqual([
      "attesterKeyFingerprintHex",
      "attesterUserId",
      "chainHeadHashHex",
      "chainHeadSeq",
      "signatureHex",
      "suite",
    ]);
  });

  it("seq advances monotonically only: advance = overwrite, same seq = idempotent 204, regression = 409 (with the stored seq)", async () => {
    const head = await setupChain();
    const head2 = { seq: 2, hashHex: vectorEntries[1]?.entry_hash_hex ?? "" };
    expect((await submitAttestation(OWNER, head2)).status).toBe(204);
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    const regressed = await submitAttestation(OWNER, head2);
    expect(regressed.status).toBe(409);
    expect(await regressed.json()).toMatchObject({
      _tag: "AttestationRegression",
      storedSeq: 3,
    });
    const attestations = await fetchAttestations();
    expect(attestations).toHaveLength(1);
    expect(attestations[0]?.chainHeadSeq).toBe(3);
  });

  it("acceptance verification: broken signature = 422 signature-invalid, unknown head = 422 chain-head-unknown", async () => {
    const head = await setupChain();
    const good = await signAttestation(OWNER, head);
    const tampered = `${good.slice(0, -2)}${good.endsWith("00") ? "01" : "00"}`;
    const badSignature = await putAttestation(
      {
        suite: "maruhi/v1",
        chainHeadHashHex: head.hashHex,
        chainHeadSeq: head.seq,
        signatureHex: tampered,
      },
      bearer(tokenFor(OWNER)),
    );
    expect(badSignature.status).toBe(422);
    expect(await badSignature.json()).toMatchObject({ reason: "signature-invalid" });

    const bogusHead = { seq: head.seq, hashHex: "ab".repeat(32) };
    const mismatch = await submitAttestation(OWNER, bogusHead);
    expect(mismatch.status).toBe(422);
    expect(await mismatch.json()).toMatchObject({ reason: "chain-head-unknown" });

    const future = await submitAttestation(OWNER, { seq: 9, hashHex: "cd".repeat(32) });
    expect(future.status).toBe(422);
    expect(await future.json()).toMatchObject({ reason: "chain-head-unknown" });
  });

  it("acceptance verification: a head at which the attester was not yet a member = 422 chain-head-state-mismatch", async () => {
    const head = await setupChain();
    expect(head.seq).toBe(3);
    const genesisHead = { seq: 1, hashHex: vectorEntries[0]?.entry_hash_hex ?? "" };
    const response = await submitAttestation(MEMBER, genesisHead);
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({
      _tag: "AttestationRejected",
      reason: "chain-head-state-mismatch",
    });
    expect((await submitAttestation(OWNER, genesisHead)).status).toBe(204);
  });

  it("verification cannot pass with another's user_id (structural enforcement of caller = attester)", async () => {
    const head = await setupChain();
    const signatureHex = await signAttestation(MEMBER, head);
    const response = await putAttestation(
      { suite: "maruhi/v1", chainHeadHashHex: head.hashHex, chainHeadSeq: head.seq, signatureHex },
      bearer(tokenFor(OWNER)),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ reason: "signature-invalid" });
  });

  it("submissions by non-members / to uninitialized projects are uniformly 404 (§11-2)", async () => {
    await setupChain();
    await seedUser("user-outsider-0042", 9042);
    const outsiderToken = await cliToken(9042);
    const head = { seq: 1, hashHex: vectorEntries[0]?.entry_hash_hex ?? "" };
    const signatureHex = await signAttestation(OWNER, head);
    const body = {
      suite: "maruhi/v1",
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
      signatureHex,
    };
    expect((await putAttestation(body, bearer(outsiderToken))).status).toBe(404);
    expect((await putAttestation(body, bearer(tokenFor(OWNER)), "cd".repeat(32))).status).toBe(404);
  });

  it("exceeding the per-member fixed window (60/hour) is a 429 (other members' windows are independent)", async () => {
    const head = await setupChain();
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO attestation_windows (attester_user_id, window_start, count) VALUES (?, ?, ?)",
        OWNER,
        Date.now(),
        MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW,
      );
    });
    const limited = await submitAttestation(OWNER, head);
    expect(limited.status).toBe(429);
    const body = (await limited.json()) as { retryAfterSeconds: number };
    expect(body.retryAfterSeconds).toBeGreaterThan(0);
    expect((await submitAttestation(MEMBER, head)).status).toBe(204);
  });
});

describe("distribution and cleanup on remove (§6.4 / §16-1)", () => {
  it("accepting remove_member deletes the target's attestation row and later submissions are 404 (non-member)", async () => {
    const head = await setupChain();
    expect((await submitAttestation(MEMBER, head)).status).toBe(204);
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    expect((await fetchAttestations()).map((a) => a.attesterUserId).toSorted()).toEqual([
      MEMBER,
      OWNER,
    ]);

    const removal = await signEntryAt({
      seq: 4,
      prevHashHex: head.hashHex,
      actorUserId: OWNER,
      operation: { op: "remove_member", payload: { targetUserId: MEMBER } },
    });
    expect((await appendEntry(head.hashHex, removal.entry)).status).toBe(200);

    expect((await fetchAttestations()).map((a) => a.attesterUserId)).toEqual([OWNER]);
    const resubmit = await submitAttestation(MEMBER, { seq: 4, hashHex: removal.hash });
    expect(resubmit.status).toBe(404);
  });
});
