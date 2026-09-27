// Integration tests for head-attestation acceptance, storage, and
// distribution (CRYPTO_SPEC §6.4 / §6.6, AUTH_SPEC §16-1)
// (@cloudflare/vitest-plugin — real workerd environment). Items
// verified: monotonic acceptance (regression 409, idempotent 204),
// row deletion on remove, distribution to current members only, no
// acceptance-time distribution, a reader submitting under a read
// scope, and rate limiting.
//
// The chain is built with the minimal shape attestation needs
// (genesis → add_member member → add_member reader — no environments
// or composites required) using test-time signatures with vector
// keys.

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { importSigningKeyPair, signHeadAttestation } from "@maruhi/crypto";
import { vectorKeys } from "@maruhi/crypto/test-support";
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW } from "../src/policy.ts";
import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  resetAuthDb,
  seedOrgMember,
  seedUser,
} from "./support/auth.ts";
import { toWireEntry, vectorEntries, vectorProjectId } from "./support/chain-vectors.ts";
import { hexBytes, resignEntryAt, signEntryAt } from "./support/data-crypto.ts";
import { resetProjectDo } from "./support/project-do.ts";

const ORG = "org-attest-0001";
const OWNER = "user-owner-0001";
const MEMBER = "user-member-0002";
const READER = "user-admin-0003"; // stays a reader since no change_role is appended
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

/** Set up the minimal chain: genesis → add_member (member) → add_member (reader). */
async function setupChain(): Promise<Head> {
  const genesis = vectorEntries[0];
  const addMember = vectorEntries[1];
  const addReader = vectorEntries[5]; // add_member user-admin-0003 role reader
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

/** Sign a §6.6 attestation with the attester's key (project_id = genesis hash). */
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
      projectId: vectorProjectId,
      attesterUserId,
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
  await resetProjectDo(vectorProjectId);
  await resetAuthDb();
  tokens = {};
  for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
    await seedUser(userId, githubId);
    tokens[userId] = await cliToken(githubId);
  }
  await seedOrgMember(ORG, OWNER, "member");
});

describe("PUT /projects/:projectId/head-attestation (acceptance — §6.4 / §16-1)", () => {
  it("a reader can submit under a read-scope token and lands on the distribution with attester info (acceptance time is not carried)", async () => {
    const head = await setupChain();
    const readOnly: readonly TokenScope[] = [{ project: vectorProjectId, permission: "read" }];
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
    // The acceptance time is not distributed (§16-1 — limiting
    // behavioral information). Pin via the key set that no time-ish
    // key appears on the wire
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
    // Advancing (head 3) is an upsert — the latest single row per member
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    // Re-submitting the same seq is an idempotent 204 (retry-safe —
    // not a silently swallowed 200 but a success as a re-send of the
    // same content)
    expect((await submitAttestation(OWNER, head)).status).toBe(204);
    // A regression is 409 + the stored seq (does not quietly swallow
    // a floor corruption or a concurrent-CLI symptom)
    const regressed = await submitAttestation(OWNER, head2);
    expect(regressed.status).toBe(409);
    expect(await regressed.json()).toMatchObject({
      _tag: "AttestationRegression",
      storedSeq: 3,
    });
    // Only the latest single row per member is stored
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

    // seq inside the chain's own range but a hash mismatch (valid signature) = chain-head-unknown
    const bogusHead = { seq: head.seq, hashHex: "ab".repeat(32) };
    const mismatch = await submitAttestation(OWNER, bogusHead);
    expect(mismatch.status).toBe(422);
    expect(await mismatch.json()).toMatchObject({ reason: "chain-head-unknown" });

    // A seq ahead of the current head (valid signature) is also
    // chain-head-unknown (§6.4 — the server has no re-sync branch)
    const future = await submitAttestation(OWNER, { seq: 9, hashHex: "cd".repeat(32) });
    expect(future.status).toBe(422);
    expect(await future.json()).toMatchObject({ reason: "chain-head-unknown" });
  });

  it("verification cannot pass with another's user_id (structural enforcement of caller = attester)", async () => {
    const head = await setupChain();
    // Submitting an attestation signed with MEMBER's key under
    // OWNER's token — the server uses the calling principal (OWNER)
    // as the signed attester_user_id, so the signature mismatches
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
    // The window is a DO SQLite row — instead of 60 real PUTs, seed a
    // full window directly (the window's own semantics — judgment and
    // rollback — go through data-store's implementation)
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
    // The window is per member — other members are unaffected
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

    // The row was deleted as an acceptance side effect (distributed
    // to current members only — convergence to the chain-derived
    // truth)
    expect((await fetchAttestations()).map((a) => a.attesterUserId)).toEqual([OWNER]);
    // A re-submission by the removed member is §11-2's uniform 404
    const resubmit = await submitAttestation(MEMBER, { seq: 4, hashHex: removal.hash });
    expect(resubmit.status).toBe(404);
  });
});
