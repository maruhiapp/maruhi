// Measurement of the ES + PF1 K2 wire incompatibility (pinning that there is
// no compatibility-acceptance path).
//
// The 2026-09-14 ES revision changed the payload shape of add_member /
// change_role and the invite issuance statement, and there is no
// compatibility-acceptance path (CRYPTO_SPEC §6.2 — owner ruling). Here we
// reproduce "the pre-update CLI's shapes sent to the post-update server" and
// pin the **actual fail-closed responses**:
//   - appending a legacy-shape add_member (missing the 2 scope fields)
//     -> HTTP 400 (strict Schema)
//   - legacy-shape invite issue body (no scopeKind / scopeEnvironmentIds)
//     -> HTTP 400
//   - an add_member signed under the old canonicalization (scope not covered
//     by the signature) sent with the new-shape fields -> HTTP 422
//     `bad-signature` (consensus rule — an old signer cannot produce a
//     new-shape entry)
// The reverse direction (post-update CLI x pre-update server) turns unknown
// fields into a 400 under the old server's strict admission (§12-10 (1) —
// released 2026-08-19), a consequence of the behavior pinned by
// strict-payload.test.ts.

import { computeChainEntryHash, encodeHex, encodeLengthPrefixed, SUITE_ID } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import { vectorKeyOf } from "./support/data-crypto.ts";
import {
  type DataFixture,
  OWNER,
  projectId,
  setupDataProject,
  tokenOf,
} from "./support/data-fixture.ts";
import { signingKeyPairOf } from "./support/invites-scenario.ts";

const STRANGER = "user-stranger-0042";
const NEW_ENC_PUB = "ab".repeat(32);
const NEW_SIG_PUB = "cd".repeat(32);

let fixture: DataFixture;

beforeEach(async () => {
  fixture = await setupDataProject();
});

function appendRaw(entry: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
}

/** Signs a legacy CLI add_member entry (no scope fields) under the old canonicalization. */
async function legacySignedAddMember(): Promise<{
  readonly legacyEntry: Record<string, unknown>;
  readonly signatureHex: string;
  readonly base: Record<string, unknown>;
}> {
  const keys = vectorKeyOf(OWNER);
  const pair = await signingKeyPairOf(OWNER);
  const base = {
    suite: SUITE_ID,
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: { userId: OWNER, keyFingerprintHex: keys.key_fingerprint_hex },
    timestampMs: 1_700_000_000_000,
    op: "add_member",
  };
  const legacyPayload = {
    targetUserId: STRANGER,
    encPubHex: NEW_ENC_PUB,
    sigPubHex: NEW_SIG_PUB,
    role: "member",
  };
  // Old canonicalization (before 2026-09-14): payload_bytes = LP(target, enc, sig, role)
  const legacyPayloadBytes = encodeLengthPrefixed([
    legacyPayload.targetUserId,
    legacyPayload.encPubHex,
    legacyPayload.sigPubHex,
    legacyPayload.role,
  ]);
  const signedBytes = encodeLengthPrefixed([
    base.suite,
    base.seq,
    base.prevHashHex,
    base.op,
    base.actor.userId,
    base.actor.keyFingerprintHex,
    legacyPayloadBytes,
    base.timestampMs,
  ]);
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", pair.pair.privateKey, signedBytes as BufferSource),
  );
  const signatureHex = encodeHex(signature);
  return { legacyEntry: { ...base, payload: legacyPayload, signatureHex }, signatureHex, base };
}

describe("ES K2 migration — pre-release CLI shapes against the updated server", () => {
  it("rejects a legacy add_member (no scope fields) with HTTP 400 at the schema", async () => {
    const { legacyEntry } = await legacySignedAddMember();
    const response = await appendRaw(legacyEntry);
    expect(response.status).toBe(400);
  });

  it("rejects a legacy-canonicalized signature carried in the new shape with 422 bad-signature", async () => {
    const { signatureHex, base } = await legacySignedAddMember();
    const response = await appendRaw({
      ...base,
      payload: {
        targetUserId: STRANGER,
        encPubHex: NEW_ENC_PUB,
        sigPubHex: NEW_SIG_PUB,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
      signatureHex,
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { _tag: string; reason: string; seq: number };
    expect(body["_tag"]).toBe("ChainEntryInvalid");
    expect(body.reason).toBe("bad-signature");
    expect(body.seq).toBe(fixture.head.seq + 1);
    // The rejected entry does not land on the chain (head unchanged)
    const chain = await SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    const entries = ((await chain.json()) as { entries: readonly { seq: number }[] }).entries;
    expect(entries.length).toBe(fixture.head.seq);
    expect(await computeChainEntryHash(entries[entries.length - 1] as never)).toBe(
      fixture.head.hashHex,
    );
  });

  it("rejects a legacy invite issue body (no scope) with HTTP 400", async () => {
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, OWNER)) },
      body: JSON.stringify({
        id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        role: "member",
        linkPubHex: "11".repeat(32),
        headHashHex: fixture.head.hashHex,
        headSeq: fixture.head.seq,
        issueSignatureHex: "22".repeat(64),
      }),
    });
    expect(response.status).toBe(400);
  });
});
