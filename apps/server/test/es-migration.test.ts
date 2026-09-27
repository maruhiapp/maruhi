// ES + PF1 K2 のワイヤ非互換の実測(互換受理を持たないことの固定)。
//
// 2026-09-14 の ES 改訂は add_member / change_role の payload 形式と招待の発行文を変え、
// 互換受理の経路を持たない(CRYPTO_SPEC §6.2 — 所有者裁定)。ここでは「更新前の CLI が
// 更新後のサーバーへ送る形」を再現し、fail-closed の**実際の応答**を固定する:
//   - 旧形式(scope 2 フィールドを欠く)の add_member 追記 → HTTP 400(strict Schema)
//   - 旧形式の招待発行 body(scopeKind / scopeEnvironmentIds なし)→ HTTP 400
//   - 旧正規化(scope を署名対象に含まない)で署名した add_member を新形式の
//     フィールド付きで送る形 → HTTP 422 `bad-signature`(合意規則 — 旧署名者は
//     新形式のエントリを作れない)
// 逆方向(更新後の CLI × 更新前のサーバー)は旧サーバーの strict 受理(§12-10 (1)
// — 2026-08-19 リリース)により未知フィールドが 400 になる(strict-payload.test.ts が
// 固定する挙動の帰結)。

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

/** 旧 CLI の add_member エントリ(scope 2 フィールドなし)を旧正規化で署名する。 */
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
  // 旧正規化(2026-09-14 以前): payload_bytes = LP(target, enc, sig, role)
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
    // 拒否されたエントリはチェーンに載らない(ヘッド不変)
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
