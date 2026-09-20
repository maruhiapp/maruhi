// 端末鍵 2 op(`add_device` / `revoke_device`)の受理副作用と R(E) の端末展開
// (CRYPTO_SPEC §6.2 / AUTH_SPEC §12-6 / AUDIT_SPEC §3.4・§4.1 — 2026-09-19 DK K3)の
// 統合テスト(@cloudflare/vitest-plugin — workerd 実環境)。
//
// 検証項:
// - 受理ガード解除: 2 op が汎用 append で受理され、ミラー行(§3.4)が端末 FP を運ぶ
// - R(E) の端末展開: ラップの完全集合は (人, 端末) 単位。応答は自分の全端末分を運び
//   `recipientEncPubHex` で端末を識別する
// - 2 段認可(設計録 §8 K3-1): 署名鍵から端末を解き、端末の実効権限で第 2 段を判定する
// - `revoke_device` の副作用: 申告行の削除・要ローテーション検出(trigger `revoke_device`)・
//   失効鍵宛のラップ拒否・失効端末の署名拒否・既存ラップは掃除しない
// - DeviceLimit(16 / member / project — 受理ポリシー、422)
// - トークン水準(add_device = write、他人の revoke_device = admin)
// - reader の自己バックフィル(自分の端末宛のみ)
// - 端末軸の削除参照(`recipientEncPubHex` 省略時は唯一スロットのみ)
// - バージョン skew: 端末 1 つ(K2 以前のクライアント相当入力)の経路は不変

import {
  computeUserKeyFingerprint,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importSigningKeyPair,
  signHeadAttestation,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { MAX_DEVICES_PER_MEMBER } from "../src/policy.ts";
import { bearer, cliToken, JSON_HEADERS, BASE } from "./support/auth.ts";
import type { WireWrappedDek } from "./support/data-crypto.ts";
import {
  commitmentOf,
  encryptValue,
  hexBytes,
  makeDek,
  resetDeviceKeys,
  signEntryAt,
  useDeviceKey,
  valueSignedBytesHashOf,
  vectorKeyNamed,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

const OTHER = "env-other-0002";

/** ベクターの端末鍵(名義はベクターのもの — 束縛はチェーンの add_device が行う)。 */
const PHONE = "user-owner-0001@phone";
const SECOND = "user-owner-0014@second";
const READER_CAP = "user-owner-0015@reader-cap";
const CI_BOX = "user-allmember-0013@ci-box";

interface DevicePublic {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly fp: string;
}

function vectorDevice(name: string): DevicePublic {
  const keys = vectorKeyNamed(name);
  return {
    encPubHex: keys.enc_pub_hex,
    sigPubHex: keys.sig_pub_hex,
    fp: keys.key_fingerprint_hex,
  };
}

/** 使い捨ての端末公開鍵(DeviceLimit 用 — 署名には使わない)。 */
async function freshDevice(): Promise<DevicePublic> {
  const enc = await generateEncryptionKeyPair();
  const sig = await generateSigningKeyPair();
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  const digest = await computeUserKeyFingerprint(encPub, sigPub);
  if (!digest.ok) {
    throw new Error("fingerprint");
  }
  return {
    encPubHex: encodeHex(encPub),
    sigPubHex: encodeHex(sigPub),
    fp: encodeHex(digest.value),
  };
}

type Cap = {
  readonly roleCap?: "owner" | "admin" | "member" | "reader";
  readonly scopeKind?: "all" | "listed";
  readonly scopeEnvironmentIds?: readonly string[];
};

/** `add_device`(actor 自身の端末)をチェーンへ追記する。 */
async function addDevice(
  actorUserId: string,
  device: DevicePublic,
  cap: Cap = {},
): Promise<number> {
  await appendOperation(fixture, actorUserId, {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: cap.roleCap ?? "owner",
      scopeKind: cap.scopeKind ?? "all",
      scopeEnvironmentIds: cap.scopeEnvironmentIds ?? [],
    },
  });
  return fixture.head.seq;
}

/** `revoke_device` をチェーンへ追記する。 */
async function revokeDevice(
  actorUserId: string,
  targetUserId: string,
  fingerprints: readonly string[],
): Promise<number> {
  await appendOperation(fixture, actorUserId, {
    op: "revoke_device",
    payload: { targetUserId, deviceFingerprintsHex: fingerprints.toSorted() },
  });
  return fixture.head.seq;
}

/** 汎用 append を任意のトークンで送る(受理されなくてよい経路)。 */
async function appendWith(
  actorUserId: string,
  rawToken: string,
  operation: Parameters<typeof appendOperation>[2],
): Promise<Response> {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
    operation,
  });
  return SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(rawToken) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
}

interface Slot {
  readonly userId: string;
  readonly encPubHex: string;
}

/** (人, 端末) スロットごとのラップ集合(署名者 = 登録主体)。 */
async function wrapSlots(
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
  slots: readonly Slot[],
  signerUserId: string,
): Promise<WireWrappedDek[]> {
  const wraps: WireWrappedDek[] = [];
  for (const slot of slots) {
    wraps.push(
      await wrapDekTo({
        projectId,
        environmentId,
        epoch,
        dek,
        recipientUserId: slot.userId,
        recipientEncPubHex: slot.encPubHex,
        signerUserId,
      }),
    );
  }
  return wraps;
}

/** 3 メンバーの第 1 鍵スロット(ベースチェーンの端末 1 つずつ)。 */
const baseSlots = (): Slot[] =>
  ALL_MEMBERS.map((userId) => ({ userId, encPubHex: vectorKeyOf(userId).enc_pub_hex }));

/** 環境作成(任意のスロット集合)。 */
async function createEnvironmentWithSlots(
  environmentId: string,
  slots: readonly Slot[],
): Promise<{ readonly dek: Uint8Array; readonly response: Response }> {
  const dek = makeDek();
  const deks = await wrapSlots(environmentId, 1, dek, slots, OWNER);
  const response = await createEnvironmentComposite(fixture, {
    environmentId,
    name: environmentId,
    deks,
    dekCommitmentHex: await commitmentOf(projectId, environmentId, 1, dek),
  });
  return { dek, response };
}

interface WireRecipientDek {
  readonly epoch: number;
  readonly recipientEncPubHex?: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

async function listMyDeks(userId: string): Promise<readonly WireRecipientDek[]> {
  const response = await requestJson("GET", `/environments/${ENV}/deks`, token(userId));
  expect(response.status).toBe(200);
  return ((await response.json()) as { deks: readonly WireRecipientDek[] }).deks;
}

/** 値 push(署名者の現在の鍵 — useDeviceKey で端末を切り替えられる)。 */
async function pushValue(
  dek: Uint8Array,
  writerUserId: string,
  version: number,
  prevValueSigHashHex: string,
  rawToken: string = token(writerUserId),
): Promise<Response> {
  const value = await encryptValue(
    dek,
    { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version },
    `postgres://v${version}`,
    { writerUserId, head: fixture.head, prevValueSigHashHex },
  );
  return requestJson("POST", `/environments/${ENV}/variables/${VAR}/versions`, rawToken, {
    value,
  });
}

/** ヘッド申告の提出(署名者の現在の鍵)。 */
async function attest(userId: string): Promise<Response> {
  const keys = vectorKeyOf(userId);
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
      projectId,
      attesterUserId: userId,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    },
    signingKey: pair.value.privateKey,
  });
  if (!signed.ok) {
    throw new Error("attestation signing failed");
  }
  return SELF.fetch(`${BASE}/projects/${projectId}/head-attestation`, {
    method: "PUT",
    headers: { ...JSON_HEADERS, ...bearer(token(userId)) },
    body: JSON.stringify({
      suite: "maruhi/v1",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
      signatureHex: signed.value,
    }),
  });
}

async function attestationRows(): Promise<Record<string, unknown>[]> {
  return queryProjectDo(
    projectId,
    "SELECT attester_user_id, attester_key_fingerprint, chain_head_seq FROM head_attestations ORDER BY attester_user_id, attester_key_fingerprint",
  );
}

async function wrapRows(environmentId: string = ENV): Promise<Record<string, unknown>[]> {
  return queryProjectDo(
    projectId,
    "SELECT recipient_user_id, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? ORDER BY recipient_user_id, recipient_enc_pub_hex",
    environmentId,
  );
}

async function errorBody(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

interface WireRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly triggerChainSeq: number;
  readonly trigger?: string;
}

async function readFlags(): Promise<readonly WireRotationFlag[]> {
  const response = await requestJson("GET", "/rotation/flags", token(OWNER));
  expect(response.status).toBe(200);
  return ((await response.json()) as { flags: readonly WireRotationFlag[] }).flags;
}

describe("add_device の受理とミラー(CRYPTO_SPEC §6.2 / AUDIT_SPEC §3.4)", () => {
  it("accepts add_device through the generic append and mirrors chain.device_added with the device fingerprint", async () => {
    const phone = vectorDevice(PHONE);
    const seq = await addDevice(OWNER, phone, { roleCap: "admin" });

    const events = await readAuditEvents(projectId);
    const mirror = events.find((event) => event["event"] === "chain.device_added");
    expect(mirror).toBeDefined();
    expect(mirror?.["chain_seq"]).toBe(seq);
    expect(mirror?.["actor_type"]).toBe("user");
    expect(mirror?.["actor_user_id"]).toBe(OWNER);
    // アクターは追記に署名した端末(第 1 鍵)、target は本人(自分の端末しか足せない)
    expect(mirror?.["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
    expect(mirror?.["target_user_id"]).toBe(OWNER);
    expect(JSON.parse(String(mirror?.["payload"]))).toEqual({
      deviceKeyFingerprint: phone.fp,
      roleCap: "admin",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    // ミラー行は GitHub 等のプロバイダ情報を運ばない(内部 user_id と FP のみ)
    expect(JSON.stringify(mirror)).not.toContain("github");
  });

  it("expands R(E) per device: the full wrap set must cover every device of every member", async () => {
    const phone = vectorDevice(PHONE);
    await addDevice(OWNER, phone);

    // 端末 1 つ分(3 行)では完全集合にならない
    const short = await createEnvironmentWithSlots(ENV, baseSlots());
    expect(short.response.status).toBe(422);
    expect(await errorBody(short.response)).toMatchObject({
      _tag: "DekWrapRejected",
      reason: "recipient-missing",
    });

    // (人, 端末) の 4 行で受理
    const full = await createEnvironmentWithSlots(ENV, [
      ...baseSlots(),
      { userId: OWNER, encPubHex: phone.encPubHex },
    ]);
    expect(full.response.status).toBe(200);
    expect(
      (await wrapRows()).map((row) => [row["recipient_user_id"], row["recipient_enc_pub_hex"]]),
    ).toEqual(
      [
        [MEMBER, vectorKeyOf(MEMBER).enc_pub_hex],
        [OWNER, vectorKeyOf(OWNER).enc_pub_hex],
        [OWNER, phone.encPubHex],
        [READER, vectorKeyOf(READER).enc_pub_hex],
      ].toSorted((a, b) => `${a[0]}:${a[1]}`.localeCompare(`${b[0]}:${b[1]}`)),
    );

    // 応答は自分の全端末分を運び、端末は recipientEncPubHex で識別する
    const mine = await listMyDeks(OWNER);
    expect(mine).toHaveLength(2);
    expect(mine.map((row) => row.recipientEncPubHex).toSorted()).toEqual(
      [vectorKeyOf(OWNER).enc_pub_hex, phone.encPubHex].toSorted(),
    );
    // 他人の端末分は混ざらない
    expect((await listMyDeks(MEMBER)).map((row) => row.recipientEncPubHex)).toEqual([
      vectorKeyOf(MEMBER).enc_pub_hex,
    ]);
  });

  it("resolves the signing device from the signature: a phone-signed push is accepted and recorded with the phone fingerprint", async () => {
    const phone = vectorDevice(PHONE);
    await addDevice(OWNER, phone);
    const created = await createEnvironmentWithSlots(ENV, [
      ...baseSlots(),
      { userId: OWNER, encPubHex: phone.encPubHex },
    ]);
    expect(created.response.status).toBe(200);
    const v1 = await createVariableOk(created.dek, VAR, "DATABASE_URL", "postgres://alpha");

    useDeviceKey(OWNER, PHONE);
    const push = await pushValue(created.dek, OWNER, 2, await valueSignedBytesHashOf(v1, MEMBER));
    expect(push.status).toBe(200);
    resetDeviceKeys();

    const events = await readAuditEvents(projectId);
    const pushed = events.filter((event) => event["event"] === "var.version_pushed");
    expect(pushed.at(-1)?.["actor_user_id"]).toBe(OWNER);
    expect(pushed.at(-1)?.["actor_key_fingerprint"]).toBe(phone.fp);
  });

  it("stores one head attestation per device", async () => {
    const phone = vectorDevice(PHONE);
    await addDevice(OWNER, phone);
    expect((await attest(OWNER)).status).toBe(204);
    useDeviceKey(OWNER, PHONE);
    expect((await attest(OWNER)).status).toBe(204);
    resetDeviceKeys();

    const rows = await attestationRows();
    expect(rows.map((row) => [row["attester_user_id"], row["attester_key_fingerprint"]])).toEqual(
      [
        [OWNER, vectorKeyOf(OWNER).key_fingerprint_hex],
        [OWNER, phone.fp],
      ].toSorted((a, b) => `${a[1]}`.localeCompare(`${b[1]}`)),
    );
    // 配布(GET /chain)も端末ごとの行を運ぶ
    const chain = await SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
      headers: bearer(token(MEMBER)),
    });
    expect(chain.status).toBe(200);
    const body = (await chain.json()) as {
      attestations?: readonly { attesterKeyFingerprintHex: string }[];
    };
    expect(body.attestations?.map((row) => row.attesterKeyFingerprintHex).toSorted()).toEqual(
      [vectorKeyOf(OWNER).key_fingerprint_hex, phone.fp].toSorted(),
    );
  });

  it("rejects the 17th active device with 422 DeviceLimit (acceptance policy, not a consensus rule)", async () => {
    const devices: DevicePublic[] = [];
    for (let index = 0; index < MAX_DEVICES_PER_MEMBER - 1; index += 1) {
      const device = await freshDevice();
      devices.push(device);
      await addDevice(OWNER, device);
    }
    const overflow = await freshDevice();
    const rejected = await appendWith(OWNER, token(OWNER), {
      op: "add_device",
      payload: {
        encPubHex: overflow.encPubHex,
        sigPubHex: overflow.sigPubHex,
        roleCap: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect(rejected.status).toBe(422);
    expect(await errorBody(rejected)).toEqual({
      _tag: "DeviceLimit",
      limit: MAX_DEVICES_PER_MEMBER,
    });
    // 失効して枠が空けば再び足せる(有効端末数で数える)
    const first = devices[0];
    if (first === undefined) {
      throw new Error("no device");
    }
    await revokeDevice(OWNER, OWNER, [first.fp]);
    await addDevice(OWNER, overflow);
  });

  it("requires a write token for add_device and an admin token to revoke another member's device", async () => {
    const readToken = await cliToken(9001, [{ project: "*", permission: "read" }], "read-only");
    const phone = vectorDevice(PHONE);
    const denied = await appendWith(OWNER, readToken, {
      op: "add_device",
      payload: {
        encPubHex: phone.encPubHex,
        sigPubHex: phone.sigPubHex,
        roleCap: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect(denied.status).toBe(403);

    const writeToken = await cliToken(9001, [{ project: "*", permission: "write" }], "write");
    const accepted = await appendWith(OWNER, writeToken, {
      op: "add_device",
      payload: {
        encPubHex: phone.encPubHex,
        sigPubHex: phone.sigPubHex,
        roleCap: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    expect(accepted.status).toBe(200);
    const body = (await accepted.json()) as { headSeq: number; headHashHex: string };
    fixture.head = { seq: body.headSeq, hashHex: body.headHashHex };

    // MEMBER に 2 台目を足し、OWNER が write トークンで他人の端末を失効 → 403(admin 要)
    const ciBox = vectorDevice(CI_BOX);
    await addDevice(MEMBER, ciBox, { roleCap: "member" });
    const asWrite = await appendWith(OWNER, writeToken, {
      op: "revoke_device",
      payload: { targetUserId: MEMBER, deviceFingerprintsHex: [ciBox.fp] },
    });
    expect(asWrite.status).toBe(403);
    // 自分の端末の失効は write で足りる
    const own = await appendWith(OWNER, writeToken, {
      op: "revoke_device",
      payload: { targetUserId: OWNER, deviceFingerprintsHex: [phone.fp] },
    });
    expect(own.status).toBe(200);
  });
});

describe("revoke_device の受理副作用(AUDIT_SPEC §3.4 / §4.1)", () => {
  it("mirrors chain.device_revoked, drops the device's attestation, flags rotation and rejects the revoked key afterwards", async () => {
    const phone = vectorDevice(PHONE);
    await addDevice(OWNER, phone);
    const created = await createEnvironmentWithSlots(ENV, [
      ...baseSlots(),
      { userId: OWNER, encPubHex: phone.encPubHex },
    ]);
    expect(created.response.status).toBe(200);
    const v1 = await createVariableOk(created.dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 端末が pull で値を読む(var.read — 検出 (a) の材料)、申告も出す
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(OWNER));
    expect(pull.status).toBe(200);
    // 読んでいない候補を 1 本(readable)
    await createVariableOk(created.dek, "var-api-key", "API_KEY", "sk-alpha");
    useDeviceKey(OWNER, PHONE);
    expect((await attest(OWNER)).status).toBe(204);
    resetDeviceKeys();
    expect((await attest(OWNER)).status).toBe(204);
    expect(await attestationRows()).toHaveLength(2);

    const revokeSeq = await revokeDevice(OWNER, OWNER, [phone.fp]);

    // ミラー行 ★(payload = 失効 FP 列、target = 対象)
    const events = await readAuditEvents(projectId);
    const mirror = events.find((event) => event["event"] === "chain.device_revoked");
    expect(mirror?.["chain_seq"]).toBe(revokeSeq);
    expect(mirror?.["target_user_id"]).toBe(OWNER);
    expect(JSON.parse(String(mirror?.["payload"]))).toEqual({ deviceKeyFingerprints: [phone.fp] });

    // 申告行は失効端末の分だけ消える
    const rows = await attestationRows();
    expect(rows.map((row) => row["attester_key_fingerprint"])).toEqual([
      vectorKeyOf(OWNER).key_fingerprint_hex,
    ]);

    // 要ローテーション検出: ミラー直後に 1 対 1 行、trigger = revoke_device
    const recommended = events.filter((event) => event["event"] === "rotation.recommended");
    expect(recommended).toHaveLength(2);
    expect(Math.min(...recommended.map((event) => Number(event["seq"])))).toBe(
      Number(mirror?.["seq"]) + 1,
    );
    for (const event of recommended) {
      expect(event["actor_type"]).toBe("system");
      expect(event["target_user_id"]).toBe(OWNER);
      const payload = JSON.parse(String(event["payload"])) as Record<string, unknown>;
      expect(payload["trigger"]).toBe("revoke_device");
      expect(payload["triggerChainSeq"]).toBe(revokeSeq);
      expect(payload["revokedDeviceKeyFingerprints"]).toEqual([phone.fp]);
    }
    const flags = await readFlags();
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      basis: "read",
      targetUserId: OWNER,
      trigger: "revoke_device",
      triggerChainSeq: revokeSeq,
    });
    expect(byVariable.get("var-api-key")).toMatchObject({
      basis: "readable",
      trigger: "revoke_device",
    });

    // 既存ラップは掃除しない(掃除規則不変 — 次のローテーションで置き換わる)
    expect(await wrapRows()).toHaveLength(4);

    // 失効鍵宛の新しいラップは受理しない
    const toRevoked = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: created.dek,
      recipientUserId: OWNER,
      recipientEncPubHex: phone.encPubHex,
      signerUserId: OWNER,
    });
    const rejected = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [toRevoked],
    });
    expect(rejected.status).toBe(422);
    expect(await errorBody(rejected)).toMatchObject({ reason: "recipient-key-mismatch" });

    // 失効端末の署名は無効(署名鍵から端末を解けない = signature-invalid)
    useDeviceKey(OWNER, PHONE);
    const push = await pushValue(created.dek, OWNER, 2, await valueSignedBytesHashOf(v1, MEMBER));
    expect(push.status).toBe(422);
    expect(await errorBody(push)).toMatchObject({ reason: "signature-invalid" });
    // 失効端末の申告も受け付けない
    const stale = await attest(OWNER);
    expect(stale.status).not.toBe(204);
    resetDeviceKeys();
  });
});

describe("2 段認可 — 端末の実効権限(設計録 §8 K3-1 / CRYPTO_SPEC §6.2 原則 D1)", () => {
  it("lets a reader backfill wraps to its own new device but not to another member", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const second = vectorDevice(SECOND);
    await addDevice(READER, second, { roleCap: "reader" });

    // 自分の端末宛のみ = role 段は reader で足りる(自己バックフィル)
    const own = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      recipientEncPubHex: second.encPubHex,
      signerUserId: READER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(READER), {
      deks: [own],
    });
    expect(registered.status).toBe(204);
    expect((await listMyDeks(READER)).map((row) => row.recipientEncPubHex).toSorted()).toEqual(
      [vectorKeyOf(READER).enc_pub_hex, second.encPubHex].toSorted(),
    );

    // 他人宛は member 以上(reader は 403)
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: MEMBER }],
    });
    expect(removed.status).toBe(204);
    const other = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: MEMBER,
      signerUserId: READER,
    });
    const denied = await requestJson("POST", `/environments/${ENV}/deks`, token(READER), {
      deks: [other],
    });
    expect(denied.status).toBe(403);
    expect(await errorBody(denied)).toMatchObject({ reason: "insufficient-role" });
    // 自分の端末宛と他人宛の混在も同様に 403(集合全体で判定)
    const mixed = await requestJson("POST", `/environments/${ENV}/deks`, token(READER), {
      deks: [other, own],
    });
    expect(mixed.status).toBe(403);
  });

  it("applies the device cap to value pushes: a reader-cap device and an out-of-scope device are rejected at the declared head (§6.3 — 422)", async () => {
    // 値・メタ・マニフェストは CRYPTO_SPEC §6.3 の「宣言ヘッド時点の認可」(K2 で端末の
    // 実効権限に置き換わった — deviceStateAt)が署名検証の一部として先に走るため、
    // 端末 cap の不足は 422 chain-head-state-mismatch で確定する。サーバーの第 2 段
    // (ensureDevicePermission — 403)は複合・checkpoint・DEK 登録で観測される
    // (membership-negatives-composite の 3 件 / 本ファイルの reader バックフィル)
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, OTHER, "Other");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const readerCap = vectorDevice(READER_CAP);
    await addDevice(OWNER, readerCap, { roleCap: "reader" });
    const ciBox = vectorDevice(CI_BOX);
    await addDevice(OWNER, ciBox, { scopeKind: "listed", scopeEnvironmentIds: [OTHER] });

    const prev = await valueSignedBytesHashOf(v1, MEMBER);
    useDeviceKey(OWNER, READER_CAP);
    const capped = await pushValue(dek, OWNER, 2, prev);
    expect(capped.status).toBe(422);
    expect(await errorBody(capped)).toEqual({
      _tag: "ValueSignatureRejected",
      reason: "chain-head-state-mismatch",
    });

    useDeviceKey(OWNER, CI_BOX);
    const outOfScope = await pushValue(dek, OWNER, 2, prev);
    expect(outOfScope.status).toBe(422);
    expect(await errorBody(outOfScope)).toEqual({
      _tag: "ValueSignatureRejected",
      reason: "chain-head-state-mismatch",
    });
    resetDeviceKeys();

    // 第 1 鍵(cap なし)なら通る — 人の (role, scope) は変わっていない
    const primary = await pushValue(dek, OWNER, 2, prev);
    expect(primary.status).toBe(200);
  });

  it("refuses an ambiguous device-less delete reference when the member has two slots (422 duplicate-recipient)", async () => {
    const phone = vectorDevice(PHONE);
    await addDevice(OWNER, phone);
    const created = await createEnvironmentWithSlots(ENV, [
      ...baseSlots(),
      { userId: OWNER, encPubHex: phone.encPubHex },
    ]);
    expect(created.response.status).toBe(200);

    const ambiguous = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: OWNER }],
    });
    expect(ambiguous.status).toBe(422);
    expect(await errorBody(ambiguous)).toMatchObject({ reason: "duplicate-recipient" });
    expect(await wrapRows()).toHaveLength(4);

    const precise = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: OWNER, recipientEncPubHex: phone.encPubHex }],
    });
    expect(precise.status).toBe(204);
    expect(
      (await wrapRows()).map((row) => [row["recipient_user_id"], row["recipient_enc_pub_hex"]]),
    ).not.toContainEqual([OWNER, phone.encPubHex]);
    // 端末 1 つに戻れば省略形は唯一スロットを指す
    const sole = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: OWNER }],
    });
    expect(sole.status).toBe(204);
    expect((await wrapRows()).map((row) => row["recipient_user_id"])).toEqual([MEMBER, READER]);
    // 無い参照は 404(端末指定でも同じ)
    const gone = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: OWNER, recipientEncPubHex: phone.encPubHex }],
    });
    expect(gone.status).toBe(404);
  });
});

describe("バージョン skew — 端末 1 つのチェーン(K2 以前のクライアント相当入力)は不変", () => {
  it("accepts single-device wrap sets, device-less references, attestations and pushes exactly as before", async () => {
    // 環境作成: 3 メンバー × 端末 1 つ = 3 ラップ(K2 以前の CLI が送る形)
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const created = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: await commitmentOf(projectId, ENV, 1, dek),
    });
    expect(created.status).toBe(200);
    // 応答は端末軸の主キーでも 1 行(recipientEncPubHex は自分の唯一の鍵)
    const mine = await listMyDeks(READER);
    expect(mine).toHaveLength(1);
    expect(mine[0]?.recipientEncPubHex).toBe(vectorKeyOf(READER).enc_pub_hex);

    // 端末を指定しない削除参照 → 唯一スロット
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    // 端末を指定しないバックフィル(K2 以前の追記経路)→ 204
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
    });
    const backfilled = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [reWrap],
    });
    expect(backfilled.status).toBe(204);
    expect(await listMyDeks(READER)).toHaveLength(1);

    // 申告・値 push は第 1 鍵で従来どおり
    expect((await attest(OWNER)).status).toBe(204);
    expect(await attestationRows()).toEqual([
      {
        attester_user_id: OWNER,
        attester_key_fingerprint: vectorKeyOf(OWNER).key_fingerprint_hex,
        chain_head_seq: fixture.head.seq,
      },
    ]);
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const push = await pushValue(dek, OWNER, 2, await valueSignedBytesHashOf(v1, MEMBER));
    expect(push.status).toBe(200);
    const events = await readAuditEvents(projectId);
    expect(events.at(-1)?.["event"]).toBe("var.version_pushed");
    expect(events.at(-1)?.["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
  });
});
