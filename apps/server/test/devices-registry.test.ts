// 端末登録簿・端末追加要求 API の統合テスト(AUTH_SPEC §13-11 — 2026-09-19 DK K3)。
// @cloudflare/vitest-plugin(workerd 実環境)で SELF 経由の実経路を検証する。
//
// 登録簿は advisory(検証・認可の入力にならない)なので、ここで固定するのは
// HTTP 面の契約のみ: 認可(`*` × admin トークン / セッションは一覧のみ)、FP の
// サーバー再計算、上限(行 32 / 要求 5 回 / 時)、衝突(409)、TTL、404 の一様性。

import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  loginSession,
  resetAuthDb,
  sessionHeaders,
} from "./support/auth.ts";
import { vectorKeyNamed } from "./support/data-crypto.ts";

beforeEach(async () => {
  await resetAuthDb();
});

interface DeviceKeys {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly fp: string;
}

/** ベクター鍵(端末鍵)を登録簿の材料へ。 */
function vectorDevice(name: string): DeviceKeys {
  const keys = vectorKeyNamed(name);
  return {
    encPubHex: keys.enc_pub_hex,
    sigPubHex: keys.sig_pub_hex,
    fp: keys.key_fingerprint_hex,
  };
}

/** 使い捨ての端末鍵(上限テスト用 — 秘密鍵は使わない)。 */
async function freshDevice(): Promise<DeviceKeys> {
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

const PHONE = vectorDevice("user-owner-0001@phone");
const RESERVE = vectorDevice("user-owner-0001@reserve");

function registerBody(device: DeviceKeys, label = "phone", tokenId?: string): string {
  return JSON.stringify({
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label,
    ...(tokenId === undefined ? {} : { tokenId }),
  });
}

function requestBody(device: DeviceKeys, label = "reserve"): string {
  return JSON.stringify({ encPubHex: device.encPubHex, sigPubHex: device.sigPubHex, label });
}

const registerDevice = (headers: Record<string, string>, fp: string, body: string) =>
  SELF.fetch(`${BASE}/auth/devices/${fp}`, {
    method: "PUT",
    headers: { ...JSON_HEADERS, ...headers },
    body,
  });

const listDevices = (headers: Record<string, string>) =>
  SELF.fetch(`${BASE}/auth/devices`, { headers });

const removeDevice = (headers: Record<string, string>, fp: string) =>
  SELF.fetch(`${BASE}/auth/devices/${fp}`, { method: "DELETE", headers });

const createRequest = (headers: Record<string, string>, body: string) =>
  SELF.fetch(`${BASE}/auth/devices/requests`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...headers },
    body,
  });

const listRequests = (headers: Record<string, string>) =>
  SELF.fetch(`${BASE}/auth/devices/requests`, { headers });

const getRequest = (headers: Record<string, string>, fp: string) =>
  SELF.fetch(`${BASE}/auth/devices/requests/${fp}`, { headers });

const cancelRequest = (headers: Record<string, string>, fp: string) =>
  SELF.fetch(`${BASE}/auth/devices/requests/${fp}`, { method: "DELETE", headers });

async function jsonOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

describe("端末登録簿(§13-11 — PUT / GET / DELETE /auth/devices)", () => {
  it("registers, lists and updates the caller's own rows (204 → 200)", async () => {
    const token = await cliToken(601);
    expect((await registerDevice(bearer(token), PHONE.fp, registerBody(PHONE))).status).toBe(204);
    expect(
      (await registerDevice(bearer(token), RESERVE.fp, registerBody(RESERVE, "reserve", "tok-1")))
        .status,
    ).toBe(204);

    const list = await listDevices(bearer(token));
    expect(list.status).toBe(200);
    const devices = (await jsonOf(list))["devices"] as Array<Record<string, unknown>>;
    expect(devices.map((d) => d["keyFingerprintHex"]).toSorted()).toEqual(
      [PHONE.fp, RESERVE.fp].toSorted(),
    );
    const reserve = devices.find((d) => d["keyFingerprintHex"] === RESERVE.fp);
    expect(reserve?.["label"]).toBe("reserve");
    expect(reserve?.["tokenId"]).toBe("tok-1");
    expect(reserve?.["encPubHex"]).toBe(RESERVE.encPubHex);
    expect(reserve?.["sigPubHex"]).toBe(RESERVE.sigPubHex);
    expect(typeof reserve?.["createdAtMs"]).toBe("number");

    // upsert: 表示名の更新(行数は増えない・tokenId は body どおりに置き換わる)
    expect(
      (await registerDevice(bearer(token), PHONE.fp, registerBody(PHONE, "renamed"))).status,
    ).toBe(204);
    const again = (await jsonOf(await listDevices(bearer(token))))["devices"] as Array<
      Record<string, unknown>
    >;
    expect(again).toHaveLength(2);
    expect(again.find((d) => d["keyFingerprintHex"] === PHONE.fp)?.["label"]).toBe("renamed");
  });

  it("rejects a path fingerprint that does not match the body keys with 400 (server recomputes)", async () => {
    const token = await cliToken(602);
    const response = await registerDevice(bearer(token), RESERVE.fp, registerBody(PHONE));
    expect(response.status).toBe(400);
    expect((await jsonOf(response))["_tag"]).toBe("DeviceFingerprintMismatch");
    const devices = (await jsonOf(await listDevices(bearer(token))))["devices"];
    expect(devices).toEqual([]);
  });

  it("rejects an empty label at the wire schema (400)", async () => {
    const token = await cliToken(603);
    const response = await registerDevice(bearer(token), PHONE.fp, registerBody(PHONE, ""));
    expect(response.status).toBe(400);
  });

  it("keeps rows per user: another user sees an empty registry", async () => {
    const a = await cliToken(604);
    const b = await cliToken(605);
    expect((await registerDevice(bearer(a), PHONE.fp, registerBody(PHONE))).status).toBe(204);
    expect((await jsonOf(await listDevices(bearer(b))))["devices"]).toEqual([]);
    // 他人の行は消せない(本人の行として探すので 404)
    expect((await removeDevice(bearer(b), PHONE.fp)).status).toBe(404);
  });

  it("allows a session principal to list but not to write (§5)", async () => {
    const token = await cliToken(606);
    expect((await registerDevice(bearer(token), PHONE.fp, registerBody(PHONE))).status).toBe(204);
    const session = await loginSession(606);
    const list = await listDevices(sessionHeaders(session));
    expect(list.status).toBe(200);
    expect(
      ((await jsonOf(list))["devices"] as Array<Record<string, unknown>>).map(
        (d) => d["keyFingerprintHex"],
      ),
    ).toEqual([PHONE.fp]);

    const put = await registerDevice(sessionHeaders(session), RESERVE.fp, registerBody(RESERVE));
    expect(put.status).toBe(403);
    expect((await jsonOf(put))["reason"]).toBe("session-not-allowed");
    const del = await removeDevice(sessionHeaders(session), PHONE.fp);
    expect(del.status).toBe(403);
    expect((await jsonOf(del))["reason"]).toBe("session-not-allowed");
    const req = await createRequest(sessionHeaders(session), requestBody(RESERVE));
    expect(req.status).toBe(403);
    expect((await jsonOf(req))["reason"]).toBe("session-not-allowed");
    const reqList = await listRequests(sessionHeaders(session));
    expect(reqList.status).toBe(403);
    expect((await jsonOf(reqList))["reason"]).toBe("session-not-allowed");
  });

  it("rejects writes from a token below `*` × admin with 403 (§13-2 と同水準)", async () => {
    const scoped = await cliToken(607, [{ project: "f0".repeat(32), permission: "admin" }]);
    expect((await registerDevice(bearer(scoped), PHONE.fp, registerBody(PHONE))).status).toBe(403);
    expect((await removeDevice(bearer(scoped), PHONE.fp)).status).toBe(403);
    expect((await createRequest(bearer(scoped), requestBody(RESERVE))).status).toBe(403);
    expect((await listRequests(bearer(scoped))).status).toBe(403);
    expect((await getRequest(bearer(scoped), RESERVE.fp)).status).toBe(403);
    expect((await cancelRequest(bearer(scoped), RESERVE.fp)).status).toBe(403);
    // 一覧は認証済み主体すべて
    expect((await listDevices(bearer(scoped))).status).toBe(200);
    const write = await cliToken(608, [{ project: "*", permission: "write" }]);
    expect((await registerDevice(bearer(write), PHONE.fp, registerBody(PHONE))).status).toBe(403);
  });

  it("deletes a row (204) and answers 404 for an unknown fingerprint", async () => {
    const token = await cliToken(609);
    expect((await registerDevice(bearer(token), PHONE.fp, registerBody(PHONE))).status).toBe(204);
    expect((await removeDevice(bearer(token), PHONE.fp)).status).toBe(204);
    expect((await jsonOf(await listDevices(bearer(token))))["devices"]).toEqual([]);
    const missing = await removeDevice(bearer(token), PHONE.fp);
    expect(missing.status).toBe(404);
    expect((await jsonOf(missing))["_tag"]).toBe("DeviceNotFound");
  });

  it("caps the registry at 32 rows per user (429 device-rows; updates do not count)", async () => {
    const token = await cliToken(610);
    const devices: DeviceKeys[] = [];
    for (let index = 0; index < 32; index += 1) {
      const device = await freshDevice();
      devices.push(device);
      expect(
        (await registerDevice(bearer(token), device.fp, registerBody(device, `d${index}`))).status,
      ).toBe(204);
    }
    const overflow = await freshDevice();
    const rejected = await registerDevice(bearer(token), overflow.fp, registerBody(overflow));
    expect(rejected.status).toBe(429);
    const body = await jsonOf(rejected);
    expect(body["_tag"]).toBe("DeviceRegistryLimit");
    expect(body["reason"]).toBe("device-rows");
    expect(body["limit"]).toBe(32);
    // 既存行の更新は上限に数えない
    const first = devices[0];
    if (first === undefined) {
      throw new Error("no device");
    }
    expect(
      (await registerDevice(bearer(token), first.fp, registerBody(first, "renamed"))).status,
    ).toBe(204);
    // 1 行消せばまた登録できる
    expect((await removeDevice(bearer(token), first.fp)).status).toBe(204);
    expect((await registerDevice(bearer(token), overflow.fp, registerBody(overflow))).status).toBe(
      204,
    );
  });
});

describe("端末追加要求(§13-11 — /auth/devices/requests)", () => {
  it("creates, lists, reads and cancels a request (fp derived by the server)", async () => {
    const token = await cliToken(620);
    const created = await createRequest(bearer(token), requestBody(RESERVE));
    expect(created.status).toBe(200);
    const expiresAtMs = (await jsonOf(created))["expiresAtMs"];
    expect(typeof expiresAtMs).toBe("number");

    const list = await listRequests(bearer(token));
    expect(list.status).toBe(200);
    const requests = (await jsonOf(list))["requests"] as Array<Record<string, unknown>>;
    expect(requests).toHaveLength(1);
    expect(requests[0]?.["keyFingerprintHex"]).toBe(RESERVE.fp);
    expect(requests[0]?.["encPubHex"]).toBe(RESERVE.encPubHex);
    expect(requests[0]?.["sigPubHex"]).toBe(RESERVE.sigPubHex);
    expect(requests[0]?.["label"]).toBe("reserve");
    expect(requests[0]?.["expiresAtMs"]).toBe(expiresAtMs);

    const one = await getRequest(bearer(token), RESERVE.fp);
    expect(one.status).toBe(200);
    expect((await jsonOf(one))["keyFingerprintHex"]).toBe(RESERVE.fp);

    expect((await cancelRequest(bearer(token), RESERVE.fp)).status).toBe(204);
    expect((await getRequest(bearer(token), RESERVE.fp)).status).toBe(404);
    expect((await cancelRequest(bearer(token), RESERVE.fp)).status).toBe(404);
    expect((await jsonOf(await listRequests(bearer(token))))["requests"]).toEqual([]);
  });

  it("answers 409 request-exists for a duplicate live request and device-registered for a registered key", async () => {
    const token = await cliToken(621);
    expect((await createRequest(bearer(token), requestBody(RESERVE))).status).toBe(200);
    const duplicate = await createRequest(bearer(token), requestBody(RESERVE));
    expect(duplicate.status).toBe(409);
    expect((await jsonOf(duplicate))["reason"]).toBe("request-exists");

    expect((await registerDevice(bearer(token), PHONE.fp, registerBody(PHONE))).status).toBe(204);
    const registered = await createRequest(bearer(token), requestBody(PHONE));
    expect(registered.status).toBe(409);
    expect((await jsonOf(registered))["reason"]).toBe("device-registered");
  });

  it("keeps requests per user (another user cannot read or cancel them)", async () => {
    const a = await cliToken(622);
    const b = await cliToken(623);
    expect((await createRequest(bearer(a), requestBody(RESERVE))).status).toBe(200);
    expect((await jsonOf(await listRequests(bearer(b))))["requests"]).toEqual([]);
    expect((await getRequest(bearer(b), RESERVE.fp)).status).toBe(404);
    expect((await cancelRequest(bearer(b), RESERVE.fp)).status).toBe(404);
    // 別ユーザーは同じ公開鍵で要求を作れる(行は (user, fp) 軸)
    expect((await createRequest(bearer(b), requestBody(RESERVE))).status).toBe(200);
  });

  it("limits request creation to 5 per fixed hour per user (429 add-requests)", async () => {
    const token = await cliToken(624);
    for (let index = 0; index < 5; index += 1) {
      const device = await freshDevice();
      expect((await createRequest(bearer(token), requestBody(device, `d${index}`))).status).toBe(
        200,
      );
    }
    const device = await freshDevice();
    const rejected = await createRequest(bearer(token), requestBody(device));
    expect(rejected.status).toBe(429);
    const body = await jsonOf(rejected);
    expect(body["_tag"]).toBe("DeviceRegistryLimit");
    expect(body["reason"]).toBe("add-requests");
    expect(body["limit"]).toBe(5);
    expect(typeof body["retryAfterSeconds"]).toBe("number");
    // 取消しても窓は戻らない(固定窓)
    expect((await cancelRequest(bearer(token), RESERVE.fp)).status).toBe(404);
    expect((await createRequest(bearer(token), requestBody(RESERVE))).status).toBe(429);
  });

  it("rejects malformed keys at the wire schema (400) without consuming the window", async () => {
    const token = await cliToken(625);
    for (let index = 0; index < 5; index += 1) {
      const bad = await createRequest(
        bearer(token),
        JSON.stringify({ encPubHex: "zz", sigPubHex: RESERVE.sigPubHex, label: "x" }),
      );
      expect(bad.status).toBe(400);
    }
    expect((await createRequest(bearer(token), requestBody(RESERVE))).status).toBe(200);
  });
});

describe("FP の再計算(CRYPTO_SPEC §3)", () => {
  it("vector device fingerprints match SHA-256(enc ‖ sig)[0..16]", async () => {
    const digest = await computeUserKeyFingerprint(
      decodeHex(PHONE.encPubHex) ?? new Uint8Array(),
      decodeHex(PHONE.sigPubHex) ?? new Uint8Array(),
    );
    expect(digest.ok && encodeHex(digest.value)).toBe(PHONE.fp);
  });
});
