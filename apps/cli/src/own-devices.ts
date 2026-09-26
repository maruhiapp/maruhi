// 自分の端末鍵の出所の記録(設計録 dk-design.md §9 K4-3 / K4-4 — DK-D の 3 条件)。
//
// 初回同期の端末登録(device-sync.ts)が新しいプロジェクトへ `add_device` してよい鍵は
// (1) 自分が生成した鍵(予備鍵)、(2) 自分が `device approve` で承認した鍵、
// (3) 検証済みチェーン上でその人の端末として観測した鍵 — の 3 つに限る
// (AUTH_SPEC §13-11)。この記録はその 3 つの出所を**非機密**の設定として持つ
// (公開鍵・FP・cap・出所・時刻だけ。秘密鍵は無い — ディスクレス不変条件と両立)。
//
// 書き手は 3 経路(予備鍵の封印・approve・検証済みチェーンの観測)だけであり、端末
// 登録簿(`GET /auth/devices` — サーバー申告 = advisory)の応答は**読み手にも書き手にも
// ならない**(登録簿を真実源にすると、サーバーが偽の公開鍵を差し込んで CLI にゴースト
// 端末を追記させられる — DK-D)。own-devices.test.ts の negative がこれを固定する。
//
// 失効の記録(`revokedAtMs`): `device revoke` の実行と、検証済みチェーン上での自分の
// 端末の `revoke_device` の観測で立てる。立った行は二度と足さない(侵害鍵の復活と
// 四眼の票の復活 — CRYPTO_SPEC §6.2 — を初回同期が引き起こさないため)。再承認
// (`device approve`)だけが行を上書きしてフラグを消す(明示操作)。
//
// 置き場は指紋帳と同系(<config dir>/own-devices.json — ユーザー単位・プロジェクト
// 横断)。fail-open: 不在 = 記録なし、破損 = 記録なし + 区別可能な警告。破損への
// 上書きは拒否する(pins / 指紋帳と同じ規律)。

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { isEnvironmentId } from "@maruhi/core";
import type { DeviceCap, MemberScope, Role } from "@maruhi/crypto";
import { MAX_SCOPE_ENVIRONMENTS } from "@maruhi/crypto";
import { Context, Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import { BOOK_KEY, decodeOriginBook, isRecord } from "./origin-book.ts";

/** Where the record came from (the three DK-D conditions). */
export type OwnDeviceSource = "reserve" | "approved" | "observed";

/** One recorded key of the user's own (non-secret: public keys, cap, provenance). */
export interface OwnDeviceRecord {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly roleCap: Role;
  readonly scope: MemberScope;
  readonly source: OwnDeviceSource;
  /** Display label chosen at `device add` / `approve` (this machine's copy — not the registry). */
  readonly label: string | null;
  /** The device that appended the `add_device` when observed on a chain (null for the first key / unknown). */
  readonly addedByFingerprintHex: string | null;
  /** The project the key was first observed on (observed rows only). */
  readonly observedProjectId: string | null;
  readonly recordedAtMs: number;
  /** Set when the key was revoked (by this machine or observed on a verified chain). Never re-added. */
  readonly revokedAtMs: number | null;
}

/** The record with its fingerprint (the map key). */
export interface OwnDeviceEntry extends OwnDeviceRecord {
  readonly keyFingerprintHex: string;
}

/** Load result (fail-open: `corrupt` is distinguishable from `missing`). */
export type OwnDevicesLookup =
  | { readonly state: "loaded"; readonly devices: readonly OwnDeviceEntry[] }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

/** Load / record boundary for the own-devices file. */
export interface OwnDeviceStoreShape {
  readonly filePath: string;
  readonly load: (origin: string, userId: string) => Effect.Effect<OwnDevicesLookup, CliError>;
  /** Upsert one record (read-merge-write). A re-approval overwrites a revoked row. */
  readonly record: (
    origin: string,
    userId: string,
    entry: OwnDeviceEntry,
  ) => Effect.Effect<void, CliError>;
  /** Marks fingerprints revoked (rows that do not exist are created as revoked "observed" rows only when keys are given). */
  readonly markRevoked: (
    origin: string,
    userId: string,
    fingerprintsHex: readonly string[],
    nowMs: number,
  ) => Effect.Effect<void, CliError>;
}

export class OwnDeviceStore extends Context.Service<OwnDeviceStore, OwnDeviceStoreShape>()(
  "cli/OwnDeviceStore",
) {}

/** 記録の置き場所(設定と同系: <config.json の親>/own-devices.json)。 */
export function ownDevicesPathOf(configPath: string): string {
  return join(dirname(configPath), "own-devices.json");
}

/** The cap a record declares (`add_device` payload — CRYPTO_SPEC §6.2). */
export function capOfRecord(record: OwnDeviceRecord): DeviceCap {
  return { roleCap: record.roleCap, scope: record.scope };
}

interface OwnDevicesFile {
  readonly v: 1;
  readonly known: Readonly<
    Record<string, Readonly<Record<string, Readonly<Record<string, OwnDeviceRecord>>>>>
  >;
}

const HEX_32 = /^[0-9a-f]{32}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const ROLES: readonly Role[] = ["reader", "member", "admin", "owner"];
const SOURCES: readonly OwnDeviceSource[] = ["reserve", "approved", "observed"];

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function decodeListedIds(ids: readonly unknown[]): readonly string[] | null {
  if (ids.length > MAX_SCOPE_ENVIRONMENTS) {
    return null;
  }
  const environmentIds: string[] = [];
  for (const id of ids) {
    if (typeof id !== "string" || !isEnvironmentId(id) || environmentIds.includes(id)) {
      return null;
    }
    environmentIds.push(id);
  }
  return environmentIds;
}

function decodeScope(kind: unknown, ids: unknown): MemberScope | null {
  if (!Array.isArray(ids)) {
    return null;
  }
  if (kind === "all") {
    return ids.length === 0 ? { kind: "all" } : null;
  }
  const environmentIds = kind === "listed" ? decodeListedIds(ids) : null;
  return environmentIds === null ? null : { kind: "listed", environmentIds: [...environmentIds] };
}

function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX_64.test(value);
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

/** 鍵側(公開鍵・cap・出所)のデコード。 */
function decodeKeys(
  value: Record<string, unknown>,
): Pick<OwnDeviceRecord, "encPubHex" | "sigPubHex" | "roleCap" | "scope" | "source"> | null {
  const encPubHex = value["encPubHex"];
  const sigPubHex = value["sigPubHex"];
  const roleCap = ROLES.find((role) => role === value["roleCap"]);
  const source = SOURCES.find((known) => known === value["source"]);
  const scope = decodeScope(value["scopeKind"], value["scopeEnvironmentIds"]);
  if (
    !isHex64(encPubHex) ||
    !isHex64(sigPubHex) ||
    roleCap === undefined ||
    source === undefined ||
    scope === null
  ) {
    return null;
  }
  return { encPubHex, sigPubHex, roleCap, scope, source };
}

/** 出所側(表示名・追加者・観測プロジェクト・時刻)のデコード。 */
function decodeProvenance(
  value: Record<string, unknown>,
): Pick<
  OwnDeviceRecord,
  "label" | "addedByFingerprintHex" | "observedProjectId" | "recordedAtMs" | "revokedAtMs"
> | null {
  const label = value["label"];
  const addedBy = value["addedByFingerprintHex"];
  const observedProjectId = value["observedProjectId"];
  const recordedAtMs = value["recordedAtMs"];
  const revokedAtMs = value["revokedAtMs"];
  if (
    !isNullableString(label) ||
    !isNullableString(addedBy) ||
    (addedBy !== null && !HEX_32.test(addedBy)) ||
    !isNullableString(observedProjectId) ||
    !isTimestamp(recordedAtMs) ||
    !(revokedAtMs === null || isTimestamp(revokedAtMs))
  ) {
    return null;
  }
  return { label, addedByFingerprintHex: addedBy, observedProjectId, recordedAtMs, revokedAtMs };
}

function decodeEntry(value: unknown): OwnDeviceRecord | null {
  if (!isRecord(value)) {
    return null;
  }
  const keys = decodeKeys(value);
  const provenance = decodeProvenance(value);
  return keys === null || provenance === null ? null : { ...keys, ...provenance };
}

function encodeEntry(record: OwnDeviceRecord): Record<string, unknown> {
  return {
    encPubHex: record.encPubHex,
    sigPubHex: record.sigPubHex,
    roleCap: record.roleCap,
    scopeKind: record.scope.kind,
    scopeEnvironmentIds: record.scope.kind === "all" ? [] : [...record.scope.environmentIds],
    source: record.source,
    label: record.label,
    addedByFingerprintHex: record.addedByFingerprintHex,
    observedProjectId: record.observedProjectId,
    recordedAtMs: record.recordedAtMs,
    revokedAtMs: record.revokedAtMs,
  };
}

/** 1 ユーザー分(FP → 記録)のデコード(1 件でも不正なら全体拒否)。 */
function decodeDevices(value: unknown): Record<string, OwnDeviceRecord> | null {
  if (!isRecord(value)) {
    return null;
  }
  const devices: Record<string, OwnDeviceRecord> = {};
  for (const [fingerprintHex, raw] of Object.entries(value)) {
    const entry = decodeEntry(raw);
    if (entry === null || !HEX_32.test(fingerprintHex)) {
      return null;
    }
    devices[fingerprintHex] = entry;
  }
  return devices;
}

function decodeUsers(value: unknown): Record<string, Record<string, OwnDeviceRecord>> | null {
  if (!isRecord(value)) {
    return null;
  }
  const users: Record<string, Record<string, OwnDeviceRecord>> = {};
  for (const [userId, raw] of Object.entries(value)) {
    const devices = BOOK_KEY.test(userId) ? decodeDevices(raw) : null;
    if (devices === null) {
      return null;
    }
    users[userId] = devices;
  }
  return users;
}

/** 厳格デコード(部分読みしない — pins / 指紋帳と同じ)。 */
function decodeFile(json: string): OwnDevicesFile | null {
  const known = decodeOriginBook(json, 1, decodeUsers);
  return known === null ? null : { v: 1, known };
}

/** File-backed own-devices store at `path` (used by both production and tests). */
export function makeFileOwnDeviceStore(path: string): OwnDeviceStoreShape {
  const loadRaw = async (): Promise<
    | { readonly file: OwnDevicesFile; readonly state: "loaded" }
    | { readonly state: "missing" }
    | { readonly state: "corrupt" }
  > => {
    let json: string;
    try {
      json = await readFile(path, "utf8");
    } catch {
      return { state: "missing" };
    }
    const file = decodeFile(json);
    return file === null ? { state: "corrupt" } : { file, state: "loaded" };
  };

  const write = async (file: OwnDevicesFile): Promise<void> => {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temp = `${path}.${process.pid}.tmp`;
    const encoded = {
      v: 1,
      known: Object.fromEntries(
        Object.entries(file.known).map(([origin, users]) => [
          origin,
          Object.fromEntries(
            Object.entries(users).map(([userId, devices]) => [
              userId,
              Object.fromEntries(
                Object.entries(devices).map(([fp, record]) => [fp, encodeEntry(record)]),
              ),
            ]),
          ),
        ]),
      ),
    };
    await writeFile(temp, `${JSON.stringify(encoded, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  };

  const merge = (
    origin: string,
    userId: string,
    apply: (devices: Readonly<Record<string, OwnDeviceRecord>>) => Record<string, OwnDeviceRecord>,
  ): Effect.Effect<void, CliError> =>
    Effect.tryPromise({
      try: async () => {
        if (!BOOK_KEY.test(origin) || !BOOK_KEY.test(userId)) {
          throw new Error("key form");
        }
        const loaded = await loadRaw();
        if (loaded.state === "corrupt") {
          // 破損ファイルへの上書きは拒否(pins / 指紋帳と同じ規律)
          throw new Error("corrupt");
        }
        const base: OwnDevicesFile = loaded.state === "missing" ? { v: 1, known: {} } : loaded.file;
        const users = floorRecordGet(base.known, origin) ?? {};
        const devices = floorRecordGet(users, userId) ?? {};
        await write({
          v: 1,
          known: { ...base.known, [origin]: { ...users, [userId]: apply(devices) } },
        });
      },
      catch: () =>
        cliError(
          `Cannot write the own-devices record (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
        ),
    });

  return {
    filePath: path,
    load: (origin, userId) =>
      Effect.tryPromise({
        try: async (): Promise<OwnDevicesLookup> => {
          const loaded = await loadRaw();
          if (loaded.state === "missing") {
            return { state: "missing" };
          }
          if (loaded.state === "corrupt") {
            return { state: "corrupt" };
          }
          const users = floorRecordGet(loaded.file.known, origin);
          const devices = users === undefined ? undefined : floorRecordGet(users, userId);
          return {
            state: "loaded",
            devices: Object.entries(devices ?? {}).map(([keyFingerprintHex, record]) => ({
              keyFingerprintHex,
              ...record,
            })),
          };
        },
        catch: () => cliError(`Cannot read the own-devices record: ${path}`),
      }),
    record: (origin, userId, entry) => {
      const { keyFingerprintHex, ...record } = entry;
      if (!HEX_32.test(keyFingerprintHex) || decodeEntry(encodeEntry(record)) === null) {
        return Effect.fail(
          cliError("Cannot record the device: the key material is not in the expected form"),
        );
      }
      return merge(origin, userId, (devices) => ({ ...devices, [keyFingerprintHex]: record }));
    },
    markRevoked: (origin, userId, fingerprintsHex, nowMs) =>
      merge(origin, userId, (devices) => {
        const next = { ...devices };
        for (const fingerprintHex of fingerprintsHex) {
          const existing = floorRecordGet(devices, fingerprintHex);
          if (existing !== undefined && existing.revokedAtMs === null) {
            next[fingerprintHex] = { ...existing, revokedAtMs: nowMs };
          }
        }
        return next;
      }),
  };
}
