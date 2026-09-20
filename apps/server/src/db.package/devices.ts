// 端末登録簿と端末追加要求のリポジトリ(AUTH_SPEC §13-11 — 2026-09-19 DK K3)。
//
// - advisory の帳簿: 表示名・トークンの対応・追加要求の公開鍵の置き場。検証・認可の
//   入力にならない(真実源は各プロジェクトのチェーン)。監査イベントは持たない
//   (§6 のトークン一覧と同じ規律 — 端末の追加・失効の記録はチェーンのミラー行)
// - Drizzle の型・クエリはこのファイル(db.package 境界内)に閉じる。公開シェイプは
//   ドメイン型と Effect のみ
// - 要求行は状態列を持たない(行 = 未消費の要求。失効行は読み取りで隠し、作成・
//   一覧で日和見削除 — 設計録 dk-design.md §8 K3-8)。レート窓は key_wrap_windows の
//   種別 `device-request`(KeyWrapRepo.consumeWindow — 固定窓の実装を増やさない)

import { and, count, eq, gt, lte, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { deviceAddRequests, devices } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

/** D1 の障害は defect(Effect.promise)。ドメイン上の分岐だけを値で返す。 */
const run = <A>(thunk: () => Promise<A>): Effect.Effect<A> => Effect.promise(thunk);

/** 登録簿 1 行(§13-11)。 */
export interface DeviceRecord {
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly tokenId: string | null;
  readonly createdAtMs: number;
}

/** 端末追加要求 1 行(未失効のもののみ返す)。 */
export interface DeviceAddRequestRecord {
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAtMs: number;
}

export interface DeviceRepoShape {
  readonly list: (userId: string) => Effect.Effect<readonly DeviceRecord[]>;
  /**
   * 登録簿の登録・表示名の更新(upsert)。新規行は `limit` 未満のときだけ入る
   * (条件付き INSERT — 並行登録が同じ under-limit を観測しても超えない)。既存行の
   * 更新は上限に数えない。戻り値 false = 上限拒否。
   */
  readonly upsert: (input: {
    readonly userId: string;
    readonly keyFingerprintHex: string;
    readonly encPubHex: string;
    readonly sigPubHex: string;
    readonly label: string;
    readonly tokenId: string | null;
    readonly limit: number;
    readonly nowMs: number;
  }) => Effect.Effect<boolean>;
  /** 戻り値 = 実際に行が消えたか(false は呼び出し側の一様 404)。 */
  readonly remove: (userId: string, keyFingerprintHex: string) => Effect.Effect<boolean>;
  /**
   * 追加要求の作成。同じ FP の未失効の要求 = `request-exists`、登録簿の既存行 =
   * `device-registered`(§13-11 の 409)。失効した同 FP の要求は置き換える。
   */
  readonly requestCreate: (input: {
    readonly userId: string;
    readonly keyFingerprintHex: string;
    readonly encPubHex: string;
    readonly sigPubHex: string;
    readonly label: string;
    readonly nowMs: number;
    readonly ttlMs: number;
  }) => Effect.Effect<"created" | "request-exists" | "device-registered">;
  /** 未失効の要求のみ。 */
  readonly requestList: (
    userId: string,
    nowMs: number,
  ) => Effect.Effect<readonly DeviceAddRequestRecord[]>;
  readonly requestFind: (
    userId: string,
    keyFingerprintHex: string,
    nowMs: number,
  ) => Effect.Effect<DeviceAddRequestRecord | null>;
  /** 戻り値 = 実際に行が消えたか(失効済みの行も消せる — 掃除を兼ねる)。 */
  readonly requestCancel: (userId: string, keyFingerprintHex: string) => Effect.Effect<boolean>;
  /** 失効した要求の日和見削除(当該 user のみ — 作成・一覧の前に呼ぶ)。 */
  readonly requestSweep: (userId: string, nowMs: number) => Effect.Effect<void>;
}

export class DeviceRepo extends Context.Service<DeviceRepo, DeviceRepoShape>()("DeviceRepo") {}

const toRequest = (row: {
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAt: number;
}): DeviceAddRequestRecord => ({
  keyFingerprintHex: row.keyFingerprintHex,
  encPubHex: row.encPubHex,
  sigPubHex: row.sigPubHex,
  label: row.label,
  expiresAtMs: row.expiresAt,
});

export function makeDeviceRepo(db: Db): DeviceRepoShape {
  return {
    list: (userId) =>
      run(async () => {
        const rows = await db
          .select()
          .from(devices)
          .where(eq(devices.userId, userId))
          .orderBy(devices.createdAt, devices.keyFingerprintHex);
        return rows.map((row): DeviceRecord => ({
          keyFingerprintHex: row.keyFingerprintHex,
          encPubHex: row.encPubHex,
          sigPubHex: row.sigPubHex,
          label: row.label,
          tokenId: row.tokenId,
          createdAtMs: row.createdAt,
        }));
      }),
    upsert: ({ userId, keyFingerprintHex, encPubHex, sigPubHex, label, tokenId, limit, nowMs }) =>
      run(async () => {
        // 1 文の上限付き INSERT … SELECT … ON CONFLICT DO UPDATE(TokenRepo と同じ形 —
        // 並行登録の超過を許さない)。同じ (user, FP) の行が既にあれば表示名・トークン id
        // だけを更新する(公開鍵は FP が同じなら同じ鍵対 = 不変)。存在する行は上限に
        // 数えない(更新は WHERE の OR 側で通す)。同じ FP への並行した初回 PUT は片方が
        // INSERT、もう片方が主キー衝突 → DO UPDATE に倒れ、どちらも冪等に 204 になる
        const upserted = await db
          .insert(devices)
          .select(
            db
              .select({
                userId: sql<string>`${userId}`.as("user_id"),
                keyFingerprintHex: sql<string>`${keyFingerprintHex}`.as("key_fingerprint_hex"),
                encPubHex: sql<string>`${encPubHex}`.as("enc_pub_hex"),
                sigPubHex: sql<string>`${sigPubHex}`.as("sig_pub_hex"),
                label: sql<string>`${label}`.as("label"),
                tokenId: sql<string | null>`${tokenId}`.as("token_id"),
                createdAt: sql<number>`${nowMs}`.as("created_at"),
              })
              .from(sql`(select 1)`)
              .where(
                sql`(select count(*) from ${devices} where ${devices.userId} = ${userId}) < ${limit}
                  or exists(select 1 from ${devices} where ${devices.userId} = ${userId}
                            and ${devices.keyFingerprintHex} = ${keyFingerprintHex})`,
              ),
          )
          .onConflictDoUpdate({
            target: [devices.userId, devices.keyFingerprintHex],
            set: { label, tokenId },
          })
          .returning({ fp: devices.keyFingerprintHex });
        return upserted.length === 1;
      }),
    remove: (userId, keyFingerprintHex) =>
      run(async () => {
        const deleted = await db
          .delete(devices)
          .where(and(eq(devices.userId, userId), eq(devices.keyFingerprintHex, keyFingerprintHex)))
          .returning({ fp: devices.keyFingerprintHex });
        return deleted.length === 1;
      }),
    requestCreate: ({ userId, keyFingerprintHex, encPubHex, sigPubHex, label, nowMs, ttlMs }) =>
      run(async () => {
        const registered = await db
          .select({ n: count() })
          .from(devices)
          .where(and(eq(devices.userId, userId), eq(devices.keyFingerprintHex, keyFingerprintHex)))
          .get();
        if ((registered?.n ?? 0) > 0) {
          return "device-registered";
        }
        // 未失効の同 FP は衝突。失効済みは置き換える(ON CONFLICT … WHERE expires_at <= now)
        const rows = await db
          .insert(deviceAddRequests)
          .values({
            userId,
            keyFingerprintHex,
            encPubHex,
            sigPubHex,
            label,
            createdAt: nowMs,
            expiresAt: nowMs + ttlMs,
          })
          .onConflictDoUpdate({
            target: [deviceAddRequests.userId, deviceAddRequests.keyFingerprintHex],
            set: {
              encPubHex,
              sigPubHex,
              label,
              createdAt: nowMs,
              expiresAt: nowMs + ttlMs,
            },
            setWhere: sql`${deviceAddRequests.expiresAt} <= ${nowMs}`,
          })
          .returning({ fp: deviceAddRequests.keyFingerprintHex });
        return rows.length === 1 ? "created" : "request-exists";
      }),
    requestList: (userId, nowMs) =>
      run(async () => {
        const rows = await db
          .select()
          .from(deviceAddRequests)
          .where(and(eq(deviceAddRequests.userId, userId), gt(deviceAddRequests.expiresAt, nowMs)))
          .orderBy(deviceAddRequests.createdAt, deviceAddRequests.keyFingerprintHex);
        return rows.map(toRequest);
      }),
    requestFind: (userId, keyFingerprintHex, nowMs) =>
      run(async () => {
        const row = await db
          .select()
          .from(deviceAddRequests)
          .where(
            and(
              eq(deviceAddRequests.userId, userId),
              eq(deviceAddRequests.keyFingerprintHex, keyFingerprintHex),
              gt(deviceAddRequests.expiresAt, nowMs),
            ),
          )
          .get();
        return row === undefined ? null : toRequest(row);
      }),
    requestCancel: (userId, keyFingerprintHex) =>
      run(async () => {
        const deleted = await db
          .delete(deviceAddRequests)
          .where(
            and(
              eq(deviceAddRequests.userId, userId),
              eq(deviceAddRequests.keyFingerprintHex, keyFingerprintHex),
            ),
          )
          .returning({ fp: deviceAddRequests.keyFingerprintHex });
        return deleted.length === 1;
      }),
    requestSweep: (userId, nowMs) =>
      run(async () => {
        await db
          .delete(deviceAddRequests)
          .where(
            and(eq(deviceAddRequests.userId, userId), lte(deviceAddRequests.expiresAt, nowMs)),
          );
      }),
  };
}
