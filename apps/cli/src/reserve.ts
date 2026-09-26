// 予備鍵(CRYPTO_SPEC §3 / §8 — 2026-09-19 DK。設計録 dk-design.md §9 K4-1 / K4-2)。
//
// 予備鍵は端末鍵と同じ形の鍵対のうち、秘密鍵を**日常の端末に置かず台帳(§8)にだけ
// 置く**もの。チェーン上では `add_device`(cap (owner, all))で登録された普通の端末鍵で
// あり、DEK ラップを受け取る。この CLI が予備鍵の秘密を持つのは、封印(コード /
// パスキー / 保護者)・復元・台帳変更を行う**プロセスのメモリの中だけ**であり、
// キーチェーンにも agent のメモリにも書かない(§8.5 の禁止事項・K4-1)。
//
// 型で保存経路を閉じる(K4-1 a-5): 予備鍵は {@link ReserveKeys}(brand `reserve`)で
// 運び、キーチェーン保存(session.ts の `storeMasterKeyAndReport`)は端末鍵の
// `MasterKeys` しか受けない。予備鍵を保存しようとするコードは型エラーになる。
//
// 予備鍵の**公開**側(FP・公開鍵・cap)はローカルの own-devices 記録(own-devices.ts —
// 出所 "reserve")に置き、初回同期の端末登録(device-sync.ts)が各プロジェクトへ
// `add_device` する材料にする(K4-3)。

import { ALL_SCOPE, type EncryptionKeyPair, type SigningKeyPair } from "@maruhi/crypto";
import { Effect } from "effect";

import { deviceProvenanceOf } from "./device-key.ts";
import type { ReserveVerdict, StandingGroups } from "./device-standing.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote, logWarning } from "./notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "./own-devices.ts";
import { type CliSession, importMasterKeys } from "./session.ts";

/**
 * The reserve key, imported and ready to use, held in memory only. The brand
 * keeps it out of every keychain-storing function (those take `MasterKeys`).
 */
export interface ReserveKeys {
  readonly reserve: true;
  readonly record: StoredMasterKey;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
  readonly fingerprintHex: string;
}

/** 台帳から復号したレコード(または生成したレコード)を予備鍵として読み込む。 */
function reserveKeysFromRecord(record: StoredMasterKey): Effect.Effect<ReserveKeys, CliError> {
  return importMasterKeys(record).pipe(
    Effect.mapError(() =>
      cliError(
        "The reserve-key record cannot be loaded (unknown suite or corrupt). Update maruhi to the latest version and re-run",
      ),
    ),
    Effect.map((keys): ReserveKeys => ({
      reserve: true,
      record: keys.record,
      encKeyPair: keys.encKeyPair,
      sigKeyPair: keys.sigKeyPair,
      fingerprintHex: keys.fingerprintHex,
    })),
  );
}

/** Generates a fresh reserve key (memory only — the caller seals it into the ledger). */
export function generateReserveKeys(): Effect.Effect<ReserveKeys, CliError> {
  return Effect.flatMap(generateKeyRecord(), reserveKeysFromRecord);
}

/** The own-devices row for a reserve key (cap (owner, all) — CRYPTO_SPEC §3). */
function reserveEntryOf(reserve: ReserveKeys, nowMs: number): OwnDeviceEntry {
  return {
    keyFingerprintHex: reserve.fingerprintHex,
    encPubHex: reserve.record.encPubHex,
    sigPubHex: reserve.record.sigPubHex,
    roleCap: "owner",
    scope: ALL_SCOPE,
    source: "reserve",
    label: "reserve",
    addedByFingerprintHex: null,
    observedProjectId: null,
    recordedAtMs: nowMs,
    revokedAtMs: null,
  };
}

/**
 * Records the reserve key's public side locally (K4-3 (1)). A write failure is
 * reported as a typed failure: without the record the reserve key never reaches
 * the project chains, so the caller must not report the sealing as complete.
 */
export function recordReserveLocally(
  session: CliSession,
  reserve: ReserveKeys,
): Effect.Effect<void, CliError, OwnDeviceStore> {
  return Effect.flatMap(OwnDeviceStore, (store) =>
    store.record(session.origin, session.userId, reserveEntryOf(reserve, Date.now())),
  );
}

/** The locally recorded reserve keys (not revoked), newest first. */
export function recordedReserves(
  session: CliSession,
): Effect.Effect<readonly OwnDeviceEntry[], CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const loaded = yield* store.load(session.origin, session.userId);
    if (loaded.state !== "loaded") {
      return [];
    }
    return loaded.devices
      .filter((device) => device.source === "reserve" && device.revokedAtMs === null)
      .toSorted((a, b) => b.recordedAtMs - a.recordedAtMs);
  });
}

/**
 * 台帳の鍵が予備鍵として働かないと分かったとき、この端末の誤った reserve の行を直す
 * (DK K14-4 4-g)。書き手の事実は既存のもの(K4-3)だけ: `first-key` → 検証済みチェーンで
 * 最初の鍵として観測した行(出所 observed)に置き換える。`revoked` → 失効を観測した印を
 * 付ける。行が無ければ何もしない。書き込みの失敗はコマンドを落とさず Warning にする。
 */
export function retractReserveRecord(input: {
  readonly session: CliSession;
  readonly fingerprintHex: string;
  readonly verdict: ReserveVerdict;
  readonly groups: StandingGroups;
}): Effect.Effect<void, never, OwnDeviceStore | CliIo> {
  return Effect.gen(function* () {
    const { session, fingerprintHex } = input;
    const store = yield* OwnDeviceStore;
    const loaded = yield* store.load(session.origin, session.userId);
    const recorded =
      loaded.state === "loaded"
        ? loaded.devices.find(
            (row) =>
              row.keyFingerprintHex === fingerprintHex &&
              row.source === "reserve" &&
              row.revokedAtMs === null,
          )
        : undefined;
    if (recorded === undefined) {
      return;
    }
    if (input.verdict.kind === "revoked") {
      yield* store.markRevoked(session.origin, session.userId, [fingerprintHex], Date.now());
      yield* logNote(
        `this machine had recorded ${fingerprintHex} as your reserve key; it is revoked, so the record now says so`,
      );
      return;
    }
    if (input.verdict.kind !== "first-key") {
      return;
    }
    // 観測の行の材料は、有効な立場(最初の鍵のプロジェクトを優先)。最初の鍵だったプロジェクトで
    // 既に失効し、どこにも有効でなければ、失効の印を付ける(K14-18)。同期できないプロジェクトが
    // あれば「どこにも無い」とは言えないので、行に触れない(K14-19 — 門は引き続き鍵を守る)
    const first =
      input.groups.active.find((entry) => entry.standing.firstKey) ?? input.groups.active[0];
    if (first === undefined && input.groups.unsynced.length > 0) {
      return;
    }
    if (first === undefined) {
      yield* store.markRevoked(session.origin, session.userId, [fingerprintHex], Date.now());
      yield* logNote(
        `this machine had recorded ${fingerprintHex} as your reserve key; it is your first key on ${input.verdict.projectIds.map(displayText).join(", ")} and is registered nowhere now, so the record now says it is revoked`,
      );
      return;
    }
    const { device, context } = first.standing;
    yield* store.record(session.origin, session.userId, {
      keyFingerprintHex: fingerprintHex,
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: device.roleCap,
      scope: device.scope,
      source: "observed",
      label: null,
      addedByFingerprintHex: deviceProvenanceOf(context.verified, session.userId, device)
        .addedByFingerprintHex,
      observedProjectId: first.projectId,
      recordedAtMs: Date.now(),
      revokedAtMs: null,
    });
    yield* logNote(
      `this machine had recorded ${fingerprintHex} as your reserve key; it is your first key on ${input.verdict.projectIds.map(displayText).join(", ")}, so the record now lists it as an observed device key (it is no longer revoked by \`maruhi key reserve rotate\` or \`maruhi key recovery --replace\`)`,
    );
  }).pipe(
    Effect.catch((error) =>
      logWarning(
        `could not correct this machine's record of ${input.fingerprintHex} (${error.message}); check it with \`maruhi key show\``,
      ),
    ),
  );
}
