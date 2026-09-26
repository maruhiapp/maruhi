// 台帳の開封(CRYPTO_SPEC §8 改訂 (4) — 2026-09-19 DK。設計録 dk-design.md §9 K4-2)。
//
// 台帳の変更(コード再発行・パスキー封印・保護者の指名・予備鍵の rotate)は、まず
// コード入力かパスキーで予備鍵 B を開封してから行う(台帳を変えるのは台帳を開ける者
// だけ)。開封した B は {@link ReserveKeys}(メモリのみ — reserve.ts)として呼び出し側へ
// 渡し、用が済んだら捨てる。
//
// 台帳の鍵を予備鍵として扱うのは、台帳の中身に予備鍵の印(`kind: "reserve"` — この CLI が
// 生成したときに書く。CRYPTO_SPEC §8)があり、チェーンでどこも失効していないときだけ(DK K16)。

import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import { ledgerKeyVerdictOf, type ReserveVerdict } from "./device-standing.ts";
import { describeProjects, describeUnmarkedLedgerKey } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { openReserveWithPasskey } from "./passkey.ts";
import { mapUnloadableRecoveryBlob, unwrapRecoveryBlobWithCode } from "./recovery.ts";
import {
  isMarkedReserve,
  markRevokedReserveRecord,
  recordReserveLocally,
  type ReserveKeys,
} from "./reserve.ts";
import { type CliSession, importMasterKeys, loadMasterKeys } from "./session.ts";

/** How the ledger is opened: the recovery code (default) or a registered passkey. */
export type LedgerOpenVia = "code" | "passkey";

/** Opens the ledger blob B and loads it as the reserve key (memory only). */
export function openLedgerReserve(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
}): Effect.Effect<ReserveKeys, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const record: StoredMasterKey =
      input.via === "passkey"
        ? yield* openReserveWithPasskey({ session: input.session, client: input.client })
        : yield* unwrapRecoveryBlobWithCode({ session: input.session, client: input.client });
    const keys = yield* mapUnloadableRecoveryBlob(importMasterKeys(record));
    return {
      reserve: true,
      record: keys.record,
      encKeyPair: keys.encKeyPair,
      sigKeyPair: keys.sigKeyPair,
      fingerprintHex: keys.fingerprintHex,
    } satisfies ReserveKeys;
  });
}

/**
 * Opens the ledger for a change (passkey sealing / guardian designation): the key
 * must carry the reserve-key mark and be revoked nowhere (DK K16); it is then
 * recorded locally as the reserve key (state restoration — K4-2 の反例 2).
 */
export function openLedgerReserveForChange(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
  /** 拒否文言に埋める再実行コマンド(例: "maruhi guardian add …")。 */
  readonly command: string;
}): Effect.Effect<ReserveKeys, CliError, CliServices> {
  return Effect.gen(function* () {
    // 端末鍵の読み込みが開封より先(鍵の無い端末に台帳を変える資格は無い)
    yield* loadMasterKeys(input.session);
    const reserve = yield* openLedgerReserve(input);
    const verdict = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: reserve.fingerprintHex,
    });
    yield* settleLedgerKeyForChange({ ...input, reserve, verdict });
    return reserve;
  });
}

/**
 * 開いた台帳の鍵を、台帳を変えるコマンドで使ってよいか(DK K16): どこかで失効していれば、または
 * 予備鍵の印が無ければ、記録せずに止めて `key recovery` を名指す。それ以外は記録する。
 */
export function settleLedgerKeyForChange(input: {
  readonly session: CliSession;
  readonly reserve: ReserveKeys;
  readonly verdict: ReserveVerdict;
  readonly command: string;
}): Effect.Effect<void, CliError, CliIo | OwnDeviceStore> {
  return Effect.gen(function* () {
    const { reserve, verdict } = input;
    const fingerprintHex = reserve.fingerprintHex;
    if (verdict.kind === "revoked") {
      yield* markRevokedReserveRecord(input.session, fingerprintHex);
      return yield* Effect.fail(
        cliError(
          `The recovery ledger holds key ${fingerprintHex}, which is revoked on ${describeProjects(verdict.projectIds)}, so it cannot serve as your reserve key. Run \`maruhi key recovery\` first: it seals a new reserve key in its place. Then re-run \`${input.command}\``,
        ),
      );
    }
    if (!isMarkedReserve(reserve)) {
      return yield* Effect.fail(
        cliError(
          `The recovery ledger holds key ${fingerprintHex}, which ${describeUnmarkedLedgerKey()}. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${input.command}\``,
        ),
      );
    }
    yield* recordReserveLocally(input.session, reserve);
    yield* logNote(`opened the reserve key (fingerprint ${fingerprintHex}) for this change`);
  });
}
