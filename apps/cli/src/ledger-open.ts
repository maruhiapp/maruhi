// 台帳の開封(CRYPTO_SPEC §8 改訂 (4) — 2026-09-19 DK。設計録 dk-design.md §9 K4-2)。
//
// 台帳の変更(コード再発行・パスキー封印・保護者の指名・予備鍵の rotate)は、まず
// コード入力かパスキーで予備鍵 B を開封してから行う(台帳を変えるのは台帳を開ける者
// だけ)。開封した B は {@link ReserveKeys}(メモリのみ — reserve.ts)として呼び出し側へ
// 渡し、用が済んだら捨てる。
//
// pre-DK 台帳の判別: 開封した B の FP が**手元の端末鍵の FP と一致**すれば、台帳は
// 端末鍵の複製(旧「master 鍵」)を持っている。その分離は `maruhi key recovery` だけが
// 行い(key-recover.ts)、他の台帳変更は「先に `key recovery` を」と拒む。判別は
// 暗号的事実(B の中身)で行い、ローカル状態や申告で行わない。一致しなくても、開いた B が
// 検証済みチェーン上でどこかの最初の鍵(別の端末から見た pre-DK の複製)か失効した鍵なら
// 同じく止める(DK K14-4 — `key recover` / `key recovery` と同じ判定 `reserveVerdictOf`)。
// サーバーが一覧から隠したプロジェクトで最初の鍵だった鍵も、この端末の観測の記録にあれば同じく
// 止める(DK K15 — `recorded-first-key`)。

import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import { type LedgerKeyCheck, ledgerKeyVerdictOf, type ReserveVerdict } from "./device-standing.ts";
import { describeProjects, describeRecordedFirstKey } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { StoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import type { OwnDeviceStore } from "./own-devices.ts";
import { openReserveWithPasskey } from "./passkey.ts";
import { mapUnloadableRecoveryBlob, unwrapRecoveryBlobWithCode } from "./recovery.ts";
import { recordReserveLocally, type ReserveKeys, retractReserveRecord } from "./reserve.ts";
import { type CliSession, importMasterKeys, type MasterKeys } from "./session.ts";

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

/** 台帳が端末鍵の複製(pre-DK)を持っているときの拒否文言。 */
function ledgerHoldsDeviceKeyMessage(command: string): string {
  return `The recovery ledger holds a copy of this device's key (an install from before device keys), not a separate reserve key. Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${command}\``;
}

/**
 * 台帳の鍵がチェーン上で予備鍵として働かないときの拒否文言(DK K14-4 4-f — FP の一致の
 * 拒否と同じ形: 何が → なぜ → `key recovery` を先に → 再実行)。
 */
function ledgerKeyUnusableMessage(
  fingerprintHex: string,
  verdict: Extract<
    ReserveVerdict,
    { readonly kind: "first-key" | "recorded-first-key" | "revoked" }
  >,
  command: string,
): string {
  const separate = `Run \`maruhi key recovery\` first: it creates a reserve key, seals it with a new recovery code and replaces the ledger. Then re-run \`${command}\``;
  switch (verdict.kind) {
    case "first-key":
      return `The recovery ledger holds key ${fingerprintHex}, your first key on ${describeProjects(verdict.projectIds)} (the key you created or joined that project with): a copy of a device key from an install before device keys, not a separate reserve key. ${separate}`;
    case "recorded-first-key":
      return `The recovery ledger holds key ${fingerprintHex}. This machine's records show it ${describeRecordedFirstKey(verdict.projectId)}: a copy of a device key from an install before device keys, not a separate reserve key. ${separate}`;
    case "revoked":
      return `The recovery ledger holds key ${fingerprintHex}, which is revoked on ${describeProjects(verdict.projectIds)}, so it cannot serve as your reserve key. Run \`maruhi key recovery\` first: it seals a new reserve key in its place. Then re-run \`${command}\``;
  }
}

/** 確かめられなかった範囲(同期できないプロジェクト、または一覧の失敗)の句(K14-13 — 写しを作らない)。 */
export function describeUncheckedLedgerKey(
  key: string,
  verdict: Extract<ReserveVerdict, { readonly kind: "unchecked" }>,
): string {
  return verdict.listFailure === null
    ? `could not check ${key} on ${describeProjects(verdict.projectIds)}`
    : `could not list your projects to check ${key} (${verdict.listFailure})`;
}

/** 台帳を変えるコマンドの入力(開封の手段・比較する端末鍵・拒否文に埋める再実行コマンド)。 */
interface LedgerChangeInput {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
  /** この端末の端末鍵(pre-DK 判別の比較対象)。 */
  readonly masterKeys: MasterKeys;
  /** 拒否文言に埋める再実行コマンド(例: "maruhi guardian add …")。 */
  readonly command: string;
}

/**
 * Opens the ledger for a change (passkey sealing / guardian designation / reserve
 * rotation): refuses a pre-DK ledger (B = this device's key, or — from the
 * project chains — a first key or a revoked key: DK K14-4) and records the
 * reserve key's public side locally (state restoration — K4-2 の反例 2).
 */
export function openLedgerReserveForChange(
  input: LedgerChangeInput,
): Effect.Effect<ReserveKeys, CliError, CliServices> {
  return Effect.gen(function* () {
    const reserve = yield* openLedgerKeyForChange(input);
    const check = yield* ledgerKeyVerdictOf({
      session: input.session,
      client: input.client,
      fingerprintHex: reserve.fingerprintHex,
    });
    yield* settleLedgerKeyForChange({ ...input, reserve, check, onUnchecked: "proceed" });
    return reserve;
  });
}

/**
 * 台帳を開き、手元の端末鍵の複製(FP の一致)なら拒否する(判定の前半 — チェーンを見る後半は
 * `settleLedgerKeyForChange`)。rotate は開いた鍵と記録の行をまとめて 1 回で確かめるために、
 * 前半と後半を分けて呼ぶ(DK K14-16)。
 */
export function openLedgerKeyForChange(
  input: LedgerChangeInput,
): Effect.Effect<ReserveKeys, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const reserve = yield* openLedgerReserve(input);
    if (reserve.fingerprintHex === input.masterKeys.fingerprintHex) {
      return yield* Effect.fail(cliError(ledgerHoldsDeviceKeyMessage(input.command)));
    }
    return reserve;
  });
}

/**
 * 開いた台帳の鍵のチェーン上の判定に従う(判定の後半): 最初の鍵・失効した鍵は記録せずに止め
 * (この端末の誤った reserve の行は直す)、確かめられない鍵は `onUnchecked` に従う —
 * "proceed"(台帳の操作は進めるが記録しない — K14-13)か "refuse"(操作の目的が旧い鍵の失効
 * である rotate — 何も変えずに止める。K14-15)。それ以外は記録する。
 */
export function settleLedgerKeyForChange(input: {
  readonly session: CliSession;
  readonly reserve: ReserveKeys;
  readonly check: LedgerKeyCheck;
  readonly command: string;
  readonly onUnchecked: "proceed" | "refuse";
}): Effect.Effect<void, CliError, CliIo | OwnDeviceStore> {
  return Effect.gen(function* () {
    const { reserve, check } = input;
    const fingerprintHex = reserve.fingerprintHex;
    const { verdict, groups } = check;
    // 手元の鍵と一致しなくても、チェーンで予備鍵として働かないと分かる鍵は記録せずに止める
    // (`key recovery` と同じ判定 — 複製を reserve と記録すると、rotate / --replace が元の
    // 端末を黙って失効させる入力になる)
    if (
      verdict.kind === "first-key" ||
      verdict.kind === "recorded-first-key" ||
      verdict.kind === "revoked"
    ) {
      yield* retractReserveRecord({ session: input.session, fingerprintHex, verdict, groups });
      return yield* Effect.fail(
        cliError(ledgerKeyUnusableMessage(fingerprintHex, verdict, input.command)),
      );
    }
    if (check.unchecked !== null && input.onUnchecked === "refuse") {
      return yield* Effect.fail(
        cliError(
          `Refused to change anything: ${describeUncheckedLedgerKey(`the opened key ${fingerprintHex}`, check.unchecked)}. \`${input.command}\` exists to revoke the previous reserve key, and a key that cannot be checked on every project is never revoked (it could be one of your device keys), so the new reserve key would not replace it. Nothing was changed; re-run \`${input.command}\` once they can be checked`,
        ),
      );
    }
    if (check.unchecked !== null) {
      // 台帳の操作は進めるが、判定できない鍵は記録しない(記録は rotate / --replace の失効の
      // 入力になる — K14-13)
      yield* logNote(
        `${describeUncheckedLedgerKey(`the opened key ${fingerprintHex}`, check.unchecked)}, so this change goes ahead, but the key is not recorded on this machine as your reserve key. Once they can be checked, run \`maruhi key recovery\`: it separates the key if it is your first key on one of them (a copy of a device key from an install before device keys), and records it otherwise`,
      );
    } else {
      yield* recordReserveLocally(input.session, reserve);
    }
    yield* logNote(`opened the reserve key (fingerprint ${fingerprintHex}) for this change`);
  });
}
