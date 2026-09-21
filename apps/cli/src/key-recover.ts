// 復元(`maruhi key recover`)と予備鍵の再封印 / 分離(`key recovery`)/ rotate(`key
// reserve rotate`)— CRYPTO_SPEC §3 / §8、設計録 dk-design.md §9 K4-2 / K4-9 / K4-10 / K4-11。
//
// 復元の後段 `finishRecovery`(K4-10): 台帳から得た予備鍵 B は**端末鍵の発行にだけ**
// 用いる(§8.1) — (1) この端末の新しい端末鍵を生成しキーチェーンへ保存、(2) 各
// プロジェクトで B が現端末なら B の sig 鍵で `add_device(新端末)` を署名し、B の enc 鍵で
// 自分宛ラップを開いて新端末へバックフィル、(3) B を捨てる(メモリの参照を手放す —
// キーチェーンにも agent メモリにも書かない)。B が予備鍵か(日常の端末で使ったことの
// ない鍵か)は暗号的事実からは判別できないので儀式の中で 1 問聞き、既定(no)は記録
// しない側に倒す(pre-DK の紛失端末の鍵を予備鍵として伝播させない — fail-closed)。
//
// `key recovery`(K4-2 / K4-9): 台帳が無ければ予備鍵を生成して封印(初回)。あれば
// 開封し、B の FP が手元の端末鍵と一致 = pre-DK(台帳が端末鍵の複製)→ 新しい予備鍵を
// 生成して封印し直す(分離)。一致しなければ B は予備鍵 → 同じ B を新しいコードで
// 再封印し、記録を復元する。`--replace` は開封せずに置換(コード紛失の逃げ道)。
//
// `key reserve rotate`(K4-11): 開封 → 新予備鍵を生成・封印・記録 → 各プロジェクトで
// `add_device(新)` + バックフィル → `revoke_device(旧)` + sweep → 旧 B のパスキー /
// 保護者行を削除(失効した鍵しか復元しない行 — 誤信を残さない)。

import { ALL_SCOPE, type ChainDevice } from "@maruhi/crypto";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import {
  type CliServices,
  openMetadataProject,
  openProject,
  type ProjectContext,
} from "./context.ts";
import type { DekRecipient } from "./deks.ts";
import { findOwnDevice } from "./device-key.ts";
import {
  appendAddDevice,
  appendRevokeDevice,
  backfillToDevice,
  DEVICE_REVOKED_ROTATION_REASON,
  type DeviceBackfillOutcome,
  type DeviceSweepOutcome,
  sweepAfterDeviceRevoke,
} from "./device-ops.ts";
import { describeBackfill, reportRegisteredDevice } from "./device.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { requestHandoffReserve } from "./handoff.ts";
import { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, masterKeyEntryName, serializeStoredMasterKey } from "./keychain.ts";
import { recoveryRegistered } from "./keygen.ts";
import {
  type LedgerOpenVia,
  openLedgerReserve,
  openLedgerReserveForChange,
} from "./ledger-open.ts";
import { logNote, logWarning } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { issueRecoveryCodeOp, mapUnloadableRecoveryBlob, sealNewReserve } from "./recovery.ts";
import { generateReserveKeys, recordReserveLocally, type ReserveKeys } from "./reserve.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";

/** How `maruhi key recover` opens the reserve key. */
export type RecoverVia = LedgerOpenVia | "handoff";

/** この端末の新しい端末鍵(復元後に発行 — 既にあれば `--resume` で再利用)。 */
function newOrExistingDeviceKeys(input: {
  readonly session: CliSession;
  readonly resume: boolean;
}): Effect.Effect<MasterKeys, CliError, Keychain | CliIo> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const existing = yield* keychain.get(
      masterKeyEntryName(input.session.origin, input.session.userId),
    );
    if (existing !== null) {
      if (!input.resume) {
        return yield* Effect.fail(
          cliError(
            "A device key already exists on this machine. If an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume (it reuses the existing key and registers it where it is missing); otherwise add this machine as a device from a registered one (`maruhi device add`)",
          ),
        );
      }
      return yield* loadMasterKeys(input.session);
    }
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "A device key already exists on this machine (check it with `maruhi key show`)",
    );
    const record = yield* generateKeyRecord();
    const validated = yield* importMasterKeys(record).pipe(
      Effect.mapError(() =>
        cliError(
          "Could not load the generated device key back (nothing was stored in the keychain). Report this as a maruhi bug",
        ),
      ),
    );
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Generated this device's key",
      fingerprintHex: validated.fingerprintHex,
    });
    return validated;
  });
}

/** 1 プロジェクトでの復元後登録の結果。 */
interface ProjectRecoveryOutcome {
  readonly projectId: string;
  readonly state: "registered" | "already" | "reserve-missing" | "failed";
  readonly backfill: DeviceBackfillOutcome | null;
  readonly message: string | null;
}

/** B(復元した予備鍵)で新端末鍵を 1 プロジェクトへ登録しバックフィルする。 */
function registerDeviceWithReserve(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly reserve: ReserveKeys;
  readonly device: MasterKeys;
}): Effect.Effect<ProjectRecoveryOutcome, never, CliServices> {
  return Effect.gen(function* () {
    // 鍵なしの前段(床・アンカー・ゴシップは通す。申告の提出と初回同期の登録は
    // 新端末がチェーンに載る前なので走らない — 署名は B で手動に行う)
    const context = yield* openMetadataProject({
      server: input.session.origin,
      project: input.projectId,
    });
    const member = context.verified.state.members.get(input.session.userId);
    if (member === undefined) {
      return yield* Effect.fail(cliError("You are not a chain-derived member of this project"));
    }
    if (!member.devices.has(input.reserve.fingerprintHex)) {
      return {
        projectId: input.projectId,
        state: "reserve-missing",
        backfill: null,
        message: null,
      } satisfies ProjectRecoveryOutcome;
    }
    const outcome = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.reserve.sigKeyPair },
      candidate: {
        encPubHex: input.device.record.encPubHex,
        sigPubHex: input.device.record.sigPubHex,
        cap: { roleCap: "owner", scope: ALL_SCOPE },
      },
    });
    const verified = yield* context.resync;
    const current = verified.state.members.get(input.session.userId);
    const targetDevice =
      current === undefined
        ? undefined
        : findOwnDevice(current, { keyFingerprintHex: input.device.fingerprintHex });
    if (current === undefined || targetDevice === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_device was accepted does not show this device on the chain (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    const recipient: DekRecipient = {
      userId: input.session.userId,
      encPubHex: input.reserve.record.encPubHex,
      encKeyPair: input.reserve.encKeyPair,
    };
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient,
      targetMember: current,
      targetDevice,
      signerUserId: input.session.userId,
      signingKeyPair: input.reserve.sigKeyPair,
    });
    return {
      projectId: input.projectId,
      state: outcome.appended ? "registered" : "already",
      backfill,
      message: null,
    } satisfies ProjectRecoveryOutcome;
  }).pipe(
    Effect.catch((error) =>
      Effect.succeed({
        projectId: input.projectId,
        state: "failed",
        backfill: null,
        message: error.message,
      } satisfies ProjectRecoveryOutcome),
    ),
  );
}

/** 予備鍵かを 1 問聞く(K4-10 — 既定 no = 記録しない側)。 */
function askIsReserve(reserve: ReserveKeys): Effect.Effect<boolean, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `Opened key ${reserve.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    yield* io.log(
      "Was this key created as your reserve key (`maruhi key generate` / `key recovery` on a device-key release), never used as a daily device key? On an install from before device keys, the ledger holds a copy of a device key instead",
    );
    const answer = yield* io.promptLine({
      prompt: "Type yes if it is your reserve key (anything else = no): ",
    });
    return answer.trim().toLowerCase() === "yes";
  });
}

/**
 * The common tail of every recovery path: new device key → `add_device` signed
 * by the reserve key on every project where it is registered → backfill →
 * discard the reserve key (K4-10).
 */
function finishRecovery(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly reserve: ReserveKeys;
  readonly resume: boolean;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const device = yield* newOrExistingDeviceKeys({ session: input.session, resume: input.resume });
    const isReserve = yield* askIsReserve(input.reserve);
    if (isReserve) {
      yield* recordReserveLocally(input.session, input.reserve);
    } else {
      yield* logWarning(
        `the opened key ${input.reserve.fingerprintHex} was not recorded as your reserve key. If it is the key of a lost or retired device, revoke it now: \`maruhi device revoke ${input.reserve.fingerprintHex}\`. Then create a separate reserve key with \`maruhi key recovery\``,
      );
    }
    const projects = yield* fetchProjectMemberships(input.client);
    const outcomes: ProjectRecoveryOutcome[] = [];
    for (const project of projects) {
      outcomes.push(
        yield* registerDeviceWithReserve({
          session: input.session,
          client: input.client,
          projectId: project.projectId,
          reserve: input.reserve,
          device,
        }),
      );
    }
    for (const outcome of outcomes) {
      yield* reportRecoveryOutcome(outcome);
    }
    // B の秘密はここで役目を終える(参照を手放す。保存経路は型で閉じている — reserve.ts)
    yield* logNote(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
  });
}

/** 1 プロジェクトの復元後登録の報告(登録 / 済み / 予備鍵未登録 / 失敗)。 */
function reportRecoveryOutcome(outcome: ProjectRecoveryOutcome): Effect.Effect<void, never, CliIo> {
  const label = displayText(outcome.projectId);
  switch (outcome.state) {
    case "registered":
    case "already":
      return reportRegisteredDevice({
        label,
        action:
          outcome.state === "registered"
            ? "registered this device"
            : "this device was already registered",
        backfill: outcome.backfill,
        rerun:
          "Re-run `maruhi key recover --resume` or have a registered device run `maruhi device approve` for this machine",
      }).pipe(Effect.asVoid);
    case "reserve-missing":
      return logWarning(
        `${label}: the opened key is not registered on this project, so this device could not be added there. Ask an admin of the project to re-invite you (\`maruhi invite create\`)`,
      );
    case "failed":
      return logWarning(`${label}: could not register this device (${outcome.message ?? ""})`);
  }
}

/**
 * `maruhi key recover [--passkey|--handoff] [--resume]`: open the reserve key,
 * then register this machine as a new device with it (K4-10).
 */
export function keyRecoverOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: RecoverVia;
  readonly resume: boolean;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // 鍵がある端末は、儀式(コード入力・パスキー・要求の作成)やサーバーに触れる前に
    // 拒否する(--resume だけが例外 — 中断した復元の続き)
    if (!input.resume) {
      const keychain = yield* Keychain;
      const existing = yield* keychain.get(
        masterKeyEntryName(input.session.origin, input.session.userId),
      );
      if (existing !== null) {
        return yield* Effect.fail(
          cliError(
            "A device key already exists on this machine, so there is nothing to recover here. To add this machine as another device of yours, run `maruhi device add` and approve it from a registered device; if an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume",
          ),
        );
      }
    }
    const reserve =
      input.via === "handoff"
        ? yield* Effect.flatMap(
            requestHandoffReserve({ session: input.session, client: input.client }),
            (record) => mapUnloadableRecoveryBlob(importMasterKeys(record)),
          ).pipe(
            Effect.map((keys): ReserveKeys => ({
              reserve: true,
              record: keys.record,
              encKeyPair: keys.encKeyPair,
              sigKeyPair: keys.sigKeyPair,
              fingerprintHex: keys.fingerprintHex,
            })),
          )
        : yield* openLedgerReserve({
            session: input.session,
            client: input.client,
            via: input.via,
          });
    yield* finishRecovery({
      session: input.session,
      client: input.client,
      reserve,
      resume: input.resume,
    });
  });
}

/**
 * `maruhi key recovery [--passkey] [--replace]`: create the reserve key (first
 * sealing), separate it from a pre-DK ledger, or reissue its recovery code (K4-2).
 */
export function keyRecoveryOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
  readonly replace: boolean;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const registered = yield* recoveryRegistered(input.client);
    if (!registered) {
      yield* io.log("No reserve key is sealed yet — creating one");
      yield* sealNewReserve({ session: input.session, client: input.client });
      return 0;
    }
    if (input.replace) {
      if (input.via === "passkey") {
        // --passkey は台帳を開く手段。--replace は開かない前提なので両立しない —
        // パスキーがあるなら開いて再発行する方が同じ予備鍵を保てる(pullfrog 指摘)
        return yield* Effect.fail(
          usageError(
            "--passkey cannot be combined with --replace: --replace never opens the ledger. If you still have a passkey, run `maruhi key recovery --passkey` (without --replace) to reissue the recovery code for the same reserve key",
          ),
        );
      }
      return yield* replaceReserveWithoutOpening(input);
    }
    const opened = yield* openLedgerReserve({
      session: input.session,
      client: input.client,
      via: input.via,
    });
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(
      masterKeyEntryName(input.session.origin, input.session.userId),
    );
    const device = stored === null ? null : yield* loadMasterKeys(input.session);
    if (device !== null && opened.fingerprintHex === device.fingerprintHex) {
      // pre-DK: 台帳 = 端末鍵の複製 → 分離(DK-J J-1)
      yield* io.log(
        `The recovery ledger holds a copy of this device's key (${device.fingerprintHex}) — an install from before device keys. Separating: creating a reserve key and sealing it instead`,
      );
      yield* sealNewReserve({ session: input.session, client: input.client });
      yield* logNote(
        "this device keeps its key as its own device key. Other machines that hold a copy of the same key should register their own device key: run `maruhi device add --replace` there and approve it from this machine with `maruhi device approve`",
      );
      return 0;
    }
    // 予備鍵の再封印(同じ B・新しいコード)+ 記録の復元
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: opened.record,
    });
    yield* recordReserveLocally(input.session, opened);
    yield* logNote(
      `reissued the recovery code for your reserve key (fingerprint ${opened.fingerprintHex}); the previous code no longer works`,
    );
    return 0;
  });
}

/**
 * `key recovery --replace`(コード紛失 / 漏洩の逃げ道): 台帳を開かずに新しい予備鍵を
 * 封印し、この端末の記録にある旧予備鍵をすべてのプロジェクトで失効させる(K4-38)。
 * 旧 B は開けないので、失効の署名はこの端末鍵で行う(rotate と同じ経路)。記録に
 * 無い旧予備鍵は失効できないので、その旨を警告する。
 */
function replaceReserveWithoutOpening(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // 書き込みの前に、何が消えるかを名指しする: コード・記録上の予備鍵の登録・旧 B を
    // 封印していた台帳の行(パスキー / 保護者)。パスキーが残っているなら --passkey の方が
    // 同じ予備鍵を保てる(pullfrog 指摘)
    // 台帳の行の件数は警告の文面のためだけに読む: 読めなくても置換は止めない(コードを
    // 失った利用者の逃げ道なので、一覧の障害で塞がない — Bugbot 指摘)。読めなかった事実は Note
    const status = yield* input.client.keyWraps.status({}).pipe(
      Effect.mapError(toCliError),
      Effect.catch((error) =>
        logNote(
          `could not read the ledger's passkey wraps and guardian groups (${error.message}); the warning below names them generically`,
        ).pipe(Effect.as(null)),
      ),
    );
    yield* logWarning(
      `replacing the recovery ledger without opening it: the previous recovery code stops working, and the reserve keys recorded on this machine are revoked on every project${describeSealedRows(status)}. A previous reserve key that is not recorded here stays registered until you revoke it with \`maruhi device revoke <fingerprint>\` (\`maruhi device list\` shows your devices)`,
    );
    const next = yield* generateReserveKeys();
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: next.record,
    });
    const retiring = yield* staleReserveFingerprints(input.session, null, next.fingerprintHex);
    if (retiring.length === 0) {
      yield* logWarning(
        "no previous reserve key is recorded on this machine, so none was revoked. Check `maruhi device list` and revoke any reserve device you do not recognise with `maruhi device revoke <fingerprint>`",
      );
    }
    return yield* registerReserveAndRetire({ ...input, next, retiring, ledgerRows: status });
  });
}

/**
 * `--replace` の警告に添える、旧 B を封印していた台帳の行の説明(pullfrog 指摘): 一覧が
 * 読めなければ一般形、行が無ければ何も言わない(無い行の削除も、成立しない `--passkey`
 * の案内も出さない)、あればその件数と、パスキーがあるなら `--passkey` の代替を示す。
 */
function describeSealedRows(
  status: {
    readonly passkeys: readonly unknown[];
    readonly guardianGroups: readonly unknown[];
  } | null,
): string {
  if (status === null) {
    return ", and any passkey wraps and guardian groups that seal the current reserve key are deleted. If you still have a passkey for the current reserve key, stop here and run `maruhi key recovery --passkey` instead: it reissues the code for the same reserve key";
  }
  const passkeys = status.passkeys.length;
  const groups = status.guardianGroups.length;
  if (passkeys + groups === 0) {
    return "";
  }
  const passkeyAdvice =
    passkeys === 0
      ? ""
      : ". If you still have that passkey, stop here and run `maruhi key recovery --passkey` instead: it reissues the code for the same reserve key";
  return `, and ${countNoun(passkeys, "passkey wrap")} and ${countNoun(groups, "guardian group")} that seal the current reserve key are deleted${passkeyAdvice}`;
}

/**
 * 新予備鍵の記録 → 旧予備鍵の記録上の失効 → 各プロジェクトで add_device / revoke_device /
 * sweep → 旧 B を封印していた台帳の行の削除(rotate と `--replace` で共通の後段)。
 */
function registerReserveAndRetire(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly next: ReserveKeys;
  readonly retiring: readonly string[];
  /** 事前に読んだ台帳の行(`--replace`)。undefined = 末尾で読む(rotate)。 */
  readonly ledgerRows?: LedgerRows;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* OwnDeviceStore;
    yield* recordReserveLocally(input.session, input.next);
    yield* store.markRevoked(
      input.session.origin,
      input.session.userId,
      input.retiring,
      Date.now(),
    );
    yield* io.log(
      `Sealed the new reserve key ${input.next.fingerprintHex}; registering it${input.retiring.length === 0 ? "" : ` and revoking the previous reserve ${input.retiring.length === 1 ? "key" : "keys"} ${input.retiring.join(", ")}`} on every project`,
    );
    const projects = yield* fetchProjectMemberships(input.client);
    let exitCode = 0;
    for (const project of projects) {
      const outcome = yield* rotateReserveOnProject({
        session: input.session,
        projectId: project.projectId,
        newReserve: input.next,
        oldFingerprintsHex: input.retiring,
      });
      if ((yield* reportReserveRotateOutcome(outcome)) !== 0) {
        exitCode = 1;
      }
    }
    yield* retireOldLedgerRows(input.client, input.ledgerRows);
    return exitCode;
  });
}

/** 台帳の行の一覧(`GET /auth/key-wraps`)。null = 読めなかった(事前警告で Note 済み)。 */
type LedgerRows = {
  readonly passkeys: readonly { readonly wrapId: string }[];
  readonly guardianGroups: readonly { readonly groupId: string }[];
} | null;

/** 1 プロジェクトでの予備鍵 rotate の結果。 */
interface ReserveRotateOutcome {
  readonly projectId: string;
  readonly added: boolean;
  readonly backfill: DeviceBackfillOutcome | null;
  readonly revoked: readonly string[];
  readonly sweep: DeviceSweepOutcome | null;
  readonly failure: string | null;
}

/** 1 プロジェクトで新予備鍵を足し、旧予備鍵を失効させ、sweep する(K4-11 の順序)。 */
function rotateReserveOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly newReserve: ReserveKeys;
  /** 失効させる旧予備鍵の FP(開封した B + 記録上の旧予備鍵 — 中断後の再実行で取り残さない)。 */
  readonly oldFingerprintsHex: readonly string[];
}): Effect.Effect<ReserveRotateOutcome, never, CliServices> {
  return Effect.gen(function* () {
    const context: ProjectContext = yield* openProject(
      { server: input.session.origin, project: input.projectId },
      { quietMandateWarning: true },
    );
    const added = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: context.session.userId, signingKeyPair: context.masterKeys.sigKeyPair },
      candidate: {
        encPubHex: input.newReserve.record.encPubHex,
        sigPubHex: input.newReserve.record.sigPubHex,
        cap: { roleCap: "owner", scope: ALL_SCOPE },
      },
    });
    let verified = yield* context.resync;
    const member = verified.state.members.get(context.session.userId);
    const target: ChainDevice | undefined =
      member === undefined
        ? undefined
        : findOwnDevice(member, { keyFingerprintHex: input.newReserve.fingerprintHex });
    if (member === undefined || target === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_device was accepted does not show the new reserve key on the chain (the server's response contradicts the chain)",
        ),
      );
    }
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient: context.recipient,
      targetMember: member,
      targetDevice: target,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
    });
    const revoke = yield* appendRevokeDevice({
      client: context.client,
      verified,
      resync: context.resync,
      signer: { userId: context.session.userId, signingKeyPair: context.masterKeys.sigKeyPair },
      targetUserId: context.session.userId,
      fingerprintsHex: input.oldFingerprintsHex,
    });
    verified = yield* context.resync;
    const actorMember = verified.state.members.get(context.session.userId);
    const actorDevice =
      actorMember === undefined
        ? undefined
        : findOwnDevice(actorMember, { keyFingerprintHex: context.masterKeys.fingerprintHex });
    const sweep =
      revoke.revoked.length === 0 || actorDevice === undefined
        ? null
        : yield* sweepAfterDeviceRevoke({
            client: context.client,
            verified,
            targetUserId: context.session.userId,
            actorUserId: context.session.userId,
            actorDevice,
            rotate: sweepRotateFor(
              { ...context, verified, resync: context.resync },
              DEVICE_REVOKED_ROTATION_REASON,
            ),
          });
    return {
      projectId: input.projectId,
      added: added.appended,
      backfill,
      revoked: revoke.revoked,
      sweep,
      failure: null,
    } satisfies ReserveRotateOutcome;
  }).pipe(
    Effect.catch((error) =>
      Effect.succeed({
        projectId: input.projectId,
        added: false,
        backfill: null,
        revoked: [],
        sweep: null,
        failure: error.message,
      } satisfies ReserveRotateOutcome),
    ),
  );
}

/** 1 プロジェクトの予備鍵 rotate の報告(終了コード: 失敗があれば 1)。 */
function reportReserveRotateOutcome(
  outcome: ReserveRotateOutcome,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const label = displayText(outcome.projectId);
    if (outcome.failure !== null) {
      yield* logWarning(`${label}: ${outcome.failure} — re-run to continue`);
      return 1;
    }
    yield* io.log(
      `${label}: new reserve key ${outcome.added ? "registered" : "already registered"}${describeBackfill(outcome.backfill)}; previous reserve key ${outcome.revoked.length > 0 ? "revoked" : "already revoked"}`,
    );
    return outcome.sweep === null ? 0 : yield* reportReserveSweep(label, outcome.sweep);
  });
}

/** 旧予備鍵の失効に伴う sweep(K4-8)の報告(失敗があれば 1)。 */
function reportReserveSweep(
  label: string,
  sweep: DeviceSweepOutcome,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const failures =
      sweep.failed.length > 0 ? `, ${countNoun(sweep.failed.length, "failure")}` : "";
    yield* io.log(
      `${label}: rotated ${countNoun(sweep.rotated.length, "environment")}, ${sweep.alreadyRotated.length} already rotated${failures}`,
    );
    for (const failure of sweep.failed) {
      yield* logWarning(
        `${label}: environment ${displayText(failure.environmentId)}: ${failure.message}`,
      );
    }
    if (sweep.outOfScope.length > 0) {
      yield* logWarning(
        `${label}: ${countNoun(sweep.outOfScope.length, "environment")} with a rotation mandate cannot be rotated from this device (${sweep.outOfScope.map(displayText).join(", ")}) — a member holding those DEKs converges them with \`maruhi env rotate <environment> --new-epoch --reason <text>\``,
      );
    }
    return sweep.failed.length > 0 ? 1 : 0;
  });
}

/**
 * 失効させる旧予備鍵の FP 集合(昇順): 開封した B と、ローカル記録で出所 "reserve" の
 * 行すべて(revoked の印の有無を問わない — 前回の中断で印だけ先に付いた鍵を拾う)から
 * 新鍵を除いたもの。
 */
function staleReserveFingerprints(
  session: CliSession,
  openedFingerprintHex: string | null,
  nextFingerprintHex: string,
): Effect.Effect<readonly string[], CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const lookup = yield* store.load(session.origin, session.userId);
    const recorded =
      lookup.state === "loaded"
        ? lookup.devices
            .filter((entry) => entry.source === "reserve")
            .map((entry) => entry.keyFingerprintHex)
        : [];
    return [
      ...new Set([...(openedFingerprintHex === null ? [] : [openedFingerprintHex]), ...recorded]),
    ]
      .filter((fingerprintHex) => fingerprintHex !== nextFingerprintHex)
      .toSorted();
  });
}

/**
 * 旧 B のパスキー行・保護者グループを削除する(失効した鍵しか復元しない行 — K4-11)。
 * `rows` が undefined なら今読む。null(事前に読めなかった — `--replace`)なら、途中の書き込みは
 * これらの行に触れないので同じ障害を再び踏まず、削除を飛ばして後で消す手順を Note に出す
 * (pullfrog 指摘: 書き込みが済んだ後に同じ障害でコマンドを失敗させない)。
 */
function retireOldLedgerRows(
  client: MaruhiClient,
  rows?: LedgerRows,
): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (rows === null) {
      yield* logNote(
        "the ledger's passkey wraps and guardian groups could not be listed, so any that sealed the previous reserve key were left in place (they can only restore a revoked key). Remove them later with `maruhi key seal list` / `maruhi key seal remove <wrap-id>` and `maruhi guardian list` / `maruhi guardian remove <group-id>`",
      );
      return;
    }
    const status = rows ?? (yield* client.keyWraps.status({}).pipe(Effect.mapError(toCliError)));
    for (const passkey of status.passkeys) {
      yield* client.keyWraps.passkeyDelete({ params: { wrapId: passkey.wrapId } }).pipe(
        Effect.catchTag("KeyWrapNotFound", () => Effect.void),
        Effect.mapError(toCliError),
      );
    }
    for (const group of status.guardianGroups) {
      yield* client.keyWraps.guardianDelete({ params: { groupId: group.groupId } }).pipe(
        Effect.catchTag("KeyWrapNotFound", () => Effect.void),
        Effect.mapError(toCliError),
      );
    }
    if (status.passkeys.length > 0 || status.guardianGroups.length > 0) {
      yield* logNote(
        `removed ${countNoun(status.passkeys.length, "passkey wrap")} and ${countNoun(status.guardianGroups.length, "guardian group")} that sealed the previous reserve key (they could only restore a revoked key). Seal the new reserve key again with \`maruhi key seal passkey\` / \`maruhi guardian add\``,
      );
    }
  });
}

/**
 * `maruhi key reserve rotate [--passkey]`: register a new reserve key and revoke
 * the previous one on every project (K4-11).
 */
export function keyReserveRotateOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly via: LedgerOpenVia;
}): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const masterKeys = yield* loadMasterKeys(input.session);
    const old = yield* openLedgerReserveForChange({
      session: input.session,
      client: input.client,
      via: input.via,
      masterKeys,
      command: "maruhi key reserve rotate",
    });
    const next = yield* generateReserveKeys();
    yield* issueRecoveryCodeOp({
      session: input.session,
      client: input.client,
      record: next.record,
    });
    // 失効対象 = 開封した B + ローカル記録上の予備鍵(失効済みの印を含む)のうち新鍵以外。
    // 中断した前回の実行が台帳だけ差し替えて終わっていた場合、B は前回の新鍵で、
    // 元の予備鍵は記録に revoked として残るがチェーンにはまだ載っている(Bugbot 指摘)。
    // appendRevokeDevice はチェーン上で有効な端末だけを失効させる(冪等)
    const retiring = yield* staleReserveFingerprints(
      input.session,
      old.fingerprintHex,
      next.fingerprintHex,
    );
    return yield* registerReserveAndRetire({ ...input, next, retiring });
  });
}
