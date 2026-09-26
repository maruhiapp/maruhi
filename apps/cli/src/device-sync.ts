// 初回同期の端末登録と端末集合の観測(CRYPTO_SPEC §6.2 / §7 — 2026-09-19 DK。設計録
// dk-design.md §9 K4-3 / K4-4 / K4-9 / K4-14)。
//
// 鍵ありの前段(context.ts の openProjectWith)が同期の後に毎回呼ぶ(冪等 — K4-3
// 第 3 巡)。行うこと:
//   (a) 観測: 検証済みチェーン上の自分の端末で、ローカル記録に無いものを "observed" で
//       記録し、出所(誰の端末が seq いくつで足したか)を Note で見せる(K4-4 d-2)。
//       失効済みと記録した端末が再び載っていれば Note(明示の再承認だけが記録を戻す)
//   (b) 失効の観測: チェーン上の自分宛 `revoke_device` に含まれる記録行を revoked にする
//       (K4-3 反例 1 — 別プロジェクトで復活させない)
//   (c) 登録: ローカル記録のうち失効しておらず、このチェーンに無い端末(予備鍵・承認した
//       端末・他プロジェクトで観測した端末)を、この端末の署名で `add_device` し、
//       バックフィルする。通信前判定(cap の単調性・`listed` の環境の存在)で足せない
//       行と、サーバーの受理ポリシー(DeviceLimit)・旧サーバー(DeviceOpsNotAccepted —
//       K4-14)は Note にして続ける。コマンド本体の成否を変えない(SHOULD の付随)
//   (d) 予備鍵の不在の警告(K4-9): 自分の端末がこの端末だけで、記録にも予備鍵が無い
//
// 登録簿(`GET /auth/devices`)はここでは読まない・書かない(K4-3 反例 2 — テストで固定)。

import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Effect, type Stdio } from "effect";

import { ensureHumanCeremonyAllowed } from "./agent-gate.ts";
import type { ProjectContext } from "./context.ts";
import { gapFillCommandOf } from "./device-gaps.ts";
import {
  capWithinSignerCap,
  describeCap,
  deviceProvenanceOf,
  devicesOf,
  findOwnDevice,
  reAddDeviceRoute,
  revokedFingerprintsOf,
} from "./device-key.ts";
import { appendAddDevice, backfillToDevice } from "./device-ops.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import {
  capOfRecord,
  type OwnDeviceEntry,
  OwnDeviceStore,
  type OwnDeviceStoreShape,
} from "./own-devices.ts";
import { requireScopeEnvironmentsExist } from "./scope.ts";
import type { VerifiedProject } from "./sync.ts";

/**
 * Runs the device-set reconciliation for one keyed command (idempotent). Returns
 * the context with a resynced view when this device appended anything. Never
 * fails the command: every problem becomes a Note / Warning.
 */
export function syncOwnDevices(
  context: ProjectContext,
): Effect.Effect<ProjectContext, never, OwnDeviceStore | CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const { session } = context;
    const self = context.verified.state.members.get(session.userId);
    if (self === undefined) {
      return context;
    }
    const lookup = yield* store
      .load(session.origin, session.userId)
      .pipe(Effect.catch(() => Effect.succeed({ state: "corrupt" } as const)));
    if (lookup.state === "corrupt") {
      yield* logWarning(
        `the own-devices record is corrupt and was ignored: ${store.filePath} — inspect it, and delete it if the change was not intentional (device keys are re-observed from the project chains)`,
      );
      return context;
    }
    const records = lookup.state === "loaded" ? lookup.devices : [];
    // (a)(b): 観測と失効の観測(記録の更新は fail-open — 書けなければ Note)
    yield* observeDevices({ context, self, records, store });
    // (c): 登録(この端末がチェーン上の自分の端末であるときだけ署名できる)
    const own = findOwnDevice(self, { keyFingerprintHex: context.masterKeys.fingerprintHex });
    if (own === undefined) {
      return context;
    }
    let current = context;
    const candidates = registrationCandidates(context.verified, self, records);
    // 登録は署名を伴う(add_device + DEK のラップ)ので、`device approve` と同じ儀式ゲート
    // (既知エージェント → stdin / stdout が端末か)を通る人のセッションでだけ行う。
    // ローカル記録は署名されていないファイルで、エージェント環境で行を仕込めば
    // このゲート抜きに署名者を足せてしまう(K4-37 — セキュリティレビュー指摘)
    if (candidates.length > 0 && (yield* registrationAllowed(context.projectId, candidates))) {
      for (const candidate of candidates) {
        current = yield* registerRecorded({ context: current, self, own, candidate });
      }
    }
    // (d): 予備鍵の不在(K4-9)
    yield* warnReserveMissing({
      self: current.verified.state.members.get(session.userId) ?? self,
      own,
      records,
    });
    return current;
  });
}

/**
 * (c) の儀式ゲート(K4-37): 通らなければ Note を出して false(コマンド本体は止めない —
 * 登録は SHOULD の付随)。材料は `ensureDeviceApproveAllowed` と同じ 2 層。
 */
function registrationAllowed(
  projectId: string,
  candidates: readonly OwnDeviceEntry[],
): Effect.Effect<boolean, never, CliIo | Stdio.Stdio> {
  return ensureHumanCeremonyAllowed({
    agentRefusal: (detected) => `an AI agent environment was detected${detected}`,
    terminalRefusal: (reason) => reason,
  }).pipe(
    Effect.as(true),
    Effect.catch((error) =>
      logNote(
        `${countNoun(candidates.length, "device key")} recorded on this machine (${candidates.map((candidate) => candidate.keyFingerprintHex).join(", ")}) ${candidates.length === 1 ? "is" : "are"} not registered on project ${displayText(projectId)} yet. Registering a device key adds a signer and wraps DEKs to it, so it is done only when a person runs maruhi at an interactive terminal — skipped here because ${error.message}. Run a keyed maruhi command on this project yourself in a terminal (for example \`maruhi pull --project ${displayText(projectId)}\`) to register ${candidates.length === 1 ? "it" : "them"}, or remove the record if you do not recognise it (\`maruhi device list\`)`,
      ).pipe(Effect.as(false)),
    ),
  );
}

/** (c) の候補: 失効しておらず、このチェーンに無く、このチェーンで失効してもいない記録。 */
function registrationCandidates(
  verified: VerifiedProject,
  self: ChainMember,
  records: readonly OwnDeviceEntry[],
): readonly OwnDeviceEntry[] {
  const revokedHere = revokedFingerprintsOf(verified, self.userId);
  return records.filter(
    (record) =>
      record.revokedAtMs === null &&
      !self.devices.has(record.keyFingerprintHex) &&
      !revokedHere.has(record.keyFingerprintHex),
  );
}

/** (d) K4-9: 自分の端末がこの端末だけで、記録にも予備鍵が無いときの警告(1 つの事実に 1 つの案内)。 */
function warnReserveMissing(input: {
  readonly self: ChainMember;
  readonly own: ChainDevice;
  readonly records: readonly OwnDeviceEntry[];
}): Effect.Effect<void, never, CliIo> {
  const onlyThisDevice =
    input.self.devices.size === 1 && input.self.devices.has(input.own.keyFingerprintHex);
  const hasReserveRecord = input.records.some(
    (record) => record.source === "reserve" && record.revokedAtMs === null,
  );
  if (!onlyThisDevice || hasReserveRecord) {
    return Effect.void;
  }
  return logWarning(
    "no reserve key is registered for you on this project (only this device's key). Run `maruhi key recovery` to create a reserve key and seal it. Without a reserve key, losing this device means losing access",
  );
}

/** (a)(b) 観測: チェーン上の自分の端末を記録し、失効を記録に写す。 */
function observeDevices(input: {
  readonly context: ProjectContext;
  readonly self: ChainMember;
  readonly records: readonly OwnDeviceEntry[];
  readonly store: OwnDeviceStoreShape;
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const { context, self, records, store } = input;
    const { session } = context;
    const byFp = new Map(records.map((record) => [record.keyFingerprintHex, record]));
    for (const device of devicesOf(self)) {
      const known = byFp.get(device.keyFingerprintHex);
      const provenance = deviceProvenanceOf(context.verified, session.userId, device);
      if (known === undefined) {
        // 初回観測(K4-4 d-2): 出所つきの Note。自分の端末自身は黙って記録する
        const entry: OwnDeviceEntry = {
          keyFingerprintHex: device.keyFingerprintHex,
          encPubHex: device.encPubHex,
          sigPubHex: device.sigPubHex,
          roleCap: device.roleCap,
          scope: device.scope,
          source: "observed",
          label: null,
          addedByFingerprintHex: provenance.addedByFingerprintHex,
          observedProjectId: context.projectId,
          recordedAtMs: Date.now(),
          revokedAtMs: null,
        };
        yield* store
          .record(session.origin, session.userId, entry)
          .pipe(Effect.catch((error) => noteWriteFailure(error)));
        if (device.keyFingerprintHex !== context.masterKeys.fingerprintHex) {
          yield* logNote(describeObservation(context.projectId, device, provenance));
        }
      } else if (known.revokedAtMs !== null) {
        // 失効の印を消すのは再承認だけで、登録済みの鍵は要求を作り直せない(DK K10-5)ので、
        // 「承認し直せ」とは言わない(従えない手順)。他のプロジェクトにも要るなら新しい鍵で
        yield* logNote(
          `device ${device.keyFingerprintHex} was revoked from this machine's records but is active on project ${displayText(context.projectId)} (${describeAdder(provenance)}). It is not re-added to other projects from here (a revoked record is never cleared by syncing). If it should not be active, revoke it with \`maruhi device revoke ${device.keyFingerprintHex}\`; if that machine should be on more projects, revoke it, then ${reAddDeviceRoute("that machine")}`,
        );
      }
    }
    // (b): このチェーンの失効を記録に写す(現端末でない失効 FP のうち、記録が active のもの)
    const revokedHere = revokedFingerprintsOf(context.verified, session.userId);
    const toMark = records
      .filter(
        (record) =>
          record.revokedAtMs === null &&
          revokedHere.has(record.keyFingerprintHex) &&
          !self.devices.has(record.keyFingerprintHex),
      )
      .map((record) => record.keyFingerprintHex);
    if (toMark.length > 0) {
      yield* store
        .markRevoked(session.origin, session.userId, toMark, Date.now())
        .pipe(Effect.catch((error) => noteWriteFailure(error)));
      yield* logNote(
        `device ${toMark.join(", ")} is revoked on project ${displayText(context.projectId)}; marked as revoked in this machine's records (it will not be added to other projects from here)`,
      );
    }
  });
}

function describeAdder(provenance: {
  readonly addedByFingerprintHex: string | null;
  readonly seq: number;
  readonly adderStillActive: boolean;
}): string {
  return provenance.addedByFingerprintHex === null
    ? `your first key on the chain, seq ${provenance.seq}`
    : `added by device ${provenance.addedByFingerprintHex} at seq ${provenance.seq}${provenance.adderStillActive ? "" : " — that device is now revoked"}`;
}

function describeObservation(
  projectId: string,
  device: ChainDevice,
  provenance: {
    readonly addedByFingerprintHex: string | null;
    readonly seq: number;
    readonly adderStillActive: boolean;
  },
): string {
  return `observed your device ${device.keyFingerprintHex} (cap ${describeCap(device)}) on project ${displayText(projectId)}: ${describeAdder(provenance)}. It was not approved from this machine; compare it with \`maruhi device list\` and, if you do not recognise it, revoke it with \`maruhi device revoke ${device.keyFingerprintHex}\``;
}

function noteWriteFailure(error: CliError): Effect.Effect<void, never, CliIo> {
  return logNote(
    `could not update this machine's own-devices record (${error.message}); the device set is re-observed on the next sync`,
  );
}

/** (c) 1 行の登録(失敗はすべて Note — 1 台の失敗で同期を止めない)。 */
function registerRecorded(input: {
  readonly context: ProjectContext;
  readonly self: ChainMember;
  readonly own: ChainDevice;
  readonly candidate: OwnDeviceEntry;
}): Effect.Effect<ProjectContext, never, CliIo> {
  const { context, candidate, own } = input;
  const label = `${candidate.keyFingerprintHex} (${candidate.source}${candidate.label === null ? "" : `, "${displayText(candidate.label)}"`})`;
  const cap = capOfRecord(candidate);
  return Effect.gen(function* () {
    if (!capWithinSignerCap(cap, own)) {
      yield* logNote(
        `your device ${label} is not registered on project ${displayText(context.projectId)} yet, and this device's cap ${describeCap(own)} cannot register a device with cap ${describeCap(cap)}. Sync from a device with a wider cap to register it`,
      );
      return context;
    }
    yield* requireScopeEnvironmentsExist(context.verified, cap.scope);
    const { appended } = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: context.session.userId, signingKeyPair: context.masterKeys.sigKeyPair },
      candidate: { encPubHex: candidate.encPubHex, sigPubHex: candidate.sigPubHex, cap },
    });
    const verified = yield* context.resync;
    const current = verified.state.members.get(context.session.userId);
    const targetDevice = current?.devices.get(candidate.keyFingerprintHex);
    if (current === undefined || targetDevice === undefined) {
      yield* logNote(
        `registered your device ${label} on project ${displayText(context.projectId)}, but the resync does not show it yet, so its keys were not distributed. Once it appears there, \`${gapFillCommandOf(context.projectId, "<environment>")}\` on a registered device of yours whose cap covers the environment fills its keys, for each environment it should read`,
      );
      return { ...context, verified };
    }
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient: context.recipient,
      targetMember: current,
      targetDevice,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
    });
    // 記録の cap が働く唯一の時点なので、足した(見つけた)cap をチェーンから出す(DK K10-3)
    yield* logNote(
      `${appended ? "registered" : "found"} your device ${label} with cap ${describeCap(targetDevice)} on project ${displayText(context.projectId)} and backfilled ${backfill.registered} DEK wraps (${backfill.alreadyRegistered} already present)${describeFailedBackfill(context.projectId, backfill.failed)}`,
    );
    return { ...context, verified };
  }).pipe(
    Effect.catch((error) =>
      Effect.gen(function* () {
        yield* logNote(describeRegistrationFailure(context.projectId, label, error));
        return context;
      }),
    ),
  );
}

/**
 * 登録した端末のバックフィルの失敗(DK K11-5): 同期の候補はチェーンに無い記録だけなので、
 * 次の同期は補わない。補うのは cap が覆う端末の pull(`device-gaps.ts`)。
 */
function describeFailedBackfill(
  projectId: string,
  failed: readonly { readonly environmentId: string }[],
): string {
  if (failed.length === 0) {
    return "";
  }
  const environments = failed.map((failure) => displayText(failure.environmentId)).join(", ");
  // 失敗した環境は分かっているので、コマンドは環境ごとに実 id で出す(写して打てる形 —
  // Cursor Bugbot 指摘。`<environment>` の置き場所は環境が分からない場面だけ)
  const commands = failed
    .map((failure) => `\`${gapFillCommandOf(projectId, failure.environmentId)}\``)
    .join(", ");
  return `; the backfill failed for ${countNoun(failed.length, "environment")} (${environments}) — a registered device of yours whose cap covers ${failed.length === 1 ? "it" : "them"} fills the missing epochs when it runs ${commands}`;
}

function describeRegistrationFailure(projectId: string, label: string, error: CliError): string {
  // 追記経路は型付きエラーを failure.ts の文言(1 箇所)へ写した後なので、ここは
  // その文言に K4-14 の持ち越し(ローカル記録は保つ)を添えるだけ
  if (error.message.startsWith("This server does not accept device operations")) {
    return `your device ${label} is recorded on this machine but project ${displayText(projectId)}'s server does not accept device operations yet. ${error.message}. The registration is retried by a sync after the server is updated`;
  }
  return `your device ${label} could not be registered on project ${displayText(projectId)} (${error.message}); the registration is retried on the next sync`;
}
