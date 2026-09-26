// 同じ人の他の端末の欠けたエポックの補完(CRYPTO_SPEC §7 の端末追加のバックフィル /
// AUTH_SPEC §12-6 の登録経路 6 番目 — 2026-09-25 DK K11。設計録 dk-design.md §16)。
//
// 端末の追加のバックフィルは途中で落ちうる(環境ごとの失敗・追記との間の中断・署名側の
// 欠け)が、一度チェーンに載った端末を補う経路は `device approve` にも同期にも無い
// (§16 の事実確認 2)。値付き pull の同梱ラップはその人の**全端末宛**の行を
// `recipientEncPubHex` つきで運ぶ(`listWrapsForRecipient`)ので、pull をした端末は
// 追加の通信なしに兄弟端末の欠けを導ける。ここでは:
//   - 合図: 同梱の行(サーバーの申告)で、兄弟端末の鍵宛の行が無いエポック(K11-3 —
//     申告が決めるのは「試みるか」だけ)
//   - 中身: 対象の端末と鍵は検証済みチェーン、DEK は §5.1 / §5.2 を通した自分宛
//     (pull が開いたもの)。自分が開けたエポックだけを包む(§7「ラップの実行者 = DEK
//     保持者」)。登録済みかどうかはサーバーの受理(409 = 登録済み)が決める
//   - 儀式ゲートの外(K11-2 — 署名者も受信者も増やさない。受信者は R(E) の自分の端末)
//   - 失敗は結果に畳み、pull の成否を変えない(K11-2 の上位互換)
//
// 呼ぶのは `maruhi pull` だけ(K11-4 — pull.ts の `pullVariables` が明示の入力で有効にする)。

import type { RecipientDek } from "@maruhi/api-schema";
import type { ChainDevice, SigningKeyPair } from "@maruhi/crypto";
import { Effect, type Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { backfillEnvironmentFor } from "./backfill.ts";
import { deviceReceivesEnvironment } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { devicesOf } from "./device-key.ts";
import { displayText } from "./display.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import type { VerifiedProject } from "./sync.ts";

/** 1 台の兄弟端末の補完の結果(事実だけを運ぶ — 文言は報告側)。 */
export interface OwnDeviceGapFill {
  readonly deviceFingerprintHex: string;
  /** 同梱の行に、この端末宛が無かったエポック。 */
  readonly missingEpochs: readonly number[];
  /** そのうち、包んで登録したエポックの数(409 = 既にあったものを除く)。 */
  readonly registered: number;
  /** そのうち、登録済み(409)だったエポックの数。 */
  readonly alreadyPresent: number;
  /** そのうち、この端末も開けない(自分宛が無い)ので包めなかったエポック。 */
  readonly unavailableEpochs: readonly number[];
  /** 登録の失敗(null = 失敗なし)。 */
  readonly failure: string | null;
}

/** 兄弟端末の欠け(補完の合図 — 導くだけで何もしない)。 */
interface OwnDeviceGap {
  readonly device: ChainDevice;
  readonly missingEpochs: readonly number[];
}

/**
 * 同梱の行から、同じ人の他の有効な端末のうちこの環境の受信者(`deviceReceivesEnvironment`
 * — 実効 scope)であるものについて、1〜現エポックのうち行の無いエポックを導く。
 */
function ownDeviceGapsOf(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly currentEpoch: number;
  readonly rows: readonly RecipientDek[];
}): readonly OwnDeviceGap[] {
  const self = input.verified.state.members.get(input.recipient.userId);
  if (self === undefined) {
    return [];
  }
  const held = new Map<string, Set<number>>();
  for (const row of input.rows) {
    held.set(
      row.recipientEncPubHex,
      (held.get(row.recipientEncPubHex) ?? new Set()).add(row.epoch),
    );
  }
  return devicesOf(self).flatMap((device) => {
    if (
      device.encPubHex === input.recipient.encPubHex ||
      !deviceReceivesEnvironment(self, device, input.environmentId)
    ) {
      return [];
    }
    const epochs = held.get(device.encPubHex);
    const missingEpochs = Array.from(
      { length: input.currentEpoch },
      (_, index) => index + 1,
    ).filter((epoch) => epochs?.has(epoch) !== true);
    return missingEpochs.length === 0 ? [] : [{ device, missingEpochs }];
  });
}

/**
 * Fills the epochs that the caller's other devices are missing in one
 * environment, from the rows a value-bearing pull already received (DK K11).
 * Wraps only the epochs this device could open; never fails (every problem is
 * returned as a fact for the report).
 */
export function fillOwnDeviceGaps(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  /** 署名する鍵(この端末)。undefined = 補わない(`maruhi pull` 以外 — K11-4)。 */
  readonly signer: { readonly signingKeyPair: SigningKeyPair } | undefined;
  readonly currentEpoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly rows: readonly RecipientDek[];
}): Effect.Effect<readonly OwnDeviceGapFill[]> {
  return Effect.gen(function* () {
    const { signer } = input;
    const self = input.verified.state.members.get(input.recipient.userId);
    const gaps = signer === undefined ? [] : ownDeviceGapsOf(input);
    if (signer === undefined || self === undefined || gaps.length === 0) {
      return [];
    }
    const fills: OwnDeviceGapFill[] = [];
    for (const gap of gaps) {
      const fillable = gap.missingEpochs.filter((epoch) => input.deksByEpoch.has(epoch));
      const unavailableEpochs = gap.missingEpochs.filter((epoch) => !input.deksByEpoch.has(epoch));
      const base = {
        deviceFingerprintHex: gap.device.keyFingerprintHex,
        missingEpochs: gap.missingEpochs,
        unavailableEpochs,
      };
      if (fillable.length === 0) {
        fills.push({ ...base, registered: 0, alreadyPresent: 0, failure: null });
        continue;
      }
      fills.push(
        yield* backfillEnvironmentFor({
          client: input.client,
          verified: input.verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          wrapRecipient: { kind: "member", member: self, device: gap.device },
          recipientLabel: "device-addressed",
          signerUserId: input.recipient.userId,
          signingKeyPair: signer.signingKeyPair,
          epochs: fillable,
          cached: input.deksByEpoch,
        }).pipe(
          Effect.map((outcome): OwnDeviceGapFill => ({
            ...base,
            registered: outcome.registered,
            alreadyPresent: outcome.alreadyRegistered,
            failure: null,
          })),
          Effect.catch((error) =>
            Effect.succeed<OwnDeviceGapFill>({
              ...base,
              registered: 0,
              alreadyPresent: 0,
              failure: error.message,
            }),
          ),
        ),
      );
    }
    return fills;
  });
}

/**
 * 欠けたエポックを補うコマンド(DK K11-5 — 案内の字面はここだけで作る)。`--env` と
 * `--project` は常に明示する(既定の環境に頼ると別の環境を pull する)。
 */
export function gapFillCommandOf(projectId: string, environmentId: string): string {
  return `maruhi pull --project ${displayText(projectId)} --env ${displayText(environmentId)}`;
}

/** 補完の経路の 1 文(承認・復元・同期のバックフィル失敗と、欠けた端末の警告が共有する)。 */
export function describeGapFillRoute(projectId: string, environmentId: string): string {
  return `A registered device of yours whose cap covers environment ${displayText(environmentId)} and that holds its keys fills the missing epochs when it runs \`${gapFillCommandOf(projectId, environmentId)}\``;
}

/**
 * 自分宛の DEK が欠けたエポックの警告(値付き pull と `device add` の到達の確認が共有する —
 * DK K12-3。原因は member 側のバックフィルと端末のバックフィルの両方を並べる)。
 */
export function describeMissingOwnEpochs(
  projectId: string,
  environmentId: string,
  missingEpochs: readonly number[],
): string {
  return `no DEK wraps for you exist at epochs ${missingEpochs.join(", ")} (inconsistent with the CRYPTO_SPEC §7 all-epoch distribution). A backfill (after \`maruhi member add\`, or after a widening \`maruhi member change-role\`) may have been interrupted — historical versions in those epochs cannot be decrypted. Ask an administrator whose scope covers this environment to re-run \`maruhi member add\` or \`maruhi member change-role\` with your current role and scope (a \`maruhi env rotate\` of the environment also distributes the new epoch's key; or re-register through the repair path). If this machine was added as a device, the backfill to it may not have completed instead. ${describeGapFillRoute(projectId, environmentId)}`;
}

function epochList(epochs: readonly number[]): string {
  return `epoch${epochs.length === 1 ? "" : "s"} ${epochs.join(", ")}`;
}

/** 補完の報告(Note だけ — pull の終了コードを変えない)。 */
export function reportOwnDeviceGapFills(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly fills: readonly OwnDeviceGapFill[];
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const environment = displayText(input.environmentId);
    for (const fill of input.fills) {
      const device = `your device ${fill.deviceFingerprintHex}`;
      // 包もうとしたエポック(この端末が開けたもの)。失敗の文も成功の文もこの集合だけを言い、
      // この端末も持たないエポックの文は失敗のときも出す(pullfrog 指摘 — 失敗の文が全部の
      // 欠けを「次の pull で再試行」と言うと、この端末からは決して補えないエポックまで含む)
      const attempted = fill.missingEpochs.filter(
        (epoch) => !fill.unavailableEpochs.includes(epoch),
      );
      if (fill.failure !== null) {
        // 再試行が効くのは原因を除いた後だけ(read スコープのトークンの 403 など — K11-7 の限界 (3))
        yield* logNote(
          `${device} has no keys for ${epochList(attempted)} of environment ${environment} (its backfill did not complete), and filling them from this device failed (${fill.failure}); once the cause is fixed, the next \`${gapFillCommandOf(input.projectId, input.environmentId)}\` tries again`,
        );
      } else if (attempted.length > 0) {
        yield* logNote(
          `${device} had no keys for ${epochList(attempted)} of environment ${environment} (its backfill did not complete); wrapped them to it from this device (${fill.registered} registered, ${fill.alreadyPresent} already present)`,
        );
      }
      if (fill.unavailableEpochs.length > 0) {
        yield* logNote(
          `${device} has no keys for ${epochList(fill.unavailableEpochs)} of environment ${environment}, and this device has none for them either, so it cannot fill them. ${describeGapFillRoute(input.projectId, input.environmentId)}`,
        );
      }
    }
  });
}
