import type { RecipientDek } from "@maruhi/api-schema";
import { type EnvironmentId, type ProjectId } from "@maruhi/core";
import { type ChainDevice, deviceReceivesEnvironment, type SigningKeyPair } from "@maruhi/crypto";
import { Effect, type Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { backfillEnvironmentFor } from "./backfill.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import type { DekRecipient } from "./deks.ts";
import { devicesOf } from "./device-key.ts";
import { displayText } from "./display.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";

export interface OwnDeviceGapFill {
  readonly deviceFingerprintHex: string;
  readonly missingEpochs: readonly number[];
  readonly registered: number;
  readonly alreadyPresent: number;
  readonly unavailableEpochs: readonly number[];
  readonly failure: string | null;
}

interface OwnDeviceGap {
  readonly device: ChainDevice;
  readonly missingEpochs: readonly number[];
}

function ownDeviceGapsOf(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
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

export const fillOwnDeviceGaps = Effect.fn("device-gaps.fillOwnDeviceGaps")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly signer: { readonly signingKeyPair: SigningKeyPair } | undefined;
  readonly currentEpoch: number;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly rows: readonly RecipientDek[];
}): Effect.fn.Return<readonly OwnDeviceGapFill[]> {
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

export function gapFillCommandOf(projectId: ProjectId, environmentId: string): string {
  return `maruhi pull --project ${displayText(projectId)} --env ${displayText(environmentId)}`;
}

export function describeGapFillRoute(projectId: ProjectId, environmentId: string): string {
  return `A registered device of yours whose cap covers environment ${displayText(environmentId)} and that holds its keys fills the missing epochs when it runs \`${gapFillCommandOf(projectId, environmentId)}\``;
}

export function describeMissingOwnEpochs(
  projectId: ProjectId,
  environmentId: EnvironmentId,
  missingEpochs: readonly number[],
): string {
  return `no DEK wraps for you exist at epochs ${missingEpochs.join(", ")} (inconsistent with the CRYPTO_SPEC §7 all-epoch distribution). A backfill (after \`maruhi member add\`, or after a widening \`maruhi member change-role\`) may have been interrupted — historical versions in those epochs cannot be decrypted. Ask an administrator whose scope covers this environment to re-run \`maruhi member add\` or \`maruhi member change-role\` with your current role and scope (a \`maruhi env rotate\` of the environment also distributes the new epoch's key; or re-register through the repair path). If this machine was added as a device, the backfill to it may not have completed instead. ${describeGapFillRoute(projectId, environmentId)}`;
}

function epochList(epochs: readonly number[]): string {
  return `epoch${epochs.length === 1 ? "" : "s"} ${epochs.join(", ")}`;
}

export const reportOwnDeviceGapFills = Effect.fn("device-gaps.reportOwnDeviceGapFills")(
  function* (input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly fills: readonly OwnDeviceGapFill[];
  }): Effect.fn.Return<void, never, CliIo> {
    const environment = displayText(input.environmentId);
    for (const fill of input.fills) {
      const device = `your device ${fill.deviceFingerprintHex}`;
      const attempted = fill.missingEpochs.filter(
        (epoch) => !fill.unavailableEpochs.includes(epoch),
      );
      if (fill.failure !== null) {
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
  },
);
