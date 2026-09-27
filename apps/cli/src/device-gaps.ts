// Filling missing epochs of my other devices of the same person
// (CRYPTO_SPEC §7's device-addition backfill / AUTH_SPEC §12-6
// registration path #6 — 2026-09-25 DK K11; design record
// dk-design.md §16).
//
// The device-addition backfill can die midway (a per-environment
// failure, an interruption before appending, a missing signer), but
// there is no path that fills a device once it is on the chain — not in
// `device approve`, not in sync (§16 fact-check 2). The wraps bundled
// with a pull of values carry rows addressed to **all of the person's
// devices** with `recipientEncPubHex` (`listWrapsForRecipient`), so a
// device that pulled can derive a sibling device's gap without extra
// traffic. Here:
//   - Signal: bundled rows (the server's declaration) — epochs where no
//     row is addressed to the sibling device's key (K11-3 — a
//     declaration decides only "whether to try")
//   - Content: the target device and key come from the verified chain;
//     the DEK is a my-addressed one that passed §5.1 / §5.2 (what the
//     pull opened). Wrap only epochs I could open myself (§7 "the wrap
//     performer = a DEK holder"). Whether already registered is decided
//     by server acceptance (409 = already registered)
//   - Outside the ceremony gate (K11-2 — neither signers nor recipients
//     grow; recipients are my devices in R(E))
//   - Failures fold into the result and do not change the pull's
//     success (a superset of K11-2)
//
// Only `maruhi pull` calls this (K11-4 — `pullVariables` in pull.ts
// enables it via an explicit input).

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

/** Result of filling one sibling device's gap (carries only facts — wording lives on the reporting side). */
export interface OwnDeviceGapFill {
  readonly deviceFingerprintHex: string;
  /** The epochs for which the bundled rows had none addressed to this device. */
  readonly missingEpochs: readonly number[];
  /** Among them, the number of epochs wrapped and registered (excluding 409 = already present). */
  readonly registered: number;
  /** Among them, the number of epochs that were already registered (409). */
  readonly alreadyPresent: number;
  /** Among them, the epochs this device also cannot open (none addressed to me), so they could not be wrapped. */
  readonly unavailableEpochs: readonly number[];
  /** Registration failure (null = none). */
  readonly failure: string | null;
}

/** A sibling device's gap (the fill signal — derived only, nothing done). */
interface OwnDeviceGap {
  readonly device: ChainDevice;
  readonly missingEpochs: readonly number[];
}

/**
 * From the bundled rows, derive the epochs among 1 through the
 * current epoch with no row, for each of the same person's other
 * valid devices that is a recipient of this environment
 * (`deviceReceivesEnvironment` — effective scope).
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
  /** The signing key (this device). undefined = do not fill (anything but `maruhi pull` — K11-4). */
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
 * The command that fills missing epochs (DK K11-5 — the wording of the
 * guidance is produced only here). `--env` and `--project` are always
 * explicit (relying on the default environment would pull a different
 * one).
 */
export function gapFillCommandOf(projectId: string, environmentId: string): string {
  return `maruhi pull --project ${displayText(projectId)} --env ${displayText(environmentId)}`;
}

/** One sentence describing the fill path (shared by the backfill failures of approval / recovery / sync and by the warning of a device with gaps). */
export function describeGapFillRoute(projectId: string, environmentId: string): string {
  return `A registered device of yours whose cap covers environment ${displayText(environmentId)} and that holds its keys fills the missing epochs when it runs \`${gapFillCommandOf(projectId, environmentId)}\``;
}

/**
 * Warning for epochs missing a my-addressed DEK (shared by a pull of
 * values and the `device add` reachability check — DK K12-3. The causes
 * list both the member-side backfill and the device backfill).
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

/** Reporting the fill (Note only — does not change pull's exit code). */
export function reportOwnDeviceGapFills(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly fills: readonly OwnDeviceGapFill[];
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const environment = displayText(input.environmentId);
    for (const fill of input.fills) {
      const device = `your device ${fill.deviceFingerprintHex}`;
      // The epochs we tried to wrap (those this device could open).
      // Both the failure message and the success message name only this
      // set, and a failure also emits the epochs this device itself
      // lacks (pullfrog's point — if the failure message said all gaps
      // "retry on the next pull", it would include epochs this device
      // can never fill)
      const attempted = fill.missingEpochs.filter(
        (epoch) => !fill.unavailableEpochs.includes(epoch),
      );
      if (fill.failure !== null) {
        // A retry helps only after the cause is removed (e.g. the 403 of a token with read scope — K11-7 limit (3))
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
