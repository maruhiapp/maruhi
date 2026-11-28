import { type ProjectId, type UserId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { CliServices } from "../cli.ts";
import { openMetadataProject, type ProjectContextBase } from "../context.ts";
import { describeCap, deviceProvenanceOf, devicesOf } from "../device-key.ts";
import { keyStandingIn } from "../device-standing.ts";
import { countNoun, displayText } from "../display.ts";
import type { CliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "../own-devices.ts";
import { compareCodePoints } from "../scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "../session.ts";
import { fetchRegistry, type RegistryRow, resolveProjectIds } from "./device.ts";

interface ListRows {
  readonly rows: Map<string, { readonly projectId: ProjectId; readonly line: string }[]>;
  readonly chains: readonly { readonly projectId: ProjectId; readonly verified: VerifiedProject }[];
}

const collectChainRows = Effect.fn("device-list.collectChainRows")(function* (input: {
  readonly session: CliSession;
  readonly projectIds: readonly ProjectId[];
}): Effect.fn.Return<ListRows, never, CliServices> {
  const rows: ListRows["rows"] = new Map();
  const chains: ListRows["chains"][number][] = [];
  for (const projectId of input.projectIds) {
    const context = yield* openMetadataProject({
      server: input.session.origin,
      project: projectId,
    }).pipe(Effect.orElseSucceed((): ProjectContextBase | null => null));
    if (context === null) {
      yield* logNote(
        `${displayText(projectId)}: could not sync this project; its devices are not shown`,
      );
      continue;
    }
    chains.push({ projectId, verified: context.verified });
    const self = context.verified.state.members.get(input.session.userId);
    for (const device of self === undefined ? [] : devicesOf(self)) {
      const provenance = deviceProvenanceOf(context.verified, input.session.userId, device);
      const adder =
        provenance.addedByFingerprintHex === null
          ? "first key"
          : `added by ${provenance.addedByFingerprintHex}${provenance.adderStillActive ? "" : " (that device is now revoked)"}`;
      const lines = rows.get(device.keyFingerprintHex) ?? [];
      lines.push({
        projectId,
        line: `${displayText(projectId)}: cap=${describeCap(device)} seq=${device.addedSeq} ${adder}`,
      });
      rows.set(device.keyFingerprintHex, lines);
    }
  }
  return { rows, chains };
});

function chainLinesOf(input: {
  readonly listed: ListRows;
  readonly userId: UserId;
  readonly fingerprintHex: string;
}): readonly string[] {
  const active = (input.listed.rows.get(input.fingerprintHex) ?? []).map((row) => row.line);
  const revoked = input.listed.chains
    .filter(
      (chain) =>
        keyStandingIn(chain.verified, input.userId, input.fingerprintHex).kind === "revoked",
    )
    .map(
      (chain) =>
        `${displayText(chain.projectId)}: revoked (a revoked key is never registered again)`,
    );
  return [...active, ...revoked];
}

function describeListRow(input: {
  readonly fingerprintHex: string;
  readonly ownFingerprintHex: string | null;
  readonly registryRow: RegistryRow | undefined;
  readonly record: OwnDeviceEntry | undefined;
}): string {
  const tags: string[] = [];
  if (input.ownFingerprintHex === input.fingerprintHex) {
    tags.push("this machine");
  }
  if (input.registryRow !== undefined) {
    tags.push(`label "${displayText(input.registryRow.label)}" (server-reported)`);
    if (input.registryRow.tokenId !== undefined) {
      tags.push(`token ${displayText(input.registryRow.tokenId)} (server-reported)`);
    }
  }
  if (input.record !== undefined) {
    tags.push(
      input.record.revokedAtMs === null
        ? `recorded here as ${input.record.source}`
        : "recorded here as revoked",
    );
  }
  return `${input.fingerprintHex}${tags.length === 0 ? "" : `\t${tags.join(", ")}`}`;
}

export const deviceListOp = Effect.fn("device-list.deviceListOp")(function* (input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly project: ProjectId | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const store = yield* OwnDeviceStore;
  const registry = yield* fetchRegistry(input.client);
  const lookup = yield* store.load(input.session.origin, input.session.userId);
  const local = lookup.state === "loaded" ? lookup.devices : [];
  const projectIds = yield* resolveProjectIds(input.client, input.project).pipe(
    Effect.catch((error) =>
      logNote(
        `your projects could not be listed (${error.message}), so no project chain is shown`,
      ).pipe(Effect.as<readonly ProjectId[]>([])),
    ),
  );
  const localKeys = yield* Effect.catch(loadMasterKeys(input.session), () =>
    Effect.succeed<MasterKeys | null>(null),
  );
  const listed = yield* collectChainRows({ session: input.session, projectIds });
  const active = local.filter((entry) => entry.revokedAtMs === null);
  const fingerprints = [
    ...new Set([
      ...listed.rows.keys(),
      ...(registry ?? []).map((row) => row.keyFingerprintHex),
      ...active.map((entry) => entry.keyFingerprintHex),
      ...(localKeys === null ? [] : [localKeys.fingerprintHex]),
    ]),
  ].toSorted(compareCodePoints);
  if (fingerprints.length === 0) {
    yield* io.log(
      "No devices found (no project chain lists a device of yours, and the registry is empty)",
    );
    return;
  }
  if (registry === null) {
    yield* logNote(
      "the device registry could not be read (labels are server-reported and advisory anyway)",
    );
  }
  for (const fingerprintHex of fingerprints) {
    yield* io.log(
      describeListRow({
        fingerprintHex,
        ownFingerprintHex: localKeys?.fingerprintHex ?? null,
        registryRow: registry?.find((row) => row.keyFingerprintHex === fingerprintHex),
        record: local.find((entry) => entry.keyFingerprintHex === fingerprintHex),
      }),
    );
    yield* printChainLines({
      lines: chainLinesOf({ listed, userId: input.session.userId, fingerprintHex }),
      project: input.project,
      unsynced: projectIds.length - listed.chains.length,
    });
  }
});

const printChainLines = Effect.fn("device-list.printChainLines")(function* (input: {
  readonly lines: readonly string[];
  readonly project: ProjectId | undefined;
  readonly unsynced: number;
}): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  if (input.lines.length === 0) {
    yield* io.log(describeNoChainLines(input.project, input.unsynced));
  }
  for (const line of input.lines) {
    yield* io.log(`  ${line}`);
  }
});

function describeNoChainLines(project: string | undefined, unsynced: number): string {
  if (project !== undefined) {
    return unsynced > 0
      ? `  (project ${displayText(project)} could not be synced, so whether this key is on its chain is unknown)`
      : `  (not on the chain of project ${displayText(project)}, the only project shown)`;
  }
  return unsynced > 0
    ? `  (not on any synced project chain; ${countNoun(unsynced, "project")} could not be synced)`
    : "  (not on any synced project chain)";
}
