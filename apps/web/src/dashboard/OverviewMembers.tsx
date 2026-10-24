"use client";

// The S5 overview tab's Members section (ProjectScreenOverview.tsx):
// the chain-derived members, roles, environment scopes and device keys,
// as reported by the server.
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import type { ReactNode } from "react";

import {
  reportedDeviceCount,
  type ReportedDevice,
  type ReportedMember,
} from "./chain-view-reported.ts";
import { HexText, RoleToken } from "./display.tsx";
import { shortId } from "./ids.ts";
import { SectionBlock } from "./sections.tsx";

interface MemberRow extends Record<string, unknown> {
  id: string;
  role: string;
  /** Environment scope as reported (`all environments` or the listed ids — ES K4). */
  scope: string;
  sinceSeq: number;
  /** Device keys as reported (DK K5 — the chain-view fold). */
  devices: ReadonlyArray<ReportedDevice>;
  deviceCount: number;
  unresolvedRevocations: number;
}

/** The display wording of a scope (a fold of the server report — drawn the same way as the Granted servers Scope column). */
function describeMemberScope(member: ReportedMember): string {
  if (member.scopeKind === "all") return "all environments";
  return member.scopeEnvironmentIds.length === 0
    ? "no environments"
    : member.scopeEnvironmentIds.join(", ");
}

/**
 * The wording of a device cap (same as the CLI's `describeCap` —
 * apps/cli/src/device-key.ts: `owner/all`, `member/dev, staging`,
 * `owner/no environments`). The same fact is written the same way on
 * the web and the CLI (K5-3).
 */
function describeCap(device: ReportedDevice): string {
  if (device.scopeKind === "all") return `${device.roleCap}/all`;
  return `${device.roleCap}/${
    device.scopeEnvironmentIds.length === 0
      ? "no environments"
      : device.scopeEnvironmentIds.join(", ")
  }`;
}

/** Only a bounded device carries the cap (same as the CLI's `describeDevice`). */
function isBounded(device: ReportedDevice): boolean {
  return device.roleCap !== "owner" || device.scopeKind !== "all";
}

const FINGERPRINT_NOT_REPORTED = "fingerprint not reported";

/** The chip's wording: the shortened FP (or not reported) + `(cap)` only when bounded. */
function deviceChipLabel(device: ReportedDevice): string {
  const fp = device.keyFingerprintHex;
  const head = fp === null ? FINGERPRINT_NOT_REPORTED : shortId(fp);
  return isBounded(device) ? `${head} (${describeCap(device)})` : head;
}

/** The chip's description (the full FP, cap, and adding seq — for hover / assistive tech). */
function deviceChipDescription(device: ReportedDevice): string {
  const fp = device.keyFingerprintHex ?? FINGERPRINT_NOT_REPORTED;
  return `${fp} · cap ${describeCap(device)} · added at seq ${device.addedSeq}`;
}

/** The chip of one device (shortened FP + bound. The full FP and cap go in the description). */
function DeviceChip({ device }: { device: ReportedDevice }): ReactNode {
  return (
    <Token
      label={deviceChipLabel(device)}
      size="sm"
      color={device.keyFingerprintHex === null ? "gray" : "default"}
      description={deviceChipDescription(device)}
    />
  );
}

/**
 * The Devices column: the device count (exact, by arithmetic) + one
 * chip per device. An FP appears only once it could be bound from the
 * reported bytes (the `add_device` wire carries no FP — K5-1). When
 * unresolved entries exist, one sentence notes how many of the unbound
 * devices were revoked (which ones is unknown).
 */
function DeviceChips({ row }: { row: MemberRow }): ReactNode {
  return (
    <VStack gap={1}>
      <Text size="sm" hasTabularNumbers>
        {row.deviceCount}
      </Text>
      <HStack gap={1} wrap="wrap">
        {row.devices.map((device) => (
          <DeviceChip key={`${device.encPubHex}:${device.sigPubHex}`} device={device} />
        ))}
      </HStack>
      {row.unresolvedRevocations === 0 ? null : (
        <Text type="supporting" size="sm">
          {row.unresolvedRevocations === 1
            ? "1 of the devices without a reported fingerprint was revoked; which one is not reported."
            : `${row.unresolvedRevocations} of the devices without a reported fingerprint were revoked; which ones is not reported.`}
        </Text>
      )}
    </VStack>
  );
}

const MEMBER_COLUMNS: TableColumn<MemberRow>[] = [
  {
    key: "id",
    header: "User",
    width: proportional(1),
    renderCell: (row: MemberRow) => <HexText>{row.id}</HexText>,
  },
  {
    key: "role",
    header: "Role",
    width: pixel(110),
    renderCell: (row: MemberRow) => <RoleToken role={row.role} />,
  },
  {
    key: "scope",
    header: "Scope",
    width: proportional(1),
    renderCell: (row: MemberRow) => (
      <Text type="supporting" size="sm">
        {row.scope}
      </Text>
    ),
  },
  {
    key: "devices",
    header: "Devices",
    width: proportional(2),
    renderCell: (row: MemberRow) => <DeviceChips row={row} />,
  },
  {
    key: "sinceSeq",
    header: "Since (chain seq)",
    width: pixel(140),
    renderCell: (row: MemberRow) => (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {row.sinceSeq}
      </Text>
    ),
  },
];

/**
 * Entries dropped as unreadable are never silently absorbed (K5-17):
 * a dropped `add_device` leaves a device missing and a dropped
 * `revoke_device` leaves one in, so the display may be off in either
 * direction (never asserts a single direction — K5-18). Not rendered
 * at 0. Verification is the CLI's job
 */
function UnreadableEntriesNote({ count }: { count: number }): ReactNode {
  if (count === 0) return null;
  const rows = count === 1 ? "1 entry" : `${count} entries`;
  const verb = count === 1 ? "was" : "were";
  return (
    <Text type="supporting" size="sm" data-testid="unreadable-entries">
      {`${rows} in the reported chain could not be read and ${verb} left out; the view above may not match what those entries would have produced. Verify with maruhi project verify.`}
    </Text>
  );
}

/**
 * The members (rows = a Table — a collection is drawn as rows) and the
 * note on the reported entries left out as unreadable.
 */
export function MembersSection({
  members,
  unreadableEntries,
}: {
  members: ReadonlyArray<ReportedMember>;
  unreadableEntries: number;
}): ReactNode {
  const memberRows: MemberRow[] = members.map((m) => ({
    id: m.userId,
    role: m.role,
    scope: describeMemberScope(m),
    sinceSeq: m.sinceSeq,
    devices: m.devices,
    deviceCount: reportedDeviceCount(m),
    unresolvedRevocations: m.unresolvedRevocations,
  }));
  return (
    <SectionBlock
      title="Members"
      description="Chain-derived members, roles, environment scopes and device keys, as reported by the server. A device's fingerprint appears once the reported entries bind it; an unbound fingerprint does not change the count. Verify with maruhi member list."
    >
      <Table
        data={memberRows}
        columns={MEMBER_COLUMNS}
        idKey="id"
        density="balanced"
        hasHover
        dividers="rows"
        data-testid="member-table"
      />
      <UnreadableEntriesNote count={unreadableEntries} />
    </SectionBlock>
  );
}
