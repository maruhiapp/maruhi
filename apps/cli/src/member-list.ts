import { type UserId } from "@maruhi/core";
import type { ChainDevice, MemberScope, Role } from "@maruhi/crypto";

import type { VerifiedProject } from "./chain-sync.ts";
import { describeDevice, devicesOf } from "./device-key.ts";
import { displayText } from "./display.ts";
import { describeScope } from "./scope.ts";

export interface MemberListRow {
  readonly userId: UserId;
  readonly role: Role;
  readonly scope: MemberScope;
  readonly devices: readonly ChainDevice[];
}

export function memberListRows(verified: VerifiedProject): readonly MemberListRow[] {
  return [...verified.state.members.values()]
    .map((member) => ({
      userId: member.userId,
      role: member.role,
      scope: member.scope,
      devices: devicesOf(member),
    }))
    .toSorted((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
}

export function memberListJson(rows: readonly MemberListRow[]): string {
  return JSON.stringify(
    {
      members: rows.map((row) => ({
        userId: row.userId,
        role: row.role,
        scope: jsonScope(row.scope),
        devices: row.devices.map((device) => ({
          keyFingerprintHex: device.keyFingerprintHex,
          roleCap: device.roleCap,
          scope: jsonScope(device.scope),
        })),
        deviceKeyFingerprintsHex: row.devices.map((device) => device.keyFingerprintHex),
      })),
    },
    null,
    2,
  );
}

function jsonScope(scope: MemberScope) {
  return scope.kind === "all"
    ? { kind: "all" as const }
    : { kind: "listed" as const, environmentIds: [...scope.environmentIds] };
}

export function formatMemberListRow(row: MemberListRow): string {
  return `${displayText(row.userId)}\t${row.role}\tscope=${describeScope(row.scope)}\tdevices=${row.devices.length}\tfp=${row.devices.map(describeDevice).join(",")}`;
}
