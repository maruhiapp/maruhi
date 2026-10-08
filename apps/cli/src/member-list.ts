// `maruhi member list`: verified-chain-derived member rows (user id, role,
// scope, devices — zero values. The group's overview lives in member.ts).

import { type UserId } from "@maruhi/core";
import type { ChainDevice, MemberScope, Role } from "@maruhi/crypto";

import type { VerifiedProject } from "./chain-sync.ts";
import { describeDevice, devicesOf } from "./device-key.ts";
import { displayText } from "./display.ts";
import { describeScope } from "./scope.ts";

// ---------------------------------------------------------------------------
// member list
// ---------------------------------------------------------------------------

/** One member row (verified-chain-derived — zero values. Design record ruling M / K4-E; the devices column is DK K4-20). */
export interface MemberListRow {
  readonly userId: UserId;
  readonly role: Role;
  readonly scope: MemberScope;
  /** The member's device keys (fingerprint ascending — 2026-09-19 DK: a member can have multiple devices). */
  readonly devices: readonly ChainDevice[];
}

/** The verified chain's member list (user_id ascending). */
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

/** One `--json` document (machine-readable — for agents / scripts. Zero values). */
export function memberListJson(rows: readonly MemberListRow[]): string {
  return JSON.stringify(
    {
      members: rows.map((row) => ({
        userId: row.userId,
        role: row.role,
        scope: jsonScope(row.scope),
        // The devices list (K4-20): FP and cap emitted structured. The
        // concatenated `keyFingerprintHex` was removed in K4 (never make
        // consumers decompose it — the finished form of design record §7
        // K2-10 extra round j-4)
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

/** The human-readable row (user id, role, scope, device count, device FPs (cap). The id is neutralized). */
export function formatMemberListRow(row: MemberListRow): string {
  return `${displayText(row.userId)}\t${row.role}\tscope=${describeScope(row.scope)}\tdevices=${row.devices.length}\tfp=${row.devices.map(describeDevice).join(",")}`;
}
