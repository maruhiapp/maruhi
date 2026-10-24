"use client";

// The display of server-reported fields: timestamps, chain roles,
// identifiers and expiry.
// One of the shared dashboard parts: display.tsx, resource-states.tsx,
// sections.tsx and revocation.tsx.
// Every user-visible string is English (ADR-0017). The display
// discipline (design document §4): only server-reported phrasing —
// no client-side assertions (expired / revoked / not a member etc.).
// The one judgment made on the client here is ExpiryCell's Expired,
// which ruling CQ allows: it compares the server-reported expiry with
// the client clock.
import { HStack } from "@astryxdesign/core/Layout";
import { Text } from "@astryxdesign/core/Text";
import { Timestamp } from "@astryxdesign/core/Timestamp";
import { Token } from "@astryxdesign/core/Token";
import type { ReactNode } from "react";

import type { ChainRole } from "./types.ts";

// The hover card's rows: the absolute UTC time and Unix seconds (both
// copyable). The display is the viewer's timezone + an abbreviation
const SERVER_TIME_TOOLTIP = [
  { timezoneID: "UTC", label: "UTC", isCopyable: true },
  { format: "unix_seconds", label: "Unix", isCopyable: true },
] as const;

/**
 * The human-readable display of a server timestamp (ms) (DP3
 * amendment 6 — ruling Q): Astryx `Timestamp` (date_time + the
 * timezone abbreviation). The value is the server-reported serverTs /
 * expiresAtMs itself; only the rendering converts it to the viewer's
 * timezone. The hover card carries UTC and Unix seconds (copyable).
 * `hasTooltip={false}` is for inside a button (the audit row's
 * trigger) — never build a nested interactive element.
 * An out-of-range ms (an Invalid Date) renders the raw number.
 */
export function ServerTime({
  ms,
  hasTooltip = true,
}: {
  ms: number;
  hasTooltip?: boolean;
}): ReactNode {
  const date = new Date(ms);
  if (!Number.isFinite(date.getTime())) {
    return (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {String(ms)}
      </Text>
    );
  }
  return (
    <Timestamp
      value={date.toISOString()}
      format="date_time"
      isTimezoneShown
      hasTooltip={hasTooltip}
      tooltipEntries={SERVER_TIME_TOOLTIP}
      size="sm"
    />
  );
}

const ROLE_TOKEN_COLOR: Record<ChainRole, "purple" | "blue" | "green" | "gray"> = {
  owner: "purple",
  admin: "blue",
  member: "green",
  reader: "gray",
};

/**
 * Displays the server-reported value of a chain-derived role (design
 * document §4 — never claims to be verified).
 * Object.hasOwn: an unexpected role string (including a
 * prototype-chain key name) falls back to the default color.
 */
export function RoleToken({ role }: { role: string }): ReactNode {
  const color = Object.hasOwn(ROLE_TOKEN_COLOR, role)
    ? ROLE_TOKEN_COLOR[role as ChainRole]
    : ("default" as const);
  return <Token label={role} size="sm" color={color} />;
}

/**
 * The display of an identifier (monospace, wraps at any position — the
 * theme's code-text rules in apps/web/theme/maruhi.ts). `size` matches
 * the surrounding density.
 */
export function HexText({
  children,
  size = "sm",
  testId,
}: {
  children: string;
  size?: "sm" | "xsm" | "2xs";
  testId?: string;
}): ReactNode {
  return (
    <Text type="code" size={size} data-testid={testId}>
      {children}
    </Text>
  );
}

/**
 * The expiry display (ruling CQ — docs/notes/session-45.md). The
 * displayed value is always the server-reported expiresAtMs (only the
 * is-past check compares against the client clock).
 */
export function ExpiryCell({ expiresAtMs }: { expiresAtMs: number }): ReactNode {
  return (
    <HStack gap={2} align="center" wrap="wrap">
      <ServerTime ms={expiresAtMs} />
      {expiresAtMs <= Date.now() ? <Token label="Expired" size="sm" color="red" /> : null}
    </HStack>
  );
}
