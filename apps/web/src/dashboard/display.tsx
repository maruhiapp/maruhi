"use client";

import { HStack } from "@astryxdesign/core/Layout";
import { Text } from "@astryxdesign/core/Text";
import { Timestamp } from "@astryxdesign/core/Timestamp";
import { Token } from "@astryxdesign/core/Token";
import type { ReactNode } from "react";

import type { ChainRole } from "./types.ts";

const SERVER_TIME_TOOLTIP = [
  { timezoneID: "UTC", label: "UTC", isCopyable: true },
  { format: "unix_seconds", label: "Unix", isCopyable: true },
] as const;

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

export function RoleToken({ role }: { role: string }): ReactNode {
  const color = Object.hasOwn(ROLE_TOKEN_COLOR, role)
    ? ROLE_TOKEN_COLOR[role as ChainRole]
    : ("default" as const);
  return <Token label={role} size="sm" color={color} />;
}

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

export function ExpiryCell({ expiresAtMs }: { expiresAtMs: number }): ReactNode {
  return (
    <HStack gap={2} align="center" wrap="wrap">
      <ServerTime ms={expiresAtMs} />
      {expiresAtMs <= Date.now() ? <Token label="Expired" size="sm" color="red" /> : null}
    </HStack>
  );
}
