"use client";

import { Code } from "@astryxdesign/core/Code";
import { VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { HexText, ServerTime } from "./display.tsx";
import { apiPaths } from "./endpoints.ts";
import { EmptyNotice, FailureNotice, LoadingRow } from "./resource-states.tsx";
import { RevokeButton, RevocationOutcome } from "./revocation.tsx";
import { spaPaths } from "./routes.ts";
import { Callout, SectionBlock } from "./sections.tsx";
import { armedTokenName, tokenRevokedMessage } from "./token-text.ts";
import type { DeviceList, DeviceSummary, TokenList, TokenSummary } from "./types.ts";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

type LinkedToken =
  | { kind: "none" }
  | { kind: "found"; token: TokenSummary }
  | { kind: "not-listed"; tokenId: string }
  | { kind: "pending"; tokenId: string }
  | { kind: "unresolved"; tokenId: string };

interface DeviceRow extends Record<string, unknown> {
  id: string;
  label: string;
  fingerprint: string;
  createdAtMs: number;
  linked: LinkedToken;
}

function linkedFromList(tokenId: string, tokens: TokenList): LinkedToken {
  const token = tokens.tokens.find((t) => t.id === tokenId);
  return token === undefined ? { kind: "not-listed", tokenId } : { kind: "found", token };
}

function linkedTokenOf(tokenId: string | undefined, tokens: ResourceState<TokenList>): LinkedToken {
  if (tokenId === undefined) return { kind: "none" };
  if (tokens.kind === "ok") return linkedFromList(tokenId, tokens.value);
  return tokens.kind === "loading" ? { kind: "pending", tokenId } : { kind: "unresolved", tokenId };
}

function toDeviceRow(device: DeviceSummary, tokens: ResourceState<TokenList>): DeviceRow {
  return {
    id: device.keyFingerprintHex,
    label: device.label,
    fingerprint: device.keyFingerprintHex,
    createdAtMs: device.createdAtMs,
    linked: linkedTokenOf(device.tokenId, tokens),
  };
}

function LinkedTokenCell({ linked }: { linked: LinkedToken }): ReactNode {
  if (linked.kind === "none") {
    return (
      <Text type="supporting" size="sm">
        none linked
      </Text>
    );
  }
  if (linked.kind === "found") {
    return (
      <VStack gap={1}>
        <Text size="sm" wordBreak="break-all">
          {linked.token.name}
        </Text>
        <HexText>{linked.token.tokenPrefix}</HexText>
      </VStack>
    );
  }
  return <UnmatchedTokenCell linked={linked} />;
}

function UnmatchedTokenCell({
  linked,
}: {
  linked: Extract<LinkedToken, { kind: "not-listed" | "pending" | "unresolved" }>;
}): ReactNode {
  return (
    <VStack gap={1}>
      {linked.kind === "pending" ? null : (
        <Text type="supporting" size="sm">
          {linked.kind === "not-listed"
            ? "not among your tokens (revoked or expired?)"
            : "token list unavailable"}
        </Text>
      )}
      <HexText>{linked.tokenId}</HexText>
    </VStack>
  );
}

function buildDeviceColumns(
  isLocked: boolean,
  onArm: (id: string | undefined) => void,
): TableColumn<DeviceRow>[] {
  return [
    {
      key: "label",
      header: "Label",
      width: proportional(1),
      renderCell: (row: DeviceRow) => (
        <Text size="sm" wordBreak="break-all">
          {row.label}
        </Text>
      ),
    },
    {
      key: "fingerprint",
      header: "Fingerprint",
      width: proportional(1),
      renderCell: (row: DeviceRow) => <HexText>{row.fingerprint}</HexText>,
    },
    {
      key: "createdAtMs",
      header: "Registered",
      width: pixel(220),
      renderCell: (row: DeviceRow) => <ServerTime ms={row.createdAtMs} />,
    },
    {
      key: "linked",
      header: "API token",
      width: proportional(1),
      renderCell: (row: DeviceRow) => <LinkedTokenCell linked={row.linked} />,
    },
    {
      key: "actions",
      header: "Actions",
      width: pixel(160),
      renderCell: (row: DeviceRow) => {
        const linked = row.linked;
        if (linked.kind !== "found") return null;
        return (
          <RevokeButton
            label="Revoke token"
            accessibleName={`Revoke token "${linked.token.name}" of device ${row.label}`}
            onArm={() => onArm(linked.token.id)}
            isLocked={isLocked}
          />
        );
      },
    },
  ];
}

function DeviceNotes(): ReactNode {
  return (
    <Callout title="Lost a device?" headingLevel={2} testId="device-notes">
      Revoke its key from another device with <Code>maruhi device revoke &lt;fingerprint&gt;</Code>,
      then revoke its API token here (or on the <Link href={spaPaths.tokens()}>API tokens</Link>{" "}
      page). Revoking the token stops that device from reaching the API immediately; revoking the
      key is what removes it from the project chains. Registering, approving and removing devices is
      done from the CLI (<Code>maruhi device add</Code> / <Code>maruhi device approve</Code>) and is
      not available in the dashboard.
    </Callout>
  );
}

function DevicesTable({
  devices,
  tokens,
  isLocked,
  onArm,
}: {
  devices: ReadonlyArray<DeviceSummary>;
  tokens: ResourceState<TokenList>;
  isLocked: boolean;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (devices.length === 0) {
    return (
      <EmptyNotice
        title="No devices registered"
        description="Devices you register from the CLI (maruhi device add) appear here, as reported by the server."
        headingLevel={2}
        testId="device-empty"
      />
    );
  }
  return (
    <Table
      data={devices.map((device) => toDeviceRow(device, tokens))}
      columns={buildDeviceColumns(isLocked, onArm)}
      idKey="id"
      density="balanced"
      hasHover
      dividers="rows"
      data-testid="device-table"
    />
  );
}

function isRowActionLocked(
  revocation: RevocationState,
  resources: ReadonlyArray<{ readonly kind: string; readonly refreshing?: boolean }>,
): boolean {
  return (
    revocation.pendingId !== undefined || resources.some((resource) => resource.refreshing === true)
  );
}

function DevicesResource({
  state,
  tokens,
  reload,
  revocation,
  onArm,
}: {
  state: ResourceState<DeviceList>;
  tokens: ResourceState<TokenList>;
  reload: () => void;
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (state.kind === "loading") return <LoadingRow label="Loading devices" />;
  if (state.kind === "failed") {
    return <FailureNotice failure={state.failure} onRetry={reload} subject="device registry" />;
  }
  return (
    <DevicesTable
      devices={state.value.devices}
      tokens={tokens}
      isLocked={isRowActionLocked(revocation, [state, tokens])}
      onArm={onArm}
    />
  );
}

export function DevicesScreen(): ReactNode {
  const devices = useApiResource<DeviceList>(apiPaths.devices());
  const tokens = useApiResource<TokenList>(apiPaths.tokens());
  const reloadDevices = devices.reload;
  const reloadTokens = tokens.reload;
  const reloadBoth = useCallback(() => {
    reloadDevices();
    reloadTokens();
  }, [reloadDevices, reloadTokens]);
  const { revocation, arm, confirm } = useRevocation(apiPaths.tokenRevoke, reloadBoth);
  return (
    <DashboardShell
      destination="devices"
      title="Devices"
      intro={
        <Text as="p" type="supporting">
          Your device registry (display names and linked API tokens), as reported by the server. The
          registry is advisory; the project chains are the source of truth —{" "}
          <Code>maruhi device list</Code> verifies them.
        </Text>
      }
    >
      <VStack gap={4} data-testid="device-list">
        <SectionBlock>
          <DevicesResource
            state={devices.state}
            tokens={tokens.state}
            reload={reloadDevices}
            revocation={revocation}
            onArm={arm}
          />
        </SectionBlock>
        {}
        <RevocationOutcome
          revocation={revocation}
          title={`Revoke ${armedTokenName(tokens.state, revocation.armedId)}?`}
          description="Any CLI or CI job still using this token is signed out immediately. This does not revoke the device key on the project chains — do that from the CLI."
          successMessage={tokenRevokedMessage(tokens.state, revocation.armedId)}
          subject="token"
          arm={arm}
          confirm={confirm}
        />
        <DeviceNotes />
      </VStack>
    </DashboardShell>
  );
}
