"use client";

// S9 token management (listing + revocation — design document §3 S9 /
// AUTH_SPEC §6 W3a).
//
// - Only your own tokens (the user axis — ruling CP made it the
//   separate route /dashboard/tokens). Visible under every role
//   (visibility §5)
// - **No issuing or raw-value display here** (ADR-0018 amendment 2 —
//   the only issuance path is the device in the device flow. The
//   response structurally has no raw values or hashes —
//   TokenSummarySchema)
// - An expired token (expiresAtMs in the past) is displayed as Expired,
//   as reported by the server (ruling CQ)
// - Revocation is an inline two-step confirm (ruling CO). Because
//   revoking your own token instantly 401s any running CLI / CI, the
//   consequence note is always shown below the table

import { Code } from "@astryxdesign/core/Code";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { shortId } from "./ids.ts";
import {
  Callout,
  EmptyNotice,
  ExpiryCell,
  FailureNotice,
  ServerTime,
  HexText,
  LoadingRow,
  RevokeButton,
  RevocationOutcome,
  armedTokenName,
  tokenRevokedMessage,
  SectionBlock,
} from "./shared.tsx";
import type { TokenList, TokenSummary } from "./types.ts";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

interface TokenRow extends Record<string, unknown> {
  id: string;
  name: string;
  tokenPrefix: string;
  token: TokenSummary;
  lastUsedAtMs: number | null;
  expiresAtMs: number;
}

/**
 * Displays the scopes (`project:permission` — `*` is all projects).
 * project is 64 hex, so the chip carries the shortened form and the
 * full text rides aria-description.
 */
function ScopeChips({ token }: { token: TokenSummary }): ReactNode {
  return (
    <HStack gap={1} wrap="wrap">
      {token.scopes.map((scope) => {
        const project = scope.project === "*" ? "*" : shortId(scope.project);
        return (
          <Token
            key={`${scope.project}:${scope.permission}`}
            label={`${project}:${scope.permission}`}
            size="sm"
            description={`${scope.project}:${scope.permission}`}
          />
        );
      })}
    </HStack>
  );
}

function toTokenRow(token: TokenSummary): TokenRow {
  return {
    id: token.id,
    name: token.name,
    tokenPrefix: token.tokenPrefix,
    token,
    lastUsedAtMs: token.lastUsedAtMs,
    expiresAtMs: token.expiresAtMs,
  };
}

function buildTokenColumns(
  isLocked: boolean,
  onArm: (id: string | undefined) => void,
): TableColumn<TokenRow>[] {
  return [
    {
      key: "name",
      header: "Name",
      width: proportional(1),
      renderCell: (row: TokenRow) => (
        <Text size="sm" wordBreak="break-all">
          {row.name}
        </Text>
      ),
    },
    {
      key: "tokenPrefix",
      header: "Prefix",
      width: pixel(130),
      renderCell: (row: TokenRow) => <HexText>{row.tokenPrefix}</HexText>,
    },
    {
      key: "scopes",
      header: "Scopes",
      width: proportional(1),
      renderCell: (row: TokenRow) => <ScopeChips token={row.token} />,
    },
    {
      key: "lastUsedAtMs",
      header: "Last used",
      width: pixel(220),
      renderCell: (row: TokenRow) =>
        row.lastUsedAtMs === null ? (
          <Text type="supporting" size="sm">
            never
          </Text>
        ) : (
          <ServerTime ms={row.lastUsedAtMs} />
        ),
    },
    {
      key: "expiresAtMs",
      header: "Expires",
      width: pixel(260),
      renderCell: (row: TokenRow) => <ExpiryCell expiresAtMs={row.expiresAtMs} />,
    },
    {
      key: "actions",
      header: "Actions",
      width: pixel(200),
      renderCell: (row: TokenRow) => (
        <RevokeButton
          onArm={() => onArm(row.id)}
          isLocked={isLocked}
          accessibleName={`Revoke token "${row.name}"`}
        />
      ),
    },
  ];
}

/** Static guidance on issuing (no issue UI here) + a note on the consequence of revoking (ruling CO). */
function TokenNotes(): ReactNode {
  return (
    <Callout title="Issuing and revoking" headingLevel={2} testId="token-notes">
      Issuing tokens is not available in the dashboard — a token is issued when you sign in from the
      CLI: <Code>maruhi login</Code> (raw token values never appear here). Revoking a token
      immediately signs out any CLI or CI job still using it; sign in again from the CLI to issue a
      replacement.
    </Callout>
  );
}

function TokensTable({
  tokens,
  isLocked,
  onArm,
}: {
  tokens: ReadonlyArray<TokenSummary>;
  isLocked: boolean;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (tokens.length === 0) {
    return (
      <EmptyNotice
        title="No API tokens"
        description="Tokens issued to you appear here, as reported by the server."
        // The list's box has no heading (the page h1 doubles as it), so h2
        headingLevel={2}
        testId="token-empty"
      />
    );
  }
  return (
    <Table
      data={tokens.map(toTokenRow)}
      columns={buildTokenColumns(isLocked, onArm)}
      idKey="id"
      density="balanced"
      hasHover
      dividers="rows"
      data-testid="token-table"
    />
  );
}

function TokensResource({
  revocation,
  onArm,
  reload,
  state,
}: {
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
  reload: () => void;
  state: ResourceState<TokenList>;
}): ReactNode {
  // Replacement form (ruling B-a). During the post-revocation re-fetch
  // (refreshing) the previous list stays, and each row's Revoke is
  // disabled the same as when one is in flight (prevents a double
  // revocation on a pre-refetch row)
  if (state.kind === "loading") return <LoadingRow label="Loading tokens" />;
  if (state.kind === "failed") {
    return <FailureNotice failure={state.failure} onRetry={reload} subject="token" />;
  }
  return (
    <TokensTable
      tokens={state.value.tokens}
      isLocked={revocation.pendingId !== undefined || state.refreshing}
      onArm={onArm}
    />
  );
}

export function TokensScreen(): ReactNode {
  const { state, reload } = useApiResource<TokenList>(apiPaths.tokens());
  // The revocation state lives outside the list resource (the header
  // comment of use-revocation.ts)
  const { revocation, arm, confirm } = useRevocation(apiPaths.tokenRevoke, reload);
  return (
    <DashboardShell
      destination="tokens"
      title="API tokens"
      intro={
        <Text as="p" type="supporting">
          Your own API tokens (CLI and CI credentials), as reported by the server.
        </Text>
      }
    >
      <VStack gap={4} data-testid="token-list">
        <SectionBlock>
          <TokensResource revocation={revocation} onArm={arm} reload={reload} state={state} />
        </SectionBlock>
        {/* Confirmation is modal (AlertDialogAsyncAction template). The target's name is drawn from the list */}
        <RevocationOutcome
          revocation={revocation}
          title={`Revoke ${armedTokenName(state, revocation.armedId)}?`}
          description="Any CLI or CI job still using this token is signed out immediately. Sign in again from the CLI to issue a replacement."
          successMessage={tokenRevokedMessage(state, revocation.armedId)}
          subject="token"
          arm={arm}
          confirm={confirm}
        />
        <TokenNotes />
      </VStack>
    </DashboardShell>
  );
}
