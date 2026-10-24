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
// - A token whose server-reported expiresAtMs is past the client clock
//   is marked Expired (ruling CQ — ExpiryCell)
// - Revocation is confirmed in a modal dialog (ruling CO's state
//   machine, with the confirm DP3 amendment 4 moved out of the row —
//   revocation.tsx). Because revoking your own token instantly 401s any
//   running CLI / CI, the consequence note is always shown below the
//   table

import { Code } from "@astryxdesign/core/Code";
import { HStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { ExpiryCell, ServerTime, HexText } from "./display.tsx";
import { apiPaths } from "./endpoints.ts";
import { shortId } from "./ids.ts";
import { EmptyNotice } from "./resource-states.tsx";
import { RevocableList, useRevocableList } from "./revocable-list.tsx";
import { Callout } from "./sections.tsx";
import { armedTokenName, tokenRevokedMessage } from "./token-text.ts";
import type { TokenList, TokenSummary } from "./types.ts";

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

/** The data columns (revocable-list.tsx appends the Actions column). */
const TOKEN_COLUMNS: TableColumn<TokenRow>[] = [
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
];

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

export function TokensScreen(): ReactNode {
  // The revocation state lives outside the list resource (the header
  // comment of use-revocation.ts)
  const list = useRevocableList<TokenList>(apiPaths.tokens(), apiPaths.tokenRevoke);
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
      <RevocableList
        list={list}
        testId="token-list"
        loadingLabel="Loading tokens"
        listSubject="token"
        table={{
          toRows: (value) => value.tokens.map(toTokenRow),
          columns: TOKEN_COLUMNS,
          tableTestId: "token-table",
          empty: (
            <EmptyNotice
              title="No API tokens"
              description="Tokens issued to you appear here, as reported by the server."
              // The list's box has no heading (the page h1 doubles as it), so h2
              headingLevel={2}
              testId="token-empty"
            />
          ),
          revokeName: (row) => `Revoke token "${row.name}"`,
        }}
        // The target's name is drawn from the list
        revocationWording={{
          title: `Revoke ${armedTokenName(list.state, list.revocation.armedId)}?`,
          description:
            "Any CLI or CI job still using this token is signed out immediately. Sign in again from the CLI to issue a replacement.",
          successMessage: tokenRevokedMessage(list.state, list.revocation.armedId),
          subject: "token",
        }}
        notes={<TokenNotes />}
      />
    </DashboardShell>
  );
}
