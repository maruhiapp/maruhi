"use client";

// S9 トークン管理(一覧・失効 — 設計文書 §3 S9 / AUTH_SPEC §6 W3a)。
//
// - 対象は本人のトークンのみ(user 軸 — 裁定 CP で独立ルート /dashboard/tokens)。
//   全ロールで可視(可視性 §5)
// - **発行・生値表示は置かない**(ADR-0018 改訂 2 — 発行経路は device flow の
//   端末のみ。応答に生値・ハッシュは構造ごと存在しない — TokenSummarySchema)
// - 期限切れ(expiresAtMs が過去)と null(移行前の旧無期限行 — 検証側は
//   fail-closed で期限切れ扱い)は Expired のサーバー申告表示(裁定 CQ)
// - 失効はインライン 2 段階確認(裁定 CO)。自トークンの失効は稼働中の
//   CLI / CI を即 401 にするため、帰結の注記をテーブル下へ常時表示する
import { Card } from "@astryxdesign/core/Card";
import { Layout, LayoutContent, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Heading, Text } from "@astryxdesign/core/Text";
import { type ReactNode } from "react";

import { apiPaths } from "./endpoints.ts";
import { spaPaths } from "./routes.ts";
import {
  ExpiryCell,
  FailureNotice,
  formatServerTime,
  LoadingRow,
  RevokeControl,
  ServerReportedNote,
} from "./shared.tsx";
import type { TokenList, TokenSummary } from "./types.ts";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

interface TokenRow extends Record<string, unknown> {
  id: string;
  name: string;
  tokenPrefix: string;
  scopes: string;
  lastUsedAtMs: number | null;
  expiresAtMs: number | null;
}

/** スコープの表示形(`project:permission` — `*` は全プロジェクト)。 */
function scopeLabel(token: TokenSummary): string {
  return token.scopes.map((scope) => `${scope.project}:${scope.permission}`).join(" ");
}

function toTokenRow(token: TokenSummary): TokenRow {
  return {
    id: token.id,
    name: token.name,
    tokenPrefix: token.tokenPrefix,
    scopes: scopeLabel(token),
    lastUsedAtMs: token.lastUsedAtMs,
    expiresAtMs: token.expiresAtMs,
  };
}

function buildTokenColumns(
  revocation: RevocationState,
  onArm: (id: string | undefined) => void,
  onConfirm: (id: string) => void,
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
      renderCell: (row: TokenRow) => (
        <Text type="code" size="sm" wordBreak="break-all">
          {row.tokenPrefix}
        </Text>
      ),
    },
    {
      key: "scopes",
      header: "Scopes",
      width: proportional(1),
      renderCell: (row: TokenRow) => (
        <Text type="code" size="sm" wordBreak="break-all">
          {row.scopes}
        </Text>
      ),
    },
    {
      key: "lastUsedAtMs",
      header: "Last used (UTC)",
      width: pixel(190),
      renderCell: (row: TokenRow) => (
        <Text type="supporting" size="sm" hasTabularNumbers>
          {row.lastUsedAtMs === null ? "never" : formatServerTime(row.lastUsedAtMs)}
        </Text>
      ),
    },
    {
      key: "expiresAtMs",
      header: "Expires (UTC)",
      width: pixel(230),
      renderCell: (row: TokenRow) => <ExpiryCell expiresAtMs={row.expiresAtMs} />,
    },
    {
      key: "actions",
      header: "",
      width: pixel(200),
      renderCell: (row: TokenRow) => (
        <RevokeControl
          armed={revocation.armedId === row.id}
          isPending={revocation.pendingId === row.id}
          isLocked={revocation.pendingId !== undefined && revocation.pendingId !== row.id}
          onArm={() => onArm(row.id)}
          onCancel={() => onArm(undefined)}
          onConfirm={() => onConfirm(row.id)}
        />
      ),
    },
  ];
}

/** 発行の静的案内(発行 UI は置かない)+ 失効の帰結の注記(裁定 CO)。 */
function TokenNotes(): ReactNode {
  return (
    <Text type="supporting" data-testid="token-notes">
      Issuing tokens is not available in the dashboard — a token is issued when you sign in from the
      CLI: <Text type="code">maruhi login</Text> (raw token values never appear here). Revoking a
      token immediately signs out any CLI or CI job still using it; sign in again from the CLI to
      issue a replacement.
    </Text>
  );
}

function TokensTable({
  tokens,
  revocation,
  onArm,
  onConfirm,
}: {
  tokens: ReadonlyArray<TokenSummary>;
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
  onConfirm: (id: string) => void;
}): ReactNode {
  if (tokens.length === 0) {
    return (
      <Text type="supporting" data-testid="token-empty">
        No API tokens, as reported by the server.
      </Text>
    );
  }
  return (
    <Table
      data={tokens.map(toTokenRow)}
      columns={buildTokenColumns(revocation, onArm, onConfirm)}
      idKey="id"
      density="compact"
      dividers="rows"
      data-testid="token-table"
    />
  );
}

function TokensResource({
  revocation,
  onArm,
  onConfirm,
  reload,
  state,
}: {
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
  onConfirm: (id: string) => void;
  reload: () => void;
  state: ResourceState<TokenList>;
}): ReactNode {
  if (state.kind === "loading") return <LoadingRow label="Loading tokens" />;
  if (state.kind === "failed") {
    return <FailureNotice failure={state.failure} onRetry={reload} subject="token" />;
  }
  return (
    <TokensTable
      tokens={state.value.tokens}
      revocation={revocation}
      onArm={onArm}
      onConfirm={onConfirm}
    />
  );
}

export function TokensScreen(): ReactNode {
  const { state, reload } = useApiResource<TokenList>(apiPaths.tokens());
  // 失効状態は一覧リソースの外に持つ(use-revocation.ts のヘッダーコメント)
  const { revocation, arm, confirm } = useRevocation(apiPaths.tokenRevoke, reload);
  return (
    <Layout
      contentWidth={960}
      padding={6}
      content={
        <LayoutContent>
          <VStack gap={5}>
            <VStack gap={2}>
              <Link href={spaPaths.dashboard()}>← Dashboard</Link>
              <Heading level={1}>API tokens</Heading>
              <Text type="supporting">
                Your own API tokens (CLI and CI credentials), as reported by the server.
              </Text>
            </VStack>
            <Card padding={5}>
              <VStack gap={4} data-testid="token-list">
                <TokensResource
                  revocation={revocation}
                  onArm={arm}
                  onConfirm={confirm}
                  reload={reload}
                  state={state}
                />
                {revocation.failure !== undefined ? (
                  <FailureNotice failure={revocation.failure} subject="token" />
                ) : null}
                <TokenNotes />
                <ServerReportedNote />
              </VStack>
            </Card>
          </VStack>
        </LayoutContent>
      }
    />
  );
}
