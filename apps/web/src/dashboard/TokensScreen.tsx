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
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Heading, Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { shortId } from "./ids.ts";
import {
  EmptyNotice,
  ExpiryCell,
  FailureNotice,
  formatServerTime,
  HexText,
  LoadingRow,
  RevokeButton,
  RevokeDialog,
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
  expiresAtMs: number | null;
}

/**
 * スコープの表示(`project:permission` — `*` は全プロジェクト)。project は 64 hex なので
 * chip には短縮形を出し、全文は aria-description に載せる。
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
  revocation: RevocationState,
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
      header: "Actions",
      width: pixel(200),
      renderCell: (row: TokenRow) => (
        <RevokeButton onArm={() => onArm(row.id)} isLocked={revocation.pendingId !== undefined} />
      ),
    },
  ];
}

/**
 * 発行の静的案内(発行 UI は置かない)+ 失効の帰結の注記(裁定 CO)。
 * 形は Astryx の `CardCallout` ブロック(muted の Card + 見出し + 本文)。
 */
function TokenNotes(): ReactNode {
  return (
    <Card variant="muted" data-testid="token-notes">
      <VStack gap={2}>
        <Heading level={4} accessibilityLevel={2}>
          Issuing and revoking
        </Heading>
        <Text type="body" color="secondary">
          Issuing tokens is not available in the dashboard — a token is issued when you sign in from
          the CLI: <Text type="code">maruhi login</Text> (raw token values never appear here).
          Revoking a token immediately signs out any CLI or CI job still using it; sign in again
          from the CLI to issue a replacement.
        </Text>
      </VStack>
    </Card>
  );
}

function TokensTable({
  tokens,
  revocation,
  onArm,
}: {
  tokens: ReadonlyArray<TokenSummary>;
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (tokens.length === 0) {
    return (
      <EmptyNotice
        title="No API tokens"
        description="Tokens issued to you appear here, as reported by the server."
        testId="token-empty"
      />
    );
  }
  return (
    <Table
      data={tokens.map(toTokenRow)}
      columns={buildTokenColumns(revocation, onArm)}
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
  // 置換形(裁定 B-a)
  if (state.kind === "loading") return <LoadingRow label="Loading tokens" />;
  if (state.kind === "failed") {
    return <FailureNotice failure={state.failure} onRetry={reload} subject="token" />;
  }
  return <TokensTable tokens={state.value.tokens} revocation={revocation} onArm={onArm} />;
}

/** 確認ダイアログの見出しに出す対象名(一覧にあれば名前、無ければ "this token")。 */
function armedName(state: ResourceState<TokenList>, armedId: string | undefined): string {
  const token = state.kind === "ok" ? state.value.tokens.find((t) => t.id === armedId) : undefined;
  return token === undefined ? "this token" : `token "${token.name}"`;
}

export function TokensScreen(): ReactNode {
  const { state, reload } = useApiResource<TokenList>(apiPaths.tokens());
  // 失効状態は一覧リソースの外に持つ(use-revocation.ts のヘッダーコメント)
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
        <TokensResource revocation={revocation} onArm={arm} reload={reload} state={state} />
        {/* 確認はモーダル(AlertDialogAsyncAction テンプレート)。対象名は一覧から引く */}
        <RevokeDialog
          isOpen={revocation.armedId !== undefined}
          title={`Revoke ${armedName(state, revocation.armedId)}?`}
          description="Any CLI or CI job still using this token is signed out immediately. Sign in again from the CLI to issue a replacement."
          isPending={revocation.pendingId !== undefined}
          onCancel={() => arm(undefined)}
          onConfirm={() => {
            if (revocation.armedId !== undefined) confirm(revocation.armedId);
          }}
        />
        {/* 追記形(裁定 B-b): 失効の失敗は一覧の下に足す。再操作は行から行えるので Retry なし */}
        {revocation.failure !== undefined ? (
          <FailureNotice failure={revocation.failure} subject="token" />
        ) : null}
        <TokenNotes />
      </VStack>
    </DashboardShell>
  );
}
