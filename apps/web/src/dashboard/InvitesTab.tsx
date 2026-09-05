"use client";

// S8 招待管理(一覧・失効 — 設計文書 §3 S8 / ADR-0018 改訂 2)。
//
// - 対象はチェーン role admin 以上 — 真実源はサーバー認可で、タブは role で
//   事前に隠さない(裁定 CP 第 3 周 — 403 は役割文言で表示。裁定 BQ と同じ
//   「事前判定をクライアントへ複製しない」)
// - **発行は置かない**(ADR-0018 改訂 2 — 帯域外アンカーの欠落 + capability
//   生成)。CLI `maruhi invite create` の静的案内のみ
// - 失効はインライン 2 段階確認(裁定 CO)+ 完了後のサーバー再取得。
//   Revoke は status が pending | accepted の行のみ(サーバーの受理条件 —
//   期限切れ pending の掃除も可 — の写し)
import { VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode, useCallback } from "react";

import { apiPaths } from "./endpoints.ts";
import {
  Callout,
  EmptyNotice,
  ExpiryCell,
  FailureNotice,
  HexText,
  LoadingRow,
  RevokeButton,
  RevokeDialog,
  RoleToken,
  SectionBlock,
} from "./shared.tsx";
import type { InvitationList, InvitationSummary, InviteStatus } from "./types.ts";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

interface InviteRow extends Record<string, unknown> {
  id: string;
  role: string;
  status: string;
  inviterUserId: string;
  inviteeUserId: string | undefined;
  expiresAtMs: number;
}

function toInviteRow(invite: InvitationSummary): InviteRow {
  return {
    id: invite.id,
    role: invite.role,
    status: invite.status,
    inviterUserId: invite.inviterUserId,
    inviteeUserId: invite.acceptance?.inviteeUserId,
    expiresAtMs: invite.expiresAtMs,
  };
}

const STATUS_TOKEN_COLOR: Record<InviteStatus, "blue" | "orange" | "green" | "gray"> = {
  pending: "blue",
  accepted: "orange",
  completed: "green",
  revoked: "gray",
};

/**
 * 招待状態のサーバー申告値の表示。Object.hasOwn: 想定外の status 文字列
 * (プロトタイプ鎖の鍵名を含む)は default 色へ落とす(RoleToken と同じ自衛 —
 * PR #107 pullfrog 指摘の型)。
 */
function InviteStatusToken({ status }: { status: string }): ReactNode {
  const color = Object.hasOwn(STATUS_TOKEN_COLOR, status)
    ? STATUS_TOKEN_COLOR[status as InviteStatus]
    : ("default" as const);
  return <Token label={status} size="sm" color={color} />;
}

/**
 * サーバーの失効受理条件(pending | accepted)の写し — 表示の出し分けのみで
 * 防御ではない。リテラルは閉じた列挙へ型束縛する(裁定 CC と同型 — status 名の
 * リネームはボタンの無音消失でなくコンパイルエラーで割れる)。
 */
const REVOCABLE_STATUSES: ReadonlyArray<string> = [
  "pending",
  "accepted",
] as const satisfies ReadonlyArray<InviteStatus>;

function isRevocable(row: InviteRow): boolean {
  return REVOCABLE_STATUSES.includes(row.status);
}

function buildInviteColumns(
  revocation: RevocationState,
  onArm: (id: string | undefined) => void,
): TableColumn<InviteRow>[] {
  return [
    {
      key: "status",
      header: "Status",
      width: pixel(110),
      renderCell: (row: InviteRow) => <InviteStatusToken status={row.status} />,
    },
    {
      key: "role",
      header: "Role",
      width: pixel(100),
      renderCell: (row: InviteRow) => <RoleToken role={row.role} />,
    },
    {
      key: "inviterUserId",
      header: "Invited by",
      width: proportional(1),
      renderCell: (row: InviteRow) => <HexText>{row.inviterUserId}</HexText>,
    },
    {
      key: "inviteeUserId",
      header: "Accepted by",
      width: proportional(1),
      renderCell: (row: InviteRow) =>
        row.inviteeUserId === undefined ? null : <HexText>{row.inviteeUserId}</HexText>,
    },
    {
      key: "expiresAtMs",
      header: "Expires",
      width: pixel(260),
      renderCell: (row: InviteRow) => <ExpiryCell expiresAtMs={row.expiresAtMs} />,
    },
    {
      key: "actions",
      header: "Actions",
      width: pixel(200),
      renderCell: (row: InviteRow) =>
        isRevocable(row) ? (
          <RevokeButton onArm={() => onArm(row.id)} isLocked={revocation.pendingId !== undefined} />
        ) : null,
    },
  ];
}

/** 発行の静的案内(発行 UI は置かない — ADR-0018 改訂 2)+ 失効の帰結の注記。 */
function InviteNotes(): ReactNode {
  return (
    <Callout title="Issuing and revoking" headingLevel={3} testId="invite-notes">
      Issuing invitations is not available in the dashboard — issue one from the CLI:{" "}
      <Text type="code">maruhi invite create</Text> (admin). Revoking makes the invitation link
      unusable immediately; issue a new invitation to replace it.
    </Callout>
  );
}

function InvitesTable({
  invitations,
  revocation,
  onArm,
}: {
  invitations: ReadonlyArray<InvitationSummary>;
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (invitations.length === 0) {
    return (
      <EmptyNotice
        title="No invitations"
        description="Invitations issued for this project appear here, as reported by the server."
        testId="invite-empty"
      />
    );
  }
  return (
    <Table
      data={invitations.map(toInviteRow)}
      columns={buildInviteColumns(revocation, onArm)}
      idKey="id"
      density="balanced"
      hasHover
      dividers="rows"
      data-testid="invite-table"
    />
  );
}

function InvitesResource({
  revocation,
  onArm,
  reload,
  state,
}: {
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
  reload: () => void;
  state: ResourceState<InvitationList>;
}): ReactNode {
  // 置換形(裁定 B-a)
  if (state.kind === "loading") return <LoadingRow label="Loading invitations" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <InvitesTable invitations={state.value.invitations} revocation={revocation} onArm={onArm} />
  );
}

export function InvitesTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<InvitationList>(apiPaths.invites(projectId));
  // 失効状態は一覧リソースの外(タブ直下)に持つ — 再取得中のアンマウントで
  // 直近の失敗表示が消えない(use-revocation.ts のヘッダーコメント)
  const revokePath = useCallback((id: string) => apiPaths.inviteRevoke(projectId, id), [projectId]);
  const { revocation, arm, confirm } = useRevocation(revokePath, reload);
  return (
    <VStack gap={4} data-testid="invite-list">
      <SectionBlock
        title="Invitations"
        description="Pending, accepted, and completed invitations for this project, as reported by the server."
      >
        <InvitesResource revocation={revocation} onArm={arm} reload={reload} state={state} />
      </SectionBlock>
      {/* 確認はモーダル(AlertDialogAsyncAction テンプレート) */}
      <RevokeDialog
        isOpen={revocation.armedId !== undefined}
        title="Revoke this invitation?"
        description="The invitation link becomes unusable immediately. Issue a new invitation from the CLI to replace it."
        isPending={revocation.pendingId !== undefined}
        onCancel={() => arm(undefined)}
        onConfirm={() => {
          if (revocation.armedId !== undefined) confirm(revocation.armedId);
        }}
      />
      {/* 追記形(裁定 B-b): 失効の失敗は一覧の下に足す。再操作は行から行えるので Retry なし */}
      {revocation.failure !== undefined ? (
        <FailureNotice failure={revocation.failure} subject="invitation" />
      ) : null}
      <InviteNotes />
    </VStack>
  );
}
