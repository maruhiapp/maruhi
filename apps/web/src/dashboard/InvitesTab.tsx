"use client";

// S8 invite management (listing + revocation — design document §3 S8 /
// ADR-0018 amendment 2).
//
// - The audience is chain role admin or above — the source of truth is
//   server authorization, and the tab is not hidden in advance by role
//   (ruling CP round 3 — a 403 is displayed with role wording. Same
//   "do not replicate the pre-judgment onto the client" as ruling BQ)
// - **No issuing here** (ADR-0018 amendment 2 — no out-of-band anchor +
//   capability minting). Only static guidance pointing at the CLI
//   `maruhi invite create`
// - Revocation is an inline two-step confirm (ruling CO) + a server
//   re-fetch after completion. Revoke exists only on rows whose status
//   is pending | accepted (a copy of the server's acceptance
//   conditions — which also allow cleaning up an expired pending)
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
  formatServerTime,
  HexText,
  LoadingRow,
  RevokeButton,
  RevocationOutcome,
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
 * Displays the server-reported value of an invite's status.
 * Object.hasOwn: an unexpected status string (including prototype-chain
 * key names) falls back to the default color (same self-defense as
 * RoleToken).
 */
function InviteStatusToken({ status }: { status: string }): ReactNode {
  const color = Object.hasOwn(STATUS_TOKEN_COLOR, status)
    ? STATUS_TOKEN_COLOR[status as InviteStatus]
    : ("default" as const);
  return <Token label={status} size="sm" color={color} />;
}

/**
 * A copy of the server's revocation-acceptance condition (pending |
 * accepted) — it only switches what is displayed and is not a defense.
 * The literals are type-bound to the closed enumeration (same shape as
 * ruling CC — renaming a status fails at compile time, not as a
 * silently vanishing button).
 */
const REVOCABLE_STATUSES: ReadonlyArray<string> = [
  "pending",
  "accepted",
] as const satisfies ReadonlyArray<InviteStatus>;

function isRevocable(row: InviteRow): boolean {
  return REVOCABLE_STATUSES.includes(row.status);
}

/**
 * The accessible name of an invite row's Revoke. Identifies the row by
 * the columns visible in the table (state, role, inviter, expiry)
 * (the invite id is not in the table, so it is not used).
 */
function inviteRevokeName(row: InviteRow): string {
  return `Revoke ${row.status} ${row.role} invitation from ${row.inviterUserId}, expires ${formatServerTime(row.expiresAtMs)}`;
}

function buildInviteColumns(
  isLocked: boolean,
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
          <RevokeButton
            onArm={() => onArm(row.id)}
            isLocked={isLocked}
            accessibleName={inviteRevokeName(row)}
          />
        ) : null,
    },
  ];
}

/** Static guidance on issuing (no issue UI here — ADR-0018 amendment 2) + a note on the consequence of revoking. */
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
  isLocked,
  onArm,
}: {
  invitations: ReadonlyArray<InvitationSummary>;
  isLocked: boolean;
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
      columns={buildInviteColumns(isLocked, onArm)}
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
  // Replacement form (ruling B-a). During the post-revocation re-fetch
  // (refreshing) the previous list stays, and each row's Revoke is
  // disabled the same as when one is in flight (prevents a double
  // revocation on a pre-refetch row)
  if (state.kind === "loading") return <LoadingRow label="Loading invitations" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <InvitesTable
      invitations={state.value.invitations}
      isLocked={revocation.pendingId !== undefined || state.refreshing}
      onArm={onArm}
    />
  );
}

export function InvitesTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<InvitationList>(apiPaths.invites(projectId));
  // The revocation state lives outside the list resource (directly
  // under the tab) — the latest failure display must not disappear on
  // an unmount mid-refetch (the header comment of use-revocation.ts)
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
      {/* Confirmation is modal (AlertDialogAsyncAction template) + an appended-form failure (ruling B-b) */}
      <RevocationOutcome
        revocation={revocation}
        title="Revoke this invitation?"
        description="The invitation link becomes unusable immediately. Issue a new invitation from the CLI to replace it."
        successMessage="Invitation revoked."
        subject="invitation"
        arm={arm}
        confirm={confirm}
      />
      <InviteNotes />
    </VStack>
  );
}
