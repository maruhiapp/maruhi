"use client";

import { Code } from "@astryxdesign/core/Code";
import { pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode, useCallback } from "react";

import { ExpiryCell, HexText, RoleToken } from "./display.tsx";
import { apiPaths } from "./endpoints.ts";
import { EmptyNotice } from "./resource-states.tsx";
import { RevocableList, useRevocableList } from "./revocable-list.tsx";
import { Callout } from "./sections.tsx";
import { formatServerTime } from "./server-time.ts";
import type { InvitationList, InvitationSummary, InviteStatus } from "./types.ts";

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

function InviteStatusToken({ status }: { status: string }): ReactNode {
  const color = Object.hasOwn(STATUS_TOKEN_COLOR, status)
    ? STATUS_TOKEN_COLOR[status as InviteStatus]
    : ("default" as const);
  return <Token label={status} size="sm" color={color} />;
}

const REVOCABLE_STATUSES: ReadonlyArray<string> = [
  "pending",
  "accepted",
] as const satisfies ReadonlyArray<InviteStatus>;

function isRevocable(row: InviteRow): boolean {
  return REVOCABLE_STATUSES.includes(row.status);
}

function inviteRevokeName(row: InviteRow): string {
  return `Revoke ${row.status} ${row.role} invitation from ${row.inviterUserId}, expires ${formatServerTime(row.expiresAtMs)}`;
}

const INVITE_COLUMNS: TableColumn<InviteRow>[] = [
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
];

function InviteNotes(): ReactNode {
  return (
    <Callout title="Issuing and revoking" headingLevel={3} testId="invite-notes">
      Issuing invitations is not available in the dashboard — issue one from the CLI:{" "}
      <Code>maruhi invite create</Code> (admin). Revoking makes the invitation link unusable
      immediately; issue a new invitation to replace it.
    </Callout>
  );
}

export function InvitesTab({ projectId }: { projectId: string }): ReactNode {
  const revokePath = useCallback((id: string) => apiPaths.inviteRevoke(projectId, id), [projectId]);
  const list = useRevocableList<InvitationList>(apiPaths.invites(projectId), revokePath);
  return (
    <RevocableList
      list={list}
      testId="invite-list"
      title="Invitations"
      description="Pending, accepted, and completed invitations for this project, as reported by the server."
      loadingLabel="Loading invitations"
      listSubject="project"
      table={{
        toRows: (value) => value.invitations.map(toInviteRow),
        columns: INVITE_COLUMNS,
        tableTestId: "invite-table",
        empty: (
          <EmptyNotice
            title="No invitations"
            description="Invitations issued for this project appear here, as reported by the server."
            testId="invite-empty"
          />
        ),
        isRevocable,
        revokeName: inviteRevokeName,
      }}
      revocationWording={{
        title: "Revoke this invitation?",
        description:
          "The invitation link becomes unusable immediately. Issue a new invitation from the CLI to replace it.",
        successMessage: "Invitation revoked.",
        subject: "invitation",
      }}
      notes={<InviteNotes />}
    />
  );
}
