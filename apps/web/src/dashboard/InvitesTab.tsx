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
// - Revocation is confirmed in a modal dialog (ruling CO's state
//   machine, with the confirm DP3 amendment 4 moved out of the row —
//   revocation.tsx) + a server re-fetch after completion. Revoke exists
//   only on rows whose status is pending | accepted (a copy of the
//   server's acceptance conditions — which also allow cleaning up an
//   expired pending)

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

/** The data columns (revocable-list.tsx appends the Actions column). */
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

/** Static guidance on issuing (no issue UI here — ADR-0018 amendment 2) + a note on the consequence of revoking. */
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
  // The revocation state lives outside the list resource (directly
  // under the tab) — the latest failure display must not disappear on
  // an unmount mid-refetch (the header comment of use-revocation.ts)
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
