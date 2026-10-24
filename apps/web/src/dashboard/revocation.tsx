"use client";

// The revocation surface of S8 / S9 / S11 (invites, tokens, devices):
// the per-row Revoke button, the confirm dialog, and the outcome below
// the list. use-revocation.ts holds the state they show.
// One of the shared dashboard parts: display.tsx, resource-states.tsx,
// sections.tsx and revocation.tsx.
// Every user-visible string is English (ADR-0017). The display
// discipline (design document §4): only server-reported phrasing —
// no client-side assertions (expired / revoked / not a member etc.).
import { AlertDialog } from "@astryxdesign/core/AlertDialog";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { type ReactNode, useEffect, useRef } from "react";

import { FailureNotice, type FailureSubject } from "./resource-states.tsx";
import type { RevocationState } from "./use-revocation.ts";

/**
 * The entry to a revocation (a per-row ghost button). Confirmation
 * happens in `RevokeDialog` (AlertDialog) — DP3 amendment 4 replaced
 * ruling CO's inline two-step (Cancel / Confirm revoke inside the
 * row) with the Astryx `AlertDialogAsyncAction` template's shape (a
 * modal confirm + a spinner on the action button while running). The
 * in-row two buttons stacked vertically in a narrow column and
 * changed the height of other rows. The meaning of the armed state is
 * unchanged: at most one row, disarmed when another row arms.
 * `isLocked` = another row's revocation is running (other rows are
 * disabled while in-flight). `label` is the visible wording, used when
 * the object's noun should be attached (from an S11 device row the
 * thing being revoked is not the device but the token — "Revoke
 * token"). `accessibleName` is the spoken name including the row's
 * identification (a table lined with "Revoke" buttons cannot be told
 * apart in assistive tech's button list). An Astryx Button makes label
 * the aria-label when children differ from label, so pass label = the
 * spoken name, children = the visible wording.
 */
export function RevokeButton({
  onArm,
  isLocked,
  accessibleName,
  label = "Revoke",
}: {
  onArm: () => void;
  isLocked: boolean;
  accessibleName: string;
  label?: string;
}): ReactNode {
  return (
    <Button label={accessibleName} variant="ghost" size="sm" onClick={onArm} isDisabled={isLocked}>
      {label}
    </Button>
  );
}

/**
 * The revocation confirm dialog (one per table. Open only while an
 * `armedId` is set). `title` / `description` are given by the screen
 * as the object's noun and the consequence (ruling CO's "consequence
 * note" is read at the point of confirmation). While running, the
 * action button is isActionLoading and Cancel only closes.
 */
function RevokeDialog({
  isOpen,
  title,
  description,
  isPending,
  onCancel,
  onConfirm,
}: {
  isOpen: boolean;
  title: string;
  description: string;
  isPending: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}): ReactNode {
  return (
    <AlertDialog
      isOpen={isOpen}
      onOpenChange={(open) => {
        if (!open && !isPending) onCancel();
      }}
      title={title}
      description={description}
      actionLabel="Revoke"
      isActionLoading={isPending}
      onAction={onConfirm}
    />
  );
}

/**
 * The announcement of a successful revocation (a role="status"
 * Banner). Because the revoked row disappears and loses its button on
 * re-fetch, the focus the dialog returned is lost with the row. On
 * appearance focus moves to the Banner itself (tabIndex -1), which
 * becomes the base for the announcement and the next action.
 */
function RevocationSuccess({ message }: { message: string }): ReactNode {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, [message]);
  return (
    <Banner
      ref={ref}
      tabIndex={-1}
      role="status"
      status="success"
      title={message}
      data-testid="revocation-success"
    />
  );
}

/**
 * The revocation outcome surface (shared by S8 / S9 / S11 — promoted
 * when DK K5 produced a third screen): while armed it is
 * `RevokeDialog`, the latest failure is the appended form below the
 * list (ruling B-b — the row itself can retry, so no Retry), the
 * latest success is `RevocationSuccess`. `arm(undefined)` /
 * `confirm(id, …)` are passed straight from use-revocation.ts's
 * operations. `successMessage` is built with the object's name at the
 * moment of confirmation (the object may not remain in the list after
 * the re-fetch).
 */
export function RevocationOutcome({
  revocation,
  title,
  description,
  successMessage,
  subject,
  arm,
  confirm,
}: {
  revocation: RevocationState;
  title: string;
  description: string;
  successMessage: string;
  subject: FailureSubject;
  arm: (id: string | undefined) => void;
  confirm: (id: string, successMessage: string) => void;
}): ReactNode {
  return (
    <>
      <RevokeDialog
        isOpen={revocation.armedId !== undefined}
        title={title}
        description={description}
        isPending={revocation.pendingId !== undefined}
        onCancel={() => arm(undefined)}
        onConfirm={() => {
          if (revocation.armedId !== undefined) confirm(revocation.armedId, successMessage);
        }}
      />
      {revocation.failure !== undefined ? (
        <FailureNotice failure={revocation.failure} subject={subject} />
      ) : null}
      {revocation.succeeded !== undefined ? (
        <RevocationSuccess message={revocation.succeeded} />
      ) : null}
    </>
  );
}
