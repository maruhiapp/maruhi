"use client";

import { AlertDialog } from "@astryxdesign/core/AlertDialog";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { type ReactNode, useEffect, useRef } from "react";

import { FailureNotice, type FailureSubject } from "./resource-states.tsx";
import type { RevocationState } from "./use-revocation.ts";

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
