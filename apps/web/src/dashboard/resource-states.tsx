"use client";

import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { Spinner } from "@astryxdesign/core/Spinner";
import type { ReactNode } from "react";

import type { ApiFailure } from "./api.ts";
import { spaPaths } from "./routes.ts";
import { useReportSessionExpired } from "./session-expiry.ts";
import type { ForbiddenReason } from "./types.ts";

const SESSION_NOT_ALLOWED = "session-not-allowed" satisfies ForbiddenReason;

export type FailureSubject = "project" | "invitation" | "token" | "device registry";

const NOT_FOUND_DESCRIPTION: Record<FailureSubject, string> = {
  project: "The server reports no such project for your account.",
  invitation: "The server reports no such invitation for this project.",
  token: "The server reports no such token for your account.",
  "device registry": "The server reports no device registry for your account.",
};

function ForbiddenNotice({ reason }: { reason: string | undefined }): ReactNode {
  return reason === SESSION_NOT_ALLOWED ? (
    <Banner
      role="alert"
      status="warning"
      title="Not available to browser sessions"
      description="This data is not exposed to browser sessions. Use the maruhi CLI instead."
    />
  ) : (
    <Banner
      role="status"
      status="info"
      title="Not available to your role"
      description="Not available to your role in this project, as reported by the server."
    />
  );
}

function UnreachableNotice({ onRetry }: { onRetry: (() => void) | undefined }): ReactNode {
  return (
    <Banner
      role="alert"
      status="error"
      title="Could not reach the server"
      endContent={onRetry ? <Button label="Retry" variant="secondary" onClick={onRetry} /> : null}
    />
  );
}

function GoneNotice({
  reason,
  subject,
}: {
  reason: string | undefined;
  subject: FailureSubject;
}): ReactNode {
  return (
    <Banner
      role="status"
      status="info"
      title="No longer active"
      description={
        reason === undefined
          ? `The server reports this ${subject} is no longer active.`
          : `The server reports this ${subject} as ${reason}.`
      }
    />
  );
}

function StatusNotice({
  failure,
  onRetry,
  subject,
}: {
  failure: ApiFailure;
  onRetry: (() => void) | undefined;
  subject: FailureSubject;
}): ReactNode {
  if (failure.kind === "not-found") {
    return (
      <Banner
        role="status"
        status="info"
        title="Not found"
        description={NOT_FOUND_DESCRIPTION[subject]}
      />
    );
  }
  if (failure.kind === "unauthorized") {
    return (
      <Banner
        role="alert"
        status="warning"
        title="Signed out"
        description="Your session has ended. Sign in again to continue."
        endContent={<Link href={spaPaths.dashboard()}>Go to sign-in</Link>}
      />
    );
  }
  return <UnreachableNotice onRetry={onRetry} />;
}

export function FailureNotice({
  failure,
  onRetry,
  subject = "project",
}: {
  failure: ApiFailure;
  onRetry?: () => void;
  subject?: FailureSubject;
}): ReactNode {
  useReportSessionExpired(failure.kind === "unauthorized");
  if (failure.kind === "forbidden") return <ForbiddenNotice reason={failure.reason} />;
  if (failure.kind === "gone") return <GoneNotice reason={failure.reason} subject={subject} />;
  return <StatusNotice failure={failure} onRetry={onRetry} subject={subject} />;
}

export function LoadingRow({ label }: { label: string }): ReactNode {
  return (
    <HStack>
      <Spinner size="sm" label={label} />
    </HStack>
  );
}

export function EmptyNotice({
  title,
  description = "Nothing to show, as reported by the server.",
  headingLevel = 3,
  testId,
}: {
  title: string;
  description?: string;
  headingLevel?: 2 | 3 | 4;
  testId?: string;
}): ReactNode {
  return (
    <VStack data-testid={testId}>
      <EmptyState title={title} description={description} headingLevel={headingLevel} isCompact />
    </VStack>
  );
}
