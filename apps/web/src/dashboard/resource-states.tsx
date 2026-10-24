"use client";

// The three states of a resource: loading, empty and failure, with the
// unified failure wording of ruling BP (docs/notes/session-43.md).
// One of the shared dashboard parts: display.tsx, resource-states.tsx,
// sections.tsx and revocation.tsx.
// Every user-visible string is English (ADR-0017). The display
// discipline (design document §4): only server-reported phrasing —
// no client-side assertions (expired / revoked / not a member etc.).
//
// The empty / loading / error discipline (DP3 ruling B —
// docs/notes/web-design-pass.md §5):
// each resource's three states are drawn with only these three parts.
// A screen never composes a Text / Banner directly.
//   - Loading = `LoadingRow` (a spinner + one line naming what is being
//     loaded. role="status")
//   - Empty = `EmptyNotice` (a heading + an "as reported by the
//     server" description. No counts)
//   - Failure = `FailureNotice` (a Banner per HTTP classification.
//     Only two placements)
//       (a) Replacement: rendered in place of the resource body.
//           Pass onRetry if a re-fetch exists
//       (b) Appended: added below the already-rendered body (a Load
//           more failure, a revocation failure).
//           A failure the row itself can retry (revocation) gets no
//           onRetry
//     The appended form of a revocation is held in one place by
//     revocation.tsx's `RevocationOutcome` (shared by S8 / S9 / S11)
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

// Type-binds the comparison literal to api-schema's closed
// enumeration (ruling CC): renaming a reason fails at compile time,
// not as a silent fallback to the generic wording
const SESSION_NOT_ALLOWED = "session-not-allowed" satisfies ForbiddenReason;

/**
 * The object noun of the 404 wording (the concrete form accompanying
 * ruling CN — docs/notes/session-45.md §5).
 * The uniform-404 meaning (it does not distinguish someone else's
 * from nonexistent) never changes — only the noun adapts to the
 * screen's subject — and this module holds the wording unification
 * (ruling BP).
 */
export type FailureSubject = "project" | "invitation" | "token" | "device registry";

const NOT_FOUND_DESCRIPTION: Record<FailureSubject, string> = {
  project: "The server reports no such project for your account.",
  invitation: "The server reports no such invitation for this project.",
  token: "The server reports no such token for your account.",
  // A 404 does not fold into an empty state (K5-9)
  "device registry": "The server reports no device registry for your account.",
};

/** The 403 display (per reason — session-not-allowed points at the CLI). */
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

/**
 * The 410 display (today only the invite-revocation surface can
 * receive one — it transcribes the server-reported reason).
 * The noun comes from the subject, same as NOT_FOUND_DESCRIPTION
 * (ruling BP's single implementation point — so that when another
 * consumer surface gains a 410 it does not leave one noun fixed on
 * only one side).
 */
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

/**
 * The in-screen display of a failure. A 401 reports "session expired"
 * to the shell (session-expiry.ts) and the shell swaps to the
 * sign-in screen on the spot — for the single render until the report
 * lands (or outside the shell) the "Signed out" Banner shows.
 */
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

/**
 * The loading display (replaces the resource body). Astryx `Spinner`'s
 * `label` slot (the string doubles as the aria-label — the visible
 * wording and the spoken name are one. Ruling B / amendment 7).
 */
export function LoadingRow({ label }: { label: string }): ReactNode {
  return (
    <HStack>
      <Spinner size="sm" label={label} />
    </HStack>
  );
}

/**
 * The empty state (ruling B). The description defaults to the
 * prescribed wording including "as reported by the server" — it must
 * not hint at counts or the existence of an invisible class (design
 * document §4-4). `headingLevel` matches the heading hierarchy of
 * where it sits (the default is page h1 → section h2 → empty-state
 * h3. In a box without a heading [listing, audit, rotation — directly
 * under the page h1] pass h2 so there is no h1 → h3 jump).
 */
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
