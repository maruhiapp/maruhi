"use client";

// Shared dashboard parts (the wording unification of ruling BP —
// docs/notes/session-43.md).
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
//     `RevocationOutcome` (shared by S8 / S9 / S11)
import { AlertDialog } from "@astryxdesign/core/AlertDialog";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { Spinner } from "@astryxdesign/core/Spinner";
import { Heading, Text } from "@astryxdesign/core/Text";
import { Timestamp } from "@astryxdesign/core/Timestamp";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode, useEffect, useRef } from "react";

import type { ApiFailure } from "./api.ts";
import { spaPaths } from "./routes.ts";
import { useReportSessionExpired } from "./session-expiry.ts";
import type { ChainRole, ForbiddenReason } from "./types.ts";
import type { RevocationState } from "./use-revocation.ts";

// The hover card's rows: the absolute UTC time and Unix seconds (both
// copyable). The display is the viewer's timezone + an abbreviation
const SERVER_TIME_TOOLTIP = [
  { timezoneID: "UTC", label: "UTC", isCopyable: true },
  { format: "unix_seconds", label: "Unix", isCopyable: true },
] as const;

/**
 * The human-readable display of a server timestamp (ms) (DP3
 * amendment 6 — ruling Q): Astryx `Timestamp` (date_time + the
 * timezone abbreviation). The value is the server-reported serverTs /
 * expiresAtMs itself; only the rendering converts it to the viewer's
 * timezone. The hover card carries UTC and Unix seconds (copyable).
 * `hasTooltip={false}` is for inside a button (the audit row's
 * trigger) — never build a nested interactive element.
 * An out-of-range ms (an Invalid Date) renders the raw number.
 */
export function ServerTime({
  ms,
  hasTooltip = true,
}: {
  ms: number;
  hasTooltip?: boolean;
}): ReactNode {
  const date = new Date(ms);
  if (!Number.isFinite(date.getTime())) {
    return (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {String(ms)}
      </Text>
    );
  }
  return (
    <Timestamp
      value={date.toISOString()}
      format="date_time"
      isTimezoneShown
      hasTooltip={hasTooltip}
      tooltipEntries={SERVER_TIME_TOOLTIP}
      size="sm"
    />
  );
}

const ROLE_TOKEN_COLOR: Record<ChainRole, "purple" | "blue" | "green" | "gray"> = {
  owner: "purple",
  admin: "blue",
  member: "green",
  reader: "gray",
};

/**
 * Displays the server-reported value of a chain-derived role (design
 * document §4 — never claims to be verified).
 * Object.hasOwn: an unexpected role string (including a
 * prototype-chain key name) falls back to the default color.
 */
export function RoleToken({ role }: { role: string }): ReactNode {
  const color = Object.hasOwn(ROLE_TOKEN_COLOR, role)
    ? ROLE_TOKEN_COLOR[role as ChainRole]
    : ("default" as const);
  return <Token label={role} size="sm" color={color} />;
}

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
      status="warning"
      title="Not available to browser sessions"
      description="This data is not exposed to browser sessions. Use the maruhi CLI instead."
    />
  ) : (
    <Banner
      status="info"
      title="Not available to your role"
      description="Not available to your role in this project, as reported by the server."
    />
  );
}

function UnreachableNotice({ onRetry }: { onRetry: (() => void) | undefined }): ReactNode {
  return (
    <Banner
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
    return <Banner status="info" title="Not found" description={NOT_FOUND_DESCRIPTION[subject]} />;
  }
  if (failure.kind === "unauthorized") {
    return (
      <Banner
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
 * The between-sections gap (DP3 amendment 5 — ruling O). A section
 * boundary is marked by whitespace, not a line, so 10 (40px), which
 * contrasts with the in-section gap (4), is shared by every screen.
 */
export const SECTION_GAP = 10;

/**
 * The section heading block (the Astryx `settings` template's shape:
 * a heading + a one-line description).
 * The h2 directly under the page h1. A section's start is marked by
 * the heading's weight, not a line (ruling O), so it has the level-2
 * look.
 */
export function SectionHeader({
  title,
  description,
}: {
  title: string;
  description?: string | undefined;
}): ReactNode {
  return (
    <VStack gap={1}>
      <Heading level={2}>{title}</Heading>
      {description === undefined ? null : (
        <Text type="supporting" color="secondary">
          {description}
        </Text>
      )}
    </VStack>
  );
}

/**
 * The container for a collection (DP3 amendment 9 → 10 — amended
 * ruling S): the heading + description sit on the page's content line,
 * and only the collection of rows goes into a `Card` (a fixed-width
 * box with a border). Every text start position aligns on one line
 * across the page (the h1, descriptions, the overview's MetadataList,
 * and section headings sit on the same line), and only what is inside
 * the bordered box shifts right (amendment 10 — owner ruling).
 * Astryx's docs say "do not use a Card for a page section" (use a
 * Section), but under maruhi's theme a Section's surface is identical
 * to the body and the section is invisible. In this shape the Card
 * wraps not a section but a collection (a table, audit rows), which is
 * closer to the Card docs' "the firm boundary of a self-contained
 * part". The Table inside extends to the Card's edge (Astryx's
 * alignment model), so row lines stop inside the border. Omit `title`
 * and it is only the box (a listing whose page h1 doubles as its
 * heading).
 */
export function SectionBlock({
  title,
  description,
  children,
  testId,
}: {
  title?: string | undefined;
  description?: string | undefined;
  children: ReactNode;
  testId?: string | undefined;
}): ReactNode {
  const box = (
    <Card padding={4} data-testid={title === undefined ? testId : undefined}>
      <VStack gap={4}>{children}</VStack>
    </Card>
  );
  if (title === undefined) return box;
  return (
    <VStack gap={4} data-testid={testId}>
      <SectionHeader title={title} description={description} />
      {box}
    </VStack>
  );
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
 * The note block (the Astryx `CardCallout` block's shape: a muted
 * Card + heading + body).
 * Used for static guidance pointing at the CLI (issuing, revoking,
 * dismissing). `headingLevel` matches the document structure of where
 * it sits (the look is level 4).
 */
export function Callout({
  title,
  headingLevel,
  children,
  testId,
}: {
  title: string;
  headingLevel: 2 | 3;
  children: ReactNode;
  testId?: string;
}): ReactNode {
  return (
    <Card variant="muted" data-testid={testId}>
      <VStack gap={2}>
        <Heading level={4} accessibilityLevel={headingLevel}>
          {title}
        </Heading>
        <Text type="body" color="secondary">
          {children}
        </Text>
      </VStack>
    </Card>
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

/**
 * The display of an identifier (monospace, wraps at any position — the
 * theme's code-text rules in apps/web/theme/maruhi.ts). `size` matches
 * the surrounding density.
 */
export function HexText({
  children,
  size = "sm",
  testId,
}: {
  children: string;
  size?: "sm" | "xsm" | "2xs";
  testId?: string;
}): ReactNode {
  return (
    <Text type="code" size={size} data-testid={testId}>
      {children}
    </Text>
  );
}

/**
 * The expiry display (ruling CQ — docs/notes/session-45.md). The
 * displayed value is always the server-reported expiresAtMs (only the
 * is-past check compares against the client clock).
 */
export function ExpiryCell({ expiresAtMs }: { expiresAtMs: number }): ReactNode {
  return (
    <HStack gap={2} align="center" wrap="wrap">
      <ServerTime ms={expiresAtMs} />
      {expiresAtMs <= Date.now() ? <Token label="Expired" size="sm" color="red" /> : null}
    </HStack>
  );
}

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
 * The announcement of a successful revocation (Banner
 * status="success" = role="status"). Because the revoked row
 * disappears and loses its button on re-fetch, the focus the dialog
 * returned is lost with the row. On appearance focus moves to the
 * Banner itself (tabIndex -1), which becomes the base for the
 * announcement and the next action.
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

/**
 * The display-discipline caveat (design document §4-1 and §4-2):
 * everything shown is server-reported, and when a verified display is
 * needed it points at the CLI.
 */
export function ServerReportedNote(): ReactNode {
  return (
    <Text type="supporting" as="p">
      Everything on this page is shown as reported by the server. Integrity verification is the
      CLI's job: run <Code>maruhi project verify</Code> or <Code>maruhi audit verify</Code> on your
      own machine.
    </Text>
  );
}
