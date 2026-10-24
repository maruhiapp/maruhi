"use client";

// The page's sections and their static guidance: the gap between
// sections, the section heading and box, the callout, and the
// server-reported caveat.
// One of the shared dashboard parts: display.tsx, resource-states.tsx,
// sections.tsx and revocation.tsx.
// Every user-visible string is English (ADR-0017). The display
// discipline (design document §4): only server-reported phrasing —
// no client-side assertions (expired / revoked / not a member etc.).
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { VStack } from "@astryxdesign/core/Layout";
import { Heading, Text } from "@astryxdesign/core/Text";
import type { ReactNode } from "react";

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
