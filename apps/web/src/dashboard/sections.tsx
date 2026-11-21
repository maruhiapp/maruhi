"use client";

import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { VStack } from "@astryxdesign/core/Layout";
import { Heading, Text } from "@astryxdesign/core/Text";
import type { ReactNode } from "react";

export const SECTION_GAP = 10;

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

export function ServerReportedNote(): ReactNode {
  return (
    <Text type="supporting" as="p">
      Everything on this page is shown as reported by the server. Integrity verification is the
      CLI's job: run <Code>maruhi project verify</Code> or <Code>maruhi audit verify</Code> on your
      own machine.
    </Text>
  );
}
